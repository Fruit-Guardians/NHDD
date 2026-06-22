// nhdd.c — No-Hook DEX/SO Dumper (NHDD)
// Scan a process for DEX and SO files via /proc/<pid>/mem, dump and auto-fix.
// No injection, no hooks — undetectable by packer security checks.
//
// Build: aarch64-linux-android34-clang -O2 -static -o nhdd nhdd.c
// Usage: nhdd <pid|package> [output_dir] [--so|--dex|--all]
//                           [--snapshot ROUNDS] [--interval SECS]
//
// Features:
//   - Accept PID or package name (auto-resolve via /proc/*/cmdline)
//   - Multi-process scan: when given a package, ALL matching PIDs are scanned
//     (main + child :remote / push processes). The real decrypted DEX is often
//     loaded in a child process; scanning only the smallest PID misses it.
//   - Page-by-page scanning (proven effective, no false negatives)
//   - DEX content de-duplication (by recomputed SHA-1 signature) — across both
//     processes and snapshot rounds, the same DEX is written only once.
//   - Dump DEX files (default) with auto-fix SHA-1 + Adler32 + header fields
//   - Dump SO files (--so) with auto-fix ELF header, spanning contiguous maps
//   - Snapshot mode (--snapshot N --interval T): re-scan the target N times so
//     even a DEX that only briefly exists in memory gets captured.
//   - Static binary, no dependencies

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      // log() for Shannon entropy (B5 decryption-state scoring)
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/uio.h>    // process_vm_readv

// ---- Magic constants ----
static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"
static const uint8_t kElfMagic[] = {0x7f, 0x45, 0x4c, 0x46}; // \x7fELF
// DEX endian_tag at offset 0x28 — always 0x12345678 for a valid DEX.
// Second-gen packers often erase the "dex\n" magic but rarely touch this.
static const uint32_t kDexEndianTag = 0x12345678;

// ---- DEX map_list item sizes (bytes per entry) for each section type ----
// Used to recover DEX extent when file_size is erased (FRIDA-DEXDump approach:
// walk map_list, take max(offset + count*item_size) over all entries).
// map_list type codes (DexFile.h): 0x0000 header, 0x0001 string_id, 0x0002 type_id,
// 0x0003 proto_id, 0x0004 field_id, 0x0005 method_id, 0x0006 class_def,
// 0x0007 call_site_id, 0x0008 method_handle, 0x1000 map_list, 0x1001 type_list,
// 0x1002 anno_set_ref_list, 0x1003 anno_set_item, 0x1004 class_data_item,
// 0x1005 code_item, 0x1006 string_data_item, 0x1007 debug_info, 0x1008 anno_item,
// 0x1009 encoded_array, 0x100A annotations_directory.
#define DEX_TYPE_MAP_LIST 0x1000
static uint32_t dex_map_item_size(uint16_t type) {
    switch (type) {
        case 0x0000: return 0x70;        // header
        case 0x0001: return 4;          // string_id
        case 0x0002: return 4;          // type_id
        case 0x0003: return 12;         // proto_id
        case 0x0004: return 8;          // field_id
        case 0x0005: return 8;          // method_id
        case 0x0006: return 32;         // class_def
        case 0x0007: return 4;          // call_site_id
        case 0x0008: return 8;          // method_handle
        case DEX_TYPE_MAP_LIST: return 0; // map_list entry itself (count is the list)
        default:    return 0;          // variable-size / unknown (string_data, code_item, ...)
    }
}

// ---- Dump mode ----
#define MODE_DEX 1
#define MODE_SO  2
#define MODE_ALL (MODE_DEX | MODE_SO)

// ---- Limits ----
#define MAX_PIDS         256
#define DEDUP_DEX_MAX    1024
#define DEDUP_SO_MAX     512

// ---- Parsed /proc/<pid>/maps region ----
typedef struct {
    uintptr_t start;
    uintptr_t end;
    char      perms[8];   // e.g. "r-xp"
    char      path[512];  // mapped file path ("" if anonymous)
} maps_region;

typedef struct {
    maps_region *regs;
    size_t       count;
} maps_list;

// ---- Cross-process / cross-snapshot de-dup tables ----
// DEX identity = the 20-byte SHA-1 signature recomputed in fix_dex_header_and_checksums
// (lives at offset 0x0C of a fixed DEX). Same content => same signature.
static uint8_t g_dex_sigs[DEDUP_DEX_MAX][20];
static int     g_dex_sig_count = 0;
// SO identity = resolved maps path (when present). Anonymous SOs dedup by base addr.
static char    g_so_paths[DEDUP_SO_MAX][512];
static int     g_so_path_count = 0;

static int dex_sig_seen(const uint8_t sig[20]) {
    for (int i = 0; i < g_dex_sig_count; i++)
        if (memcmp(g_dex_sigs[i], sig, 20) == 0) return 1;
    return 0;
}

static void dex_sig_remember(const uint8_t sig[20]) {
    if (g_dex_sig_count < DEDUP_DEX_MAX) {
        memcpy(g_dex_sigs[g_dex_sig_count], sig, 20);
        g_dex_sig_count++;
    }
}

static int so_path_seen(const char *path) {
    if (path[0] == '\0') return 0;
    for (int i = 0; i < g_so_path_count; i++)
        if (strcmp(g_so_paths[i], path) == 0) return 1;
    return 0;
}

static void so_path_remember(const char *path) {
    if (path[0] == '\0') return;
    if (g_so_path_count < DEDUP_SO_MAX) {
        strncpy(g_so_paths[g_so_path_count], path, sizeof(g_so_paths[0]) - 1);
        g_so_paths[g_so_path_count][sizeof(g_so_paths[0]) - 1] = '\0';
        g_so_path_count++;
    }
}

// ---- B5: decryption-state selection across watch rounds ----
// A packer may leave a SO's .text encrypted at scan time (or re-encrypt it). Across
// watch rounds the same SO base may appear in different states. We keep the snapshot
// whose executable segment looks most like real code: low Shannon entropy + many ARM
// prologue patterns. Encrypted/compressed text has entropy ~7.5-8.0 and ~random
// prologue hits; real ARM64 code has entropy ~5.5-6.8 and dense prologues.
//
// Per dumped SO we store {key, outfile, score}; on re-encounter we overwrite the file
// only if the new snapshot scores higher (more decrypted). Anonymous SOs key on a
// content hash of their first executable page instead of a path.

#define SO_BEST_MAX 512
typedef struct {
    char     key[512];     // maps path, or hex content-hash for anonymous SOs
    char     outfile[768];
    double   score;        // higher = more decrypted
    int      have;
} so_best;
static so_best g_so_best[SO_BEST_MAX];
static int    g_so_best_count = 0;

// Shannon entropy (bits/byte) over a buffer. 0..8.
static double buf_entropy(const uint8_t *p, size_t n) {
    if (n == 0) return 8.0;
    size_t hist[256] = {0};
    for (size_t i = 0; i < n; i++) hist[p[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (hist[i] == 0) continue;
        double pr = (double)hist[i] / (double)n;
        h -= pr * (log(pr) / log(2.0));
    }
    return h;
}

// Count ARM64 function-prologue-ish words in the text. Real code starts many
// functions with STP X29,X30,[SP,#imm] frame pushes. The store-STP family encodes
// with the high byte 0xA9; when Rt/Rt2 are X29(29)/X30(30) the low two bytes are
// 0xFD 0x7B (or 0x7B 0xFD if operand order is swapped). We also count SUB sp,sp,#imm.
// This is a cheap density signal: decrypted code is dense in these; encrypted/compressed
// text matches at ~random rates.
static size_t arm_prologue_hits(const uint8_t *p, size_t n) {
    size_t hits = 0;
    for (size_t i = 0; i + 4 <= n; i += 4) {
        uint8_t b0 = p[i], b1 = p[i+1], b3 = p[i+3];
        // STP X29, X30, [SP, #imm] (store): high byte 0xA9, low pair {0xFD,0x7B}
        if (b3 == 0xA9 &&
            ((b0 == 0xFD && b1 == 0x7B) || (b0 == 0x7B && b1 == 0xFD))) {
            hits++;
            continue;
        }
        // SUB sp, sp, #imm: 0xD1xxxxFF with Rd=31 (sp) in low 5 bits -> low byte 0xFF,
        // opcode bits 30..23 = 1001001 -> high byte 0xD1.
        if (b3 == 0xD1 && b0 == 0xFF) {
            hits++;
        }
    }
    return hits;
}

// Score a dumped SO's decryption state. Higher = more decrypted.
// `data`/`size` is the full SO image; `is_64` selects program-header layout.
// Finds the first executable PT_LOAD, scores its text: prologue_density - entropy.
// Returns -1.0 if no executable segment can be located (treat as neutral/keep).
static double so_text_score(const uint8_t *data, size_t size, int is_64) {
    if (size < 64) return -1.0;
    uint64_t e_phoff = 0; uint16_t e_phentsize = 0, e_phnum = 0;
    if (is_64) {
        memcpy(&e_phoff, data + 32, 8);
        e_phentsize = data[54] | (data[55] << 8);
        e_phnum = data[56] | (data[57] << 8);
    } else {
        uint32_t ph32 = 0; memcpy(&ph32, data + 28, 4); e_phoff = ph32;
        e_phentsize = data[42] | (data[43] << 8);
        e_phnum = data[44] | (data[45] << 8);
    }
    if (e_phnum == 0 || e_phentsize == 0 || e_phoff >= size) return -1.0;
    if (e_phoff + (uint64_t)e_phnum * (uint64_t)e_phentsize > size) return -1.0;

    for (int p = 0; p < e_phnum && p < 64; p++) {
        uint64_t base = e_phoff + (uint64_t)p * (uint64_t)e_phentsize;
        uint32_t p_type = 0, p_flags = 0;
        uint64_t p_vaddr = 0, p_filesz = 0;
        if (is_64) {
            memcpy(&p_type, data + base + 0, 4);
            memcpy(&p_flags, data + base + 4, 4);
            memcpy(&p_vaddr, data + base + 16, 8);
            memcpy(&p_filesz, data + base + 32, 8);
        } else {
            memcpy(&p_type, data + base + 0, 4);
            memcpy(&p_flags, data + base + 24, 4);
            uint32_t v32 = 0, f32 = 0;
            memcpy(&v32, data + base + 8, 4); p_vaddr = v32;
            memcpy(&f32, data + base + 16, 4); p_filesz = f32;
        }
        if (p_type != 1) continue;            // PT_LOAD
        if (!(p_flags & 0x1)) continue;        // PF_X (executable)
        if (p_filesz < 64) continue;
        if (p_vaddr + p_filesz > size) p_filesz = size - p_vaddr;  // clamp
        const uint8_t *text = data + p_vaddr;
        double ent = buf_entropy(text, (size_t)p_filesz);
        size_t hits = arm_prologue_hits(text, (size_t)p_filesz);
        double prologue_density = (double)hits / ((double)p_filesz / 4.0);
        // Higher prologue density and lower entropy => more decrypted.
        return prologue_density * 100.0 - ent;
    }
    return -1.0;
}

// Look up the best snapshot for a key. Returns the entry or NULL.
static so_best *so_best_find(const char *key) {
    if (key[0] == '\0') return NULL;
    for (int i = 0; i < g_so_best_count; i++)
        if (strcmp(g_so_best[i].key, key) == 0) return &g_so_best[i];
    return NULL;
}

// Record/update the best snapshot for a key. Returns 1 if this snapshot was kept
// (new best or first), 0 if discarded (an equal-or-better snapshot already exists).
static int so_best_record(const char *key, const char *outfile, double score) {
    so_best *e = so_best_find(key);
    if (e) {
        if (score > e->score) {
            e->score = score;
            strncpy(e->outfile, outfile, sizeof(e->outfile) - 1);
            e->outfile[sizeof(e->outfile) - 1] = '\0';
            return 1;  // replaced
        }
        return 0;  // kept existing (better) snapshot
    }
    if (g_so_best_count < SO_BEST_MAX) {
        so_best *n = &g_so_best[g_so_best_count++];
        strncpy(n->key, key, sizeof(n->key) - 1); n->key[sizeof(n->key) - 1] = '\0';
        strncpy(n->outfile, outfile, sizeof(n->outfile) - 1); n->outfile[sizeof(n->outfile) - 1] = '\0';
        n->score = score; n->have = 1;
        return 1;
    }
    return 1;  // table full: keep (best-effort)
}

// ---- Scan configuration (set in main, read by scan_pid) ----
static int g_region_delay_us = 0;  // usleep between regions (stealth mode)
static int g_relaxed = 0;          // --relaxed: scan for DEX without magic (endian_tag based)
static int g_relaxed_so = 0;       // --relaxed-so: scan for SO without ELF magic (structure based)
static int g_anon_only = 0;        // --anon: only scan anonymous mappings (faster, less crash-prone)
static int g_use_vm_readv = 0;     // --stealth2: use process_vm_readv instead of /proc/pid/mem

// pread with EINTR retry. Returns total bytes read into buf (<=want), or -1 on
// hard error before any byte. Avoids treating a transient signal as EOF.
static ssize_t pread_retry(int fd, void *buf, size_t want, off_t off) {
    size_t got = 0;
    while (got < want) {
        ssize_t r = pread(fd, (char *)buf + got, want - got, off + (off_t)got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;  // r==0 (EOF/hole) or hard error
    }
    return (ssize_t)got;
}

// Read remote process memory via process_vm_readv(2).
// Does NOT require opening /proc/<pid>/mem — much harder for packers to detect.
// Returns bytes read, or -1 on error.
static ssize_t vm_readv_retry(pid_t pid, void *buf, size_t want, uintptr_t remote_addr) {
    struct iovec local = { .iov_base = buf, .iov_len = want };
    struct iovec remote = { .iov_base = (void *)remote_addr, .iov_len = want };
    size_t got = 0;
    while (got < want) {
        local.iov_base = (char *)buf + got;
        local.iov_len = want - got;
        remote.iov_base = (void *)(remote_addr + got);
        remote.iov_len = want - got;
        ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    return (ssize_t)got;
}

// Validate a DEX hit to filter false-positive magic in random data.
// `magic_off` points at the "dex\n" within `buf` (n bytes available there).
// Returns 1 if the version tag + size + header fields look like a real DEX.
// Recover DEX file_size when the header field is erased/zero (FRIDA-DEXDump idea).
// `hdr` is a full 0x70 DEX header. We can't read the map_list from `hdr` alone
// (it lives at map_off, beyond the header), so this returns a *provisional* extent
// derived from the data section (data_off + data_size) when file_size is bad.
// The caller must then read the map_list from memory and finalize the real size
// via dex_recover_size_from_map_buf(). Returns 0 if no provisional size can be found.
static uint32_t dex_recover_size_provisional(const uint8_t *hdr) {
    uint32_t data_size = 0, data_off = 0;
    memcpy(&data_size, hdr + 0x68, 4);
    memcpy(&data_off,  hdr + 0x6C, 4);
    if (data_off == 0 || data_size == 0) return 0;
    uint64_t end = (uint64_t)data_off + (uint64_t)data_size;
    if (end < 0x70 || end > 0x10000000) return 0;
    return (uint32_t)end;
}

// Given a DEX memory image of `cap` bytes (read into a buffer by the caller),
// walk the map_list at map_off and compute the real extent = max over entries of
// (offset + count*item_size), including the map_list itself. Returns 0 on failure.
static uint32_t dex_recover_size_from_map_buf(const uint8_t *img, size_t cap, uint32_t map_off) {
    if (map_off < 0x70 || map_off + 4 > cap) return 0;
    uint32_t count = 0;
    memcpy(&count, img + map_off, 4);
    if (count == 0 || count > 50) return 0;  // a real DEX has <50 distinct section types
    uint32_t map_end = map_off + 4 + count * 12;
    if (map_end > cap) return 0;

    uint32_t extent = 0;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *ent = img + map_off + 4 + i * 12;
        uint16_t type = 0;
        uint32_t ecount = 0, eoff = 0;
        memcpy(&type, ent, 2);
        memcpy(&ecount, ent + 4, 4);
        memcpy(&eoff, ent + 8, 4);
        uint32_t isz = dex_map_item_size(type);
        if (isz == 0) continue;  // variable-size section: skip (can't compute extent)
        if (eoff == 0) continue;
        uint64_t end = (uint64_t)eoff + (uint64_t)ecount * (uint64_t)isz;
        if (end > extent && end <= 0x10000000) extent = (uint32_t)end;
    }
    if (map_end > extent) extent = map_end;  // map_list itself is part of the file
    if (extent < 0x70 || extent > 0x10000000) return 0;
    return extent;
}

// Strong confirmation that a candidate region is a real DEX (FRIDA-DEXDump keys):
//   (1) string_ids_off == 0x70  (string_ids table immediately follows the header)
//   (2) map_list contains a TYPE_MAP_LIST(0x1000) entry whose offset == header.map_off
// `img` is the DEX memory image (at least up to map_end), `cap` its readable size.
// These are the structural signals FRIDA-DEXDump uses to confirm a DEX when the
// magic has been erased; they cut false positives vs endian_tag alone.
static int dex_confirm_by_map_list(const uint8_t *img, size_t cap, uint32_t map_off,
                                   uint32_t string_ids_off) {
    if (string_ids_off != 0x70) return 0;  // (1) header immediately followed by string_ids
    if (map_off < 0x70 || map_off + 4 > cap) return 0;
    uint32_t count = 0;
    memcpy(&count, img + map_off, 4);
    if (count == 0 || count > 50) return 0;
    if (map_off + 4 + (size_t)count * 12 > cap) return 0;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *ent = img + map_off + 4 + i * 12;
        uint16_t type = 0;
        uint32_t eoff = 0;
        memcpy(&type, ent, 2);
        memcpy(&eoff, ent + 8, 4);
        if (type == DEX_TYPE_MAP_LIST && eoff == map_off) return 1;  // (2) self-reference
    }
    return 0;
}

// Identify an ELF SO at a page boundary even when the "\x7fELF" magic has been
// erased by a packer (B4, SO-side equivalent of DEX --relaxed). Header-level
// structural check (full PT_LOAD validation happens later in fix_so.py):
//   - EI_CLASS (byte 4) == 1 or 2 (32/64-bit)
//   - e_type (offset 16) == ET_DYN(3)
//   - e_machine (offset 18) == EM_ARM(40) or EM_AARCH64(183)
//   - e_phoff/e_phentsize/e_phnum sane
// Returns 1 and fills *out_is_64 if the header looks like a magic-erased SO.
// (If the magic is intact, the standard scan already handled it; callers skip those.)
static int elf_so_struct_valid(const uint8_t *hdr, size_t hdr_len, int *out_is_64) {
    if (hdr_len < 64) return 0;
    uint8_t ei_class = hdr[4];
    if (ei_class != 1 && ei_class != 2) return 0;
    int is_64 = (ei_class == 2);
    uint16_t e_type = hdr[16] | (hdr[17] << 8);
    if (e_type != 3) return 0;  // ET_DYN
    uint16_t e_machine = hdr[18] | (hdr[19] << 8);
    if (e_machine != 40 && e_machine != 183) return 0;  // EM_ARM / EM_AARCH64

    uint64_t e_phoff = 0;
    uint16_t e_phentsize = 0, e_phnum = 0;
    if (is_64) {
        memcpy(&e_phoff, hdr + 32, 8);
        e_phentsize = hdr[54] | (hdr[55] << 8);
        e_phnum = hdr[56] | (hdr[57] << 8);
    } else {
        uint32_t ph32 = 0;
        memcpy(&ph32, hdr + 28, 4);
        e_phoff = ph32;
        e_phentsize = hdr[42] | (hdr[43] << 8);
        e_phnum = hdr[44] | (hdr[45] << 8);
    }
    if (e_phnum == 0 || e_phnum > 64) return 0;
    if (e_phentsize == 0) return 0;
    if (e_phoff < 64 || e_phoff > 0x100000) return 0;

    if (out_is_64) *out_is_64 = is_64;
    return 1;
}

static int dex_hit_valid(const uint8_t *buf, size_t n, size_t magic_off, uint32_t *out_size) {
    // version tag: bytes after magic must start with a digit (covers 035..041).
    size_t v = magic_off + 4;
    if (v >= n) return 0;
    if (!isdigit((unsigned char)buf[v])) return 0;

    // Read file_size (0x20) either from this page or via a fresh header read.
    uint32_t dex_size = 0;
    if (magic_off + 0x24 <= n) {
        memcpy(&dex_size, buf + magic_off + 0x20, 4);
    } else {
        // Header crosses the page boundary; caller will re-read full header.
        // Accept for now, full validation happens after we read it.
        *out_size = 0;
        return 1;
    }

    // Header cross-checks (sanity): header_size==0x70, key offsets within file.
    uint32_t header_size = 0, string_ids_off = 0, class_defs_off = 0;
    memcpy(&header_size, buf + magic_off + 0x24, 4);
    memcpy(&string_ids_off, buf + magic_off + 0x3c, 4);
    memcpy(&class_defs_off, buf + magic_off + 0x64, 4);
    if (header_size != 0x70) return 0;

    // file_size erased/zero (FRIDA-DEXDump case): defer — caller recovers size
    // from the map_list via dex_recover_size_from_map(). Signal with *out_size = 0
    // and return 1, but only if the structural cross-checks still hold against a
    // generous upper bound (we can't trust file_size here, so check < 0x10000000).
    if (dex_size == 0 || dex_size < 0x70 || dex_size > 0x10000000) {
        // Use the in-page map_off if available to sanity-check structure; otherwise
        // require the caller to re-read a full header. Accept deferred recovery.
        *out_size = 0;
        return 1;
    }
    if (string_ids_off >= dex_size) return 0;
    if (class_defs_off >= dex_size) return 0;

    *out_size = dex_size;
    return 1;
}

// Validate a DEX header by structural features alone (no magic required).
// Used for second-gen extraction shells that erase the "dex\n" magic.
// Checks: endian_tag == 0x12345678, header_size == 0x70, file_size sane,
// key section offsets within file, section counts reasonable.
// DEX header layout (from art/libdexfile/dex/dex_file.h):
//   0x00 magic[8], 0x08 checksum, 0x0C signature[20],
//   0x20 file_size, 0x24 header_size, 0x28 endian_tag,
//   0x2C link_size, 0x30 link_off, 0x34 map_off,
//   0x38 string_ids_size, 0x3C string_ids_off,
//   0x40 type_ids_size,   0x44 type_ids_off,
//   0x48 proto_ids_size,  0x4C proto_ids_off,
//   0x50 field_ids_size,  0x54 field_ids_off,
//   0x58 method_ids_size, 0x5C method_ids_off,
//   0x60 class_defs_size, 0x64 class_defs_off,
//   0x68 data_size,       0x6C data_off
static int dex_header_relaxed_valid(const uint8_t *hdr, size_t hdr_len, uint32_t *out_size) {
    if (hdr_len < 0x70) return 0;

    // endian_tag at offset 0x28 must be 0x12345678
    uint32_t endian_tag = 0;
    memcpy(&endian_tag, hdr + 0x28, 4);
    if (endian_tag != kDexEndianTag) return 0;

    // header_size at offset 0x24 must be 0x70
    uint32_t header_size = 0;
    memcpy(&header_size, hdr + 0x24, 4);
    if (header_size != 0x70) return 0;

    // file_size at offset 0x20: if erased/zero (FRIDA-DEXDump case), defer — the
    // caller recovers the real size from the map_list. Require it to be 0 or sane
    // (reject clearly-garbage values like 1..0x6F or >0x10000000).
    uint32_t file_size = 0;
    memcpy(&file_size, hdr + 0x20, 4);
    if (file_size != 0 && (file_size < 0x70 || file_size > 0x10000000)) return 0;
    uint32_t size_cap = (file_size != 0) ? file_size : 0x10000000;  // generous bound when erased

    // Read key section fields
    uint32_t string_ids_size = 0, string_ids_off = 0;
    uint32_t type_ids_size = 0,   type_ids_off = 0;
    uint32_t method_ids_size = 0, method_ids_off = 0;
    uint32_t class_defs_size = 0, class_defs_off = 0;
    uint32_t data_size = 0,       data_off = 0;
    memcpy(&string_ids_size, hdr + 0x38, 4);
    memcpy(&string_ids_off,  hdr + 0x3C, 4);
    memcpy(&type_ids_size,   hdr + 0x40, 4);
    memcpy(&type_ids_off,    hdr + 0x44, 4);
    memcpy(&method_ids_size, hdr + 0x58, 4);
    memcpy(&method_ids_off,  hdr + 0x5C, 4);
    memcpy(&class_defs_size, hdr + 0x60, 4);
    memcpy(&class_defs_off,  hdr + 0x64, 4);
    memcpy(&data_size,       hdr + 0x68, 4);
    memcpy(&data_off,        hdr + 0x6C, 4);

    // class_defs must be present — a DEX without classes is useless
    if (class_defs_size == 0) return 0;
    if (class_defs_off == 0 || class_defs_off >= size_cap) return 0;

    // class_defs occupy class_defs_size * 32 bytes, must fit in file
    uint32_t class_defs_bytes = class_defs_size * 32;
    if (class_defs_off + class_defs_bytes > size_cap) return 0;

    // string_ids and type_ids offsets must be within file (if present)
    if (string_ids_off != 0 && string_ids_off >= size_cap) return 0;
    if (type_ids_off != 0 && type_ids_off >= size_cap) return 0;

    // data section should fit within file (if present)
    if (data_off != 0 && data_size != 0) {
        if (data_off >= size_cap || data_off + data_size > size_cap) return 0;
    }

    // file_size erased → defer (caller recovers from map_list). A2 confirmation
    // (map_list self-reference) happens at the call site, so returning size 0 here
    // is safe — the caller only trusts it after dex_confirm_by_map_list passes.
    *out_size = file_size;
    return 1;
}

// ---- Anti-detection: rename our process so /proc/<pid>/comm and
// /proc/<pid>/cmdline no longer read "nhdd ...". Defeats packers that scan
// /proc/*/comm and /proc/*/cmdline for known tool names.
//
// Limitation: a packer running in the TARGET app context cannot ptrace our
// root process, so it cannot observe our syscall sequence — only our names.
// We can't fully hide from a detector that cross-checks comm vs path/owner,
// but this defeats the common /proc name scanners (e.g. zero-run/bangbang).
static void disguise_self(int argc, char **argv, const char *name) {
    if (!name || !*name || argc < 1) return;

    // 1) /proc/self/comm — 16 bytes incl. NUL (kernel truncates).
    char comm[16];
    snprintf(comm, sizeof(comm), "%s", name);
    prctl(PR_SET_NAME, (unsigned long)comm, 0, 0, 0);

    // 2) /proc/self/cmdline — the kernel reads the WHOLE arg region
    // [arg_start, arg_end); NULs are separators, not terminators, so argv[1..]
    // (target package, paths) would still be exposed. To hide them we zero the
    // entire region argv[0]..argv[argc-1]+NUL, then write the fake name at the
    // start. cmdline then reads only the fake name + empty args.
    // Caller MUST have copied any argv strings it still needs (see main): we are
    // about to destroy them.
    char *start = argv[0];
    char *end = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    if (end <= start) return;
    size_t cap = (size_t)(end - start);
    size_t nl = strlen(name);
    if (nl >= cap) nl = cap - 1;
    memset(start, 0, cap);
    memcpy(start, name, nl);
    start[nl] = '\0';
}

// ---- Package name resolution ----
static int read_cmdline(const char *pid, char *out, size_t outsz) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, out, outsz - 1);
    close(fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    char *colon = strchr(out, ':');
    if (colon) *colon = '\0';
    return 0;
}

// Collect ALL pids whose (colon-stripped) cmdline equals pkg.
// Returns count, fills pids[]. This is the key to catching child processes
// where the real decrypted DEX actually lives.
static int find_pids_for_package(const char *pkg, char pids[][16], size_t pid_sz, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    int count = 0;
    while ((de = readdir(d))) {
        const char *n = de->d_name;
        int all_digit = 1;
        for (const char *c = n; *c; c++)
            if (!isdigit((unsigned char)*c)) { all_digit = 0; break; }
        if (!all_digit) continue;
        char cmd[256];
        if (read_cmdline(n, cmd, sizeof(cmd)) != 0) continue;
        if (strcmp(cmd, pkg) != 0) continue;
        if (count >= max) break;
        snprintf(pids[count], pid_sz, "%s", n);
        count++;
    }
    closedir(d);
    return count;
}

// ---- Minimal SHA-1 (inline, no deps) ----
typedef struct { uint32_t state[5]; uint64_t count; uint8_t buffer[64]; } SHA1_CTX;
#define ROL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void sha1_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = ROL(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if      (i<20) { f=(b&c)|(~b&d); k=0x5A827999; }
        else if (i<40) { f=b^c^d;         k=0x6ED9EBA1; }
        else if (i<60) { f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else           { f=b^c^d;         k=0xCA62C1D6; }
        uint32_t tmp = ROL(a,5)+f+e+k+w[i]; e=d; d=c; c=ROL(b,30); b=a; a=tmp;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
}

static void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0]=0x67452301; ctx->state[1]=0xEFCDAB89;
    ctx->state[2]=0x98BADCFE; ctx->state[3]=0x10325476;
    ctx->state[4]=0xC3D2E1F0; ctx->count=0;
}

static void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)(ctx->count % 64);
    ctx->count += len;
    size_t i = 0;
    if (idx) {
        size_t need = 64 - idx;
        if (len < need) { memcpy(ctx->buffer+idx, data, len); return; }
        memcpy(ctx->buffer+idx, data, need);
        sha1_transform(ctx->state, ctx->buffer);
        i = need;
    }
    for (; i+64 <= len; i += 64) sha1_transform(ctx->state, data+i);
    if (i < len) memcpy(ctx->buffer+idx, data+i, len-i);
}

static void sha1_final(SHA1_CTX *ctx, uint8_t digest[20]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while ((ctx->count % 64) != 56) sha1_update(ctx, &zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56-i*8));
    sha1_update(ctx, len_be, 8);
    for (int i = 0; i < 5; i++) {
        digest[i*4]  =(uint8_t)(ctx->state[i]>>24);
        digest[i*4+1]=(uint8_t)(ctx->state[i]>>16);
        digest[i*4+2]=(uint8_t)(ctx->state[i]>>8);
        digest[i*4+3]=(uint8_t)(ctx->state[i]);
    }
}

// ---- Adler-32 (RFC 1950) ----
#define ADLER32_BASE 65521
static uint32_t my_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % ADLER32_BASE;
        b = (b + a) % ADLER32_BASE;
    }
    return (b << 16) | a;
}

// ---- Fix DEX header + checksums (SHA-1 + Adler32) ----
// Also fills the recomputed SHA-1 signature into the buffer (offset 0x0C).
static void fix_dex_header_and_checksums(uint8_t *data, size_t size) {
    if (size < 0x70 || memcmp(data, kDexMagic, 4) != 0) return;

    // DEX fields are little-endian on Android.
    uint32_t file_size = (uint32_t)size;
    uint32_t header_size = 0x70;
    uint32_t endian_tag = 0x12345678;
    memcpy(data + 0x20, &file_size, 4);
    memcpy(data + 0x24, &header_size, 4);
    memcpy(data + 0x28, &endian_tag, 4);

    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data + 0x20, size - 0x20);
    uint8_t sha1[20];
    sha1_final(&ctx, sha1);
    memcpy(data + 0x0C, sha1, 20);

    uint32_t cksum = my_adler32(data + 0x0C, size - 0x0C);
    memcpy(data + 0x08, &cksum, 4);
}

// ---- Load /proc/<pid>/maps into memory once, reused for scanning & SO lookup ----
static maps_list *load_maps(const char *pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    maps_list *ml = calloc(1, sizeof(maps_list));
    if (!ml) { fclose(f); return NULL; }
    size_t cap = 512;
    ml->regs = calloc(cap, sizeof(maps_region));
    if (!ml->regs) { fclose(f); free(ml); return NULL; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (ml->count == cap) {
            cap *= 2;
            maps_region *nr = realloc(ml->regs, cap * sizeof(maps_region));
            if (!nr) break;
            ml->regs = nr;
            memset(ml->regs + ml->count, 0, (cap - ml->count) * sizeof(maps_region));
        }
        maps_region *r = &ml->regs[ml->count];
        memset(r, 0, sizeof(*r));

        // addr range + perms always present.
        if (sscanf(line, "%lx-%lx %7s", &r->start, &r->end, r->perms) < 3) continue;

        // Pathname (optional): the 6th whitespace-delimited field. Walk past
        // start-end/perms/offset/dev/inode, then capture the rest as the path.
        // Robust against anonymous mappings that have no path token.
        const char *p = strchr(line, '\n');
        char tmp[768];
        snprintf(tmp, sizeof(tmp), "%s", line);
        // Find the path: take substring after the inode field.
        int fields = 0;
        char *q = tmp;
        while (fields < 5 && *q) {
            while (*q == ' ') q++;
            if (!*q) break;
            while (*q && *q != ' ') q++;
            fields++;
        }
        if (fields == 5) {
            while (*q == ' ') q++;
            // q now points at the path (or end of line). Trim trailing newline.
            size_t plen = strlen(q);
            while (plen > 0 && (q[plen-1] == '\n' || q[plen-1] == '\r' ||
                               q[plen-1] == ' ' || q[plen-1] == '\t')) {
                q[--plen] = '\0';
            }
            snprintf(r->path, sizeof(r->path), "%s", q);
        }
        (void)p;
        ml->count++;
    }
    fclose(f);
    return ml;
}

static void free_maps(maps_list *ml) {
    if (!ml) return;
    free(ml->regs);
    free(ml);
}

// Find the SO's full contiguous extent by walking forward over regions that
// share the same mapped path. ELF segments of one .so are mapped adjacently.
static uintptr_t so_extent_end(const maps_list *ml, size_t idx, uintptr_t base_end) {
    if (!ml || idx >= ml->count) return base_end;
    const char *path = ml->regs[idx].path;
    uintptr_t end = ml->regs[idx].end;
    for (size_t i = idx + 1; i < ml->count; i++) {
        const maps_region *r = &ml->regs[i];
        // Stop at a gap or when the path changes / becomes a different file.
        if (r->start > end + (1U << 20)) break;          // large hole => different area
        if (path[0] != '\0' && strcmp(r->path, path) != 0) {
            // Allow an anonymous continuation of the same SO (writable data etc.)
            if (r->path[0] != '\0') break;
        }
        end = r->end;
    }
    return end > base_end ? end : base_end;
}

// ---- Extract basename from path ----
static const char *my_basename(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

// ---- Filter out system noise from SO dumping ----
// nhdd matches ANY \x7fELF + ET_DYN in memory, which pulls in a lot of system
// artifacts that are useless for unpacking: ART AOT output (.oat/.odex/.art/.vdex),
// the dynamic linker, the zygote entry point, [vdso], and APK files mmap'd whole.
// Anonymous SOs (no maps path) are KEPT — these are often packer-injected/decrypted
// native libraries, exactly what unpacking wants to catch. Returns 1 if the SO should
// be skipped as system noise, 0 to keep.
static int so_is_system_noise(const char *so_path) {
    // Anonymous mapping: never noise (keep — likely packer-injected/decrypted SO).
    if (so_path[0] == '\0') return 0;

    // System directory prefixes: /system/ /apex/ /data/dalvik-cache/ /dev/__properties__
    if (strncmp(so_path, "/system/", 8) == 0) return 1;
    if (strncmp(so_path, "/apex/", 6) == 0) return 1;
    if (strncmp(so_path, "/data/dalvik-cache", 17) == 0) return 1;
    if (strncmp(so_path, "/dev/", 5) == 0) return 1;

    const char *bname = my_basename(so_path);
    // [vdso] — kernel virtual dynamic shared object
    if (bname[0] == '[') return 1;

    size_t blen = strlen(bname);
    // ART AOT/ODEX output by extension
    if (blen >= 5 && (strcmp(bname + blen - 4, ".oat") == 0 ||
                      strcmp(bname + blen - 5, ".odex") == 0 ||
                      strcmp(bname + blen - 5, ".art") == 0 ||
                      strcmp(bname + blen - 5, ".vdex") == 0)) return 1;
    // APK files mmap'd whole (the ELF we saw was the APK's internal zip structure)
    if (blen >= 4 && strcmp(bname + blen - 4, ".apk") == 0) return 1;
    // Dynamic linker / zygote entry
    if (strcmp(bname, "linker64") == 0 || strcmp(bname, "linker") == 0 ||
        strcmp(bname, "linker_asan") == 0 || strcmp(bname, "linker_asan64") == 0)
        return 1;
    if (strncmp(bname, "app_process", 11) == 0) return 1;

    return 0;
}

// Counters carried across PID + snapshot iterations.
typedef struct {
    int dex_unique;     // DEX actually written to disk
    int dex_dedup;      // DEX skipped as duplicates of an already-dumped one
    int dex_total;      // every DEX magic hit
    int so_count;       // SO files written
    int procs;          // number of process scans performed
} counters;

// ---- Scan a single PID. Uses shared global de-dup tables. ----
// Returns 0 if the process was dead/inaccessible, 1 if scanned.
static int scan_pid(const char *pid, const char *dex_dir, const char *so_dir,
                    int mode, counters *c) {
    char pkg[256] = "unknown";
    read_cmdline(pid, pkg, sizeof(pkg));

    maps_list *ml = load_maps(pid);
    if (!ml) {
        fprintf(stderr, "[-] PID %s (%s): process gone (cannot read maps)\n", pid, pkg);
        return 0;
    }

    pid_t target_pid = (pid_t)atoi(pid);
    int mem_fd = -1;

    // --stealth2: use process_vm_readv instead of /proc/pid/mem
    // This avoids opening the mem file, which packers can detect via /proc/self/fd.
    if (!g_use_vm_readv) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%s/mem", pid);
        mem_fd = open(path, O_RDONLY);
        if (mem_fd < 0) {
            fprintf(stderr, "[-] PID %s (%s): cannot open mem: %s\n", pid, pkg, strerror(errno));
            free_maps(ml);
            return 0;
        }
    }

    // Helper macro: read remote memory using the selected method
    #define READ_REMOTE(buf, size, addr) ({ \
        ssize_t _rr; \
        if (g_use_vm_readv) { \
            _rr = vm_readv_retry(target_pid, (buf), (size), (addr)); \
        } else { \
            _rr = pread_retry(mem_fd, (buf), (size), (off_t)(addr)); \
        } \
        _rr; \
    })

    c->procs++;
    fprintf(stderr, "[*] Scanning PID %s (%s): %zu regions%s\n", pid, pkg, ml->count,
            g_use_vm_readv ? " (stealth2: vm_readv)" : "");

    uint8_t buf[4096];
    // Per-PID SO base de-dup (same base within one process is the same SO).
    uintptr_t dumped_so_bases[256];
    int dumped_so_base_count = 0;
    int pid_dex_unique = 0, pid_dex_seen = 0;

    for (size_t ri = 0; ri < ml->count; ri++) {
        maps_region *r = &ml->regs[ri];
        if (r->perms[0] != 'r') continue;

        size_t region_size = r->end - r->start;
        if (region_size < 64 || region_size > 0x40000000) continue;

        // --anon: skip regions backed by a file (system libs, OAT, VDEX, etc.)
        // DEX loaded by packers is almost always in anonymous memory.
        if (g_anon_only && r->path[0] != '\0') continue;

        // Stealth: brief pause between regions to look less like bulk extraction.
        if (g_region_delay_us > 0) usleep((useconds_t)g_region_delay_us);

        for (uintptr_t addr = r->start; addr < r->end; addr += 4096) {
            ssize_t n = READ_REMOTE(buf, sizeof(buf), addr);
            if (n < 64) continue;

            for (int i = 0; i <= n - 4; i++) {
                // ---- DEX scanning (standard: "dex\n" magic) ----
                if ((mode & MODE_DEX) && memcmp(buf + i, kDexMagic, 4) == 0) {
                    uintptr_t dex_addr = addr + i;

                    // Validate the hit (version tag + header cross-checks) to
                    // reject false-positive magic in random data.
                    uint32_t dex_size = 0;
                    if (!dex_hit_valid(buf, (size_t)n, (size_t)i, &dex_size)) {
                        // Header may cross the page; re-read a full 0x70 header.
                        uint8_t hdr[0x70];
                        if (READ_REMOTE(hdr, 0x70, dex_addr) == 0x70) {
                            if (dex_hit_valid(hdr, 0x70, 0, &dex_size)) goto dex_accept;
                        }
                        continue;
                    }
                dex_accept:;
                    // file_size erased (FRIDA-DEXDump case): dex_hit_valid deferred
                    // with *out_size = 0. Recover the real size from the map_list.
                    if (dex_size == 0) {
                        uint8_t hdr[0x70];
                        if (READ_REMOTE(hdr, 0x70, dex_addr) != 0x70) continue;
                        uint32_t map_off = 0;
                        memcpy(&map_off, hdr + 0x34, 4);
                        // Provisional extent from the data section, to bound our read.
                        uint32_t prov = dex_recover_size_provisional(hdr);
                        if (prov < 0x70) {
                            // No data section hint: fall back to scanning up to 1MB.
                            prov = 0x100000;
                        }
                        // Read that much of the DEX image to walk its map_list.
                        uint8_t *img = (uint8_t *)calloc(1, prov);
                        if (!img) continue;
                        size_t got = 0;
                        while (got < prov) {
                            ssize_t rr = READ_REMOTE(img + got, prov - got, dex_addr + got);
                            if (rr <= 0) break;
                            got += (size_t)rr;
                        }
                        uint32_t recovered = dex_recover_size_from_map_buf(img, got, map_off);
                        uint32_t string_ids_off = 0;
                        memcpy(&string_ids_off, hdr + 0x3C, 4);
                        // A2: confirm it's really a DEX via the map_list self-reference.
                        int confirmed = dex_confirm_by_map_list(img, got, map_off, string_ids_off);
                        free(img);
                        if (recovered == 0 || !confirmed) continue;
                        dex_size = recovered;
                    }
                    if (dex_size < 0x70 || dex_size > 0x10000000) continue;

                    c->dex_total++;
                    pid_dex_seen++;
                    fprintf(stderr, "[+] PID %s: DEX hit at 0x%lx size=%u\n",
                           pid, (unsigned long)dex_addr, dex_size);

                    uint8_t *dex_data = (uint8_t *)calloc(1, dex_size);
                    if (!dex_data) { fprintf(stderr, "[-] calloc failed\n"); continue; }

                    // Read page-by-page instead of one huge contiguous pread.
                    // calloc already zero-fills, so unreadable holes become zeros —
                    // the file stays dex_size bytes with valid offsets for jadx.
                    size_t readable_total = 0;
                    int missing_pages = 0;
                    for (size_t off = 0; off < dex_size; off += 4096) {
                        size_t todo = dex_size - off;
                        if (todo > 4096) todo = 4096;
                        ssize_t rr = READ_REMOTE(dex_data + off, todo, dex_addr + off);
                        if (rr > 0) {
                            readable_total += (size_t)rr;
                            if ((size_t)rr < todo) missing_pages++;
                        } else {
                            missing_pages++;
                        }
                    }

                    if (readable_total == 0) { free(dex_data); continue; }

                    fix_dex_header_and_checksums(dex_data, dex_size);

                    // De-dup by recomputed SHA-1 signature (offset 0x0C).
                    const uint8_t *sig = dex_data + 0x0C;
                    if (dex_sig_seen(sig)) {
                        c->dex_dedup++;
                        fprintf(stderr, "[=] PID %s: DEX at 0x%lx is a duplicate, skipped\n",
                               pid, (unsigned long)dex_addr);
                        free(dex_data);
                        i += (dex_size > 4096 ? 4096 : dex_size);
                        continue;
                    }
                    dex_sig_remember(sig);
                    pid_dex_unique++;

                    char outfile[768];
                    snprintf(outfile, sizeof(outfile),
                             "%s/dump_%s_%d.dex", dex_dir, pid, pid_dex_seen);

                    int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                    if (fd >= 0) {
                        size_t written_total = 0;
                        while (written_total < dex_size) {
                            ssize_t w = write(fd, dex_data + written_total, dex_size - written_total);
                            if (w <= 0) break;
                            written_total += (size_t)w;
                        }
                        close(fd);
                        if (written_total == dex_size) {
                            c->dex_unique++;
                            printf("[+] DEX: %s (%u bytes, readable=%zu, zero_pages=%d) pid=%s\n",
                                   outfile, dex_size, readable_total, missing_pages, pid);
                        } else {
                            fprintf(stderr, "[-] write failed/truncated for %s: %s\n", outfile, strerror(errno));
                        }
                    }
                    free(dex_data);
                    i += (dex_size > 4096 ? 4096 : dex_size);
                }

                // ---- SO (ELF) scanning ----
                if ((mode & MODE_SO) && memcmp(buf + i, kElfMagic, 4) == 0) {
                    uintptr_t elf_addr = addr + i;
                    // Only treat page-boundary ELF as a real SO start.
                    if (i != 0) continue;

                    // Per-PID base de-dup.
                    int already = 0;
                    for (int j = 0; j < dumped_so_base_count; j++)
                        if (dumped_so_bases[j] == elf_addr) { already = 1; break; }
                    if (already) continue;

                    uint8_t elf_hdr[64];
                    if (READ_REMOTE(elf_hdr, 64, elf_addr) < 64) continue;

                    int is_64 = (elf_hdr[4] == 2);
                    if (elf_hdr[4] != 1 && elf_hdr[4] != 2) continue;

                    uint16_t e_type = elf_hdr[16] | (elf_hdr[17] << 8);
                    if (e_type != 3) continue; // ET_DYN only

                    // SO name from the maps region we are inside.
                    const char *so_path = r->path;
                    // Skip system noise: ART AOT output (.oat/.odex/.art/.vdex), linker,
                    // app_process, [vdso], APK files, and /system /apex /dalvik-cache libs.
                    // Anonymous SOs (no path) are kept — those are often packer-injected.
                    if (so_is_system_noise(so_path)) {
                        i += 4096;
                        continue;
                    }
                    // B5: no longer skip-by-path here. We dump into a buffer, score its
                    // decryption state, and keep the best snapshot across watch rounds.
                    // (Anonymous SOs key on a content hash below.)

                    // SO extent = contiguous same-path regions, not just this line.
                    uintptr_t so_end = so_extent_end(ml, ri, r->end);
                    uintptr_t so_start = elf_addr;
                    size_t max_so_size = 64 * 1024 * 1024;
                    size_t so_size = so_end - so_start;
                    if (so_size > max_so_size) so_size = max_so_size;

                    // Refine size from ELF program headers if smaller & sane.
                    if (is_64) {
                        uint64_t e_phoff = 0;
                        memcpy(&e_phoff, elf_hdr + 32, 8);
                        uint16_t e_phentsize = elf_hdr[54] | (elf_hdr[55] << 8);
                        uint16_t e_phnum = elf_hdr[56] | (elf_hdr[57] << 8);
                        uint64_t max_addr = 0;
                        for (int p = 0; p < e_phnum && p < 32; p++) {
                            uint8_t phdr[56];
                            if (READ_REMOTE(phdr, 56, elf_addr + e_phoff + p * e_phentsize) < 56) break;
                            uint32_t p_type = 0;
                            memcpy(&p_type, phdr, 4);
                            if (p_type != 1) continue;
                            uint64_t p_vaddr = 0, p_memsz = 0;
                            memcpy(&p_vaddr, phdr + 16, 8);
                            memcpy(&p_memsz, phdr + 40, 8);
                            uint64_t seg_end = p_vaddr + p_memsz;
                            if (seg_end > max_addr) max_addr = seg_end;
                        }
                        if (max_addr > 0 && max_addr < so_size) so_size = (size_t)max_addr;
                    } else {
                        uint32_t e_phoff = 0;
                        memcpy(&e_phoff, elf_hdr + 28, 4);
                        uint16_t e_phentsize = elf_hdr[42] | (elf_hdr[43] << 8);
                        uint16_t e_phnum = elf_hdr[44] | (elf_hdr[45] << 8);
                        uint32_t max_addr = 0;
                        for (int p = 0; p < e_phnum && p < 32; p++) {
                            uint8_t phdr[32];
                            if (READ_REMOTE(phdr, 32, elf_addr + e_phoff + p * e_phentsize) < 32) break;
                            uint32_t p_type = 0;
                            memcpy(&p_type, phdr, 4);
                            if (p_type != 1) continue;
                            uint32_t p_vaddr = 0, p_memsz = 0;
                            memcpy(&p_vaddr, phdr + 12, 4);
                            memcpy(&p_memsz, phdr + 20, 4);
                            uint32_t seg_end = p_vaddr + p_memsz;
                            if (seg_end > max_addr) max_addr = seg_end;
                        }
                        if (max_addr > 0 && max_addr < so_size) so_size = (size_t)max_addr;
                    }

                    if (dumped_so_base_count < 256) dumped_so_bases[dumped_so_base_count++] = elf_addr;

                    char outfile[768];
                    if (so_path[0] != '\0') {
                        const char *bname = my_basename(so_path);
                        snprintf(outfile, sizeof(outfile), "%s/%s", so_dir, bname);
                    } else {
                        snprintf(outfile, sizeof(outfile), "%s/so_%s_%d.so", so_dir, pid, c->so_count + 1);
                    }

                    uint8_t *so_data = (uint8_t *)malloc(so_size);
                    if (!so_data) { fprintf(stderr, "[-] malloc failed\n"); continue; }

                    ssize_t read_total = 0;
                    while (read_total < (ssize_t)so_size) {
                        ssize_t rr = READ_REMOTE(so_data + read_total,
                                          so_size - read_total,
                                          elf_addr + read_total);
                        if (rr <= 0) break;
                        read_total += rr;
                    }

                    if (read_total > 0) {
                        // B5: score this snapshot's decryption state (text entropy +
                        // ARM prologue density). Keep the best across watch rounds.
                        double score = so_text_score(so_data, (size_t)read_total, is_64);
                        const char *key = so_path[0] ? so_path : outfile;  // anon SOs key on outfile name
                        int kept = so_best_record(key, outfile, score);
                        if (kept) {
                            int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                            if (fd >= 0) {
                                write(fd, so_data, read_total);
                                close(fd);
                                so_path_remember(so_path);
                                c->so_count++;
                                printf("[+] SO: %s (%zd bytes) score=%.1f from %s pid=%s\n",
                                       outfile, read_total, score, so_path[0] ? so_path : "(anon)", pid);
                            }
                        } else {
                            // A better (more decrypted) snapshot already exists; discard this one.
                            fprintf(stderr, "[=] PID %s: SO at 0x%lx score=%.1f not better than existing, skipped\n",
                                   pid, (unsigned long)elf_addr, score);
                        }
                    }
                    free(so_data);
                    i += 4096;
                }

                // ---- Relaxed SO scanning (ELF magic erased, structure-based) ----
                // B4: for packers that erase the "\x7fELF" magic. At each page start,
                // if --relaxed-so is on and the magic is NOT intact, check whether the
                // 64-byte header is structurally a valid ET_DYN SO. If so, dump it; the
                // dumped file will have a zeroed magic, which fix_so.py restores.
                if (g_relaxed_so && (mode & MODE_SO) && i == 0 &&
                    memcmp(buf, kElfMagic, 4) != 0) {
                    uintptr_t elf_addr = addr;

                    // Per-PID base de-dup.
                    int already = 0;
                    for (int j = 0; j < dumped_so_base_count; j++)
                        if (dumped_so_bases[j] == elf_addr) { already = 1; break; }
                    if (!already) {
                        uint8_t elf_hdr[64];
                        int is_64 = 0;
                        if (READ_REMOTE(elf_hdr, 64, elf_addr) == 64 &&
                            elf_so_struct_valid(elf_hdr, 64, &is_64)) {
                            const char *so_path = r->path;
                            // Skip system noise (same filter as standard scan).
                            if (so_is_system_noise(so_path)) {
                                i += 4096;
                                continue;
                            }
                            // B5: don't skip-by-path; score & keep best snapshot instead.
                            {
                                // SO extent = contiguous same-path regions.
                                uintptr_t so_end = so_extent_end(ml, ri, r->end);
                                size_t max_so_size = 64 * 1024 * 1024;
                                size_t so_size = so_end - elf_addr;
                                if (so_size > max_so_size) so_size = max_so_size;

                                // Refine size from program headers (same logic as standard scan).
                                if (is_64) {
                                    uint64_t e_phoff = 0; memcpy(&e_phoff, elf_hdr + 32, 8);
                                    uint16_t e_phentsize = elf_hdr[54] | (elf_hdr[55] << 8);
                                    uint16_t e_phnum = elf_hdr[56] | (elf_hdr[57] << 8);
                                    uint64_t max_addr = 0;
                                    for (int p = 0; p < e_phnum && p < 32; p++) {
                                        uint8_t phdr[56];
                                        if (READ_REMOTE(phdr, 56, elf_addr + e_phoff + p * e_phentsize) < 56) break;
                                        uint32_t p_type = 0; memcpy(&p_type, phdr, 4);
                                        if (p_type != 1) continue;
                                        uint64_t p_vaddr = 0, p_memsz = 0;
                                        memcpy(&p_vaddr, phdr + 16, 8);
                                        memcpy(&p_memsz, phdr + 40, 8);
                                        uint64_t seg_end = p_vaddr + p_memsz;
                                        if (seg_end > max_addr) max_addr = seg_end;
                                    }
                                    if (max_addr > 0 && max_addr < so_size) so_size = (size_t)max_addr;
                                } else {
                                    uint32_t e_phoff = 0; memcpy(&e_phoff, elf_hdr + 28, 4);
                                    uint16_t e_phentsize = elf_hdr[42] | (elf_hdr[43] << 8);
                                    uint16_t e_phnum = elf_hdr[44] | (elf_hdr[45] << 8);
                                    uint32_t max_addr = 0;
                                    for (int p = 0; p < e_phnum && p < 32; p++) {
                                        uint8_t phdr[32];
                                        if (READ_REMOTE(phdr, 32, elf_addr + e_phoff + p * e_phentsize) < 32) break;
                                        uint32_t p_type = 0; memcpy(&p_type, phdr, 4);
                                        if (p_type != 1) continue;
                                        uint32_t p_vaddr = 0, p_memsz = 0;
                                        memcpy(&p_vaddr, phdr + 12, 4);
                                        memcpy(&p_memsz, phdr + 20, 4);
                                        uint32_t seg_end = p_vaddr + p_memsz;
                                        if (seg_end > max_addr) max_addr = seg_end;
                                    }
                                    if (max_addr > 0 && max_addr < so_size) so_size = (size_t)max_addr;
                                }

                                if (dumped_so_base_count < 256) dumped_so_bases[dumped_so_base_count++] = elf_addr;

                                char outfile[768];
                                if (so_path[0] != '\0') {
                                    const char *bname = my_basename(so_path);
                                    snprintf(outfile, sizeof(outfile), "%s/%s", so_dir, bname);
                                } else {
                                    snprintf(outfile, sizeof(outfile), "%s/so_%s_%d.so", so_dir, pid, c->so_count + 1);
                                }

                                uint8_t *so_data = (uint8_t *)malloc(so_size);
                                if (so_data) {
                                    ssize_t read_total = 0;
                                    while (read_total < (ssize_t)so_size) {
                                        ssize_t rr = READ_REMOTE(so_data + read_total, so_size - read_total,
                                                 elf_addr + read_total);
                                        if (rr <= 0) break;
                                        read_total += rr;
                                    }
                                    if (read_total > 0) {
                                        // B5: score & keep best decryption-state snapshot.
                                        double score = so_text_score(so_data, (size_t)read_total, is_64);
                                        const char *key = so_path[0] ? so_path : outfile;
                                        int kept = so_best_record(key, outfile, score);
                                        if (kept) {
                                            int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                                            if (fd >= 0) {
                                                write(fd, so_data, read_total);
                                                close(fd);
                                                so_path_remember(so_path);
                                                c->so_count++;
                                                printf("[+] SO(relaxed, magic erased): %s (%zd bytes) score=%.1f from %s pid=%s\n",
                                                       outfile, read_total, score, so_path[0] ? so_path : "(anon)", pid);
                                            }
                                        }
                                    }
                                    free(so_data);
                                }
                            }
                        }
                    }
                    i += 4096;  // page-aligned SO; skip the rest of this page
                }

                // ---- Relaxed DEX scanning (endian_tag based, no magic) ----
                // For second-gen shells that erase "dex\n" but keep the header structure.
                // endian_tag 0x12345678 at offset 0x28 from DEX start.
                // We scan for this 4-byte pattern, then back up 0x28 bytes to
                // check the full header. Only active with --relaxed flag.
                if (g_relaxed && (mode & MODE_DEX) && i + 4 <= n) {
                    uint32_t val = 0;
                    memcpy(&val, buf + i, 4);
                    if (val == kDexEndianTag && i >= 0x28) {
                        // Potential DEX: endian_tag at buf[i] means DEX starts at buf[i - 0x28]
                        size_t dex_start_in_buf = (size_t)(i - 0x28);
                        uintptr_t dex_addr = addr + dex_start_in_buf;

                        // Read a full 0x70 header from the candidate DEX start
                        uint8_t hdr[0x70];
                        if (READ_REMOTE(hdr, 0x70, dex_addr) == 0x70) {
                            uint32_t dex_size = 0;
                            if (dex_header_relaxed_valid(hdr, 0x70, &dex_size)) {
                                // Skip if this was already found by standard magic scan
                                // (check if the magic is intact — if so, it was already handled)
                                if (memcmp(hdr, kDexMagic, 4) == 0) {
                                    i += 4; // skip this endian_tag, standard scan already got it
                                    continue;
                                }

                                // A2: magic was erased — strongly confirm this is a real DEX
                                // via the map_list self-reference (FRIDA-DEXDump keys) before
                                // trusting it. This avoids false positives from random endian_tag.
                                uint32_t map_off = 0, string_ids_off = 0;
                                memcpy(&map_off, hdr + 0x34, 4);
                                memcpy(&string_ids_off, hdr + 0x3C, 4);
                                uint32_t prov = dex_recover_size_provisional(hdr);
                                if (prov < 0x70) prov = 0x100000;
                                uint8_t *img = (uint8_t *)calloc(1, prov);
                                if (img) {
                                    size_t got = 0;
                                    while (got < prov) {
                                        ssize_t rr = READ_REMOTE(img + got, prov - got, dex_addr + got);
                                        if (rr <= 0) break;
                                        got += (size_t)rr;
                                    }
                                    int confirmed = dex_confirm_by_map_list(img, got, map_off, string_ids_off);
                                    // If file_size was also erased, recover the real size now.
                                    if (confirmed && dex_size == 0) {
                                        uint32_t recovered = dex_recover_size_from_map_buf(img, got, map_off);
                                        if (recovered) dex_size = recovered;
                                        else confirmed = 0;
                                    }
                                    free(img);
                                    if (!confirmed) { i += 4; continue; }
                                } else { i += 4; continue; }

                                // Magic was erased — restore it before dumping
                                c->dex_total++;
                                pid_dex_seen++;
                                fprintf(stderr, "[+] PID %s: DEX (relaxed, magic erased) at 0x%lx size=%u\n",
                                       pid, (unsigned long)dex_addr, dex_size);

                                uint8_t *dex_data = (uint8_t *)calloc(1, dex_size);
                                if (!dex_data) { fprintf(stderr, "[-] calloc failed\n"); i += 4; continue; }

                                size_t readable_total = 0;
                                int missing_pages = 0;
                                for (size_t off = 0; off < dex_size; off += 4096) {
                                    size_t todo = dex_size - off;
                                    if (todo > 4096) todo = 4096;
                                    ssize_t rr = READ_REMOTE(dex_data + off, todo, dex_addr + off);
                                    if (rr > 0) {
                                        readable_total += (size_t)rr;
                                        if ((size_t)rr < todo) missing_pages++;
                                    } else {
                                        missing_pages++;
                                    }
                                }

                                if (readable_total == 0) { free(dex_data); i += 4; continue; }

                                // Restore the "dex\n" magic + version tag in the dump
                                // Version: try to infer from file_size and structure.
                                // Default to "039\0" (Android 10+, most common for current apps).
                                memcpy(dex_data, kDexMagic, 4);
                                dex_data[4] = '0'; dex_data[5] = '3';
                                dex_data[6] = '9'; dex_data[7] = '\0';

                                fix_dex_header_and_checksums(dex_data, dex_size);

                                // De-dup by recomputed SHA-1 signature
                                const uint8_t *sig = dex_data + 0x0C;
                                if (dex_sig_seen(sig)) {
                                    c->dex_dedup++;
                                    fprintf(stderr, "[=] PID %s: DEX (relaxed) at 0x%lx is a duplicate, skipped\n",
                                           pid, (unsigned long)dex_addr);
                                    free(dex_data);
                                    i += (dex_size > 4096 ? 4096 : dex_size);
                                    continue;
                                }
                                dex_sig_remember(sig);
                                pid_dex_unique++;

                                char outfile[768];
                                snprintf(outfile, sizeof(outfile),
                                         "%s/dump_%s_%d.dex", dex_dir, pid, pid_dex_seen);

                                int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                                if (fd >= 0) {
                                    size_t written_total = 0;
                                    while (written_total < dex_size) {
                                        ssize_t w = write(fd, dex_data + written_total, dex_size - written_total);
                                        if (w <= 0) break;
                                        written_total += (size_t)w;
                                    }
                                    close(fd);
                                    if (written_total == dex_size) {
                                        c->dex_unique++;
                                        printf("[+] DEX(relaxed): %s (%u bytes, readable=%zu, zero_pages=%d) pid=%s\n",
                                               outfile, dex_size, readable_total, missing_pages, pid);
                                    }
                                }
                                free(dex_data);
                                i += (dex_size > 4096 ? 4096 : dex_size);
                            }
                        }
                        // Whether valid or not, skip past this endian_tag
                        i += 3; // +1 will be added by the for loop
                    }
                }
            }
        }
    }

    if (mem_fd >= 0) close(mem_fd);
    #undef READ_REMOTE
    free_maps(ml);
    fprintf(stderr, "[*] PID %s (%s): %d DEX (%d new), running totals: unique=%d dedup=%d\n",
           pid, pkg, pid_dex_seen, pid_dex_unique, c->dex_unique, c->dex_dedup);
    return 1;
}

static int mkdir_checked(const char *path) {
    if (mkdir(path, 0777) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "[-] %s exists and is not a directory\n", path);
        return -1;
    }
    fprintf(stderr, "[-] mkdir %s failed: %s\n", path, strerror(errno));
    return -1;
}

// Remove files ending in `ext` from `dir`. Prevents stale output from a
// previous run accumulating (NHDD only mkdir's, never cleans — so re-runs
// into the same out_dir would mix old and new dumps).
static void clean_dir_ext(const char *dir, const char *ext) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    size_t el = strlen(ext);
    while ((de = readdir(d))) {
        if (de->d_type != DT_REG && de->d_type != DT_UNKNOWN) continue;
        size_t l = strlen(de->d_name);
        if (l < el || strcmp(de->d_name + l - el, ext) != 0) continue;
        char p[768];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        unlink(p);
    }
    closedir(d);
}

// ---- Main ----
int main(int argc, char **argv) {
    int mode = MODE_DEX;
    int snapshot_rounds = 1;     // fixed rounds (--snapshot N)
    int snapshot_interval = 1;   // seconds between rounds
    int watch = 0;               // --watch: loop until stable
    int watch_dry_limit = 3;     // stop after K consecutive dry rounds
    int max_rounds = 60;         // safety cap on rounds
    int max_seconds = 120;       // safety cap on wall time
    int stealth = 0;             // --stealth: add region delay + auto-disguise
    int keep = 0;                // --keep: do NOT wipe stale dex/so output
    const char *disguise = NULL; // --name/--disguise: fake process name
    const char *sofixer_path = NULL; // --sofixer <path>: override default lookup

    const char *target = NULL;
    const char *out_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--so") == 0) { mode = MODE_SO; continue; }
        if (strcmp(argv[i], "--dex") == 0) { mode = MODE_DEX; continue; }
        if (strcmp(argv[i], "--all") == 0) { mode = MODE_ALL; continue; }
        if (strcmp(argv[i], "--keep") == 0) { keep = 1; continue; }
        if (strcmp(argv[i], "--snapshot") == 0 && i + 1 < argc) {
            snapshot_rounds = atoi(argv[++i]);
            if (snapshot_rounds < 1) snapshot_rounds = 1;
            continue;
        }
        if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            snapshot_interval = atoi(argv[++i]);
            if (snapshot_interval < 0) snapshot_interval = 0;
            continue;
        }
        if (strcmp(argv[i], "--watch") == 0) {
            watch = 1;
            // optional K: --watch 3
            if (i + 1 < argc && atoi(argv[i + 1]) > 0) { watch_dry_limit = atoi(argv[++i]); }
            continue;
        }
        if (strcmp(argv[i], "--max-rounds") == 0 && i + 1 < argc) {
            max_rounds = atoi(argv[++i]); if (max_rounds < 1) max_rounds = 60; continue;
        }
        if (strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc) {
            max_seconds = atoi(argv[++i]); if (max_seconds < 1) max_seconds = 120; continue;
        }
        if (strcmp(argv[i], "--stealth") == 0) { stealth = 1; continue; }
        if (strcmp(argv[i], "--stealth2") == 0) { g_use_vm_readv = 1; continue; }
        if (strcmp(argv[i], "--relaxed") == 0) { g_relaxed = 1; continue; }
        if (strcmp(argv[i], "--relaxed-so") == 0) { g_relaxed_so = 1; continue; }
        if (strcmp(argv[i], "--anon") == 0) { g_anon_only = 1; continue; }
        if (strcmp(argv[i], "--region-delay") == 0 && i + 1 < argc) {
            g_region_delay_us = atoi(argv[++i]) * 1000; continue;  // ms -> us
        }
        if ((strcmp(argv[i], "--name") == 0 || strcmp(argv[i], "--disguise") == 0)
            && i + 1 < argc) { disguise = argv[++i]; continue; }
        if (strcmp(argv[i], "--sofixer") == 0 && i + 1 < argc) {
            sofixer_path = argv[++i]; continue;
        }
        if (!target) { target = argv[i]; continue; }
        if (!out_dir) { out_dir = argv[i]; continue; }
    }

    // --stealth enables a modest region delay by default (1ms) unless set.
    if (stealth && g_region_delay_us == 0) g_region_delay_us = 1000;
    // --stealth without an explicit name auto-disguises as a kworker thread.
    if (stealth && !disguise) disguise = "kworker/u16:2";
    // disguise_self() will zero the whole argv region (to hide target/paths in
    // /proc/self/cmdline), destroying any pointers INTO argv. Copy the strings
    // we still need first.
    if (target) target = strdup(target);
    if (out_dir) out_dir = strdup(out_dir);
    if (sofixer_path) sofixer_path = strdup(sofixer_path);
    if (disguise) disguise = strdup(disguise);
    // Apply disguise early, before we open any target /proc files.
    disguise_self(argc, argv, disguise);

    if (!target) {
        fprintf(stderr,
            "NHDD — No-Hook DEX/SO Dumper v8.0\n"
            "Usage: %s <pid|package> [output_dir] [--so|--dex|--all]\n"
            "                       [--watch [K]] [--snapshot ROUNDS] [--interval SECS]\n"
            "                       [--stealth] [--stealth2] [--relaxed] [--relaxed-so] [--anon]\n"
            "                       [--region-delay MS] [--name NAME] [--sofixer PATH]\n"
            "                       [--max-rounds N] [--max-seconds S] [--keep]\n"
            "\n"
            "  Modes:\n"
            "    --dex  Dump DEX files only (default)\n"
            "    --so   Dump SO files only\n"
            "    --all  Dump both DEX and SO files\n"
            "\n"
            "  Capture (key to ~100%% first-gen recovery):\n"
            "    --watch [K]    Keep scanning until K consecutive dry rounds (default 3).\n"
            "                   Run it, then navigate the app's feature pages on the phone —\n"
            "                   every lazily-loaded DEX gets captured as it enters memory.\n"
            "                   Caps: --max-rounds (60), --max-seconds (120).\n"
            "    --snapshot N   Fixed N rounds instead of --watch (default 1).\n"
            "    --interval T   Seconds between rounds (default 1).\n"
            "\n"
            "  Anti-detection:\n"
            "    --stealth      Region delay + auto-disguise as a kworker thread (see below).\n"
            "    --stealth2     Use process_vm_readv() instead of /proc/pid/mem. Avoids\n"
            "                   opening the mem file, which packers can detect via /proc/self/fd.\n"
            "                   Combine with --stealth for best anti-detection.\n"
            "    --relaxed      Relaxed DEX scan: also detect DEX files whose \"dex\\n\" magic\n"
            "                   has been erased by second-gen extraction shells. Uses endian_tag\n"
            "                   (0x12345678) + header structure to identify DEX. Restores magic\n"
            "                   in the dump. Use with --watch for best results.\n"
            "    --relaxed-so   Relaxed SO scan: also detect SO files whose \"\\x7fELF\" magic\n"
            "                   has been erased. Uses e_type==ET_DYN + e_machine + program-header\n"
            "                   structure to identify SO. fix_so.py restores the magic post-dump.\n"
            "    --anon         Only scan anonymous memory mappings (skip file-backed regions\n"
            "                   like system libs, OAT, VDEX). Much faster, less likely to crash\n"
            "                   anti-dump packers that monitor reads of their mapped files.\n"
            "    --region-delay MS  Region pause in ms (0 = none).\n"
            "    --name NAME    Fake /proc/self/comm AND /proc/self/cmdline to NAME (e.g.\n"
            "                   'kworker/u17:2','gms:ui'). Defeats packers scanning /proc/*/comm\n"
            "                   and /proc/*/cmdline for tool names. --stealth sets a default.\n"
            "\n"
            "  Output:\n"
            "    --keep          Do NOT wipe stale .dex/.so in the output dir before\n"
            "                   scanning (default: wipe, so re-runs don't mix old+new).\n"
            "    --sofixer PATH  Use SoFixer at PATH (default: /data/local/tmp/sofixer).\n"
            "\n"
            "  DEX checksums (SHA-1 + Adler32) are auto-fixed; hits are validated\n"
            "  (DEX version tag + header fields) to reject false positives.\n"
            "  SO files are dumped from memory (auto-fixed via SoFixer if present).\n",
            argv[0]);
        return 1;
    }

    if (!out_dir) out_dir = "/data/local/tmp/nhdd_dump";

    // Resolve target: numeric PID => single pid; package => all matching pids.
    char pids[MAX_PIDS][16];
    int pid_count = 0;
    int is_numeric = 1;
    for (const char *c = target; *c; c++) {
        if (!isdigit((unsigned char)*c)) { is_numeric = 0; break; }
    }

    if (is_numeric) {
        snprintf(pids[0], sizeof(pids[0]), "%s", target);
        pid_count = 1;
    } else {
        pid_count = find_pids_for_package(target, pids, sizeof(pids[0]), MAX_PIDS);
        if (pid_count <= 0) {
            fprintf(stderr, "[-] No running process matches package '%s'\n", target);
            return 1;
        }
        fprintf(stderr, "[*] Resolved package '%s' -> %d process(es):", target, pid_count);
        for (int i = 0; i < pid_count; i++) fprintf(stderr, " %s", pids[i]);
        fprintf(stderr, "\n");
    }

    // Create output directories.
    char dex_dir[512], so_dir[512];
    snprintf(dex_dir, sizeof(dex_dir), "%s/dex", out_dir);
    snprintf(so_dir, sizeof(so_dir), "%s/so", out_dir);
    if (mkdir_checked(out_dir)) return 1;
    if (mode & MODE_DEX) { if (mkdir_checked(dex_dir)) return 1; }
    if (mode & MODE_SO)  { if (mkdir_checked(so_dir)) return 1; }

    // Wipe stale output so a re-run into the same out_dir never mixes old
    // dumps with new ones (--keep to preserve, e.g. for incremental runs).
    if (!keep) {
        if (mode & MODE_DEX) clean_dir_ext(dex_dir, ".dex");
        if (mode & MODE_SO)  clean_dir_ext(so_dir, ".so");
    }

    if (mode & MODE_DEX) fprintf(stderr, "[*] Scanning for DEX files...\n");
    if (mode & MODE_SO)  fprintf(stderr, "[*] Scanning for SO files...\n");
    fprintf(stderr, "[*] Output directory: %s\n", out_dir);
    if (watch) {
        fprintf(stderr, "[*] WATCH mode: scan until %d dry rounds (max %d rounds / %ds)\n",
                watch_dry_limit, max_rounds, max_seconds);
        fprintf(stderr, "[*] >>> Now navigate the app's feature pages on the phone; lazily-loaded\n");
        fprintf(stderr, "        DEX will be captured as they enter memory. Stops automatically. <<<\n");
    } else {
        fprintf(stderr, "[*] Rounds: %d, interval: %ds\n", snapshot_rounds, snapshot_interval);
    }

    counters c;
    memset(&c, 0, sizeof(c));

    int rounds_run = 0;
    int dry_rounds = 0;
    time_t t_start = time(NULL);
    int rounds_limit = watch ? max_rounds : snapshot_rounds;

    for (int round = 0; round < rounds_limit; round++) {
        // Wall-time safety cap (watch mode).
        if (watch && max_seconds > 0) {
            if (difftime(time(NULL), t_start) >= max_seconds) {
                fprintf(stderr, "\n[*] Max seconds (%d) reached, stopping.\n", max_seconds);
                break;
            }
        }
        rounds_run++;
        int unique_before = c.dex_unique;

        if (rounds_limit > 1) fprintf(stderr, "\n[*] === Round %d ===\n", round + 1);

        // Re-resolve pids each round for package targets (processes may respawn/die).
        if (!is_numeric && rounds_limit > 1) {
            pid_count = find_pids_for_package(target, pids, sizeof(pids[0]), MAX_PIDS);
            if (pid_count <= 0) {
                if (watch) {
                    fprintf(stderr, "[*] no matching process yet, waiting for it to (re)appear...\n");
                } else {
                    fprintf(stderr, "[-] Round %d: no matching process (app may have exited)\n", round + 1);
                }
                if (snapshot_interval > 0) sleep(snapshot_interval);
                continue;
            }
        }
        for (int p = 0; p < pid_count; p++) {
            scan_pid(pids[p], dex_dir, so_dir, mode, &c);
        }

        if (watch) {
            int new_this = c.dex_unique - unique_before;
            if (new_this > 0) dry_rounds = 0; else dry_rounds++;
            fprintf(stderr, "[*] round %d: +%d new unique DEX (total=%d, dry=%d/%d)\n",
                    round + 1, new_this, c.dex_unique, dry_rounds, watch_dry_limit);
            if (dry_rounds >= watch_dry_limit) {
                fprintf(stderr, "[*] stable set reached (%d dry rounds), stopping.\n", watch_dry_limit);
                break;
            }
        }

        if (round + 1 < rounds_limit && snapshot_interval > 0) {
            sleep(snapshot_interval);
        }
    }

    fprintf(stderr, "\n[*] Done. rounds=%d%s, processes_scanned=%d, DEX unique=%d (hits=%d, dedup_skipped=%d), SO=%d\n",
            rounds_run, watch ? " (watch)" : "", c.procs, c.dex_unique,
            c.dex_total, c.dex_dedup, c.so_count);

    // ---- Auto-fix SO files with SoFixer ----
    if (c.so_count > 0) {
        const char *sofixer_paths[] = {
            "/data/local/tmp/sofixer",
            "/data/local/tmp/SoFixer64",
            NULL
        };
        const char *sofixer = NULL;
        // --sofixer <path> takes precedence over default lookup locations.
        if (sofixer_path && access(sofixer_path, X_OK) == 0) {
            sofixer = sofixer_path;
        } else {
            for (int i = 0; sofixer_paths[i]; i++) {
                if (access(sofixer_paths[i], X_OK) == 0) {
                    sofixer = sofixer_paths[i];
                    break;
                }
            }
        }

        if (sofixer) {
            fprintf(stderr, "\n[*] Fixing SO files with SoFixer...\n");
            int fixed = 0, failed = 0;

            DIR *d = opendir(so_dir);
            if (d) {
                struct dirent *de;
                while ((de = readdir(d))) {
                    if (de->d_type != DT_REG && de->d_type != DT_UNKNOWN) continue;
                    size_t namelen = strlen(de->d_name);
                    if (namelen < 4 || strcmp(de->d_name + namelen - 3, ".so") != 0) continue;

                    char src[768], dst[768];
                    snprintf(src, sizeof(src), "%s/%s", so_dir, de->d_name);
                    snprintf(dst, sizeof(dst), "%s/fixed_%s", so_dir, de->d_name);

                    char cmd[2048];
                    snprintf(cmd, sizeof(cmd), "%s -s %s -o %s -m 0x0 2>/dev/null", sofixer, src, dst);
                    int ret = system(cmd);
                    if (ret == 0) {
                        unlink(src);
                        rename(dst, src);
                        fixed++;
                        fprintf(stderr, "[+] Fixed: %s\n", de->d_name);
                    } else {
                        unlink(dst);
                        failed++;
                        fprintf(stderr, "[-] Fix failed: %s (kept raw dump)\n", de->d_name);
                    }
                }
                closedir(d);
            }
            fprintf(stderr, "[*] SoFixer: %d fixed, %d failed\n", fixed, failed);
        } else {
            fprintf(stderr, "[!] SoFixer not found at /data/local/tmp/sofixer. "
                    "SO files are raw memory dumps.\n"
                    "[!] Get SoFixer: https://github.com/F8LEFT/SoFixer\n"
                    "[!] Usage: sofixer -s input.so -o output.so -m 0x0\n");
        }
    }

    return 0;
}
