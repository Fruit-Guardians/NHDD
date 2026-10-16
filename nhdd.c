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
//   - Dump SO files (--so) via maps-driven classification + precise offset merge
//     (system/vendor/oat libraries are classified and skipped; only app SOs dumped)
//   - Snapshot mode (--snapshot N --interval T): re-scan the target N times so
//     even a DEX that only briefly exists in memory gets captured.
//   - Static binary, no dependencies

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char      perms[8];       // e.g. "r-xp"
    uint64_t  offset;         // file offset (maps column 4)
    uint64_t  inode;          // inode (maps column 5)
    uint32_t  dev_major;      // device major
    uint32_t  dev_minor;      // device minor
    char      path[512];      // mapped file path ("" if anonymous)
    int       readable;       // permission shortcuts
    int       writable;
    int       executable;
} maps_region;

typedef struct {
    maps_region *regs;
    size_t       count;
} maps_list;

// ---- Object kind / origin / policy enums (SO classification) ----
enum {
    OBJ_UNKNOWN = 0,
    OBJ_ELF_SO,
    OBJ_ELF_EXEC,
    OBJ_DEX,
    OBJ_OAT,
    OBJ_ODEX,
    OBJ_APK_ZIP,
    OBJ_LINKER,
    OBJ_VDSO,
    OBJ_MEMFD,
    OBJ_INVALID
};

enum {
    ORIGIN_UNKNOWN = 0,
    ORIGIN_APP_APK,      // /data/app/<pkg>/...
    ORIGIN_APP_DATA,     // /data/data/<pkg>/ or /data/user/0/<pkg>/
    ORIGIN_APP_ANON,     // anonymous, suspected app-related
    ORIGIN_SYSTEM,       // /system /system_ext /product
    ORIGIN_APEX,         // /apex
    ORIGIN_VENDOR,       // /vendor /odm
    ORIGIN_RUNTIME,      // linker64, app_process64, boot.oat
    ORIGIN_WEBVIEW,
    ORIGIN_SPECIAL       // [vdso], memfd, etc
};

enum {
    POLICY_SKIP = 0,
    POLICY_DUMP_MERGE,          // dump via maps merge, no repair
    POLICY_DUMP_AND_FIX,        // dump + basic elf repair
    POLICY_DUMP_AND_SOFIXER_FIX // dump + SoFixer full repair
};

// Grouped object from maps: all regions sharing the same path+inode
typedef struct {
    char     path[512];
    char     name[256];
    uint64_t inode;

    uintptr_t base_addr;       // min(start - offset)
    uintptr_t min_start, max_end;
    uint64_t min_offset;
    uint64_t file_size;        // max(offset + (end-start))

    int region_count;
    int has_r, has_w, has_x;

    int kind;
    int origin;
    int policy;

    char     reason[256];
} MappedObject;

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

// ---- Scan configuration (set in main, read by scan_pid) ----
static int g_region_delay_us = 0;  // usleep between regions (stealth mode)
static int g_relaxed = 0;          // --relaxed: scan for DEX without magic (endian_tag based)
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

// Strong DEX header validation: check endian_tag + all section table ranges
static int dex_header_strong_valid(const uint8_t *hdr, uint32_t file_size) {
    // endian_tag must be 0x12345678
    uint32_t endian_tag = 0;
    memcpy(&endian_tag, hdr + 0x28, 4);
    if (endian_tag != 0x12345678) return 0;

    // Read all section table offsets and sizes
    uint32_t string_ids_off=0, string_ids_size=0;
    uint32_t type_ids_off=0, type_ids_size=0;
    uint32_t proto_ids_off=0, proto_ids_size=0;
    uint32_t field_ids_off=0, field_ids_size=0;
    uint32_t method_ids_off=0, method_ids_size=0;
    uint32_t class_defs_off=0, class_defs_size=0;

    memcpy(&string_ids_off, hdr + 0x3C, 4);
    memcpy(&string_ids_size, hdr + 0x40, 4);
    memcpy(&type_ids_off, hdr + 0x44, 4);
    memcpy(&type_ids_size, hdr + 0x48, 4);
    memcpy(&proto_ids_off, hdr + 0x4C, 4);
    memcpy(&proto_ids_size, hdr + 0x50, 4);
    memcpy(&field_ids_off, hdr + 0x54, 4);
    memcpy(&field_ids_size, hdr + 0x58, 4);
    memcpy(&method_ids_off, hdr + 0x5C, 4);
    memcpy(&method_ids_size, hdr + 0x60, 4);
    memcpy(&class_defs_off, hdr + 0x64, 4);
    memcpy(&class_defs_size, hdr + 0x68, 4);

    // Each section must be fully within file_size
    if (string_ids_off + string_ids_size * 4 > file_size) return 0;
    if (type_ids_off + type_ids_size * 4 > file_size) return 0;
    if (proto_ids_off + proto_ids_size * 12 > file_size) return 0;
    if (field_ids_off + field_ids_size * 8 > file_size) return 0;
    if (method_ids_off + method_ids_size * 8 > file_size) return 0;
    if (class_defs_off + class_defs_size * 32 > file_size) return 0;

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

// ---- Load /proc/<pid>/maps into memory, parsing full columns ----
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

    char line[1024];
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

        // Parse: start-end perms offset dev_major:dev_minor inode [path]
        // Maps format: 7f000000-7f001000 r-xp 00000000 fd:02 12345 /path/to/file.so
        unsigned long dmaj = 0, dmin = 0, off = 0, ino = 0;
        int n = sscanf(line, "%lx-%lx %7s %lx %lx:%lx %lu",
                       &r->start, &r->end, r->perms, &off, &dmaj, &dmin, &ino);
        if (n < 7) {
            // Fallback: parse just address+perms for broken/incomplete lines
            if (sscanf(line, "%lx-%lx %7s", &r->start, &r->end, r->perms) < 3) continue;
            off = 0; dmaj = 0; dmin = 0; ino = 0;
        }
        r->offset = (uint64_t)off;
        r->inode = (uint64_t)ino;
        r->dev_major = (uint32_t)dmaj;
        r->dev_minor = (uint32_t)dmin;

        // Permission shortcuts
        for (int i = 0; i < 4; i++) {
            if (r->perms[i] == 'r') r->readable = 1;
            if (r->perms[i] == 'w') r->writable = 1;
            if (r->perms[i] == 'x') r->executable = 1;
        }

        // Extract path: everything after the 5th whitespace field (address, perms, offset, dev, inode)
        // Maps format guarantees: addr-perms-offset-dev-inode are always 5 whitespace-delimited tokens.
        // The 6th token onwards (including spaces) is the path.
        char *p = line;
        int fields = 0;
        // Skip exactly 5 whitespace-delimited fields (addr, perms, offset, dev:inode as two, inode)
        while (fields < 5 && *p) {
            while (*p == ' ') p++;
            if (!*p) break;
            while (*p && *p != ' ' && *p != '\n') p++;
            fields++;
        }
        // Now p points at the whitespace before the path (or end of line)
        while (*p == ' ') p++;  // skip leading spaces
        if (*p && *p != '\n') {
            // Copy rest of line as path, trimming trailing newline
            size_t plen = strlen(p);
            while (plen > 0 && (p[plen-1] == '\n' || p[plen-1] == '\r')) plen--;
            snprintf(r->path, sizeof(r->path), "%.*s", (int)plen, p);
        }

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

// ---- Group maps regions by path + inode into MappedObject array ----
static int group_maps_by_path_inode(const maps_list *ml, MappedObject *objs, int max_objs) {
    int count = 0;
    for (size_t i = 0; i < ml->count && count < max_objs; i++) {
        const maps_region *r = &ml->regs[i];

        // Anonymous mappings (path=="" or inode==0) each get their own object
        if (r->path[0] == '\0' || r->inode == 0) {
            MappedObject *o = &objs[count];
            memset(o, 0, sizeof(*o));
            snprintf(o->path, sizeof(o->path), "anon_%lx", (unsigned long)r->start);
            snprintf(o->name, sizeof(o->name), "anon_%lx", (unsigned long)r->start);
            o->inode = 0;
            o->base_addr = r->start - r->offset;
            o->min_start = r->start;
            o->max_end = r->end;
            o->min_offset = r->offset;
            o->file_size = r->offset + (r->end - r->start);
            o->region_count = 1;
            if (r->readable) o->has_r = 1;
            if (r->writable) o->has_w = 1;
            if (r->executable) o->has_x = 1;
            count++;
            continue;
        }

        // Group key = path + inode
        int found = 0;
        for (int j = 0; j < count; j++) {
            if (objs[j].inode == r->inode &&
                strcmp(objs[j].path, r->path) == 0) {
                // Extend bounds
                if (r->start < objs[j].min_start) objs[j].min_start = r->start;
                if (r->end > objs[j].max_end) objs[j].max_end = r->end;
                if (r->offset < objs[j].min_offset) objs[j].min_offset = r->offset;
                uint64_t seg_end = r->offset + (r->end - r->start);
                if (seg_end > objs[j].file_size) objs[j].file_size = seg_end;
                objs[j].region_count++;
                if (r->readable) objs[j].has_r = 1;
                if (r->writable) objs[j].has_w = 1;
                if (r->executable) objs[j].has_x = 1;
                // Recalc base_addr
                uintptr_t base = r->start - r->offset;
                if (base < objs[j].base_addr || objs[j].region_count == 1)
                    objs[j].base_addr = base;
                found = 1;
                break;
            }
        }
        if (!found) {
            MappedObject *o = &objs[count];
            memset(o, 0, sizeof(*o));
            snprintf(o->path, sizeof(o->path), "%s", r->path);
            const char *bn = strrchr(r->path, '/');
            snprintf(o->name, sizeof(o->name), "%s", bn ? bn + 1 : r->path);
            o->inode = r->inode;
            o->base_addr = r->start - r->offset;
            o->min_start = r->start;
            o->max_end = r->end;
            o->min_offset = r->offset;
            o->file_size = r->offset + (r->end - r->start);
            o->region_count = 1;
            if (r->readable) o->has_r = 1;
            if (r->writable) o->has_w = 1;
            if (r->executable) o->has_x = 1;
            count++;
        }
    }
    return count;
}

// ---- Classify object origin by path ----
static int classify_origin(const char *path, const char *pkg) {
    if (!path || path[0] == '\0') return ORIGIN_APP_ANON;
    if (strstr(path, "[vdso]")) return ORIGIN_SPECIAL;
    if (strstr(path, "memfd")) return ORIGIN_SPECIAL;
    if (strstr(path, "/data/app/") && strstr(path, pkg))
        return ORIGIN_APP_APK;
    if ((strstr(path, "/data/data/") || strstr(path, "/data/user/0/")) && strstr(path, pkg))
        return ORIGIN_APP_DATA;
    if (strstr(path, "/apex/"))
        return ORIGIN_APEX;
    if (strstr(path, "/vendor/") || strstr(path, "/odm/"))
        return ORIGIN_VENDOR;
    if (strstr(path, "/system/") || strstr(path, "/system_ext/") || strstr(path, "/product/"))
        return ORIGIN_SYSTEM;
    return ORIGIN_UNKNOWN;
}

// ---- Classify object kind from header bytes + path hints ----
static int classify_kind(const char *path, const uint8_t *head, size_t head_size) {
    if (!head || head_size < 4) return OBJ_UNKNOWN;

    // Path-based hints checked first (ODEX/OAT are ELF-wrapped but NOT SOs)
    if (path && strstr(path, "[vdso]")) return OBJ_VDSO;
    if (path && strstr(path, "memfd")) return OBJ_MEMFD;
    if (path && strstr(path, ".odex")) return OBJ_ODEX;
    if (path && strstr(path, ".oat")) return OBJ_OAT;
    if (path && (strstr(path, "linker64") || strstr(path, "linker")))
        return OBJ_LINKER;

    // ELF check
    if (memcmp(head, "\x7f""ELF", 4) == 0) {
        if (head_size < 18) return OBJ_ELF_SO;
        uint16_t e_type = head[16] | (head[17] << 8);
        if (e_type == 3) return OBJ_ELF_SO;      // ET_DYN
        if (e_type == 2 || e_type == 1) return OBJ_ELF_EXEC; // ET_EXEC/ET_REL
        return OBJ_ELF_SO;
    }
    if (memcmp(head, "dex\n", 4) == 0) return OBJ_DEX;
    if (memcmp(head, "oat\n", 4) == 0) return OBJ_OAT;
    if (memcmp(head, "PK\x03\x04", 4) == 0) return OBJ_APK_ZIP;
    return OBJ_UNKNOWN;
}

// ---- Decide repair policy for SO objects ----
static int decide_policy(const MappedObject *o) {
    // Skip non-SO types
    if (o->kind == OBJ_OAT || o->kind == OBJ_ODEX || o->kind == OBJ_APK_ZIP ||
        o->kind == OBJ_VDSO || o->kind == OBJ_MEMFD || o->kind == OBJ_DEX ||
        o->kind == OBJ_ELF_EXEC || o->kind == OBJ_LINKER)
        return POLICY_SKIP;
    // Skip system/vendor/apex — only care about app-logic SOs
    if (o->origin == ORIGIN_SYSTEM || o->origin == ORIGIN_APEX ||
        o->origin == ORIGIN_VENDOR || o->origin == ORIGIN_RUNTIME ||
        o->origin == ORIGIN_WEBVIEW || o->origin == ORIGIN_SPECIAL)
        return POLICY_SKIP;
    // Dump app-related SOs
    if (o->kind == OBJ_ELF_SO && o->origin != ORIGIN_UNKNOWN)
        return POLICY_DUMP_AND_FIX;
    // Unknown anonymous ELF SO (might be shell-loaded app code)
    if (o->kind == OBJ_ELF_SO && o->origin == ORIGIN_UNKNOWN && o->has_x)
        return POLICY_DUMP_MERGE;
    return POLICY_SKIP;
}

// ---- Dump object by precise offset-based maps merging ----
static int dump_object_by_maps(int mem_fd, pid_t pid, MappedObject *obj,
                               const maps_list *ml, const char *out_path) {
    if (obj->file_size > 64 * 1024 * 1024) {
        fprintf(stderr, "  [-] SO too large (%llu bytes), skip\n",
                (unsigned long long)obj->file_size);
        return -1;
    }
    if (obj->file_size == 0) return -1;

    uint8_t *buf = calloc(1, (size_t)obj->file_size);
    if (!buf) {
        fprintf(stderr, "  [-] OOM for SO %s (%llu bytes)\n",
                obj->name, (unsigned long long)obj->file_size);
        return -1;
    }

    // Read each region of this object by offset
    for (size_t i = 0; i < ml->count; i++) {
        const maps_region *r = &ml->regs[i];
        if (r->inode != obj->inode || strcmp(r->path, obj->path) != 0)
            continue;
        if (!r->readable) continue;

        size_t seg_len = (size_t)(r->end - r->start);
        if ((uint64_t)obj->file_size < r->offset + seg_len) continue;

        if (g_use_vm_readv) {
            vm_readv_retry(pid, buf + r->offset, seg_len, r->start);
        } else if (mem_fd >= 0) {
            pread_retry(mem_fd, buf + r->offset, seg_len, (off_t)r->start);
        }
    }

    // Extend dump to cover all PT_LOAD segments from ELF header
    if (obj->file_size >= 0x40 && memcmp(buf, "\x7f""ELF", 4) == 0) {
        int is64 = (buf[4] == 2);
        uint64_t e_phoff = is64 ? *(uint64_t*)(buf + 32) : *(uint32_t*)(buf + 28);
        uint16_t e_phentsize = is64 ? *(uint16_t*)(buf + 54) : *(uint16_t*)(buf + 42);
        uint16_t e_phnum = is64 ? *(uint16_t*)(buf + 56) : *(uint16_t*)(buf + 44);
        if (e_phoff > 0 && e_phentsize > 0 && e_phnum < 64 &&
            e_phoff + (uint64_t)e_phnum * e_phentsize <= obj->file_size) {
            uint64_t needed = 0;
            for (uint16_t i = 0; i < e_phnum; i++) {
                uint64_t base = e_phoff + (uint64_t)i * e_phentsize;
                uint32_t p_type = *(uint32_t*)(buf + base);
                uint64_t p_vaddr, p_memsz;
                if (is64) { p_vaddr = *(uint64_t*)(buf + base + 16); p_memsz = *(uint64_t*)(buf + base + 40); }
                else { p_vaddr = *(uint32_t*)(buf + base + 8); p_memsz = *(uint32_t*)(buf + base + 20); }
                if (p_type == 1 && p_vaddr + p_memsz > needed) needed = p_vaddr + p_memsz;
            }
            if (needed > obj->file_size && needed <= 64*1024*1024) {
                uint8_t *nbuf = realloc(buf, (size_t)needed);
                if (nbuf) {
                    buf = nbuf;
                    memset(buf + obj->file_size, 0, (size_t)(needed - obj->file_size));
                    // Try to read additional LOAD segments from process memory
                    for (uint16_t i = 0; i < e_phnum; i++) {
                        uint64_t base = e_phoff + (uint64_t)i * e_phentsize;
                        uint32_t p_type = *(uint32_t*)(buf + base);
                        if (p_type != 1) continue;
                        uint64_t p_offset, p_filesz;
                        if (is64) { p_offset = *(uint64_t*)(buf + base + 8); p_filesz = *(uint64_t*)(buf + base + 32); }
                        else { p_offset = *(uint32_t*)(buf + base + 4); p_filesz = *(uint32_t*)(buf + base + 16); }
                        // Only read if segment is beyond what maps captured
                        if (p_offset + p_filesz > obj->file_size && p_offset < needed) {
                            size_t to_read = (size_t)(needed - p_offset);
                            if (to_read > (size_t)(p_filesz)) to_read = (size_t)p_filesz;
                            if (p_offset < obj->file_size) to_read -= (size_t)(obj->file_size - p_offset);
                            uintptr_t remote_addr = (uintptr_t)(obj->base_addr + p_offset);
                            if (g_use_vm_readv)
                                vm_readv_retry(pid, buf + p_offset, to_read, remote_addr);
                            else if (mem_fd >= 0)
                                pread_retry(mem_fd, buf + p_offset, to_read, (off_t)remote_addr);
                        }
                    }
                    obj->file_size = needed;
                }
            }
        }
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) { free(buf); return -1; }
    size_t written = fwrite(buf, 1, (size_t)obj->file_size, out);
    fclose(out);
    free(buf);

    if (written != (size_t)obj->file_size) {
        fprintf(stderr, "  [!] Partial write for %s (%zu/%llu)\n",
                obj->name, written, (unsigned long long)obj->file_size);
    }
    return (written > 0) ? 0 : -1;
}

// ---- Enhanced ELF repair: never-give-up, always save ----
static int elf_repair_basic(const char *path) {
    FILE *f = fopen(path, "r+b");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0x40) { fclose(f); return -1; }

    uint8_t *data = malloc((size_t)fsize + 32768);
    if (!data) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);
    fread(data, 1, (size_t)fsize, f);
    fclose(f);

    // Bare minimum: must have ELF magic
    if (memcmp(data, "\x7f""ELF", 4) != 0) {
        // Check if offset 0 looks like ARM64 code → might be header-less dump
        // Just write magic and hope
        memcpy(data, "\x7f""ELF", 4);
    }

    // Always fix e_ident
    int is64 = (data[4] == 2);
    if (data[4] != 1 && data[4] != 2) {
        is64 = 1; // default to ELF64 (Android is 64-bit)
        data[4] = 2;
    }
    data[5] = 1; // EI_DATA = little-endian
    data[6] = 1; // EI_VERSION = 1

    // Always fix e_type (dump SOs are always ET_DYN)
    if (is64) {
        uint16_t e_type = *(uint16_t*)(data + 16);
        if (e_type != 3) { e_type = 3; memcpy(data + 16, &e_type, 2); }
        // Fix e_machine if invalid
        uint16_t e_mach = *(uint16_t*)(data + 18);
        if (e_mach != 183 && e_mach != 40) { e_mach = 183; memcpy(data + 18, &e_mach, 2); }
    } else {
        uint16_t e_type = *(uint16_t*)(data + 16);
        if (e_type != 3) { e_type = 3; memcpy(data + 16, &e_type, 2); }
        uint16_t e_mach = *(uint16_t*)(data + 18);
        if (e_mach != 183 && e_mach != 40) { e_mach = 40; memcpy(data + 18, &e_mach, 2); }
    }

    // Parse PHT
    uint64_t e_phoff;
    uint16_t e_phentsize, e_phnum;
    if (is64) {
        e_phoff = *(uint64_t*)(data + 32);
        e_phentsize = *(uint16_t*)(data + 54);
        e_phnum = *(uint16_t*)(data + 56);
    } else {
        e_phoff = *(uint32_t*)(data + 28);
        e_phentsize = *(uint16_t*)(data + 42);
        e_phnum = *(uint16_t*)(data + 44);
    }
    if (e_phnum == 0 || e_phentsize == 0 ||
        e_phoff + (uint64_t)e_phnum * e_phentsize > (uint64_t)fsize) {
        // PHT is broken beyond repair — still save with fixes applied so far
        goto save_and_exit;
    }

    // Calculate actual needed size from PT_LOAD to extend truncated dumps
    {
        uint64_t needed_size = 0;
        for (uint16_t i = 0; i < e_phnum; i++) {
            uint64_t base = e_phoff + (uint64_t)i * e_phentsize;
            uint32_t p_type = *(uint32_t*)(data + base);
            if (p_type != 1) continue; // PT_LOAD only
            uint64_t p_vaddr, p_memsz;
            if (is64) { p_vaddr = *(uint64_t*)(data + base + 16); p_memsz = *(uint64_t*)(data + base + 40); }
            else { p_vaddr = *(uint32_t*)(data + base + 8); p_memsz = *(uint32_t*)(data + base + 20); }
            if (p_vaddr + p_memsz > needed_size) needed_size = p_vaddr + p_memsz;
        }
        if (needed_size > (uint64_t)fsize && needed_size <= 64u*1024*1024) {
            uint8_t *n = realloc(data, (size_t)needed_size + 32768);
            if (n) { data = n; memset(data + fsize, 0, (size_t)(needed_size - fsize)); fsize = (long)needed_size; }
        }
    }

    // Fix p_offset = p_vaddr + p_filesz = p_memsz, track PT_DYNAMIC
    uint64_t dyn_vaddr = 0, dyn_filesz = 0;
    for (uint16_t i = 0; i < e_phnum; i++) {
        uint64_t base = e_phoff + (uint64_t)i * e_phentsize;
        uint32_t p_type = *(uint32_t*)(data + base);
        uint64_t p_offset, p_vaddr, p_filesz, p_memsz;
        if (is64) {
            p_offset = *(uint64_t*)(data + base + 8);
            p_vaddr = *(uint64_t*)(data + base + 16);
            p_filesz = *(uint64_t*)(data + base + 32);
            p_memsz = *(uint64_t*)(data + base + 40);
        } else {
            p_offset = *(uint32_t*)(data + base + 4);
            p_vaddr = *(uint32_t*)(data + base + 8);
            p_filesz = *(uint32_t*)(data + base + 16);
            p_memsz = *(uint32_t*)(data + base + 20);
        }
        if (p_type == 1 || p_type == 2) { // PT_LOAD or PT_DYNAMIC
            if (p_offset != p_vaddr) {
                if (is64) memcpy(data + base + 8, &p_vaddr, 8);
                else { uint32_t v32 = (uint32_t)p_vaddr; memcpy(data + base + 4, &v32, 4); }
            }
            if (p_type == 1 && p_filesz < p_memsz) {
                if (is64) memcpy(data + base + 32, &p_memsz, 8);
                else { uint32_t m32 = (uint32_t)p_memsz; memcpy(data + base + 16, &m32, 4); }
            }
            if (p_type == 2) { // PT_DYNAMIC
                dyn_vaddr = p_vaddr;
                dyn_filesz = p_filesz;
            }
        }
    }

    // ---- SoFixer-style section header rebuild ----
    // Always build at least minimal SHT for IDA compatibility
    {
        uint64_t dt_symtab = 0, dt_strtab = 0, dt_strsz = 0;
        uint64_t dt_hash = 0, dt_nbucket = 0, dt_nchain = 0;
        uint64_t entsize = is64 ? 16 : 8;

        // Parse DT_* tags if .dynamic is accessible
        if (dyn_vaddr > 0 && dyn_vaddr + entsize <= (uint64_t)fsize) {
            uint64_t di = dyn_vaddr;
            for (int cnt = 0; cnt < 256 && di + entsize <= (uint64_t)fsize; cnt++) {
                uint64_t d_tag, d_val;
                if (is64) {
                    d_tag = *(uint64_t*)(data + di);
                    d_val = *(uint64_t*)(data + di + 8);
                } else {
                    d_tag = *(uint32_t*)(data + di);
                    d_val = *(uint32_t*)(data + di + 4);
                }
                if (d_tag == 0) break;
                switch ((uint32_t)d_tag) {
                    case 5:  dt_strtab = d_val; break;
                    case 6:  dt_symtab = d_val; break;
                    case 4:  dt_hash = d_val; break;
                    case 10: dt_strsz = d_val; break;
                }
                di += entsize;
            }
        }

        // Read hash nbucket/nchain if dt_hash is accessible
        if (dt_hash > 0 && dt_hash + 8 <= (uint64_t)fsize) {
            dt_nbucket = *(uint32_t*)(data + dt_hash);
            dt_nchain = *(uint32_t*)(data + dt_hash + 4);
        }

        // Build shstrtab + section headers at end of file
        uint32_t shoff = (uint32_t)fsize;
        uint8_t *out = data + shoff;
        uint32_t out_off = 0;

        // Helper: write bytes to out buffer
        #define SH_PUT(buf, len) do { memcpy(out + out_off, (buf), (len)); out_off += (len); } while(0)
        #define SH_PUT32(v) do { uint32_t _v = (uint32_t)(v); SH_PUT(&_v, 4); } while(0)
        #define SH_PUT64(v) do { uint64_t _v = (uint64_t)(v); SH_PUT(&_v, 8); } while(0)

        // shstrtab: section name strings (use sizeof, not strlen — first byte is \0)
        uint32_t shstrtab_off = out_off;
        static const char shstrtab[] =
            "\0.shstrtab\0.dynsym\0.dynstr\0.hash\0.dynamic\0";
        uint32_t shstrtab_len = sizeof(shstrtab);
        SH_PUT(shstrtab, shstrtab_len);
        // Name offsets in shstrtab:
        #define SHN_SHSTRTAB  1
        #define SHN_DYNSYM   11
        #define SHN_DYNSTR   19
        #define SHN_HASH     27
        #define SHN_DYNAMIC  33

        // Count sections: always include NULL, .dynsym, .dynstr, .dynamic, .shstrtab
        uint16_t sh_count = 1; // SHT_NULL at index 0
        uint16_t sh_dynsym = sh_count++;
        uint16_t sh_dynstr = sh_count++;
        uint16_t sh_dynamic = sh_count++;
        uint16_t sh_hash = 0;
        if (dt_hash) { sh_hash = sh_count++; }
        uint16_t sh_shstrtab = sh_count++;

        // Calculate SHT size
        uint32_t shentsize = is64 ? 64 : 40;
        uint32_t sht_off = out_off;
        uint32_t sht_size = sh_count * shentsize;
        memset(out + out_off, 0, sht_size);
        out_off += sht_size;

        // Helper: write SHT entry at index
        #define SHDR(idx, name_off, type, flags, addr, off, size, link, info, align, esize) do { \
            uint8_t *s = out + sht_off + (idx) * shentsize; \
            SHDR32(s, 0, name_off); \
            SHDR32(s, 4, type); \
            if (is64) { SHDR64(s, 8, flags); SHDR64(s, 16, addr); SHDR64(s, 24, off); \
                        SHDR64(s, 32, size); SHDR32(s, 40, link); SHDR32(s, 44, info); \
                        SHDR64(s, 48, align); SHDR64(s, 56, esize); } \
            else { SHDR32(s, 8, flags); SHDR32(s, 12, addr); SHDR32(s, 16, off); \
                   SHDR32(s, 20, size); SHDR32(s, 24, link); SHDR32(s, 28, info); \
                   SHDR32(s, 32, align); SHDR32(s, 36, esize); } \
        } while(0)
        #define SHDR32(s, off, v) do { uint32_t _v = (uint32_t)(v); memcpy((s)+(off), &_v, 4); } while(0)
        #define SHDR64(s, off, v) do { uint64_t _v = (uint64_t)(v); memcpy((s)+(off), &_v, 8); } while(0)

        // SHT[0] = NULL (implicitly zero)
        // .dynsym (always present, even if dt_symtab unknown)
        SHDR(sh_dynsym, SHN_DYNSYM, 11/*SHT_DYNSYM*/, 2/*SHF_ALLOC*/,
             dt_symtab ? dt_symtab : dyn_vaddr, dt_symtab ? dt_symtab : dyn_vaddr,
             0, sh_dynstr, 1, is64?8:4, is64?24:16);
        // .dynstr (always present)
        SHDR(sh_dynstr, SHN_DYNSTR, 3/*SHT_STRTAB*/, 2,
             dt_strtab ? dt_strtab : dyn_vaddr, dt_strtab ? dt_strtab : dyn_vaddr,
             dt_strsz ? dt_strsz : 1, 0, 0, 1, 0);
        // .hash
        if (sh_hash) SHDR(sh_hash, SHN_HASH, 5/*SHT_HASH*/, 2, dt_hash, dt_hash, (dt_nbucket+dt_nchain)*4+8, sh_dynsym, 0, 4, 4);
        // .dynamic
        SHDR(sh_dynamic, SHN_DYNAMIC, 6/*SHT_DYNAMIC*/, 3/*SHF_ALLOC|SHF_WRITE*/, dyn_vaddr, dyn_vaddr, dyn_filesz, sh_dynstr, 0, is64?8:4, entsize);
        // .shstrtab (last section)
        SHDR(sh_shstrtab, SHN_SHSTRTAB, 3/*SHT_STRTAB*/, 0, 0, shoff + shstrtab_off, shstrtab_len, 0, 0, 1, 0);

        // Fix dynsym .sh_link to point to .dynstr
        if (sh_dynsym) { uint32_t link = sh_dynstr; memcpy(out + sht_off + sh_dynsym * shentsize + (is64 ? 40 : 24), &link, 4); }

        // Fix .sh_size for .dynsym: pad to next section's sh_addr
        if (sh_dynsym && sh_dynstr && sh_count > 0) {
            uint64_t ds_addr = 0, dn_addr = 0;
            if (is64) { ds_addr = *(uint64_t*)(out + sht_off + sh_dynsym * 64 + 16); dn_addr = *(uint64_t*)(out + sht_off + sh_dynstr * 64 + 16); }
            else { ds_addr = *(uint32_t*)(out + sht_off + sh_dynsym * 40 + 12); dn_addr = *(uint32_t*)(out + sht_off + sh_dynstr * 40 + 12); }
            if (dn_addr > ds_addr) {
                uint64_t sz = dn_addr - ds_addr;
                if (is64) memcpy(out + sht_off + sh_dynsym * 64 + 32, &sz, 8);
                else { uint32_t s32 = (uint32_t)sz; memcpy(out + sht_off + sh_dynsym * 40 + 20, &s32, 4); }
            }
        }

        // Update ELF header: e_shoff, e_shnum, e_shstrndx
        if (is64) {
            uint64_t sho = shoff + sht_off;
            memcpy(data + 0x28, &sho, 8);
            memcpy(data + 0x3C, &sh_count, 2);
            memcpy(data + 0x3E, &sh_shstrtab, 2);
        } else {
            uint32_t sho = (uint32_t)(shoff + sht_off);
            memcpy(data + 0x20, &sho, 4);
            memcpy(data + 0x30, &sh_count, 2);
            memcpy(data + 0x32, &sh_shstrtab, 2);
        }

        fsize = (long)(shoff + out_off);

        #undef SH_PUT
        #undef SH_PUT32
        #undef SH_PUT64
        #undef SHDR
        #undef SHDR32
        #undef SHDR64
    } // end SHT rebuild

save_and_exit:
    // Re-open for truncating write (always save, even partial repair)
    f = fopen(path, "wb");
    if (!f) { free(data); return -1; }
    fwrite(data, 1, (size_t)fsize, f);
    fclose(f);
    free(data);
    return (fsize > 0) ? 0 : -1;
}

// ---- Write manifest JSON for SO objects ----
static void so_manifest_write(const char *so_dir, const MappedObject *objs, int count,
                               int dumped, int skipped_system, int skipped_other) {
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.json", so_dir);
    FILE *f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "{\n  \"total_objects\": %d,\n  \"so_dumped\": %d,\n", count, dumped);
    fprintf(f, "  \"skipped_system\": %d,\n  \"skipped_other\": %d,\n", skipped_system, skipped_other);
    fprintf(f, "  \"objects\": [\n");

    int first = 1;
    for (int i = 0; i < count; i++) {
        const MappedObject *o = &objs[i];
        const char *kind_str = "unknown";
        switch (o->kind) {
            case OBJ_ELF_SO: kind_str = "elf_so"; break;
            case OBJ_ELF_EXEC: kind_str = "elf_exec"; break;
            case OBJ_DEX: kind_str = "dex"; break;
            case OBJ_OAT: kind_str = "oat"; break;
            case OBJ_ODEX: kind_str = "odex"; break;
            case OBJ_APK_ZIP: kind_str = "apk_zip"; break;
            case OBJ_VDSO: kind_str = "vdso"; break;
            case OBJ_MEMFD: kind_str = "memfd"; break;
        }

        if (!first) fprintf(f, ",\n");
        fprintf(f, "    {\"path\":\"%s\",\"name\":\"%s\",\"kind\":\"%s\",\"origin\":%d,"
                "\"policy\":%d,\"size\":%llu}",
                o->path, o->name, kind_str, o->origin, o->policy,
                (unsigned long long)o->file_size);
        first = 0;
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
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

    uint8_t buf[4096 + 0x70];  // +0x70 overlap for cross-page magic/header coverage
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

        #define PAGE_READ_SIZE (4096 + 0x70)
        for (uintptr_t addr = r->start; addr < r->end; addr += 4096) {
            size_t to_read = PAGE_READ_SIZE;
            if (addr + to_read > r->end)
                to_read = (size_t)(r->end - addr);
            ssize_t n = READ_REMOTE(buf, to_read, addr);
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

                    // Strong validation: check endian_tag + all section table ranges
                    {
                        uint8_t hdr_check[0x70];
                        if (READ_REMOTE(hdr_check, 0x70, dex_addr) == 0x70) {
                            if (!dex_header_strong_valid(hdr_check, dex_size)) {
                                continue;  // structural checks failed — likely false positive
                            }
                        }
                    }

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

                // ---- SO (ELF) via maps grouping + classification ----
                // DEX continues with magic-scan; SO is now maps-driven.
                // Handled below after the region loop.


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

    // ---- SO classification-driven dump (maps-based, runs after DEX magic-scan) ----
    if (mode & MODE_SO) {
        MappedObject objs[1024];
        int obj_count = group_maps_by_path_inode(ml, objs, 1024);
        int so_dumped = 0, so_skipped_sys = 0, so_skipped_other = 0;

        // Read ELF header: prefer offset==0 readable region, fallback to any readable
        for (int i = 0; i < obj_count; i++) {
            MappedObject *o = &objs[i];

            // Read header bytes from memory for kind detection
            uint8_t head[64] = {0};
            int have_head = 0;

            // First pass: look for offset==0 && readable
            for (size_t j = 0; j < ml->count; j++) {
                const maps_region *rg = &ml->regs[j];
                if (rg->inode != o->inode || strcmp(rg->path, o->path) != 0) continue;
                if (rg->offset != 0) continue;
                if (!rg->readable) continue;
                if (g_use_vm_readv) {
                    ssize_t n = vm_readv_retry(target_pid, head, sizeof(head), rg->start);
                    if (n > 0) { have_head = 1; break; }
                } else if (mem_fd >= 0) {
                    ssize_t n = pread_retry(mem_fd, head, sizeof(head), (off_t)rg->start);
                    if (n > 0) { have_head = 1; break; }
                }
            }

            // Second pass (fallback): any readable region
            if (!have_head) {
                for (size_t j = 0; j < ml->count; j++) {
                    const maps_region *rg = &ml->regs[j];
                    if (rg->inode != o->inode || strcmp(rg->path, o->path) != 0) continue;
                    if (!rg->readable) continue;
                    if (g_use_vm_readv) {
                        ssize_t n = vm_readv_retry(target_pid, head, sizeof(head), rg->start);
                        if (n > 0) { have_head = 1; break; }
                    } else if (mem_fd >= 0) {
                        ssize_t n = pread_retry(mem_fd, head, sizeof(head), (off_t)rg->start);
                        if (n > 0) { have_head = 1; break; }
                    }
                }
            }

            o->kind = have_head ? classify_kind(o->path, head, sizeof(head)) : OBJ_UNKNOWN;
            o->origin = classify_origin(o->path, pkg);
            o->policy = decide_policy(o);

            if (o->policy == POLICY_SKIP) {
                if (o->origin == ORIGIN_SYSTEM || o->origin == ORIGIN_APEX || o->origin == ORIGIN_VENDOR)
                    so_skipped_sys++;
                else
                    so_skipped_other++;
                snprintf(o->reason, sizeof(o->reason), "skipped: kind=%d origin=%d", o->kind, o->origin);
                continue;
            }

            // Cross-process de-dup by path
            if (so_path_seen(o->path)) {
                so_skipped_other++;
                snprintf(o->reason, sizeof(o->reason), "skipped: cross-process duplicate");
                continue;
            }

            // Build output filename
            char outfile[768];
            if (o->path[0] != '\0') {
                snprintf(outfile, sizeof(outfile), "%s/%s", so_dir, o->name);
            } else {
                snprintf(outfile, sizeof(outfile), "%s/so_%s_%d.so", so_dir, pid, c->so_count + 1);
            }
            // Handle name conflicts: append _2, _3, etc.
            {
                struct stat st;
                if (stat(outfile, &st) == 0) {
                    char alt[768];
                    for (int k = 2; k < 100; k++) {
                        if (o->name[0] != '\0')
                            snprintf(alt, sizeof(alt), "%s/%s_%d.so", so_dir, o->name, k);
                        else
                            snprintf(alt, sizeof(alt), "%s/so_%s_%d_%d.so", so_dir, pid, c->so_count + 1, k);
                        if (stat(alt, &st) != 0) {
                            snprintf(outfile, sizeof(outfile), "%s", alt);
                            break;
                        }
                    }
                }
            }

            // Dump via precise offset-based maps merge
            int rc = dump_object_by_maps(mem_fd, target_pid, o, ml, outfile);
            if (rc == 0) {
                so_path_remember(o->path);
                c->so_count++;
                so_dumped++;
                printf("[+] SO: %s (%llu bytes, %d segs) origin=%d kind=%d pid=%s\n",
                       outfile, (unsigned long long)o->file_size, o->region_count,
                       o->origin, o->kind, pid);

                // Repair deferred to main()'s unified batch pass (avoids double-repair)
                snprintf(o->reason, sizeof(o->reason), "dumped: %llu bytes, %d regions",
                         (unsigned long long)o->file_size, o->region_count);
            } else {
                so_skipped_other++;
                snprintf(o->reason, sizeof(o->reason), "dump failed");
            }
        }

        // Write manifest
        so_manifest_write(so_dir, objs, obj_count, so_dumped, so_skipped_sys, so_skipped_other);
        fprintf(stderr, "[*] SO classification: %d total objects, %d dumped, %d skipped (system), %d skipped (other)\n",
                obj_count, so_dumped, so_skipped_sys, so_skipped_other);
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
// NHDD_LIB_ONLY compiles nhdd.c without main() so the contract-test host
// harness (tests/contract/v8_harness.c) can link the static repair primitives
// directly. The device build never defines it — behavior is unchanged.
#ifndef NHDD_LIB_ONLY
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

    const char *target = NULL;
    const char *out_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--so") == 0) { mode = MODE_SO; continue; }
        if (strcmp(argv[i], "--dex") == 0) { mode = MODE_DEX; continue; }
        if (strcmp(argv[i], "--all") == 0 || strcmp(argv[i], "--apk") == 0) { mode = MODE_ALL; continue; }
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
        if (strcmp(argv[i], "--anon") == 0) { g_anon_only = 1; continue; }
        if (strcmp(argv[i], "--region-delay") == 0 && i + 1 < argc) {
            g_region_delay_us = atoi(argv[++i]) * 1000; continue;  // ms -> us
        }
        if ((strcmp(argv[i], "--name") == 0 || strcmp(argv[i], "--disguise") == 0)
            && i + 1 < argc) { disguise = argv[++i]; continue; }
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
    if (disguise) disguise = strdup(disguise);
    // Apply disguise early, before we open any target /proc files.
    disguise_self(argc, argv, disguise);

    if (!target) {
        fprintf(stderr,
            "NHDD — No-Hook DEX/SO Dumper v8.0\n"
            "Usage: %s <pid|package> [output_dir] [--so|--dex|--all]\n"
            "                       [--watch [K]] [--snapshot ROUNDS] [--interval SECS]\n"
            "                       [--stealth] [--stealth2] [--relaxed] [--anon]\n"
            "                       [--region-delay MS] [--name NAME]\n"
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
            "  SO files are automatically repaired with built-in elf_repair_basic.\n"
            "\n"
            "  DEX checksums (SHA-1 + Adler32) are auto-fixed; hits are validated\n"
            "  (DEX version tag + header fields) to reject false positives.\n",
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
        int unique_before = c.dex_unique + c.so_count;

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
            int new_this = (c.dex_unique + c.so_count) - unique_before;
            if (new_this > 0) dry_rounds = 0; else dry_rounds++;
            fprintf(stderr, "[*] round %d: +%d new unique (DEX=%d, SO=%d, dry=%d/%d)\n",
                    round + 1, new_this, c.dex_unique, c.so_count, dry_rounds, watch_dry_limit);
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

    // ---- Auto-fix SO files with built-in repair ----
    if (c.so_count > 0) {
        fprintf(stderr, "[*] Fixing %d SO files with built-in ELF repair...\n", c.so_count);
        int fixed = 0, failed = 0;

        DIR *d = opendir(so_dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d))) {
                if (de->d_type != DT_REG && de->d_type != DT_UNKNOWN) continue;
                size_t namelen = strlen(de->d_name);
                if (namelen < 4 || strcmp(de->d_name + namelen - 3, ".so") != 0) continue;

                char path[768];
                snprintf(path, sizeof(path), "%s/%s", so_dir, de->d_name);
                if (elf_repair_basic(path) == 0) {
                    fixed++;
                } else {
                    failed++;
                    fprintf(stderr, "[-] Repair failed: %s\n", de->d_name);
                }
            }
            closedir(d);
        }
        fprintf(stderr, "[*] Built-in repair: %d fixed, %d failed\n", fixed, failed);
    }

    return 0;
}
#endif /* NHDD_LIB_ONLY */
