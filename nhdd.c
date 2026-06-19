// nhdd.c — No-Hook DEX/SO Dumper (NHDD)
// Scan a process for DEX and SO files via /proc/<pid>/mem, dump and auto-fix.
// No injection, no hooks — undetectable by packer security checks.
//
// Build: aarch64-linux-android34-clang -O2 -static -o nhdd nhdd.c
// Usage: nhdd <pid|package> [output_dir] [--so|--dex|--all]
//
// Features:
//   - Accept PID or package name (auto-resolve via /proc/*/cmdline)
//   - Page-by-page scanning (proven effective, no false negatives)
//   - Dump DEX files (default) with auto-fix SHA-1 + Adler32
//   - Dump SO files (--so) with auto-fix ELF header
//   - Dump both (--all)
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
#include <sys/stat.h>
#include <errno.h>

// ---- Magic constants ----
static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"
static const uint8_t kElfMagic[] = {0x7f, 0x45, 0x4c, 0x46}; // \x7fELF

// ---- Dump mode ----
#define MODE_DEX 1
#define MODE_SO  2
#define MODE_ALL (MODE_DEX | MODE_SO)

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

static int find_pid_for_package(const char *pkg, char *pid_out, size_t pid_sz) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    int best_pid = -1;
    while ((de = readdir(d))) {
        const char *n = de->d_name;
        int all_digit = 1;
        for (const char *c = n; *c; c++)
            if (!isdigit((unsigned char)*c)) { all_digit = 0; break; }
        if (!all_digit) continue;
        char cmd[256];
        if (read_cmdline(n, cmd, sizeof(cmd)) != 0) continue;
        if (strcmp(cmd, pkg) != 0) continue;
        int pid_val = atoi(n);
        if (best_pid < 0 || pid_val < best_pid)
            best_pid = pid_val;
    }
    closedir(d);
    if (best_pid < 0) return -1;
    snprintf(pid_out, pid_sz, "%d", best_pid);
    return 0;
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

// ---- Fix DEX checksums (SHA-1 + Adler32) ----
static void fix_dex_checksums(uint8_t *data, size_t size) {
    if (size < 0x24 || memcmp(data, kDexMagic, 4) != 0) return;
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data + 0x20, size - 0x20);
    uint8_t sha1[20];
    sha1_final(&ctx, sha1);
    memcpy(data + 0x0C, sha1, 20);
    uint32_t cksum = my_adler32(data + 0x0C, size - 0x0C);
    memcpy(data + 0x08, &cksum, 4);
}

// ---- Get SO name from maps line ----
// Extracts the filename from a maps line like:
// 7f8a001000-7f8a100000 r-xp 00000000 fd:00 12345 /data/app/.../libfoo.so
static void get_so_name_from_maps(const char *pid, uintptr_t start_addr, char *name_out, size_t name_sz) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { name_out[0] = '\0'; return; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) < 2) continue;
        if (s == start_addr) {
            // Find the pathname after the inode
            char *p = strchr(line, '/');
            if (!p) p = strchr(line, '[');
            if (p) {
                // Remove trailing newline
                size_t len = strlen(p);
                if (len > 0 && p[len-1] == '\n') p[len-1] = '\0';
                strncpy(name_out, p, name_sz - 1);
                name_out[name_sz - 1] = '\0';
            } else {
                name_out[0] = '\0';
            }
            fclose(f);
            return;
        }
    }
    fclose(f);
    name_out[0] = '\0';
}

// ---- Extract basename from path ----
static const char *my_basename(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

// ---- Main ----
int main(int argc, char **argv) {
    int mode = MODE_DEX; // default: dump DEX only

    // Parse arguments
    const char *target = NULL;
    const char *out_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--so") == 0) { mode = MODE_SO; continue; }
        if (strcmp(argv[i], "--dex") == 0) { mode = MODE_DEX; continue; }
        if (strcmp(argv[i], "--all") == 0) { mode = MODE_ALL; continue; }
        if (!target) { target = argv[i]; continue; }
        if (!out_dir) { out_dir = argv[i]; continue; }
    }

    if (!target) {
        fprintf(stderr,
            "NHDD — No-Hook DEX/SO Dumper v4.0\n"
            "Usage: %s <pid|package> [output_dir] [--so|--dex|--all]\n"
            "\n"
            "  Modes:\n"
            "    --dex  Dump DEX files only (default)\n"
            "    --so   Dump SO files only\n"
            "    --all  Dump both DEX and SO files\n"
            "\n"
            "  DEX checksums (SHA-1 + Adler32) are auto-fixed.\n"
            "  SO files are dumped from memory (may differ from disk).\n",
            argv[0]);
        return 1;
    }

    if (!out_dir) out_dir = "/data/local/tmp/nhdd_dump";

    // Resolve target to PID
    char pid_buf[16];
    const char *pid;
    int is_numeric = 1;
    for (const char *c = target; *c; c++) {
        if (!isdigit((unsigned char)*c)) { is_numeric = 0; break; }
    }

    if (is_numeric) {
        pid = target;
    } else {
        if (find_pid_for_package(target, pid_buf, sizeof(pid_buf)) != 0) {
            fprintf(stderr, "[-] No running process matches package '%s'\n", target);
            return 1;
        }
        pid = pid_buf;
        fprintf(stderr, "[*] Resolved package '%s' -> PID %s\n", target, pid);
    }

    // Read package name from PID
    char pkg[256] = "unknown";
    read_cmdline(pid, pkg, sizeof(pkg));
    fprintf(stderr, "[*] Target package: %s (PID %s)\n", pkg, pid);

    // Open maps and mem
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) { fprintf(stderr, "[-] Cannot open %s: %s\n", path, strerror(errno)); return 1; }

    snprintf(path, sizeof(path), "/proc/%s/mem", pid);
    int mem_fd = open(path, O_RDONLY);
    if (mem_fd < 0) { fprintf(stderr, "[-] Cannot open %s: %s\n", path, strerror(errno)); fclose(maps); return 1; }

    // Create output directories
    char dex_dir[512], so_dir[512];
    snprintf(dex_dir, sizeof(dex_dir), "%s/dex", out_dir);
    snprintf(so_dir, sizeof(so_dir), "%s/so", out_dir);
    mkdir(out_dir, 0777);
    if (mode & MODE_DEX) mkdir(dex_dir, 0777);
    if (mode & MODE_SO)  mkdir(so_dir, 0777);

    if (mode & MODE_DEX)
        fprintf(stderr, "[*] Scanning for DEX files...\n");
    if (mode & MODE_SO)
        fprintf(stderr, "[*] Scanning for SO files...\n");
    fprintf(stderr, "[*] Output directory: %s\n", out_dir);

    char line[512];
    int dex_count = 0, so_count = 0;
    uint8_t buf[4096];

    // Track dumped SO base addresses to avoid duplicates
    uintptr_t dumped_so_bases[256];
    int dumped_so_count = 0;

    // Page-by-page scanning
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (perms[0] != 'r') continue;

        size_t region_size = end - start;
        if (region_size < 64 || region_size > 0x40000000) continue;

        for (uintptr_t addr = start; addr < end; addr += 4096) {
            ssize_t n = pread(mem_fd, buf, sizeof(buf), (off_t)addr);
            if (n < 64) continue;

            for (int i = 0; i <= n - 4; i++) {
                // ---- DEX scanning ----
                if ((mode & MODE_DEX) && memcmp(buf + i, kDexMagic, 4) == 0) {
                    uintptr_t dex_addr = addr + i;

                    uint32_t dex_size = 0;
                    if (i + 0x24 <= n) {
                        memcpy(&dex_size, buf + i + 0x20, 4);
                    } else {
                        uint8_t hdr[64];
                        pread(mem_fd, hdr, 64, (off_t)dex_addr);
                        memcpy(&dex_size, hdr + 0x20, 4);
                    }

                    if (dex_size < 64 || dex_size > 0x10000000) continue;

                    dex_count++;
                    fprintf(stderr, "[+] Found DEX #%d at 0x%lx size=%u\n",
                           dex_count, (unsigned long)dex_addr, dex_size);

                    char outfile[512];
                    snprintf(outfile, sizeof(outfile),
                             "%s/dump_%d_%d.dex", dex_dir, atoi(pid), dex_count);

                    uint8_t *dex_data = (uint8_t *)malloc(dex_size);
                    if (!dex_data) { fprintf(stderr, "[-] malloc failed\n"); continue; }

                    ssize_t read_total = 0;
                    while (read_total < (ssize_t)dex_size) {
                        ssize_t r = pread(mem_fd, dex_data + read_total,
                                          dex_size - read_total,
                                          (off_t)(dex_addr + read_total));
                        if (r <= 0) break;
                        read_total += r;
                    }

                    if (read_total > 0) {
                        fix_dex_checksums(dex_data, read_total);
                        int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                        if (fd >= 0) {
                            write(fd, dex_data, read_total);
                            close(fd);
                            printf("[+] DEX: %s (%zd bytes)\n", outfile, read_total);
                        }
                    }
                    free(dex_data);
                    i += (dex_size > 4096 ? 4096 : dex_size);
                }

                // ---- SO (ELF) scanning ----
                if ((mode & MODE_SO) && memcmp(buf + i, kElfMagic, 4) == 0) {
                    uintptr_t elf_addr = addr + i;

                    // Only dump ELF at page boundary (start of mmap'd region)
                    // to avoid dumping ELF headers in the middle of data
                    if (i != 0) continue;

                    // Check if we already dumped this base address
                    int already_dumped = 0;
                    for (int j = 0; j < dumped_so_count; j++) {
                        if (dumped_so_bases[j] == elf_addr) {
                            already_dumped = 1;
                            break;
                        }
                    }
                    if (already_dumped) continue;

                    // Read ELF header to get size info
                    uint8_t elf_hdr[64];
                    if (pread(mem_fd, elf_hdr, 64, (off_t)elf_addr) < 64) continue;

                    // Check ELF class (32 or 64 bit)
                    int is_64 = (elf_hdr[4] == 2); // EI_CLASS
                    if (elf_hdr[4] != 1 && elf_hdr[4] != 2) continue;

                    // Get e_type (offset 16, 2 bytes LE)
                    uint16_t e_type = elf_hdr[16] | (elf_hdr[17] << 8);
                    // Only dump shared objects (ET_DYN = 3)
                    if (e_type != 3) continue;

                    // Get the full size from maps
                    // Find all contiguous regions belonging to this SO
                    // Use the maps line we already have to determine the first segment
                    // For a more accurate size, scan maps for all segments at this base

                    // Simple approach: use the current region size as minimum,
                    // then try to find the full mapped range
                    uintptr_t so_start = elf_addr;
                    uintptr_t so_end = end;

                    // Look ahead in maps for more segments of the same file
                    // For now, just use a reasonable max size
                    // Read up to 64MB max for a single SO
                    size_t max_so_size = 64 * 1024 * 1024;
                    size_t so_size = so_end - so_start;
                    if (so_size > max_so_size) so_size = max_so_size;

                    // Try to determine actual SO size from ELF program headers
                    if (is_64) {
                        // ELF64: e_phoff=off28(8B), e_phentsize=off54(2B), e_phnum=off56(2B)
                        uint64_t e_phoff = 0;
                        memcpy(&e_phoff, elf_hdr + 32, 8);
                        uint16_t e_phentsize = elf_hdr[54] | (elf_hdr[55] << 8);
                        uint16_t e_phnum = elf_hdr[56] | (elf_hdr[57] << 8);

                        // Find the maximum vaddr + memsz from LOAD segments
                        uint64_t max_addr = 0;
                        for (int p = 0; p < e_phnum && p < 32; p++) {
                            uint8_t phdr[56];
                            if (pread(mem_fd, phdr, 56, (off_t)(elf_addr + e_phoff + p * e_phentsize)) < 56) break;
                            uint32_t p_type = 0;
                            memcpy(&p_type, phdr, 4);
                            if (p_type != 1) continue; // PT_LOAD
                            uint64_t p_vaddr = 0, p_memsz = 0;
                            memcpy(&p_vaddr, phdr + 16, 8);
                            memcpy(&p_memsz, phdr + 40, 8);
                            uint64_t seg_end = p_vaddr + p_memsz;
                            if (seg_end > max_addr) max_addr = seg_end;
                        }
                        if (max_addr > 0 && max_addr < max_so_size) {
                            so_size = (size_t)max_addr;
                        }
                    } else {
                        // ELF32: e_phoff=off28(4B), e_phentsize=off42(2B), e_phnum=off44(2B)
                        uint32_t e_phoff = 0;
                        memcpy(&e_phoff, elf_hdr + 28, 4);
                        uint16_t e_phentsize = elf_hdr[42] | (elf_hdr[43] << 8);
                        uint16_t e_phnum = elf_hdr[44] | (elf_hdr[45] << 8);

                        uint32_t max_addr = 0;
                        for (int p = 0; p < e_phnum && p < 32; p++) {
                            uint8_t phdr[32];
                            if (pread(mem_fd, phdr, 32, (off_t)(elf_addr + e_phoff + p * e_phentsize)) < 32) break;
                            uint32_t p_type = 0;
                            memcpy(&p_type, phdr, 4);
                            if (p_type != 1) continue;
                            uint32_t p_vaddr = 0, p_memsz = 0;
                            memcpy(&p_vaddr, phdr + 12, 4);
                            memcpy(&p_memsz, phdr + 20, 4);
                            uint32_t seg_end = p_vaddr + p_memsz;
                            if (seg_end > max_addr) max_addr = seg_end;
                        }
                        if (max_addr > 0 && max_addr < max_so_size) {
                            so_size = (size_t)max_addr;
                        }
                    }

                    // Track this base address
                    if (dumped_so_count < 256) {
                        dumped_so_bases[dumped_so_count++] = elf_addr;
                    }

                    so_count++;
                    fprintf(stderr, "[+] Found SO #%d at 0x%lx size=%zu\n",
                           so_count, (unsigned long)elf_addr, so_size);

                    // Get SO name from maps
                    char so_path[512] = "unknown";
                    get_so_name_from_maps(pid, elf_addr, so_path, sizeof(so_path));

                    // Build output filename
                    char outfile[512];
                    if (so_path[0] != '\0' && strcmp(so_path, "unknown") != 0) {
                        const char *bname = my_basename(so_path);
                        snprintf(outfile, sizeof(outfile), "%s/%s", so_dir, bname);
                    } else {
                        snprintf(outfile, sizeof(outfile), "%s/so_%d_%d.so", so_dir, atoi(pid), so_count);
                    }

                    uint8_t *so_data = (uint8_t *)malloc(so_size);
                    if (!so_data) { fprintf(stderr, "[-] malloc failed\n"); continue; }

                    ssize_t read_total = 0;
                    while (read_total < (ssize_t)so_size) {
                        ssize_t r = pread(mem_fd, so_data + read_total,
                                          so_size - read_total,
                                          (off_t)(elf_addr + read_total));
                        if (r <= 0) break;
                        read_total += r;
                    }

                    if (read_total > 0) {
                        int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                        if (fd >= 0) {
                            write(fd, so_data, read_total);
                            close(fd);
                            printf("[+] SO: %s (%zd bytes) from %s\n", outfile, read_total, so_path);
                        }
                    }
                    free(so_data);
                    // Skip past this SO
                    i += 4096;
                }
            }
        }
    }

    close(mem_fd);
    fclose(maps);

    fprintf(stderr, "\n[*] Done. Found %d DEX, %d SO files in %s\n",
            dex_count, so_count, out_dir);

    // ---- Auto-fix SO files with SoFixer ----
    if (so_count > 0) {
        // Check if sofixer binary exists
        const char *sofixer_paths[] = {
            "/data/local/tmp/sofixer",
            "/data/local/tmp/SoFixer64",
            NULL
        };
        const char *sofixer = NULL;
        for (int i = 0; sofixer_paths[i]; i++) {
            if (access(sofixer_paths[i], X_OK) == 0) {
                sofixer = sofixer_paths[i];
                break;
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
                        // Replace original with fixed version
                        unlink(src);
                        rename(dst, src);
                        fixed++;
                        fprintf(stderr, "[+] Fixed: %s\n", de->d_name);
                    } else {
                        // Fix failed, keep original dump
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
