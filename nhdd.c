// nhdd.c — No-Hook DEX Dumper (NHDD)
// Scan a process for DEX files via /proc/<pid>/mem, dump and auto-fix checksums.
// No injection, no hooks — undetectable by packer security checks.
//
// Combines the best of dex_scanner (SHA-1+Adler32 auto-fix) and dexhound
// (package name resolution, header validation, region filtering).
//
// Build: aarch64-linux-android34-clang -O2 -static -o nhdd nhdd.c
// Usage: nhdd <pid|package> [output_dir]
//
// Features:
//   - Accept PID or package name (auto-resolve via /proc/*/cmdline)
//   - Strict DEX validation: magic + version + header_size + endian_tag
//   - Filter out system regions (/system, /apex, /dev, other apps)
//   - Auto-fix SHA-1 signature and Adler32 checksum
//   - Track DEX source region for debugging
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

// ---- DEX constants ----
static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"
#define DEX_HEADER_SIZE 0x70
#define DEX_ENDIAN_TAG  0x12345678

// ---- Strict DEX magic validation (from dexhound) ----
static int is_valid_dex_header(const uint8_t *p) {
    // Check "dex\n" magic
    if (memcmp(p, kDexMagic, 4) != 0) return 0;
    // Check version string: 3 digits + NUL (e.g. "035\0", "039\0")
    if (p[4] < '0' || p[4] > '9') return 0;
    if (p[5] < '0' || p[5] > '9') return 0;
    if (p[6] < '0' || p[6] > '9') return 0;
    if (p[7] != 0) return 0;
    return 1;
}

// ---- Package name resolution (from dexhound) ----
static int read_cmdline(const char *pid, char *out, size_t outsz) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, out, outsz - 1);
    close(fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    // Strip ":subproc" suffix
    char *colon = strchr(out, ':');
    if (colon) *colon = '\0';
    return 0;
}

static int find_pid_for_package(const char *pkg, char *pid_out, size_t pid_sz) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        const char *n = de->d_name;
        int all_digit = 1;
        for (const char *c = n; *c; c++)
            if (!isdigit((unsigned char)*c)) { all_digit = 0; break; }
        if (!all_digit) continue;
        char cmd[256];
        if (read_cmdline(n, cmd, sizeof(cmd)) != 0) continue;
        if (strcmp(cmd, pkg) != 0) continue;
        snprintf(pid_out, pid_sz, "%s", n);
        closedir(d);
        return 0;
    }
    closedir(d);
    return -1;
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
    if (i < len) memcpy(ctx->buffer, data+i, len-i);
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
    if (size < DEX_HEADER_SIZE) return;
    // 1. Fix SHA-1 signature (offset 0x0C, covers 0x20..file_size)
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data + 0x20, size - 0x20);
    uint8_t sha1[20];
    sha1_final(&ctx, sha1);
    memcpy(data + 0x0C, sha1, 20);
    // 2. Fix Adler32 checksum (offset 0x08, covers 0x0C..file_size)
    uint32_t cksum = my_adler32(data + 0x0C, size - 0x0C);
    memcpy(data + 0x08, &cksum, 4);
}

// ---- Region filtering (from dexhound) ----
// Returns 1 if this region should be scanned, 0 if skipped
static int should_scan_region(const char *region_path, const char *pkg) {
    // Skip device mappings
    if (strstr(region_path, "/dev/")) return 0;
    // Skip system framework
    if (strncmp(region_path, "/system/", 8) == 0) return 0;
    if (strncmp(region_path, "/system_ext/", 12) == 0) return 0;
    if (strncmp(region_path, "/apex/", 6) == 0) return 0;
    // Skip other apps' data (but allow target app's data)
    if (strncmp(region_path, "/data/", 6) == 0 && !strstr(region_path, pkg)) return 0;
    return 1;
}

// ---- Main ----
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "NHDD — No-Hook DEX Dumper v2.0\n"
            "Usage: %s <pid|package> [output_dir]\n"
            "\n"
            "  Accepts either a numeric PID or a package name.\n"
            "  Package names are auto-resolved via /proc/*/cmdline.\n"
            "  DEX checksums (SHA-1 + Adler32) are auto-fixed.\n",
            argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *out_dir = argc > 2 ? argv[2] : "/data/local/tmp/nhdd_dump";

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
    int mem_fd = open(path, O_RDONLY | O_LARGEFILE);
    if (mem_fd < 0) { fprintf(stderr, "[-] Cannot open %s: %s\n", path, strerror(errno)); fclose(maps); return 1; }

    // Create output directory
    mkdir(out_dir, 0777);

    fprintf(stderr, "[*] Scanning memory for DEX files...\n");
    fprintf(stderr, "[*] Output directory: %s\n", out_dir);

    char line[512];
    int found = 0, fixed = 0, skipped = 0;
    uint8_t *region_buf = NULL;

    while (fgets(line, sizeof(line), maps)) {
        uint64_t start, end;
        char perms[5] = {};
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue;

        uint64_t region_size = end - start;
        if (region_size < DEX_HEADER_SIZE || region_size > (1ULL << 30)) continue;

        // Extract region path
        char region_path[256] = "[anon]";
        const char *sp = strchr(line, '/');
        if (!sp) sp = strchr(line, '[');
        if (sp) {
            size_t n = strcspn(sp, "\n");
            if (n >= sizeof(region_path)) n = sizeof(region_path) - 1;
            memcpy(region_path, sp, n);
            region_path[n] = '\0';
        }

        // Filter regions
        if (!should_scan_region(region_path, pkg)) {
            skipped++;
            continue;
        }

        // Read entire region at once (more efficient than page-by-page)
        region_buf = (uint8_t *)realloc(region_buf, region_size);
        if (!region_buf) continue;
        ssize_t r = pread(mem_fd, region_buf, region_size, (off_t)start);
        if (r < DEX_HEADER_SIZE) continue;

        // Scan for DEX headers within this region
        for (ssize_t i = 0; i + DEX_HEADER_SIZE < r; i++) {
            if (!is_valid_dex_header(region_buf + i)) continue;

            // Validate header fields
            uint32_t file_size, header_size, endian_tag, stored_adler;
            memcpy(&file_size,   region_buf + i + 0x20, 4);
            memcpy(&header_size, region_buf + i + 0x24, 4);
            memcpy(&endian_tag,  region_buf + i + 0x28, 4);
            memcpy(&stored_adler, region_buf + i + 0x08, 4);

            if (header_size != DEX_HEADER_SIZE) continue;
            if (endian_tag != DEX_ENDIAN_TAG) continue;
            if (file_size < DEX_HEADER_SIZE || file_size > (uint32_t)(r - i)) continue;

            // Verify Adler32
            uint32_t calc_adler = my_adler32(region_buf + i + 0x0C, file_size - 0x0C);
            int needs_fix = (calc_adler != stored_adler);

            found++;

            // Output filename with address and checksum status
            char outfile[512];
            const char *tag = needs_fix ? "FIX" : "OK";
            snprintf(outfile, sizeof(outfile), "%s/dump_%016" PRIx64 "_%s_%s.dex",
                     out_dir, start + i, tag, pkg);

            // Copy DEX data and fix checksums if needed
            uint8_t *dex_data = (uint8_t *)malloc(file_size);
            if (!dex_data) continue;
            memcpy(dex_data, region_buf + i, file_size);

            if (needs_fix) {
                fix_dex_checksums(dex_data, file_size);
                fixed++;
            }

            int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                write(fd, dex_data, file_size);
                close(fd);
                printf("[+] %s  (%u bytes)  adler32=%08x->%08x [%s]  src=%s\n",
                       outfile, file_size, stored_adler,
                       needs_fix ? my_adler32(dex_data + 0x0C, file_size - 0x0C) : stored_adler,
                       tag, region_path);
            } else {
                fprintf(stderr, "[-] Cannot create %s: %s\n", outfile, strerror(errno));
            }
            free(dex_data);

            // Skip past this DEX
            i += file_size - 1;
        }
    }

    free(region_buf);
    close(mem_fd);
    fclose(maps);

    fprintf(stderr, "\n[*] Done. Found %d DEX files, fixed %d, skipped %d regions\n",
            found, fixed, skipped);
    fprintf(stderr, "[*] Output: %s\n", out_dir);
    return 0;
}
