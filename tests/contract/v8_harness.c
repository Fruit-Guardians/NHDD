// v8_harness.c — primitive-level contract harness for the device-side dumper
// (nhdd.c, "v8"). nhdd.c is #included wholesale with NHDD_LIB_ONLY so its
// static repair primitives are reachable from this single translation unit.
//
// Applies, over a fixture work dir (dex/*.dex, so/*.so), in place:
//   dex: fix_dex_header_and_checksums (header fields + SHA-1 + Adler32)
//   so : elf_repair_basic (identity fixes + p_offset=p_vaddr + appended SHT)
//
// No quarantine semantics exist on-device (that lives in the host pipelines),
// so BAD-class expectations are not judged for this harness.
//
// Build (host, Linux; Android/Linux-only headers make Windows skip it):
//   gcc -std=gnu11 -O1 -w -fno-strict-aliasing v8_harness.c -o v8_harness
// Run: v8_harness <workdir-with-dex-and-so>

#define NHDD_LIB_ONLY 1

// Must be the first include: nhdd.c defines _GNU_SOURCE before its own
// system headers, which the glibc feature-test macros need to see early.
#include "../../nhdd.c"

static int slurp(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(buf); return -1; }
    *out = buf;
    *out_len = (size_t)n;
    return 0;
}

static int spit(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = fwrite(buf, 1, len, f);
    fclose(f);
    return put == len ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <workdir>\n", argv[0]);
        return 2;
    }

    char dirpath[768];
    int errors = 0;

    snprintf(dirpath, sizeof(dirpath), "%s/dex", argv[1]);
    DIR *d = opendir(dirpath);
    if (!d) { perror("opendir dex"); return 1; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_type != DT_REG) continue;
        size_t l = strlen(de->d_name);
        if (l < 4 || strcmp(de->d_name + l - 4, ".dex") != 0) continue;
        char path[1536];
        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
        uint8_t *buf = NULL;
        size_t len = 0;
        if (slurp(path, &buf, &len) != 0) { errors++; continue; }
        fix_dex_header_and_checksums(buf, len);  // guards size<0x70 || bad magic
        if (spit(path, buf, len) != 0) errors++;
        free(buf);
    }
    closedir(d);

    snprintf(dirpath, sizeof(dirpath), "%s/so", argv[1]);
    d = opendir(dirpath);
    if (!d) { perror("opendir so"); return 1; }
    while ((de = readdir(d)) != NULL) {
        if (de->d_type != DT_REG) continue;
        size_t l = strlen(de->d_name);
        if (l < 3 || strcmp(de->d_name + l - 3, ".so") != 0) continue;
        char path[1536];
        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
        (void)elf_repair_basic(path);  // -1 on <0x40 bytes: file left untouched
    }
    closedir(d);

    printf("v8_harness done errors=%d\n", errors);
    return 0;
}
