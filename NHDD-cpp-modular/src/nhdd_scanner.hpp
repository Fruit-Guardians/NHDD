// nhdd_scanner.hpp — Single PID scanner: DEX/SO/JNI orchestration (1:1 port of original nhdd.c scan_pid)
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <sys/uio.h>
#include <dirent.h>
#include "common_types.hpp"
#include "nhdd_config.hpp"
#include "dedup_table.hpp"
#include "dex_validator.hpp"
#include "process_manager.hpp"
#include "object_classifier.hpp"
#include "jnimap_scanner.hpp"

// ---- Forward-declared helper: load /proc/pid/maps ----
static int load_maps_inline(const char* pid,
                             MapsRegion** out_regs, size_t* out_count) {
    char path[256];
    std::snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return -1;

    size_t cap = 512;
    auto* regs = static_cast<MapsRegion*>(std::calloc(cap, sizeof(MapsRegion)));
    if (!regs) { std::fclose(f); return -1; }
    size_t count = 0;

    char line[1024];
    while (std::fgets(line, sizeof(line), f)) {
        if (count == cap) {
            cap *= 2;
            auto* nr = static_cast<MapsRegion*>(std::realloc(regs, cap * sizeof(MapsRegion)));
            if (!nr) break;
            regs = nr;
            std::memset(regs + count, 0, (cap - count) * sizeof(MapsRegion));
        }
        MapsRegion* r = &regs[count];
        std::memset(r, 0, sizeof(*r));

        unsigned long dmaj = 0, dmin = 0, off = 0, ino = 0;
        int n = std::sscanf(line, "%lx-%lx %7s %lx %lx:%lx %lu",
                            &r->start, &r->end, r->perms, &off, &dmaj, &dmin, &ino);
        if (n < 7) {
            if (std::sscanf(line, "%lx-%lx %7s", &r->start, &r->end, r->perms) < 3)
                continue;
            off = 0; dmaj = 0; dmin = 0; ino = 0;
        }
        r->offset = static_cast<uint64_t>(off);
        r->inode = static_cast<uint64_t>(ino);
        r->dev_major = static_cast<uint32_t>(dmaj);
        r->dev_minor = static_cast<uint32_t>(dmin);

        for (int i = 0; i < 4; i++) {
            if (r->perms[i] == 'r') r->readable = true;
            if (r->perms[i] == 'w') r->writable = true;
            if (r->perms[i] == 'x') r->executable = true;
        }
        char* p = line;
        int fields = 0;
        while (fields < 5 && *p) {
            while (*p == ' ') p++;
            if (!*p) break;
            while (*p && *p != ' ' && *p != '\n') p++;
            fields++;
        }
        while (*p == ' ') p++;
        if (*p && *p != '\n') {
            size_t plen = std::strlen(p);
            while (plen > 0 && (p[plen - 1] == '\n' || p[plen - 1] == '\r'))
                plen--;
            std::snprintf(r->path, sizeof(r->path), "%.*s", static_cast<int>(plen), p);
        }
        count++;
    }
    std::fclose(f);
    *out_regs = regs;
    *out_count = count;
    return 0;
}

static ssize_t read_remote_retry_inline(int mem_fd, pid_t target_pid, void* buf,
                                        size_t size, uintptr_t addr, bool use_vm_readv) {
    size_t got = 0;
    while (got < size) {
        ssize_t rr;
        if (use_vm_readv) {
            struct iovec loc, rem;
            loc.iov_base = static_cast<uint8_t*>(buf) + got;
            loc.iov_len = size - got;
            rem.iov_base = reinterpret_cast<void*>(addr + got);
            rem.iov_len = size - got;
            rr = process_vm_readv(target_pid, &loc, 1, &rem, 1, 0);
        } else {
            rr = ::pread(mem_fd, static_cast<uint8_t*>(buf) + got, size - got,
                         static_cast<off_t>(addr + got));
        }
        if (rr > 0) { got += static_cast<size_t>(rr); continue; }
        if (rr < 0 && errno == EINTR) continue;
        break;
    }
    return static_cast<ssize_t>(got);
}


static bool deep_so_region_candidate(const MapsRegion* r, const char* pkg) {
    if (!r || !r->readable) return false;
    size_t region_size = r->end - r->start;
    if (region_size < 0x40 || region_size > 0x40000000u) return false;
    // Only scan executable regions — shellcode / decrypted ELF lives in X pages.
    // Pure RW anonymous heap is huge and never contains valid ELFs.
    if (!r->executable) return false;
    // Runtime-unpacked SOs normally live in anonymous / memfd / app-private mappings.
    if (r->path[0] == '\0' || r->inode == 0) return true;
    if (std::strstr(r->path, "memfd") || std::strstr(r->path, "ashmem")) return true;
    if ((std::strstr(r->path, "/data/data/") || std::strstr(r->path, "/data/user/0/")) &&
        (!pkg || !*pkg || std::strstr(r->path, pkg))) return true;
    return false;
}

static uint64_t read_u32_le(const uint8_t* p) {
    uint32_t v = 0; std::memcpy(&v, p, 4); return v;
}
static uint64_t read_u16_le(const uint8_t* p) {
    uint16_t v = 0; std::memcpy(&v, p, 2); return v;
}
static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0; std::memcpy(&v, p, 8); return v;
}

static int dump_mem_elf_at_inline(int mem_fd, pid_t pid, uintptr_t elf_addr,
                                  const char* so_dir, const char* pid_s,
                                  SoDedup& so_dedup, int* so_counter,
                                  bool use_vm_readv) {
    char key[128];
    std::snprintf(key, sizeof(key), "memelf_%s_%lx", pid_s, (unsigned long)elf_addr);
    if (so_dedup.seen(key)) return 0;

    uint8_t hdr[0x4000];
    std::memset(hdr, 0, sizeof(hdr));
    ssize_t hn = read_remote_retry_inline(mem_fd, pid, hdr, sizeof(hdr), elf_addr, use_vm_readv);
    if (hn < 0x40 || std::memcmp(hdr, "\x7f""ELF", 4) != 0) return 0;
    if (hdr[4] != 1 && hdr[4] != 2) return 0;
    if (hdr[5] != 1) return 0; // Android is little-endian.

    bool is64 = hdr[4] == 2;
    uint64_t e_phoff = is64 ? read_u64_le(hdr + 32) : read_u32_le(hdr + 28);
    uint16_t e_phentsize = static_cast<uint16_t>(is64 ? read_u16_le(hdr + 54) : read_u16_le(hdr + 42));
    uint16_t e_phnum = static_cast<uint16_t>(is64 ? read_u16_le(hdr + 56) : read_u16_le(hdr + 44));
    if (e_phoff == 0 || e_phentsize == 0 || e_phnum == 0 || e_phnum > 64) return 0;
    if (e_phoff + static_cast<uint64_t>(e_phnum) * e_phentsize > static_cast<uint64_t>(hn)) return 0;

    uint64_t needed = 0;
    for (uint16_t i = 0; i < e_phnum; i++) {
        uint64_t ph = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
        uint32_t p_type = static_cast<uint32_t>(read_u32_le(hdr + ph));
        if (p_type != 1) continue; // PT_LOAD
        uint64_t p_offset = 0, p_vaddr = 0, p_filesz = 0, p_memsz = 0;
        if (is64) {
            p_offset = read_u64_le(hdr + ph + 8);
            p_vaddr  = read_u64_le(hdr + ph + 16);
            p_filesz = read_u64_le(hdr + ph + 32);
            p_memsz  = read_u64_le(hdr + ph + 40);
        } else {
            p_offset = read_u32_le(hdr + ph + 4);
            p_vaddr  = read_u32_le(hdr + ph + 8);
            p_filesz = read_u32_le(hdr + ph + 16);
            p_memsz  = read_u32_le(hdr + ph + 20);
        }
        uint64_t end1 = p_offset + (p_filesz ? p_filesz : p_memsz);
        uint64_t end2 = p_vaddr  + (p_memsz ? p_memsz : p_filesz);
        if (end1 > needed) needed = end1;
        if (end2 > needed) needed = end2;
    }
    if (needed < 0x1000 || needed > 64u * 1024u * 1024u) return 0;

    auto* buf = static_cast<uint8_t*>(std::calloc(1, static_cast<size_t>(needed)));
    if (!buf) return 0;
    for (uint64_t off = 0; off < needed; off += 4096) {
        size_t todo = static_cast<size_t>(needed - off);
        if (todo > 4096) todo = 4096;
        read_remote_retry_inline(mem_fd, pid, buf + off, todo, elf_addr + static_cast<uintptr_t>(off), use_vm_readv);
    }
    if (std::memcmp(buf, "\x7f""ELF", 4) != 0) { std::free(buf); return 0; }

    char out[768];
    int idx = so_counter ? (*so_counter + 1) : 1;
    std::snprintf(out, sizeof(out), "%s/memelf_%s_%lx.so", so_dir, pid_s, (unsigned long)elf_addr);
    FILE* f = std::fopen(out, "wb");
    if (!f) { std::free(buf); return 0; }
    size_t wr = std::fwrite(buf, 1, static_cast<size_t>(needed), f);
    std::fclose(f);
    std::free(buf);
    if (wr == 0) return 0;
    so_dedup.remember(key);
    if (so_counter) (*so_counter)++;
    std::printf("[+] SO(memelf): %s (%llu bytes) pid=%s\n",
                out, (unsigned long long)needed, pid_s);
    (void)idx;
    return 1;
}

static int deep_scan_mem_elf_inline(int mem_fd, pid_t pid, const char* pid_s,
                                    const char* pkg, MapsRegion* regs,
                                    size_t reg_count, const char* so_dir,
                                    SoDedup& so_dedup, bool use_vm_readv) {
    int found = 0;
    static const int kMaxMemElfPerProc = 12;
    uint8_t page[4096 + 16];
    for (size_t ri = 0; ri < reg_count && found < kMaxMemElfPerProc; ri++) {
        MapsRegion* r = &regs[ri];
        if (!deep_so_region_candidate(r, pkg)) continue;
        // Skip huge regions that are clearly heap/art, not shellcode
        if ((r->end - r->start) > 128u * 1024u * 1024u) continue;
        for (uintptr_t addr = r->start; addr < r->end && found < kMaxMemElfPerProc; addr += 4096) {
            size_t to_read = sizeof(page);
            if (addr + to_read > r->end) to_read = static_cast<size_t>(r->end - addr);
            if (to_read < 0x40) continue;
            ssize_t n = read_remote_retry_inline(mem_fd, pid, page, to_read, addr, use_vm_readv);
            if (n < 0x40) continue;
            for (int i = 0; i <= n - 4; i += 4) {
                if (std::memcmp(page + i, "\x7f""ELF", 4) != 0) continue;
                uintptr_t ea = addr + static_cast<uintptr_t>(i);
                found += dump_mem_elf_at_inline(mem_fd, pid, ea, so_dir, pid_s,
                                                so_dedup, nullptr, use_vm_readv);
            }
        }
    }
    return found;
}

// ---- SO dump helper (inline in scan_pid context, like original) ----
static int dump_so_inline(int mem_fd, pid_t pid, MappedObject* obj,
                           MapsRegion* regs, size_t reg_count,
                           const char* out_path) {
    auto& cfg = NhddConfig::instance();
    if (obj->file_size > 64u * 1024u * 1024u) {
        std::fprintf(stderr, "  [-] SO too large (%llu bytes), skip\n",
                     static_cast<unsigned long long>(obj->file_size));
        return -1;
    }
    if (obj->file_size == 0) return -1;

    auto* buf = static_cast<uint8_t*>(
        std::calloc(1, static_cast<size_t>(obj->file_size)));
    if (!buf) {
        std::fprintf(stderr, "  [-] OOM for SO %s (%llu bytes)\n",
                     obj->name, static_cast<unsigned long long>(obj->file_size));
        return -1;
    }

    for (size_t i = 0; i < reg_count; i++) {
        const MapsRegion* r = &regs[i];
        if (!ObjectClassifier::region_belongs_to_object(r, obj))
            continue;
        if (!r->readable) continue;

        size_t seg_len = static_cast<size_t>(r->end - r->start);
        if (static_cast<uint64_t>(obj->file_size) < r->offset + seg_len)
            continue;

        if (cfg.use_vm_readv) {
            struct iovec local, remote;
            size_t got = 0;
            while (got < seg_len) {
                local.iov_base = buf + r->offset + got;
                local.iov_len = seg_len - got;
                remote.iov_base = reinterpret_cast<void*>(r->start + got);
                remote.iov_len = seg_len - got;
                ssize_t rr = process_vm_readv(pid, &local, 1, &remote, 1, 0);
                if (rr > 0) { got += static_cast<size_t>(rr); continue; }
                if (rr < 0 && errno == EINTR) continue;
                break;
            }
        } else if (mem_fd >= 0) {
            size_t got = 0;
            while (got < seg_len) {
                ssize_t rr = ::pread(mem_fd, buf + r->offset + got,
                                     seg_len - got,
                                     static_cast<off_t>(r->start + got));
                if (rr > 0) { got += static_cast<size_t>(rr); continue; }
                if (rr < 0 && errno == EINTR) continue;
                break;
            }
        }
    }

    // Extend dump to cover all PT_LOAD segments from ELF header
    if (obj->file_size >= 0x40 &&
        std::memcmp(buf, "\x7f""ELF", 4) == 0) {
        int is64 = (buf[4] == 2);
        uint64_t e_phoff = is64 ? *reinterpret_cast<uint64_t*>(buf + 32)
                                : static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(buf + 28));
        uint16_t e_phentsize = is64 ? *reinterpret_cast<uint16_t*>(buf + 54)
                                    : *reinterpret_cast<uint16_t*>(buf + 42);
        uint16_t e_phnum = is64 ? *reinterpret_cast<uint16_t*>(buf + 56)
                                : *reinterpret_cast<uint16_t*>(buf + 44);
        if (e_phoff > 0 && e_phentsize > 0 && e_phnum < 64 &&
            e_phoff + static_cast<uint64_t>(e_phnum) * e_phentsize <= obj->file_size) {
            uint64_t needed = 0;
            for (uint16_t i = 0; i < e_phnum; i++) {
                uint64_t base = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
                uint32_t p_type;
                std::memcpy(&p_type, buf + base, 4);
                uint64_t p_vaddr, p_memsz;
                if (is64) {
                    std::memcpy(&p_vaddr, buf + base + 16, 8);
                    std::memcpy(&p_memsz, buf + base + 40, 8);
                } else {
                    p_vaddr = static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(buf + base + 8));
                    p_memsz = static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(buf + base + 20));
                }
                if (p_type == 1 && p_vaddr + p_memsz > needed)
                    needed = p_vaddr + p_memsz;
            }
            if (needed > obj->file_size && needed <= 64u * 1024u * 1024u) {
                auto* nbuf = static_cast<uint8_t*>(std::realloc(buf, static_cast<size_t>(needed)));
                if (nbuf) {
                    buf = nbuf;
                    std::memset(buf + obj->file_size, 0,
                                static_cast<size_t>(needed - obj->file_size));
                    for (uint16_t i = 0; i < e_phnum; i++) {
                        uint64_t base = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
                        uint32_t p_type;
                        std::memcpy(&p_type, buf + base, 4);
                        if (p_type != 1) continue;
                        uint64_t p_offset, p_filesz;
                        if (is64) {
                            std::memcpy(&p_offset, buf + base + 8, 8);
                            std::memcpy(&p_filesz, buf + base + 32, 8);
                        } else {
                            p_offset = static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(buf + base + 4));
                            p_filesz = static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(buf + base + 16));
                        }
                        if (p_offset + p_filesz > obj->file_size && p_offset < needed) {
                            size_t to_read = static_cast<size_t>(needed - p_offset);
                            if (to_read > static_cast<size_t>(p_filesz))
                                to_read = static_cast<size_t>(p_filesz);
                            if (p_offset < obj->file_size)
                                to_read -= static_cast<size_t>(obj->file_size - p_offset);
                            uintptr_t remote_addr = static_cast<uintptr_t>(obj->base_addr + p_offset);
                            if (cfg.use_vm_readv) {
                                struct iovec local, remote;
                                local.iov_base = buf + p_offset;
                                local.iov_len = to_read;
                                remote.iov_base = reinterpret_cast<void*>(remote_addr);
                                remote.iov_len = to_read;
                                process_vm_readv(pid, &local, 1, &remote, 1, 0);
                            } else if (mem_fd >= 0) {
                                ::pread(mem_fd, buf + p_offset, to_read,
                                        static_cast<off_t>(remote_addr));
                            }
                        }
                    }
                    obj->file_size = needed;
                }
            }
        }
    }

    FILE* out = std::fopen(out_path, "wb");
    if (!out) { std::free(buf); return -1; }
    size_t written = std::fwrite(buf, 1, static_cast<size_t>(obj->file_size), out);
    std::fclose(out);
    std::free(buf);

    if (written != static_cast<size_t>(obj->file_size)) {
        std::fprintf(stderr, "  [!] Partial write for %s (%zu/%llu)\n",
                     obj->name, written,
                     static_cast<unsigned long long>(obj->file_size));
    }
    return (written > 0) ? 0 : -1;
}


class NhddScanner {
public:
    NhddScanner(DexDedup& dex_dedup, SoDedup& so_dedup, JniDedup& jni_dedup)
        : dex_dedup_(dex_dedup), so_dedup_(so_dedup), jni_dedup_(jni_dedup) {}

    // ---- scan_pid — 1:1 port of original nhdd.c scan_pid() ----
    bool scan_pid(const char* pid, const char* dex_dir, const char* so_dir,
                  const char* jni_dir, ScanMode mode, ScanCounters& c) {
        auto& cfg = NhddConfig::instance();
        char pkg[256] = "unknown";
        ProcessManager::read_cmdline(pid, pkg, sizeof(pkg));

        // Load maps
        MapsRegion* regs = nullptr;
        size_t reg_count = 0;
        if (load_maps_inline(pid, &regs, &reg_count) != 0) {
            std::fprintf(stderr, "[-] PID %s (%s): process gone (cannot read maps)\n", pid, pkg);
            return false;
        }

        pid_t target_pid = static_cast<pid_t>(std::atoi(pid));
        int mem_fd = -1;

        if (!cfg.use_vm_readv) {
            char path[256];
            std::snprintf(path, sizeof(path), "/proc/%s/mem", pid);
            mem_fd = ::open(path, O_RDONLY);
            if (mem_fd < 0) {
                std::fprintf(stderr, "[-] PID %s (%s): cannot open mem: %s\n",
                             pid, pkg, std::strerror(errno));
                std::free(regs);
                return false;
            }
        }

        // READ_REMOTE macro equivalent: retry-aware. The first C++ OOP
        // refactor used one-shot pread/process_vm_readv here, which made
        // large DEX reads more fragile on partially readable mappings.
        #define READ_REMOTE(buf, size, addr) \
            read_remote_retry_inline(mem_fd, target_pid, (buf), (size), \
                                     static_cast<uintptr_t>(addr), cfg.use_vm_readv)


        c.procs++;
        std::fprintf(stderr, "[*] Scanning PID %s (%s): %zu regions%s\n",
                     pid, pkg, reg_count,
                     cfg.use_vm_readv ? " (stealth2: vm_readv)" : "");

        uint8_t buf[4096 + 0x70];
        int pid_dex_unique = 0, pid_dex_seen = 0;

        // ==== MAIN SCANNING LOOP (DEX magic + relaxed) ====
        bool do_descan = (mode & ScanMode::DEX);
        if (do_descan) {
        for (size_t ri = 0; ri < reg_count; ri++) {
            MapsRegion* r = &regs[ri];
            if (r->perms[0] != 'r') continue;

            size_t region_size = r->end - r->start;
            if (region_size < 64 || region_size > 0x40000000) continue;

            if (cfg.anon_only && r->path[0] != '\0') continue;
            if (cfg.region_delay_us > 0)
                usleep(static_cast<useconds_t>(cfg.region_delay_us));

            for (uintptr_t addr = r->start; addr < r->end; addr += 4096) {
                size_t to_read = sizeof(buf);
                if (addr + to_read > r->end)
                    to_read = static_cast<size_t>(r->end - addr);
                ssize_t n = READ_REMOTE(buf, to_read, addr);
                if (n < 64) continue;

                for (int i = 0; i <= n - 4; i++) {
                    // ---- Standard "dex\n" magic scan ----
                    if ((mode & ScanMode::DEX) &&
                        std::memcmp(buf + i, kDexMagic, 4) == 0) {
                        uintptr_t dex_addr = addr + i;
                        uint32_t dex_size = 0;
                        if (!DexValidator::hit_valid(buf, static_cast<size_t>(n),
                                                      static_cast<size_t>(i), &dex_size)) {
                            uint8_t hdr[0x70];
                            if (READ_REMOTE(hdr, 0x70, dex_addr) == 0x70) {
                                if (DexValidator::hit_valid(hdr, 0x70, 0, &dex_size)) goto dex_accept;
                            }
                            continue;
                        }
                    dex_accept:;
                        if (dex_size == 0) {
                            uint8_t hdr[0x70];
                            if (READ_REMOTE(hdr, 0x70, dex_addr) != 0x70) continue;
                            uint32_t map_off = 0;
                            std::memcpy(&map_off, hdr + 0x34, 4);
                            uint32_t prov = DexValidator::recover_size_provisional(hdr);
                            if (prov < 0x70) prov = 0x100000;
                            auto* img = static_cast<uint8_t*>(std::calloc(1, prov));
                            if (!img) continue;
                            size_t got = 0;
                            while (got < prov) {
                                ssize_t rr = READ_REMOTE(img + got, prov - got, dex_addr + got);
                                if (rr <= 0) break;
                                got += static_cast<size_t>(rr);
                            }
                            uint32_t recovered = DexValidator::recover_size_from_map_buf(img, got, map_off);
                            uint32_t string_ids_off = 0;
                            std::memcpy(&string_ids_off, hdr + 0x3C, 4);
                            int confirmed = DexValidator::confirm_by_map_list(img, got, map_off, string_ids_off);
                            std::free(img);
                            if (recovered == 0 || !confirmed) continue;
                            dex_size = recovered;
                        }
                        if (dex_size < 0x70 || dex_size > 0x10000000) continue;

                        {
                            uint8_t hdr_check[0x70];
                            if (READ_REMOTE(hdr_check, 0x70, dex_addr) == 0x70) {
                                if (!DexValidator::header_strong_valid(hdr_check, dex_size))
                                    continue;
                            }
                        }

                        c.dex_total++;
                        pid_dex_seen++;
                        std::fprintf(stderr, "[+] PID %s: DEX hit at 0x%lx size=%u\n",
                                     pid, static_cast<unsigned long>(dex_addr), dex_size);

                        auto* dex_data = static_cast<uint8_t*>(std::calloc(1, dex_size));
                        if (!dex_data) { std::fprintf(stderr, "[-] calloc failed\n"); goto dex_skip; }

                        {
                            size_t readable_total = 0;
                            int missing_pages = 0;
                            for (size_t off = 0; off < dex_size; off += 4096) {
                                size_t todo = dex_size - off;
                                if (todo > 4096) todo = 4096;
                                ssize_t rr = READ_REMOTE(dex_data + off, todo, dex_addr + off);
                                if (rr > 0) {
                                    readable_total += static_cast<size_t>(rr);
                                    if (static_cast<size_t>(rr) < todo) missing_pages++;
                                } else {
                                    missing_pages++;
                                }
                            }
                            if (readable_total == 0) { std::free(dex_data); goto dex_skip; }

                            DexValidator::fix_header_and_checksums(dex_data, dex_size);

                            const uint8_t* sig = dex_data + 0x0C;
                            if (dex_dedup_.seen(sig)) {
                                c.dex_dedup++;
                                std::fprintf(stderr, "[=] PID %s: DEX at 0x%lx is a duplicate, skipped\n",
                                             pid, static_cast<unsigned long>(dex_addr));
                                std::free(dex_data);
                                goto dex_skip;
                            }
                            dex_dedup_.remember(sig);
                            pid_dex_unique++;

                            char outfile[768];
                            std::snprintf(outfile, sizeof(outfile),
                                          "%s/dump_%s_%d.dex", dex_dir, pid, pid_dex_seen);

                            int fd = ::open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                            if (fd >= 0) {
                                size_t written_total = 0;
                                while (written_total < dex_size) {
                                    ssize_t w = ::write(fd, dex_data + written_total,
                                                        dex_size - written_total);
                                    if (w <= 0) break;
                                    written_total += static_cast<size_t>(w);
                                }
                                ::close(fd);
                                if (written_total == dex_size) {
                                    c.dex_unique++;
                                    std::printf("[+] DEX: %s (%u bytes, readable=%zu, zero_pages=%d) pid=%s\n",
                                                outfile, dex_size, readable_total, missing_pages, pid);
                                } else {
                                    std::fprintf(stderr, "[-] write failed for %s: %s\n",
                                                 outfile, std::strerror(errno));
                                }
                            }
                            std::free(dex_data);
                        }
                    dex_skip:
                        i += (dex_size > 4096 ? 4096 : static_cast<int>(dex_size));
                    }

                    // ---- Relaxed DEX scan (endian_tag based) ----
                    if (cfg.relaxed && (mode & ScanMode::DEX) && i + 4 <= n) {
                        uint32_t val = 0;
                        std::memcpy(&val, buf + i, 4);
                        if (val == kDexEndianTag && i >= 0x28) {
                            size_t dex_start_in_buf = static_cast<size_t>(i - 0x28);
                            uintptr_t dex_addr = addr + dex_start_in_buf;

                            uint8_t hdr[0x70];
                            if (READ_REMOTE(hdr, 0x70, dex_addr) == 0x70) {
                                uint32_t dex_size = 0;
                                if (DexValidator::header_relaxed_valid(hdr, 0x70, &dex_size)) {
                                    if (std::memcmp(hdr, kDexMagic, 4) == 0) {
                                        i += 4;
                                        continue;
                                    }

                                    uint32_t map_off = 0, string_ids_off = 0;
                                    std::memcpy(&map_off, hdr + 0x34, 4);
                                    std::memcpy(&string_ids_off, hdr + 0x3C, 4);
                                    uint32_t prov = DexValidator::recover_size_provisional(hdr);
                                    if (prov < 0x70) prov = 0x100000;
                                    auto* img = static_cast<uint8_t*>(std::calloc(1, prov));
                                    if (img) {
                                        size_t got = 0;
                                        while (got < prov) {
                                            ssize_t rr = READ_REMOTE(img + got, prov - got, dex_addr + got);
                                            if (rr <= 0) break;
                                            got += static_cast<size_t>(rr);
                                        }
                                        int confirmed = DexValidator::confirm_by_map_list(
                                            img, got, map_off, string_ids_off);
                                        if (confirmed && dex_size == 0) {
                                            uint32_t recovered = DexValidator::recover_size_from_map_buf(
                                                img, got, map_off);
                                            if (recovered) dex_size = recovered;
                                            else confirmed = 0;
                                        }
                                        std::free(img);
                                        if (!confirmed) { i += 4; continue; }
                                    } else { i += 4; continue; }

                                    c.dex_total++;
                                    pid_dex_seen++;
                                    std::fprintf(stderr,
                                        "[+] PID %s: DEX (relaxed, magic erased) at 0x%lx size=%u\n",
                                        pid, static_cast<unsigned long>(dex_addr), dex_size);

                                    auto* dex_data = static_cast<uint8_t*>(std::calloc(1, dex_size));
                                    if (!dex_data) { i += 4; continue; }

                                    size_t readable_total = 0;
                                    int missing_pages = 0;
                                    for (size_t off = 0; off < dex_size; off += 4096) {
                                        size_t todo = dex_size - off;
                                        if (todo > 4096) todo = 4096;
                                        ssize_t rr = READ_REMOTE(dex_data + off, todo, dex_addr + off);
                                        if (rr > 0) {
                                            readable_total += static_cast<size_t>(rr);
                                            if (static_cast<size_t>(rr) < todo) missing_pages++;
                                        } else {
                                            missing_pages++;
                                        }
                                    }

                                    if (readable_total == 0) { std::free(dex_data); i += 4; continue; }

                                    std::memcpy(dex_data, kDexMagic, 4);
                                    dex_data[4] = '0'; dex_data[5] = '3';
                                    dex_data[6] = '9'; dex_data[7] = '\0';

                                    DexValidator::fix_header_and_checksums(dex_data, dex_size);

                                    const uint8_t* sig = dex_data + 0x0C;
                                    if (dex_dedup_.seen(sig)) {
                                        c.dex_dedup++;
                                        std::fprintf(stderr,
                                            "[=] PID %s: DEX (relaxed) at 0x%lx is a duplicate\n",
                                            pid, static_cast<unsigned long>(dex_addr));
                                        std::free(dex_data);
                                        i += (dex_size > 4096 ? 4096 : static_cast<int>(dex_size));
                                        continue;
                                    }
                                    dex_dedup_.remember(sig);
                                    pid_dex_unique++;

                                    char outfile[768];
                                    std::snprintf(outfile, sizeof(outfile),
                                                  "%s/dump_%s_%d.dex", dex_dir, pid, pid_dex_seen);

                                    int fd = ::open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                                    if (fd >= 0) {
                                        size_t written_total = 0;
                                        while (written_total < dex_size) {
                                            ssize_t w = ::write(fd, dex_data + written_total,
                                                                dex_size - written_total);
                                            if (w <= 0) break;
                                            written_total += static_cast<size_t>(w);
                                        }
                                        ::close(fd);
                                        if (written_total == dex_size) {
                                            c.dex_unique++;
                                            std::printf(
                                                "[+] DEX(relaxed): %s (%u bytes, readable=%zu, zero_pages=%d) pid=%s\n",
                                                outfile, dex_size, readable_total, missing_pages, pid);
                                        }
                                    }
                                    std::free(dex_data);
                                    i += (dex_size > 4096 ? 4096 : static_cast<int>(dex_size));
                                }
                            }
                            i += 3; // +1 from for loop => +4 total
                        }
                    }
                }
            }
        }
        } // if (do_descan)
        // ==== END MAIN SCANNING LOOP ====

        // ---- SO classification-driven dump (maps-based) ----
        if (mode & ScanMode::SO) {
            MappedObject objs[4096];
            int obj_count = ObjectClassifier::group_by_path_inline(regs, reg_count, objs, 4096);
            int so_dumped = 0, so_skipped_sys = 0, so_skipped_other = 0;

            for (int i = 0; i < obj_count; i++) {
                MappedObject* o = &objs[i];

                uint8_t head[64] = {};
                int have_head = 0;

                // First pass: offset==0 && readable
                for (size_t j = 0; j < reg_count && !have_head; j++) {
                    const MapsRegion* rg = &regs[j];
                    if (!ObjectClassifier::region_belongs_to_object(rg, o)) continue;
                    if (rg->offset != 0) continue;
                    if (!rg->readable) continue;
                    ssize_t n;
                    if (cfg.use_vm_readv) {
                        struct iovec loc = {head, sizeof(head)};
                        struct iovec rem = {reinterpret_cast<void*>(rg->start), sizeof(head)};
                        n = process_vm_readv(target_pid, &loc, 1, &rem, 1, 0);
                    } else if (mem_fd >= 0) {
                        n = ::pread(mem_fd, head, sizeof(head), static_cast<off_t>(rg->start));
                    } else { n = -1; }
                    if (n > 0) { have_head = 1; break; }
                }
                // Second pass: any readable region
                if (!have_head) {
                    for (size_t j = 0; j < reg_count; j++) {
                        const MapsRegion* rg = &regs[j];
                        if (!ObjectClassifier::region_belongs_to_object(rg, o)) continue;
                        if (!rg->readable) continue;
                        ssize_t n;
                        if (cfg.use_vm_readv) {
                            struct iovec loc2 = {head, sizeof(head)};
                            struct iovec rem2 = {reinterpret_cast<void*>(rg->start), sizeof(head)};
                            n = process_vm_readv(target_pid, &loc2, 1, &rem2, 1, 0);
                        } else if (mem_fd >= 0) {
                            n = ::pread(mem_fd, head, sizeof(head), static_cast<off_t>(rg->start));
                        } else { n = -1; }
                        if (n > 0) { have_head = 1; break; }
                    }
                }

                o->kind = have_head ?
                    ObjectClassifier::classify_kind(o->path, head, sizeof(head))
                    : OBJ_UNKNOWN;
                o->origin = ObjectClassifier::classify_origin(o->path, pkg);
                o->policy = ObjectClassifier::decide_policy(o);

                if (o->policy == POLICY_SKIP) {
                    if (o->origin == ORIGIN_SYSTEM || o->origin == ORIGIN_APEX ||
                        o->origin == ORIGIN_VENDOR)
                        so_skipped_sys++;
                    else
                        so_skipped_other++;
                    std::snprintf(o->reason, sizeof(o->reason),
                                  "skipped: kind=%d origin=%d",
                                  static_cast<int>(o->kind), static_cast<int>(o->origin));
                    continue;
                }

                if (so_dedup_.seen(o->path)) {
                    so_skipped_other++;
                    std::snprintf(o->reason, sizeof(o->reason), "skipped: cross-process duplicate");
                    continue;
                }

                char outfile[768];
                if (o->path[0] != '\0') {
                    std::snprintf(outfile, sizeof(outfile), "%s/%s", so_dir, o->name);
                } else {
                    std::snprintf(outfile, sizeof(outfile), "%s/so_%s_%d.so",
                                  so_dir, pid, c.so_count + 1);
                }
                {
                    struct stat st;
                    if (::stat(outfile, &st) == 0) {
                        char alt[768];
                        for (int k = 2; k < 100; k++) {
                            if (o->name[0] != '\0')
                                std::snprintf(alt, sizeof(alt), "%s/%s_%d.so",
                                              so_dir, o->name, k);
                            else
                                std::snprintf(alt, sizeof(alt), "%s/so_%s_%d_%d.so",
                                              so_dir, pid, c.so_count + 1, k);
                            if (::stat(alt, &st) != 0) {
                                std::snprintf(outfile, sizeof(outfile), "%s", alt);
                                break;
                            }
                        }
                    }
                }

                int rc = dump_so_inline(mem_fd, target_pid, o, regs, reg_count, outfile);
                if (rc == 0) {
                    so_dedup_.remember(o->path);
                    c.so_count++;
                    so_dumped++;
                    std::printf("[+] SO: %s (%llu bytes, %d segs) origin=%d kind=%d pid=%s\n",
                                outfile, static_cast<unsigned long long>(o->file_size),
                                o->region_count, static_cast<int>(o->origin),
                                static_cast<int>(o->kind), pid);
                    std::snprintf(o->reason, sizeof(o->reason),
                                  "dumped: %llu bytes, %d regions",
                                  static_cast<unsigned long long>(o->file_size),
                                  o->region_count);
                } else {
                    so_skipped_other++;
                    std::snprintf(o->reason, sizeof(o->reason), "dump failed");
                }
            }

            // Write manifest
            {
                char mpath[512];
                std::snprintf(mpath, sizeof(mpath), "%s/manifest.json", so_dir);
                FILE* mf = std::fopen(mpath, "w");
                if (mf) {
                    std::fprintf(mf, "{\n  \"total_objects\": %d,\n  \"so_dumped\": %d,\n",
                                 obj_count, so_dumped);
                    std::fprintf(mf, "  \"skipped_system\": %d,\n  \"skipped_other\": %d,\n",
                                 so_skipped_sys, so_skipped_other);
                    std::fprintf(mf, "  \"objects\": [\n");
                    int first = 1;
                    for (int j = 0; j < obj_count; j++) {
                        const MappedObject* io = &objs[j];
                        const char* kind_str = "unknown";
                        switch (io->kind) {
                            case OBJ_ELF_SO: kind_str = "elf_so"; break;
                            case OBJ_ELF_EXEC: kind_str = "elf_exec"; break;
                            case OBJ_DEX: kind_str = "dex"; break;
                            case OBJ_OAT: kind_str = "oat"; break;
                            case OBJ_ODEX: kind_str = "odex"; break;
                            case OBJ_APK_ZIP: kind_str = "apk_zip"; break;
                            case OBJ_VDSO: kind_str = "vdso"; break;
                            case OBJ_MEMFD: kind_str = "memfd"; break;
                        }
                        if (!first) std::fprintf(mf, ",\n");
                        std::fprintf(mf,
                            "    {\"path\":\"%s\",\"name\":\"%s\",\"kind\":\"%s\","
                            "\"origin\":%d,\"policy\":%d,\"size\":%llu}",
                            io->path, io->name, kind_str, static_cast<int>(io->origin),
                            static_cast<int>(io->policy),
                            static_cast<unsigned long long>(io->file_size));
                        first = 0;
                    }
                    std::fprintf(mf, "\n  ]\n}\n");
                    std::fclose(mf);
                }
            }

            if (cfg.deep_so_scan) {
                int memelf = deep_scan_mem_elf_inline(mem_fd, target_pid, pid, pkg,
                                                      regs, reg_count, so_dir,
                                                      so_dedup_, cfg.use_vm_readv);
                if (memelf > 0) {
                    c.so_count += memelf;
                    so_dumped += memelf;
                    std::fprintf(stderr, "[*] SO deep memory ELF scan: +%d dumped\n", memelf);
                }
            }

            std::fprintf(stderr,
                "[*] SO classification: %d total, %d dumped, %d skipped (sys), %d skipped (other)\n",
                obj_count, so_dumped, so_skipped_sys, so_skipped_other);
        }

        // ---- JNIMAP ----
        if (mode & ScanMode::JNIMAP) {
            ProcessMemory pm_jni;
            pm_jni.set_pid(target_pid);
            if (!cfg.use_vm_readv) pm_jni.open_mem(pid);
            MapsParser::RegionList ml_jni;
            ml_jni.regs = regs;
            ml_jni.count = reg_count;
            int nj = JniMapScanner::scan(target_pid, pid, pkg, pm_jni, &ml_jni,
                                          jni_dir, jni_dedup_);
            c.jni_count += nj;
            ml_jni.regs = nullptr;
        }

        // ---- Analysis mode: save maps + dump target SO ----
        if (cfg.save_maps || cfg.dump_target_so) {
            save_maps_and_dump_target(pid, pkg, regs, reg_count,
                                       target_pid, so_dir, mem_fd);
        }

        if (mem_fd >= 0) ::close(mem_fd);
        #undef READ_REMOTE
        std::free(regs);

        std::fprintf(stderr, "[*] PID %s (%s): %d DEX hits (%d new), running totals: unique=%d dedup=%d\n",
                     pid, pkg, pid_dex_seen, pid_dex_unique, c.dex_unique, c.dex_dedup);
        return true;
    }

private:
    void save_maps_and_dump_target(const char* pid, const char* pkg,
                                    MapsRegion* regs, size_t reg_count,
                                    pid_t target_pid, const char* so_dir,
                                    int mem_fd) {
        auto& cfg = NhddConfig::instance();

        // Save /proc/pid/maps snapshot
        if (cfg.save_maps) {
            char maps_path[512];
            std::snprintf(maps_path, sizeof(maps_path), "%s/../maps/maps_%s.txt",
                          so_dir, pid);
            FILE* mf = std::fopen(maps_path, "w");
            if (mf) {
                std::fprintf(mf, "# /proc/%s/maps snapshot for %s\n", pid, pkg);
                std::fprintf(mf, "# scan_time=%lld\n",
                             static_cast<long long>(std::time(nullptr)));
                for (size_t i = 0; i < reg_count; i++) {
                    MapsRegion* r = &regs[i];
                    std::fprintf(mf, "%08lx-%08lx %s %08llx %02x:%02x %llu",
                                 static_cast<unsigned long>(r->start),
                                 static_cast<unsigned long>(r->end),
                                 r->perms,
                                 static_cast<unsigned long long>(r->offset),
                                 static_cast<unsigned>(r->dev_major),
                                 static_cast<unsigned>(r->dev_minor),
                                 static_cast<unsigned long long>(r->inode));
                    if (r->path[0])
                        std::fprintf(mf, "   %s", r->path);
                    std::fprintf(mf, "\n");
                }
                std::fclose(mf);
                std::printf("[+] MAPS: %s (%zu regions) pid=%s\n",
                            maps_path, reg_count, pid);
            }
        }

        // Dump target SO from memory
        if (cfg.dump_target_so && cfg.target_so[0]) {
            // Strip .so extension for prefix matching
            char target_prefix[256];
            std::snprintf(target_prefix, sizeof(target_prefix), "%s", cfg.target_so);
            char* dot = std::strrchr(target_prefix, '.');
            if (dot) *dot = '\0'; // "libjiagu.so" -> "libjiagu"

            // Find the mapping for target SO
            MapsRegion* target_reg = nullptr;
            uintptr_t target_base = 0;
            for (size_t i = 0; i < reg_count; i++) {
                if (!regs[i].path[0]) continue;
                const char* bn = std::strrchr(regs[i].path, '/');
                const char* name = bn ? bn + 1 : regs[i].path;
                // Match: filename starts with target prefix (handles libjiagu_vip_64.so vs libjiagu.so)
                if (std::strstr(name, target_prefix) ||
                    std::strstr(regs[i].path, target_prefix)) {
                    if (!target_reg || regs[i].offset < target_reg->offset) {
                        target_reg = &regs[i];
                        target_base = regs[i].start - regs[i].offset;
                    }
                }
            }
            if (target_reg && target_base > 0) {
                // Calculate total SO size from all regions with same path
                uint64_t total_size = 0;
                for (size_t i = 0; i < reg_count; i++) {
                    if (std::strcmp(regs[i].path, target_reg->path) == 0) {
                        uint64_t end = regs[i].offset +
                                       (regs[i].end - regs[i].start);
                        if (end > total_size) total_size = end;
                    }
                }
                if (total_size > 0 && total_size < 64u * 1024u * 1024u) {
                    char so_path[768];
                    const char* bn2 = std::strrchr(target_reg->path, '/');
                    std::snprintf(so_path, sizeof(so_path), "%s/%s_%s_%lx.so",
                                  so_dir,
                                  bn2 ? bn2 + 1 : cfg.target_so,
                                  pid, static_cast<unsigned long>(target_base));

                    auto* so_buf = static_cast<uint8_t*>(
                        std::calloc(1, static_cast<size_t>(total_size)));
                    if (so_buf) {
                        for (size_t i = 0; i < reg_count; i++) {
                            if (std::strcmp(regs[i].path, target_reg->path) != 0)
                                continue;
                            if (!regs[i].readable) continue;
                            size_t seg_len = static_cast<size_t>(
                                regs[i].end - regs[i].start);
                            if (regs[i].offset + seg_len > total_size) continue;

                            if (cfg.use_vm_readv) {
                                struct iovec loc = {so_buf + regs[i].offset, seg_len};
                                struct iovec rem = {reinterpret_cast<void*>(regs[i].start), seg_len};
                                process_vm_readv(target_pid, &loc, 1, &rem, 1, 0);
                            } else if (mem_fd >= 0) {
                                ::pread(mem_fd, so_buf + regs[i].offset,
                                        seg_len, static_cast<off_t>(regs[i].start));
                            }
                        }
                        FILE* so_out = std::fopen(so_path, "wb");
                        if (so_out) {
                            std::fwrite(so_buf, 1,
                                        static_cast<size_t>(total_size), so_out);
                            std::fclose(so_out);
                            std::printf("[+] TARGET-SO: %s (%llu bytes, base=0x%lx) pid=%s\n",
                                        so_path,
                                        static_cast<unsigned long long>(total_size),
                                        static_cast<unsigned long>(target_base), pid);
                        }
                        std::free(so_buf);
                    }
                }
            }

            // Also dump large anonymous RWX segments (unpacked shellcode)
            int anon_dumped = 0;
            for (size_t i = 0; i < reg_count && anon_dumped < 8; i++) {
                if (regs[i].path[0] != '\0') continue;
                if (!regs[i].readable || !regs[i].executable) continue;
                uint64_t blob_size = regs[i].end - regs[i].start;
                if (blob_size < 4096 || blob_size > 64u * 1024u * 1024u)
                    continue;

                char blob_path[768];
                std::snprintf(blob_path, sizeof(blob_path),
                              "%s/anon_%s_%lx.bin",
                              so_dir, pid,
                              static_cast<unsigned long>(regs[i].start));

                auto* blob_buf = static_cast<uint8_t*>(
                    std::calloc(1, static_cast<size_t>(blob_size)));
                if (!blob_buf) continue;

                if (cfg.use_vm_readv) {
                    struct iovec loc = {blob_buf, static_cast<size_t>(blob_size)};
                    struct iovec rem = {
                        reinterpret_cast<void*>(regs[i].start),
                        static_cast<size_t>(blob_size)};
                    process_vm_readv(target_pid, &loc, 1, &rem, 1, 0);
                } else if (mem_fd >= 0) {
                    ::pread(mem_fd, blob_buf, static_cast<size_t>(blob_size),
                            static_cast<off_t>(regs[i].start));
                }

                FILE* blob_out = std::fopen(blob_path, "wb");
                if (blob_out) {
                    std::fwrite(blob_buf, 1, static_cast<size_t>(blob_size),
                                blob_out);
                    std::fclose(blob_out);
                    std::printf("[+] ANON-BLOB: %s (%llu bytes, %s) pid=%s\n",
                                blob_path,
                                static_cast<unsigned long long>(blob_size),
                                regs[i].perms, pid);
                    anon_dumped++;
                }
                std::free(blob_buf);
            }
        }
    }

    DexDedup& dex_dedup_;
    SoDedup& so_dedup_;
    JniDedup& jni_dedup_;
};
