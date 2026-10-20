// jnimap_scanner.hpp — No-hook JNINativeMethod scanner
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <limits>
#include <unistd.h>
#include "common_types.hpp"
#include "maps_parser.hpp"
#include "process_memory.hpp"
#include "object_classifier.hpp"
#include "dedup_table.hpp"
#include "nhdd_config.hpp"
#include "artifact_transaction.hpp"
#include "jni_artifact_identity.hpp"
#include "process_generation_guard.hpp"

class JniMapScanner {
public:
    struct Candidate {
        uintptr_t table_addr;
        uintptr_t name_ptr;
        uintptr_t sig_ptr;
        uintptr_t fn_ptr;
        uintptr_t module_base;
        uintptr_t offset;
        char name[160];
        char sig[240];
        char module[256];
        char module_path[512];
    };

    // Scan a process for JNINativeMethod arrays, write JSONL output.
    // Optimized path:
    //   1) build executable fnPtr ranges once;
    //   2) scan only plausible table regions;
    //   3) reject fnPtr before remote string reads;
    //   4) cache name/signature cstring reads.
    static int scan(pid_t target_pid, const char* pid_str, const char* pkg,
                     ProcessMemory& pm, const MapsParser::RegionList* ml,
                     const char* jni_dir, JniDedup& dedup,
                     const ScanScope* scope = nullptr,
                     ProcessGenerationGuardInline* generation = nullptr,
                     uint64_t process_start_time = 0) {
        if (sizeof(uintptr_t) != 8) {
            std::fprintf(stderr, "[-] JNIMAP expects 64-bit process pointers\n");
            return 0;
        }
        if (!ml || !ml->regs || ml->count == 0) return 0;
        if (generation && !generation->verify()) return 0;

        auto& cfg = NhddConfig::instance();
        const bool has_lib_filter = cfg.jnimap_module[0] != '\0';

        std::vector<ExecRange> exec_ranges;
        build_exec_ranges(ml, pkg, exec_ranges);
        if (exec_ranges.empty()) {
            std::fprintf(stderr,
                "[*] JNIMAP pid=%s: no executable fnPtr ranges match%s%s\n",
                pid_str,
                has_lib_filter ? " lib=" : "",
                has_lib_filter ? cfg.jnimap_module : "");
            return 0;
        }

        std::vector<const MapsRegion*> scan_regions;
        scan_regions.reserve(ml->count);
        size_t scan_bytes = 0;
        bool executable_dependency_changed = false;
        if (scope && scope->incremental) {
            for (size_t i = 0; i < scope->count; ++i) {
                if (scope->ranges[i].executable) {
                    executable_dependency_changed = true;
                    break;
                }
            }
        }
        for (size_t i = 0; i < ml->count; i++) {
            const MapsRegion* r = &ml->regs[i];
            if (scope && scope->incremental &&
                !scope->intersects(r->start, r->end) &&
                !executable_dependency_changed) continue;
            if (!table_region_candidate(r, pkg, has_lib_filter)) continue;
            scan_regions.push_back(r);
            scan_bytes += static_cast<size_t>(r->end - r->start);
        }

        std::fprintf(stderr,
            "[*] JNIMAP pid=%s: scan_regions=%zu, scan_bytes=%.1fMB, fn_ranges=%zu%s%s, min_group=%d, max_region=%dMB%s\n",
            pid_str, scan_regions.size(), scan_bytes / 1048576.0,
            exec_ranges.size(),
            has_lib_filter ? ", lib=" : "",
            has_lib_filter ? cfg.jnimap_module : "",
            cfg.jnimap_min_group, cfg.jnimap_max_region_mb,
            cfg.jnimap_full_scan ? ", full" : "");
        std::fflush(stderr);

        if (scan_regions.empty()) return 0;

        int cap = 8192, count = 0;
        auto* arr = static_cast<Candidate*>(
            std::calloc(static_cast<size_t>(cap), sizeof(Candidate)));
        if (!arr) return 0;

        constexpr size_t kChunk = 256 * 1024;
        auto* buf = static_cast<uint8_t*>(std::malloc(kChunk + 24));
        if (!buf) { std::free(arr); return 0; }

        std::unordered_map<uintptr_t, std::string> str_cache;
        str_cache.reserve(4096);

        size_t regions_done = 0;
        size_t bytes_done = 0;
        time_t last_progress = std::time(nullptr);
        size_t fn_hits = 0;
        size_t str_hits = 0;

        for (const MapsRegion* r : scan_regions) {
            if (generation && !generation->verify()) break;
            const size_t region_size = static_cast<size_t>(r->end - r->start);
            for (uintptr_t addr = r->start; addr < r->end; addr += kChunk) {
                if (generation && generation->invalid) break;
                size_t to_read = kChunk + 24;
                if (addr + to_read > r->end)
                    to_read = static_cast<size_t>(r->end - addr);
                ssize_t n = pm.read(buf, to_read, addr);
                if (n < 24) {
                    bytes_done += to_read;
                    continue;
                }

                const size_t got = static_cast<size_t>(n);
                for (size_t off = 0; off + 24 <= got; off += 8) {
                    uint64_t raw_name_ptr = 0, raw_sig_ptr = 0, raw_fn_ptr = 0;
                    std::memcpy(&raw_name_ptr, buf + off, 8);
                    std::memcpy(&raw_sig_ptr,  buf + off + 8, 8);
                    std::memcpy(&raw_fn_ptr,   buf + off + 16, 8);
                    if (raw_name_ptr > std::numeric_limits<uintptr_t>::max() ||
                        raw_sig_ptr > std::numeric_limits<uintptr_t>::max() ||
                        raw_fn_ptr > std::numeric_limits<uintptr_t>::max()) {
                        continue;
                    }
                    const uintptr_t name_ptr = static_cast<uintptr_t>(raw_name_ptr);
                    const uintptr_t sig_ptr = static_cast<uintptr_t>(raw_sig_ptr);
                    const uintptr_t fn_ptr = static_cast<uintptr_t>(raw_fn_ptr);

                    // arm64 function pointers are 4-byte aligned. Reject obvious junk fast.
                    if ((fn_ptr & 3) != 0) continue;

                    const ExecRange* er = find_exec_range(exec_ranges, fn_ptr);
                    if (!er) continue;
                    fn_hits++;

                    // Avoid expensive remote reads unless both string pointers are readable.
                    if (!map_region_containing_fast(ml, name_ptr)) continue;
                    if (!map_region_containing_fast(ml, sig_ptr)) continue;

                    char name[160], sig[240];
                    if (!read_cstring_cached(pm, ml, str_cache, name_ptr, name, sizeof(name)))
                        continue;
                    if (!looks_like_method_name(name)) continue;
                    if (!read_cstring_cached(pm, ml, str_cache, sig_ptr, sig, sizeof(sig)))
                        continue;
                    if (!looks_like_signature(sig)) continue;
                    str_hits++;

                    if (count >= cap) {
                        int ncap = cap * 2;
                        auto* na = static_cast<Candidate*>(
                            std::realloc(arr,
                                         static_cast<size_t>(ncap) * sizeof(Candidate)));
                        if (!na) goto finish_collect;
                        arr = na;
                        std::memset(arr + cap, 0,
                                    static_cast<size_t>(ncap - cap) * sizeof(Candidate));
                        cap = ncap;
                    }

                    Candidate* c = &arr[count++];
                    c->table_addr = addr + off;
                    c->name_ptr = name_ptr;
                    c->sig_ptr = sig_ptr;
                    c->fn_ptr = fn_ptr;
                    c->module_base = er->region->start - er->region->offset;
                    c->offset = fn_ptr - c->module_base;
                    std::snprintf(c->name, sizeof(c->name), "%s", name);
                    std::snprintf(c->sig, sizeof(c->sig), "%s", sig);
                    std::snprintf(c->module_path, sizeof(c->module_path), "%s",
                                  er->region->path[0] ? er->region->path : "anonymous");
                    std::snprintf(c->module, sizeof(c->module), "%s",
                                  basename(er->region->path));
                }
                if (generation && !generation->verify()) break;
                bytes_done += to_read;

                time_t now = std::time(nullptr);
                if (now - last_progress >= 2) {
                    std::fprintf(stderr,
                        "[*] JNIMAP pid=%s: %.1f/%.1fMB, regions=%zu/%zu, fn_hits=%zu, candidates=%d\r",
                        pid_str, bytes_done / 1048576.0, scan_bytes / 1048576.0,
                        regions_done, scan_regions.size(), fn_hits, count);
                    std::fflush(stderr);
                    last_progress = now;
                }
            }
            regions_done++;
            if (cfg.region_delay_us > 0) usleep(cfg.region_delay_us);
            (void)region_size;
        }

    finish_collect:
        std::free(buf);
        std::fprintf(stderr,
            "\n[*] JNIMAP pid=%s: collected=%d, fn_hits=%zu, string_hits=%zu, cache=%zu\n",
            pid_str, count, fn_hits, str_hits, str_cache.size());
        std::fflush(stderr);

        if (generation && !generation->verify()) {
            std::free(arr);
            return 0;
        }

        if (count == 0) {
            // No standard JNINativeMethod found, but fnPtr hits exist.
            // Dump raw fnPtr addresses for manual IDA analysis.
            if (fn_hits > 0) {
                write_fnptr_dump(jni_dir, pid_str, scan_regions, exec_ranges,
                                 pm, dedup, target_pid, generation,
                                 process_start_time);
            }
            std::free(arr);
            return 0;
        }

        // Sort by table_addr for grouping.
        std::qsort(arr, static_cast<size_t>(count), sizeof(Candidate),
                   [](const void* a, const void* b) -> int {
            auto* x = static_cast<const Candidate*>(a);
            auto* y = static_cast<const Candidate*>(b);
            if (x->table_addr < y->table_addr) return -1;
            if (x->table_addr > y->table_addr) return 1;
            return 0;
        });

        char outpath[768];
        std::snprintf(outpath, sizeof(outpath),
                      "%s/jnimap_%s_g%llu.jsonl", jni_dir, pid_str,
                      static_cast<unsigned long long>(process_start_time));
        const std::string temporary_path =
            artifact_sidecar_path_inline(outpath, "tmp");
        (void)std::remove(temporary_path.c_str());
        const bool output_existed = artifact_file_exists_inline(outpath);
        if (output_existed &&
            !artifact_copy_file_inline(outpath, temporary_path.c_str())) {
            std::free(arr);
            return 0;
        }
        FILE* out = std::fopen(temporary_path.c_str(),
                               output_existed ? "ab" : "wb");
        if (!out) {
            (void)std::remove(temporary_path.c_str());
            std::free(arr);
            return 0;
        }

        int written = 0;
        int groups = 0;
        std::vector<std::string> pending_keys;
        for (int i = 0; i < count; ) {
            int j = i + 1;
            while (j < count &&
                   arr[j].table_addr == arr[j - 1].table_addr + 24)
                j++;
            int group_len = j - i;
            if (group_len >= cfg.jnimap_min_group) {
                groups++;
                for (int k = i; k < j; k++) {
                    Candidate* c = &arr[k];
                    char key[384];
                    if (!jni_format_dedup_key_inline(
                            key, sizeof(key),
                            static_cast<uint32_t>(target_pid),
                            process_start_time, c->name, c->sig, c->module,
                            c->offset)) {
                        continue;
                    }
                    if (dedup.seen(key)) continue;
                    if (std::find(pending_keys.begin(), pending_keys.end(), key) !=
                        pending_keys.end()) continue;
                    pending_keys.emplace_back(key);

                    std::fprintf(out,
                        "{\"pid\":\"%s\",\"table\":\"0x%lx\","
                        "\"process_start_time_ticks\":%llu,"
                        "\"group_start\":\"0x%lx\",\"group_len\":%d,"
                        "\"index\":%d,\"name\":\"",
                        pid_str,
                        static_cast<unsigned long>(c->table_addr),
                        static_cast<unsigned long long>(process_start_time),
                        static_cast<unsigned long>(arr[i].table_addr),
                        group_len, k - i);
                    json_escape(out, c->name);
                    std::fprintf(out, "\",\"sig\":\"");
                    json_escape(out, c->sig);
                    std::fprintf(out,
                        "\",\"fn\":\"0x%lx\",\"module\":\"",
                        static_cast<unsigned long>(c->fn_ptr));
                    json_escape(out, c->module);
                    std::fprintf(out, "\",\"module_path\":\"");
                    json_escape(out, c->module_path);
                    std::fprintf(out,
                        "\",\"module_base\":\"0x%lx\","
                        "\"offset\":\"0x%lx\"}\n",
                        static_cast<unsigned long>(c->module_base),
                        static_cast<unsigned long>(c->offset));
                    written++;
                }
            }
            i = j;
        }
        bool output_ok = std::fflush(out) == 0 && ::fsync(::fileno(out)) == 0;
        if (generation && !generation->verify()) output_ok = false;
        if (std::fclose(out) != 0) output_ok = false;
        if (output_ok) {
            std::vector<ArtifactTransactionEntryInline> publications;
            publications.emplace_back(outpath, temporary_path.c_str());
            output_ok = artifact_publish_transaction_inline(
                &publications,
                generation ? &process_generation_publish_guard_inline
                           : nullptr,
                generation);
        }
        if (output_ok) {
            for (const std::string& key : pending_keys)
                dedup.remember(key.c_str());
        } else {
            (void)std::remove(temporary_path.c_str());
            written = 0;
        }

        if (written > 0) {
            std::printf("[+] JNIMAP: %s (%d entries, %d groups) pid=%s%s%s\n",
                        outpath, written, groups, pid_str,
                        cfg.jnimap_module[0] ? " lib=" : "",
                        cfg.jnimap_module[0] ? cfg.jnimap_module : "");
        } else {
            std::fprintf(stderr,
                "[*] JNIMAP pid=%s: no group >= --jni-min %d. Try --jni-min 1 for diagnosis.\n",
                pid_str, cfg.jnimap_min_group);
        }
        std::free(arr);
        return written;
    }

private:
    struct ExecRange {
        uintptr_t start;
        uintptr_t end;
        const MapsRegion* region;
    };

    static void build_exec_ranges(const MapsParser::RegionList* ml, const char* pkg,
                                  std::vector<ExecRange>& out) {
        auto& cfg = NhddConfig::instance();
        const bool has_lib_filter = cfg.jnimap_module[0] != '\0';
        for (size_t i = 0; i < ml->count; i++) {
            const MapsRegion* r = &ml->regs[i];
            if (!r->executable) continue;
            if (has_lib_filter) {
                // Named lib match OR anonymous X region (packer shellcode load)
                if (!filter_match(r->path) && (r->path[0] != '\0' || r->inode != 0))
                    continue;
            } else {
                if (!allowed_without_filter(r->path, pkg)) continue;
            }
            out.push_back({r->start, r->end, r});
        }
        std::sort(out.begin(), out.end(), [](const ExecRange& a, const ExecRange& b) {
            return a.start < b.start;
        });
    }

    static const ExecRange* find_exec_range(const std::vector<ExecRange>& ranges,
                                            uintptr_t addr) {
        size_t lo = 0, hi = ranges.size();
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (addr < ranges[mid].start) hi = mid;
            else if (addr >= ranges[mid].end) lo = mid + 1;
            else return &ranges[mid];
        }
        return nullptr;
    }

    static const MapsRegion* map_region_containing_fast(
        const MapsParser::RegionList* ml, uintptr_t addr) {
        if (!ml || !ml->regs || ml->count == 0) return nullptr;
        size_t lo = 0, hi = ml->count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            const MapsRegion& r = ml->regs[mid];
            if (addr < r.start) hi = mid;
            else if (addr >= r.end) lo = mid + 1;
            else return r.readable ? &r : nullptr;
        }
        return nullptr;
    }

    static bool table_region_candidate(const MapsRegion* r, const char* pkg,
                                       bool has_lib_filter) {
        if (!r || !r->readable) return false;
        const size_t region_size = static_cast<size_t>(r->end - r->start);
        if (region_size < 24) return false;

        // JNI tables live in .rodata/.data/.bss/heap, not executable-only text.
        if (!r->writable && r->executable) return false;

        auto& cfg = NhddConfig::instance();
        const char* path = r->path;
        const bool anonymous = (!path || !*path || r->inode == 0);
        const bool target_module_data = has_lib_filter && filter_match(path);
        if (target_module_data) return true;

        const size_t generic_limit = static_cast<size_t>(cfg.jnimap_max_region_mb) * 1024u * 1024u;
        // When targeting a specific SO for analysis, no size limit
        if (!cfg.dump_target_so) {
            if (!cfg.jnimap_full_scan && region_size > generic_limit) return false;
            if (cfg.jnimap_full_scan && region_size > 128u * 1024u * 1024u) return false;
        }

        // Exclude giant ART/Dalvik heaps: they are noisy and extremely slow.
        if (path && (std::strstr(path, "dalvik-") ||
                     std::strstr(path, "zygote") ||
                     std::strstr(path, "jit-cache") ||
                     std::strstr(path, "LinearAlloc") ||
                     std::strstr(path, "CompilerMetadata"))) {
            return false;
        }

        if (has_lib_filter) {
            // With --jni-lib, the fnPtr filter already pins the destination module.
            // Scan plausible table storage only: target .data/.rodata, app private
            // memory, anonymous/malloc/memfd. Avoid system/vendor/APEX data regions.
            if (anonymous) return true;
            if (path && (std::strstr(path, "memfd") || std::strstr(path, "ashmem"))) return true;
            if (path && pkg && *pkg &&
                (std::strstr(path, "/data/data/") || std::strstr(path, "/data/user/0/") ||
                 std::strstr(path, "/data/app/")) && std::strstr(path, pkg)) return true;
            return false;
        }

        if (anonymous) return true;
        return allowed_without_filter(path, pkg);
    }

    static const char* basename(const char* path) {
        if (!path || !*path) return "anonymous";
        const char* s = std::strrchr(path, '/');
        return s ? s + 1 : path;
    }

    static ssize_t read_remote(ProcessMemory& pm, void* buf, size_t size,
                                uintptr_t addr) {
        return pm.read(static_cast<uint8_t*>(buf), size, addr);
    }

    static bool read_cstring(ProcessMemory& pm,
                              const MapsParser::RegionList* ml,
                              uintptr_t addr, char* out, size_t outsz) {
        if (!out || outsz < 2) return false;
        out[0] = '\0';
        const MapsRegion* r = map_region_containing_fast(ml, addr);
        if (!r || !r->readable) return false;

        size_t max = outsz - 1;
        uintptr_t max_in_region = r->end - addr;
        if (max > max_in_region) max = static_cast<size_t>(max_in_region);
        if (max == 0) return false;

        ssize_t n = read_remote(pm, out, max, addr);
        if (n <= 0) return false;
        size_t got = static_cast<size_t>(n);
        if (got >= outsz) got = outsz - 1;
        out[got] = '\0';

        for (size_t i = 0; i < got; i++) {
            unsigned char c = static_cast<unsigned char>(out[i]);
            if (c == '\0') {
                if (i == 0) return false;
                return true;
            }
            if (c < 0x20 || c > 0x7e) return false;
        }
        return false;
    }

    static bool read_cstring_cached(ProcessMemory& pm,
                                    const MapsParser::RegionList* ml,
                                    std::unordered_map<uintptr_t, std::string>& cache,
                                    uintptr_t addr, char* out, size_t outsz) {
        auto it = cache.find(addr);
        if (it != cache.end()) {
            std::snprintf(out, outsz, "%s", it->second.c_str());
            return true;
        }
        if (!read_cstring(pm, ml, addr, out, outsz)) return false;
        if (cache.size() < 32768) cache.emplace(addr, std::string(out));
        return true;
    }

    static bool looks_like_method_name(const char* s) {
        if (!s || !*s) return false;
        size_t n = std::strlen(s);
        if (n > 120) return false;
        unsigned char c0 = static_cast<unsigned char>(s[0]);
        if (!(std::isalpha(c0) || c0 == '_' || c0 == '$' || c0 == '<'))
            return false;
        for (size_t i = 0; i < n; i++) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (!(std::isalnum(c) || c == '_' || c == '$' || c == '<' || c == '>'))
                return false;
        }
        return true;
    }

    static bool looks_like_signature(const char* s) {
        if (!s || s[0] != '(') return false;
        const char* ret = std::strchr(s, ')');
        if (!ret || !ret[1]) return false;
        size_t n = std::strlen(s);
        if (n > 220) return false;
        for (size_t i = 0; i < n; i++) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (!(std::isalnum(c) || c == '(' || c == ')' || c == '[' ||
                  c == ';' || c == '/' || c == '$' || c == '_' || c == '.'))
                return false;
        }
        char r = ret[1];
        if (!(r == 'V' || r == 'Z' || r == 'B' || r == 'C' || r == 'S' ||
              r == 'I' || r == 'J' || r == 'F' || r == 'D' || r == 'L' || r == '['))
            return false;
        return true;
    }

    static bool filter_match(const char* path) {
        auto& cfg = NhddConfig::instance();
        if (cfg.jnimap_module[0] == '\0') return true;
        if (!path) return false;
        const char* bn = basename(path);
        return std::strstr(path, cfg.jnimap_module) != nullptr ||
               std::strstr(bn, cfg.jnimap_module) != nullptr;
    }

    static bool allowed_without_filter(const char* path, const char* pkg) {
        if (!path || !*path) return true;
        auto origin = ObjectClassifier::classify_origin(path, pkg);
        if (origin == ORIGIN_SYSTEM || origin == ORIGIN_APEX ||
            origin == ORIGIN_VENDOR || origin == ORIGIN_RUNTIME ||
            origin == ORIGIN_WEBVIEW || origin == ORIGIN_SPECIAL)
            return false;
        if (std::strstr(path, ".so") || (pkg && *pkg && std::strstr(path, pkg)) ||
            origin == ORIGIN_APP_APK || origin == ORIGIN_APP_DATA)
            return true;
        return false;
    }

    static void json_escape(FILE* f, const char* s) {
        for (; s && *s; s++) {
            unsigned char c = static_cast<unsigned char>(*s);
            if (c == '\\' || c == '"') {
                std::fputc('\\', f);
                std::fputc(c, f);
            } else if (c == '\n') std::fputs("\\n", f);
            else if (c == '\r') std::fputs("\\r", f);
            else if (c == '\t') std::fputs("\\t", f);
            else if (c >= 0x20 && c <= 0x7e) std::fputc(c, f);
            else std::fprintf(f, "\\u%04x", c);
        }
    }

    // Write raw fnPtr dump when no standard JNINativeMethod found.
    // Outputs fnPtr-only data for manual IDA analysis (packer shellcode tables).
    static int write_fnptr_dump(const char* jni_dir, const char* pid_str,
                                const std::vector<const MapsRegion*>& scan_regions,
                                const std::vector<ExecRange>& exec_ranges,
                                ProcessMemory& pm, JniDedup& /*dedup*/,
                                pid_t /*target_pid*/,
                                ProcessGenerationGuardInline* generation,
                                uint64_t process_start_time) {
        struct FnPtrHit {
            uintptr_t table_addr;
            uintptr_t fn_ptr;
            uintptr_t offset;         // offset within module
            uintptr_t module_base;
            uintptr_t entry_addr;     // this slot's address in the table
            uintptr_t region_start;
            uintptr_t region_end;
            char module[256];
            char module_path[512];
            char region_perm[8];
        };

        constexpr size_t kChunk = 256 * 1024;
        auto* buf = static_cast<uint8_t*>(std::malloc(kChunk + 24));
        if (!buf) return -1;

        int cap = 16384, count = 0;
        auto* hits = static_cast<FnPtrHit*>(
            std::calloc(static_cast<size_t>(cap), sizeof(FnPtrHit)));
        if (!hits) { std::free(buf); return -1; }

        for (const MapsRegion* r : scan_regions) {
            if (generation && !generation->verify()) break;
            for (uintptr_t addr = r->start; addr < r->end; addr += kChunk) {
                if (generation && generation->invalid) break;
                size_t to_read = kChunk + 24;
                if (addr + to_read > r->end)
                    to_read = static_cast<size_t>(r->end - addr);
                ssize_t n = pm.read(buf, to_read, addr);
                if (n < 24) continue;
                const size_t got = static_cast<size_t>(n);
                for (size_t off = 0; off + 24 <= got; off += 8) {
                    uint64_t raw_fn_ptr = 0;
                    std::memcpy(&raw_fn_ptr, buf + off + 16, 8);
                    if (raw_fn_ptr > std::numeric_limits<uintptr_t>::max())
                        continue;
                    const uintptr_t fn_ptr = static_cast<uintptr_t>(raw_fn_ptr);
                    if ((fn_ptr & 3) != 0) continue;
                    const ExecRange* er = find_exec_range(exec_ranges, fn_ptr);
                    if (!er) continue;

                    if (count >= cap) {
                        if (!jni_grow_zeroed_buffer_inline(&hits, &cap))
                            goto done;
                    }

                    FnPtrHit* h = &hits[count++];
                    h->table_addr = addr + off;
                    h->entry_addr = addr + off + 16;  // fn_ptr slot address
                    h->fn_ptr = fn_ptr;
                    h->module_base = er->region->start - er->region->offset;
                    h->offset = fn_ptr - h->module_base;
                    h->region_start = r->start;
                    h->region_end   = r->end;
                    std::snprintf(h->region_perm, sizeof(h->region_perm),
                                  "%s", r->perms);
                    std::snprintf(h->module_path, sizeof(h->module_path), "%s",
                                  er->region->path[0] ? er->region->path : "anonymous");
                    std::snprintf(h->module, sizeof(h->module), "%s",
                                  basename(er->region->path));
                }
                if (generation && !generation->verify()) break;
            }
        }

    done:
        std::free(buf);
        if (generation && !generation->verify()) {
            std::free(hits);
            return 0;
        }
        if (count == 0) { std::free(hits); return 0; }

        // Sort by table_addr
        std::qsort(hits, static_cast<size_t>(count), sizeof(FnPtrHit),
                   [](const void* a, const void* b) -> int {
            auto* x = static_cast<const FnPtrHit*>(a);
            auto* y = static_cast<const FnPtrHit*>(b);
            if (x->table_addr < y->table_addr) return -1;
            if (x->table_addr > y->table_addr) return 1;
            return 0;
        });

        char outpath[768];
        std::snprintf(outpath, sizeof(outpath),
                      "%s/fnptrs_%s_g%llu.jsonl", jni_dir, pid_str,
                      static_cast<unsigned long long>(process_start_time));
        const std::string temporary_path =
            artifact_sidecar_path_inline(outpath, "tmp");
        (void)std::remove(temporary_path.c_str());
        FILE* out = std::fopen(temporary_path.c_str(), "w");
        if (!out) { std::free(hits); return -1; }

        int written = 0;
        int group_id = 0;
        for (int i = 0; i < count; ) {
            int j = i + 1;
            while (j < count &&
                   hits[j].table_addr == hits[j - 1].table_addr + 8) j++;
            int group_len = j - i;
            if (group_len >= NhddConfig::instance().jnimap_min_group) {
                group_id++;
                for (int k = i; k < j; k++) {
                    FnPtrHit* h = &hits[k];
                    std::fprintf(out,
                        "{\"pid\":\"%s\","
                        "\"process_start_time_ticks\":%llu,"
                        "\"target_so\":\"%s\","
                        "\"group_id\":%d,\"group_len\":%d,\"group_index\":%d,"
                        "\"table_addr\":\"0x%lx\",\"entry_addr\":\"0x%lx\","
                        "\"fn\":\"0x%lx\",\"offset\":\"0x%lx\","
                        "\"module\":\"",
                        pid_str,
                        static_cast<unsigned long long>(process_start_time),
                        NhddConfig::instance().target_so[0]
                            ? NhddConfig::instance().target_so : "unknown",
                        group_id, group_len, k - i,
                        static_cast<unsigned long>(h->table_addr),
                        static_cast<unsigned long>(h->entry_addr),
                        static_cast<unsigned long>(h->fn_ptr),
                        static_cast<unsigned long>(h->offset));
                    json_escape(out, h->module);
                    std::fprintf(out, "\",\"module_base\":\"0x%lx\"",
                                 static_cast<unsigned long>(h->module_base));
                    std::fprintf(out, ",\"module_path\":\"");
                    json_escape(out, h->module_path);
                    std::fprintf(out,
                        "\",\"region_start\":\"0x%lx\""
                        ",\"region_end\":\"0x%lx\""
                        ",\"region_perm\":\"%s\""
                        "}\n",
                        static_cast<unsigned long>(h->region_start),
                        static_cast<unsigned long>(h->region_end),
                        h->region_perm);
                    written++;
                }
            }
            i = j;
        }
        bool output_ok = std::fflush(out) == 0 && ::fsync(::fileno(out)) == 0;
        if (generation && !generation->verify()) output_ok = false;
        if (std::fclose(out) != 0) output_ok = false;
        if (output_ok) {
            std::vector<ArtifactTransactionEntryInline> publications;
            publications.emplace_back(outpath, temporary_path.c_str());
            output_ok = artifact_publish_transaction_inline(
                &publications,
                generation ? &process_generation_publish_guard_inline
                           : nullptr,
                generation);
        }
        if (!output_ok) {
            (void)std::remove(temporary_path.c_str());
            written = 0;
        }

        if (written > 0) {
            std::printf("[+] FNPTRS: %s (%d entries, %d groups) pid=%s\n",
                        outpath, written, group_id, pid_str);
            std::fprintf(stderr,
                "[*] FNPTRS pid=%s: wrote %d fnPtr-only entries (no name/sig found). "
                "Match offsets in IDA manually.\n",
                pid_str, written);
        }
        std::free(hits);
        return written;
    }
};
