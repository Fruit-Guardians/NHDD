// nhdd_scanner.hpp — Single PID scanner: DEX/SO/JNI orchestration (1:1 port of original nhdd.c scan_pid)
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <limits>
#include <functional>
#include <new>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <sys/uio.h>
#include <dirent.h>
#include "common_types.hpp"
#include "nhdd_config.hpp"
#include "maps_parser.hpp"
#include "dedup_table.hpp"
#include "dex_capture.hpp"
#include "dex_validator.hpp"
#include "dex_semantics.hpp"
#include "runtime_formats.hpp"
#include "art_dex_discovery.hpp"
#include "process_manager.hpp"
#include "object_classifier.hpp"
#include "jnimap_scanner.hpp"
#include "elf_reconstructor.hpp"
#include "artifact_transaction.hpp"
#include "so_artifact_identity.hpp"
#include "so_manifest.hpp"
#include "process_generation_guard.hpp"
#include "process_stat.hpp"

static uint64_t read_process_start_time_inline(const char* pid);

static uint64_t read_process_start_time_for_guard_inline(void*,
                                                         const char* pid) {
    return read_process_start_time_inline(pid);
}

// ---- Forward-declared helper: load /proc/pid/maps ----
static int load_maps_inline(const char* pid,
                             MapsRegion** out_regs, size_t* out_count) {
    if (!out_regs || !out_count) {
        errno = EINVAL;
        return -1;
    }
    *out_regs = nullptr;
    *out_count = 0;

    int maps_error = 0;
    MapsParser::RegionList* parsed =
        MapsParser::load_maps(pid, &maps_error);
    if (!parsed) {
        errno = maps_error != 0 ? maps_error : EIO;
        return -1;
    }

    MapsRegion* regs = nullptr;
    if (parsed->count != 0) {
        if (parsed->count >
            std::numeric_limits<size_t>::max() / sizeof(MapsRegion)) {
            delete parsed;
            errno = EOVERFLOW;
            return -1;
        }
        // Keep the allocation family identical to MapsParser::RegionList so
        // the temporary JNIMAP owner remains exception-safe.
        regs = new (std::nothrow) MapsRegion[parsed->count];
        if (!regs) {
            delete parsed;
            errno = ENOMEM;
            return -1;
        }
        std::memcpy(regs, parsed->regs,
                    parsed->count * sizeof(MapsRegion));
    }

    const size_t count = parsed->count;
    delete parsed;
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
    if (!r) return false;
    size_t region_size = r->end - r->start;
    if (region_size < 0x40 || region_size > 0x40000000u) return false;
    // Packers also keep an embedded ELF header in RW staging buffers before
    // copying/mprotecting PT_LOAD pages. Include RW and execute-only candidate
    // regions; ordinary read-only carrier files are still handled by the
    // map-start pass and are not byte-scanned here.
    if ((!r->readable && !r->executable) ||
        (!r->writable && !r->executable)) return false;
    // Runtime-unpacked SOs normally live in anonymous / memfd / app-private mappings.
    if (r->path[0] == '\0' || r->inode == 0) return true;
    if (std::strstr(r->path, "memfd") || std::strstr(r->path, "ashmem")) return true;
    if ((std::strstr(r->path, "/data/data/") || std::strstr(r->path, "/data/user/0/")) &&
        (!pkg || !*pkg || std::strstr(r->path, pkg))) return true;
    return false;
}

struct ElfInlineReaderContext {
    int mem_fd = -1;
    pid_t pid = 0;
    bool use_vm_readv = false;
};

static std::ptrdiff_t elf_read_remote_inline(void* opaque, uint8_t* destination,
                                             size_t size,
                                             uintptr_t remote_address) {
    auto* context = static_cast<ElfInlineReaderContext*>(opaque);
    return static_cast<std::ptrdiff_t>(read_remote_retry_inline(
        context->mem_fd, context->pid, destination, size, remote_address,
        context->use_vm_readv));
}

static const MapsRegion* map_containing_inline(const MapsRegion* regs,
                                               size_t reg_count,
                                               uintptr_t address) {
    for (size_t i = 0; i < reg_count; ++i) {
        if (regs[i].start <= address && address < regs[i].end) return &regs[i];
    }
    return nullptr;
}

static uint64_t mapping_fingerprint_inline(const MapsRegion* region) {
    if (!region) return 0;
    uint64_t hash = 1469598103934665603ULL;
    const auto mix_u64 = [&hash](uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) {
            hash ^= static_cast<uint8_t>(value >> (i * 8));
            hash *= 1099511628211ULL;
        }
    };
    mix_u64(static_cast<uint64_t>(region->start));
    mix_u64(static_cast<uint64_t>(region->end));
    mix_u64(region->offset);
    mix_u64(region->inode);
    mix_u64(region->dev_major);
    mix_u64(region->dev_minor);
    for (const unsigned char* p =
             reinterpret_cast<const unsigned char*>(region->path);
         *p; ++p) {
        hash ^= *p;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void safe_artifact_name_inline(const char* source, char* output,
                                      size_t output_size) {
    if (!output || output_size == 0) return;
    const char* basename = source && *source ? std::strrchr(source, '/') : nullptr;
    basename = basename ? basename + 1 : source;
    if (!basename || !*basename) basename = "anonymous";
    size_t written = 0;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(basename);
         *p && written + 1 < output_size; ++p) {
        const bool allowed = (*p >= 'a' && *p <= 'z') ||
                             (*p >= 'A' && *p <= 'Z') ||
                             (*p >= '0' && *p <= '9') || *p == '.' ||
                             *p == '_' || *p == '-';
        output[written++] = allowed ? static_cast<char>(*p) : '_';
    }
    output[written] = '\0';
}

static uint64_t artifact_hash_inline(const uint8_t* data, size_t size) {
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void artifact_hash_mix_u64_inline(uint64_t* hash, uint64_t value) {
    if (!hash) return;
    for (unsigned i = 0; i < 8; ++i) {
        *hash ^= static_cast<uint8_t>(value >> (i * 8));
        *hash *= 1099511628211ULL;
    }
}

static bool scope_intersects_inline(const ScanScope* scope, uintptr_t start,
                                    uintptr_t end) {
    return !scope || !scope->incremental || scope->intersects(start, end);
}

// A changed PT_LOAD mapping usually does not contain the ELF header. Relate
// file/APK/memfd mappings by their backing path so an incremental event in
// .text can still locate the corresponding header mapping. Anonymous mappings
// are only related when they are close enough to plausibly be adjacent loads.
static bool scope_related_to_region_inline(const ScanScope* scope,
                                           const MapsRegion* region) {
    if (!scope || !scope->incremental) return true;
    if (!region || region->start >= region->end) return false;
    if (scope->intersects(region->start, region->end)) return true;

    constexpr uintptr_t kAnonymousNeighbourLimit = 64u * 1024u * 1024u;
    for (size_t i = 0; i < scope->count; ++i) {
        const IncrementalScanRange& changed = scope->ranges[i];
        if (region->path[0] != '\0' && changed.path[0] != '\0' &&
            std::strcmp(region->path, changed.path) == 0) {
            return true;
        }
        if (region->path[0] == '\0' && changed.path[0] == '\0') {
            const uintptr_t gap = region->end <= changed.start
                                      ? changed.start - region->end
                                      : (changed.end <= region->start
                                             ? region->start - changed.end
                                             : 0);
            if (gap <= kAnonymousNeighbourLimit) return true;
        }
    }
    return false;
}

struct SoArtifactCountsInline {
    int coverage_complete = 0;
    int partial = 0;

    void add(bool complete) {
        if (complete) ++coverage_complete;
        else ++partial;
    }
};

static int dump_mem_elf_at_inline(int mem_fd, pid_t pid, uintptr_t elf_addr,
                                  const MapsRegion* regs, size_t reg_count,
                                  const char* so_dir, const char* pid_s,
                                  uint64_t process_start_time,
                                  SoDedup& so_dedup,
                                  SoArtifactCountsInline* artifact_counts,
                                  bool use_vm_readv,
                                  ProcessGenerationGuardInline* generation) {
    if (!generation || !generation->verify()) return 0;
    ElfInlineReaderContext reader_context{mem_fd, pid, use_vm_readv};
    ElfReconstructor::Result result;
    if (!ElfReconstructor::reconstruct(elf_addr, regs, reg_count,
                                       &elf_read_remote_inline, &reader_context,
                                       &result)) {
        std::fprintf(stderr, "  [!] ELF candidate 0x%lx rejected: %s\n",
                     static_cast<unsigned long>(elf_addr), result.error.c_str());
        return 0;
    }
    // In particular, process_vm_readv() resolves the numeric PID at syscall
    // time rather than pinning the generation.  Reject the whole candidate if
    // the PID disappeared or was recycled while its PT_LOAD bytes were read.
    if (!generation->verify()) return 0;

    const uint64_t reconstructed_hash = artifact_hash_inline(
        result.image.data(), result.image.size());
    const uint64_t raw_layout_hash = result.raw_image.empty()
                                         ? reconstructed_hash
                                         : artifact_hash_inline(
                                               result.raw_image.data(),
                                               result.raw_image.size());
    uint64_t evidence_hash = so_combine_evidence_hash_inline(
        reconstructed_hash, raw_layout_hash);
    // Always retain pre-normalization header identity. raw_image is usually
    // available, but this also protects unusual layouts where it is disabled
    // or does not cover the ELF header/SHT references.
    evidence_hash = so_mix_original_elf_identity_inline(
        evidence_hash, result.original_elf_header_hash,
        result.original_e_shoff, result.original_e_shnum,
        result.original_e_shstrndx);
    artifact_hash_mix_u64_inline(&evidence_hash, result.recovered_bytes);
    for (const auto& hole : result.holes) {
        artifact_hash_mix_u64_inline(&evidence_hash, hole.file_offset);
        artifact_hash_mix_u64_inline(&evidence_hash, hole.size);
        artifact_hash_mix_u64_inline(&evidence_hash, hole.remote_address);
    }
    SoArtifactIdentityInline identity;
    identity.pid = static_cast<uint32_t>(pid);
    identity.process_start_time = process_start_time;
    identity.address = elf_addr;
    identity.evidence_hash = evidence_hash;
    char key[256];
    if (!so_format_dedup_key_inline(key, sizeof(key), identity)) return 0;
    if (so_dedup.seen(key)) return 0;

    const MapsRegion* source_map = map_containing_inline(regs, reg_count, elf_addr);
    const char* source_path = source_map ? source_map->path : "";
    char safe_name[192];
    safe_artifact_name_inline(source_path, safe_name, sizeof(safe_name));
    char stem[512];
    if (!so_format_artifact_stem_inline(stem, sizeof(stem), safe_name,
                                        identity)) {
        return 0;
    }

    char raw_path[1024];
    char reconstructed_path[1024];
    char metadata_path[1024];
    std::snprintf(raw_path, sizeof(raw_path), "%s/%s.raw.bin", so_dir,
                  stem);
    std::snprintf(reconstructed_path, sizeof(reconstructed_path),
                  "%s/%s.%s.so", so_dir, stem,
                  result.complete ? "reconstructed" : "partial");
    std::snprintf(metadata_path, sizeof(metadata_path), "%s/%s.json", so_dir,
                  stem);

    ElfReconstructor::ArtifactMetadata metadata_identity;
    metadata_identity.pid = identity.pid;
    metadata_identity.process_start_time = process_start_time;
    metadata_identity.reconstructed_hash = reconstructed_hash;
    metadata_identity.raw_layout_hash = raw_layout_hash;
    metadata_identity.evidence_hash = evidence_hash;

    if (!ElfReconstructor::write_artifacts(
            result, result.raw_layout_available ? raw_path : nullptr,
            reconstructed_path, metadata_path, source_path,
            &metadata_identity, &process_generation_publish_guard_inline,
            generation)) {
        std::fprintf(stderr, "  [-] Failed to publish ELF artifact 0x%lx\n",
                     static_cast<unsigned long>(elf_addr));
        return 0;
    }

    const bool evicted = so_dedup.remember(key);
    if (evicted && (so_dedup.eviction_count() == 1 ||
                    so_dedup.eviction_count() % 256 == 0)) {
        std::fprintf(stderr,
                     "[!] SO dedup LRU eviction: total=%llu capacity=%zu\n",
                     static_cast<unsigned long long>(
                         so_dedup.eviction_count()),
                     so_dedup.capacity());
    }
    if (artifact_counts) artifact_counts->add(result.complete);
    std::printf("[%c] SO(%s): %s (%llu bytes, %.2f%% coverage, holes=%zu, "
                "bias=0x%lx) pid=%s\n",
                result.complete ? '+' : '~',
                result.complete ? "reconstructed" : "partial",
                reconstructed_path,
                static_cast<unsigned long long>(result.output_size),
                result.completeness_percent(), result.holes.size(),
                static_cast<unsigned long>(result.load_bias), pid_s);
    return 1;
}

static int deep_scan_mem_elf_inline(int mem_fd, pid_t pid, const char* pid_s,
                                    uint64_t process_start_time,
                                    const char* pkg, MapsRegion* regs,
                                    size_t reg_count, const char* so_dir,
                                    SoDedup& so_dedup, bool use_vm_readv,
                                    const ScanScope* scope,
                                    SoArtifactCountsInline* artifact_counts,
                                    ProcessGenerationGuardInline* generation) {
    int found = 0;
    static const int kMaxMemElfPerProc = 12;
    uint8_t page[4096 + 16];
    for (size_t ri = 0; ri < reg_count && found < kMaxMemElfPerProc; ri++) {
        if (!generation || !generation->verify()) break;
        MapsRegion* r = &regs[ri];
        if (!scope_related_to_region_inline(scope, r)) continue;
        if (!deep_so_region_candidate(r, pkg)) continue;
        // Skip huge regions that are clearly heap/art, not shellcode
        if ((r->end - r->start) > 128u * 1024u * 1024u) continue;
        for (uintptr_t addr = r->start; addr < r->end && found < kMaxMemElfPerProc; addr += 4096) {
            size_t to_read = sizeof(page);
            if (addr + to_read > r->end) to_read = static_cast<size_t>(r->end - addr);
            if (to_read < 0x40) continue;
            ssize_t n = read_remote_retry_inline(mem_fd, pid, page, to_read, addr, use_vm_readv);
            if (n < 0x40) continue;
            for (int i = 0; i <= n - 4; ++i) {
                if (std::memcmp(page + i, "\x7f""ELF", 4) != 0) continue;
                uintptr_t ea = addr + static_cast<uintptr_t>(i);
                found += dump_mem_elf_at_inline(mem_fd, pid, ea, regs,
                                                reg_count, so_dir, pid_s,
                                                process_start_time,
                                                so_dedup, artifact_counts,
                                                use_vm_readv, generation);
                if (generation->invalid) return found;
            }
        }
    }
    return found;
}

// ---- DEX capture helpers -------------------------------------------------

static uint64_t read_process_start_time_inline(const char* pid) {
    uint64_t value=0;return ProcessStat::starttime(pid,&value)?value:0;
}

static bool write_staged_bytes_inline(const char* temporary_path,
                                      const uint8_t* data, size_t size) {
    if (!temporary_path || (!data && size != 0)) return false;
    (void)::unlink(temporary_path);
    int fd = ::open(temporary_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < size) {
        ssize_t n = ::write(fd, data + written, size - written);
        if (n > 0) {
            written += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    bool ok = written == size && ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok) ::unlink(temporary_path);
    return ok;
}

static bool write_atomic_bytes_inline(
        const char* path, const uint8_t* data, size_t size,
        ProcessGenerationGuardInline* generation = nullptr) {
    if (!path) return false;
    const std::string temporary = artifact_sidecar_path_inline(path, "tmp");
    if (!write_staged_bytes_inline(temporary.c_str(), data, size)) return false;
    std::vector<ArtifactTransactionEntryInline> publications;
    publications.emplace_back(path, temporary.c_str());
    return artifact_publish_transaction_inline(
        &publications,
        generation ? &process_generation_publish_guard_inline : nullptr,
        generation);
}

static bool write_staged_dex_metadata_inline(
        const char* temporary_path, const char* status,
        const DexCapture& capture, uint64_t content_hash,
        bool magic_synthesized, const char* partial_name,
        const char* raw_name, const char* fixed_name) {
    if (!temporary_path) return false;
    (void)::unlink(temporary_path);
    FILE* f = std::fopen(temporary_path, "w");
    if (!f) return false;

    const DexCandidateIdentity& id = capture.identity();
    const DexPageCoverage pages = capture.page_coverage();
    const std::vector<DexByteSpan> holes = capture.holes();
    const double ratio = capture.size() == 0
                             ? 0.0
                             : static_cast<double>(capture.covered_bytes()) /
                                   static_cast<double>(capture.size());

    std::fprintf(f,
        "{\n"
        "  \"schema_version\": 2,\n"
        "  \"status\": \"%s\",\n"
        "  \"pid\": %u,\n"
        "  \"process_start_time_ticks\": %llu,\n"
        "  \"address\": \"0x%llx\",\n"
        "  \"declared_size\": %u,\n"
        "  \"mapping_fingerprint\": \"%016llx\",\n"
        "  \"header_fingerprint\": \"%016llx\",\n"
        "  \"content_hash\": \"%016llx\",\n"
        "  \"content_revision\": %llu,\n"
        "  \"relaxed_detection\": %s,\n"
        "  \"magic_version_synthesized\": %s,\n"
        "  \"observations\": %zu,\n"
        "  \"completeness_basis\": \"byte_coverage\",\n"
        "  \"coverage\": {\"read_bytes\": %zu, \"total_bytes\": %zu, "
        "\"ratio\": %.8f, \"page_size\": %zu, \"pages_total\": %zu, "
        "\"pages_complete\": %zu, \"pages_partial\": %zu, "
        "\"pages_missing\": %zu},\n",
        status, id.pid,
        static_cast<unsigned long long>(id.process_start_time),
        static_cast<unsigned long long>(id.address), id.dex_size,
        static_cast<unsigned long long>(id.mapping_fingerprint),
        static_cast<unsigned long long>(id.header_fingerprint),
        static_cast<unsigned long long>(content_hash),
        static_cast<unsigned long long>(capture.content_revision()),
        capture.relaxed_detection() ? "true" : "false",
        magic_synthesized ? "true" : "false",
        capture.observations(),
        capture.covered_bytes(), capture.size(), ratio, pages.page_size,
        pages.total_pages, pages.complete_pages, pages.partial_pages,
        pages.missing_pages);

    std::fprintf(f,"  \"discovery\": {\"source\":\"%s\",\"art_object\":\"0x%llx\","
        "\"art_vtable\":\"0x%llx\",\"libdexfile_build_id\":\"%s\"},\n",
        capture.art_object()?"art_standard_dexfile":"header_scan",
        static_cast<unsigned long long>(capture.art_object()),
        static_cast<unsigned long long>(capture.art_vtable()),capture.art_build_id().c_str());
    std::fprintf(f, "  \"holes\": [");
    for (size_t i = 0; i < holes.size(); ++i) {
        if (i != 0) std::fprintf(f, ",");
        std::fprintf(f, "%s{\"offset\":%zu,\"length\":%zu}",
                     (i % 8 == 0) ? "\n    " : "", holes[i].offset,
                     holes[i].length);
    }
    if (!holes.empty()) std::fprintf(f, "\n  ");
    std::fputs("],\n  \"semantic\": ", f);
    if (capture.complete()) {
        auto raw = DexSemantics::validate(capture.data(), capture.size());
        std::vector<uint8_t> normalized(capture.data(), capture.data()+capture.size());
        if (magic_synthesized) std::memcpy(normalized.data(), "dex\n039\0", 8);
        DexValidator::fix_header_and_checksums(normalized.data(), normalized.size());
        auto repaired = DexSemantics::validate(normalized.data(), normalized.size());
        std::fputs("{\"raw\":",f); raw.write_json(f);
        std::fputs(",\"fixed\":",f); repaired.write_json(f);
        std::fputc('}',f);
    } else std::fputs("{\"status\":\"not_checked_partial_bytes\",\"art_accepted\":null}", f);
    std::fprintf(f,
        ",\n"
        "  \"artifacts\": {\"partial\": %s%s%s, \"raw\": %s%s%s, "
        "\"fixed\": %s%s%s}\n"
        "}\n",
        partial_name ? "\"" : "null", partial_name ? partial_name : "",
        partial_name ? "\"" : "", raw_name ? "\"" : "null",
        raw_name ? raw_name : "", raw_name ? "\"" : "",
        fixed_name ? "\"" : "null", fixed_name ? fixed_name : "",
        fixed_name ? "\"" : "");

    bool ok = std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
    if (std::fclose(f) != 0) ok = false;
    if (!ok) ::unlink(temporary_path);
    return ok;
}

static bool write_dex_metadata_inline(
        const char* path, const char* status, const DexCapture& capture,
        uint64_t content_hash, bool magic_synthesized,
        const char* partial_name, const char* raw_name,
        const char* fixed_name,
        ProcessGenerationGuardInline* generation = nullptr) {
    if (!path) return false;
    const std::string temporary = artifact_sidecar_path_inline(path, "tmp");
    if (!write_staged_dex_metadata_inline(
            temporary.c_str(), status, capture, content_hash,
            magic_synthesized, partial_name, raw_name, fixed_name)) {
        return false;
    }
    std::vector<ArtifactTransactionEntryInline> publications;
    publications.emplace_back(path, temporary.c_str());
    return artifact_publish_transaction_inline(
        &publications,
        generation ? &process_generation_publish_guard_inline : nullptr,
        generation);
}

class NhddScanner {
public:
    using ArtCaptureObserver=std::function<void(const DexCapture&,const MapsRegion*,size_t,
        const std::function<bool(uintptr_t,void*,size_t)>&)>;
    void on_art_capture(ArtCaptureObserver observer) {art_capture_observer_=std::move(observer);}
    void on_background_read(std::function<void()> checkpoint) {background_checkpoint_=std::move(checkpoint);}
    NhddScanner(DexDedup& dex_dedup, SoDedup& so_dedup, JniDedup& jni_dedup)
        : dex_dedup_(dex_dedup), so_dedup_(so_dedup), jni_dedup_(jni_dedup) {}

    size_t invalidate_dex_range(uint32_t pid, uint64_t process_start_time,
                                uintptr_t start, uintptr_t end) {
        return dex_capture_cache_.discard_intersecting(
            pid, process_start_time, start, end);
    }

    // ---- scan_pid — 1:1 port of original nhdd.c scan_pid() ----
    bool scan_pid(const char* pid, const char* dex_dir, const char* so_dir,
                  const char* jni_dir, ScanMode mode, ScanCounters& c,
                  const ScanScope* scope = nullptr,
                  uint64_t expected_starttime = 0) {
        auto& cfg = NhddConfig::instance();
        char pkg[256] = "unknown";
        ProcessManager::read_cmdline(pid, pkg, sizeof(pkg));

        errno = 0;
        const uint64_t starttime_before = read_process_start_time_inline(pid);
        if (starttime_before == 0) {
            const int identity_errno = errno;
            if (identity_errno == EACCES || identity_errno == EPERM) {
                std::fprintf(
                    stderr,
                    "[-] PID %s (%s): permission denied reading process "
                    "identity: %s (requires root, run-as for a debuggable "
                    "app, or an in-process self mode)\n",
                    pid, pkg, std::strerror(identity_errno));
            } else if (identity_errno == ESRCH || identity_errno == ENOENT) {
                std::fprintf(stderr,
                             "[-] PID %s (%s): process disappeared before "
                             "generation check: %s\n",
                             pid, pkg, std::strerror(identity_errno));
            } else {
                std::fprintf(stderr,
                             "[-] PID %s (%s): cannot establish process "
                             "generation%s%s\n",
                             pid, pkg, identity_errno != 0 ? ": " : "",
                             identity_errno != 0
                                 ? std::strerror(identity_errno)
                                 : "");
            }
            return false;
        }
        if (expected_starttime != 0 &&
            starttime_before != expected_starttime) {
            std::fprintf(
                stderr,
                "[!] PID %s (%s): process generation changed before scan "
                "(expected=%llu observed=%llu); skipping\n",
                pid, pkg,
                static_cast<unsigned long long>(expected_starttime),
                static_cast<unsigned long long>(starttime_before));
            return false;
        }

        // Load maps
        MapsRegion* regs = nullptr;
        size_t reg_count = 0;
        if (load_maps_inline(pid, &regs, &reg_count) != 0) {
            const int maps_errno = errno != 0 ? errno : EIO;
            if (maps_errno == EACCES || maps_errno == EPERM) {
                std::fprintf(
                    stderr,
                    "[-] PID %s (%s): permission denied reading /proc/%s/maps: "
                    "%s (requires root, run-as for a debuggable app, or an "
                    "in-process self mode)\n",
                    pid, pkg, pid, std::strerror(maps_errno));
            } else if (maps_errno == ESRCH || maps_errno == ENOENT) {
                std::fprintf(stderr,
                             "[-] PID %s (%s): process disappeared while "
                             "opening maps: %s\n",
                             pid, pkg, std::strerror(maps_errno));
            } else {
                std::fprintf(stderr,
                             "[-] PID %s (%s): cannot read /proc/%s/maps: "
                             "%s (errno=%d)\n",
                             pid, pkg, pid, std::strerror(maps_errno),
                             maps_errno);
            }
            return false;
        }

        pid_t target_pid = static_cast<pid_t>(std::atoi(pid));
        int mem_fd = -1;

        if (!cfg.use_vm_readv) {
            char path[256];
            std::snprintf(path, sizeof(path), "/proc/%s/mem", pid);
            mem_fd = ::open(path, O_RDONLY);
            if (mem_fd < 0) {
                const int mem_errno = errno != 0 ? errno : EIO;
                if (mem_errno == EACCES || mem_errno == EPERM) {
                    std::fprintf(
                        stderr,
                        "[-] PID %s (%s): permission denied opening "
                        "/proc/%s/mem: %s (requires root, run-as for a "
                        "debuggable app, or an in-process self mode)\n",
                        pid, pkg, pid, std::strerror(mem_errno));
                } else {
                    std::fprintf(stderr,
                                 "[-] PID %s (%s): cannot open mem: %s "
                                 "(errno=%d)\n",
                                 pid, pkg, std::strerror(mem_errno), mem_errno);
                }
                delete[] regs;
                return false;
            }
        }

        const uint64_t starttime_after_open =
            read_process_start_time_inline(pid);
        if (starttime_after_open == 0 ||
            starttime_after_open != starttime_before ||
            (expected_starttime != 0 &&
             starttime_after_open != expected_starttime)) {
            std::fprintf(
                stderr,
                "[!] PID %s (%s): process generation changed while opening "
                "maps/memory (before=%llu after=%llu expected=%llu); skipping\n",
                pid, pkg,
                static_cast<unsigned long long>(starttime_before),
                static_cast<unsigned long long>(starttime_after_open),
                static_cast<unsigned long long>(expected_starttime));
            if (mem_fd >= 0) ::close(mem_fd);
            delete[] regs;
            return false;
        }
        const uint64_t process_start_time = starttime_after_open;
        ProcessGenerationGuardInline generation{
            pid, process_start_time, &read_process_start_time_for_guard_inline,
            nullptr};
        if (!generation.verify()) {
            if (mem_fd >= 0) ::close(mem_fd);
            delete[] regs;
            return false;
        }

        // READ_REMOTE macro equivalent: retry-aware. The first C++ OOP
        // refactor used one-shot pread/process_vm_readv here, which made
        // large DEX reads more fragile on partially readable mappings.
        auto background_read=[&](void* out,size_t length,uintptr_t address) {
            if(background_checkpoint_)background_checkpoint_();
            return read_remote_retry_inline(mem_fd,target_pid,out,length,address,cfg.use_vm_readv);
        };
        #define READ_REMOTE(buf, size, addr) \
            background_read((buf),(size),static_cast<uintptr_t>(addr))


        const ScanCounters counters_before_scan = c;
        c.procs++;
        if (scope && scope->incremental) {
            std::fprintf(stderr,
                         "[*] Scanning PID %s (%s): %zu regions%s, "
                         "incremental ranges=%zu\n",
                         pid, pkg, reg_count,
                         cfg.use_vm_readv ? " (stealth2: vm_readv)" : "",
                         scope->count);
        } else {
            std::fprintf(stderr, "[*] Scanning PID %s (%s): %zu regions%s\n",
                         pid, pkg, reg_count,
                         cfg.use_vm_readv ? " (stealth2: vm_readv)" : "");
        }

        uint8_t buf[4096 + 0x70];
        int pid_dex_unique = 0, pid_dex_seen = 0;
        dex_capture_cache_.discard_other_process_generations(
            static_cast<uint32_t>(target_pid), process_start_time);

        // Refresh the whole candidate on every relevant round. Besides filling
        // holes, this detects pages decrypted in place after they were already
        // readable. Complete revisions are content-addressed and remain on
        // disk, so a later plaintext revision never destroys earlier evidence.
        auto refresh_and_publish_dex = [&](DexCapture& capture,
                                           const uint8_t* seed_header) {
            if (!generation.verify()) return;
            auto art_still_valid=[&]() {
                if(!capture.art_object())return true;
                ArtDexCandidate current;
                auto read=[&](uintptr_t a,void* p,size_t length){return generation.verify() &&
                    READ_REMOTE(p,length,a)==static_cast<ssize_t>(length);};
                const auto profile=ArtDexDiscovery::scan(read,regs,reg_count,0,0,[](const ArtDexCandidate&){});
                if(!profile.supported || profile.vtable!=capture.art_vtable())return false;
                return ArtDexDiscovery::validate(read,regs,reg_count,capture.art_vtable(),capture.art_object(),current) &&
                    current.begin==capture.identity().address && current.size==capture.size() &&
                    (!seed_header || !std::memcmp(current.header.data(),seed_header,112));
            };
            if(!art_still_valid())return;
            DexCapture observation(capture.identity(),
                                   capture.relaxed_detection());
            if (seed_header) observation.merge(0, seed_header, 0x70);
            uint8_t page[4096];
            for (size_t off = 0; off < capture.size(); off += sizeof(page)) {
                if (off > static_cast<size_t>(
                              std::numeric_limits<uintptr_t>::max() -
                              capture.identity().address)) {
                    break;
                }
                const size_t todo = std::min(sizeof(page), capture.size() - off);
                const ssize_t rr = READ_REMOTE(
                    page, todo, capture.identity().address + off);
                if (rr <= 0) continue;
                observation.merge(off, page, static_cast<size_t>(rr));
            }
            // Never merge bytes into the old generation's capture until every
            // remote read has been bracketed by a matching starttime check.
            if (!generation.verify() || !art_still_valid()) return;
            const DexRefreshResult update = capture.apply_observation(observation);
            if(art_capture_observer_ && capture.art_object() && capture.complete()) {
                const std::function<bool(uintptr_t,void*,size_t)> read=[&](uintptr_t address,void* bytes,size_t size) {
                    return generation.verify() && READ_REMOTE(bytes,size,address)==static_cast<ssize_t>(size);
                };
                art_capture_observer_(capture,regs,reg_count,read);
            }
            const size_t new_bytes = update.new_bytes;
            const size_t changed_bytes = update.changed_bytes;
            const size_t updates = new_bytes + changed_bytes;
            if (updates != 0) c.dex_updates++;
            if (capture.covered_bytes() == 0) return;

            const DexCandidateIdentity& id = capture.identity();
            char stem[256];
            std::snprintf(stem, sizeof(stem),
                          "dump_%u_%llx_%llx_%08x_%016llx_%016llx",
                          id.pid,
                          static_cast<unsigned long long>(id.process_start_time),
                          static_cast<unsigned long long>(id.address),
                          id.dex_size,
                          static_cast<unsigned long long>(id.mapping_fingerprint),
                          static_cast<unsigned long long>(id.header_fingerprint));
            const uint64_t content_hash = artifact_hash_inline(
                capture.data(), capture.size());
            char partial_name[320], partial_path[896], partial_meta_path[896];
            std::snprintf(partial_name, sizeof(partial_name), "%s.partial.dex", stem);
            std::snprintf(partial_path, sizeof(partial_path), "%s/%s", dex_dir, partial_name);
            std::snprintf(partial_meta_path, sizeof(partial_meta_path),
                          "%s/%s.meta.json", dex_dir, stem);

            if (!capture.complete()) {
                if (updates == 0) return;
                const std::string partial_temp =
                    artifact_sidecar_path_inline(partial_path, "tmp");
                const std::string metadata_temp =
                    artifact_sidecar_path_inline(partial_meta_path, "tmp");
                bool staged = write_staged_bytes_inline(
                    partial_temp.c_str(), capture.data(), capture.size());
                staged = staged && write_staged_dex_metadata_inline(
                    metadata_temp.c_str(), "partial", capture, content_hash,
                    false, partial_name, nullptr, nullptr);
                bool published = false;
                if (staged) {
                    std::vector<ArtifactTransactionEntryInline> publications;
                    publications.emplace_back(partial_path,
                                              partial_temp.c_str());
                    publications.emplace_back(partial_meta_path,
                                              metadata_temp.c_str());
                    published = artifact_publish_transaction_inline(
                        &publications,
                        &process_generation_publish_guard_inline,
                        &generation);
                } else {
                    (void)::unlink(partial_temp.c_str());
                    (void)::unlink(metadata_temp.c_str());
                }
                const DexPageCoverage pages = capture.page_coverage();
                if (published) {
                    std::printf(
                        "[~] DEX partial: %s (%zu/%zu bytes, %.2f%%, "
                        "changed=%zu, "
                        "complete_pages=%zu, partial_pages=%zu, missing_pages=%zu) pid=%s\n",
                        partial_path, capture.covered_bytes(), capture.size(),
                        100.0 * static_cast<double>(capture.covered_bytes()) /
                            static_cast<double>(capture.size()),
                        changed_bytes,
                        pages.complete_pages, pages.partial_pages,
                        pages.missing_pages, pid);
                } else {
                    std::fprintf(stderr, "[-] Failed to publish partial DEX %s: %s\n",
                                 partial_path, std::strerror(errno));
                }
                return;
            }

            std::vector<uint8_t> fixed(capture.data(),
                                       capture.data() + capture.size());
            const bool current_magic_valid = fixed.size() >= 8 &&
                std::memcmp(fixed.data(), kDexMagic, 4) == 0 &&
                fixed[4] >= '0' && fixed[4] <= '9' &&
                fixed[5] >= '0' && fixed[5] <= '9' &&
                fixed[6] >= '0' && fixed[6] <= '9' && fixed[7] == '\0';
            const bool magic_synthesized = !current_magic_valid;
            if (magic_synthesized) {
                std::memcpy(fixed.data(), kDexMagic, 4);
                // With an erased version there is no trustworthy value to
                // recover.  Keep the exact bytes in .raw.dex and mark the
                // synthesized analyzable copy by its .fixed.dex suffix.
                fixed[4] = '0'; fixed[5] = '3'; fixed[6] = '9'; fixed[7] = '\0';
            }
            DexValidator::fix_header_and_checksums(fixed.data(), fixed.size());
            const uint64_t fixed_hash = artifact_hash_inline(
                fixed.data(), fixed.size());
            const uint64_t processed_key = content_hash ^
                (fixed_hash + 0x9e3779b97f4a7c15ULL +
                 (content_hash << 6) + (content_hash >> 2));

            // An unchanged raw+fixed revision has already been either
            // published or recorded as a duplicate. Keep the capture live for
            // future in-place changes, but do not rewrite artifacts every round.
            if (capture.content_key_processed(processed_key)) return;

            char revision_stem[320], raw_name[352], fixed_name[352];
            char raw_path[896], fixed_path[896], meta_path[896];
            std::snprintf(revision_stem, sizeof(revision_stem),
                          "%s_%016llx", stem,
                          static_cast<unsigned long long>(content_hash));
            std::snprintf(raw_name, sizeof(raw_name), "%s.raw.dex", revision_stem);
            std::snprintf(fixed_name, sizeof(fixed_name), "%s.fixed.dex", revision_stem);
            std::snprintf(raw_path, sizeof(raw_path), "%s/%s", dex_dir, raw_name);
            std::snprintf(fixed_path, sizeof(fixed_path), "%s/%s", dex_dir, fixed_name);
            std::snprintf(meta_path, sizeof(meta_path), "%s/%s.meta.json",
                          dex_dir, revision_stem);

            const uint8_t* signature = fixed.data() + 0x0C;
            if (dex_dedup_.seen(signature)) {
                if (write_dex_metadata_inline(meta_path, "duplicate", capture,
                                              content_hash, magic_synthesized,
                                              nullptr, nullptr, nullptr,
                                              &generation)) {
                    capture.mark_content_key_processed(processed_key, false);
                    c.dex_dedup++;
                    ::unlink(partial_path);
                    ::unlink(partial_meta_path);
                    std::fprintf(stderr,
                        "[=] PID %s: byte-complete DEX revision at 0x%llx "
                        "duplicates an already published artifact\n", pid,
                        static_cast<unsigned long long>(id.address));
                }
                return;
            }

            const std::string raw_temp =
                artifact_sidecar_path_inline(raw_path, "tmp");
            const std::string fixed_temp =
                artifact_sidecar_path_inline(fixed_path, "tmp");
            const std::string metadata_temp =
                artifact_sidecar_path_inline(meta_path, "tmp");
            bool staged = write_staged_bytes_inline(
                raw_temp.c_str(), capture.data(), capture.size());
            staged = staged && write_staged_bytes_inline(
                fixed_temp.c_str(), fixed.data(), fixed.size());
            staged = staged && write_staged_dex_metadata_inline(
                metadata_temp.c_str(), "byte_complete", capture,
                content_hash, magic_synthesized, nullptr, raw_name,
                fixed_name);
            bool published = false;
            if (staged) {
                std::vector<ArtifactTransactionEntryInline> publications;
                publications.emplace_back(raw_path, raw_temp.c_str());
                publications.emplace_back(fixed_path, fixed_temp.c_str());
                publications.emplace_back(meta_path, metadata_temp.c_str());
                published = artifact_publish_transaction_inline(
                    &publications, &process_generation_publish_guard_inline,
                    &generation);
            } else {
                (void)::unlink(raw_temp.c_str());
                (void)::unlink(fixed_temp.c_str());
                (void)::unlink(metadata_temp.c_str());
            }
            if (!published) {
                std::fprintf(stderr, "[-] Failed to publish complete DEX %s: %s\n",
                             fixed_path, std::strerror(errno));
                return;
            }

            // Content dedup becomes authoritative only after raw, fixed and
            // metadata artifacts have all been published successfully.
            dex_dedup_.remember(signature);
            capture.mark_content_key_processed(processed_key, true);
            ::unlink(partial_path);
            ::unlink(partial_meta_path);
            c.dex_unique++;
            pid_dex_unique++;
            std::printf(
                "[+] DEX byte-complete revision: raw=%s fixed=%s "
                "(%zu bytes, changed=%zu, revision=%llu) pid=%s\n",
                raw_path, fixed_path, capture.size(), changed_bytes,
                static_cast<unsigned long long>(capture.content_revision()), pid);
        };

        auto observe_dex_candidate = [&](uintptr_t dex_addr, uint32_t dex_size,
                                         const uint8_t header[0x70],
                                         bool relaxed_detection,
                                         const MapsRegion* source_mapping,
                                         const ArtDexCandidate* art=nullptr) {
            if (!generation.verify()) return;
            DexCandidateIdentity identity;
            identity.pid = static_cast<uint32_t>(target_pid);
            identity.process_start_time = process_start_time;
            identity.address = dex_addr;
            identity.dex_size = dex_size;
            identity.mapping_fingerprint =
                mapping_fingerprint_inline(source_mapping);
            identity.header_fingerprint =
                DexCaptureCache::stable_header_fingerprint(header, 0x70);

            bool created = false;
            DexCapture* capture = dex_capture_cache_.get_or_create(
                identity, relaxed_detection, &created);
            if (!capture) {
                std::fprintf(stderr,
                    "[-] DEX merge cache budget exhausted for PID %s at 0x%llx "
                    "(%u bytes)\n", pid,
                    static_cast<unsigned long long>(dex_addr), dex_size);
                return;
            }
            if (created) {
                c.dex_total++;
                pid_dex_seen++;
                std::fprintf(stderr,
                    "[+] PID %s: new %sDEX candidate at 0x%llx size=%u "
                    "header=%016llx\n",
                    pid, relaxed_detection ? "relaxed " : "",
                    static_cast<unsigned long long>(dex_addr), dex_size,
                    static_cast<unsigned long long>(identity.header_fingerprint));
            }
            // ART-owned captures may rebind to a newly validated object after
            // loader churn; header-owned captures retain their initial source.
            if(art && (created || capture->art_object()))
                capture->mark_art(art->object,art->vtable,ArtDexDiscovery::kBuildId);
            capture->observe(relaxed_detection);
            if (!created) {
                // Existing candidates were refreshed at the beginning of this
                // scan. Avoid a second full read from overlapping magic hits.
                return;
            }
            // The separately validated header is itself a real read span.  Seed
            // it before retrying the remaining holes so a failed first page
            // read does not discard useful coverage information.
            refresh_and_publish_dex(*capture, header);
        };

        auto observe_runtime_format = [&](uintptr_t address, const MapsRegion& region) {
            uint8_t header[512] = {};
            const ssize_t header_read = READ_REMOTE(header, sizeof(header), address);
            if (header_read < 8 || !generation.verify()) return;
            if(header[7] || !std::isdigit(header[4]) || !std::isdigit(header[5]) || !std::isdigit(header[6])) return;
            const std::string format = RuntimeFormats::identify(header, static_cast<size_t>(header_read));
            uint64_t extent = RuntimeFormats::capture_extent(header, static_cast<size_t>(header_read));
            const bool header_only = format == "oat" || !extent || extent > 64ull*1024*1024;
            if (!extent || extent > 64ull*1024*1024) extent = static_cast<uint64_t>(header_read);
            if (extent < 8 || extent > std::numeric_limits<uintptr_t>::max() - address) return;
            DexCandidateIdentity id;
            id.pid = static_cast<uint32_t>(target_pid);
            id.process_start_time = process_start_time;
            id.address = address; id.dex_size = static_cast<uint32_t>(extent);
            id.mapping_fingerprint = mapping_fingerprint_inline(&region);
            DexCapture capture(id, false);
            for (size_t offset = 0; offset < extent; offset += 4096) {
                if (!generation.verify()) return;
                uint8_t page[4096];
                const size_t length = std::min<size_t>(sizeof(page), static_cast<size_t>(extent)-offset);
                const ssize_t got = READ_REMOTE(page, length, address + offset);
                if (got > 0) capture.merge(offset, page, static_cast<size_t>(got));
            }
            if (!generation.verify()) return;
            const uint64_t hash = artifact_hash_inline(capture.data(), capture.size());
            const std::string key = std::to_string(target_pid)+":"+std::to_string(process_start_time)+":"+
                std::to_string(address)+":"+std::to_string(hash)+":"+std::to_string(capture.covered_bytes());
            if (runtime_processed_.count(key)) return;
            auto report = RuntimeFormats::inspect(capture.data(), capture.size(), header_only);
            if (!capture.complete()) {report.valid = false;report.errors.emplace_back("unread_memory_holes");}
            const char* extension = format == "compact_dex" ? "cdex" : (format == "vdex" ? "vdex" : "oat-header.bin");
            char name[256], path[896], metadata[928];
            std::snprintf(name, sizeof(name), "runtime_%s_%s_g%llu_%llx_%016llx%s.%s", format.c_str(), pid,
                static_cast<unsigned long long>(process_start_time),static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(hash),capture.complete()?"":".partial",extension);
            std::snprintf(path,sizeof(path),"%s/%s",dex_dir,name);
            std::snprintf(metadata,sizeof(metadata),"%s.json",path);
            const std::string bytes_temp=artifact_sidecar_path_inline(path,"tmp");
            const std::string meta_temp=artifact_sidecar_path_inline(metadata,"tmp");
            bool staged=write_staged_bytes_inline(bytes_temp.c_str(),capture.data(),capture.size());
            FILE* f=staged?std::fopen(meta_temp.c_str(),"w"):nullptr;
            if(f) {
                std::fprintf(f,"{\"schema\":\"nhdd-runtime-format-v1\",\"pid\":%u,\"process_starttime\":%llu,"
                    "\"address\":\"0x%llx\",\"capture_scope\":\"%s\",\"read_bytes\":%zu,\"total_bytes\":%zu,"
                    "\"byte_complete\":%s,\"validation\":",id.pid,static_cast<unsigned long long>(process_start_time),
                    static_cast<unsigned long long>(address),header_only?"header_only":"declared_extent",
                    capture.covered_bytes(),capture.size(),capture.complete()?"true":"false");
                report.write_json(f);std::fputs("}\n",f);
                staged=std::fflush(f)==0 && ::fsync(::fileno(f))==0;
                if(std::fclose(f)!=0)staged=false;
            } else staged=false;
            std::vector<ArtifactTransactionEntryInline> entries;
            entries.emplace_back(path,bytes_temp.c_str());entries.emplace_back(metadata,meta_temp.c_str());
            if(staged && artifact_publish_transaction_inline(&entries,&process_generation_publish_guard_inline,&generation)) {
                if(runtime_processed_.size()>=1024)runtime_processed_.clear();
                runtime_processed_.insert(key);
                std::fprintf(stderr,"[+] RUNTIME %s: %s (%s, %zu/%zu bytes)\n",format.c_str(),path,
                    !report.supported?"unsupported version":(report.valid?"format checks passed":"invalid/incomplete"),
                    capture.covered_bytes(),capture.size());
            } else {
                ::unlink(bytes_temp.c_str());::unlink(meta_temp.c_str());
                std::fprintf(stderr,"[-] Runtime format publication failed at 0x%llx\n",static_cast<unsigned long long>(address));
            }
        };

        // ==== MAIN SCANNING LOOP (DEX magic + ART container formats) ====
        bool do_descan = (mode & ScanMode::DEX);
        if (do_descan) {
            // Refresh known candidates even if a later round no longer exposes
            // the original magic/header. This fills holes and captures later
            // decrypt-in-place revisions.
            dex_capture_cache_.for_each_process(
                static_cast<uint32_t>(target_pid), process_start_time,
                [&](DexCapture& capture) {
                    if (generation.invalid) return;
                    const DexCandidateIdentity& id = capture.identity();
                    uintptr_t end = id.address;
                    if (id.dex_size <=
                        static_cast<uint64_t>(
                            std::numeric_limits<uintptr_t>::max() - id.address)) {
                        end += static_cast<uintptr_t>(id.dex_size);
                    } else {
                        end = std::numeric_limits<uintptr_t>::max();
                    }
                    if (scope_intersects_inline(scope, id.address, end)) {
                        // Revalidate the structural header before touching an
                        // existing capture. Within one process an address can
                        // be unmapped and reused; blindly refreshing would mix
                        // the replacement mapping into the old DEX identity.
                        // Magic/checksum/signature/file_size remain excluded,
                        // so ordinary header wiping and restoration still work.
                        uint8_t current_header[0x70];
                        if (READ_REMOTE(current_header, sizeof(current_header),
                                        id.address) !=
                            static_cast<ssize_t>(sizeof(current_header))) {
                            return;
                        }
                        if (DexCaptureCache::stable_header_fingerprint(
                                current_header, sizeof(current_header)) !=
                            id.header_fingerprint) {
                            return;
                        }
                        const MapsRegion* current_mapping = map_containing_inline(
                            regs, reg_count, id.address);
                        if (!current_mapping ||
                            mapping_fingerprint_inline(current_mapping) !=
                                id.mapping_fingerprint) {
                            return;
                        }
                        uint32_t declared_size = 0;
                        std::memcpy(&declared_size, current_header + 0x20,
                                    sizeof(declared_size));
                        if (declared_size != 0 && declared_size != id.dex_size)
                            return;
                        dex_capture_cache_.touch(capture);
                        capture.observe(capture.relaxed_detection());
                        refresh_and_publish_dex(capture, current_header);
                    }
                });

            if(cfg.art_dex && generation.verify()) {
                const std::string key=std::to_string(target_pid)+":"+std::to_string(process_start_time);
                if(art_scan_cursors_.size()>1024)art_scan_cursors_.clear();
                auto read=[&](uintptr_t a,void* p,size_t length){return generation.verify() &&
                    READ_REMOTE(p,length,a)==static_cast<ssize_t>(length);};
                auto& cursor=art_scan_cursors_[key];
                const bool resume=cursor.resume_next;
                const auto stats=ArtDexDiscovery::scan(read,regs,reg_count,uint64_t(cfg.art_scan_mb)*1024*1024,
                    resume?cursor.next:0,[&](const ArtDexCandidate& candidate) {
                        const auto* mapping=ArtDexDiscovery::region(regs,reg_count,candidate.begin);
                        if(cfg.anon_only && mapping && mapping->path[0])return;
                        std::fprintf(stderr,"[ART] DEX object=0x%llx begin=0x%llx size=%u (cached tables verified)\n",
                            static_cast<unsigned long long>(candidate.object),
                            static_cast<unsigned long long>(candidate.begin),candidate.size);
                        observe_dex_candidate(candidate.begin,candidate.size,candidate.header.data(),false,mapping,&candidate);
                    });
                // Revisit high-priority primary heaps every other round while
                // retaining a separate cursor for the rest of the address space.
                if(resume || !cursor.next)cursor.next=stats.next;
                cursor.resume_next=!resume;
                std::fprintf(stderr,"[ART] status=%s build_id=%s heap_read=%llu matches=%llu rejected=%llu accepted=%llu read_failures=%llu budget_exhausted=%s\n",
                    stats.status.c_str(),stats.build_id.c_str(),static_cast<unsigned long long>(stats.bytes),
                    static_cast<unsigned long long>(stats.matches),static_cast<unsigned long long>(stats.rejected),
                    static_cast<unsigned long long>(stats.accepted),static_cast<unsigned long long>(stats.read_failures),
                    stats.exhausted?"true":"false");
            }
            if(!cfg.art_only) for (size_t ri = 0; ri < reg_count; ri++) {
                if (generation.invalid || !generation.verify()) break;
                MapsRegion* r = &regs[ri];
                // Hardened loaders may transition pages to execute-only. Root
                // /proc/<pid>/mem can often still read these pages, so attempt
                // them and let the remote reader decide instead of filtering
                // solely on the maps 'r' bit.
                if (!r->readable && !r->executable) continue;
                if (!scope_intersects_inline(scope, r->start, r->end)) continue;

                size_t region_size = r->end - r->start;
                if (region_size < 64 || region_size > 0x40000000) continue;

                if (cfg.anon_only && r->path[0] != '\0') continue;
                if (cfg.region_delay_us > 0)
                    usleep(static_cast<useconds_t>(cfg.region_delay_us));

                for (uintptr_t addr = r->start; addr < r->end; addr += 4096) {
                    if (generation.invalid) break;
                    size_t to_read = sizeof(buf);
                    if (addr + to_read > r->end)
                        to_read = static_cast<size_t>(r->end - addr);
                    if(!scope_intersects_inline(scope,addr,addr+to_read))continue;
                    ssize_t n = READ_REMOTE(buf, to_read, addr);
                    if (n < 64) continue;

                    for (int i = 0; i <= n - 4; i++) {
                        if ((std::memcmp(buf+i,"cdex",4)==0 || std::memcmp(buf+i,"vdex",4)==0 ||
                             std::memcmp(buf+i,"oat\n",4)==0) &&
                            ObjectClassifier::classify_origin(r->path,pkg) != ORIGIN_SYSTEM &&
                            ObjectClassifier::classify_origin(r->path,pkg) != ORIGIN_APEX &&
                            ObjectClassifier::classify_origin(r->path,pkg) != ORIGIN_VENDOR) {
                            observe_runtime_format(addr+static_cast<uintptr_t>(i),*r);
                            continue;
                        }
                        // ---- Standard "dex\n" magic scan ----
                        if (std::memcmp(buf + i, kDexMagic, 4) == 0) {
                            uintptr_t dex_addr = addr + static_cast<uintptr_t>(i);
                            uint32_t dex_size = 0;
                            if (!DexValidator::hit_valid(
                                    buf, static_cast<size_t>(n),
                                    static_cast<size_t>(i), &dex_size)) {
                                uint8_t header_retry[0x70];
                                if (READ_REMOTE(header_retry, sizeof(header_retry),
                                                dex_addr) !=
                                        static_cast<ssize_t>(sizeof(header_retry)) ||
                                    !DexValidator::hit_valid(
                                        header_retry, sizeof(header_retry), 0,
                                        &dex_size))
                                    continue;
                            }

                            uint8_t header[0x70];
                            if (READ_REMOTE(header, sizeof(header), dex_addr) !=
                                static_cast<ssize_t>(sizeof(header)))
                                continue;
                            if (dex_size == 0) {
                                uint32_t map_off = 0;
                                std::memcpy(&map_off, header + 0x34, 4);
                                const uint32_t header_extent =
                                    DexValidator::recover_size_provisional(header);
                                uint32_t read_cap = header_extent;
                                if (read_cap < 0x70) read_cap = 0x100000;
                                auto* image = static_cast<uint8_t*>(
                                    std::calloc(1, read_cap));
                                if (!image) continue;
                                ssize_t got = READ_REMOTE(image, read_cap, dex_addr);
                                uint32_t string_ids_off = 0;
                                std::memcpy(&string_ids_off, header + 0x3C, 4);
                                uint32_t recovered = got > 0
                                    ? DexValidator::recover_size_from_map_buf(
                                          image, static_cast<size_t>(got), map_off)
                                    : 0;
                                bool confirmed = got > 0 &&
                                    DexValidator::confirm_by_map_list(
                                        image, static_cast<size_t>(got), map_off,
                                        string_ids_off);
                                std::free(image);
                                if (!confirmed) continue;
                                dex_size = std::max(header_extent, recovered);
                                if (dex_size == 0) continue;
                            }
                            if (dex_size < 0x70 || dex_size > 0x10000000 ||
                                !DexValidator::header_strong_valid(header, dex_size))
                                continue;

                            observe_dex_candidate(dex_addr, dex_size, header, false,
                                                  r);
                            i += dex_size > 4096 ? 4096
                                                 : static_cast<int>(dex_size);
                            continue;
                        }

                        // ---- Relaxed DEX scan (endian_tag based) ----
                        if (cfg.relaxed && i >= 0x28) {
                            uint32_t value = 0;
                            std::memcpy(&value, buf + i, 4);
                            if (value != kDexEndianTag) continue;

                            uintptr_t dex_addr = addr +
                                static_cast<uintptr_t>(i - 0x28);
                            uint8_t header[0x70];
                            if (READ_REMOTE(header, sizeof(header), dex_addr) !=
                                static_cast<ssize_t>(sizeof(header)))
                                continue;
                            if (std::memcmp(header, kDexMagic, 4) == 0) continue;

                            uint32_t dex_size = 0;
                            if (!DexValidator::header_relaxed_valid(
                                    header, sizeof(header), &dex_size))
                                continue;
                            uint32_t map_off = 0, string_ids_off = 0;
                            std::memcpy(&map_off, header + 0x34, 4);
                            std::memcpy(&string_ids_off, header + 0x3C, 4);
                            const uint32_t header_extent =
                                DexValidator::recover_size_provisional(header);
                            uint32_t read_cap = std::max(dex_size, header_extent);
                            if (read_cap < 0x70) read_cap = 0x100000;
                            auto* image = static_cast<uint8_t*>(
                                std::calloc(1, read_cap));
                            if (!image) continue;
                            ssize_t got = READ_REMOTE(image, read_cap, dex_addr);
                            bool confirmed = got > 0 &&
                                DexValidator::confirm_by_map_list(
                                    image, static_cast<size_t>(got), map_off,
                                    string_ids_off);
                            if (confirmed) {
                                const uint32_t recovered =
                                    DexValidator::recover_size_from_map_buf(
                                        image, static_cast<size_t>(got), map_off);
                                dex_size = std::max(
                                    dex_size, std::max(header_extent, recovered));
                                if (dex_size == 0) confirmed = false;
                            }
                            std::free(image);
                            if (!confirmed || dex_size < 0x70 ||
                                dex_size > 0x10000000)
                                continue;

                            observe_dex_candidate(dex_addr, dex_size, header, true,
                                                  r);
                            i += dex_size > 4096 ? 4096
                                                 : static_cast<int>(dex_size);
                        }
                    }
                }
            }
        } // if (do_descan)
        // ==== END MAIN SCANNING LOOP ====

        bool have_so_manifest = false;
        SoScanManifestStatsInline pending_manifest_scan;

        // ---- SO reconstruction: each ELF header is an independent object ----
        // Do not group by path+inode: Android can mmap several uncompressed
        // libraries directly from the same base.apk, all sharing both fields.
        if (mode & ScanMode::SO) {
            int map_start_candidates = 0;
            int so_dumped = 0;
            int so_skipped_system = 0;
            SoArtifactCountsInline so_artifacts;
            uint8_t elf_ident[16];

            for (size_t i = 0; i < reg_count; ++i) {
                if (generation.invalid || !generation.verify()) break;
                const MapsRegion* region = &regs[i];
                if (!scope_related_to_region_inline(scope, region)) continue;
                if (region->end <= region->start ||
                    region->end - region->start < sizeof(elf_ident)) {
                    continue;
                }

                const ObjectOrigin origin =
                    ObjectClassifier::classify_origin(region->path, pkg);
                if (origin == ORIGIN_SYSTEM || origin == ORIGIN_APEX ||
                    origin == ORIGIN_VENDOR || origin == ORIGIN_RUNTIME ||
                    origin == ORIGIN_WEBVIEW ||
                    (region->path[0] == '[' &&
                     std::strstr(region->path, "vdso"))) {
                    ++so_skipped_system;
                    continue;
                }

                const ssize_t got = READ_REMOTE(elf_ident, sizeof(elf_ident),
                                                region->start);
                if (got != static_cast<ssize_t>(sizeof(elf_ident)) ||
                    std::memcmp(elf_ident, "\x7f" "ELF", 4) != 0) {
                    continue;
                }

                ++map_start_candidates;
                const int dumped = dump_mem_elf_at_inline(
                    mem_fd, target_pid, region->start, regs, reg_count, so_dir,
                    pid, process_start_time, so_dedup_, &so_artifacts,
                    cfg.use_vm_readv, &generation);
                so_dumped += dumped;
                c.so_count += dumped;
            }

            int deep_dumped = 0;
            if (cfg.deep_so_scan) {
                deep_dumped = deep_scan_mem_elf_inline(
                    mem_fd, target_pid, pid, process_start_time, pkg, regs,
                    reg_count, so_dir, so_dedup_, cfg.use_vm_readv, scope,
                    &so_artifacts, &generation);
                so_dumped += deep_dumped;
                c.so_count += deep_dumped;
            }

            SoScanManifestStatsInline manifest_scan;
            manifest_scan.maps = reg_count;
            manifest_scan.incremental = scope && scope->incremental;
            manifest_scan.scope_ranges = manifest_scan.incremental
                                             ? scope->count
                                             : 0;
            manifest_scan.map_start_elf_candidates = map_start_candidates;
            manifest_scan.deep_scan_artifacts_published = deep_dumped;
            manifest_scan.artifacts_published = so_dumped;
            manifest_scan.coverage_complete_artifacts =
                so_artifacts.coverage_complete;
            manifest_scan.partial_artifacts = so_artifacts.partial;
            manifest_scan.skipped_system_maps = so_skipped_system;
            pending_manifest_scan = manifest_scan;
            have_so_manifest = true;

            std::fprintf(
                stderr,
                "[*] SO reconstruction: %d map-start candidates, %d artifacts published "
                "(%d deep), %d system maps skipped\n",
                map_start_candidates, so_dumped, deep_dumped,
                so_skipped_system);
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
                                          jni_dir, jni_dedup_, scope,
                                          &generation, process_start_time);
            c.jni_count += nj;
            ml_jni.regs = nullptr;
        }

        // ---- Analysis mode: save maps + dump target SO ----
        if (cfg.save_maps || cfg.dump_target_so) {
            save_maps_and_dump_target(pid, pkg, regs, reg_count,
                                       target_pid, process_start_time, so_dir,
                                       mem_fd, scope, &generation);
        }

        bool generation_stable = generation.verify();
        uint64_t starttime_after_scan = generation.last_observed_start_time;

        // A failed generation is never recorded as a completed manifest scan.
        // Build a copy first; guard failure discards it, while a pure manifest
        // I/O failure retains it in memory so a later round can retry totals.
        if (generation_stable && have_so_manifest) {
            const SoProcessGenerationKeyInline generation_key{
                static_cast<uint32_t>(target_pid), process_start_time};
            SoManifestSessionInline manifest_session;
            (void)so_manifest_sessions_.get(generation_key,
                                             &manifest_session);
            manifest_session.record(process_start_time, cfg.continuous,
                                    pending_manifest_scan);

            char manifest_path[768];
            std::snprintf(
                manifest_path, sizeof(manifest_path),
                "%s/manifest_%s_g%llu.json", so_dir, pid,
                static_cast<unsigned long long>(process_start_time));
            const bool manifest_written = write_so_manifest_inline(
                manifest_path, target_pid, manifest_session,
                &process_generation_publish_guard_inline, &generation);
            if (manifest_written) {
                (void)so_manifest_retain_session_inline(
                    &so_manifest_sessions_, generation_key, manifest_session,
                    false);
            } else {
                if (generation.invalid) {
                    generation_stable = false;
                    starttime_after_scan =
                        generation.last_observed_start_time;
                } else {
                    // Disk/rename failure only: retain the accumulated session
                    // so the next stable continuous round retries these totals
                    // instead of permanently dropping this scan.
                    (void)so_manifest_retain_session_inline(
                        &so_manifest_sessions_, generation_key,
                        manifest_session, false);
                }
                std::fprintf(stderr, "[-] Failed to write SO manifest: %s\n",
                             manifest_path);
            }
        }
        if (!generation_stable) {
            // Individual artifact transactions commit only after a matching
            // generation check. They remain valid evidence for the generation
            // opened above even if that process exits later in this scan. Only
            // the unfinished round-level counters and manifest are rolled back;
            // retaining their content dedup keys prevents rewriting that valid
            // evidence on a later package scan.
            std::fprintf(
                stderr,
                "[!] PID %s (%s): process generation changed during scan "
                "(opened=%llu finished=%llu expected=%llu); scan marked failed "
                "and this round's counters/manifest were discarded; already "
                "committed artifacts remain attributed to opened generation\n",
                pid, pkg,
                static_cast<unsigned long long>(process_start_time),
                static_cast<unsigned long long>(starttime_after_scan),
                static_cast<unsigned long long>(expected_starttime));
            c = counters_before_scan;
        }

        if (mem_fd >= 0) ::close(mem_fd);
        #undef READ_REMOTE
        delete[] regs;

        std::fprintf(stderr, "[*] PID %s (%s): %d DEX hits (%d new), running totals: unique=%d dedup=%d\n",
                     pid, pkg, pid_dex_seen, pid_dex_unique, c.dex_unique, c.dex_dedup);
        return generation_stable;
    }

private:
    void save_maps_and_dump_target(const char* pid, const char* pkg,
                                    MapsRegion* regs, size_t reg_count,
                                    pid_t target_pid,
                                    uint64_t process_start_time,
                                    const char* so_dir, int mem_fd,
                                    const ScanScope* scope,
                                    ProcessGenerationGuardInline* generation) {
        auto& cfg = NhddConfig::instance();

        // Save /proc/pid/maps snapshot
        if (cfg.save_maps && generation && generation->verify()) {
            char maps_path[512];
            std::snprintf(
                maps_path, sizeof(maps_path),
                "%s/../maps/maps_%s_g%llu.txt", so_dir, pid,
                static_cast<unsigned long long>(process_start_time));
            const std::string maps_temp =
                artifact_sidecar_path_inline(maps_path, "tmp");
            (void)::unlink(maps_temp.c_str());
            FILE* mf = std::fopen(maps_temp.c_str(), "w");
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
                bool maps_ok = std::fflush(mf) == 0 &&
                               ::fsync(::fileno(mf)) == 0;
                if (std::fclose(mf) != 0) maps_ok = false;
                if (maps_ok) {
                    std::vector<ArtifactTransactionEntryInline> publications;
                    publications.emplace_back(maps_path, maps_temp.c_str());
                    maps_ok = artifact_publish_transaction_inline(
                        &publications,
                        &process_generation_publish_guard_inline,
                        generation);
                }
                if (maps_ok) {
                    std::printf("[+] MAPS: %s (%zu regions) pid=%s\n",
                                maps_path, reg_count, pid);
                } else {
                    ::unlink(maps_temp.c_str());
                }
            }
        }

        // Dump target SO from memory
        if (cfg.dump_target_so && cfg.target_so[0]) {
            // Strip .so extension for prefix matching
            char target_prefix[256];
            std::snprintf(target_prefix, sizeof(target_prefix), "%s", cfg.target_so);
            char* dot = std::strrchr(target_prefix, '.');
            if (dot) *dot = '\0'; // "libjiagu.so" -> "libjiagu"

            // A pathname may have several load instances; reconstruct every
            // matching ELF header independently instead of merging by path.
            int target_dumped = 0;
            for (size_t i = 0; i < reg_count; i++) {
                if (!generation || generation->invalid ||
                    !generation->verify()) break;
                if (!scope_related_to_region_inline(scope, &regs[i])) continue;
                if (!regs[i].path[0]) continue;
                const char* bn = std::strrchr(regs[i].path, '/');
                const char* name = bn ? bn + 1 : regs[i].path;
                // Match: filename starts with target prefix (handles libjiagu_vip_64.so vs libjiagu.so)
                if (!std::strstr(name, target_prefix) &&
                    !std::strstr(regs[i].path, target_prefix))
                    continue;

                uint8_t magic[4] = {};
                if (read_remote_retry_inline(mem_fd, target_pid, magic,
                                             sizeof(magic), regs[i].start,
                                             cfg.use_vm_readv) !=
                        static_cast<ssize_t>(sizeof(magic)) ||
                    std::memcmp(magic, "\x7f" "ELF", 4) != 0)
                    continue;
                target_dumped += dump_mem_elf_at_inline(
                    mem_fd, target_pid, regs[i].start, regs, reg_count, so_dir,
                    pid, process_start_time, so_dedup_, nullptr,
                    cfg.use_vm_readv, generation);
            }
            if (target_dumped > 0)
                std::fprintf(stderr, "[*] TARGET-SO: %d artifact(s) published\n",
                             target_dumped);

            // Also dump large anonymous RWX segments (unpacked shellcode)
            int anon_dumped = 0;
            for (size_t i = 0; i < reg_count && anon_dumped < 8; i++) {
                if (!generation || generation->invalid ||
                    !generation->verify()) break;
                if (!scope_intersects_inline(scope, regs[i].start,
                                             regs[i].end)) continue;
                if (regs[i].path[0] != '\0') continue;
                if (!regs[i].readable || !regs[i].executable) continue;
                uint64_t blob_size = regs[i].end - regs[i].start;
                if (blob_size < 4096 || blob_size > 64u * 1024u * 1024u)
                    continue;

                char blob_path[768];
                std::snprintf(blob_path, sizeof(blob_path),
                              "%s/anon_%s_g%llu_%lx.bin",
                              so_dir, pid,
                              static_cast<unsigned long long>(
                                  process_start_time),
                              static_cast<unsigned long>(regs[i].start));

                auto* blob_buf = static_cast<uint8_t*>(
                    std::calloc(1, static_cast<size_t>(blob_size)));
                if (!blob_buf) continue;

                const ssize_t blob_read = read_remote_retry_inline(
                    mem_fd, target_pid, blob_buf,
                    static_cast<size_t>(blob_size), regs[i].start,
                    cfg.use_vm_readv);

                if (blob_read == static_cast<ssize_t>(blob_size) &&
                    generation->verify() &&
                    write_atomic_bytes_inline(
                        blob_path, blob_buf, static_cast<size_t>(blob_size),
                        generation)) {
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
    ArtCaptureObserver art_capture_observer_;
    std::function<void()> background_checkpoint_;
    DexCaptureCache dex_capture_cache_;
    SoManifestSessionCacheInline so_manifest_sessions_{128};
    std::unordered_set<std::string> runtime_processed_;
    struct ArtCursor {uintptr_t next=0;bool resume_next=false;};
    std::unordered_map<std::string,ArtCursor> art_scan_cursors_;
};
