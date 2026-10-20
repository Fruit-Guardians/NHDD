// so_manifest.hpp — lightweight, host-testable SO manifest session model
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <unordered_map>

#include "artifact_transaction.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

// Per-invocation SO statistics and their session accumulator are deliberately
// independent of Android process-memory APIs and ELF reconstruction. Continuous
// mode can therefore publish one stable manifest per process while still
// exposing the most recent incremental scan. In non-continuous mode record()
// resets on every call, preserving the historical single-scan semantics.
struct SoScanManifestStatsInline {
    size_t maps = 0;
    bool incremental = false;
    size_t scope_ranges = 0;
    uint64_t map_start_elf_candidates = 0;
    uint64_t deep_scan_artifacts_published = 0;
    uint64_t artifacts_published = 0;
    uint64_t coverage_complete_artifacts = 0;
    uint64_t partial_artifacts = 0;
    uint64_t skipped_system_maps = 0;
};

struct SoManifestSessionInline {
    bool initialized = false;
    bool continuous = false;
    uint64_t process_start_time = 0;
    uint64_t scans_completed = 0;
    SoScanManifestStatsInline totals;
    SoScanManifestStatsInline last_scan;

    void record(uint64_t start_time, bool is_continuous,
                const SoScanManifestStatsInline& scan) {
        if (!is_continuous || !initialized || continuous != is_continuous ||
            process_start_time != start_time) {
            *this = SoManifestSessionInline{};
            initialized = true;
            continuous = is_continuous;
            process_start_time = start_time;
        }

        last_scan = scan;
        ++scans_completed;
        // `maps` is a current snapshot size, not an additive quantity. The
        // remaining fields count observations/publications over this process
        // generation's scanner session.
        totals.maps = scan.maps;
        totals.map_start_elf_candidates += scan.map_start_elf_candidates;
        totals.deep_scan_artifacts_published +=
            scan.deep_scan_artifacts_published;
        totals.artifacts_published += scan.artifacts_published;
        totals.coverage_complete_artifacts +=
            scan.coverage_complete_artifacts;
        totals.partial_artifacts += scan.partial_artifacts;
        totals.skipped_system_maps += scan.skipped_system_maps;
    }
};

struct SoProcessGenerationKeyInline {
    uint32_t pid = 0;
    uint64_t process_start_time = 0;

    bool operator==(const SoProcessGenerationKeyInline& other) const {
        return pid == other.pid &&
               process_start_time == other.process_start_time;
    }
};

struct SoProcessGenerationKeyHashInline {
    size_t operator()(const SoProcessGenerationKeyInline& key) const {
        uint64_t hash = 1469598103934665603ULL;
        const auto mix = [&hash](uint64_t value) {
            for (unsigned i = 0; i < 8; ++i) {
                hash ^= static_cast<uint8_t>(value >> (i * 8));
                hash *= 1099511628211ULL;
            }
        };
        mix(key.pid);
        mix(key.process_start_time);
        return static_cast<size_t>(hash);
    }
};

// Continuous package scans can visit many child PIDs over a long session.
// Retain only a bounded set of per-generation accumulators while always
// discarding an older generation of a PID as soon as its replacement appears.
class SoManifestSessionCacheInline {
public:
    explicit SoManifestSessionCacheInline(size_t capacity = 128)
        : capacity_(capacity) {}

    bool get(const SoProcessGenerationKeyInline& key,
             SoManifestSessionInline* session) const {
        const auto found = entries_.find(key);
        if (found == entries_.end()) return false;
        if (session) *session = found->second.session;
        return true;
    }

    void put(const SoProcessGenerationKeyInline& key,
             const SoManifestSessionInline& session) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->first.pid == key.pid && !(it->first == key)) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
        if (capacity_ == 0) return;

        auto found = entries_.find(key);
        if (found == entries_.end() && entries_.size() >= capacity_) {
            auto oldest = entries_.end();
            uint64_t oldest_use = std::numeric_limits<uint64_t>::max();
            for (auto it = entries_.begin(); it != entries_.end(); ++it) {
                if (it->second.last_use < oldest_use) {
                    oldest_use = it->second.last_use;
                    oldest = it;
                }
            }
            if (oldest != entries_.end()) entries_.erase(oldest);
        }

        Entry& entry = entries_[key];
        entry.session = session;
        entry.last_use = next_use();
    }

    size_t size() const { return entries_.size(); }
    size_t capacity() const { return capacity_; }

private:
    struct Entry {
        SoManifestSessionInline session;
        uint64_t last_use = 0;
    };

    uint64_t next_use() {
        ++use_clock_;
        if (use_clock_ != 0) return use_clock_;
        // Practically unreachable, but preserve ordering if a multi-year
        // process wraps the counter.
        uint64_t next = 1;
        for (auto& item : entries_) item.second.last_use = next++;
        use_clock_ = next;
        return use_clock_;
    }

    size_t capacity_ = 0;
    uint64_t use_clock_ = 0;
    std::unordered_map<SoProcessGenerationKeyInline, Entry,
                       SoProcessGenerationKeyHashInline>
        entries_;
};

// Keep a generation-stable session in memory even when only the manifest I/O
// failed. The next continuous round can then retry publication without losing
// this round's accumulated counters. A failed generation guard must never
// commit the candidate session.
inline bool so_manifest_retain_session_inline(
        SoManifestSessionCacheInline* cache,
        const SoProcessGenerationKeyInline& key,
        const SoManifestSessionInline& session, bool generation_invalid) {
    if (!cache || generation_invalid) return false;
    cache->put(key, session);
    return true;
}

inline int so_manifest_writer_process_id_inline() {
#if defined(_WIN32)
    return ::_getpid();
#else
    return static_cast<int>(::getpid());
#endif
}

inline bool so_manifest_sync_file_inline(FILE* file) {
    if (!file) return false;
#if defined(_WIN32)
    return ::_commit(::_fileno(file)) == 0;
#else
    return ::fsync(::fileno(file)) == 0;
#endif
}

inline void so_manifest_remove_file_inline(const char* path) {
#if defined(_WIN32)
    (void)::DeleteFileA(path);
#else
    (void)::unlink(path);
#endif
}

inline bool so_manifest_temporary_path_inline(const char* path, int target_pid,
                                              char* output,
                                              size_t output_size) {
    if (!path || !*path || !output || output_size == 0) return false;
    const int length = std::snprintf(
        output, output_size, "%s.tmp.%d.%d", path, target_pid,
        so_manifest_writer_process_id_inline());
    return length >= 0 && static_cast<size_t>(length) < output_size;
}

using SoManifestPublishGuardInline = bool (*)(void*);

inline bool write_so_manifest_inline(
    const char* path, int pid, const SoManifestSessionInline& session,
    SoManifestPublishGuardInline publish_guard = nullptr,
    void* publish_guard_context = nullptr) {
    char temporary_path[1024];
    if (!so_manifest_temporary_path_inline(
            path, pid, temporary_path, sizeof(temporary_path))) {
        return false;
    }

    FILE* manifest = std::fopen(temporary_path, "w");
    if (!manifest) return false;

    const SoScanManifestStatsInline& totals = session.totals;
    const SoScanManifestStatsInline& last = session.last_scan;
    const int write_result = std::fprintf(
        manifest,
        "{\n  \"schema\": \"nhdd-so-scan-v3\",\n"
        "  \"pid\": %d,\n  \"maps\": %zu,\n"
        "  \"map_start_elf_candidates\": %llu,\n"
        "  \"deep_scan_artifacts_published\": %llu,\n"
        "  \"artifacts_published\": %llu,\n"
        "  \"coverage_complete_artifacts\": %llu,\n"
        "  \"partial_artifacts\": %llu,\n"
        "  \"skipped_system_maps\": %llu,\n"
        "  \"session\": {\n"
        "    \"continuous\": %s,\n"
        "    \"process_starttime\": %llu,\n"
        "    \"scans_completed\": %llu,\n"
        "    \"totals\": {\n"
        "      \"map_start_elf_candidates\": %llu,\n"
        "      \"deep_scan_artifacts_published\": %llu,\n"
        "      \"artifacts_published\": %llu,\n"
        "      \"coverage_complete_artifacts\": %llu,\n"
        "      \"partial_artifacts\": %llu,\n"
        "      \"skipped_system_maps\": %llu\n"
        "    }\n"
        "  },\n"
        "  \"last_scan\": {\n"
        "    \"sequence\": %llu,\n"
        "    \"incremental\": %s,\n"
        "    \"scope_ranges\": %zu,\n"
        "    \"maps\": %zu,\n"
        "    \"map_start_elf_candidates\": %llu,\n"
        "    \"deep_scan_artifacts_published\": %llu,\n"
        "    \"artifacts_published\": %llu,\n"
        "    \"coverage_complete_artifacts\": %llu,\n"
        "    \"partial_artifacts\": %llu,\n"
        "    \"skipped_system_maps\": %llu\n"
        "  }\n}\n",
        pid, totals.maps,
        static_cast<unsigned long long>(totals.map_start_elf_candidates),
        static_cast<unsigned long long>(
            totals.deep_scan_artifacts_published),
        static_cast<unsigned long long>(totals.artifacts_published),
        static_cast<unsigned long long>(totals.coverage_complete_artifacts),
        static_cast<unsigned long long>(totals.partial_artifacts),
        static_cast<unsigned long long>(totals.skipped_system_maps),
        session.continuous ? "true" : "false",
        static_cast<unsigned long long>(session.process_start_time),
        static_cast<unsigned long long>(session.scans_completed),
        static_cast<unsigned long long>(totals.map_start_elf_candidates),
        static_cast<unsigned long long>(
            totals.deep_scan_artifacts_published),
        static_cast<unsigned long long>(totals.artifacts_published),
        static_cast<unsigned long long>(totals.coverage_complete_artifacts),
        static_cast<unsigned long long>(totals.partial_artifacts),
        static_cast<unsigned long long>(totals.skipped_system_maps),
        static_cast<unsigned long long>(session.scans_completed),
        last.incremental ? "true" : "false", last.scope_ranges, last.maps,
        static_cast<unsigned long long>(last.map_start_elf_candidates),
        static_cast<unsigned long long>(last.deep_scan_artifacts_published),
        static_cast<unsigned long long>(last.artifacts_published),
        static_cast<unsigned long long>(last.coverage_complete_artifacts),
        static_cast<unsigned long long>(last.partial_artifacts),
        static_cast<unsigned long long>(last.skipped_system_maps));

    bool ok = write_result >= 0 && std::fflush(manifest) == 0 &&
              so_manifest_sync_file_inline(manifest);
    if (std::fclose(manifest) != 0) ok = false;
    if (!ok) {
        so_manifest_remove_file_inline(temporary_path);
        return false;
    }

    std::vector<ArtifactTransactionEntryInline> publications;
    publications.emplace_back(path, temporary_path);
    return artifact_publish_transaction_inline(
        &publications, publish_guard, publish_guard_context);
}
