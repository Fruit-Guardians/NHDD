// maps_monitor.hpp — Incremental /proc/<pid>/maps and sampled-content monitor
#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include "common_types.hpp"
#include "maps_parser.hpp"
#include "nhdd_config.hpp"
#include "process_stat.hpp"

class MapsMonitor {
public:
    // A snapshot entry intentionally contains both the mapping identity and a
    // bounded, sampled content fingerprint. The fingerprint is evidence of a
    // likely change, not a cryptographic digest of the entire mapping.
    struct MappingState {
        uintptr_t start = 0;
        uintptr_t end = 0;
        uint64_t offset = 0;
        uint64_t inode = 0;
        uint32_t dev_major = 0;
        uint32_t dev_minor = 0;
        std::string perms;
        std::string path;
        bool readable = false;
        bool writable = false;
        bool executable = false;
        MappingSourceKind source_kind = MAP_SOURCE_ANONYMOUS;

        bool fingerprint_sampled = false;
        uint64_t sampled_fingerprint = 0;
        uint32_t sampled_bytes = 0;
    };

    struct ContentSamplingStatus {
        // requested means the configured snapshot budget was non-zero;
        // attempted means at least the backend or one byte range was tried.
        bool requested = false;
        bool attempted = false;
        bool backend_opened = false;
        bool available = false;
        uint64_t attempted_bytes = 0;
        uint64_t sampled_bytes = 0;
        uint64_t read_failures = 0;
        int last_errno = 0;

        bool all_reads_failed() const {
            return requested && attempted &&
                   (!backend_opened ||
                    (attempted_bytes != 0 && sampled_bytes == 0));
        }
    };

    struct MapsSnapshot {
        time_t timestamp = 0;
        uint64_t process_starttime = 0;
        ContentSamplingStatus content_sampling;
        std::vector<MappingState> mappings;
    };

    struct ChangeEvent {
        time_t timestamp = 0;
        uint32_t reasons = MAP_CHANGE_NONE;
        bool has_previous = false;
        bool has_current = false;
        MappingState previous;
        MappingState current;

        bool scannable() const {
            // Execute-only mappings are common with XOM/hardened loaders. A
            // privileged /proc/<pid>/mem reader may still recover them, and a
            // W->X transition must at least trigger scans of related header
            // mappings even when the changed page itself lacks PROT_READ.
            return has_current && (current.readable || current.executable) &&
                   (reasons & ~static_cast<uint32_t>(MAP_CHANGE_REMOVED)) != 0;
        }
    };

    struct ChangeSet {
        bool capture_ok = false;
        bool process_replaced = false;
        int capture_errno = 0;
        uint64_t process_starttime = 0;
        ContentSamplingStatus content_sampling;
        std::vector<ChangeEvent> events;
        std::vector<IncrementalScanRange> scan_ranges;

        bool has_changes() const { return !events.empty(); }
        bool has_scannable_changes() const { return !scan_ranges.empty(); }

        ScanScope make_scope() const {
            ScanScope scope;
            scope.ranges = scan_ranges.empty() ? nullptr : scan_ranges.data();
            scope.count = scan_ranges.size();
            scope.incremental = true;
            return scope;
        }
    };

    MapsMonitor() = default;

    uint64_t process_starttime() const { return baseline_.process_starttime; }
    bool has_baseline() const { return baseline_taken_; }
    int last_capture_errno() const { return last_capture_errno_; }

    // Linux process identity must include starttime; a numeric PID alone may be
    // recycled while a long-running continuous session is active.
    static bool read_process_starttime(const char* pid, uint64_t* out) {
        return ProcessStat::starttime(pid,out);
    }

    static std::string process_identity_key(const char* pid, uint64_t starttime) {
        return std::string(pid ? pid : "") + ":" + std::to_string(starttime);
    }

    // Package targets intentionally follow newly spawned generations. A
    // numeric PID target is pinned to the generation observed at baseline and
    // must never adopt a later, potentially unrelated process reusing the PID.
    static bool may_follow_new_generation(bool target_is_numeric) {
        return !target_is_numeric;
    }

    // Take the initial state. Unlike the old monitor this records every maps
    // entry: anonymous, memfd, APK-backed and ordinary file mappings alike.
    bool take_baseline(const char* pid, uint64_t expected_starttime = 0) {
        MapsSnapshot snapshot;
        int capture_error = 0;
        if (!capture_snapshot(pid, &snapshot, expected_starttime,
                              &capture_error)) {
            last_capture_errno_ = capture_error != 0 ? capture_error : EIO;
            return false;
        }
        last_capture_errno_ = 0;
        baseline_ = std::move(snapshot);
        baseline_taken_ = true;

        size_t sampled = 0;
        for (const auto& mapping : baseline_.mappings)
            if (mapping.fingerprint_sampled) ++sampled;
        std::fprintf(stderr,
                     "[*] MAPS MONITOR: PID %s baseline=%zu mappings, "
                     "%zu sampled fingerprints, starttime=%llu\n",
                     pid, baseline_.mappings.size(), sampled,
                     static_cast<unsigned long long>(baseline_.process_starttime));
        report_sampling_failure(pid, baseline_.content_sampling, "baseline");
        sampling_failure_reported_ =
            baseline_.content_sampling.all_reads_failed();
        return true;
    }

    // Compare against the immediately preceding snapshot, then advance the
    // baseline. This catches load, unload, permission, identity and sampled
    // in-place content changes without repeatedly reporting the same event.
    ChangeSet check_changes(const char* pid, uint64_t expected_starttime = 0) {
        ChangeSet result;
        MapsSnapshot current;
        int capture_error = 0;
        if (!capture_snapshot(pid, &current, expected_starttime,
                              &capture_error)) {
            result.capture_errno = capture_error != 0 ? capture_error : EIO;
            last_capture_errno_ = result.capture_errno;
            return result;
        }
        last_capture_errno_ = 0;
        result.capture_ok = true;
        result.process_starttime = current.process_starttime;
        result.content_sampling = current.content_sampling;
        if (current.content_sampling.all_reads_failed()) {
            if (!sampling_failure_reported_)
                report_sampling_failure(pid, current.content_sampling,
                                        "snapshot");
            sampling_failure_reported_ = true;
        } else {
            sampling_failure_reported_ = false;
        }

        if (!baseline_taken_) {
            baseline_ = std::move(current);
            baseline_taken_ = true;
            return result;
        }

        if (baseline_.process_starttime != current.process_starttime) {
            MapsSnapshot empty;
            empty.timestamp = baseline_.timestamp;
            empty.process_starttime = current.process_starttime;
            result = diff_snapshots(empty, current);
            result.capture_ok = true;
            result.process_replaced = true;
            result.process_starttime = current.process_starttime;
            result.content_sampling = current.content_sampling;
        } else {
            result = diff_snapshots(baseline_, current);
            result.capture_ok = true;
            result.process_starttime = current.process_starttime;
            result.content_sampling = current.content_sampling;
        }
        baseline_ = std::move(current);
        return result;
    }

    // Pure logic entry point used by unit tests and future snapshot replay.
    static ChangeSet diff_snapshots(const MapsSnapshot& previous,
                                    const MapsSnapshot& current) {
        ChangeSet result;
        result.capture_ok = true;
        result.process_starttime = current.process_starttime;
        result.content_sampling = current.content_sampling;
        const time_t when = current.timestamp ? current.timestamp : std::time(nullptr);

        std::unordered_map<std::string, size_t> previous_by_identity;
        previous_by_identity.reserve(previous.mappings.size());
        for (size_t i = 0; i < previous.mappings.size(); ++i)
            previous_by_identity.emplace(identity_key(previous.mappings[i]), i);

        std::vector<bool> previous_matched(previous.mappings.size(), false);

        for (const auto& now : current.mappings) {
            const MappingState* before = nullptr;
            size_t before_index = 0;
            bool identity_changed = false;

            auto exact = previous_by_identity.find(identity_key(now));
            if (exact != previous_by_identity.end()) {
                before_index = exact->second;
                before = &previous.mappings[before_index];
                previous_matched[before_index] = true;
            } else {
                // The address range stayed in place but the backing identity
                // (path/inode/device/offset) changed.
                for (size_t i = 0; i < previous.mappings.size(); ++i) {
                    if (previous_matched[i]) continue;
                    const auto& candidate = previous.mappings[i];
                    if (candidate.start == now.start && candidate.end == now.end) {
                        before = &candidate;
                        before_index = i;
                        previous_matched[i] = true;
                        identity_changed = true;
                        break;
                    }
                }
            }

            uint32_t reasons = MAP_CHANGE_NONE;
            if (!before) {
                reasons |= MAP_CHANGE_ADDED;

                // mprotect commonly splits a mapping. Find an overlapping old
                // range with the same backing to retain W->X semantics even
                // though the exact range identity no longer exists.
                const MappingState* overlap = find_backing_overlap(previous, now);
                if (overlap) {
                    if (overlap->perms != now.perms)
                        reasons |= MAP_CHANGE_PERMISSIONS;
                    if (is_write_to_execute(*overlap, now))
                        reasons |= MAP_CHANGE_WRITE_EXEC;
                }
            } else {
                if (identity_changed) reasons |= MAP_CHANGE_IDENTITY;
                if (before->perms != now.perms)
                    reasons |= MAP_CHANGE_PERMISSIONS;
                if (is_write_to_execute(*before, now))
                    reasons |= MAP_CHANGE_WRITE_EXEC;
                if (fingerprint_changed(*before, now))
                    reasons |= MAP_CHANGE_CONTENT;
            }

            if (reasons != MAP_CHANGE_NONE) {
                ChangeEvent event;
                event.timestamp = when;
                event.reasons = reasons;
                event.has_current = true;
                event.current = now;
                if (before) {
                    event.has_previous = true;
                    event.previous = *before;
                }
                append_event(result, event);
            }
        }

        // An old range that has no exact/replacement counterpart was removed.
        // Removal is timeline evidence, but there is no current memory to read.
        for (size_t i = 0; i < previous.mappings.size(); ++i) {
            if (previous_matched[i]) continue;
            ChangeEvent event;
            event.timestamp = when;
            event.reasons = MAP_CHANGE_REMOVED;
            event.has_previous = true;
            event.previous = previous.mappings[i];
            append_event(result, event);
        }

        return result;
    }

    static const char* source_kind_name(MappingSourceKind kind) {
        switch (kind) {
            case MAP_SOURCE_ANONYMOUS: return "anonymous";
            case MAP_SOURCE_MEMFD: return "memfd";
            case MAP_SOURCE_APK: return "apk";
            case MAP_SOURCE_FILE: return "file";
            case MAP_SOURCE_SPECIAL: return "special";
        }
        return "unknown";
    }

    static std::string reasons_string(uint32_t reasons) {
        std::string value;
        append_reason(value, reasons, MAP_CHANGE_ADDED, "added");
        append_reason(value, reasons, MAP_CHANGE_REMOVED, "removed");
        append_reason(value, reasons, MAP_CHANGE_IDENTITY, "identity");
        append_reason(value, reasons, MAP_CHANGE_PERMISSIONS, "permissions");
        append_reason(value, reasons, MAP_CHANGE_WRITE_EXEC, "write_to_execute");
        append_reason(value, reasons, MAP_CHANGE_CONTENT, "sampled_content");
        return value.empty() ? "none" : value;
    }

    static void report_sampling_failure(const char* pid,
                                        const ContentSamplingStatus& status,
                                        const char* phase) {
        if (!status.all_reads_failed()) return;
        const int error = status.last_errno != 0 ? status.last_errno : EIO;
        std::fprintf(
            stderr,
            "[!] MAPS MONITOR: PID %s %s content sampling unavailable "
            "(attempted_bytes=%llu sampled_bytes=%llu failures=%llu errno=%d: %s); "
            "mapping/permission monitoring remains active\n",
            pid ? pid : "?", phase ? phase : "snapshot",
            static_cast<unsigned long long>(status.attempted_bytes),
            static_cast<unsigned long long>(status.sampled_bytes),
            static_cast<unsigned long long>(status.read_failures), error,
            std::strerror(error));
    }

    // One JSONL record per mapping change. Fingerprints are explicitly marked
    // as sampled so users cannot mistake them for whole-map hashes.
    static bool write_timeline_events(const char* timeline_path, const char* pid,
                                      uint64_t process_starttime,
                                      const ChangeSet& changes) {
        if (changes.events.empty()) return true;
        if (!timeline_path) {
            errno = EINVAL;
            return false;
        }
        FILE* f = std::fopen(timeline_path, "a");
        if (!f) return false;

        for (const auto& event : changes.events) {
            const MappingState& shown = event.has_current ? event.current : event.previous;
            std::fprintf(f, "{\"timestamp\":%lld,\"pid\":\"",
                         static_cast<long long>(event.timestamp));
            json_escape(f, pid ? pid : "");
            std::fprintf(f,
                         "\",\"process_starttime\":%llu,\"event\":\"mapping_change\","
                         "\"reasons\":[",
                         static_cast<unsigned long long>(process_starttime));
            write_reason_array(f, event.reasons);
            std::fprintf(f,
                         "],\"mapping_kind\":\"%s\",\"start\":\"0x%lx\","
                         "\"end\":\"0x%lx\",\"size\":%llu,\"path\":\"",
                         source_kind_name(shown.source_kind),
                         static_cast<unsigned long>(shown.start),
                         static_cast<unsigned long>(shown.end),
                         static_cast<unsigned long long>(shown.end - shown.start));
            json_escape(f, shown.path.c_str());
            std::fprintf(f, "\",\"before_perms\":\"");
            if (event.has_previous) json_escape(f, event.previous.perms.c_str());
            std::fprintf(f, "\",\"after_perms\":\"");
            if (event.has_current) json_escape(f, event.current.perms.c_str());
            std::fprintf(f, "\",\"before_identity\":");
            write_mapping_identity(f, event.has_previous, event.previous);
            std::fprintf(f, ",\"after_identity\":");
            write_mapping_identity(f, event.has_current, event.current);
            std::fprintf(f,
                         ",\"content_sampling\":{\"requested\":%s,"
                         "\"attempted\":%s,\"backend_opened\":%s,"
                         "\"available\":%s,"
                         "\"attempted_bytes\":%llu,\"sampled_bytes\":%llu,"
                         "\"read_failures\":%llu,\"errno\":%d},"
                         "\"fingerprint_sampled\":%s",
                         changes.content_sampling.requested ? "true" : "false",
                         changes.content_sampling.attempted ? "true" : "false",
                         changes.content_sampling.backend_opened ? "true" : "false",
                         changes.content_sampling.available ? "true" : "false",
                         static_cast<unsigned long long>(
                             changes.content_sampling.attempted_bytes),
                         static_cast<unsigned long long>(
                             changes.content_sampling.sampled_bytes),
                         static_cast<unsigned long long>(
                             changes.content_sampling.read_failures),
                         changes.content_sampling.last_errno,
                         (event.has_current && event.current.fingerprint_sampled) ||
                                 (event.has_previous && event.previous.fingerprint_sampled)
                             ? "true" : "false");
            if ((event.has_current && event.current.fingerprint_sampled) ||
                (event.has_previous && event.previous.fingerprint_sampled)) {
                std::fprintf(f,
                             ",\"fingerprint\":{\"mode\":\"sampled\","
                             "\"algorithm\":\"fnv1a64-3xN\",\"before\":\"");
                if (event.has_previous && event.previous.fingerprint_sampled)
                    std::fprintf(f, "%016llx",
                                 static_cast<unsigned long long>(
                                     event.previous.sampled_fingerprint));
                std::fprintf(f, "\",\"after\":\"");
                if (event.has_current && event.current.fingerprint_sampled)
                    std::fprintf(f, "%016llx",
                                 static_cast<unsigned long long>(
                                     event.current.sampled_fingerprint));
                std::fprintf(f, "\",\"sampled_bytes\":%u}",
                             event.has_current ? event.current.sampled_bytes
                                               : event.previous.sampled_bytes);
            }
            std::fprintf(f, "}\n");
        }
        bool ok = true;
        int failure_errno = 0;
        if (std::ferror(f) != 0) {
            ok = false;
            failure_errno = errno != 0 ? errno : EIO;
        }
        if (std::fflush(f) != 0) {
            ok = false;
            if (failure_errno == 0)
                failure_errno = errno != 0 ? errno : EIO;
        }
        if (std::ferror(f) != 0) {
            ok = false;
            if (failure_errno == 0)
                failure_errno = errno != 0 ? errno : EIO;
        }
        if (std::fclose(f) != 0) {
            ok = false;
            if (failure_errno == 0)
                failure_errno = errno != 0 ? errno : EIO;
        }
        if (!ok) errno = failure_errno != 0 ? failure_errno : EIO;
        return ok;
    }

    // Establish the session's timeline semantics before the first event. A
    // fresh run truncates stale records even when it observes no changes;
    // --keep opens in append mode and preserves the earlier session.
    static bool prepare_timeline_file(const char* timeline_path,
                                      bool keep_existing) {
        if (!timeline_path || !*timeline_path) {
            errno = EINVAL;
            return false;
        }
        FILE* f = std::fopen(timeline_path, keep_existing ? "a" : "w");
        if (!f) return false;

        bool ok = true;
        int failure_errno = 0;
        if (std::fflush(f) != 0 || std::ferror(f) != 0) {
            ok = false;
            failure_errno = errno != 0 ? errno : EIO;
        }
        if (std::fclose(f) != 0) {
            ok = false;
            if (failure_errno == 0)
                failure_errno = errno != 0 ? errno : EIO;
        }
        if (!ok) errno = failure_errno != 0 ? failure_errno : EIO;
        return ok;
    }

    void reset() {
        baseline_taken_ = false;
        sampling_failure_reported_ = false;
        last_capture_errno_ = 0;
        baseline_ = MapsSnapshot{};
    }

    // Exposed for deterministic tests and scanner scope labeling.
    static MappingSourceKind classify_source(const std::string& path) {
        if (path.empty() || path.compare(0, 6, "[anon:") == 0)
            return MAP_SOURCE_ANONYMOUS;
        if (path.find("memfd:") != std::string::npos)
            return MAP_SOURCE_MEMFD;
        if (has_suffix(path, ".apk") || path.find(".apk!") != std::string::npos)
            return MAP_SOURCE_APK;
        if (!path.empty() && path.front() == '[')
            return MAP_SOURCE_SPECIAL;
        return MAP_SOURCE_FILE;
    }

private:
    static bool capture_snapshot(const char* pid, MapsSnapshot* out,
                                 uint64_t expected_starttime,
                                 int* error_out) {
        if (error_out) *error_out = 0;
        if (!out) {
            if (error_out) *error_out = EINVAL;
            errno = EINVAL;
            return false;
        }
        uint64_t starttime_before = 0;
        if (!read_process_starttime(pid, &starttime_before)) {
            const int error = errno != 0 ? errno : ESRCH;
            if (error_out) *error_out = error;
            errno = error;
            return false;
        }
        if (expected_starttime != 0 &&
            starttime_before != expected_starttime) {
            if (error_out) *error_out = ESRCH;
            errno = ESRCH;
            return false;
        }

        int maps_error = 0;
        MapsParser::RegionList* maps = MapsParser::load_maps(pid, &maps_error);
        if (!maps) {
            const int error = maps_error != 0 ? maps_error : EIO;
            if (error_out) *error_out = error;
            errno = error;
            return false;
        }

        out->timestamp = std::time(nullptr);
        out->process_starttime = starttime_before;
        out->content_sampling = ContentSamplingStatus{};
        out->mappings.clear();
        out->mappings.reserve(maps->count);

        const auto& cfg = NhddConfig::instance();
        size_t budget = cfg.monitor_fingerprint_budget_kb > 0
                            ? static_cast<size_t>(cfg.monitor_fingerprint_budget_kb) * 1024u
                            : 0u;
        size_t sample_size = cfg.monitor_fingerprint_sample_bytes > 0
                                 ? static_cast<size_t>(cfg.monitor_fingerprint_sample_bytes)
                                 : 64u;
        if (sample_size > 4096u) sample_size = 4096u;
        out->content_sampling.requested = budget > 0;
        out->content_sampling.backend_opened =
            cfg.use_vm_readv && budget > 0;

#if defined(__linux__)
        int mem_fd = -1;
        if (!cfg.use_vm_readv && budget > 0) {
            char mem_path[128];
            std::snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", pid);
            errno = 0;
            mem_fd = ::open(mem_path, O_RDONLY | O_CLOEXEC);
            out->content_sampling.attempted = true;
            if (mem_fd >= 0) {
                out->content_sampling.backend_opened = true;
            } else {
                out->content_sampling.last_errno = errno != 0 ? errno : EIO;
            }
        }
        const pid_t target_pid = static_cast<pid_t>(std::atoi(pid));
#else
        const int mem_fd = -1;
        const int target_pid = 0;
#endif

        for (size_t i = 0; i < maps->count; ++i) {
            const MapsRegion& region = maps->regs[i];
            MappingState state;
            state.start = region.start;
            state.end = region.end;
            state.offset = region.offset;
            state.inode = region.inode;
            state.dev_major = region.dev_major;
            state.dev_minor = region.dev_minor;
            state.perms = region.perms;
            state.path = region.path;
            state.readable = region.readable;
            state.writable = region.writable;
            state.executable = region.executable;
            state.source_kind = classify_source(state.path);

            out->mappings.push_back(std::move(state));
        }

        // Spend the bounded budget on unpacking-relevant mappings first so a
        // long list of early system DSOs cannot permanently starve anonymous,
        // memfd, APK or app-private mappings near the end of /proc/pid/maps.
        const bool can_sample = cfg.use_vm_readv || mem_fd >= 0;
        for (int priority = 0;
             priority <= 2 && budget > 0 && can_sample; ++priority) {
            for (auto& mapping : out->mappings) {
                if (budget == 0) break;
                if (sample_priority(mapping) != priority) continue;
                sample_mapping(mem_fd, target_pid, cfg.use_vm_readv,
                               mapping, sample_size, &budget,
                               &out->content_sampling);
            }
        }

#if defined(__linux__)
        if (mem_fd >= 0) ::close(mem_fd);
#endif
        delete maps;

        uint64_t starttime_after = 0;
        if (!read_process_starttime(pid, &starttime_after) ||
            starttime_after != starttime_before ||
            (expected_starttime != 0 &&
             starttime_after != expected_starttime)) {
            *out = MapsSnapshot{};
            const int error = errno != 0 ? errno : ESRCH;
            if (error_out) *error_out = error;
            errno = error;
            return false;
        }
        return true;
    }

    static int sample_priority(const MappingState& mapping) {
        if (mapping.start >= mapping.end ||
            (!mapping.readable && !mapping.executable)) return 3;
        if (mapping.source_kind == MAP_SOURCE_ANONYMOUS ||
            mapping.source_kind == MAP_SOURCE_MEMFD ||
            mapping.source_kind == MAP_SOURCE_APK || mapping.inode == 0 ||
            mapping.path == "[heap]" ||
            mapping.path.find("ashmem") != std::string::npos)
            return 0;
        if (mapping.path.find("/data/") != std::string::npos)
            return 0;
        if (mapping.executable) return 1;
        return 2;
    }

    static void sample_mapping(int mem_fd, int target_pid, bool use_vm_readv,
                               MappingState& mapping, size_t sample_size,
                               size_t* budget,
                               ContentSamplingStatus* status) {
        if (!budget || !status || *budget == 0 ||
            mapping.start >= mapping.end) return;
        const uint64_t length = static_cast<uint64_t>(mapping.end - mapping.start);
        const size_t wanted = static_cast<size_t>(std::min<uint64_t>(sample_size, length));
        if (wanted == 0) return;

        uint64_t offsets[3] = {0, 0, 0};
        offsets[0] = 0;
        offsets[1] = length > wanted ? (length - wanted) / 2u : 0;
        offsets[2] = length > wanted ? length - wanted : 0;

        uint64_t hash = 1469598103934665603ull;
        uint32_t total = 0;
        std::vector<unsigned char> bytes(wanted);
        uint64_t last_offset = UINT64_MAX;

        for (uint64_t offset : offsets) {
            if (offset == last_offset || *budget == 0) continue;
            last_offset = offset;
            size_t to_read = std::min(wanted, *budget);
            status->attempted = true;
            status->attempted_bytes += static_cast<uint64_t>(to_read);
            errno = 0;
            ssize_t got = read_sample(mem_fd, target_pid, use_vm_readv,
                                      mapping.start + static_cast<uintptr_t>(offset),
                                      bytes.data(), to_read);
            const int read_errno = errno;
            if (got <= 0) {
                ++status->read_failures;
                status->last_errno = read_errno != 0 ? read_errno : EIO;
                if (use_vm_readv &&
                    (status->last_errno == ENOSYS ||
                     status->last_errno == EPERM ||
                     status->last_errno == EACCES ||
                     status->last_errno == ESRCH)) {
                    *budget = 0;
                }
                continue;
            }
            status->available = true;
            status->sampled_bytes += static_cast<uint64_t>(got);

            // Incorporate the sampled position as well as bytes so different
            // layouts cannot trivially collapse to the same observation.
            hash_bytes(hash, reinterpret_cast<const unsigned char*>(&offset),
                       sizeof(offset));
            hash_bytes(hash, bytes.data(), static_cast<size_t>(got));
            total += static_cast<uint32_t>(got);
            *budget -= static_cast<size_t>(got);
        }

        if (total > 0) {
            mapping.fingerprint_sampled = true;
            mapping.sampled_fingerprint = hash;
            mapping.sampled_bytes = total;
        }
    }

    static ssize_t read_sample(int mem_fd, int target_pid, bool use_vm_readv,
                               uintptr_t address, void* out, size_t size) {
#if defined(__linux__)
        if (use_vm_readv) {
            struct iovec local = {out, size};
            struct iovec remote = {reinterpret_cast<void*>(address), size};
            return ::process_vm_readv(static_cast<pid_t>(target_pid),
                                      &local, 1, &remote, 1, 0);
        }
        if (mem_fd >= 0)
            return ::pread(mem_fd, out, size, static_cast<off_t>(address));
#else
        (void)mem_fd;
        (void)target_pid;
        (void)use_vm_readv;
        (void)address;
        (void)out;
        (void)size;
#endif
        return -1;
    }

    static void hash_bytes(uint64_t& hash, const unsigned char* bytes, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            hash ^= bytes[i];
            hash *= 1099511628211ull;
        }
    }

    static std::string identity_key(const MappingState& mapping) {
        std::ostringstream key;
        key << std::hex << mapping.start << ':' << mapping.end << ':'
            << mapping.offset << ':' << mapping.dev_major << ':'
            << mapping.dev_minor << ':' << mapping.inode << ':'
            << mapping.path.size() << ':' << mapping.path;
        return key.str();
    }

    static bool same_backing(const MappingState& old_mapping,
                             const MappingState& new_mapping) {
        if (old_mapping.path != new_mapping.path ||
            old_mapping.dev_major != new_mapping.dev_major ||
            old_mapping.dev_minor != new_mapping.dev_minor ||
            old_mapping.inode != new_mapping.inode)
            return false;

        // Anonymous mappings keep offset 0 even after mprotect splits them, so
        // address overlap plus the anonymous identity is the best predecessor
        // signal available from /proc/<pid>/maps.
        if (old_mapping.source_kind == MAP_SOURCE_ANONYMOUS &&
            new_mapping.source_kind == MAP_SOURCE_ANONYMOUS)
            return true;

        if (new_mapping.start >= old_mapping.start) {
            const uint64_t delta = static_cast<uint64_t>(new_mapping.start - old_mapping.start);
            return old_mapping.offset + delta == new_mapping.offset;
        }
        return true;
    }

    static const MappingState* find_backing_overlap(const MapsSnapshot& previous,
                                                    const MappingState& current) {
        for (const auto& candidate : previous.mappings) {
            if (candidate.start >= current.end || current.start >= candidate.end)
                continue;
            if (same_backing(candidate, current)) return &candidate;
        }
        return nullptr;
    }

    static bool fingerprint_changed(const MappingState& before,
                                    const MappingState& after) {
        return before.fingerprint_sampled && after.fingerprint_sampled &&
               before.sampled_bytes == after.sampled_bytes &&
               before.sampled_fingerprint != after.sampled_fingerprint;
    }

    static bool is_write_to_execute(const MappingState& before,
                                    const MappingState& after) {
        return before.writable && !before.executable && after.executable;
    }

    static void append_event(ChangeSet& result, const ChangeEvent& event) {
        result.events.push_back(event);
        if (!event.scannable()) return;

        const MappingState& mapping = event.current;
        for (auto& range : result.scan_ranges) {
            if (range.start == mapping.start && range.end == mapping.end &&
                std::strcmp(range.path, mapping.path.c_str()) == 0) {
                range.reasons |= event.reasons;
                range.fingerprint_sampled =
                    range.fingerprint_sampled || mapping.fingerprint_sampled;
                return;
            }
        }

        IncrementalScanRange range;
        range.start = mapping.start;
        range.end = mapping.end;
        range.reasons = event.reasons;
        range.source_kind = mapping.source_kind;
        range.fingerprint_sampled = mapping.fingerprint_sampled;
        range.readable = mapping.readable;
        range.writable = mapping.writable;
        range.executable = mapping.executable;
        std::snprintf(range.path, sizeof(range.path), "%s", mapping.path.c_str());
        result.scan_ranges.push_back(range);
    }

    static bool has_suffix(const std::string& text, const char* suffix) {
        const size_t suffix_len = std::strlen(suffix);
        return text.size() >= suffix_len &&
               text.compare(text.size() - suffix_len, suffix_len, suffix) == 0;
    }

    static void append_reason(std::string& out, uint32_t reasons,
                              uint32_t bit, const char* name) {
        if ((reasons & bit) == 0) return;
        if (!out.empty()) out += ',';
        out += name;
    }

    static void write_reason_array(FILE* f, uint32_t reasons) {
        bool first = true;
        const struct ReasonName { uint32_t bit; const char* name; } names[] = {
            {MAP_CHANGE_ADDED, "added"},
            {MAP_CHANGE_REMOVED, "removed"},
            {MAP_CHANGE_IDENTITY, "identity"},
            {MAP_CHANGE_PERMISSIONS, "permissions"},
            {MAP_CHANGE_WRITE_EXEC, "write_to_execute"},
            {MAP_CHANGE_CONTENT, "sampled_content"},
        };
        for (const auto& item : names) {
            if ((reasons & item.bit) == 0) continue;
            if (!first) std::fputc(',', f);
            std::fprintf(f, "\"%s\"", item.name);
            first = false;
        }
    }

    static void write_mapping_identity(FILE* f, bool present,
                                       const MappingState& mapping) {
        if (!present) {
            std::fputs("null", f);
            return;
        }
        std::fputs("{\"path\":\"", f);
        json_escape(f, mapping.path.c_str());
        std::fprintf(
            f,
            "\",\"inode\":%llu,\"dev\":\"%x:%x\","
            "\"dev_major\":%u,\"dev_minor\":%u,\"offset\":\"0x%llx\","
            "\"perms\":\"",
            static_cast<unsigned long long>(mapping.inode),
            static_cast<unsigned>(mapping.dev_major),
            static_cast<unsigned>(mapping.dev_minor),
            mapping.dev_major, mapping.dev_minor,
            static_cast<unsigned long long>(mapping.offset));
        json_escape(f, mapping.perms.c_str());
        std::fprintf(
            f,
            "\",\"range\":{\"start\":\"0x%lx\",\"end\":\"0x%lx\","
            "\"size\":%llu}}",
            static_cast<unsigned long>(mapping.start),
            static_cast<unsigned long>(mapping.end),
            static_cast<unsigned long long>(mapping.end - mapping.start));
    }

    static void json_escape(FILE* f, const char* s) {
        for (; s && *s; ++s) {
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

    bool baseline_taken_ = false;
    bool sampling_failure_reported_ = false;
    int last_capture_errno_ = 0;
    MapsSnapshot baseline_;
};
