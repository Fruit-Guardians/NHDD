// artifact_transaction.hpp — guarded, rollback-safe publication of file sets
#pragma once

#include <cstdio>
#include <string>
#include <vector>

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

using ArtifactTransactionGuardInline = bool (*)(void*);

inline long artifact_transaction_writer_pid_inline() {
#if defined(_WIN32)
    return static_cast<long>(::_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

inline bool artifact_file_exists_inline(const char* path) {
    if (!path || !*path) return false;
    FILE* file = std::fopen(path, "rb");
    if (!file) return false;
    (void)std::fclose(file);
    return true;
}

inline bool artifact_sync_file_inline(FILE* file) {
    if (!file) return false;
#if defined(_WIN32)
    return ::_commit(::_fileno(file)) == 0;
#else
    return ::fsync(::fileno(file)) == 0;
#endif
}

inline bool artifact_replace_file_inline(const char* source,
                                         const char* destination) {
    if (!source || !destination) return false;
#if defined(_WIN32)
    return ::MoveFileExA(source, destination,
                         MOVEFILE_REPLACE_EXISTING |
                             MOVEFILE_WRITE_THROUGH) != 0;
#else
    return std::rename(source, destination) == 0;
#endif
}

inline bool artifact_copy_file_inline(const char* source,
                                      const char* destination) {
    if (!source || !destination) return false;
    FILE* input = std::fopen(source, "rb");
    if (!input) return false;
    FILE* output = std::fopen(destination, "wb");
    if (!output) {
        (void)std::fclose(input);
        return false;
    }

    bool ok = true;
    unsigned char buffer[64 * 1024];
    while (ok) {
        const size_t count = std::fread(buffer, 1, sizeof(buffer), input);
        if (count != 0 && std::fwrite(buffer, 1, count, output) != count)
            ok = false;
        if (count < sizeof(buffer)) {
            if (std::ferror(input)) ok = false;
            break;
        }
    }
    if (ok && (std::fflush(output) != 0 ||
               !artifact_sync_file_inline(output))) {
        ok = false;
    }
    if (std::fclose(input) != 0) ok = false;
    if (std::fclose(output) != 0) ok = false;
    if (!ok) (void)std::remove(destination);
    return ok;
}

inline std::string artifact_sidecar_path_inline(const char* path,
                                                const char* kind) {
    std::string sidecar(path ? path : "");
    sidecar += ".nhdd-";
    sidecar += kind ? kind : "sidecar";
    sidecar += ".";
    sidecar += std::to_string(artifact_transaction_writer_pid_inline());
    return sidecar;
}

struct ArtifactTransactionEntryInline {
    std::string final_path;
    std::string temporary_path;
    std::string backup_path;
    bool final_existed = false;
    bool backup_created = false;
    bool final_published = false;

    ArtifactTransactionEntryInline(const char* final_name,
                                   const char* temporary_name)
        : final_path(final_name ? final_name : ""),
          temporary_path(temporary_name ? temporary_name : ""),
          backup_path(artifact_sidecar_path_inline(final_name, "bak")) {}
};

inline void artifact_cleanup_temporaries_inline(
        const std::vector<ArtifactTransactionEntryInline>& entries) {
    for (const auto& entry : entries) {
        if (!entry.temporary_path.empty())
            (void)std::remove(entry.temporary_path.c_str());
    }
}

// Publish every staged file as one logical failure/rollback set. This is not an
// externally atomic multi-file snapshot: observers may see earlier entries new
// while later entries are old. Each individual final name, however, stays
// continuously present because the old file is copied to a synced backup and
// the staged file atomically replaces it. Any replace failure or rejected
// generation guard restores every old final in reverse order and removes newly
// published files.
// A backup is deliberately retained if its restoration itself fails: keeping
// recoverable evidence is safer than deleting the last good copy.
inline bool artifact_publish_transaction_inline(
        std::vector<ArtifactTransactionEntryInline>* entries,
        ArtifactTransactionGuardInline guard = nullptr,
        void* guard_context = nullptr) {
    if (!entries || entries->empty()) return false;
    const auto guard_allows = [&]() {
        return !guard || guard(guard_context);
    };

    for (auto& entry : *entries) {
        if (entry.final_path.empty() || entry.temporary_path.empty() ||
            entry.backup_path.empty()) {
            artifact_cleanup_temporaries_inline(*entries);
            return false;
        }

        // Recover an interrupted earlier publication before starting a new
        // transaction. If both names exist their authority is ambiguous (a
        // prior rollback may have failed), so preserve both and fail closed.
        if (artifact_file_exists_inline(entry.backup_path.c_str())) {
            if (artifact_file_exists_inline(entry.final_path.c_str())) {
                std::fprintf(stderr,
                             "[!] Refusing artifact publication with both "
                             "final and recovery backup present: %s\n",
                             entry.final_path.c_str());
                artifact_cleanup_temporaries_inline(*entries);
                return false;
            } else if (!artifact_replace_file_inline(
                           entry.backup_path.c_str(),
                           entry.final_path.c_str())) {
                artifact_cleanup_temporaries_inline(*entries);
                return false;
            }
        }
        entry.final_existed =
            artifact_file_exists_inline(entry.final_path.c_str());
    }

    const auto rollback = [&]() {
        bool restored = true;
        for (auto it = entries->rbegin(); it != entries->rend(); ++it) {
            if (it->backup_created) {
                if (it->final_published) {
                    if (!artifact_replace_file_inline(
                            it->backup_path.c_str(),
                            it->final_path.c_str())) {
                        restored = false;
                        std::fprintf(stderr,
                                     "[!] Failed to restore artifact backup "
                                     "%s -> %s\n",
                                     it->backup_path.c_str(),
                                     it->final_path.c_str());
                    } else {
                        it->backup_created = false;
                    }
                } else if (std::remove(it->backup_path.c_str()) != 0) {
                    restored = false;
                    std::fprintf(stderr,
                                 "[!] Failed to remove unused artifact "
                                 "backup: %s\n",
                                 it->backup_path.c_str());
                } else {
                    it->backup_created = false;
                }
            } else if (it->final_published &&
                       artifact_file_exists_inline(it->final_path.c_str()) &&
                       std::remove(it->final_path.c_str()) != 0) {
                restored = false;
                std::fprintf(stderr,
                             "[!] Failed to remove rolled-back artifact: %s\n",
                             it->final_path.c_str());
            }
        }
        artifact_cleanup_temporaries_inline(*entries);
        return restored;
    };

    if (!guard_allows()) {
        artifact_cleanup_temporaries_inline(*entries);
        return false;
    }

    for (auto& entry : *entries) {
        if (entry.final_existed) {
            if (!artifact_copy_file_inline(entry.final_path.c_str(),
                                           entry.backup_path.c_str())) {
                (void)rollback();
                return false;
            }
            entry.backup_created = true;
        }
        if (!artifact_replace_file_inline(entry.temporary_path.c_str(),
                                          entry.final_path.c_str())) {
            (void)rollback();
            return false;
        }
        entry.final_published = true;
        if (!guard_allows()) {
            (void)rollback();
            return false;
        }
    }

    if (!guard_allows()) {
        (void)rollback();
        return false;
    }

    artifact_cleanup_temporaries_inline(*entries);
    for (auto& entry : *entries) {
        if (entry.backup_created) {
            if (std::remove(entry.backup_path.c_str()) == 0) {
                entry.backup_created = false;
            } else {
                // The committed final is authoritative. Retain a cleanup-
                // resistant backup for recovery and report it, but do not turn
                // a successful publication into a false rollback failure.
                std::fprintf(stderr,
                             "[!] Published artifact but retained stale "
                             "backup: %s\n",
                             entry.backup_path.c_str());
            }
        }
    }
    return true;
}
