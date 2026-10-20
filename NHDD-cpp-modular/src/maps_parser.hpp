// maps_parser.hpp — Parse /proc/<pid>/maps into typed regions
#pragma once

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include "common_types.hpp"

class MapsParser {
public:
    struct RegionList {
        MapsRegion* regs = nullptr;
        size_t      count = 0;

        ~RegionList() { delete[] regs; }
        RegionList(const RegionList&) = delete;
        RegionList& operator=(const RegionList&) = delete;
        RegionList() = default;
    };

    // Load maps for a given PID. Returns nullptr on failure and preserves a
    // concrete errno in error_out/errno. In particular, a stream error after
    // some valid lines never publishes a truncated RegionList as a snapshot.
    static RegionList* load_maps(const char* pid, int* error_out = nullptr) {
        if (error_out) *error_out = 0;
        if (!pid || !*pid) {
            set_error(error_out, EINVAL);
            return nullptr;
        }

        char path[256];
        const int path_length =
            std::snprintf(path, sizeof(path), "/proc/%s/maps", pid);
        if (path_length < 0 ||
            static_cast<size_t>(path_length) >= sizeof(path)) {
            set_error(error_out, ENAMETOOLONG);
            return nullptr;
        }

        FILE* f = std::fopen(path, "r");
        if (!f) {
            set_error(error_out, errno != 0 ? errno : EIO);
            return nullptr;
        }

        RegionList* result = parse_stream(f, error_out);
        const int parse_error = error_out ? *error_out : errno;
        if (std::fclose(f) != 0 && result) {
            delete result;
            result = nullptr;
            set_error(error_out, errno != 0 ? errno : EIO);
        } else if (!result) {
            // fclose may change errno; retain the actual parser/read failure.
            set_error(error_out, parse_error != 0 ? parse_error : EIO);
        }
        return result;
    }

    // Parse one maps-formatted stream without taking ownership of FILE*. This
    // is public so the parser's all-or-nothing I/O semantics can be tested with
    // deterministic streams instead of depending on a live /proc process.
    static RegionList* parse_stream(FILE* f, int* error_out = nullptr) {
        if (error_out) *error_out = 0;
        if (!f) {
            set_error(error_out, EINVAL);
            return nullptr;
        }

        auto* ml = new (std::nothrow) RegionList();
        if (!ml) {
            set_error(error_out, ENOMEM);
            return nullptr;
        }
        size_t cap = 512;
        ml->regs = new (std::nothrow) MapsRegion[cap]();
        if (!ml->regs) {
            delete ml;
            set_error(error_out, ENOMEM);
            return nullptr;
        }

        // A maps pathname can approach PATH_MAX; leave room for the numeric
        // fields too. If even this buffer is insufficient, fail the whole
        // snapshot rather than silently truncating the mapping identity.
        char line[8192];
        for (;;) {
            errno = 0;
            char* read_result = std::fgets(line, sizeof(line), f);
            const int read_errno = errno;
            if (!read_result) {
                if (std::ferror(f) != 0) {
                    delete ml;
                    set_error(error_out,
                              read_errno != 0 ? read_errno : EIO);
                    return nullptr;
                }
                break;
            }

            if (!std::strchr(line, '\n') && std::feof(f) == 0) {
                delete ml;
                set_error(error_out, EOVERFLOW);
                return nullptr;
            }

            if (ml->count == cap) {
                if (cap > static_cast<size_t>(-1) / 2u) {
                    delete ml;
                    set_error(error_out, EOVERFLOW);
                    return nullptr;
                }
                const size_t new_cap = cap * 2;
                auto* nr = new (std::nothrow) MapsRegion[new_cap]();
                if (!nr) {
                    delete ml;
                    set_error(error_out, ENOMEM);
                    return nullptr;
                }
                for (size_t i = 0; i < ml->count; ++i) nr[i] = ml->regs[i];
                delete[] ml->regs;
                ml->regs = nr;
                cap = new_cap;
            }
            MapsRegion* r = &ml->regs[ml->count];
            *r = MapsRegion{};

            unsigned long long start = 0, end = 0;
            unsigned long long dmaj = 0, dmin = 0, off_val = 0, ino = 0;
            int n = std::sscanf(line, "%llx-%llx %7s %llx %llx:%llx %llu",
                                &start, &end, r->perms, &off_val, &dmaj,
                                &dmin, &ino);
            if (n < 7) {
                // Every non-empty /proc/<pid>/maps record has seven fixed
                // numeric/permission fields before its optional pathname.
                // Treat a short or malformed record as a failed snapshot;
                // accepting it would turn parser damage into false mapping
                // removals or an incorrect continuous-scan identity.
                delete ml;
                set_error(error_out, EPROTO);
                return nullptr;
            }
            r->start = static_cast<uintptr_t>(start);
            r->end = static_cast<uintptr_t>(end);
            r->offset = static_cast<uint64_t>(off_val);
            r->inode = static_cast<uint64_t>(ino);
            r->dev_major = static_cast<uint32_t>(dmaj);
            r->dev_minor = static_cast<uint32_t>(dmin);

            for (int i = 0; i < 4; i++) {
                if (r->perms[i] == 'r') r->readable = true;
                if (r->perms[i] == 'w') r->writable = true;
                if (r->perms[i] == 'x') r->executable = true;
            }

            // Extract path: skip 5 whitespace-delimited fields
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
                while (plen > 0 && (p[plen-1] == '\n' || p[plen-1] == '\r'))
                    plen--;
                if (plen >= sizeof(r->path)) {
                    delete ml;
                    set_error(error_out, EOVERFLOW);
                    return nullptr;
                }
                std::snprintf(r->path, sizeof(r->path), "%.*s",
                              static_cast<int>(plen), p);
            }
            ml->count++;
        }

        // Keep this explicit even though the terminal fgets() path checked it:
        // callers must never mistake an I/O-shortened /proc snapshot for a
        // successful mapping removal/change observation.
        if (std::ferror(f) != 0) {
            delete ml;
            set_error(error_out, errno != 0 ? errno : EIO);
            return nullptr;
        }
        return ml;
    }

private:
    static void set_error(int* error_out, int error) {
        const int normalized = error != 0 ? error : EIO;
        if (error_out) *error_out = normalized;
        errno = normalized;
    }
};
