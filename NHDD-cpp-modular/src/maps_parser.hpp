// maps_parser.hpp — Parse /proc/<pid>/maps into typed regions
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "common_types.hpp"

class MapsParser {
public:
    struct RegionList {
        MapsRegion* regs = nullptr;
        size_t      count = 0;

        ~RegionList() { free(regs); }
        RegionList(const RegionList&) = delete;
        RegionList& operator=(const RegionList&) = delete;
        RegionList() = default;
    };

    // Load maps for a given PID. Returns nullptr on failure.
    static RegionList* load_maps(const char* pid) {
        char path[256];
        std::snprintf(path, sizeof(path), "/proc/%s/maps", pid);
        FILE* f = std::fopen(path, "r");
        if (!f) return nullptr;

        auto* ml = new RegionList();
        size_t cap = 512;
        ml->regs = static_cast<MapsRegion*>(std::calloc(cap, sizeof(MapsRegion)));
        if (!ml->regs) { std::fclose(f); delete ml; return nullptr; }

        char line[1024];
        while (std::fgets(line, sizeof(line), f)) {
            if (ml->count == cap) {
                cap *= 2;
                auto* nr = static_cast<MapsRegion*>(
                    std::realloc(ml->regs, cap * sizeof(MapsRegion)));
                if (!nr) break;
                ml->regs = nr;
                std::memset(ml->regs + ml->count, 0,
                            (cap - ml->count) * sizeof(MapsRegion));
            }
            MapsRegion* r = &ml->regs[ml->count];
            std::memset(r, 0, sizeof(*r));

            unsigned long dmaj = 0, dmin = 0, off_val = 0, ino = 0;
            int n = std::sscanf(line, "%lx-%lx %7s %lx %lx:%lx %lu",
                                &r->start, &r->end, r->perms,
                                &off_val, &dmaj, &dmin, &ino);
            if (n < 7) {
                if (std::sscanf(line, "%lx-%lx %7s",
                                &r->start, &r->end, r->perms) < 3)
                    continue;
                off_val = 0; dmaj = 0; dmin = 0; ino = 0;
            }
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
                std::snprintf(r->path, sizeof(r->path), "%.*s",
                              static_cast<int>(plen), p);
            }
            ml->count++;
        }
        std::fclose(f);
        return ml;
    }
};
