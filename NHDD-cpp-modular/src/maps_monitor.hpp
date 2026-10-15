// maps_monitor.hpp — Continuous maps monitoring for dynamic SO loading detection
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "common_types.hpp"
#include "maps_parser.hpp"
#include "nhdd_config.hpp"

class MapsMonitor {
public:
    struct MapsSnapshot {
        time_t timestamp;
        std::unordered_set<std::string> so_paths;  // All SO paths in this snapshot
        std::unordered_map<std::string, uintptr_t> so_bases;  // path -> base_addr
    };

    struct LoadEvent {
        time_t timestamp;
        std::string path;
        std::string name;
        uintptr_t base_addr;
        uint64_t size;
        bool is_new;  // true if newly loaded, false if already existed
    };

    MapsMonitor() : baseline_taken_(false) {}

    // Take initial snapshot of current maps state
    bool take_baseline(const char* pid) {
        baseline_.timestamp = std::time(nullptr);
        baseline_.so_paths.clear();
        baseline_.so_bases.clear();

        MapsRegion* regs = nullptr;
        size_t count = 0;
        if (load_maps(pid, &regs, &count) != 0) {
            return false;
        }

        // Extract all SO paths from maps
        std::unordered_map<std::string, uintptr_t> path_to_min_addr;
        for (size_t i = 0; i < count; i++) {
            const MapsRegion& r = regs[i];
            if (r.path[0] == '\0') continue;
            
            // Check if it's a .so file
            const char* ext = std::strrchr(r.path, '.');
            if (!ext || std::strcmp(ext, ".so") != 0) continue;

            std::string path_key(r.path);
            
            // Calculate base address (min start - offset)
            uintptr_t base = r.start - r.offset;
            
            if (path_to_min_addr.find(path_key) == path_to_min_addr.end()) {
                path_to_min_addr[path_key] = base;
            }
            
            baseline_.so_paths.insert(path_key);
            baseline_.so_bases[path_key] = base;
        }

        std::free(regs);
        baseline_taken_ = true;
        
        std::fprintf(stderr, "[*] MAPS MONITOR: baseline snapshot taken, %zu SO(s) loaded\n",
                     baseline_.so_paths.size());
        
        return true;
    }

    // Check for new SO loads since baseline
    std::vector<LoadEvent> check_new_loads(const char* pid) {
        std::vector<LoadEvent> events;
        
        if (!baseline_taken_) {
            if (!take_baseline(pid)) return events;
        }

        MapsRegion* regs = nullptr;
        size_t count = 0;
        if (load_maps(pid, &regs, &count) != 0) {
            return events;
        }

        time_t now = std::time(nullptr);
        std::unordered_set<std::string> current_paths;
        std::unordered_map<std::string, uintptr_t> current_bases;
        std::unordered_map<std::string, uint64_t> current_sizes;

        // Build current state
        for (size_t i = 0; i < count; i++) {
            const MapsRegion& r = regs[i];
            if (r.path[0] == '\0') continue;

            const char* ext = std::strrchr(r.path, '.');
            if (!ext || std::strcmp(ext, ".so") != 0) continue;

            std::string path_key(r.path);
            uintptr_t base = r.start - r.offset;
            
            current_paths.insert(path_key);
            if (current_bases.find(path_key) == current_bases.end()) {
                current_bases[path_key] = base;
                current_sizes[path_key] = r.end - r.start + r.offset;
            } else {
                // Update size to max
                uint64_t end_offset = r.offset + (r.end - r.start);
                if (end_offset > current_sizes[path_key]) {
                    current_sizes[path_key] = end_offset;
                }
            }
        }

        // Detect newly loaded SOs
        for (const auto& path : current_paths) {
            bool is_new = (baseline_.so_paths.find(path) == baseline_.so_paths.end());
            
            if (is_new) {
                LoadEvent evt;
                evt.timestamp = now;
                evt.path = path;
                evt.base_addr = current_bases[path];
                evt.size = current_sizes[path];
                evt.is_new = true;
                
                // Extract basename
                const char* slash = std::strrchr(path.c_str(), '/');
                evt.name = slash ? (slash + 1) : path;
                
                events.push_back(evt);
                
                // Add to baseline so we don't report it again
                baseline_.so_paths.insert(path);
                baseline_.so_bases[path] = evt.base_addr;
            }
        }

        std::free(regs);
        return events;
    }

    // Write timeline event to JSONL
    static void write_timeline_event(const char* timeline_path, const char* pid,
                                     const LoadEvent& evt, const char* event_type) {
        FILE* f = std::fopen(timeline_path, "a");
        if (!f) return;

        std::fprintf(f, "{\"timestamp\":%lld,\"pid\":\"%s\",\"event\":\"%s\","
                        "\"type\":\"so\",\"name\":\"",
                     static_cast<long long>(evt.timestamp), pid, event_type);
        json_escape(f, evt.name.c_str());
        std::fprintf(f, "\",\"path\":\"");
        json_escape(f, evt.path.c_str());
        std::fprintf(f, "\",\"base\":\"0x%lx\",\"size\":%llu}\n",
                     static_cast<unsigned long>(evt.base_addr),
                     static_cast<unsigned long long>(evt.size));
        std::fclose(f);
    }

    // Reset monitor state
    void reset() {
        baseline_taken_ = false;
        baseline_.so_paths.clear();
        baseline_.so_bases.clear();
    }

private:
    static int load_maps(const char* pid, MapsRegion** out_regs, size_t* out_count) {
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
                auto* nr = static_cast<MapsRegion*>(
                    std::realloc(regs, cap * sizeof(MapsRegion)));
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

            // Parse path
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
                std::snprintf(r->path, sizeof(r->path), "%.*s",
                             static_cast<int>(plen), p);
            }
            count++;
        }
        std::fclose(f);
        *out_regs = regs;
        *out_count = count;
        return 0;
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

    bool baseline_taken_;
    MapsSnapshot baseline_;
};
