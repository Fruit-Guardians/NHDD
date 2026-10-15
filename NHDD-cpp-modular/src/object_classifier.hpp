// object_classifier.hpp — Group maps regions, classify origin/kind/policy
#pragma once

#include <cstdio>
#include <cstring>
#include <cstdint>
#include "common_types.hpp"
#include "maps_parser.hpp"

class ObjectClassifier {
public:
    static bool is_synthetic_anon_path(const char* path) {
        return path && std::strncmp(path, "anon_", 5) == 0;
    }

    static bool region_belongs_to_object(const MapsRegion* r, const MappedObject* o) {
        if (!r || !o) return false;
        if (o->inode == 0 && is_synthetic_anon_path(o->path)) {
            // Anonymous / inode-zero regions were given a synthetic path by the
            // grouping pass. Match them by the exact region bounds instead of
            // comparing the original empty maps path against "anon_xxx".
            return r->inode == 0 && r->start == o->min_start && r->end == o->max_end;
        }
        return r->inode == o->inode && std::strcmp(r->path, o->path) == 0;
    }

    // Group maps regions by path + inode into MappedObject array
    // Returns number of objects found (capped at max_objs)
    static int group_by_path_inode(const MapsParser::RegionList* ml,
                                    MappedObject* objs, int max_objs) {
        int count = 0;
        for (size_t i = 0; i < ml->count && count < max_objs; i++) {
            const MapsRegion* r = &ml->regs[i];

            if (r->path[0] == '\0' || r->inode == 0) {
                // Anonymous: each region is its own object
                MappedObject* o = &objs[count];
                std::memset(o, 0, sizeof(*o));
                std::snprintf(o->path, sizeof(o->path), "anon_%lx",
                              static_cast<unsigned long>(r->start));
                std::snprintf(o->name, sizeof(o->name), "anon_%lx.so",
                              static_cast<unsigned long>(r->start));
                o->inode = 0;
                o->base_addr = r->start - r->offset;
                o->min_start = r->start;
                o->max_end = r->end;
                o->min_offset = r->offset;
                o->file_size = r->offset + (r->end - r->start);
                o->region_count = 1;
                if (r->readable) o->has_r = true;
                if (r->writable) o->has_w = true;
                if (r->executable) o->has_x = true;
                count++;
                continue;
            }

            // Group by path + inode
            bool found = false;
            for (int j = 0; j < count; j++) {
                if (objs[j].inode == r->inode &&
                    std::strcmp(objs[j].path, r->path) == 0) {
                    if (r->start < objs[j].min_start) objs[j].min_start = r->start;
                    if (r->end > objs[j].max_end) objs[j].max_end = r->end;
                    if (r->offset < objs[j].min_offset) objs[j].min_offset = r->offset;
                    uint64_t seg_end = r->offset + (r->end - r->start);
                    if (seg_end > objs[j].file_size) objs[j].file_size = seg_end;
                    objs[j].region_count++;
                    if (r->readable) objs[j].has_r = true;
                    if (r->writable) objs[j].has_w = true;
                    if (r->executable) objs[j].has_x = true;
                    uintptr_t base = r->start - r->offset;
                    if (base < objs[j].base_addr || objs[j].region_count == 1)
                        objs[j].base_addr = base;
                    found = true;
                    break;
                }
            }
            if (!found) {
                MappedObject* o = &objs[count];
                std::memset(o, 0, sizeof(*o));
                std::snprintf(o->path, sizeof(o->path), "%s", r->path);
                const char* bn = std::strrchr(r->path, '/');
                std::snprintf(o->name, sizeof(o->name), "%s",
                              bn ? bn + 1 : r->path);
                o->inode = r->inode;
                o->base_addr = r->start - r->offset;
                o->min_start = r->start;
                o->max_end = r->end;
                o->min_offset = r->offset;
                o->file_size = r->offset + (r->end - r->start);
                o->region_count = 1;
                if (r->readable) o->has_r = true;
                if (r->writable) o->has_w = true;
                if (r->executable) o->has_x = true;
                count++;
            }
        }
        return count;
    }

    // Classify object origin by path
    static ObjectOrigin classify_origin(const char* path, const char* pkg) {
        if (!path || path[0] == '\0') return ORIGIN_APP_ANON;
        if (is_synthetic_anon_path(path)) return ORIGIN_APP_ANON;
        if (std::strstr(path, "[vdso]")) return ORIGIN_SPECIAL;
        if (std::strstr(path, "memfd")) return ORIGIN_SPECIAL;
        if (std::strstr(path, "/data/app/") && std::strstr(path, pkg))
            return ORIGIN_APP_APK;
        if ((std::strstr(path, "/data/data/") ||
             std::strstr(path, "/data/user/0/")) && std::strstr(path, pkg))
            return ORIGIN_APP_DATA;
        if (std::strstr(path, "/apex/")) return ORIGIN_APEX;
        if (std::strstr(path, "/vendor/") || std::strstr(path, "/odm/"))
            return ORIGIN_VENDOR;
        if (std::strstr(path, "/system/") || std::strstr(path, "/system_ext/") ||
            std::strstr(path, "/product/"))
            return ORIGIN_SYSTEM;
        return ORIGIN_UNKNOWN;
    }

    // Classify object kind from header bytes and path hints
    static ObjectKind classify_kind(const char* path, const uint8_t* head,
                                      size_t head_size) {
        if (!head || head_size < 4) return OBJ_UNKNOWN;

        if (path && std::strstr(path, "[vdso]")) return OBJ_VDSO;
        if (path && std::strstr(path, "memfd")) return OBJ_MEMFD;
        if (path && std::strstr(path, ".odex")) return OBJ_ODEX;
        if (path && std::strstr(path, ".oat")) return OBJ_OAT;
        if (path && (std::strstr(path, "linker64") || std::strstr(path, "linker")))
            return OBJ_LINKER;

        if (std::memcmp(head, "\x7f""ELF", 4) == 0) {
            if (head_size < 18) return OBJ_ELF_SO;
            uint16_t e_type = head[16] | (head[17] << 8);
            if (e_type == 3) return OBJ_ELF_SO;
            if (e_type == 2 || e_type == 1) return OBJ_ELF_EXEC;
            return OBJ_ELF_SO;
        }
        if (std::memcmp(head, "dex\n", 4) == 0) return OBJ_DEX;
        if (std::memcmp(head, "oat\n", 4) == 0) return OBJ_OAT;
        if (std::memcmp(head, "PK\x03\x04", 4) == 0) return OBJ_APK_ZIP;
        return OBJ_UNKNOWN;
    }

    // Decide dump/repair policy for a MappedObject
    static DumpPolicy decide_policy(const MappedObject* o) {
        // Skip non-SO types
        if (o->kind == OBJ_OAT || o->kind == OBJ_ODEX ||
            o->kind == OBJ_APK_ZIP || o->kind == OBJ_VDSO ||
            o->kind == OBJ_MEMFD || o->kind == OBJ_DEX ||
            o->kind == OBJ_ELF_EXEC || o->kind == OBJ_LINKER)
            return POLICY_SKIP;
        // Skip system/vendor/apex
        if (o->origin == ORIGIN_SYSTEM || o->origin == ORIGIN_APEX ||
            o->origin == ORIGIN_VENDOR || o->origin == ORIGIN_RUNTIME ||
            o->origin == ORIGIN_WEBVIEW || o->origin == ORIGIN_SPECIAL)
            return POLICY_SKIP;
        // Dump app-related SOs
        if (o->kind == OBJ_ELF_SO && o->origin != ORIGIN_UNKNOWN)
            return POLICY_DUMP_AND_FIX;
        // Unknown anonymous ELF SO (shell-loaded code)
        if (o->kind == OBJ_ELF_SO && o->origin == ORIGIN_UNKNOWN && o->has_x)
            return POLICY_DUMP_MERGE;
        return POLICY_SKIP;
    }

    // Classify all objects in an array
    static void classify_all(MappedObject* objs, int count,
                              const char* pkg) {
        for (int i = 0; i < count; i++) {
            // Classify by path alone first (origin is path-based)
            objs[i].origin = classify_origin(objs[i].path, pkg);
            // Kind will be set later after reading headers
        }
    }

    // Inline version: works with raw MapsRegion array
    static int group_by_path_inline(const MapsRegion* regs, size_t reg_count,
                                     MappedObject* objs, int max_objs) {
        int count = 0;
        for (size_t i = 0; i < reg_count && count < max_objs; i++) {
            const MapsRegion* r = &regs[i];
            if (r->path[0] == '\0' || r->inode == 0) {
                MappedObject* o = &objs[count];
                std::memset(o, 0, sizeof(*o));
                std::snprintf(o->path, sizeof(o->path), "anon_%lx",
                              static_cast<unsigned long>(r->start));
                std::snprintf(o->name, sizeof(o->name), "anon_%lx.so",
                              static_cast<unsigned long>(r->start));
                o->inode = 0;
                o->base_addr = r->start - r->offset;
                o->min_start = r->start;
                o->max_end = r->end;
                o->min_offset = r->offset;
                o->file_size = r->offset + (r->end - r->start);
                o->region_count = 1;
                if (r->readable) o->has_r = true;
                if (r->writable) o->has_w = true;
                if (r->executable) o->has_x = true;
                count++;
                continue;
            }
            int found = 0;
            for (int j = 0; j < count; j++) {
                if (objs[j].inode == r->inode &&
                    std::strcmp(objs[j].path, r->path) == 0) {
                    if (r->start < objs[j].min_start) objs[j].min_start = r->start;
                    if (r->end > objs[j].max_end) objs[j].max_end = r->end;
                    if (r->offset < objs[j].min_offset) objs[j].min_offset = r->offset;
                    uint64_t seg_end = r->offset + (r->end - r->start);
                    if (seg_end > objs[j].file_size) objs[j].file_size = seg_end;
                    objs[j].region_count++;
                    if (r->readable) objs[j].has_r = true;
                    if (r->writable) objs[j].has_w = true;
                    if (r->executable) objs[j].has_x = true;
                    uintptr_t base = r->start - r->offset;
                    if (base < objs[j].base_addr || objs[j].region_count == 1)
                        objs[j].base_addr = base;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                MappedObject* o = &objs[count];
                std::memset(o, 0, sizeof(*o));
                std::snprintf(o->path, sizeof(o->path), "%s", r->path);
                const char* bn = std::strrchr(r->path, '/');
                std::snprintf(o->name, sizeof(o->name), "%s",
                              bn ? bn + 1 : r->path);
                o->inode = r->inode;
                o->base_addr = r->start - r->offset;
                o->min_start = r->start;
                o->max_end = r->end;
                o->min_offset = r->offset;
                o->file_size = r->offset + (r->end - r->start);
                o->region_count = 1;
                if (r->readable) o->has_r = true;
                if (r->writable) o->has_w = true;
                if (r->executable) o->has_x = true;
                count++;
            }
        }
        return count;
    }
};
