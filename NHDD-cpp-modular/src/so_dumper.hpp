// so_dumper.hpp — SO dump, ELF repair, manifest write
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "common_types.hpp"
#include "maps_parser.hpp"
#include "process_memory.hpp"

class SoDumper {
public:
    // Dump a MappedObject by reading from process memory via maps
    static int dump_by_maps(ProcessMemory& pm, MappedObject* obj,
                            const MapsParser::RegionList* ml,
                            const char* out_path) {
        if (obj->file_size > 64 * 1024 * 1024) {
            std::fprintf(stderr, "  [-] SO too large (%llu bytes), skip\n",
                         static_cast<unsigned long long>(obj->file_size));
            return -1;
        }
        if (obj->file_size == 0) return -1;

        auto* buf = static_cast<uint8_t*>(
            std::calloc(1, static_cast<size_t>(obj->file_size)));
        if (!buf) {
            std::fprintf(stderr, "  [-] OOM for SO %s (%llu bytes)\n",
                         obj->name,
                         static_cast<unsigned long long>(obj->file_size));
            return -1;
        }

        // Read each region of this object by offset
        for (size_t i = 0; i < ml->count; i++) {
            const MapsRegion* r = &ml->regs[i];
            if (r->inode != obj->inode ||
                std::strcmp(r->path, obj->path) != 0)
                continue;
            if (!r->readable) continue;

            size_t seg_len = static_cast<size_t>(r->end - r->start);
            // Bounds check: both offset and offset+seg_len must fit within file_size
            if (r->offset >= obj->file_size) continue;
            if (obj->file_size - r->offset < seg_len) continue;

            pm.read(buf + r->offset, seg_len, r->start);
        }

        // Extend dump to cover all PT_LOAD segments from ELF header
        if (obj->file_size >= 0x40 &&
            std::memcmp(buf, "\x7f""ELF", 4) == 0) {
            buf = extend_to_cover_load_segments(buf, obj, pm);
        }

        // Write to file
        FILE* out = std::fopen(out_path, "wb");
        if (!out) { std::free(buf); return -1; }
        size_t written = std::fwrite(buf, 1,
                                      static_cast<size_t>(obj->file_size), out);
        std::fclose(out);
        std::free(buf);

        if (written != static_cast<size_t>(obj->file_size)) {
            std::fprintf(stderr, "  [!] Partial write for %s (%zu/%llu)\n",
                         obj->name, written,
                         static_cast<unsigned long long>(obj->file_size));
        }
        return (written > 0) ? 0 : -1;
    }

    // Built-in ELF repair: fix e_type, e_machine, p_offset=p_vaddr, rebuild SHT
    static int repair_basic(const char* path) {
        FILE* f = std::fopen(path, "r+b");
        if (!f) return -1;
        std::fseek(f, 0, SEEK_END);
        long fsize = std::ftell(f);
        if (fsize < 0x40) { std::fclose(f); return -1; }

        auto* data = static_cast<uint8_t*>(
            std::malloc(static_cast<size_t>(fsize) + 32768));
        if (!data) { std::fclose(f); return -1; }
        std::fseek(f, 0, SEEK_SET);
        std::fread(data, 1, static_cast<size_t>(fsize), f);
        std::fclose(f);

        // Must have ELF magic
        if (std::memcmp(data, "\x7f""ELF", 4) != 0) {
            std::memcpy(data, "\x7f""ELF", 4);
        }

        // Fix e_ident
        bool is64 = (data[4] == 2);
        if (data[4] != 1 && data[4] != 2) {
            is64 = true;
            data[4] = 2;
        }
        data[5] = 1; // EI_DATA = little-endian
        data[6] = 1; // EI_VERSION = 1

        // Fix e_type to ET_DYN
        if (is64) {
            uint16_t e_type;
            std::memcpy(&e_type, data + 16, 2);
            if (e_type != 3) { e_type = 3; std::memcpy(data + 16, &e_type, 2); }
            uint16_t e_mach;
            std::memcpy(&e_mach, data + 18, 2);
            if (e_mach != 183 && e_mach != 40) {
                e_mach = 183; std::memcpy(data + 18, &e_mach, 2);
            }
        } else {
            uint16_t e_type;
            std::memcpy(&e_type, data + 16, 2);
            if (e_type != 3) { e_type = 3; std::memcpy(data + 16, &e_type, 2); }
            uint16_t e_mach;
            std::memcpy(&e_mach, data + 18, 2);
            if (e_mach != 183 && e_mach != 40) {
                e_mach = 40; std::memcpy(data + 18, &e_mach, 2);
            }
        }

        // Parse PHT
        uint64_t e_phoff;
        uint16_t e_phentsize, e_phnum;
        if (is64) {
            std::memcpy(&e_phoff, data + 32, 8);
            std::memcpy(&e_phentsize, data + 54, 2);
            std::memcpy(&e_phnum, data + 56, 2);
        } else {
            uint32_t phoff32;
            std::memcpy(&phoff32, data + 28, 4);
            e_phoff = phoff32;
            std::memcpy(&e_phentsize, data + 42, 2);
            std::memcpy(&e_phnum, data + 44, 2);
        }

        if (e_phnum == 0 || e_phentsize == 0 ||
            e_phoff + static_cast<uint64_t>(e_phnum) * e_phentsize >
            static_cast<uint64_t>(fsize)) {
            goto save_and_exit;
        }

        // Fix p_offset = p_vaddr, track PT_DYNAMIC
        {
            uint64_t dyn_vaddr = 0, dyn_filesz = 0;
            for (uint16_t i = 0; i < e_phnum; i++) {
                uint64_t base = e_phoff + static_cast<uint64_t>(i) * e_phentsize;
                uint32_t p_type;
                std::memcpy(&p_type, data + base, 4);
                uint64_t p_offset, p_vaddr, p_filesz, p_memsz;
                if (is64) {
                    std::memcpy(&p_offset, data + base + 8, 8);
                    std::memcpy(&p_vaddr,  data + base + 16, 8);
                    std::memcpy(&p_filesz, data + base + 32, 8);
                    std::memcpy(&p_memsz,  data + base + 40, 8);
                } else {
                    uint32_t tmp;
                    std::memcpy(&tmp, data + base + 4, 4); p_offset = tmp;
                    std::memcpy(&tmp, data + base + 8, 4); p_vaddr = tmp;
                    std::memcpy(&tmp, data + base + 16, 4); p_filesz = tmp;
                    std::memcpy(&tmp, data + base + 20, 4); p_memsz = tmp;
                }
                if (p_type == 1 || p_type == 2) {
                    if (p_offset != p_vaddr) {
                        if (is64) std::memcpy(data + base + 8, &p_vaddr, 8);
                        else {
                            uint32_t v32 = static_cast<uint32_t>(p_vaddr);
                            std::memcpy(data + base + 4, &v32, 4);
                        }
                    }
                    if (p_type == 1 && p_filesz < p_memsz) {
                        if (is64) std::memcpy(data + base + 32, &p_memsz, 8);
                        else {
                            uint32_t m32 = static_cast<uint32_t>(p_memsz);
                            std::memcpy(data + base + 16, &m32, 4);
                        }
                    }
                    if (p_type == 2) { dyn_vaddr = p_vaddr; dyn_filesz = p_filesz; }
                }
            }

            // Rebuild SHT
            long new_fsize = rebuild_sht(data, fsize, is64, dyn_vaddr, dyn_filesz);
            if (new_fsize > 0) fsize = new_fsize;
        }

    save_and_exit:
        f = std::fopen(path, "wb");
        if (!f) { std::free(data); return -1; }
        std::fwrite(data, 1, static_cast<size_t>(fsize), f);
        std::fclose(f);
        std::free(data);
        return (fsize > 0) ? 0 : -1;
    }

    // Write manifest JSON for dumped SO objects
    static void write_manifest(const char* so_dir, const MappedObject* objs,
                                int count, int dumped, int skipped_system,
                                int skipped_other) {
        char path[512];
        std::snprintf(path, sizeof(path), "%s/manifest.json", so_dir);
        FILE* f = std::fopen(path, "w");
        if (!f) return;

        std::fprintf(f, "{\n  \"total_objects\": %d,\n  \"so_dumped\": %d,\n",
                     count, dumped);
        std::fprintf(f, "  \"skipped_system\": %d,\n  \"skipped_other\": %d,\n",
                     skipped_system, skipped_other);
        std::fprintf(f, "  \"objects\": [\n");

        int first = 1;
        for (int i = 0; i < count; i++) {
            const MappedObject* o = &objs[i];
            const char* kind_str = "unknown";
            switch (o->kind) {
                case OBJ_ELF_SO: kind_str = "elf_so"; break;
                case OBJ_ELF_EXEC: kind_str = "elf_exec"; break;
                case OBJ_DEX: kind_str = "dex"; break;
                case OBJ_OAT: kind_str = "oat"; break;
                case OBJ_ODEX: kind_str = "odex"; break;
                case OBJ_APK_ZIP: kind_str = "apk_zip"; break;
                case OBJ_VDSO: kind_str = "vdso"; break;
                case OBJ_MEMFD: kind_str = "memfd"; break;
                default: break;
            }

            if (!first) std::fprintf(f, ",\n");
            std::fprintf(f,
                "    {\"path\":\"%s\",\"name\":\"%s\",\"kind\":\"%s\","
                "\"origin\":%d,\"policy\":%d,\"size\":%llu}",
                o->path, o->name, kind_str, static_cast<int>(o->origin),
                static_cast<int>(o->policy),
                static_cast<unsigned long long>(o->file_size));
            first = 0;
        }
        std::fprintf(f, "\n  ]\n}\n");
        std::fclose(f);
    }

private:
    static uint8_t* extend_to_cover_load_segments(uint8_t* buf, MappedObject* obj,
                                               ProcessMemory& pm) {
        bool is64 = (buf[4] == 2);
        uint64_t e_phoff;
        uint16_t e_phentsize, e_phnum;
        if (is64) {
            std::memcpy(&e_phoff, buf + 32, 8);
            std::memcpy(&e_phentsize, buf + 54, 2);
            std::memcpy(&e_phnum, buf + 56, 2);
        } else {
            uint32_t tmp;
            std::memcpy(&tmp, buf + 28, 4); e_phoff = tmp;
            std::memcpy(&e_phentsize, buf + 42, 2);
            std::memcpy(&e_phnum, buf + 44, 2);
        }

        if (e_phoff <= 0 || e_phentsize <= 0 || e_phnum >= 64 ||
            e_phoff + static_cast<uint64_t>(e_phnum) * e_phentsize >
            obj->file_size)
            return buf;

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
                uint32_t tmp;
                std::memcpy(&tmp, buf + base + 8, 4); p_vaddr = tmp;
                std::memcpy(&tmp, buf + base + 20, 4); p_memsz = tmp;
            }
            if (p_type == 1 && p_vaddr + p_memsz > needed)
                needed = p_vaddr + p_memsz;
        }

        if (needed > obj->file_size && needed <= 64 * 1024 * 1024) {
            auto* nbuf = static_cast<uint8_t*>(
                std::realloc(buf, static_cast<size_t>(needed)));
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
                        uint32_t tmp;
                        std::memcpy(&tmp, buf + base + 4, 4); p_offset = tmp;
                        std::memcpy(&tmp, buf + base + 16, 4); p_filesz = tmp;
                    }
                    if (p_offset + p_filesz > obj->file_size &&
                        p_offset < needed) {
                        size_t to_read = static_cast<size_t>(needed - p_offset);
                        if (to_read > static_cast<size_t>(p_filesz))
                            to_read = static_cast<size_t>(p_filesz);
                        if (p_offset < obj->file_size)
                            to_read -= static_cast<size_t>(
                                obj->file_size - p_offset);
                        pm.read(buf + p_offset, to_read,
                                static_cast<uintptr_t>(obj->base_addr + p_offset));
                    }
                }
                obj->file_size = needed;
            }
        }
        return buf;
    }

    static long rebuild_sht(uint8_t* data, long fsize, bool is64,
                             uint64_t dyn_vaddr, uint64_t dyn_filesz) {
        uint64_t dt_symtab = 0, dt_strtab = 0, dt_strsz = 0;
        uint64_t dt_hash = 0, dt_nbucket = 0, dt_nchain = 0;
        uint64_t entsize = is64 ? 16 : 8;

        // Parse DT_* tags
        if (dyn_vaddr > 0 && dyn_vaddr + entsize <= static_cast<uint64_t>(fsize)) {
            uint64_t di = dyn_vaddr;
            for (int cnt = 0; cnt < 256 && di + entsize <= static_cast<uint64_t>(fsize); cnt++) {
                uint64_t d_tag, d_val;
                if (is64) {
                    std::memcpy(&d_tag, data + di, 8);
                    std::memcpy(&d_val, data + di + 8, 8);
                } else {
                    uint32_t t32, v32;
                    std::memcpy(&t32, data + di, 4); d_tag = t32;
                    std::memcpy(&v32, data + di + 4, 4); d_val = v32;
                }
                if (d_tag == 0) break;
                switch (static_cast<uint32_t>(d_tag)) {
                    case 5:  dt_strtab = d_val; break;
                    case 6:  dt_symtab = d_val; break;
                    case 4:  dt_hash = d_val; break;
                    case 10: dt_strsz = d_val; break;
                }
                di += entsize;
            }
        }

        if (dt_hash > 0 && dt_hash + 8 <= static_cast<uint64_t>(fsize)) {
            std::memcpy(&dt_nbucket, data + dt_hash, 4);
            std::memcpy(&dt_nchain, data + dt_hash + 4, 4);
        }

        // Build section header table at end of file
        uint32_t shoff = static_cast<uint32_t>(fsize);
        uint8_t* out = data + shoff;
        uint32_t out_off = 0;

        // shstrtab
        uint32_t shstrtab_off = out_off;
        static const char shstrtab[] =
            "\0.shstrtab\0.dynsym\0.dynstr\0.hash\0.dynamic\0";
        uint32_t shstrtab_len = sizeof(shstrtab);
        std::memcpy(out + out_off, shstrtab, shstrtab_len);
        out_off += shstrtab_len;

        const uint32_t SHN_SHSTRTAB =  1;
        const uint32_t SHN_DYNSYM   = 11;
        const uint32_t SHN_DYNSTR   = 19;
        const uint32_t SHN_HASH     = 27;
        const uint32_t SHN_DYNAMIC  = 33;

        uint16_t sh_count = 1;
        uint16_t sh_dynsym = sh_count++;
        uint16_t sh_dynstr = sh_count++;
        uint16_t sh_dynamic = sh_count++;
        uint16_t sh_hash = 0;
        if (dt_hash) { sh_hash = sh_count++; }
        uint16_t sh_shstrtab = sh_count++;

        uint32_t shentsize = is64 ? 64 : 40;
        uint32_t sht_off = out_off;
        uint32_t sht_size = sh_count * shentsize;
        std::memset(out + out_off, 0, sht_size);
        out_off += sht_size;

        // Helper macros
#define SHDR32(s, off_val, v) do { uint32_t _v = static_cast<uint32_t>(v); std::memcpy((s)+(off_val), &_v, 4); } while(0)
#define SHDR64(s, off_val, v) do { uint64_t _v = static_cast<uint64_t>(v); std::memcpy((s)+(off_val), &_v, 8); } while(0)
#define SHDR(idx, name_off, type, flags, addr, off, size, link, info, align, esize) do { \
            uint8_t* s = out + sht_off + (idx) * shentsize; \
            SHDR32(s, 0, name_off); SHDR32(s, 4, type); \
            if (is64) { SHDR64(s, 8, flags); SHDR64(s, 16, addr); SHDR64(s, 24, off); \
                        SHDR64(s, 32, size); SHDR32(s, 40, link); SHDR32(s, 44, info); \
                        SHDR64(s, 48, align); SHDR64(s, 56, esize); } \
            else { SHDR32(s, 8, flags); SHDR32(s, 12, addr); SHDR32(s, 16, off); \
                   SHDR32(s, 20, size); SHDR32(s, 24, link); SHDR32(s, 28, info); \
                   SHDR32(s, 32, align); SHDR32(s, 36, esize); } \
        } while(0)

        SHDR(sh_dynsym, SHN_DYNSYM, 11/*SHT_DYNSYM*/, 2/*SHF_ALLOC*/,
             dt_symtab ? dt_symtab : dyn_vaddr,
             dt_symtab ? dt_symtab : dyn_vaddr,
             0, sh_dynstr, 1, is64 ? 8 : 4, is64 ? 24 : 16);
        SHDR(sh_dynstr, SHN_DYNSTR, 3/*SHT_STRTAB*/, 2,
             dt_strtab ? dt_strtab : dyn_vaddr,
             dt_strtab ? dt_strtab : dyn_vaddr,
             dt_strsz ? dt_strsz : 1, 0, 0, 1, 0);
        if (sh_hash) SHDR(sh_hash, SHN_HASH, 5/*SHT_HASH*/, 2,
                          dt_hash, dt_hash,
                          (dt_nbucket + dt_nchain) * 4 + 8,
                          sh_dynsym, 0, 4, 4);
        SHDR(sh_dynamic, SHN_DYNAMIC, 6/*SHT_DYNAMIC*/, 3/*SHF_ALLOC|SHF_WRITE*/,
             dyn_vaddr, dyn_vaddr, dyn_filesz, sh_dynstr, 0,
             is64 ? 8 : 4, entsize);
        SHDR(sh_shstrtab, SHN_SHSTRTAB, 3/*SHT_STRTAB*/, 0, 0,
             shoff + shstrtab_off, shstrtab_len, 0, 0, 1, 0);

        // Fix dynsym .sh_link to point to .dynstr
        if (sh_dynsym) {
            uint32_t link = sh_dynstr;
            std::memcpy(out + sht_off + sh_dynsym * shentsize +
                        (is64 ? 40 : 24), &link, 4);
        }

        // Fix .dynsym .sh_size
        if (sh_dynsym && sh_dynstr && sh_count > 0) {
            uint64_t ds_addr = 0, dn_addr = 0;
            if (is64) {
                std::memcpy(&ds_addr, out + sht_off + sh_dynsym * 64 + 16, 8);
                std::memcpy(&dn_addr, out + sht_off + sh_dynstr * 64 + 16, 8);
            } else {
                uint32_t t;
                std::memcpy(&t, out + sht_off + sh_dynsym * 40 + 12, 4); ds_addr = t;
                std::memcpy(&t, out + sht_off + sh_dynstr * 40 + 12, 4); dn_addr = t;
            }
            if (dn_addr > ds_addr) {
                uint64_t sz = dn_addr - ds_addr;
                if (is64) std::memcpy(out + sht_off + sh_dynsym * 64 + 32, &sz, 8);
                else { uint32_t s32 = static_cast<uint32_t>(sz);
                       std::memcpy(out + sht_off + sh_dynsym * 40 + 20, &s32, 4); }
            }
        }

        // Update ELF header
        if (is64) {
            uint64_t sho = shoff + sht_off;
            std::memcpy(data + 0x28, &sho, 8);
            std::memcpy(data + 0x3C, &sh_count, 2);
            std::memcpy(data + 0x3E, &sh_shstrtab, 2);
        } else {
            uint32_t sho = shoff + sht_off;
            std::memcpy(data + 0x20, &sho, 4);
            std::memcpy(data + 0x30, &sh_count, 2);
            std::memcpy(data + 0x32, &sh_shstrtab, 2);
        }

        return static_cast<long>(shoff + out_off);

#undef SHDR32
#undef SHDR64
#undef SHDR
    }
};
