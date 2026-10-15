// dex_validator.hpp — DEX format validation, size recovery, checksum repair
#pragma once

#include <cstdint>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include "common_types.hpp"
#include "sha1.hpp"

class DexValidator {
public:
    // Get map item size in bytes for a given DEX section type
    static uint32_t map_item_size(uint16_t type) {
        switch (type) {
            case 0x0000: return 0x70;     // header_item
            case 0x0001: return 4;        // string_id_item
            case 0x0002: return 4;        // type_id_item
            case 0x0003: return 12;       // proto_id_item
            case 0x0004: return 8;        // field_id_item
            case 0x0005: return 8;        // method_id_item
            case 0x0006: return 32;       // class_def_item
            case 0x0007: return 4;        // call_site_id_item
            case 0x0008: return 8;        // method_handle_item
            case kDexTypeMapList: return 0;
            default: return 0;
        }
    }

    // Provisional extent from data section (data_off + data_size)
    static uint32_t recover_size_provisional(const uint8_t* hdr) {
        uint32_t data_size = 0, data_off = 0;
        std::memcpy(&data_size, hdr + 0x68, 4);
        std::memcpy(&data_off,  hdr + 0x6C, 4);
        if (data_off == 0 || data_size == 0) return 0;
        uint64_t end = static_cast<uint64_t>(data_off) + static_cast<uint64_t>(data_size);
        if (end < 0x70 || end > 0x10000000) return 0;
        return static_cast<uint32_t>(end);
    }

    // Recover real DEX file_size by walking map_list in memory buffer
    static uint32_t recover_size_from_map_buf(const uint8_t* img, size_t cap,
                                               uint32_t map_off) {
        if (map_off < 0x70 || map_off + 4 > cap) return 0;
        uint32_t count = 0;
        std::memcpy(&count, img + map_off, 4);
        if (count == 0 || count > 50) return 0;
        uint32_t map_end = map_off + 4 + count * 12;
        if (map_end > cap) return 0;

        uint32_t extent = 0;
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t* ent = img + map_off + 4 + i * 12;
            uint16_t type = 0;
            uint32_t ecount = 0, eoff = 0;
            std::memcpy(&type, ent, 2);
            std::memcpy(&ecount, ent + 4, 4);
            std::memcpy(&eoff, ent + 8, 4);
            uint32_t isz = map_item_size(type);
            if (isz == 0) continue;
            if (eoff == 0) continue;
            uint64_t end = static_cast<uint64_t>(eoff) + static_cast<uint64_t>(ecount) * isz;
            if (end > extent && end <= 0x10000000) extent = static_cast<uint32_t>(end);
        }
        if (map_end > extent) extent = map_end;
        if (extent < 0x70 || extent > 0x10000000) return 0;
        return extent;
    }

    // FRIDA-DEXDump-style confirmation: map_list self-reference
    static bool confirm_by_map_list(const uint8_t* img, size_t cap,
                                     uint32_t map_off, uint32_t string_ids_off) {
        if (string_ids_off != 0x70) return false;
        if (map_off < 0x70 || map_off + 4 > cap) return false;
        uint32_t count = 0;
        std::memcpy(&count, img + map_off, 4);
        if (count == 0 || count > 50) return false;
        if (map_off + 4 + static_cast<size_t>(count) * 12 > cap) return false;
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t* ent = img + map_off + 4 + i * 12;
            uint16_t type = 0;
            uint32_t eoff = 0;
            std::memcpy(&type, ent, 2);
            std::memcpy(&eoff, ent + 8, 4);
            if (type == kDexTypeMapList && eoff == map_off) return true;
        }
        return false;
    }

    // Validate a standard DEX hit from page buffer
    // Returns true if looks valid, sets out_size (0 = deferred recovery needed)
    static bool hit_valid(const uint8_t* buf, size_t n, size_t magic_off,
                           uint32_t* out_size) {
        size_t v = magic_off + 4;
        if (v >= n) return false;
        if (!std::isdigit(static_cast<unsigned char>(buf[v]))) return false;

        uint32_t dex_size = 0;
        if (magic_off + 0x24 <= n) {
            std::memcpy(&dex_size, buf + magic_off + 0x20, 4);
        } else {
            *out_size = 0;
            return true;  // header crosses page, caller re-reads
        }

        uint32_t header_size = 0, string_ids_off = 0, class_defs_off = 0;
        std::memcpy(&header_size, buf + magic_off + 0x24, 4);
        std::memcpy(&string_ids_off, buf + magic_off + 0x3c, 4);
        std::memcpy(&class_defs_off, buf + magic_off + 0x64, 4);
        if (header_size != 0x70) return false;

        if (dex_size == 0 || dex_size < 0x70 || dex_size > 0x10000000) {
            *out_size = 0;
            return true;  // file_size erased, deferred recovery
        }
        if (string_ids_off >= dex_size) return false;
        if (class_defs_off >= dex_size) return false;

        *out_size = dex_size;
        return true;
    }

    // Strong structural validation by checking all section table ranges.
    // DEX header layout:
    //   0x38 string_ids_size, 0x3C string_ids_off,
    //   0x40 type_ids_size,   0x44 type_ids_off,
    //   0x48 proto_ids_size,  0x4C proto_ids_off,
    //   0x50 field_ids_size,  0x54 field_ids_off,
    //   0x58 method_ids_size, 0x5C method_ids_off,
    //   0x60 class_defs_size, 0x64 class_defs_off,
    //   0x68 data_size,       0x6C data_off.
    // The previous C++ refactor accidentally read from 0x3C as (off,size)
    // pairs, which treated data_size as class_defs_size and caused many real
    // DEX images to be rejected.
    static bool header_strong_valid(const uint8_t* hdr, uint32_t file_size) {
        if (!hdr || file_size < 0x70 || file_size > 0x10000000) return false;

        uint32_t header_size = 0, endian_tag = 0;
        std::memcpy(&header_size, hdr + 0x24, 4);
        std::memcpy(&endian_tag,  hdr + 0x28, 4);
        if (header_size != 0x70) return false;
        if (endian_tag != kDexEndianTag) return false;

        uint32_t string_ids_size=0, string_ids_off=0;
        uint32_t type_ids_size=0,   type_ids_off=0;
        uint32_t proto_ids_size=0,  proto_ids_off=0;
        uint32_t field_ids_size=0,  field_ids_off=0;
        uint32_t method_ids_size=0, method_ids_off=0;
        uint32_t class_defs_size=0, class_defs_off=0;
        uint32_t data_size=0,       data_off=0;

        std::memcpy(&string_ids_size, hdr + 0x38, 4);
        std::memcpy(&string_ids_off,  hdr + 0x3C, 4);
        std::memcpy(&type_ids_size,   hdr + 0x40, 4);
        std::memcpy(&type_ids_off,    hdr + 0x44, 4);
        std::memcpy(&proto_ids_size,  hdr + 0x48, 4);
        std::memcpy(&proto_ids_off,   hdr + 0x4C, 4);
        std::memcpy(&field_ids_size,  hdr + 0x50, 4);
        std::memcpy(&field_ids_off,   hdr + 0x54, 4);
        std::memcpy(&method_ids_size, hdr + 0x58, 4);
        std::memcpy(&method_ids_off,  hdr + 0x5C, 4);
        std::memcpy(&class_defs_size, hdr + 0x60, 4);
        std::memcpy(&class_defs_off,  hdr + 0x64, 4);
        std::memcpy(&data_size,       hdr + 0x68, 4);
        std::memcpy(&data_off,        hdr + 0x6C, 4);

        auto range_ok = [file_size](uint32_t count, uint32_t off, uint32_t item_size) -> bool {
            // Match the old C scanner's permissive behavior: zero-sized optional
            // sections should not kill a candidate just because the corresponding
            // off field is noisy in memory.
            if (count == 0) return true;
            if (off >= file_size) return false;
            uint64_t end = static_cast<uint64_t>(off) +
                           static_cast<uint64_t>(count) * item_size;
            return end <= file_size;
        };

        if (!range_ok(string_ids_size, string_ids_off, 4)) return false;
        if (!range_ok(type_ids_size,   type_ids_off,   4)) return false;
        if (!range_ok(proto_ids_size,  proto_ids_off,  12)) return false;
        if (!range_ok(field_ids_size,  field_ids_off,  8)) return false;
        if (!range_ok(method_ids_size, method_ids_off, 8)) return false;
        if (!range_ok(class_defs_size, class_defs_off, 32)) return false;
        if (data_size != 0) {
            if (data_off < 0x70 || data_off >= file_size) return false;
            if (static_cast<uint64_t>(data_off) + data_size > file_size) return false;
        } else if (data_off != 0) {
            return false;
        }

        return true;
    }

    // Relaxed validation: no magic required, structural checks only
    static bool header_relaxed_valid(const uint8_t* hdr, size_t hdr_len,
                                      uint32_t* out_size) {
        if (hdr_len < 0x70) return false;

        uint32_t endian_tag = 0;
        std::memcpy(&endian_tag, hdr + 0x28, 4);
        if (endian_tag != kDexEndianTag) return false;

        uint32_t header_size = 0;
        std::memcpy(&header_size, hdr + 0x24, 4);
        if (header_size != 0x70) return false;

        uint32_t file_size = 0;
        std::memcpy(&file_size, hdr + 0x20, 4);
        if (file_size != 0 && (file_size < 0x70 || file_size > 0x10000000))
            return false;
        uint32_t size_cap = (file_size != 0) ? file_size : 0x10000000;

        uint32_t string_ids_size=0, string_ids_off=0;
        uint32_t type_ids_size=0,   type_ids_off=0;
        uint32_t class_defs_size=0, class_defs_off=0;
        uint32_t data_size = 0, data_off = 0;
        std::memcpy(&string_ids_size, hdr + 0x38, 4);
        std::memcpy(&string_ids_off,  hdr + 0x3C, 4);
        std::memcpy(&type_ids_size,   hdr + 0x40, 4);
        std::memcpy(&type_ids_off,    hdr + 0x44, 4);
        std::memcpy(&class_defs_size, hdr + 0x60, 4);
        std::memcpy(&class_defs_off,  hdr + 0x64, 4);
        std::memcpy(&data_size,       hdr + 0x68, 4);
        std::memcpy(&data_off,        hdr + 0x6C, 4);

        if (string_ids_size == 0 || type_ids_size == 0 || class_defs_size == 0)
            return false;
        if (string_ids_off < 0x70 || string_ids_off >= size_cap) return false;
        if (type_ids_off   < 0x70 || type_ids_off   >= size_cap) return false;
        if (class_defs_off < 0x70 || class_defs_off >= size_cap) return false;
        uint64_t class_defs_end = static_cast<uint64_t>(class_defs_off) +
                                  static_cast<uint64_t>(class_defs_size) * 32;
        if (class_defs_end > size_cap) return false;

        if (data_off != 0 && data_size != 0) {
            if (data_off >= size_cap ||
                static_cast<uint64_t>(data_off) + data_size > size_cap)
                return false;
        }

        *out_size = file_size;
        return true;
    }

    // Fix DEX header + checksums (SHA-1 + Adler32)
    static void fix_header_and_checksums(uint8_t* data, size_t size) {
        if (size < 0x70 || std::memcmp(data, kDexMagic, 4) != 0) return;

        uint32_t file_size   = static_cast<uint32_t>(size);
        uint32_t header_size = 0x70;
        uint32_t endian_tag  = 0x12345678;
        std::memcpy(data + 0x20, &file_size, 4);
        std::memcpy(data + 0x24, &header_size, 4);
        std::memcpy(data + 0x28, &endian_tag, 4);

        // SHA-1 of data[0x20..end)
        SHA1 sha1;
        sha1.update(data + 0x20, size - 0x20);
        uint8_t sig[20];
        sha1.final(sig);
        std::memcpy(data + 0x0C, sig, 20);

        // Adler32 of data[0x0C..end)
        uint32_t cksum = adler32(data + 0x0C, size - 0x0C);
        std::memcpy(data + 0x08, &cksum, 4);
    }

private:
    static constexpr uint32_t kAdlerBase = 65521;

    static uint32_t adler32(const uint8_t* data, size_t len) {
        uint32_t a = 1, b = 0;
        for (size_t i = 0; i < len; i++) {
            a = (a + data[i]) % kAdlerBase;
            b = (b + a) % kAdlerBase;
        }
        return (b << 16) | a;
    }
};
