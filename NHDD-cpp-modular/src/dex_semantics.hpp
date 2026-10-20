// Bounded static DEX checks. This is not ART's bytecode/type verifier.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <tuple>
#include <vector>
#include "sha1.hpp"

struct DexSemanticReport {
    bool supported = true, valid = false;
    bool checksum_valid = false, signature_valid = false;
    uint32_t strings = 0, classes = 0, methods = 0, code_items = 0, debug_items = 0;
    std::vector<std::string> errors;
    void write_json(FILE* f) const {
        std::fprintf(f, "{\"status\":\"%s\",\"validation_scope\":\"header_map_tables_class_data_code_debug_bounds\","
            "\"art_accepted\":null,\"bytecode_type_verified\":false,\"checksum_valid\":%s,\"signature_valid\":%s,"
            "\"strings\":%u,\"classes\":%u,\"methods\":%u,\"code_items\":%u,\"debug_items\":%u,\"errors\":[",
            !supported ? "unsupported_version" : (valid ? "structural_checks_passed" : "invalid"),
            checksum_valid ? "true" : "false", signature_valid ? "true" : "false",
            strings, classes, methods, code_items, debug_items);
        for (size_t i = 0; i < errors.size(); ++i)
            std::fprintf(f, "%s\"%s\"", i ? "," : "", errors[i].c_str());
        std::fputs("]}", f);
    }
};

class DexSemantics {
public:
    static DexSemanticReport validate(const uint8_t* data, size_t size) {
        DexSemantics v(data, size);
        v.run();
        return v.report_;
    }
private:
    DexSemantics(const uint8_t* data, size_t size) : d_(data), n_(size) {}
    bool fail(const char* reason) {
        if (report_.errors.size() < 32) report_.errors.emplace_back(reason);
        return false;
    }
    bool span(uint64_t off, uint64_t bytes) const { return off <= n_ && bytes <= n_ - off; }
    uint16_t u16(size_t off) const { return static_cast<uint16_t>(d_[off] | (d_[off+1] << 8)); }
    uint32_t u32(size_t off) const {
        return static_cast<uint32_t>(d_[off]) | (static_cast<uint32_t>(d_[off+1]) << 8) |
            (static_cast<uint32_t>(d_[off+2]) << 16) | (static_cast<uint32_t>(d_[off+3]) << 24);
    }
    bool tick(uint64_t count = 1) {
        if (count > budget_) return fail("validation_budget_exhausted");
        budget_ -= count; return true;
    }
    bool leb(size_t& p, uint32_t& value, bool signed_value = false) {
        value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            if (!span(p, 1) || !tick()) return fail("truncated_leb128");
            uint8_t b = d_[p++];
            if (i == 4 && ((!signed_value && (b & 0xf0)) ||
                (signed_value && (b & 0x70) != 0 && (b & 0x70) != 0x70)))
                return fail("overflow_leb128");
            value |= static_cast<uint32_t>(b & 0x7f) << (7 * i);
            if (!(b & 0x80)) {
                if (signed_value && i < 4 && (b & 0x40)) value |= ~0u << (7 * (i + 1));
                return true;
            }
        }
        return fail("unterminated_leb128");
    }
    bool table(uint32_t count, uint32_t off, uint32_t width) {
        if (count == 0) return off == 0 || fail("empty_table_nonzero_offset");
        return (off >= 0x70 && off % 4 == 0 && span(off, uint64_t(count) * width)) ||
            fail("table_out_of_bounds_or_unaligned");
    }
    bool index(uint32_t value, uint32_t count, bool optional = false) {
        return (value < count || (optional && value == 0xffffffffu)) || fail("index_out_of_range");
    }
    bool type_list(uint32_t off) {
        if (!off) return true;
        if (off % 4 || !span(off, 4)) return fail("type_list_header");
        const uint32_t count = u32(off);
        if (!span(uint64_t(off) + 4, uint64_t(count) * 2) || !tick(count)) return fail("type_list_bounds");
        for (uint32_t i = 0; i < count; ++i) if (!index(u16(off + 4 + 2*i), types_)) return false;
        return true;
    }
    bool debug_info(uint32_t off, uint16_t registers, uint32_t insns) {
        const auto context=std::make_tuple(off,registers,insns);
        if (!off || debug_contexts_.count(context)) return true;
        if (!span(off, 1)) return fail("debug_info_offset");
        if(debug_seen_.insert(off).second)++report_.debug_items;
        debug_contexts_.insert(context);
        size_t p = off; uint32_t x = 0, count = 0, pc = 0;
        if (!leb(p, x) || !leb(p, count) || count > n_ || !tick(count)) return false;
        for (uint32_t i = 0; i < count; ++i)
            if (!leb(p, x) || (x && !index(x-1, strings_))) return false;
        while (span(p, 1) && tick()) {
            uint8_t op = d_[p++];
            if (!op) return true;
            if (op == 1) {
                if (!leb(p, x) || x > insns - pc) return fail("debug_pc_bounds");
                pc += x;
            } else if (op == 2) { if (!leb(p, x, true)) return false; }
            else if (op == 3 || op == 4) {
                if (!leb(p, x) || x >= registers) return fail("debug_register_bounds");
                if (!leb(p, x) || (x && !index(x-1, strings_))) return false;
                if (!leb(p, x) || (x && !index(x-1, types_))) return false;
                if (op == 4 && (!leb(p, x) || (x && !index(x-1, strings_)))) return false;
            } else if (op == 5 || op == 6) {
                if (!leb(p, x) || x >= registers) return fail("debug_register_bounds");
            } else if (op == 9) {
                if (!leb(p, x) || (x && !index(x-1, strings_))) return false;
            } else if (op >= 10) {
                uint32_t advance = (op - 10) / 15;
                if (advance > insns - pc) return fail("debug_special_pc_bounds");
                pc += advance;
            }
        }
        return fail("debug_end_sequence_missing");
    }
    bool code(uint32_t off) {
        if (code_seen_.count(off)) return true;
        if (off % 4 || !span(off, 16)) return fail("code_item_header");
        code_seen_.insert(off); ++report_.code_items;
        const uint16_t registers = u16(off), ins = u16(off+2), tries = u16(off+6);
        const uint32_t instructions = u32(off+12);
        if (ins > registers || !span(uint64_t(off) + 16, uint64_t(instructions) * 2))
            return fail("code_insns_bounds");
        if (!debug_info(u32(off+8), registers, instructions)) return false;
        if (!tries) return true;
        size_t p = off + 16 + size_t(instructions)*2;
        if (instructions & 1) p += 2;
        if (!span(p, uint64_t(tries)*8)) return fail("tries_bounds");
        const size_t tries_base = p;
        p += size_t(tries)*8;
        const size_t handlers_base = p;
        uint32_t count = 0, x = 0;
        if (!leb(p, count) || count > n_ || !tick(count)) return false;
        std::set<size_t> handler_offsets;
        for (uint32_t i = 0; i < count; ++i) {
            handler_offsets.insert(p - handlers_base);
            if (!leb(p, x, true)) return false;
            const int64_t signed_count = static_cast<int32_t>(x);
            const uint64_t typed = signed_count < 0 ? static_cast<uint64_t>(-signed_count) : static_cast<uint64_t>(signed_count);
            if (!tick(typed) || typed > n_) return fail("catch_handler_count");
            for (uint64_t k = 0; k < typed; ++k) {
                if (!leb(p, x) || !index(x, types_) || !leb(p, x) || x >= instructions)
                    return fail("catch_handler_reference");
            }
            if (signed_count <= 0 && (!leb(p, x) || x >= instructions)) return fail("catch_all_reference");
        }
        for (uint16_t i = 0; i < tries; ++i) {
            size_t t = tries_base + size_t(i)*8;
            if (!u16(t+4) || u32(t) >= instructions || u16(t+4) > instructions - u32(t) ||
                !handler_offsets.count(u16(t+6))) return fail("try_handler_reference");
            if(i && uint64_t(u32(t-8))+u16(t-4)>u32(t))return fail("try_ranges_overlap");
        }
        return true;
    }
    bool class_data(uint32_t off,uint32_t owner) {
        if (!off) return true;
        if (!span(off, 1)) return fail("class_data_offset");
        size_t p = off;
        uint32_t counts[4] = {};
        for (auto& c : counts) if (!leb(p, c)) return false;
        for (unsigned group = 0; group < 4; ++group) {
            if (counts[group] > (group < 2 ? fields_ : methods_) || !tick(counts[group]))
                return fail("class_data_count");
            uint64_t idx = 0;
            for (uint32_t i = 0; i < counts[group]; ++i) {
                uint32_t delta = 0, flags = 0, code_off = 0;
                if (!leb(p, delta) || !leb(p, flags) || (i && !delta)) return fail("class_data_delta");
                idx += delta;
                if (idx >= (group < 2 ? fields_ : methods_)) return fail("class_data_index");
                const size_t member=u32(group<2?84:92)+static_cast<size_t>(idx)*8;
                if(u16(member)!=owner)return fail("class_data_wrong_owner");
                if (group >= 2) {
                    if (!leb(p, code_off)) return false;
                    const bool abstract_native = (flags & (0x100 | 0x400)) != 0;
                    if ((code_off == 0) != abstract_native) return fail("method_code_presence");
                    if (code_off && !code(code_off)) return false;
                }
            }
        }
        return true;
    }
    void run() {
        if (!d_ || n_ < 0x70 || std::memcmp(d_, "dex\n", 4) || d_[7]) { fail("dex_header_magic"); return; }
        const std::string version(reinterpret_cast<const char*>(d_+4), 3);
        if (version != "035" && version != "037" && version != "038" && version != "039" && version != "040") {
            report_.supported = false; fail("dex_version_not_supported"); return;
        }
        if (u32(0x20) != n_ || u32(0x24) != 0x70 || u32(0x28) != 0x12345678) { fail("dex_header_size_endian"); return; }
        uint32_t a = 1, b = 0;
        for (size_t i = 12; i < n_; ++i) { a = (a + d_[i]) % 65521; b = (b + a) % 65521; }
        report_.checksum_valid = u32(8) == ((b << 16) | a);
        SHA1 sha; sha.update(d_+32, n_-32); uint8_t digest[20]; sha.final(digest);
        report_.signature_valid = std::memcmp(digest, d_+12, 20) == 0;
        strings_=u32(56); types_=u32(64); protos_=u32(72); fields_=u32(80); methods_=u32(88);
        const uint32_t classes=u32(96);
        report_.strings = strings_; report_.classes = classes; report_.methods = methods_;
        const uint32_t widths[] = {4,4,12,8,8,32};
        std::vector<std::pair<uint64_t,uint64_t>> fixed{{0,0x70}};
        for (unsigned i=0;i<6;++i) {
            const uint32_t count=u32(56+8*i), off=u32(60+8*i);
            if (!table(count,off,widths[i]) || !tick(count)) return;
            if (count) fixed.emplace_back(off,uint64_t(off)+uint64_t(count)*widths[i]);
        }
        std::sort(fixed.begin(),fixed.end());
        for(size_t i=1;i<fixed.size();++i) if(fixed[i].first<fixed[i-1].second) {fail("overlapping_fixed_tables");return;}
        if (types_>65535 || protos_>65535 || fields_>65536 || methods_>65536) {fail("dex_index_limit");return;}
        const uint32_t data_size=u32(104), data_off=u32(108);
        if ((data_size && (data_off%4 || data_off<0x70 || !span(data_off,data_size))) ||
            (!data_size && data_off) || !span(u32(48),u32(44))) {fail("data_link_bounds");return;}
        uint32_t map=u32(52);
        if (map%4 || map<0x70 || !span(map,4)) {fail("map_list_offset");return;}
        uint32_t count=u32(map);
        if (!count || count>4096 || !span(uint64_t(map)+4,uint64_t(count)*12)) {fail("map_list_bounds");return;}
        std::set<uint16_t> seen; uint32_t last=0; bool self=false,header=false;
        for(uint32_t i=0;i<count;++i) {
            size_t p=map+4+size_t(i)*12; uint16_t type=u16(p); uint32_t c=u32(p+4),off=u32(p+8);
            if(!seen.insert(type).second || !c || off>=n_ || (i && off<=last) || u16(p+2)) {fail("map_list_order_or_entry");return;}
            last=off;
            if(type==0) header=c==1 && off==0;
            if(type==0x1000) self=c==1 && off==map;
            if(type>=1 && type<=6 && (c!=u32(56+(type-1)*8) || off!=u32(60+(type-1)*8))) {fail("map_header_disagreement");return;}
        }
        if(!self || !header) {fail("map_self_or_header_missing");return;}
        for(unsigned i=0;i<6;++i) if(u32(56+i*8) && !seen.count(static_cast<uint16_t>(i+1))) {fail("map_table_missing");return;}
        for(uint32_t i=0;i<strings_;++i) {
            size_t p=u32(u32(60)+size_t(i)*4); uint32_t length=0;
            if(p<data_off || !leb(p,length)) {fail("string_data_offset");return;}
            uint64_t units=0;
            while(span(p,1) && d_[p] && tick()) {
                uint8_t c=d_[p++];
                if(c<0x80) ++units;
                else if((c&0xe0)==0xc0) {
                    if(!span(p,1) || (d_[p]&0xc0)!=0x80) {fail("mutf8_sequence");return;}
                    if(c<0xc2 && !(c==0xc0 && d_[p]==0x80)) {fail("mutf8_overlong");return;}
                    ++p; ++units;
                } else if((c&0xf0)==0xe0) {
                    if(!span(p,2) || (d_[p]&0xc0)!=0x80 || (d_[p+1]&0xc0)!=0x80 || (c==0xe0 && d_[p]<0xa0)) {fail("mutf8_sequence");return;}
                    p+=2; ++units;
                } else {fail("mutf8_leading_byte");return;}
            }
            if(!span(p,1) || d_[p] || units!=length) {fail("string_length_or_terminator");return;}
        }
        for(uint32_t i=0;i<types_;++i) if(!index(u32(u32(68)+size_t(i)*4),strings_)) return;
        for(uint32_t i=0;i<protos_;++i) {
            size_t p=u32(76)+size_t(i)*12;
            if(!index(u32(p),strings_) || !index(u32(p+4),types_) || !type_list(u32(p+8))) return;
        }
        for(unsigned kind=0;kind<2;++kind) for(uint32_t i=0;i<(kind?methods_:fields_);++i) {
            size_t p=u32(kind?92:84)+size_t(i)*8;
            if(!index(u16(p),types_) || !index(u16(p+2),kind?protos_:types_) || !index(u32(p+4),strings_)) return;
        }
        std::set<uint32_t> class_indices;
        for(uint32_t i=0;i<classes;++i) {
            size_t p=u32(100)+size_t(i)*32;
            if(!class_indices.insert(u32(p)).second || !index(u32(p),types_) ||
               !index(u32(p+8),types_,true) || !index(u32(p+16),strings_,true) ||
               !type_list(u32(p+12)) || !class_data(u32(p+24),u32(p))) {fail("class_definition");return;}
            if((u32(p+20) && !span(u32(p+20),16)) || (u32(p+28) && !span(u32(p+28),1))) {fail("class_auxiliary_offset");return;}
        }
        report_.valid = report_.errors.empty();
    }
    const uint8_t* d_; size_t n_;
    uint64_t budget_ = 32 * 1024 * 1024;
    uint32_t strings_=0,types_=0,protos_=0,fields_=0,methods_=0;
    DexSemanticReport report_;
    std::set<uint32_t> code_seen_,debug_seen_;
    std::set<std::tuple<uint32_t,uint16_t,uint32_t>> debug_contexts_;
};
