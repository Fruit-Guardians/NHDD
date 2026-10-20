// Versioned ART container inspection; preserves native formats, never fabricates DEX.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include "dex_semantics.hpp"

struct RuntimeFormatReport {
    std::string format = "unknown", version = "unknown", scope = "header_and_sections";
    bool supported = false, valid = false;
    uint64_t extent = 0;
    uint32_t dex_count = 0;
    struct OatHeader {
        uint32_t size = 0, key_value_size = 0, key_value_pairs = 0;
        uint32_t instruction_set = 0, dex_directory_offset = 0;
        uint32_t executable_offset = 0, base_file_offset = 0;
        bool has_base_file_offset = false;
    } oat;
    std::vector<std::string> errors;
    struct Embedded { uint32_t offset = 0, size = 0; std::string format; bool valid = false; };
    std::vector<Embedded> embedded;
    void write_json(FILE* f) const {
        std::fprintf(f, "{\"format\":\"%s\",\"version\":\"%s\",\"status\":\"%s\","
            "\"validation_scope\":\"%s\",\"art_accepted\":null,\"dequickened\":false,"
            "\"extent\":%llu,\"dex_count\":%u,\"errors\":[", format.c_str(), version.c_str(),
            !supported ? "unsupported_version" : (valid ? "format_checks_passed" : "invalid_or_incomplete"),
            scope.c_str(), static_cast<unsigned long long>(extent), dex_count);
        for (size_t i=0;i<errors.size();++i) std::fprintf(f,"%s\"%s\"",i?",":"",errors[i].c_str());
        std::fputs("],\"embedded\":[", f);
        for (size_t i=0;i<embedded.size();++i) {
            const auto& e=embedded[i];
            std::fprintf(f,"%s{\"offset\":%u,\"size\":%u,\"format\":\"%s\",\"structural_checks_passed\":%s}",
                i?",":"",e.offset,e.size,e.format.c_str(),e.valid?"true":"false");
        }
        std::fputc(']',f);
        if(format=="oat" && oat.size) {
            std::fprintf(f,",\"oat_header\":{\"size\":%u,\"instruction_set\":%u,"
                "\"key_value_size\":%u,\"key_value_pairs\":%u,\"dex_directory_offset\":%u,"
                "\"executable_offset\":%u,\"offset_base\":\"oat_header\",\"base_file_offset\":",
                oat.size,oat.instruction_set,oat.key_value_size,oat.key_value_pairs,
                oat.dex_directory_offset,oat.executable_offset);
            if(oat.has_base_file_offset)std::fprintf(f,"%u",oat.base_file_offset);
            else std::fputs("null",f);
            std::fputc('}',f);
        }
        std::fputc('}',f);
    }
};

class RuntimeFormats {
public:
    static const char* identify(const uint8_t* d, size_t n) {
        if (!d || n<4) return "unknown";
        if (!std::memcmp(d,"dex\n",4)) return "dex";
        if (!std::memcmp(d,"cdex",4)) return "compact_dex";
        if (!std::memcmp(d,"vdex",4)) return "vdex";
        if (!std::memcmp(d,"oat\n",4)) return "oat";
        return "unknown";
    }
    static uint32_t u32(const uint8_t* d,size_t p) {
        return uint32_t(d[p]) | (uint32_t(d[p+1])<<8) | (uint32_t(d[p+2])<<16) | (uint32_t(d[p+3])<<24);
    }
    // Only header reads are needed to determine a bounded capture extent.
    // OAT has no total-size field: return its header/KV extent and label it.
    static uint64_t capture_extent(const uint8_t* d,size_t n) {
        const std::string kind=identify(d,n);
        if(n<8 || d[7]) return 0;
        const std::string v(reinterpret_cast<const char*>(d+4),3);
        if(kind=="compact_dex" && v=="001" && n>=136) {
            return std::max<uint64_t>(u32(d,32),uint64_t(u32(d,108))+u32(d,104));
        }
        if(kind=="vdex") {
            if((v=="006" || v=="010") && n>=24) return 24ull+uint64_t(u32(d,8))*4+u32(d,12)+u32(d,16)+u32(d,20);
            if((v=="019" || v=="021") && n>=(v=="019"?20u:28u)) {
                size_t base=v=="019"?20:28;
                uint64_t dex_header=base+uint64_t(u32(d,12))*4;
                uint64_t extent=dex_header+u32(d,16);
                if(v=="021") extent+=uint64_t(u32(d,20))+u32(d,24);
                if(!std::memcmp(d+8,"002\0",4)) {
                    if(dex_header>n || n-dex_header<12) return 0;
                    extent+=12ull+u32(d,size_t(dex_header))+u32(d,size_t(dex_header)+4)+u32(d,size_t(dex_header)+8);
                } else if(std::memcmp(d+8,"000\0",4)) return 0;
                return extent;
            }
            if(v=="027" && n>=12) {
                uint32_t count=u32(d,8);
                if(count!=4 || n<12+size_t(count)*12) return 0;
                uint64_t extent=12+uint64_t(count)*12;
                for(uint32_t i=0;i<count;++i) extent=std::max(extent,uint64_t(u32(d,16+12*i))+u32(d,20+12*i));
                return extent;
            }
        }
        if(kind=="oat") {
            size_t h=oat_header_size(v);
            if(h && n>=h) return h+uint64_t(u32(d,h-4));
        }
        return 0;
    }
    static RuntimeFormatReport inspect(const uint8_t* d,size_t n,bool header_only=false,
            uint64_t elf_payload_offset=UINT64_MAX) {
        RuntimeFormatReport r;
        r.format=identify(d,n);
        if(n>=8 && d[4]>='0'&&d[4]<='9'&&d[5]>='0'&&d[5]<='9'&&d[6]>='0'&&d[6]<='9'&&!d[7])
            r.version=std::string(reinterpret_cast<const char*>(d+4),3);
        else {r.errors.emplace_back("invalid_magic_version");return r;}
        r.extent=capture_extent(d,n);
        if(r.format=="compact_dex") {
            r.scope="compact_header_id_tables_shared_data_bounds";
            r.supported=r.version=="001";
            if(!r.supported)return r;
            if(n<136 || u32(d,36)!=136 || u32(d,40)!=0x12345678 ||
               u32(d,32)<136 || r.extent>n || u32(d,128)>u32(d,132) ||
               u32(d,132)>u32(d,104)) {r.errors.emplace_back("compact_header_or_shared_data_bounds");return r;}
            const uint32_t widths[]={4,4,12,8,8,32};
            for(unsigned i=0;i<6;++i) {
                uint32_t count=u32(d,56+8*i),off=u32(d,60+8*i);
                if(count && (off<136 || off%4 || uint64_t(off)+uint64_t(count)*widths[i]>u32(d,32))) {
                    r.errors.emplace_back("compact_id_table_bounds");return r;
                }
            }
            r.valid=true; r.dex_count=1;
            return r;
        }
        if(r.format=="vdex") {
            r.supported=r.version=="006"||r.version=="010"||r.version=="019"||r.version=="021"||r.version=="027";
            if(!r.supported)return r;
            if(!r.extent || r.extent>n || r.extent>256ull*1024*1024) {r.errors.emplace_back("vdex_sections_truncated_or_oversize");return r;}
            uint64_t dex_begin=0,dex_end=0;
            if(r.version=="027") {
                std::set<uint32_t> kinds;
                std::vector<std::pair<uint64_t,uint64_t>> sections;
                for(unsigned i=0;i<4;++i) {
                    uint32_t kind=u32(d,12+12*i),off=u32(d,16+12*i),size=u32(d,20+12*i);
                    if(kind>=4 || !kinds.insert(kind).second || (size && (off<60 || uint64_t(off)+size>n))) {
                        r.errors.emplace_back("vdex_section_directory");return r;
                    }
                    if(size) sections.emplace_back(off,uint64_t(off)+size);
                    if(kind==0) {if(size%4){r.errors.emplace_back("vdex_checksum_section");return r;} r.dex_count=size/4;}
                    if(kind==1) {dex_begin=off;dex_end=uint64_t(off)+size;}
                }
                std::sort(sections.begin(),sections.end());
                for(size_t i=1;i<sections.size();++i) if(sections[i].first<sections[i-1].second) {r.errors.emplace_back("vdex_overlapping_sections");return r;}
            } else if(r.version=="006" || r.version=="010") {
                r.dex_count=u32(d,8);dex_begin=24ull+uint64_t(r.dex_count)*4;dex_end=dex_begin+u32(d,12);
            } else {
                r.dex_count=u32(d,12);
                size_t base=r.version=="019"?20:28;
                uint64_t h=base+uint64_t(r.dex_count)*4;
                if(!std::memcmp(d+8,"002\0",4)) {dex_begin=h+12;dex_end=dex_begin+u32(d,size_t(h));}
            }
            if(dex_end>n || dex_begin>dex_end || r.dex_count>65536) {r.errors.emplace_back("vdex_dex_section_bounds");return r;}
            // 019/021 may prefix each DEX with a quickening-table offset.
            for(uint64_t p=dex_begin;p+8<=dex_end;p+=4) {
                const std::string kind=identify(d+size_t(p),size_t(dex_end-p));
                if(kind!="dex" && kind!="compact_dex")continue;
                if(dex_end-p<36)continue;
                uint32_t size=u32(d+size_t(p),32);
                if(size<0x70 || size>dex_end-p) {r.errors.emplace_back("vdex_embedded_dex_truncated");return r;}
                bool valid=kind=="dex" ? DexSemantics::validate(d+size_t(p),size).valid :
                    inspect(d+size_t(p),n-size_t(p)).valid;
                r.embedded.push_back({static_cast<uint32_t>(p),size,kind,valid});
                p+=(size-1)/4*4;
            }
            if(dex_end>dex_begin && r.embedded.size()!=r.dex_count) {r.errors.emplace_back("vdex_embedded_count_mismatch");return r;}
            for(const auto& e:r.embedded) if(!e.valid) {r.errors.emplace_back("embedded_dex_failed_static_checks");return r;}
            r.valid=true;return r;
        }
        if(r.format=="oat") {
            r.scope=header_only?"oat_header_key_value_store_only":"oat_header_key_value_and_offsets";
            const size_t h=oat_header_size(r.version);
            r.supported=h!=0;
            if(!r.supported)return r;
            r.oat.size=static_cast<uint32_t>(h);
            if(n<h || !r.extent || r.extent>n) {r.errors.emplace_back("oat_header_or_key_value_bounds");return r;}
            const size_t executable=h==72?36:(r.version=="230"?32:28);
            r.oat.instruction_set=u32(d,12);
            r.oat.key_value_size=u32(d,h-4);
            r.oat.dex_directory_offset=u32(d,24);
            r.oat.executable_offset=u32(d,executable);
            r.oat.has_base_file_offset=h==72;
            if(r.oat.has_base_file_offset)r.oat.base_file_offset=u32(d,32);
            r.dex_count=u32(d,20);
            if(r.dex_count>65536 || (r.dex_count && u32(d,24)<r.extent)) {r.errors.emplace_back("oat_dex_directory_offset");return r;}
            size_t p=h;
            while(p<r.extent) {
                // A trailing zero-filled reserve is not a set of empty pairs.
                if(!d[p]) {
                    if(std::any_of(d+p,d+static_cast<size_t>(r.extent),[](uint8_t c){return c!=0;})) {
                        r.errors.emplace_back("oat_nonzero_key_value_padding");return r;
                    }
                    break;
                }
                const size_t key_start=p;
                size_t value_start=0;
                for(unsigned part=0;part<2;++part) {
                    while(p<r.extent && d[p]) ++p;
                    if(p==r.extent) {r.errors.emplace_back("oat_unterminated_key_value");return r;}
                    ++p;
                    if(!part)value_start=p;
                }
                // Modern ART reserves fixed-size non-deterministic values,
                // including their internal zero padding (AOSP oat.h/oat.cc).
                if(r.version=="279") {
                    const std::string key(reinterpret_cast<const char*>(d+key_start));
                    const size_t reserve=key=="apex-versions"?1024:(key=="dex2oat-cmdline"?2048:0);
                    if(reserve) {
                        if(p-value_start-1>reserve || reserve+1>r.extent-value_start) {
                            r.errors.emplace_back("oat_reserved_value_bounds");return r;
                        }
                        const size_t end=value_start+reserve+1;
                        if(std::any_of(d+p,d+end,[](uint8_t c){return c!=0;})) {
                            r.errors.emplace_back("oat_nonzero_reserved_value_padding");return r;
                        }
                        p=end;
                    }
                }
                ++r.oat.key_value_pairs;
            }
            // OAT 279's 72-byte layout was independently checked against the
            // connected device's ART oatdump and oatdata/oatexec ELF symbols.
            // Offsets are relative to oatdata, not the ELF file start. In a
            // header-only memory capture their upper bounds are unavailable.
            if(r.version=="279") {
                if(!r.oat.instruction_set || r.oat.instruction_set>6) {
                    r.errors.emplace_back("oat_instruction_set");return r;
                }
                if(elf_payload_offset!=UINT64_MAX && r.oat.base_file_offset!=elf_payload_offset) {
                    r.errors.emplace_back("oat_base_file_offset_mismatch");return r;
                }
                const uint32_t exec=r.oat.executable_offset,bcp=u32(d,28);
                if((exec && (exec<r.extent || (!header_only && exec>=n))) ||
                   (bcp && (bcp<r.extent || (!header_only && bcp>=n)))) {
                    r.errors.emplace_back("oat_section_offset");return r;
                }
                for(size_t field=40;field<=64;field+=4) {
                    const uint32_t trampoline=u32(d,field);
                    if(trampoline && (!exec || trampoline<exec || (!header_only && trampoline>=n))) {
                        r.errors.emplace_back("oat_trampoline_offset");return r;
                    }
                }
                // A directory entry needs at least location_size, checksum
                // and dex offset; actual locations and metadata need more.
                if(!header_only && r.dex_count &&
                    (r.oat.dex_directory_offset>n || uint64_t(r.dex_count)*12>n-r.oat.dex_directory_offset)) {
                    r.errors.emplace_back("oat_dex_directory_truncated");return r;
                }
            }
            if(!header_only) {
                if((r.dex_count && u32(d,24)>=n) || u32(d,executable)>n) {r.errors.emplace_back("oat_offset_outside_snapshot");return r;}
            }
            r.valid=true;return r;
        }
        r.errors.emplace_back("format_not_supported");return r;
    }
    static size_t oat_header_size(const std::string& version) {
        if(version=="170")return 56;
        if(version=="195")return 64;
        if(version=="230")return 68;
        // 259..275: AOSP android16/QPR/android17; 279: device oatdump and ELF symbols.
        if(version=="259" || version=="262" || version=="265" || version=="275" || version=="279")return 72;
        return 0;
    }
};
