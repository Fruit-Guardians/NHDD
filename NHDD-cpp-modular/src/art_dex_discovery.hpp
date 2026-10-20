// Read-only ART discovery. Exact build-id profiles, never SDK-based offset guessing.
#pragma once
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "common_types.hpp"
#include "dex_validator.hpp"

struct ArtDexCandidate {
    uintptr_t object=0, vtable=0, begin=0;
    uint32_t size=0;
    std::array<uint8_t,112> header{};
};
struct ArtDexStats {
    bool supported=false, exhausted=false;
    std::string status="libdexfile_not_mapped", build_id;
    uintptr_t next=0;
    uintptr_t vtable=0;
    uint64_t bytes=0, matches=0, rejected=0, accepted=0, read_failures=0;
};
class ArtDexDiscovery {
public:
    struct ElfHeader {
        uint8_t e_ident[16];uint16_t e_type,e_machine;uint32_t e_version;
        uint64_t e_entry,e_phoff,e_shoff;uint32_t e_flags;
        uint16_t e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx;
    };
    struct ElfProgram {
        uint32_t p_type,p_flags;uint64_t p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align;
    };
    static_assert(sizeof(ElfHeader)==64 && sizeof(ElfProgram)==56,"ELF64 layout");
    static constexpr const char* kBuildId="6c74f468d6ad7d6bfeb957fe266a05b0";
    static uint64_t u64(const uint8_t* p) {uint64_t v=0;std::memcpy(&v,p,8);return v;}
    static uint32_t u32(const uint8_t* p) {uint32_t v=0;std::memcpy(&v,p,4);return v;}
    static uintptr_t pointer(uint64_t p) {return static_cast<uintptr_t>(p & 0x00ffffffffffffffULL);}
    static const MapsRegion* region(const MapsRegion* r,size_t n,uintptr_t p,size_t length=1) {
        for(size_t i=0;i<n;++i)if(p>=r[i].start && p<r[i].end && length<=r[i].end-p)return &r[i];
        return nullptr;
    }
    static bool covered(const MapsRegion* r,size_t n,uintptr_t p,size_t size) {
        if(size>UINTPTR_MAX-p)return false;
        const uintptr_t end=p+size;
        while(p<end) {const auto* m=region(r,n,p);if(!m||!m->readable)return false;p=std::min(end,m->end);}
        return true;
    }
    static bool library(const MapsRegion& r) {
        const char* suffix="/lib64/libdexfile.so";
        const size_t len=std::strlen(r.path),s=std::strlen(suffix);
        return len>=s && !std::strcmp(r.path+len-s,suffix);
    }
    template<class Read>
    static bool validate(Read read,const MapsRegion* r,size_t n,uintptr_t vtable,
                         uintptr_t object,ArtDexCandidate& out) {
        uint8_t obj[128],again[128];
        if(!covered(r,n,object,sizeof(obj))||!read(object,obj,sizeof(obj)))return false;
        if(pointer(u64(obj))!=vtable || u64(obj+16)!=0)return false;
        const uintptr_t base=pointer(u64(obj+8));
        const uint64_t size=u64(obj+32);
        if(base!=pointer(u64(obj+24)) || base!=pointer(u64(obj+72)) ||
           size<112 || size>256ull*1024*1024 || !covered(r,n,base,static_cast<size_t>(size)))return false;
        uint8_t hdr[112],normalized[112];
        if(!read(base,hdr,sizeof(hdr)))return false;
        // This profile supports standalone standard DEX, not CDEX/041 containers.
        if(!std::memcmp(hdr,"cdex",4) || !std::memcmp(hdr,"dex\n041",7))return false;
        if((u32(hdr+32)&&u32(hdr+32)!=size) || (u32(hdr+36)&&u32(hdr+36)!=112) ||
           (u32(hdr+40)&&u32(hdr+40)!=0x12345678))return false;
        std::memcpy(normalized,hdr,112);
        const uint32_t fixed_size=static_cast<uint32_t>(size),header_size=112,endian=0x12345678;
        std::memcpy(normalized+32,&fixed_size,4);std::memcpy(normalized+36,&header_size,4);
        std::memcpy(normalized+40,&endian,4);
        if(!DexValidator::header_strong_valid(normalized,fixed_size))return false;
        // Verified ARM64 constructor fields: cached strings/types/fields/methods/protos/classes.
        const size_t offsets[]={60,68,84,92,76,100};
        unsigned populated=0;
        for(size_t i=0;i<6;++i) {
            const uint32_t off=u32(hdr+offsets[i]),count=u32(hdr+offsets[i]-4);
            if(count && (off<112 || off%4))return false;
            if(count)++populated;
            if(off>size || pointer(u64(obj+80+i*8))!=base+off)return false;
        }
        if(populated<3)return false;
        const uint32_t map=u32(hdr+52);
        if(map<112 || map>size-4 || map%4)return false;
        uint8_t word[4];if(!read(base+map,word,4))return false;
        const uint32_t count=u32(word);
        if(!count || count>50 || uint64_t(count)*12+4>size-map)return false;
        std::vector<uint8_t> entries(4+size_t(count)*12);
        if(!read(base+map,entries.data(),entries.size()))return false;
        bool self=false,header=false;unsigned tables=0;
        uint32_t last=0;std::vector<uint16_t> seen;
        for(uint32_t i=0;i<count;++i) {
            const uint8_t* e=entries.data()+4+i*12;
            uint16_t type=0;std::memcpy(&type,e,2);
            const uint32_t num=u32(e+4),off=u32(e+8);
            if(!num || off>=size || (i && off<=last) || e[2] || e[3] ||
               std::find(seen.begin(),seen.end(),type)!=seen.end())return false;
            last=off;seen.push_back(type);
            if(type==0)header=num==1 && off==0;
            if(type==0x1000)self=num==1 && off==map;
            if(type>=1 && type<=6) {
                if(num!=u32(hdr+56+(type-1)*8) || off!=u32(hdr+60+(type-1)*8))return false;
                ++tables;
            }
        }
        if(!self || !header || tables!=populated)return false;
        std::array<uint8_t,112> check{};
        if(!read(object,again,sizeof(again)) || std::memcmp(obj,again,sizeof(obj)) ||
           !read(base,check.data(),check.size()) || std::memcmp(hdr,check.data(),112))return false;
        out.object=object;out.vtable=vtable;out.begin=base;out.size=fixed_size;
        std::memcpy(out.header.data(),hdr,112);return true;
    }
    template<class Read,class Emit>
    static ArtDexStats scan(Read read,const MapsRegion* r,size_t n,uint64_t budget,
                            uintptr_t resume,Emit emit) {
        ArtDexStats s;
        if(sizeof(uintptr_t)!=8){s.status="unsupported_reader_abi";return s;}
        uintptr_t vtable=0;
        for(size_t i=0;i<n;++i)if(library(r[i]) && r[i].offset==0 && r[i].readable) {
            if(r[i].start>UINTPTR_MAX-0x42000)continue;
            ElfHeader eh{};
            if(!read(r[i].start,&eh,sizeof(eh)) || std::memcmp(eh.e_ident,"\177ELF",4) ||
               eh.e_ident[4]!=2 || eh.e_ident[5]!=1 ||
               eh.e_machine!=183 || eh.e_phentsize!=sizeof(ElfProgram) ||
               !eh.e_phnum || eh.e_phnum>64 || eh.e_phoff>4096)continue;
            std::vector<ElfProgram> ph(eh.e_phnum);
            if(!covered(r,n,r[i].start+eh.e_phoff,ph.size()*sizeof(ph[0])) ||
               !read(r[i].start+eh.e_phoff,ph.data(),ph.size()*sizeof(ph[0])))continue;
            bool zero_load=false;
            for(const auto& p:ph)if(p.p_type==1 && !p.p_offset && !p.p_vaddr)zero_load=true;
            if(!zero_load)continue;
            for(const auto& p:ph)if(p.p_type==4 && p.p_filesz<=65536 && p.p_vaddr<=UINTPTR_MAX-r[i].start) {
                std::vector<uint8_t> note(static_cast<size_t>(p.p_filesz));
                if(!covered(r,n,r[i].start+p.p_vaddr,note.size()) || !read(r[i].start+p.p_vaddr,note.data(),note.size()))continue;
                for(size_t at=0;at+12<=note.size();) {
                    const uint32_t names=u32(note.data()+at),desc=u32(note.data()+at+4),type=u32(note.data()+at+8);
                    const uint64_t ns=(uint64_t(names)+3)&~3ull,ds=(uint64_t(desc)+3)&~3ull;
                    if(ns+ds>note.size()-at-12)break;
                    if(type==3 && names==4 && !std::memcmp(note.data()+at+12,"GNU\0",4) && desc<=64) {
                        static const char hex[]="0123456789abcdef";s.build_id.clear();
                        for(size_t k=0;k<desc;++k){uint8_t b=note[at+12+size_t(ns)+k];s.build_id+=hex[b>>4];s.build_id+=hex[b&15];}
                    }
                    at+=12+static_cast<size_t>(ns+ds);
                }
            }
            if(s.build_id!=kBuildId){s.status="unsupported_libdexfile_build_id";return s;}
            // Build-id 6c74...: exported StandardDexFile vtable=0x3c2d8;
            // Itanium ABI address point is +16. No offsets apply to other builds.
            vtable=r[i].start+0x3c2e8;
            uint8_t methods[16];const auto* vm=region(r,n,vtable,16);
            if(!vm || !library(*vm) || vm->writable || !read(vtable,methods,sizeof(methods))) {
                s.status="invalid_runtime_vtable";return s;
            }
            for(unsigned k=0;k<2;++k) {
                const auto* code=region(r,n,pointer(u64(methods+k*8)));
                if(!code || !code->executable || !library(*code)){s.status="invalid_vtable_code";return s;}
            }
            break;
        }
        if(!vtable)return s;
        s.supported=true;s.status="profile_verified";s.vtable=vtable;
        std::vector<const MapsRegion*> heaps;
        for(size_t i=0;i<n;++i)if(r[i].readable && r[i].writable &&
            (!r[i].path[0] || !std::strcmp(r[i].path,"[heap]") ||
             (std::strstr(r[i].path,"[anon:") && !std::strstr(r[i].path,"dalvik") &&
              !std::strstr(r[i].path,"stack") && !std::strstr(r[i].path,"jit"))))heaps.push_back(&r[i]);
        std::stable_sort(heaps.begin(),heaps.end(),[](const MapsRegion* a,const MapsRegion* b) {
            auto rank=[](const MapsRegion* m) {
                if(std::strstr(m->path,"scudo:primary") || !std::strcmp(m->path,"[heap]"))return 0;
                if(std::strstr(m->path,"scudo:secondary"))return 3;
                return m->path[0]?2:1;
            };
            return rank(a)<rank(b);
        });
        size_t first=0;
        for(size_t i=0;i<heaps.size();++i)if(resume>=heaps[i]->start && resume<heaps[i]->end){first=i;break;}
        std::vector<uint8_t> block(65536);
        // Resume within a region; the omitted prefix is visited next round.
        for(size_t hi=0;hi<heaps.size();++hi) {
            const auto& h=*heaps[(first+hi)%heaps.size()];
            uintptr_t p=(hi==0 && resume>=h.start && resume<h.end)?resume:h.start;
            for(;p<h.end;) {
                if(s.bytes>=budget){s.exhausted=true;s.next=p;return s;}
                size_t size=static_cast<size_t>(std::min<uint64_t>({h.end-p,block.size(),budget-s.bytes}));
                size-=size%8;if(!size){s.exhausted=true;s.next=p;return s;}
                s.bytes+=size;
                if(!read(p,block.data(),size)){++s.read_failures;p+=size;continue;}
                for(size_t at=0;at+8<=size;at+=8)if(pointer(u64(block.data()+at))==vtable) {
                    if(++s.matches>4096){s.exhausted=true;s.status="candidate_limit";s.next=p;return s;}
                    ArtDexCandidate c;
                    if(validate(read,r,n,vtable,p+at,c)) {
                        const auto* source=region(r,n,c.begin);
                        // Avoid dumping boot/system ART DEX as application results.
                        if(source && !std::strstr(source->path,"/system/") && !std::strstr(source->path,"/apex/") &&
                           !std::strstr(source->path,"/data/misc/apexdata/")) {++s.accepted;emit(c);}
                    } else ++s.rejected;
                }
                p+=size;
            }
        }
        return s;
    }
};
