// Conditional temporal composites, never a target-memory write or atomic snapshot.
#pragma once
#include <array>
#include <atomic>
#include <memory>
#include "dex_capture.hpp"
#include "dex_validator.hpp"
#include "dex_semantics.hpp"
#include "fast_capture.hpp"
#include "common_types.hpp"

struct ArtRefillBudget {std::atomic<size_t> bytes{0};};
struct ArtRefillBaseline {
    DexCandidateIdentity identity;
    uintptr_t object=0,vtable=0;
    uint64_t revision=0,hash=0;
    double armed_boot=0;
    std::string build_id;
    std::array<uint8_t,128> object_bytes{};
    std::array<uint8_t,16> vtable_bytes{};
    std::vector<uint8_t> raw;
    std::vector<DexMethodCode> methods;
    std::vector<MapsRegion> mappings;
    std::atomic<bool> active{true};
    std::shared_ptr<ArtRefillBudget> budget;
    size_t charge=0;
    ~ArtRefillBaseline() {if(budget)budget->bytes.fetch_sub(charge);}
};
struct ArtRefillPlan {
    std::string reason="not_planned";
    std::vector<DexMethodCode> patches;
    size_t changed_bytes=0;
    bool accepted() const {return reason=="method_fragments_match";}
};
class ArtRefill {
public:
    static bool magic_version_valid(const std::vector<uint8_t>& raw) {
        return raw.size()>=8 && !std::memcmp(raw.data(),"dex\n",4) && raw[7]==0 &&
            raw[4]>='0' && raw[4]<='9' && raw[5]>='0' && raw[5]<='9' && raw[6]>='0' && raw[6]<='9';
    }
    static std::vector<uint8_t> normalize(const std::vector<uint8_t>& raw) {
        auto copy=raw;
        if(copy.size()<112)return {};
        if(!magic_version_valid(copy))std::memcpy(copy.data(),"dex\n039\0",8);
        DexValidator::fix_header_and_checksums(copy.data(),copy.size());return copy;
    }
    static bool layout(ArtRefillBaseline& b) {
        if(b.raw.size()!=b.identity.dex_size || b.raw.size()<112)return false;
        auto fixed=normalize(b.raw);auto r=DexSemantics::validate(fixed.data(),fixed.size(),true);
        if(!r.valid || r.method_code.empty())return false;
        const uint32_t map=u32(fixed.data()+52),count=u32(fixed.data()+map);
        uint32_t begin=0,end=static_cast<uint32_t>(fixed.size()),declared=0;
        for(uint32_t i=0;i<count;++i) {
            const uint8_t* p=fixed.data()+map+4+12*i;
            if(p[0]==1 && p[1]==0x20) {
                begin=u32(p+8);declared=u32(p+4);
                if(i+1<count)end=u32(p+20);
                break;
            }
        }
        if(!begin || !declared || declared!=r.code_items)return false;
        auto methods=std::move(r.method_code);
        std::sort(methods.begin(),methods.end(),[](const auto& a,const auto& c){return a.code_offset<c.code_offset;});
        uint32_t previous=begin;
        for(const auto& m:methods) {
            if(!m.bytes || m.code_offset<previous || m.instructions_offset!=m.code_offset+16 ||
               m.instructions_offset>end || m.bytes>end-m.instructions_offset ||
               m.code_end<m.instructions_offset+m.bytes || m.code_end>end)return false;
            previous=m.code_end;
        }
        b.methods=std::move(methods);return true;
    }
    static ArtRefillPlan plan(const ArtRefillBaseline& b,const FastObservation& o,
                             uint32_t pid,uint64_t generation,bool anchors) {
        ArtRefillPlan p;
        auto reject=[&](const char* reason){p.reason=reason;p.patches.clear();return p;};
        if(!b.active)return reject("candidate_invalidated");
        if(b.identity.pid!=pid || b.identity.process_start_time!=generation || !o.generation_valid)
            return reject("process_generation_mismatch");
        if(!anchors)return reject("capture_anchor_mismatch");
        if(o.begin<b.armed_boot)return reject("capture_precedes_candidate");
        if(b.raw.size()>UINTPTR_MAX-b.identity.address || o.first.size()>UINTPTR_MAX-o.address)
            return reject("address_overflow");
        const uintptr_t lo=std::max(b.identity.address,o.address);
        const uintptr_t hi=std::min(b.identity.address+b.raw.size(),o.address+o.first.size());
        if(lo>=hi)return reject("no_intersection");
        if(!o.covered(0,lo-o.address,hi-lo) || !o.covered(1,lo-o.address,hi-lo))return reject("fragment_holes");
        for(const auto& m:b.methods) {
            const uintptr_t a=b.identity.address+m.instructions_offset;
            if(a<lo || a>hi || m.bytes>hi-a)continue;
            const size_t off=a-o.address;
            if(!std::memcmp(b.raw.data()+m.instructions_offset,o.first.data()+off,m.bytes) &&
               !std::memcmp(b.raw.data()+m.instructions_offset,o.second.data()+off,m.bytes))continue;
            if(std::memcmp(o.first.data()+off,o.second.data()+off,m.bytes))return reject("method_changed_between_reads");
            if(std::all_of(o.first.begin()+off,o.first.begin()+off+m.bytes,[](uint8_t byte){return byte==0;}))
                return reject("zero_instruction_replacement");
            p.patches.push_back(m);
        }
        if(p.patches.empty())return reject("no_complete_changed_method");
        size_t method=0;
        for(uintptr_t a=lo;a<hi;++a) {
            const size_t d=a-b.identity.address,s=a-o.address;
            while(method<p.patches.size() && d>=p.patches[method].instructions_offset+p.patches[method].bytes)++method;
            const bool patch=method<p.patches.size() && d>=p.patches[method].instructions_offset;
            if(!patch && (o.first[s]!=b.raw[d] || o.second[s]!=b.raw[d]))return reject("fragment_non_method_changed");
            if(patch)p.changed_bytes+=o.first[s]!=b.raw[d];
        }
        p.reason="method_fragments_match";return p;
    }
    template<class Read,class Guard>
    static bool complement(const ArtRefillBaseline& b,const ArtRefillPlan& p,Read read,Guard guard) {
        if(!p.accepted() || !b.active || !guard())return false;
        uint8_t block[4096];
        for(unsigned pass=0;pass<2;++pass) {
            if(!guard())return false;
            size_t method=0;
            for(size_t off=0;off<b.raw.size();off+=sizeof(block)) {
                if(!b.active)return false;
                const size_t n=std::min(sizeof(block),b.raw.size()-off);
                if(!read(b.identity.address+off,block,n))return false;
                for(size_t i=0;i<n;++i) {
                    const size_t d=off+i;
                    while(method<p.patches.size() && d>=p.patches[method].instructions_offset+p.patches[method].bytes)++method;
                    if(method<p.patches.size() && d>=p.patches[method].instructions_offset)continue;
                    if(block[i]!=b.raw[d])return false;
                }
            }
        }
        return b.active && guard();
    }
    static std::vector<uint8_t> materialize(const ArtRefillBaseline& b,const FastObservation& o,const ArtRefillPlan& p) {
        if(!p.accepted())return {};
        auto result=b.raw;
        for(const auto& m:p.patches)std::memcpy(result.data()+m.instructions_offset,
            o.first.data()+b.identity.address+m.instructions_offset-o.address,m.bytes);
        return result;
    }
    static bool backing_matches(const ArtRefillBaseline& b,const MapsRegion* current,size_t count) {
        // Permission-induced VMA splitting is allowed, backing changes are not.
        for(const auto& old:b.mappings) {
            uintptr_t address=old.start;
            while(address<old.end) {
                const MapsRegion* found=nullptr;
                for(size_t i=0;i<count;++i)if(address>=current[i].start && address<current[i].end){found=current+i;break;}
                if(!found || !found->readable || found->inode!=old.inode || found->dev_major!=old.dev_major ||
                   found->dev_minor!=old.dev_minor || std::strcmp(found->path,old.path) || found->perms[3]!=old.perms[3])return false;
                if(old.inode && (old.offset+address-old.start!=found->offset+address-found->start))return false;
                address=std::min(old.end,found->end);
            }
        }
        return !b.mappings.empty();
    }
private:
    static uint32_t u32(const uint8_t* p) {uint32_t v;std::memcpy(&v,p,4);return v;}
};
