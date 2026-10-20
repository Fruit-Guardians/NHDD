// Publication-thread-only, generation-owned evidence. No target-memory writes.
#pragma once
#include "art_refill.hpp"
#include "sha1.hpp"

class ArtMethodMerge {
public:
    explicit ArtMethodMerge(const ArtRefillBaseline& b):owner_(&b) {}
    struct Source {
        std::string refill;
        double capture_begin=0,capture_end=0,verified=0;
    };
    struct Variant {std::vector<uint8_t> bytes;Source source;uint64_t observations=1;};
    struct Method {DexMethodCode layout;std::vector<Variant> variants;};
    enum class Result {Invalid,Duplicate,Added,Conflict,Blocked};
    std::vector<Method> methods;
    uint64_t revision=0,published_revision=0;
    std::string session;
    bool conflicted=false;

    // Only call after the independent single-event artifact was verified and
    // committed. Retain the first source for each distinct variant, not an
    // unbounded list of identical mprotect notifications.
    Result accept(const ArtRefillBaseline& b,const FastObservation& o,const ArtRefillPlan& p,const Source& source) {
        if(&b!=owner_ || !b.active || !p.accepted() || source.refill.empty() || source.refill.size()>512)return Result::Invalid;
        if(conflicted)return Result::Blocked;
        // Re-run all capture checks; an unchecked caller cannot create evidence.
        const auto checked=ArtRefill::plan(b,o,b.identity.pid,b.identity.process_start_time,true);
        if(!checked.accepted() || checked.patches.size()!=p.patches.size())return Result::Invalid;
        for(size_t i=0;i<p.patches.size();++i)if(!same(checked.patches[i],p.patches[i]))return Result::Invalid;
        bool added=false,conflict=false;
        for(const auto& m:p.patches) {
            auto it=std::find_if(methods.begin(),methods.end(),[&](const Method& item){return same(item.layout,m);});
            if(it==methods.end()) {
                if(methods.size()>=4096)return Result::Invalid;
                methods.push_back({m,{}});it=methods.end()-1;it->variants.reserve(2);
            }
            const auto* bytes=o.first.data()+b.identity.address+m.instructions_offset-o.address;
            auto known=std::find_if(it->variants.begin(),it->variants.end(),[&](const Variant& v) {
                return v.bytes.size()==m.bytes && !std::memcmp(v.bytes.data(),bytes,m.bytes);
            });
            if(known!=it->variants.end()) {if(known->observations!=UINT64_MAX)++known->observations;continue;}
            Variant variant;variant.bytes.assign(bytes,bytes+m.bytes);variant.source=source;
            it->variants.push_back(std::move(variant));added=true;
            if(it->variants.size()==2)conflict=true;
        }
        std::sort(methods.begin(),methods.end(),[](const Method& a,const Method& c) {
            return a.layout.instructions_offset<c.layout.instructions_offset;
        });
        if(added)++revision;
        conflicted=conflict;
        return conflict?Result::Conflict:(added?Result::Added:Result::Duplicate);
    }
    bool dirty() const {return revision!=published_revision;}
    // Scheduling hint only. Matching old evidence never validates this new
    // observation's live complement/identity and must not increment proofs.
    bool known(const ArtRefillBaseline& b,const FastObservation& o,const ArtRefillPlan& p) const {
        if(&b!=owner_ || !b.active || !p.accepted())return false;
        for(const auto& m:p.patches) {
            const auto it=std::find_if(methods.begin(),methods.end(),[&](const Method& item){return same(item.layout,m);});
            if(it==methods.end())return false;
            const uintptr_t a=b.identity.address+m.instructions_offset;
            if(a<o.address || a-o.address>o.first.size() || m.bytes>o.first.size()-(a-o.address))return false;
            if(std::none_of(it->variants.begin(),it->variants.end(),[&](const Variant& v) {
                return v.bytes.size()==m.bytes && !std::memcmp(v.bytes.data(),o.first.data()+a-o.address,m.bytes);
            }))return false;
        }
        return !p.patches.empty();
    }
    std::vector<uint8_t> materialize(const ArtRefillBaseline& b) const {
        if(&b!=owner_ || !b.active || conflicted || methods.empty())return {};
        auto raw=b.raw;
        for(const auto& m:methods)std::memcpy(raw.data()+m.layout.instructions_offset,m.variants[0].bytes.data(),m.layout.bytes);
        return raw;
    }
    // Two full complement passes: outside the union must equal the immutable
    // baseline; each retained method must, as a whole, equal baseline OR its
    // accepted variant. Unknown/mixed live variants are not ignored.
    template<class Read,class Guard>
    bool compatible(const ArtRefillBaseline& b,Read read,Guard guard) const {
        if(&b!=owner_ || !b.active || conflicted || methods.empty() || !guard())return false;
        std::vector<uint8_t> live(b.raw.size());
        for(unsigned pass=0;pass<2;++pass) {
            if(!guard())return false;
            for(size_t off=0;off<live.size();off+=4096) {
                if(!b.active || !read(b.identity.address+off,live.data()+off,std::min(size_t(4096),live.size()-off)))return false;
            }
            size_t previous=0;
            for(const auto& m:methods) {
                const size_t off=m.layout.instructions_offset,n=m.layout.bytes;
                if(std::memcmp(live.data()+previous,b.raw.data()+previous,off-previous))return false;
                if(std::memcmp(live.data()+off,b.raw.data()+off,n) &&
                   std::memcmp(live.data()+off,m.variants[0].bytes.data(),n))return false;
                previous=off+n;
            }
            if(std::memcmp(live.data()+previous,b.raw.data()+previous,live.size()-previous))return false;
        }
        return b.active && guard();
    }
    static std::string digest(const std::vector<uint8_t>& bytes) {
        SHA1 sha;sha.update(bytes.data(),bytes.size());uint8_t out[20];sha.final(out);
        const char hex[]="0123456789abcdef";std::string result;
        for(uint8_t c:out){result+=hex[c>>4];result+=hex[c&15];}return result;
    }
private:
    const ArtRefillBaseline* owner_;
    static bool same(const DexMethodCode& a,const DexMethodCode& c) {
        return a.method_index==c.method_index && a.code_offset==c.code_offset &&
            a.instructions_offset==c.instructions_offset && a.bytes==c.bytes && a.code_end==c.code_end;
    }
};
