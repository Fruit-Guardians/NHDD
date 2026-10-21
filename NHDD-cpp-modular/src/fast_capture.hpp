// Frozen, bounded observations. Two matching reads are NOT an atomic snapshot.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <vector>

struct FastPage {
    size_t offset=0, length=0, first=0, second=0, changed=0;
};
struct FastObservation {
    uintptr_t address=0;
    size_t requested=0;
    bool truncated=false, generation_valid=false, deadline_hit=false;
    double begin=0, end=0;
    std::vector<uint8_t> first, second;
    std::vector<FastPage> pages;
    size_t read_bytes(unsigned pass) const {
        size_t n=0;for(const auto& p:pages)n+=pass?p.second:p.first;return n;
    }
    bool covered(unsigned pass,size_t off,size_t len) const {
        if(off>first.size() || len>first.size()-off)return false;
        const size_t end=off+len;
        for(const auto& p:pages) {
            const size_t a=std::max(off,p.offset), b=std::min(end,p.offset+p.length);
            if(a<b && b>p.offset+(pass?p.second:p.first))return false;
        }
        return true;
    }
    const char* consistency(size_t off,size_t len) const {
        if(!generation_valid)return "generation_rejected";
        if(!covered(0,off,len) || !covered(1,off,len))return "partial_reads";
        return std::memcmp(first.data()+off,second.data()+off,len)?"changed_between_reads":"two_reads_match";
    }
    // Reader returns a prefix length, zero on failure. Guard is checked before,
    // between and after passes. No bytes from another event are ever merged.
    template<class Reader,class Guard,class Clock>
    static FastObservation capture(uintptr_t address,size_t length,size_t cap,
                                   Reader read,Guard guard,Clock clock,double seconds=0.008) {
        return capture_reusing(FastObservation{},address,length,cap,read,guard,clock,seconds);
    }
    template<class Reader,class Guard,class Clock>
    static FastObservation capture_reusing(FastObservation o,uintptr_t address,size_t length,size_t cap,
                                   Reader read,Guard guard,Clock clock,double seconds=0.008) {
        o.first.clear();o.second.clear();o.pages.clear();o.truncated=false;o.generation_valid=false;
        o.deadline_hit=false;o.end=0;o.address=address;o.requested=length;o.begin=clock();
        if(!length || !cap || length>std::numeric_limits<uintptr_t>::max()-address || !guard())return o;
        const size_t n=std::min(length,cap);o.truncated=n<length;
        // clear()+resize() zeroes reused storage, including unread tails. Old
        // bytes/coverage/timestamps must never become a new observation.
        o.first.resize(n);o.second.resize(n);
        for(size_t off=0;off<n;off+=4096)o.pages.push_back({off,std::min(size_t(4096),n-off),0,0,0});
        for(unsigned pass=0;pass<2;++pass) {
            if(!guard())return o;
            auto& bytes=pass?o.second:o.first;
            for(auto& p:o.pages) {
                if(clock()-o.begin>=seconds) {o.deadline_hit=true;break;}
                const size_t got=std::min(p.length,read(address+p.offset,bytes.data()+p.offset,p.length));
                (pass?p.second:p.first)=got;
            }
        }
        o.end=clock();o.generation_valid=guard();
        for(auto& p:o.pages)for(size_t i=0;i<std::min(p.first,p.second);++i)
            p.changed+=o.first[p.offset+i]!=o.second[p.offset+i];
        return o;
    }
};
