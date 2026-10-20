#include <cassert>
#include <cstdio>
#include <limits>
#include "../src/fast_capture.hpp"

int main() {
    std::vector<uint8_t> source(9000,0x51);size_t calls=0;double clock=1;
    auto read=[&](uintptr_t address,uint8_t* p,size_t n)->size_t {
        ++calls;std::memcpy(p,source.data()+address-0x1000,n);return n;
    };
    auto guard=[]{return true;};auto now=[&]{return clock;};
    auto o=FastObservation::capture(0x1000,source.size(),source.size(),read,guard,now);
    assert(o.generation_valid && o.read_bytes(0)==9000 && o.read_bytes(1)==9000);
    assert(!std::strcmp(o.consistency(0,9000),"two_reads_match") && calls==6);
    assert(!o.covered(0,8999,2));
    calls=0;
    auto mutating=[&](uintptr_t a,uint8_t* p,size_t n)->size_t {
        if(calls==3)source[4100]^=1;
        return read(a,p,n);
    };
    o=FastObservation::capture(0x1000,9000,9000,mutating,guard,now);
    assert(!std::strcmp(o.consistency(0,9000),"changed_between_reads"));
    assert(o.pages[1].changed==1 && !std::strcmp(o.consistency(0,4096),"two_reads_match"));
    calls=0;
    auto short_read=[&](uintptr_t a,uint8_t* p,size_t n)->size_t {
        const size_t got=a==0x2000?7:n;return read(a,p,got);
    };
    o=FastObservation::capture(0x1000,9000,9000,short_read,guard,now);
    assert(!std::strcmp(o.consistency(4096,8),"partial_reads"));
    assert(o.covered(0,4096,7) && !o.covered(0,4103,1));
    o=FastObservation::capture(0x1000,9000,4096,read,guard,now);
    assert(o.truncated && o.first.size()==4096 && !o.covered(0,4095,2));
    int guards=0;
    o=FastObservation::capture(0x1000,9000,9000,read,[&]{return ++guards<4;},now);
    assert(!o.generation_valid && !std::strcmp(o.consistency(0,20),"generation_rejected"));
    o=FastObservation::capture(0x1000,9000,9000,read,[]{return false;},now);
    assert(o.first.empty());
    o=FastObservation::capture(std::numeric_limits<uintptr_t>::max()-4,8,8,read,guard,now);
    assert(o.first.empty());
    calls=0;
    o=FastObservation::capture(0x1000,9000,9000,read,guard,[&]{clock+=0.01;return clock;});
    assert(o.deadline_hit && calls==0 && !std::strcmp(o.consistency(0,9000),"partial_reads"));
    std::puts("fast_capture_test: OK (stable/change/holes/cap/generation/overflow/deadline)");
}
