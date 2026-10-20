#include <cassert>
#include <cstdio>
#include "runtime_fixtures.hpp"
#include "../src/art_refill.hpp"

int main() {
    ArtRefillBaseline b;b.identity.pid=42;b.identity.process_start_time=100;
    b.identity.address=0x10000;b.raw=fixtures::dex();b.identity.dex_size=static_cast<uint32_t>(b.raw.size());
    const auto golden=b.raw;
    auto version_erased=golden;std::memset(version_erased.data()+4,0,3);
    assert(!ArtRefill::magic_version_valid(version_erased));
    assert(ArtRefill::magic_version_valid(ArtRefill::normalize(version_erased)));
    std::memset(b.raw.data(),0,44);b.raw[216]=0;b.armed_boot=1;
    assert(ArtRefill::layout(b) && b.methods.size()==1 && b.methods[0].instructions_offset==216 && b.methods[0].bytes==2);
    std::vector<uint8_t> memory=b.raw;memory[216]=golden[216];
    auto read=[&](uintptr_t address,uint8_t* p,size_t n)->size_t {
        if(address<b.identity.address || address-b.identity.address>memory.size() ||
            n>memory.size()-(address-b.identity.address))return 0;
        std::memcpy(p,memory.data()+address-b.identity.address,n);return n;
    };
    auto observe=[&](uintptr_t address,size_t n) {
        return FastObservation::capture(address,n,n,read,[]{return true;},[]{return 2.0;});
    };
    const auto o=observe(b.identity.address+216,2);
    auto p=ArtRefill::plan(b,o,42,100,true);
    assert(p.accepted() && p.patches.size()==1 && p.changed_bytes==1);
    auto refilled=ArtRefill::materialize(b,o,p);
    assert(!std::memcmp(refilled.data(),b.raw.data(),216) && refilled[216]==0x0e && refilled[0]==0);
    assert(!std::memcmp(refilled.data()+44,golden.data()+44,golden.size()-44));
    auto normalized=ArtRefill::normalize(refilled);
    assert(DexSemantics::validate(normalized.data(),normalized.size()).valid);
    // Re-encryption after capture does not overwrite the frozen method bytes.
    memory=b.raw;
    auto full_read=[&](uintptr_t a,void* out,size_t n){return read(a,static_cast<uint8_t*>(out),n)==n;};
    assert(ArtRefill::complement(b,p,full_read,[]{return true;}));
    assert(ArtRefill::materialize(b,o,p)==refilled);
    memory[185]^=1;
    assert(!ArtRefill::complement(b,p,full_read,[]{return true;}));memory=b.raw;
    unsigned calls=0;
    auto mutate_between=[&](uintptr_t a,void* out,size_t n) {
        if(++calls==2)memory[185]^=1;
        return full_read(a,out,n);
    };
    assert(!ArtRefill::complement(b,p,mutate_between,[]{return true;}));memory=b.raw;
    int guards=0;assert(!ArtRefill::complement(b,p,full_read,[&]{return ++guards<3;}));
    assert(!ArtRefill::plan(b,o,43,100,true).accepted());
    assert(!ArtRefill::plan(b,o,42,101,true).accepted());
    assert(!ArtRefill::plan(b,o,42,100,false).accepted());
    auto bad=o;bad.second[0]^=1;
    assert(ArtRefill::plan(b,bad,42,100,true).reason=="method_changed_between_reads");
    bad=o;bad.pages[0].second=1;
    assert(ArtRefill::plan(b,bad,42,100,true).reason=="fragment_holes");
    bad=o;bad.begin=0.5;assert(!ArtRefill::plan(b,bad,42,100,true).accepted());
    memory[216]=golden[216];memory[176]^=1;
    bad=observe(b.identity.address,b.raw.size());
    assert(ArtRefill::plan(b,bad,42,100,true).reason=="fragment_non_method_changed");memory=b.raw;
    memory[216]=golden[216];bad=observe(b.identity.address+216,1);
    assert(!ArtRefill::plan(b,bad,42,100,true).accepted());
    b.active=false;assert(!ArtRefill::plan(b,o,42,100,true).accepted());b.active=true;
    // A baseline first seen in plaintext must not be "repaired" back to zeros.
    b.raw[216]=0x0e;memory=b.raw;memory[216]=0;
    bad=observe(b.identity.address+216,2);
    assert(ArtRefill::plan(b,bad,42,100,true).reason=="zero_instruction_replacement");b.raw[216]=0;
    MapsRegion original{};original.start=0x1000;original.end=0x3000;original.offset=0x100;
    original.inode=7;original.readable=true;std::strcpy(original.perms,"r--p");std::strcpy(original.path,"/data/a.dex");
    b.mappings={original};MapsRegion split[]={original,original};split[0].end=0x2000;
    split[1].start=0x2000;split[1].offset=0x1100;std::strcpy(split[1].perms,"rw-p");
    assert(ArtRefill::backing_matches(b,split,2));
    split[1].inode=8;assert(!ArtRefill::backing_matches(b,split,2));split[1].inode=7;
    split[1].offset=0;assert(!ArtRefill::backing_matches(b,split,2));split[1].offset=0x1100;
    split[1].readable=false;assert(!ArtRefill::backing_matches(b,split,2));
    // No unsupported/invalid or instruction-to-structural-region layout is armed.
    b.raw=golden;b.raw[232]=0;assert(!ArtRefill::layout(b));
    b.raw=golden;fixtures::put32(b.raw,212,50);assert(!ArtRefill::layout(b));
    std::puts("art_refill_test: OK (erased header/method-only/anchors/generation/complement/holes/VMA splits)");
}
