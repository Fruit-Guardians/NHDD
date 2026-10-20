#include <cassert>
#include <cstdio>
#include "../src/art_method_merge.hpp"

int main() {
    ArtRefillBaseline b;b.identity.pid=42;b.identity.process_start_time=100;b.identity.address=0x10000;
    b.raw.resize(8192);b.identity.dex_size=8192;b.armed_boot=1;
    b.methods={{1,200,216,4,220},{2,4080,4096,8,4104},{3,6000,6016,2,6018}};
    ArtMethodMerge merge(b);auto memory=b.raw;
    auto read=[&](uintptr_t a,void* out,size_t n) {
        if(a<b.identity.address || a-b.identity.address>memory.size() || n>memory.size()-(a-b.identity.address))return false;
        std::memcpy(out,memory.data()+a-b.identity.address,n);return true;
    };
    auto capture=[&](size_t index,uint8_t value) {
        const auto& m=b.methods[index];memory=b.raw;
        std::fill(memory.begin()+m.instructions_offset,memory.begin()+m.instructions_offset+m.bytes,value);
        auto reader=[&](uintptr_t a,uint8_t* out,size_t n)->size_t{return read(a,out,n)?n:0;};
        return FastObservation::capture(b.identity.address+m.instructions_offset,m.bytes,m.bytes,reader,[]{return true;},[]{return 2.;});
    };
    const auto source=ArtMethodMerge::Source{"first.refill.json",2,2,3};
    auto first=capture(0,1);auto plan=ArtRefill::plan(b,first,42,100,true);assert(plan.accepted());
    assert(merge.accept(b,first,plan,source)==ArtMethodMerge::Result::Added);
    assert(merge.known(b,first,plan));
    assert(merge.accept(b,first,plan,source)==ArtMethodMerge::Result::Duplicate);
    assert(merge.revision==1 && merge.methods.size()==1 && merge.methods[0].variants[0].observations==2);
    auto second=capture(1,2);plan=ArtRefill::plan(b,second,42,100,true);
    assert(!merge.known(b,second,plan));
    assert(merge.accept(b,second,plan,{"second.refill.json",4,4,5})==ArtMethodMerge::Result::Added);
    assert(merge.methods.size()==2 && merge.dirty());memory=b.raw;
    assert(merge.compatible(b,read,[]{return true;}));
    auto raw=merge.materialize(b);assert(raw[216]==1 && raw[4096]==2 && raw[6016]==0);
    assert(merge.methods[0].variants[0].source.refill=="first.refill.json");
    assert(merge.methods[1].variants[0].source.capture_begin==4);
    assert(ArtMethodMerge::digest(merge.methods[0].variants[0].bytes).size()==40);
    memory=raw;assert(merge.compatible(b,read,[]{return true;}));
    memory[4097]=3;assert(!merge.compatible(b,read,[]{return true;})); // unknown whole/mixed variant
    memory=raw;memory[300]^=1;assert(!merge.compatible(b,read,[]{return true;}));
    memory=b.raw;unsigned reads=0;
    auto mutate=[&](uintptr_t a,void* out,size_t n) {if(++reads==3)memory[300]=1;return read(a,out,n);};
    assert(!merge.compatible(b,mutate,[]{return true;}));
    memory=b.raw;assert(!merge.compatible(b,read,[]{return false;}));
    ArtRefillBaseline other;other.identity=b.identity;other.raw=b.raw;other.methods=b.methods;
    assert(merge.materialize(other).empty());
    assert(merge.accept(other,second,plan,source)==ArtMethodMerge::Result::Invalid);
    auto forged=plan;forged.patches[0].bytes--;
    assert(merge.accept(b,second,forged,source)==ArtMethodMerge::Result::Invalid);
    assert(merge.accept(b,second,plan,{std::string(513,'x'),2,2,3})==ArtMethodMerge::Result::Invalid);
    auto third=capture(2,3);plan=ArtRefill::plan(b,third,42,100,true);
    assert(merge.accept(b,third,plan,{"third.refill.json",6,6,7})==ArtMethodMerge::Result::Added);
    raw=merge.materialize(b);assert(raw[6016]==3 && raw[216]==1 && raw[4096]==2);
    // A conflicting same-method variant must freeze the WHOLE generation, not
    // choose whichever appears newer, nor affect the previously exported bytes.
    auto alternate=capture(0,4);plan=ArtRefill::plan(b,alternate,42,100,true);
    assert(!merge.known(b,alternate,plan));
    assert(merge.accept(b,alternate,plan,{"conflict.refill.json",8,8,9})==ArtMethodMerge::Result::Conflict);
    assert(merge.conflicted && merge.methods[0].variants.size()==2 && merge.revision==4);
    assert(merge.materialize(b).empty() && !merge.compatible(b,read,[]{return true;}));
    assert(raw[216]==1 && merge.methods[0].variants[1].bytes[0]==4);
    assert(merge.accept(b,first,ArtRefill::plan(b,first,42,100,true),source)==ArtMethodMerge::Result::Blocked);
    b.active=false;assert(merge.accept(b,first,plan,source)==ArtMethodMerge::Result::Invalid);
    ArtMethodMerge fresh(other);assert(fresh.methods.empty() && !fresh.conflicted && fresh.revision==0);
    std::puts("art_method_merge_test: OK (3 windows/dedup/provenance/conflict/generation/complement/unknown versions)");
}
