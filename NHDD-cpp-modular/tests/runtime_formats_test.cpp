#include <cassert>
#include <cstdio>
#include "runtime_fixtures.hpp"
#include "../src/runtime_formats.hpp"

int main() {
    auto d=fixtures::dex();auto r=DexSemantics::validate(d.data(),d.size());
    if(!r.valid){r.write_json(stderr);std::fputc('\n',stderr);}
    assert(r.valid && r.checksum_valid && r.signature_valid && r.code_items==1 && r.debug_items==1);
    auto checksum_bad=d;checksum_bad[8]^=1;
    auto cr=DexSemantics::validate(checksum_bad.data(),checksum_bad.size());
    assert(cr.valid && !cr.checksum_valid && cr.signature_valid);
    auto bad=d;fixtures::put32(bad,212,0x7fffffff);assert(!DexSemantics::validate(bad.data(),bad.size()).valid);
    bad=d;fixtures::put32(bad,148,99);assert(!DexSemantics::validate(bad.data(),bad.size()).valid);
    bad=d;bad[218]=0x80;bad[219]=0x80;bad[220]=0x80;bad[221]=0x80;bad[222]=0x80;
    assert(!DexSemantics::validate(bad.data(),bad.size()).valid);
    bad=d;fixtures::put32(bad,52,0xfffffffc);assert(!DexSemantics::validate(bad.data(),bad.size()).valid);
    bad=d;bad[6]='1';assert(!DexSemantics::validate(bad.data(),bad.size()).supported);
    for(size_t n=0;n<d.size();++n)assert(!DexSemantics::validate(d.data(),n).valid);
    auto c=fixtures::cdex();assert(RuntimeFormats::inspect(c.data(),c.size()).valid);
    auto v=fixtures::vdex();auto vr=RuntimeFormats::inspect(v.data(),v.size());
    assert(vr.valid && vr.dex_count==1 && vr.embedded.size()==1 && vr.embedded[0].valid);
    bad=v;fixtures::put32(bad,28,60);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=v;fixtures::put32(bad,8,0xffffffff);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=c;fixtures::put32(bad,132,17);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=c;bad[6]='2';assert(!RuntimeFormats::inspect(bad.data(),bad.size()).supported);
    auto o=fixtures::oat();assert(RuntimeFormats::inspect(o.data(),o.size()).valid);
    for(const char* version:{"262","265","275"}) {
        bad=o;std::memcpy(bad.data()+4,version,3);assert(RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    }
    bad=o;std::memcpy(bad.data()+4,"280",3);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).supported);
    bad=o;bad.back()='x';assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    for(const auto* sample:{&c,&v,&o})for(size_t n=0;n<sample->size();++n)
        assert(!RuntimeFormats::inspect(sample->data(),n).valid);
    const auto current=fixtures::oat279();
    auto current_report=RuntimeFormats::inspect(current.data(),current.size());
    assert(current_report.valid && current_report.supported && current_report.oat.size==72);
    assert(current_report.dex_count==1 && current_report.oat.key_value_pairs==1 && current_report.extent==95);
    assert(RuntimeFormats::capture_extent(current.data(),72)==95);
    assert(RuntimeFormats::inspect(current.data(),95,true).valid);
    bad=current;fixtures::put32(bad,68,24);
    assert(RuntimeFormats::inspect(bad.data(),bad.size()).oat.key_value_pairs==1);
    assert(RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,68,24);bad[95]='x';
    assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    assert(!RuntimeFormats::inspect(current.data(),95).valid);
    for(size_t n=0;n<95;++n)assert(!RuntimeFormats::inspect(current.data(),n,true).valid);
    bad=current;fixtures::put32(bad,68,0xffffffff);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;bad[94]='x';assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,64,209);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,40,80);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,36,80);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,36,static_cast<uint32_t>(bad.size()));
    for(size_t field=40;field<=64;field+=4)fixtures::put32(bad,field,0);
    assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,24,207);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,28,209);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,12,0);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=current;fixtures::put32(bad,12,7);assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    // The real device has 1024/2048-byte reserves inside the KV store, not
    // just at its end. Nonzero reserve bytes must not become phantom keys.
    std::vector<uint8_t> padded(1280);
    std::copy(current.begin(),current.begin()+72,padded.begin());
    std::memcpy(padded.data()+72,"apex-versions\0v\0",16);
    const size_t next=72+14+1025;
    std::memcpy(padded.data()+next,current.data()+72,23);
    fixtures::put32(padded,68,static_cast<uint32_t>(next+23-72));
    fixtures::put32(padded,24,1140);fixtures::put32(padded,36,1160);
    for(size_t field=40;field<=64;field+=4)fixtures::put32(padded,field,1160);
    auto padded_report=RuntimeFormats::inspect(padded.data(),padded.size());
    assert(padded_report.valid && padded_report.oat.key_value_pairs==2);
    bad=padded;bad[90]='x';assert(!RuntimeFormats::inspect(bad.data(),bad.size()).valid);
    bad=padded;fixtures::put32(bad,68,100);assert(!RuntimeFormats::inspect(bad.data(),bad.size(),true).valid);
    assert(RuntimeFormats::inspect(current.data(),current.size(),false,0).valid);
    assert(!RuntimeFormats::inspect(current.data(),current.size(),false,1592).valid);
    bad=current;fixtures::put32(bad,32,1592);
    assert(RuntimeFormats::inspect(bad.data(),bad.size(),false,1592).valid);
    // Legacy VDEX 010 and 021 section layouts, with one embedded DEX.
    for(bool modern:{false,true}) {
        size_t offset=modern?48:28;
        std::vector<uint8_t> legacy(offset+d.size());
        std::memcpy(legacy.data(),modern?"vdex021\0":"vdex010\0",8);
        if(modern){std::memcpy(legacy.data()+8,"002\0",4);fixtures::put32(legacy,12,1);fixtures::put32(legacy,32,static_cast<uint32_t>(d.size()+4));}
        else{fixtures::put32(legacy,8,1);fixtures::put32(legacy,12,static_cast<uint32_t>(d.size()));}
        std::memcpy(legacy.data()+offset,d.data(),d.size());
        auto result=RuntimeFormats::inspect(legacy.data(),legacy.size());
        if(!result.valid){result.write_json(stderr);std::fputc('\n',stderr);}
        assert(result.valid && result.embedded.size()==1);
    }
    std::puts("runtime_formats_test: OK");
}
