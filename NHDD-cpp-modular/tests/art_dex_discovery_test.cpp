#include <cassert>
#include <cstdio>
#include "../src/art_dex_discovery.hpp"
#include "runtime_fixtures.hpp"

int main() {
    std::vector<uint8_t> lib(0x42000),heap(4096),dex=fixtures::dex();
    const uintptr_t lb=0x100000,hb=0x200000,db=0x300000,vt=lb+0x3c2e8,object=hb+256;
    auto put64=[](std::vector<uint8_t>& b,size_t p,uint64_t v){std::memcpy(b.data()+p,&v,8);};
    ArtDexDiscovery::ElfHeader eh{};std::memcpy(eh.e_ident,"\177ELF",4);eh.e_ident[4]=2;
    eh.e_ident[5]=1;eh.e_machine=183;eh.e_phoff=64;
    eh.e_phentsize=sizeof(ArtDexDiscovery::ElfProgram);eh.e_phnum=2;std::memcpy(lib.data(),&eh,sizeof(eh));
    ArtDexDiscovery::ElfProgram ph[2]{};ph[0].p_type=1;ph[1].p_type=4;ph[1].p_vaddr=512;ph[1].p_filesz=36;
    std::memcpy(lib.data()+64,ph,sizeof(ph));fixtures::put32(lib,512,4);fixtures::put32(lib,516,16);
    fixtures::put32(lib,520,3);std::memcpy(lib.data()+524,"GNU\0",4);
    const std::string id=ArtDexDiscovery::kBuildId;
    for(size_t i=0;i<16;++i)lib[528+i]=static_cast<uint8_t>(std::stoul(id.substr(i*2,2),nullptr,16));
    put64(lib,0x3c2e8,lb+0x15000);put64(lib,0x3c2f0,lb+0x15004);
    put64(heap,256,vt);put64(heap,264,db);put64(heap,280,db);put64(heap,288,dex.size());put64(heap,328,db);
    const size_t offsets[]={60,68,84,92,76,100};
    for(size_t i=0;i<6;++i)put64(heap,256+80+i*8,db+ArtDexDiscovery::u32(dex.data()+offsets[i]));
    MapsRegion maps[5]{};
    auto region=[&](size_t i,uintptr_t begin,size_t size,const char* path,bool write=false,bool exec=false) {
        maps[i].start=begin;maps[i].end=begin+size;maps[i].readable=true;
        maps[i].writable=write;maps[i].executable=exec;std::snprintf(maps[i].path,sizeof(maps[i].path),"%s",path);
    };
    region(0,lb,0x14000,"/apex/com.android.art/lib64/libdexfile.so");
    region(1,lb+0x14000,0x28000,"/apex/com.android.art/lib64/libdexfile.so",false,true);
    region(2,lb+0x3c000,0x6000,"/apex/com.android.art/lib64/libdexfile.so");maps[1].offset=0x14000;maps[2].offset=0x3c000;
    region(3,hb,heap.size(),"[anon:scudo:primary]",true);region(4,db,dex.size(),"/data/local/tmp/payload.dex");
    auto read=[&](uintptr_t addr,void* dst,size_t size) {
        for(const auto& part:std::vector<std::pair<uintptr_t,const std::vector<uint8_t>*>>{{lb,&lib},{hb,&heap},{db,&dex}})
            if(addr>=part.first && addr-part.first<=part.second->size() && size<=part.second->size()-(addr-part.first)) {
                std::memcpy(dst,part.second->data()+addr-part.first,size);return true;
            }
        return false;
    };
    ArtDexCandidate c;assert(ArtDexDiscovery::validate(read,maps,5,vt,object,c));
    unsigned found=0;auto emit=[&](const ArtDexCandidate& x){++found;assert(x.begin==db && x.object==object);};
    auto stats=ArtDexDiscovery::scan(read,maps,5,4096,0,emit);
    assert(stats.supported && stats.accepted==1 && found==1 && !stats.exhausted);
    std::fill(dex.begin(),dex.begin()+44,0);
    assert(ArtDexDiscovery::validate(read,maps,5,vt,object,c));
    assert(c.size==dex.size() && !ArtDexDiscovery::u32(c.header.data()+40));
    put64(heap,256+80,db+120);assert(!ArtDexDiscovery::validate(read,maps,5,vt,object,c));
    put64(heap,256+80,db+112);
    put64(heap,264,0xb400000000000000ULL|db);assert(ArtDexDiscovery::validate(read,maps,5,vt,object,c));
    put64(heap,264,db+8);assert(!ArtDexDiscovery::validate(read,maps,5,vt,object,c));put64(heap,264,db);
    fixtures::put32(dex,232,0xffffffff);assert(!ArtDexDiscovery::validate(read,maps,5,vt,object,c));
    dex=fixtures::dex();maps[4].end--;assert(!ArtDexDiscovery::validate(read,maps,5,vt,object,c));maps[4].end++;
    lib[528]^=1;stats=ArtDexDiscovery::scan(read,maps,5,4096,0,emit);
    assert(!stats.supported && stats.status=="unsupported_libdexfile_build_id");lib[528]^=1;
    maps[2].writable=true;stats=ArtDexDiscovery::scan(read,maps,5,4096,0,emit);
    assert(!stats.supported && stats.status=="invalid_runtime_vtable");maps[2].writable=false;
    put64(lib,0x3c2e8,db);stats=ArtDexDiscovery::scan(read,maps,5,4096,0,emit);
    assert(!stats.supported && stats.status=="invalid_vtable_code");put64(lib,0x3c2e8,lb+0x15000);
    uintptr_t resume=0;found=0;
    for(unsigned i=0;i<6;++i){stats=ArtDexDiscovery::scan(read,maps,5,64,resume,emit);assert(stats.exhausted);resume=stats.next;}
    assert(found==1);
    auto mutate=[&](uintptr_t a,void* dst,size_t size){bool ok=read(a,dst,size);if(a==object)heap[256+40]^=1;return ok;};
    assert(!ArtDexDiscovery::validate(mutate,maps,5,vt,object,c));
    std::puts("art_dex_discovery_test: OK");
}
