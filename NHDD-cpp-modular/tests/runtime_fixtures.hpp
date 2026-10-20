#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include "../src/dex_validator.hpp"

namespace fixtures {
inline void put32(std::vector<uint8_t>& d,size_t p,uint32_t v) {
    for(unsigned i=0;i<4;++i)d[p+i]=static_cast<uint8_t>(v>>(8*i));
}
inline std::vector<uint8_t> dex() {
    std::vector<uint8_t> d(368);
    std::memcpy(d.data(),"dex\n039\0",8);
    const uint32_t counts[]={3,2,1,0,1,1}, offsets[]={112,124,132,0,144,152};
    for(unsigned i=0;i<6;++i){put32(d,56+8*i,counts[i]);put32(d,60+8*i,offsets[i]);}
    put32(d,104,184);put32(d,108,184);put32(d,52,232);
    put32(d,112,184);put32(d,116,192);put32(d,120,195);
    put32(d,124,0);put32(d,128,2);
    put32(d,132,2);put32(d,136,1);
    put32(d,148,1);
    put32(d,152,0);put32(d,156,1);put32(d,160,0xffffffffu);put32(d,168,0xffffffffu);put32(d,176,221);
    const uint8_t strings[]={6,'L','T','e','s','t',';',0,1,'m',0,1,'V',0};
    std::memcpy(d.data()+184,strings,sizeof(strings));
    d[200]=1;put32(d,208,218);put32(d,212,1);d[216]=0x0e;
    d[218]=1;d[219]=0;d[220]=0;
    const uint8_t class_data[]={0,0,1,0,0,1,0xc8,1};
    std::memcpy(d.data()+221,class_data,sizeof(class_data));
    struct Item{uint16_t type;uint32_t count,off;};
    const Item map[]={{0,1,0},{1,3,112},{2,2,124},{3,1,132},{5,1,144},{6,1,152},
        {0x2002,3,184},{0x2001,1,200},{0x2003,1,218},{0x2000,1,221},{0x1000,1,232}};
    put32(d,232,11);
    for(size_t i=0;i<11;++i){size_t p=236+12*i;d[p]=static_cast<uint8_t>(map[i].type);d[p+1]=map[i].type>>8;put32(d,p+4,map[i].count);put32(d,p+8,map[i].off);}
    DexValidator::fix_header_and_checksums(d.data(),d.size());return d;
}
inline std::vector<uint8_t> cdex() {
    std::vector<uint8_t> d(152);std::memcpy(d.data(),"cdex001\0",8);
    put32(d,32,136);put32(d,36,136);put32(d,40,0x12345678);
    put32(d,104,16);put32(d,108,136);put32(d,132,16);return d;
}
inline std::vector<uint8_t> vdex() {
    auto child=dex();std::vector<uint8_t> d(64+child.size());std::memcpy(d.data(),"vdex027\0",8);
    put32(d,8,4);
    for(unsigned i=0;i<4;++i)put32(d,12+12*i,i);
    put32(d,16,60);put32(d,20,4);put32(d,28,64);put32(d,32,static_cast<uint32_t>(child.size()));
    put32(d,40,static_cast<uint32_t>(d.size()));put32(d,52,static_cast<uint32_t>(d.size()));
    std::memcpy(d.data()+64,child.data(),child.size());return d;
}
inline std::vector<uint8_t> oat() {
    std::vector<uint8_t>d(76);std::memcpy(d.data(),"oat\n259\0",8);put32(d,12,2);put32(d,68,4);
    d[72]='k';d[74]='v';return d;
}
inline std::vector<uint8_t> oat279() {
    std::vector<uint8_t>d(208);std::memcpy(d.data(),"oat\n279\0",8);
    put32(d,12,2);put32(d,20,1);put32(d,24,96);put32(d,36,160);
    for(size_t field=40;field<=64;field+=4)put32(d,field,160+static_cast<uint32_t>(field-40));
    const char kv[]="compiler-filter\0verify\0";
    put32(d,68,sizeof(kv)-1);std::memcpy(d.data()+72,kv,sizeof(kv)-1);
    put32(d,96,6);std::memcpy(d.data()+100,"/a.dex",6);
    return d;
}
}
