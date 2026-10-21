#include <jni.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "../src/art_refill.hpp"

namespace {
uintptr_t base=0;size_t mapped=0,method_offset=0,method_bytes=0;
std::vector<uint8_t> original;std::string payload;
std::vector<DexMethodCode> selected;
double boot() {timespec t{};clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;}
void write_file(const std::string& path,const std::vector<uint8_t>& bytes) {
    FILE* f=std::fopen(path.c_str(),"wb");assert(f);
    assert(std::fwrite(bytes.data(),1,bytes.size(),f)==bytes.size());assert(!std::fclose(f));
}
void permission(uintptr_t address,size_t length,int protection) {
    const size_t page=static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    const uintptr_t start=address-address%page,end=(address+length+page-1)/page*page;
    assert(!::mprotect(reinterpret_cast<void*>(start),end-start,protection));
}
void method(bool plain,bool alternate=false) {
    permission(base+method_offset,method_bytes,PROT_READ|PROT_WRITE);
    if(plain)std::memcpy(reinterpret_cast<void*>(base+method_offset),original.data()+method_offset,method_bytes);
    else std::memset(reinterpret_cast<void*>(base+method_offset),0,method_bytes);
    // Valid const/lit8 operand difference in this fixture's marker method;
    // never executed here, only used to test distinct-variant quarantine.
    if(plain && alternate)reinterpret_cast<uint8_t*>(base+method_offset)[method_bytes-3]^=1;
    permission(base+method_offset,method_bytes,PROT_READ);
}
}
extern "C" JNIEXPORT jstring JNICALL Java_ArtRefillProbe_prepare(JNIEnv* env,jclass,jstring path,jstring prefix,jstring mode) {
    const char* file=env->GetStringUTFChars(path,nullptr);assert(file);payload=file;env->ReleaseStringUTFChars(path,file);
    const char* out=env->GetStringUTFChars(prefix,nullptr);assert(out);const std::string output=out;env->ReleaseStringUTFChars(prefix,out);
    const char* mode_chars=env->GetStringUTFChars(mode,nullptr);assert(mode_chars);const std::string test=mode_chars;
    env->ReleaseStringUTFChars(mode,mode_chars);
    const bool short_burst=test=="short-burst";
    const bool burst=test=="burst" || short_burst;
    const bool multi=test.find("multi")==0 || test=="conflict" || burst;
    FILE* maps=std::fopen("/proc/self/maps","r");assert(maps);char line[2048];
    while(std::fgets(line,sizeof(line),maps)) {
        unsigned long start=0,end=0,offset=0;char perms[8]{};int at=0;
        if(std::sscanf(line,"%lx-%lx %7s %lx %*s %*s %n",&start,&end,perms,&offset,&at)!=4)continue;
        char* name=line+at;name[std::strcspn(name,"\r\n")]=0;
        if(!std::strcmp(name,payload.c_str()) && !offset && perms[3]=='p') {base=start;mapped=end-start;break;}
    }
    std::fclose(maps);assert(base && mapped>=112);
    uint32_t size=0;std::memcpy(&size,reinterpret_cast<const void*>(base+32),4);assert(size<=mapped);
    original.assign(reinterpret_cast<const uint8_t*>(base),reinterpret_cast<const uint8_t*>(base)+size);
    ArtRefillBaseline layout;layout.raw=original;layout.identity.dex_size=size;assert(ArtRefill::layout(layout));
    const size_t page=static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    unsigned eligible=0;
    for(const auto& m:layout.methods)if(m.instructions_offset>=2*page && m.bytes>=6 &&
        (base+m.instructions_offset)/page==(base+m.instructions_offset+m.bytes-1)/page) {
        if(burst) {if(eligible++%(short_burst?6:12))continue;}
        else if(!selected.empty() && m.instructions_offset/page==selected.back().instructions_offset/page)continue;
        selected.push_back(m);if(selected.size()==(burst?(short_burst?64u:32u):(multi?3u:1u)))break;
    }
    assert(selected.size()==(burst?(short_burst?64u:32u):(multi?3u:1u)));
    method_offset=selected[0].instructions_offset;method_bytes=selected[0].bytes;
    assert(method_offset && method_offset/page != (original.size()-1)/page);
    write_file(output+".golden.dex",original);
    permission(base,44,PROT_READ|PROT_WRITE);std::memset(reinterpret_cast<void*>(base),0,44);permission(base,44,PROT_READ);
    for(const auto& m:selected) {
        method_offset=m.instructions_offset;method_bytes=m.bytes;method(false);
        uint32_t method_ids=0,string_ids=0,name_index=0,name_offset=0;
        std::memcpy(&method_ids,original.data()+92,4);std::memcpy(&string_ids,original.data()+60,4);
        std::memcpy(&name_index,original.data()+method_ids+8*m.method_index+4,4);
        std::memcpy(&name_offset,original.data()+string_ids+4*name_index,4);
        while(original[name_offset++]&128){}
        std::printf("METHOD index=%u offset=%u bytes=%u name=%s\n",m.method_index,m.instructions_offset,m.bytes,
            reinterpret_cast<const char*>(original.data()+name_offset));
    }
    method_offset=selected[0].instructions_offset;method_bytes=selected[0].bytes;
    std::vector<uint8_t> baseline(reinterpret_cast<const uint8_t*>(base),reinterpret_cast<const uint8_t*>(base)+size);
    write_file(output+".baseline.dex",baseline);
    char info[320];std::snprintf(info,sizeof(info),"pid=%d payload_address=0x%llx size=%u method_offset=%zu method_bytes=%zu header_erased=44",
        ::getpid(),static_cast<unsigned long long>(base),size,method_offset,method_bytes);
    return env->NewStringUTF(info);
}
extern "C" JNIEXPORT void JNICALL Java_ArtRefillProbe_windows(JNIEnv* env,jclass,jstring prefix,jstring mode) {
    const char* p=env->GetStringUTFChars(prefix,nullptr);assert(p);const auto trigger=std::string(p)+".go";env->ReleaseStringUTFChars(prefix,p);
    const char* m=env->GetStringUTFChars(mode,nullptr);assert(m);const std::string test=m;env->ReleaseStringUTFChars(mode,m);
    for(unsigned i=0;::access(trigger.c_str(),F_OK);++i) {assert(i<6000);::usleep(10000);}
    const bool multi=selected.size()>1;
    if(test=="outside" || test=="multi-outside") {
        const uintptr_t last=base+original.size()-1;
        permission(last,1,PROT_READ|PROT_WRITE);*reinterpret_cast<uint8_t*>(last)^=0x5a;permission(last,1,PROT_READ);
    }
    const bool short_burst=test=="short-burst";
    const bool burst=test=="burst" || short_burst;
    const unsigned trials=burst?(short_burst?64u:32u):(multi?(test=="conflict"?130u:120u):(test=="remap"?2u:40u));
    for(unsigned i=0;i<trials;++i) {
        const size_t index=burst?i:(multi?(i<120?i/40:0):0);
        method_offset=selected[index].instructions_offset;method_bytes=selected[index].bytes;
        if((test=="remap" && i==1) || (test=="multi-remap" && i==40)) {
            assert(!::munmap(reinterpret_cast<void*>(base),mapped));
            const int fd=::open(payload.c_str(),O_RDONLY|O_CLOEXEC);assert(fd>=0);
            void* replacement=::mmap(reinterpret_cast<void*>(base),mapped,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd,0);
            ::close(fd);assert(replacement==reinterpret_cast<void*>(base));
            std::memset(replacement,0,44);
            for(const auto& item:selected)std::memset(reinterpret_cast<void*>(base+item.instructions_offset),0,item.bytes);
            permission(base,mapped,PROT_READ);
            // Allow fresh discovery; no first-method windows follow the remap.
            if(multi)::usleep(1500000);
        }
        const unsigned durations[]={1000,5000,20000,50000};
        const unsigned us=(test=="remap" || i>=120)?20000:durations[short_burst?i%2:(burst?i%4:(i%40)/10)];
        method(true,i>=120);const double begin=boot();::usleep(us);method(false);const double end=boot();
        std::printf("WINDOW trial=%u us=%u begin=%.9f end=%.9f method=%zu offset=%zu alternate=%u\n",
            i,us,begin,end,index,method_offset,i>=120?1u:0u);std::fflush(stdout);::usleep(burst?2000:20000);
    }
    std::puts("WINDOWS_DONE (method restored to zero, erased header retained)");std::fflush(stdout);
    ::sleep(35);
}
