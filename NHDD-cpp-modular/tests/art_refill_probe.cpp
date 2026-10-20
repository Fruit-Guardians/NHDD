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
void method(bool plain) {
    permission(base+method_offset,method_bytes,PROT_READ|PROT_WRITE);
    if(plain)std::memcpy(reinterpret_cast<void*>(base+method_offset),original.data()+method_offset,method_bytes);
    else std::memset(reinterpret_cast<void*>(base+method_offset),0,method_bytes);
    permission(base+method_offset,method_bytes,PROT_READ);
}
}
extern "C" JNIEXPORT jstring JNICALL Java_ArtRefillProbe_prepare(JNIEnv* env,jclass,jstring path,jstring prefix) {
    const char* file=env->GetStringUTFChars(path,nullptr);assert(file);payload=file;env->ReleaseStringUTFChars(path,file);
    const char* out=env->GetStringUTFChars(prefix,nullptr);assert(out);const std::string output=out;env->ReleaseStringUTFChars(prefix,out);
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
    for(const auto& m:layout.methods)if(m.instructions_offset>=2*page && m.bytes>=6 &&
        (base+m.instructions_offset)/page==(base+m.instructions_offset+m.bytes-1)/page) {
        method_offset=m.instructions_offset;method_bytes=m.bytes;break;
    }
    assert(method_offset && method_offset/page != (original.size()-1)/page);
    write_file(output+".golden.dex",original);
    permission(base,44,PROT_READ|PROT_WRITE);std::memset(reinterpret_cast<void*>(base),0,44);permission(base,44,PROT_READ);
    method(false);
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
    if(test=="outside") {
        const uintptr_t last=base+original.size()-1;
        permission(last,1,PROT_READ|PROT_WRITE);*reinterpret_cast<uint8_t*>(last)^=0x5a;permission(last,1,PROT_READ);
    }
    for(unsigned i=0;i<(test=="remap"?2u:40u);++i) {
        if(test=="remap" && i==1) {
            assert(!::munmap(reinterpret_cast<void*>(base),mapped));
            const int fd=::open(payload.c_str(),O_RDONLY|O_CLOEXEC);assert(fd>=0);
            void* replacement=::mmap(reinterpret_cast<void*>(base),mapped,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd,0);
            ::close(fd);assert(replacement==reinterpret_cast<void*>(base));
            std::memset(replacement,0,44);std::memset(reinterpret_cast<void*>(base+method_offset),0,method_bytes);
            permission(base,mapped,PROT_READ);
        }
        const unsigned durations[]={1000,5000,20000,50000};const unsigned us=test=="remap"?20000:durations[i/10];
        method(true);const double begin=boot();::usleep(us);method(false);const double end=boot();
        std::printf("WINDOW trial=%u us=%u begin=%.9f end=%.9f\n",i,us,begin,end);std::fflush(stdout);::usleep(20000);
    }
    std::puts("WINDOWS_DONE (method restored to zero, erased header retained)");std::fflush(stdout);
    ::sleep(35);
}
