#include <jni.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>

// Only changes a private mapping in this controlled app_process fixture.
extern "C" JNIEXPORT jlong JNICALL Java_ArtDiscoveryProbe_eraseHeader(JNIEnv* env,jclass,jstring path) {
    const char* target=env->GetStringUTFChars(path,nullptr);
    if(!target)return 0;
    FILE* f=std::fopen("/proc/self/maps","r");
    char line[2048];uintptr_t result=0;
    while(f && std::fgets(line,sizeof(line),f)) {
        unsigned long start=0,end=0,offset=0;char perms[8]{};int at=0;
        if(std::sscanf(line,"%lx-%lx %7s %lx %*s %*s %n",&start,&end,perms,&offset,&at)!=4)continue;
        char* name=line+at;name[std::strcspn(name,"\r\n")]=0;
        if(std::strcmp(name,target) || offset || perms[3]!='p' || end-start<112)continue;
        const long page=::sysconf(_SC_PAGESIZE);if(page<=0)break;
        if(::mprotect(reinterpret_cast<void*>(start),static_cast<size_t>(page),PROT_READ|PROT_WRITE))break;
        std::memset(reinterpret_cast<void*>(start),0,44);
        if(::mprotect(reinterpret_cast<void*>(start),static_cast<size_t>(page),PROT_READ))break;
        result=start;break;
    }
    if(f)std::fclose(f);
    env->ReleaseStringUTFChars(path,target);
    return static_cast<jlong>(result);
}
