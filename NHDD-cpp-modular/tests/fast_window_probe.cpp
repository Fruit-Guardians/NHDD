// Own-process transient plaintext fixture. Never writes another process.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
#include "runtime_fixtures.hpp"

static double boot() {
    timespec t{};clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;
}
int main(int argc,char** argv) {
    if(argc!=2 && (argc!=3 || std::strcmp(argv[2],"wide")))return 1;
    const bool wide=argc==3;
    ::prctl(PR_SET_NAME,"nhdd-fast-probe",0,0,0);
    const std::string prefix=argv[1];
    const std::string trigger=prefix+".go";
    auto dex=fixtures::dex();
    auto* arena=static_cast<uint8_t*>(::mmap(nullptr,4*1024*1024,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    assert(arena!=MAP_FAILED);
    std::printf("READY pid=%d arena=%p trigger=%s\n",getpid(),arena,trigger.c_str());std::fflush(stdout);
    for(unsigned i=0;::access(trigger.c_str(),F_OK)!=0;++i) {if(i>=3000)return 2;::usleep(10000);}
    for(unsigned i=0;i<40;++i) {
        const unsigned windows[]={1000,5000,20000,50000};const unsigned us=windows[i/10];
        uint8_t* page=arena+i*65536;
        const size_t span=wide?8192:4096,offset=wide?3968:0;
        assert(::mprotect(page,span,PROT_READ|PROT_WRITE)==0);
        // Unique valid string/checksum per trial; the source heap is not the tested address.
        dex[193]=static_cast<uint8_t>('!'+i);
        DexValidator::fix_header_and_checksums(dex.data(),dex.size());
        const auto golden=prefix+"_"+std::to_string(i)+".dex";
        FILE* f=std::fopen(golden.c_str(),"wb");assert(f);
        assert(std::fwrite(dex.data(),1,dex.size(),f)==dex.size());assert(!std::fclose(f));
        std::memcpy(page+offset,dex.data(),dex.size());
        assert(::mprotect(page,span,PROT_READ)==0);
        const double begin=boot();::usleep(us);
        assert(::mprotect(page,span,PROT_READ|PROT_WRITE)==0);
        std::memset(page,0xa5,span);
        const double end=boot();assert(::munmap(page,span)==0);
        std::printf("WINDOW trial=%u us=%u address=0x%llx begin=%.9f end=%.9f\n",i,us,
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(page+offset)),begin,end);std::fflush(stdout);
        ::usleep(20000);
    }
    // Remain alive so queued observations can be checked/published after the windows close.
    std::puts("WINDOWS_DONE");std::fflush(stdout);::sleep(35);
    assert(::munmap(arena,4*1024*1024)==0);
}
