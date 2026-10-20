// Controlled native fixture for real syscall capture and package descendant tests.
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "runtime_fixtures.hpp"

static void write_fixture(const char* base,const char* suffix,const std::vector<uint8_t>& data) {
    const std::string path=std::string(base)+suffix;
    FILE* f=std::fopen(path.c_str(),"wb");assert(f);
    assert(std::fwrite(data.data(),1,data.size(),f)==data.size());assert(std::fclose(f)==0);
}
int main(int argc,char** argv) {
    if(argc!=2)return 1;
    const size_t capacity=std::strlen(argv[0]);
    const char* name="com.nhdd.captureprobe";
    assert(capacity>=std::strlen(name));
    std::memset(argv[0],0,capacity);std::memcpy(argv[0],name,std::strlen(name));
    ::prctl(PR_SET_NAME,"nhdd-probe",0,0,0);
    auto dex=fixtures::dex(),cdex=fixtures::cdex(),vdex=fixtures::vdex(),oat=fixtures::oat();
    write_fixture(argv[1],".dex",dex);write_fixture(argv[1],".cdex",cdex);
    write_fixture(argv[1],".vdex",vdex);write_fixture(argv[1],".oat",oat);
    auto bad=dex;fixtures::put32(bad,212,0x7fffffff);write_fixture(argv[1],".bad.dex",bad);
    std::printf("PROBE pid=%d\n",::getpid());std::fflush(stdout);
    ::sleep(3);
    // Fork a process whose command no longer matches the package name.
    const pid_t child=::fork();assert(child>=0);
    if(child==0) {
        std::memset(argv[0],0,capacity);std::memcpy(argv[0],"native-helper",13);
        ::prctl(PR_SET_NAME,"nhdd-child",0,0,0);
    }
    for(const auto* bytes:{&dex,&cdex,&vdex,&oat}) {
        void* p=::mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        assert(p!=MAP_FAILED);
        std::memcpy(p,bytes->data(),bytes->size());
        assert(::mprotect(p,4096,PROT_READ|PROT_EXEC)==0);
        ::usleep(600000);
        assert(::mprotect(p,4096,PROT_READ|PROT_WRITE)==0);
        void* moved=::mremap(p,4096,8192,MREMAP_MAYMOVE);assert(moved!=MAP_FAILED);
        ::usleep(400000);
        assert(::munmap(moved,8192)==0);
        ::usleep(100000);
    }
    ::sleep(3);
    if(child>0){int status=0;assert(::waitpid(child,&status,0)==child);}
    return 0;
}
