// Android integration: synthetic trace records only read this test's own page.
#include <cassert>
#include <dirent.h>
#include <sys/mman.h>
#include "../src/fast_capture_service.hpp"
int main() {
    char directory[]="/data/local/tmp/nhdd-fast-worker-XXXXXX";assert(::mkdtemp(directory));
    auto* page=static_cast<uint8_t*>(::mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    assert(page!=MAP_FAILED);std::memset(page,0x5a,4096);
    const int pid=::getpid();FastCaptureService service(std::to_string(pid),true,4096,false);
    service.targets({pid});assert(service.start_publication(directory));assert(!service.start_publication(directory));
#if defined(__aarch64__)
    const char* protect="226";
#elif defined(__arm__)
    const char* protect="125";
#else
    const char* protect="10";
#endif
    for(unsigned i=0;i<100;++i) {
        timespec clock{};assert(!::clock_gettime(CLOCK_BOOTTIME,&clock));
        const double stamp=double(clock.tv_sec)+double(clock.tv_nsec)*1e-9;
        char entry[512];std::snprintf(entry,sizeof(entry),"worker-%d [000] .... %.9f: sys_enter: NR %s (%llx, 1000, 1, 0, 0, 0)",
            pid,stamp,protect,static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(page)));
        service.line(entry);
    }
    service.stop_publication();service.stop_publication();service.diagnostics();
    DIR* dir=::opendir((std::string(directory)+"/fast").c_str());assert(dir);size_t first=0,second=0,json=0;
    while(auto* entry=::readdir(dir)) {
        const std::string name=entry->d_name;
        if(name.size()>10 && name.substr(name.size()-10)==".first.bin")++first;
        if(name.size()>11 && name.substr(name.size()-11)==".second.bin")++second;
        if(name.size()>5 && name.substr(name.size()-5)==".json")++json;
    }
    ::closedir(dir);assert(first==100 && second==100 && json==100);
    assert(!service.start_publication(directory));assert(!::munmap(page,4096));
    std::printf("fast_publication_worker_test: OK (100 queued observations/drain/idempotent stop/no double start) evidence=%s\n",directory);
}
