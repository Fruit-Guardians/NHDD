// Android integration: synthetic trace records only read this test's own page.
#define NHDD_TESTING
#include <cassert>
#include <dirent.h>
#include <sys/mman.h>
#include "../src/fast_capture_service.hpp"
struct CaptureTestAccess {
    static void pending_invalid_merge(FastCaptureService& service) {
        auto b=std::make_shared<ArtRefillBaseline>();b->identity.pid=::getpid();
        const auto pid=std::to_string(::getpid());b->identity.process_start_time=read_process_start_time_inline(pid.c_str());
        b->identity.address=0x10000;b->identity.dex_size=8192;b->raw.resize(8192);
        b->merge=std::make_shared<ArtMethodMerge>(*b);b->merge->revision=2;
        b->merge->methods.resize(2);b->merge->publication_deferred=true;
        // Deliberately NOT a valid ART identity: the later flush must reject
        // this white-box scheduling fixture and never publish a composite.
        service.refill_.baselines_.push_back(b);service.refill_.coalesced_pending_=true;
    }
    static void check_drained(FastCaptureService& service) {
        assert(service.merge_flush_jobs_==1 && service.schedule_.items==0);
        assert(service.refill_.merge_incompatible_==1 && service.refill_.merge_published_==0);
        const auto n=service.buffer_pool_.capacity();
        for(unsigned i=0;i<n;++i)assert(service.buffer_pool_.take().first.capacity()==4096);
        assert(!service.buffer_pool_.take().first.capacity()); // No empty flush buffer poisoned the pool.
    }
};
int main() {
    const int original_nice=::getpriority(PRIO_PROCESS,static_cast<id_t>(::syscall(SYS_gettid)));
    char directory[]="/data/local/tmp/nhdd-fast-worker-XXXXXX";assert(::mkdtemp(directory));
    auto* page=static_cast<uint8_t*>(::mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    assert(page!=MAP_FAILED);std::memset(page,0x5a,4096);
    const int pid=::getpid();FastCaptureService service(std::to_string(pid),true,4096,false);
    service.targets({pid});
    CaptureTestAccess::pending_invalid_merge(service); // Before start: no race with publisher-owned state.
#if defined(__aarch64__)
    const char* protect="226";
#elif defined(__arm__)
    const char* protect="125";
#else
    const char* protect="10";
#endif
    // Real tracefs can deliver an entry before the publisher starts. Storage
    // must already exist; retain the early frame and drain it after start.
    for(unsigned i=0;i<101;++i) {
        timespec clock{};assert(!::clock_gettime(CLOCK_BOOTTIME,&clock));
        const double stamp=double(clock.tv_sec)+double(clock.tv_nsec)*1e-9;
        char entry[512];std::snprintf(entry,sizeof(entry),"worker-%d [000] .... %.9f: sys_enter: NR %s (%llx, 1000, 1, 0, 0, 0)",
            pid,stamp,protect,static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(page)));
        service.line(entry);
        if(i==0){assert(service.start_publication(directory));assert(!service.start_publication(directory));}
    }
    service.stop_publication();service.stop_publication();service.diagnostics();
    CaptureTestAccess::check_drained(service);
    assert(::getpriority(PRIO_PROCESS,static_cast<id_t>(::syscall(SYS_gettid)))==original_nice);
    DIR* dir=::opendir((std::string(directory)+"/fast").c_str());assert(dir);size_t first=0,second=0,json=0;
    while(auto* entry=::readdir(dir)) {
        const std::string name=entry->d_name;
        if(name.size()>10 && name.substr(name.size()-10)==".first.bin")++first;
        if(name.size()>11 && name.substr(name.size()-11)==".second.bin")++second;
        if(name.size()>5 && name.substr(name.size()-5)==".json")++json;
    }
    ::closedir(dir);assert(first==101 && second==101 && json==101);
    assert(!service.start_publication(directory));assert(!::munmap(page,4096));
    std::printf("fast_publication_worker_test: OK (101 observations/early entry/drain/idempotent stop/no double start) evidence=%s\n",directory);
}
