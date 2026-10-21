// Fault injection is confined to this executable; production has no bypass.
#define NHDD_TESTING
#include <cassert>
#include <cerrno>
#include <cstring>
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
static unsigned mode=0,vm_calls=0;
static ssize_t injected_vm_read(pid_t pid,const iovec* local,unsigned long nl,const iovec* remote,unsigned long nr,unsigned long flags) {
    ++vm_calls;
    if(mode==1 || mode==3){errno=EIO;return -1;}
    if(mode==2){assert(nl==1 && nr==1);std::memcpy(local->iov_base,remote->iov_base,3);return 3;}
    return ::process_vm_readv(pid,local,nl,remote,nr,flags);
}
static ssize_t injected_pread(int fd,void* bytes,size_t count,off_t offset) {
    if(mode==3){errno=EIO;return -1;}
    return ::pread(fd,bytes,count,offset);
}
#define process_vm_readv injected_vm_read
#define pread injected_pread
#include "../src/fast_capture_service.hpp"
#undef process_vm_readv
#undef pread
struct CaptureTestAccess {
    static void capture(FastCaptureService& service,MemorySyscallEvent event,const uint8_t* expected) {
        vm_calls=0;service.acquire(event,FastCaptureService::now());
        if(mode==3){assert(service.queue_.empty() && service.unreadable_==1);return;}
        assert(service.queue_.size()==1 && vm_calls==2);
        auto s=std::move(service.queue_.front());service.queue_.pop_front();
        const auto& o=s.observation;assert(o.generation_valid);
        const size_t n=mode==2?3:4096;
        assert(o.read_bytes(0)==n && o.read_bytes(1)==n);
        assert(!std::memcmp(o.first.data(),expected,n) && !std::memcmp(o.second.data(),expected,n));
        if(mode==2){assert(!o.covered(0,0,4) && o.first[3]==0 && o.second[3]==0);}
        service.schedule_.release(s.bytes());
    }
    static void reject_generation(FastCaptureService& service,MemorySyscallEvent event) {
        ++event.starttime;vm_calls=0;service.acquire(event,FastCaptureService::now());
        assert(vm_calls==0 && service.queue_.empty() && service.rejected_==1);
    }
};
int main() {
    auto* page=static_cast<uint8_t*>(::mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    assert(page!=MAP_FAILED);std::memset(page,0x5a,4096);
    const int pid=::getpid();const auto text=std::to_string(pid);
    MemorySyscallEvent event;event.pid=pid;event.tid=pid;event.operation="mprotect";event.protection=1;
    event.starttime=read_process_start_time_inline(text.c_str());assert(event.starttime);
    event.address=reinterpret_cast<uintptr_t>(page);event.end=event.address+4096;
    FastCaptureService service(text,true,4096,false,false,false,false);
    for(mode=0;mode<4;++mode)CaptureTestAccess::capture(service,event,page);
    CaptureTestAccess::reject_generation(service,event);
    assert(!::munmap(page,4096));
    std::puts("fast_reader_fallback_native_test: OK (readv/lazy mem fallback/short prefix/unreadable/generation guards)");
}
