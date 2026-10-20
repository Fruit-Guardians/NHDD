#include <cassert>
#include <cstdio>
#include "../src/syscall_events.hpp"
int main() {
    SyscallEventDecoder::Record r;
    assert(SyscallEventDecoder::parse("    worker-with-dash-123  [004] .... 1234.567890: sys_enter: NR 9 (0, 1000, 3, 22, ffffffffffffffff, 0)",&r));
    assert(r.tid==123 && r.entry && r.id==9 && r.args[1]==0x1000 && r.args[4]==~uint64_t(0));
    assert(SyscallEventDecoder::parse("    worker-123  [004] .... 1234.567891: sys_exit: NR 9 = -12",&r));
    assert(!r.entry && r.result==-12);
    assert(!SyscallEventDecoder::parse("worker-123 [000] 0.0: sys_enter: NR 9 (0, 1000)",&r));
    assert(!SyscallEventDecoder::parse("garbage",&r));
    uintptr_t a=0,e=0;
    assert(SyscallEventDecoder::range(0x1000,0x2000,&a,&e) && e==0x3000);
    assert(!SyscallEventDecoder::range(~uint64_t(0)-4,8,&a,&e));
    assert(!SyscallEventDecoder::range(0,0,&a,&e));
    SyscallEvents source;
    uint64_t generation=100;
    auto resolve=[&](int tid,int* pid,uint64_t* start,bool* compat){
        *pid=42;*start=generation;*compat=sizeof(uintptr_t)==4;return tid==123;
    };
#if defined(__aarch64__)
    const std::string nr="222";
#elif defined(__arm__)
    const std::string nr="192";
#else
    const std::string nr="9";
#endif
    const std::string entry="worker-123 [000] .... 1234.000000: sys_enter: NR "+nr+" (0, 1000, 3, 22, ffffffffffffffff, 0)";
    const std::string exit="worker-123 [000] .... 1234.000001: sys_exit: NR "+nr+" = 8192";
    assert(source.ingest(exit,resolve).empty());
    assert(source.ingest(entry,resolve).empty());
    auto event=source.ingest(exit,resolve);
    assert(event.size()==1 && event[0].address==8192 && event[0].end==12288 && event[0].pid==42);
    source.ingest(entry,resolve);generation=101;
    assert(source.ingest(exit,resolve).empty());
    source.ingest(entry,resolve);
    assert(source.ingest("worker-123 [000] .... 1234.000001: sys_exit: NR "+nr+" = -12",resolve).empty());
    std::puts("syscall_events_test: OK");
}
