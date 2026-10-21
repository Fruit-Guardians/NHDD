#include <cassert>
#include <cstdio>
#include "../src/syscall_events.hpp"
int main() {
    assert(SyscallEvents::retry_nanoseconds(true)==NHDD_TRACE_RETRY_US*1000L);
    assert(SyscallEvents::retry_nanoseconds(false)==100000000L);
    assert(SyscallEvents::collector_nice(0)==-NHDD_TRACE_NICE_DELTA);
    assert(SyscallEvents::collector_nice(-20)==-20);
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
    SyscallEvents early;early.early_entries(true);
#if defined(__aarch64__)
    const std::string protect="226",remap="216";
#elif defined(__arm__)
    const std::string protect="125",remap="163";
#else
    const std::string protect="10",remap="25";
#endif
    auto before=early.ingest("worker-123 [000] .... 1234.000002: sys_enter: NR "+protect+" (2000, 1000, 0, 0, 0, 0)",resolve);
    assert(before.size()==1 && before[0].before && before[0].address==8192);
    before=early.ingest("worker-123 [000] .... 1234.000003: sys_enter: NR "+remap+" (3000, 2000, 4000, 1, 0, 0)",resolve);
    assert(before.size()==1 && before[0].before && before[0].address==12288 && before[0].end==20480);
    auto after=early.ingest("worker-123 [000] .... 1234.000004: sys_exit: NR "+remap+" = 40960",resolve);
    assert(after.size()==1 && !after[0].before && after[0].address==40960 && after[0].end==57344);
    std::puts("syscall_events_test: OK");
}
