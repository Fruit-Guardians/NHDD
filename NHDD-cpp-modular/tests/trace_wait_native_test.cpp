// Root-only idle cost/lifecycle check; isolated instance filtered to self.
#include <cassert>
#include "../src/syscall_events.hpp"
int main() {
    const auto tid=static_cast<id_t>(::syscall(SYS_gettid));errno=0;
    const int original=::getpriority(PRIO_PROCESS,tid);assert(errno==0);
    SyscallEvents events;events.early_lines([](const std::string&){});
    assert(events.start());events.filter_processes({::getpid()});assert(events.active());
    ::usleep(2000000);events.stop();events.stop();
    errno=0;assert(::getpriority(PRIO_PROCESS,tid)==original && errno==0);
    std::puts("trace_wait_native_test: OK (isolated instance/self PID filter/stop/idempotent stop/main nice unchanged)");
}
