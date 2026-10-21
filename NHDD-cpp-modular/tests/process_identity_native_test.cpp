// Root/device integration. Only inspects self and a reaped own child.
#include <cassert>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <thread>
#include <atomic>
#include "../src/process_manager.hpp"
int main() {
    TrackedProcess full,identity;
    assert(ProcessManager::inspect(::getpid(),&full));
    assert(ProcessManager::inspect(::getpid(),&identity,false));
    assert(full.pid==identity.pid && full.parent==identity.parent && full.starttime==identity.starttime);
    assert(!full.command.empty() && identity.command.empty());
    const int leader=::getpid();std::atomic<int> tid{0};std::atomic<bool> finish{false};
    std::thread worker([&]{tid=static_cast<int>(::syscall(SYS_gettid));while(!finish.load())std::this_thread::yield();});
    while(!tid.load())std::this_thread::yield();
    int actual=0;assert(ProcessStat::tgid(tid,&actual) && actual==leader);
    for(unsigned i=0;i<100;++i)assert(ProcessStat::member(leader,tid));
    assert(!ProcessStat::member(0,tid) && !ProcessStat::member(leader,0));
    finish=true;worker.join();assert(!ProcessStat::member(leader,tid));
    const pid_t child=::fork();assert(child>=0);
    if(!child){assert(!ProcessStat::member(::getpid(),::getppid()));assert(!ProcessStat::member(::getppid(),::getpid()));::_exit(0);}
    siginfo_t info{};assert(!::waitid(P_PID,static_cast<id_t>(child),&info,WEXITED|WNOWAIT));
    // Empty cmdline is still a rejection, not a fast-path exemption.
    assert(!ProcessManager::inspect(child,&identity,false));
    assert(!ProcessManager::inspect(child,&full));
    int status=0;assert(::waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(!ProcessStat::member(leader,child));
    std::puts("process_identity_native_test: OK (fresh identity/cmdline/empty cmdline/membership/foreign process/dead thread)");
}
