// Root/device integration. Only inspects self and a reaped own child.
#include <cassert>
#include <sys/wait.h>
#include "../src/process_manager.hpp"
int main() {
    TrackedProcess full,identity;
    assert(ProcessManager::inspect(::getpid(),&full));
    assert(ProcessManager::inspect(::getpid(),&identity,false));
    assert(full.pid==identity.pid && full.parent==identity.parent && full.starttime==identity.starttime);
    assert(!full.command.empty() && identity.command.empty());
    const pid_t child=::fork();assert(child>=0);
    if(!child)::_exit(0);
    siginfo_t info{};assert(!::waitid(P_PID,static_cast<id_t>(child),&info,WEXITED|WNOWAIT));
    // Empty cmdline is still a rejection, not a fast-path exemption.
    assert(!ProcessManager::inspect(child,&identity,false));
    assert(!ProcessManager::inspect(child,&full));
    assert(::waitpid(child,nullptr,0)==child);
    std::puts("process_identity_native_test: OK (fresh identity/cmdline preserved/empty cmdline rejected)");
}
