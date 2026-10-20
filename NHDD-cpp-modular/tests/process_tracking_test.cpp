#include <cassert>
#include <cstdio>
#include "../src/process_tracking.hpp"
int main() {
    assert(PackageProcessTracker::valid_package("com.example.app"));
    assert(!PackageProcessTracker::valid_package("com.foo;id"));
    assert(!PackageProcessTracker::valid_package("com..foo"));
    assert(PackageProcessTracker::matches("com.foo","com.foo:worker"));
    assert(!PackageProcessTracker::matches("com.foo","com.foobar"));
    assert(!PackageProcessTracker::matches("com.foo","com.foo:"));
    PackageProcessTracker t;
    auto r=t.update("com.foo",{{1,9,100,"com.foo"},{2,1,101,"native-worker"},{3,9,102,"com.foo:isolated"},{4,9,101,"com.foobar"}});
    assert(r.size()==3 && t.contains(2,101));
    r=t.update("com.foo",{{2,9,101,"native-worker"},{3,9,102,"com.foo:isolated"}});
    assert(r.size()==2 && t.contains(2,101));
    r=t.update("com.foo",{{2,9,200,"unrelated"},{4,2,201,"unrelated-child"}});
    assert(r.empty() && !t.contains(2,200));
    std::puts("process_tracking_test: OK");
}
