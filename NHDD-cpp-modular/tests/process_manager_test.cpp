#include <cassert>
#include <cstdio>
#include <string>
#include "../src/process_manager.hpp"

int main() {
    const std::string dump =
        "  1 com.example/.MainActivity filter abc\n"
        "    Action: \"android.intent.action.VIEW\"\n"
        "    Category: \"android.intent.category.DEFAULT\"\n"
        "    Category: \"android.intent.category.BROWSABLE\"\n"
        "    Scheme: \"example\"\n"
        "    Authority: \"www.example.com/path\": -1\n"
        "  2 com.example/.Other filter def\n"
        "    Action: \"android.intent.action.VIEW\"\n"
        "    Category: \"android.intent.category.DEFAULT\"\n"
        "    Scheme: \"ignored\"\n"
        "  3 com.example/.MainActivity filter ghi\n"
        "    Action: \"android.intent.action.VIEW\"\n"
        "    Category: \"android.intent.category.BROWSABLE\"\n"
        "    Scheme: \"example\"\n"
        "    Authority: \"www.example.com/path\": -1\n";
    auto routes = ProcessManager::parse_deep_links("com.example", dump, 8);
    assert(routes.size() == 1);
    assert(routes[0].component == "com.example/.MainActivity");
    assert(routes[0].uri() == "example://www.example.com/path");

    const std::string scheme_only =
        "  4 com.example/.Valet filter xyz\n"
        "    Action: \"android.intent.action.VIEW\"\n"
        "    Category: \"android.intent.category.BROWSABLE\"\n"
        "    Scheme: \"valet\"\n";
    routes = ProcessManager::parse_deep_links("com.example", scheme_only, 8);
    assert(routes.size() == 1 && routes[0].uri() == "valet://");
    ProcessManager::DeepLinkRoute payment{"com.example/.RechargeActivity", "pay", "sdk"};
    assert(!ProcessManager::safe_probe_route(payment));
    ProcessManager::DeepLinkRoute home{"com.example/.MainActivity", "example", "www.example.com"};
    assert(ProcessManager::safe_probe_route(home));
    std::puts("process_manager_test: OK (manifest VIEW/BROWSABLE route parsing/dedup)");
}
