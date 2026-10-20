// process_generation_guard.hpp — sticky PID-generation validation primitive
#pragma once

#include <cstdint>

using ProcessStartTimeReaderInline = uint64_t (*)(void*, const char*);

// A guard is intentionally sticky: after /proc reports a missing process or a
// different starttime, no later check can make the scan publish again.  This
// prevents a recycled PID from being accepted merely because a subsequent
// read happens to succeed.
struct ProcessGenerationGuardInline {
    const char* pid = nullptr;
    uint64_t expected_start_time = 0;
    ProcessStartTimeReaderInline reader = nullptr;
    void* reader_context = nullptr;
    bool invalid = false;
    uint64_t last_observed_start_time = 0;
    uint64_t checks = 0;

    bool verify() {
        if (invalid || !pid || !*pid || expected_start_time == 0 || !reader) {
            invalid = true;
            return false;
        }
        ++checks;
        last_observed_start_time = reader(reader_context, pid);
        if (last_observed_start_time == 0 ||
            last_observed_start_time != expected_start_time) {
            invalid = true;
            return false;
        }
        return true;
    }
};

inline bool process_generation_publish_guard_inline(void* opaque) {
    auto* guard = static_cast<ProcessGenerationGuardInline*>(opaque);
    return guard && guard->verify();
}
