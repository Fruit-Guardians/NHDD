// Compile-time ablation controls. These only change resource scheduling/storage;
// never use them to bypass identity, double-read or publication validation.
#pragma once
#include <cstdint>
#ifndef NHDD_CAPTURE_BACKGROUND_YIELD
#define NHDD_CAPTURE_BACKGROUND_YIELD 1
#endif
#ifndef NHDD_CAPTURE_NICE_DELTA
#define NHDD_CAPTURE_NICE_DELTA 3
#endif
#ifndef NHDD_CAPTURE_POOL_SLOTS
#define NHDD_CAPTURE_POOL_SLOTS 32
#endif
#ifndef NHDD_CAPTURE_ADAPTIVE_NICE
#define NHDD_CAPTURE_ADAPTIVE_NICE 1
#endif
#ifndef NHDD_CAPTURE_COALESCE_MERGE
#define NHDD_CAPTURE_COALESCE_MERGE 1
#endif
struct CaptureTuning {
    static constexpr bool background_yield=NHDD_CAPTURE_BACKGROUND_YIELD!=0;
    static constexpr int nice_delta=NHDD_CAPTURE_NICE_DELTA;
    static constexpr unsigned pool_slots=NHDD_CAPTURE_POOL_SLOTS;
    static constexpr bool adaptive_nice=NHDD_CAPTURE_ADAPTIVE_NICE!=0;
    static constexpr bool coalesce_merge=NHDD_CAPTURE_COALESCE_MERGE!=0;
    static_assert(NHDD_CAPTURE_BACKGROUND_YIELD==0 || NHDD_CAPTURE_BACKGROUND_YIELD==1,"yield must be 0/1");
    static_assert(nice_delta==0 || nice_delta==3,"nice delta must be 0/3");
    static_assert(pool_slots==0 || pool_slots==32 || pool_slots==512,"pool slots must be 0/32/512");
    static_assert(NHDD_CAPTURE_ADAPTIVE_NICE==0 || NHDD_CAPTURE_ADAPTIVE_NICE==1,"adaptive nice must be 0/1");
    static_assert(NHDD_CAPTURE_COALESCE_MERGE==0 || NHDD_CAPTURE_COALESCE_MERGE==1,"coalescing must be 0/1");
    static constexpr bool defer_merge(bool pressure,bool conflict,uint64_t revision,uint64_t published) {
        return pressure && !conflict && revision>published && revision-published<8;
    }
    static constexpr int publisher_nice(int inherited,int delta,bool capture_recent) {
        return inherited< -20 || inherited>19?20:
            (!capture_recent?inherited:(inherited+delta>19?19:inherited+delta));
    }
};
