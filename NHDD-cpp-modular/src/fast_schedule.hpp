// Pure scheduling/accounting policy. The owner supplies the queue mutex.
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>

class FastSchedule {
public:
    static constexpr size_t max_bytes=32u*1024*1024,max_items=512;
    static constexpr unsigned max_attempts=4;
    bool admit(size_t bytes) const {return items<max_items && bytes<=max_bytes-used;}
    void retain(size_t bytes) {used+=bytes;++items;peak_items=std::max(peak_items,items);peak_bytes=std::max(peak_bytes,used);}
    void release(size_t bytes) {used-=bytes;--items;}
    // Retries do not acquire a second memory slot. Four fresh jobs cannot
    // indefinitely starve a due retry; retries never displace fresh captures.
    bool retry_turn(bool fresh,bool retry) const {return retry && (!fresh || fresh_streak>=4);}
    void dispatched(bool retry) {fresh_streak=retry?0:std::min(4u,fresh_streak+1);}
    static double retry_delay(unsigned completed) {
        return completed==1?0.025:(completed==2?0.100:0.300);
    }
    static bool can_retry(unsigned completed) {return completed<max_attempts;}
    size_t used=0,items=0,peak_items=0,peak_bytes=0;
private:
    unsigned fresh_streak=0;
};
