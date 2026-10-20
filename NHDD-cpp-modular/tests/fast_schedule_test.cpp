#include <cassert>
#include <cstdio>
#include "../src/fast_schedule.hpp"
int main() {
    FastSchedule q;assert(q.admit(FastSchedule::max_bytes));
    q.retain(FastSchedule::max_bytes);assert(!q.admit(1));
    // Popping to an in-flight job or requeuing a retry does NOT release memory.
    assert(q.items==1 && q.used==FastSchedule::max_bytes && !q.admit(1));
    q.release(FastSchedule::max_bytes);assert(q.items==0 && q.used==0);
    for(size_t i=0;i<512;++i){assert(q.admit(1));q.retain(1);}
    assert(!q.admit(0) && q.peak_items==512 && q.peak_bytes==FastSchedule::max_bytes);
    for(size_t i=0;i<512;++i)q.release(1);
    assert(q.admit(1) && !q.retry_turn(true,false) && q.retry_turn(false,true));
    for(unsigned i=0;i<4;++i){assert(!q.retry_turn(true,true));q.dispatched(false);}
    assert(q.retry_turn(true,true));q.dispatched(true);assert(!q.retry_turn(true,true));
    assert(FastSchedule::retry_delay(1)<FastSchedule::retry_delay(2));
    assert(FastSchedule::retry_delay(2)<FastSchedule::retry_delay(3));
    assert(FastSchedule::can_retry(3) && !FastSchedule::can_retry(4));
    std::puts("fast_schedule_test: OK (inflight/retry accounting/caps/fairness/bounded retries)");
}
