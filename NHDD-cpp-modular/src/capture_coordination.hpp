// Advisory scheduling only: never suppresses a read or substitutes a guard.
#pragma once
#include <atomic>
#include <cstdint>
#include <chrono>
#include <thread>

class CaptureCoordination {
public:
    static uint64_t now() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    void enter(uint64_t stamp) {active_.fetch_add(1);last_.store(stamp);}
    void leave(uint64_t stamp) {last_.store(stamp);active_.fetch_sub(1);}
    bool busy(uint64_t stamp,uint64_t recent_ns=500000) const {
        if(active_.load()!=0)return true;
        const auto last=last_.load();
        return last && stamp>=last && stamp-last<recent_ns;
    }
    class Lease {
    public:
        explicit Lease(CaptureCoordination& owner):owner_(owner){owner_.enter(now());}
        ~Lease(){owner_.leave(now());}
        Lease(const Lease&)=delete;Lease& operator=(const Lease&)=delete;
    private:CaptureCoordination& owner_;
    };
    // One per background thread. At most one requested 200us pause per 2ms;
    // continuous events cannot indefinitely starve discovery/publication.
    class alignas(64) Background {
    public:
        bool due(const CaptureCoordination& owner,uint64_t stamp) {
            if(stamp<next_ || !owner.busy(stamp))return false;
            next_=stamp+2000000;++pauses;return true;
        }
        void checkpoint(const CaptureCoordination& owner) {
            if(due(owner,now()))std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        uint64_t pauses=0;
    private:uint64_t next_=0;
    };
private:
    std::atomic<uint32_t> active_{0};std::atomic<uint64_t> last_{0};
};
