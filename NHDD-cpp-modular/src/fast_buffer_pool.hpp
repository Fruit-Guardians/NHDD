// SPSC: collector takes, publisher returns; no target bytes are reused as evidence.
#pragma once
#include <vector>
#include <atomic>
#include <stdexcept>
#include <utility>
#include "fast_capture.hpp"

class FastBufferPool {
public:
    static constexpr uint32_t slots=32;
    static constexpr uint32_t max_slots=512;
    explicit FastBufferPool(uint32_t count=slots):buffers_(checked_count(count)) {
        for(auto& o:buffers_) {
            o.first.resize(4096);o.second.resize(4096);o.first.clear();o.second.clear();o.pages.reserve(1);
        }
        written_.store(count);
    }
    FastObservation take() {
        const uint32_t r=read_.load(std::memory_order_relaxed);
        if(r==written_.load(std::memory_order_acquire))return {};
        auto result=std::move(buffers_[r%buffers_.size()]);read_.store(r+1,std::memory_order_release);return result;
    }
    bool give(FastObservation& o) {
        if(o.first.capacity()>4096 || o.second.capacity()>4096 || o.pages.capacity()>1)return false;
        const uint32_t w=written_.load(std::memory_order_relaxed);
        if(w-read_.load(std::memory_order_acquire)>=buffers_.size())return false;
        o.first.clear();o.second.clear();o.pages.clear();
        buffers_[w%buffers_.size()]=std::move(o);written_.store(w+1,std::memory_order_release);return true;
    }
    uint32_t capacity() const {return static_cast<uint32_t>(buffers_.size());}
private:
    static uint32_t checked_count(uint32_t count) {
        if(count>max_slots)throw std::length_error("fast buffer pool exceeds outstanding observation limit");
        return count;
    }
    std::vector<FastObservation> buffers_;
    alignas(64) std::atomic<uint32_t> read_{0};
    alignas(64) std::atomic<uint32_t> written_{0};
};
