#include <cassert>
#include <array>
#include <cstdio>
#include <set>
#include <thread>
#include "../src/fast_buffer_pool.hpp"
int main() {
    FastBufferPool pool;std::array<FastObservation,32> held;std::set<const void*> pointers;
    for(auto& o:held) {
        o=pool.take();assert(o.first.capacity()>=4096 && o.second.capacity()>=4096);
        assert(pointers.insert(o.first.data()).second && pointers.insert(o.second.data()).second);
    }
    assert(!pool.take().first.capacity());
    std::vector<uint8_t> source(4096,0x41);
    auto read=[&](uintptr_t,uint8_t* out,size_t n)->size_t{std::memcpy(out,source.data(),n);return n;};
    held[0]=FastObservation::capture_reusing(std::move(held[0]),0x1000,4096,4096,read,[]{return true;},[]{return 1.;});
    held[1]=FastObservation::capture_reusing(std::move(held[1]),0x2000,4096,4096,read,[]{return true;},[]{return 2.;});
    held[1].first[0]=0x51;assert(held[0].first[0]==0x41); // Frozen ownership, no alias.
    for(auto& o:held)assert(pool.give(o));
    FastObservation extra;extra.first.resize(4096);extra.second.resize(4096);
    assert(!pool.give(extra) && extra.first.size()==4096);
    auto seed=pool.take();
    auto short_read=[](uintptr_t,uint8_t* out,size_t)->size_t{std::memset(out,0x52,7);return 7;};
    auto o=FastObservation::capture_reusing(std::move(seed),0x3000,4096,4096,short_read,[]{return true;},[]{return 3.;});
    assert(o.begin==3 && o.end==3 && o.generation_valid && o.first[0]==0x52 && o.first[7]==0);
    assert(o.second[7]==0 && o.covered(0,0,7) && !o.covered(0,0,8));
    o=FastObservation::capture_reusing(std::move(o),0x4000,4096,4096,read,[]{return false;},[]{return 4.;});
    assert(!o.generation_valid && o.first.empty() && o.second.empty() && o.pages.empty() && o.end==0);
    assert(pool.give(o));
    FastObservation large;large.first.resize(8192);large.second.resize(8192);assert(!pool.give(large));
    std::thread producer([&] {
        for(unsigned i=0;i<5000;++i) {
            FastObservation item;item.first.assign(4096,0xa5);item.second.assign(4096,0xa5);item.pages.reserve(1);
            while(!pool.give(item))std::this_thread::yield();
        }
    });
    for(unsigned i=0;i<5032;++i) {
        FastObservation item;
        do {item=pool.take();if(!item.first.capacity())std::this_thread::yield();}while(!item.first.capacity());
        assert(item.first.empty() && item.second.empty() && item.pages.empty());
        auto observed=FastObservation::capture_reusing(std::move(item),0x5000,4096,4096,short_read,[]{return true;},[]{return 5.;});
        assert(observed.first[7]==0 && observed.second[7]==0 && !observed.covered(0,0,8));
    }
    producer.join();assert(!pool.take().first.capacity());
    FastBufferPool disabled(0);assert(!disabled.take().first.capacity());
    assert(!disabled.give(extra));
    bool oversized=false;try{FastBufferPool invalid(513);}catch(const std::length_error&){oversized=true;}
    assert(oversized);
    FastBufferPool burst(512);std::vector<FastObservation> window;window.reserve(512);pointers.clear();
    for(unsigned i=0;i<512;++i) {
        auto storage=burst.take();assert(storage.first.capacity()==4096 && storage.second.capacity()==4096);
        const auto first=storage.first.data(),second=storage.second.data();
        assert(pointers.insert(first).second && pointers.insert(second).second);
        window.push_back(FastObservation::capture_reusing(std::move(storage),0x6000,4096,4096,short_read,[]{return true;},[]{return 6.;}));
        assert(window.back().first.data()==first && window.back().second.data()==second);
        assert(window.back().first[7]==0 && !window.back().covered(0,0,8));
    }
    assert(!burst.take().first.capacity());
    for(auto& frame:window)assert(burst.give(frame));
    std::puts("fast_buffer_pool_test: OK (ownership/zero unread tails/guard reset/bounds/5000 concurrent handoffs)");
}
