// dedup_table.hpp — cross-process/snapshot deduplication tables
#pragma once

#include <cstdint>
#include <cstring>
#include <list>
#include <string>
#include <unordered_map>
#include "common_types.hpp"

// DEX dedup by 20-byte SHA-1 signature
class DexDedup {
public:
    explicit DexDedup(int max_entries = kDedupDexMax) : max_(max_entries) {
        sigs_ = new uint8_t[max_ * 20];
    }
    ~DexDedup() { delete[] sigs_; }

    bool seen(const uint8_t sig[20]) const {
        for (int i = 0; i < count_; i++)
            if (std::memcmp(sigs_ + i * 20, sig, 20) == 0)
                return true;
        return false;
    }

    void remember(const uint8_t sig[20]) {
        if (count_ < max_) {
            std::memcpy(sigs_ + count_ * 20, sig, 20);
            count_++;
        }
    }

    int count() const { return count_; }
    void reset() { count_ = 0; }

    DexDedup(const DexDedup&) = delete;
    DexDedup& operator=(const DexDedup&) = delete;

private:
    uint8_t* sigs_;
    int max_;
    int count_ = 0;
};

// SO evidence-key dedup with bounded LRU retention. A hit becomes MRU so a
// long-running continuous session does not immediately forget hot artifacts.
class SoDedup {
public:
    explicit SoDedup(int max_entries = kDedupSoMax)
        : max_(max_entries > 0 ? static_cast<size_t>(max_entries) : 0) {}

    bool seen(const char* key) {
        if (!key || !*key) return false;
        auto found = entries_.find(key);
        if (found == entries_.end()) return false;
        lru_.splice(lru_.end(), lru_, found->second);
        return true;
    }

    // Returns true when the oldest entry had to be evicted.
    bool remember(const char* key) {
        if (!key || !*key || max_ == 0) return false;
        auto found = entries_.find(key);
        if (found != entries_.end()) {
            lru_.splice(lru_.end(), lru_, found->second);
            return false;
        }

        bool evicted = false;
        if (entries_.size() >= max_) {
            entries_.erase(lru_.front());
            lru_.pop_front();
            ++eviction_count_;
            evicted = true;
        }
        lru_.emplace_back(key);
        auto inserted = lru_.end();
        --inserted;
        entries_.emplace(*inserted, inserted);
        return evicted;
    }

    int count() const { return static_cast<int>(entries_.size()); }
    size_t capacity() const { return max_; }
    uint64_t eviction_count() const { return eviction_count_; }
    void reset() {
        entries_.clear();
        lru_.clear();
        eviction_count_ = 0;
    }

    SoDedup(const SoDedup&) = delete;
    SoDedup& operator=(const SoDedup&) = delete;

private:
    using LruList = std::list<std::string>;
    size_t max_ = 0;
    LruList lru_;
    std::unordered_map<std::string, LruList::iterator> entries_;
    uint64_t eviction_count_ = 0;
};

// JNI key dedup
class JniDedup {
public:
    explicit JniDedup(int max_entries = kDedupJniMax) : max_(max_entries) {
        keys_ = new char[max_ * 384];
    }
    ~JniDedup() { delete[] keys_; }

    bool seen(const char* key) const {
        for (int i = 0; i < count_; i++)
            if (std::strcmp(keys_ + i * 384, key) == 0)
                return true;
        return false;
    }

    void remember(const char* key) {
        if (!key || !*key) return;
        if (count_ < max_) {
            std::strncpy(keys_ + count_ * 384, key, 383);
            (keys_ + count_ * 384)[383] = '\0';
            count_++;
        }
    }

    int count() const { return count_; }
    void reset() { count_ = 0; }

    JniDedup(const JniDedup&) = delete;
    JniDedup& operator=(const JniDedup&) = delete;

private:
    char* keys_;
    int max_;
    int count_ = 0;
};
