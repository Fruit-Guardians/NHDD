// dedup_table.hpp — cross-process/snapshot deduplication tables
#pragma once

#include <cstring>
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

// SO dedup by maps path
class SoDedup {
public:
    explicit SoDedup(int max_entries = kDedupSoMax) : max_(max_entries) {
        paths_ = new char[max_ * 512];
    }
    ~SoDedup() { delete[] paths_; }

    bool seen(const char* path) const {
        if (!path || !*path) return false;
        for (int i = 0; i < count_; i++)
            if (std::strcmp(paths_ + i * 512, path) == 0)
                return true;
        return false;
    }

    void remember(const char* path) {
        if (!path || !*path) return;
        if (count_ < max_) {
            std::strncpy(paths_ + count_ * 512, path, 511);
            (paths_ + count_ * 512)[511] = '\0';
            count_++;
        }
    }

    int count() const { return count_; }
    void reset() { count_ = 0; }

    SoDedup(const SoDedup&) = delete;
    SoDedup& operator=(const SoDedup&) = delete;

private:
    char* paths_;
    int max_;
    int count_ = 0;
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
