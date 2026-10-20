// jni_artifact_identity.hpp — generation-safe JNIMAP dedup identity
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

template <typename T>
inline bool jni_grow_zeroed_buffer_inline(T** items, int* capacity) {
    if (!items || !*items || !capacity || *capacity <= 0 ||
        *capacity > std::numeric_limits<int>::max() / 2) {
        return false;
    }
    const int old_capacity = *capacity;
    const int new_capacity = old_capacity * 2;
    if (static_cast<size_t>(new_capacity) >
        std::numeric_limits<size_t>::max() / sizeof(T)) {
        return false;
    }
    auto* resized = static_cast<T*>(
        std::realloc(*items, static_cast<size_t>(new_capacity) * sizeof(T)));
    if (!resized) return false;
    std::memset(resized + old_capacity, 0,
                static_cast<size_t>(new_capacity - old_capacity) * sizeof(T));
    *items = resized;
    *capacity = new_capacity;
    return true;
}

inline void jni_identity_hash_bytes_inline(uint64_t* hash, const char* value) {
    if (!hash) return;
    const unsigned char* cursor =
        reinterpret_cast<const unsigned char*>(value ? value : "");
    while (*cursor) {
        *hash ^= *cursor++;
        *hash *= 1099511628211ULL;
    }
    *hash ^= 0xffu;
    *hash *= 1099511628211ULL;
}

inline void jni_identity_hash_u64_inline(uint64_t* hash, uint64_t value) {
    if (!hash) return;
    for (unsigned i = 0; i < 8; ++i) {
        *hash ^= static_cast<uint8_t>(value >> (i * 8));
        *hash *= 1099511628211ULL;
    }
}

inline bool jni_format_dedup_key_inline(
        char* output, size_t output_size, uint32_t pid,
        uint64_t process_start_time, const char* name, const char* signature,
        const char* module, uintptr_t offset) {
    if (!output || output_size == 0) return false;
    uint64_t evidence_hash = 1469598103934665603ULL;
    jni_identity_hash_bytes_inline(&evidence_hash, name);
    jni_identity_hash_bytes_inline(&evidence_hash, signature);
    jni_identity_hash_bytes_inline(&evidence_hash, module);
    jni_identity_hash_u64_inline(&evidence_hash,
                                 static_cast<uint64_t>(offset));
    const int length = std::snprintf(
        output, output_size, "jni_%u_g%llx_%016llx", pid,
        static_cast<unsigned long long>(process_start_time),
        static_cast<unsigned long long>(evidence_hash));
    return length >= 0 && static_cast<size_t>(length) < output_size;
}
