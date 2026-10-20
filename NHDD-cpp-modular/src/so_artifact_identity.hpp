// so_artifact_identity.hpp — generation-safe SO evidence identity and naming
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

struct SoArtifactIdentityInline {
    uint32_t pid = 0;
    uint64_t process_start_time = 0;
    uintptr_t address = 0;
    uint64_t evidence_hash = 0;
};

inline void so_identity_mix_u64_inline(uint64_t* hash, uint64_t value) {
    if (!hash) return;
    for (unsigned i = 0; i < 8; ++i) {
        *hash ^= static_cast<uint8_t>(value >> (i * 8));
        *hash *= 1099511628211ULL;
    }
}

// The reconstructed image can normalize stale section-table fields. Mix the
// unmodified raw-layout hash so two observations that normalize to the same
// ELF still remain distinct pieces of evidence.
inline uint64_t so_combine_evidence_hash_inline(uint64_t reconstructed_hash,
                                                uint64_t raw_layout_hash) {
    uint64_t hash = 1469598103934665603ULL;
    so_identity_mix_u64_inline(&hash, reconstructed_hash);
    so_identity_mix_u64_inline(&hash, raw_layout_hash);
    return hash;
}

inline uint64_t so_mix_original_elf_identity_inline(
        uint64_t evidence_hash, uint64_t original_header_hash,
        uint64_t original_shoff, uint16_t original_shnum,
        uint16_t original_shstrndx) {
    so_identity_mix_u64_inline(&evidence_hash, original_header_hash);
    so_identity_mix_u64_inline(&evidence_hash, original_shoff);
    so_identity_mix_u64_inline(&evidence_hash, original_shnum);
    so_identity_mix_u64_inline(&evidence_hash, original_shstrndx);
    return evidence_hash;
}

inline bool so_format_dedup_key_inline(char* output, size_t output_size,
                                       const SoArtifactIdentityInline& id) {
    if (!output || output_size == 0) return false;
    const int length = std::snprintf(
        output, output_size, "elf_%u_g%llx_%llx_%016llx", id.pid,
        static_cast<unsigned long long>(id.process_start_time),
        static_cast<unsigned long long>(id.address),
        static_cast<unsigned long long>(id.evidence_hash));
    return length >= 0 && static_cast<size_t>(length) < output_size;
}

inline bool so_format_artifact_stem_inline(
        char* output, size_t output_size, const char* safe_name,
        const SoArtifactIdentityInline& id) {
    if (!output || output_size == 0) return false;
    if (!safe_name || !*safe_name) safe_name = "anonymous";
    const int length = std::snprintf(
        output, output_size, "%s_%u_g%llx_%llx_%016llx", safe_name, id.pid,
        static_cast<unsigned long long>(id.process_start_time),
        static_cast<unsigned long long>(id.address),
        static_cast<unsigned long long>(id.evidence_hash));
    return length >= 0 && static_cast<size_t>(length) < output_size;
}
