#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../src/elf_reconstructor.hpp"
#include "../src/so_artifact_identity.hpp"

namespace {

struct MemorySpan {
    uintptr_t address = 0;
    std::vector<uint8_t> bytes;
};

struct FakeMemory {
    std::vector<MemorySpan> spans;

    static std::ptrdiff_t read(void* context, uint8_t* destination, size_t size,
                               uintptr_t address) {
        auto* memory = static_cast<FakeMemory*>(context);
        for (const MemorySpan& span : memory->spans) {
            if (address < span.address) continue;
            const uintptr_t delta_address = address - span.address;
            if (delta_address >= span.bytes.size()) continue;
            const size_t delta = static_cast<size_t>(delta_address);
            const size_t count = std::min(size, span.bytes.size() - delta);
            std::memcpy(destination, span.bytes.data() + delta, count);
            return static_cast<std::ptrdiff_t>(count);
        }
        return -1;
    }
};

void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

uint16_t get16(const std::vector<uint8_t>& bytes, size_t offset) {
    uint16_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

uint32_t get32(const std::vector<uint8_t>& bytes, size_t offset) {
    uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

uint64_t get64(const std::vector<uint8_t>& bytes, size_t offset) {
    uint64_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

uint64_t fnv1a64(const uint8_t* bytes, size_t size) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool test_file_exists(const char* path) {
    FILE* file = std::fopen(path, "rb");
    if (!file) return false;
    std::fclose(file);
    return true;
}

std::string read_test_file(const char* path) {
    FILE* file = std::fopen(path, "rb");
    assert(file);
    std::string contents;
    char buffer[512];
    size_t count = 0;
    while ((count = std::fread(buffer, 1, sizeof(buffer), file)) != 0)
        contents.append(buffer, count);
    std::fclose(file);
    return contents;
}

void write_test_file(const char* path, const std::string& contents) {
    FILE* file = std::fopen(path, "wb");
    assert(file);
    assert(std::fwrite(contents.data(), 1, contents.size(), file) ==
           contents.size());
    assert(std::fclose(file) == 0);
}

void assert_artifact_sidecars_absent(const char* path) {
    const std::string temporary = artifact_sidecar_path_inline(path, "tmp");
    const std::string backup = artifact_sidecar_path_inline(path, "bak");
    assert(!test_file_exists(temporary.c_str()));
    assert(!test_file_exists(backup.c_str()));
}

struct PublishGuardSequence {
    std::vector<bool> values;
    size_t next = 0;
};

bool sequenced_publish_guard(void* opaque) {
    auto* sequence = static_cast<PublishGuardSequence*>(opaque);
    assert(sequence && !sequence->values.empty());
    if (sequence->next >= sequence->values.size())
        return sequence->values.back();
    return sequence->values[sequence->next++];
}

struct VisibilityPublishGuard {
    std::vector<std::string> paths;
    std::vector<std::vector<std::string>> expected_by_call;
    size_t next = 0;
};

bool visibility_publish_guard(void* opaque) {
    auto* state = static_cast<VisibilityPublishGuard*>(opaque);
    assert(state && state->next < state->expected_by_call.size());
    const auto& expected = state->expected_by_call[state->next];
    assert(expected.size() == state->paths.size());
    for (size_t i = 0; i < state->paths.size(); ++i) {
        assert(test_file_exists(state->paths[i].c_str()));
        assert(read_test_file(state->paths[i].c_str()) == expected[i]);
    }
    ++state->next;
    // Reject the final, fully published view to exercise atomic restoration.
    return state->next != state->expected_by_call.size();
}

std::string hex16(uint64_t value) {
    char buffer[17] = {};
    const int length = std::snprintf(
        buffer, sizeof(buffer), "%016llx",
        static_cast<unsigned long long>(value));
    assert(length == 16);
    return std::string(buffer);
}

void put_phdr64(std::vector<uint8_t>& bytes, size_t offset, uint32_t flags,
                uint64_t file_offset, uint64_t virtual_address,
                uint64_t file_size, uint64_t memory_size) {
    put32(bytes, offset, 1); // PT_LOAD
    put32(bytes, offset + 4, flags);
    put64(bytes, offset + 8, file_offset);
    put64(bytes, offset + 16, virtual_address);
    put64(bytes, offset + 24, 0);
    put64(bytes, offset + 32, file_size);
    put64(bytes, offset + 40, memory_size);
    put64(bytes, offset + 48, 0x1000);
}

void put_phdr32(std::vector<uint8_t>& bytes, size_t offset, uint32_t flags,
                uint32_t file_offset, uint32_t virtual_address,
                uint32_t file_size, uint32_t memory_size) {
    put32(bytes, offset, 1); // PT_LOAD
    put32(bytes, offset + 4, file_offset);
    put32(bytes, offset + 8, virtual_address);
    put32(bytes, offset + 12, 0);
    put32(bytes, offset + 16, file_size);
    put32(bytes, offset + 20, memory_size);
    put32(bytes, offset + 24, flags);
    put32(bytes, offset + 28, 0x1000);
}

void put_shdr64(std::vector<uint8_t>& bytes, size_t offset, uint32_t name,
                uint32_t type, uint64_t flags, uint64_t address,
                uint64_t file_offset, uint64_t size, uint32_t link = 0,
                uint32_t info = 0, uint64_t alignment = 1,
                uint64_t entry_size = 0) {
    assert(offset + 64 <= bytes.size());
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              bytes.begin() + static_cast<std::ptrdiff_t>(offset + 64), 0);
    put32(bytes, offset, name);
    put32(bytes, offset + 4, type);
    put64(bytes, offset + 8, flags);
    put64(bytes, offset + 16, address);
    put64(bytes, offset + 24, file_offset);
    put64(bytes, offset + 32, size);
    put32(bytes, offset + 40, link);
    put32(bytes, offset + 44, info);
    put64(bytes, offset + 48, alignment);
    put64(bytes, offset + 56, entry_size);
}

void put_shdr32(std::vector<uint8_t>& bytes, size_t offset, uint32_t name,
                uint32_t type, uint32_t flags, uint32_t address,
                uint32_t file_offset, uint32_t size, uint32_t link = 0,
                uint32_t info = 0, uint32_t alignment = 1,
                uint32_t entry_size = 0) {
    assert(offset + 40 <= bytes.size());
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              bytes.begin() + static_cast<std::ptrdiff_t>(offset + 40), 0);
    put32(bytes, offset, name);
    put32(bytes, offset + 4, type);
    put32(bytes, offset + 8, flags);
    put32(bytes, offset + 12, address);
    put32(bytes, offset + 16, file_offset);
    put32(bytes, offset + 20, size);
    put32(bytes, offset + 24, link);
    put32(bytes, offset + 28, info);
    put32(bytes, offset + 32, alignment);
    put32(bytes, offset + 36, entry_size);
}

void put_section_names(std::vector<uint8_t>& bytes, size_t offset,
                       bool include_bss = false) {
    static const uint8_t kNames[] = {
        0, '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0,
        '.', 'b', 's', 's', 0,
    };
    const size_t size = include_bss ? sizeof(kNames) : 11u;
    assert(offset + size <= bytes.size());
    std::memcpy(bytes.data() + offset, kNames, size);
}

struct Fixture {
    static constexpr uintptr_t kBias = 0x10000000u;
    static constexpr uintptr_t kHeader = kBias + 0x1000u;
    static constexpr uintptr_t kSecond = kBias + 0x5000u;

    FakeMemory memory;
    std::vector<MapsRegion> maps;
    std::vector<uint8_t> first;
    std::vector<uint8_t> second;

    Fixture() : first(0x200), second(0x100) {
        for (size_t i = 0; i < first.size(); ++i)
            first[i] = static_cast<uint8_t>((i * 3u + 7u) & 0xffu);
        for (size_t i = 0; i < second.size(); ++i)
            second[i] = static_cast<uint8_t>((i * 5u + 11u) & 0xffu);

        std::memcpy(first.data(), "\x7f" "ELF", 4);
        first[4] = 2; // ELFCLASS64
        first[5] = 1; // little-endian
        first[6] = 1; // current version
        put16(first, 16, 3);   // ET_DYN
        put16(first, 18, 183); // EM_AARCH64
        put32(first, 20, 1);
        put64(first, 32, 64);  // e_phoff
        put64(first, 40, 0);   // no section header table
        put16(first, 52, 64);  // e_ehsize
        put16(first, 54, 56);  // e_phentsize
        put16(first, 56, 2);   // e_phnum
        put16(first, 58, 64);  // e_shentsize
        put16(first, 60, 0);   // e_shnum
        put16(first, 62, 0);   // e_shstrndx
        put_phdr64(first, 64, 5, 0, 0x1000, first.size(), 0x400);
        put_phdr64(first, 120, 6, 0x3000, 0x5000, second.size(), 0x600);

        memory.spans.push_back({kHeader, first});
        memory.spans.push_back({kSecond, second});

        maps.resize(3);
        init_map(maps[0], kHeader, kHeader + 0x100, 0x23456000);
        init_map(maps[1], kHeader + 0x100, kHeader + 0x200, 0x23456100);
        init_map(maps[2], kSecond, kSecond + 0x100, 0x23459000);
    }

    static void init_map(MapsRegion& map, uintptr_t start, uintptr_t end,
                         uint64_t carrier_offset) {
        map.start = start;
        map.end = end;
        std::strcpy(map.perms, "r-xp");
        map.offset = carrier_offset;
        map.inode = 4242;
        map.dev_major = 8;
        map.dev_minor = 1;
        std::strcpy(map.path, "/data/app/example/base.apk");
        map.readable = true;
        map.executable = true;
    }
};

void test_file_layout_load_bias_and_bss() {
    Fixture fixture;
    ElfReconstructor::Result result;
    const bool ok = ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result);

    assert(ok);
    assert(result.success);
    assert(result.complete);
    assert(result.load_bias == Fixture::kBias);
    assert(result.output_size == 0x3100); // max(p_offset + p_filesz), not p_memsz
    assert(result.expected_bytes == 0x300);
    assert(result.recovered_bytes == 0x300);
    assert(result.missing_bytes == 0);
    assert(result.holes.empty());
    assert(result.section_headers_preserved);
    assert(!result.section_headers_normalized);
    assert(result.image.size() == 0x3100);
    assert(std::memcmp(result.image.data(), fixture.first.data(),
                       fixture.first.size()) == 0);
    assert(std::memcmp(result.image.data() + 0x3000, fixture.second.data(),
                       fixture.second.size()) == 0);
    for (size_t i = 0x200; i < 0x3000; ++i) assert(result.image[i] == 0);

    assert(result.raw_layout_available);
    assert(result.raw_base_address == Fixture::kHeader);
    assert(result.raw_span_size == 0x4100);
    assert(std::memcmp(result.raw_image.data(), fixture.first.data(),
                       fixture.first.size()) == 0);
    assert(std::memcmp(result.raw_image.data() + 0x4000, fixture.second.data(),
                       fixture.second.size()) == 0);
}

void test_holes_are_reported_not_faked_as_complete() {
    Fixture fixture;
    fixture.maps[2].end = Fixture::kSecond + 0x80;

    ElfReconstructor::Result result;
    const bool ok = ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result);

    assert(ok);
    assert(!result.complete);
    assert(result.expected_bytes == 0x300);
    assert(result.recovered_bytes == 0x280);
    assert(result.missing_bytes == 0x80);
    assert(result.holes.size() == 1);
    assert(result.holes[0].file_offset == 0x3080);
    assert(result.holes[0].size == 0x80);
    assert(result.holes[0].remote_address == Fixture::kSecond + 0x80);
    for (size_t i = 0x3080; i < 0x3100; ++i) assert(result.image[i] == 0);
}

void test_invalid_program_header_entry_size_is_rejected() {
    Fixture fixture;
    put16(fixture.memory.spans[0].bytes, 54, 55);
    ElfReconstructor::Result result;
    const bool ok = ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result);
    assert(!ok);
    assert(result.error == "invalid e_phentsize");
}

void test_program_header_range_overflow_is_rejected() {
    Fixture fixture;
    // p_offset + p_filesz wraps uint64_t.
    put64(fixture.memory.spans[0].bytes, 120 + 8,
          UINT64_MAX - 0x20);
    put64(fixture.memory.spans[0].bytes, 120 + 16,
          UINT64_MAX - 0x20);
    put64(fixture.memory.spans[0].bytes, 120 + 32, 0x100);
    put64(fixture.memory.spans[0].bytes, 120 + 40, 0x100);
    put64(fixture.memory.spans[0].bytes, 120 + 48, 1);

    ElfReconstructor::Result result;
    const bool ok = ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result);
    assert(!ok);
    assert(result.error == "PT_LOAD range overflow");
}

void test_total_pt_load_read_limit_is_preserved() {
    Fixture fixture;
    // Make the second PT_LOAD overlap the first file range.  Its file end is
    // below max_output_size, but reading both segments would exceed the same
    // bounded total budget.
    put64(fixture.memory.spans[0].bytes, 120 + 8, 0x100);
    put64(fixture.memory.spans[0].bytes, 120 + 48, 1);

    ElfReconstructor::Options options;
    options.max_output_size = 0x280;
    ElfReconstructor::Result result;
    const bool ok = ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, options, &result);
    assert(!ok);
    assert(result.error == "PT_LOAD total exceeds size limit");
}

void test_two_apk_backed_elves_with_same_inode_are_independent() {
    Fixture first;
    Fixture second;
    const uintptr_t delta = 0x20000000u;
    for (MemorySpan& span : second.memory.spans) span.address += delta;
    for (MapsRegion& map : second.maps) {
        map.start += delta;
        map.end += delta;
        // path/inode/carrier remain deliberately identical.
    }

    ElfReconstructor::Result a;
    ElfReconstructor::Result b;
    assert(ElfReconstructor::reconstruct(
        Fixture::kHeader, first.maps.data(), first.maps.size(),
        &FakeMemory::read, &first.memory, &a));
    assert(ElfReconstructor::reconstruct(
        Fixture::kHeader + delta, second.maps.data(), second.maps.size(),
        &FakeMemory::read, &second.memory, &b));
    assert(a.load_bias == Fixture::kBias);
    assert(b.load_bias == Fixture::kBias + delta);
    assert(a.image == b.image);
}

void test_elf32_program_headers() {
    constexpr uintptr_t kHeader = 0x31000000u;
    FakeMemory memory;
    std::vector<uint8_t> bytes(0x100, 0x5a);
    std::memcpy(bytes.data(), "\x7f" "ELF", 4);
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[6] = 1;
    put16(bytes, 16, 3);
    put16(bytes, 18, 40); // EM_ARM
    put32(bytes, 20, 1);
    put32(bytes, 28, 52);
    put32(bytes, 32, 0);
    put16(bytes, 40, 52);
    put16(bytes, 42, 32);
    put16(bytes, 44, 1);
    put16(bytes, 46, 40);
    put16(bytes, 48, 0);
    put16(bytes, 50, 0);
    put_phdr32(bytes, 52, 5, 0, 0, 0x100, 0x180);
    memory.spans.push_back({kHeader, bytes});

    MapsRegion map;
    Fixture::init_map(map, kHeader, kHeader + bytes.size(), 0x7000);
    ElfReconstructor::Result result;
    assert(ElfReconstructor::reconstruct(kHeader, &map, 1,
                                         &FakeMemory::read, &memory, &result));
    assert(!result.is_64_bit);
    assert(result.load_bias == kHeader);
    assert(result.output_size == bytes.size());
    assert(result.complete);
    assert(result.image == bytes);
}

void verify_sparse_raw_degrade_metadata(
        const ElfReconstructor::Result& result, const char* prefix) {
    const std::string raw_path = std::string(prefix) + ".raw";
    const std::string reconstructed_path = std::string(prefix) + ".so";
    const std::string metadata_path = std::string(prefix) + ".json";
    std::remove(raw_path.c_str());
    std::remove(reconstructed_path.c_str());
    std::remove(metadata_path.c_str());

    const uint64_t reconstructed_hash =
        fnv1a64(result.image.data(), result.image.size());
    // This matches the scanner's deterministic fallback when no contiguous
    // raw layout is retained.  The pre-normalization ELF/SHT identity must
    // still contribute independently to the evidence hash.
    const uint64_t raw_layout_hash = reconstructed_hash;
    const uint64_t evidence_without_original =
        so_combine_evidence_hash_inline(reconstructed_hash, raw_layout_hash);
    const uint64_t evidence_hash = so_mix_original_elf_identity_inline(
        evidence_without_original, result.original_elf_header_hash,
        result.original_e_shoff, result.original_e_shnum,
        result.original_e_shstrndx);
    const uint64_t changed_original_identity =
        so_mix_original_elf_identity_inline(
            evidence_without_original, result.original_elf_header_hash,
            result.original_e_shoff + 1, result.original_e_shnum,
            result.original_e_shstrndx);
    assert(evidence_hash != evidence_without_original);
    assert(evidence_hash != changed_original_identity);

    ElfReconstructor::ArtifactMetadata metadata;
    metadata.pid = 1234;
    metadata.process_start_time = 5678;
    metadata.reconstructed_hash = reconstructed_hash;
    metadata.raw_layout_hash = raw_layout_hash;
    metadata.evidence_hash = evidence_hash;
    assert(ElfReconstructor::write_artifacts(
        result, raw_path.c_str(), reconstructed_path.c_str(),
        metadata_path.c_str(), "/data/app/sparse.so", &metadata));

    assert(!test_file_exists(raw_path.c_str()));
    assert(test_file_exists(reconstructed_path.c_str()));
    const std::string json = read_test_file(metadata_path.c_str());
    assert(json.find("\"raw_layout_available\": false") !=
           std::string::npos);
    assert(json.find("\"raw_span_size\": " +
                     std::to_string(result.raw_span_size)) !=
           std::string::npos);
    assert(json.find("\"original_elf_header_hash\": \"" +
                     hex16(result.original_elf_header_hash) + "\"") !=
           std::string::npos);
    assert(json.find("\"original_e_shoff\": \"0x180\"") !=
           std::string::npos);
    assert(json.find("\"original_e_shnum\": 2") != std::string::npos);
    assert(json.find("\"original_e_shstrndx\": 1") !=
           std::string::npos);
    assert(json.find("\"evidence_hash\": \"" + hex16(evidence_hash) +
                     "\"") != std::string::npos);

    assert(std::remove(reconstructed_path.c_str()) == 0);
    assert(std::remove(metadata_path.c_str()) == 0);
}

void test_sparse_elf64_omits_raw_layout_but_reconstructs() {
    constexpr uintptr_t kBias = 0x10000000u;
    constexpr uintptr_t kHeader = kBias + 0x1000u;
    constexpr uintptr_t kSecond = kBias + 0x20001000u;

    FakeMemory memory;
    std::vector<uint8_t> first(0x100, 0x41);
    std::vector<uint8_t> second(0x80, 0x64);
    std::memcpy(first.data(), "\x7f" "ELF", 4);
    first[4] = 2;
    first[5] = 1;
    first[6] = 1;
    put16(first, 16, 3);
    put16(first, 18, 183);
    put32(first, 20, 1);
    put64(first, 32, 64);
    put64(first, 40, 0x180); // unavailable SHT: retained as original evidence
    put16(first, 52, 64);
    put16(first, 54, 56);
    put16(first, 56, 2);
    put16(first, 58, 64);
    put16(first, 60, 2);
    put16(first, 62, 1);
    put_phdr64(first, 64, 5, 0, 0x1000, first.size(), first.size());
    put_phdr64(first, 120, 4, 0x1000, 0x20001000,
               second.size(), second.size());
    const uint64_t original_header_hash = fnv1a64(first.data(), 64);
    memory.spans.push_back({kHeader, first});
    memory.spans.push_back({kSecond, second});

    std::vector<MapsRegion> maps(2);
    Fixture::init_map(maps[0], kHeader, kHeader + first.size(), 0);
    Fixture::init_map(maps[1], kSecond, kSecond + second.size(), 0x1000);

    ElfReconstructor::Result result;
    const ElfReconstructor::Options options;
    assert(ElfReconstructor::reconstruct(
        kHeader, maps.data(), maps.size(), &FakeMemory::read, &memory,
        options, &result));
    assert(result.success);
    assert(result.complete);
    assert(result.is_64_bit);
    assert(result.load_bias == kBias);
    assert(result.output_size == 0x1080);
    assert(result.raw_span_size == 0x20000080u);
    assert(result.raw_span_size > options.max_raw_span);
    assert(!result.raw_layout_available);
    assert(result.raw_image.empty());
    assert(result.image.size() == 0x1080);
    assert(std::memcmp(result.image.data() + 0x1000, second.data(),
                       second.size()) == 0);
    assert(result.original_elf_header_hash == original_header_hash);
    assert(result.original_e_shoff == 0x180);
    assert(result.original_e_shnum == 2);
    assert(result.original_e_shstrndx == 1);
    assert(result.section_headers_normalized);
    verify_sparse_raw_degrade_metadata(result, "nhdd-sparse-elf64-test");
}

void test_sparse_elf32_omits_raw_layout_but_reconstructs() {
    constexpr uintptr_t kBias = 0x08000000u;
    constexpr uintptr_t kHeader = kBias + 0x1000u;
    constexpr uintptr_t kSecond = kBias + 0x20001000u;

    FakeMemory memory;
    std::vector<uint8_t> first(0x100, 0x32);
    std::vector<uint8_t> second(0x80, 0x23);
    std::memcpy(first.data(), "\x7f" "ELF", 4);
    first[4] = 1;
    first[5] = 1;
    first[6] = 1;
    put16(first, 16, 3);
    put16(first, 18, 40);
    put32(first, 20, 1);
    put32(first, 28, 52);
    put32(first, 32, 0x180); // unavailable SHT: retained as original evidence
    put16(first, 40, 52);
    put16(first, 42, 32);
    put16(first, 44, 2);
    put16(first, 46, 40);
    put16(first, 48, 2);
    put16(first, 50, 1);
    put_phdr32(first, 52, 5, 0, 0x1000, first.size(), first.size());
    put_phdr32(first, 84, 4, 0x1000, 0x20001000,
               second.size(), second.size());
    const uint64_t original_header_hash = fnv1a64(first.data(), 52);
    memory.spans.push_back({kHeader, first});
    memory.spans.push_back({kSecond, second});

    std::vector<MapsRegion> maps(2);
    Fixture::init_map(maps[0], kHeader, kHeader + first.size(), 0);
    Fixture::init_map(maps[1], kSecond, kSecond + second.size(), 0x1000);

    ElfReconstructor::Result result;
    const ElfReconstructor::Options options;
    assert(ElfReconstructor::reconstruct(
        kHeader, maps.data(), maps.size(), &FakeMemory::read, &memory,
        options, &result));
    assert(result.success);
    assert(result.complete);
    assert(!result.is_64_bit);
    assert(result.load_bias == kBias);
    assert(result.output_size == 0x1080);
    assert(result.raw_span_size == 0x20000080u);
    assert(result.raw_span_size > options.max_raw_span);
    assert(!result.raw_layout_available);
    assert(result.raw_image.empty());
    assert(result.image.size() == 0x1080);
    assert(std::memcmp(result.image.data() + 0x1000, second.data(),
                       second.size()) == 0);
    assert(result.original_elf_header_hash == original_header_hash);
    assert(result.original_e_shoff == 0x180);
    assert(result.original_e_shnum == 2);
    assert(result.original_e_shstrndx == 1);
    assert(result.section_headers_normalized);
    verify_sparse_raw_degrade_metadata(result, "nhdd-sparse-elf32-test");
}

void test_unrecovered_section_table_references_are_normalized() {
    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x4000); // beyond reconstructed PT_LOAD output
        put16(header, 58, 64);
        put16(header, 60, 24);
        put16(header, 62, 23);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(result.complete);
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
        assert(get64(result.image, 40) == 0);
        assert(get16(result.image, 58) == 64); // entry size is evidence
        assert(get16(result.image, 60) == 0);
        assert(get16(result.image, 62) == 0);
    }

    {
        constexpr uintptr_t kHeader = 0x32000000u;
        FakeMemory memory;
        std::vector<uint8_t> bytes(0x100, 0x5a);
        std::memcpy(bytes.data(), "\x7f" "ELF", 4);
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        put16(bytes, 16, 3);
        put16(bytes, 18, 40);
        put32(bytes, 20, 1);
        put32(bytes, 28, 52);
        put32(bytes, 32, 0x200); // beyond reconstructed PT_LOAD output
        put16(bytes, 40, 52);
        put16(bytes, 42, 32);
        put16(bytes, 44, 1);
        put16(bytes, 46, 40);
        put16(bytes, 48, 0);      // extended section count
        put16(bytes, 50, 0xffff); // SHN_XINDEX
        put_phdr32(bytes, 52, 5, 0, 0, 0x100, 0x100);
        memory.spans.push_back({kHeader, bytes});

        MapsRegion map;
        Fixture::init_map(map, kHeader, kHeader + bytes.size(), 0x8000);
        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            kHeader, &map, 1, &FakeMemory::read, &memory, &result));
        assert(result.complete);
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
        assert(get32(result.image, 32) == 0);
        assert(get16(result.image, 46) == 40);
        assert(get16(result.image, 48) == 0);
        assert(get16(result.image, 50) == 0);
    }
}

void test_fully_recovered_section_tables_are_preserved() {
    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 2);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x180, 11);
        put_section_names(header, 0x180);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(result.section_headers_preserved);
        assert(!result.section_headers_normalized);
        assert(get64(result.image, 40) == 0x100);
        assert(get16(result.image, 60) == 2);
        assert(get16(result.image, 62) == 1);
    }

    {
        constexpr uintptr_t kHeader = 0x33000000u;
        FakeMemory memory;
        std::vector<uint8_t> bytes(0x100, 0x5a);
        std::memcpy(bytes.data(), "\x7f" "ELF", 4);
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        put16(bytes, 16, 3);
        put16(bytes, 18, 40);
        put32(bytes, 20, 1);
        put32(bytes, 28, 52);
        put32(bytes, 32, 0x80);
        put16(bytes, 40, 52);
        put16(bytes, 42, 32);
        put16(bytes, 44, 1);
        put16(bytes, 46, 40);
        put16(bytes, 48, 2);
        put16(bytes, 50, 1);
        put_phdr32(bytes, 52, 5, 0, 0, 0x100, 0x100);
        put_shdr32(bytes, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_shdr32(bytes, 0xa8, 1, 3, 0, 0, 0xd0, 11);
        put_section_names(bytes, 0xd0);
        memory.spans.push_back({kHeader, bytes});

        MapsRegion map;
        Fixture::init_map(map, kHeader, kHeader + bytes.size(), 0x9000);
        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            kHeader, &map, 1, &FakeMemory::read, &memory, &result));
        assert(result.section_headers_preserved);
        assert(!result.section_headers_normalized);
        assert(get32(result.image, 32) == 0x80);
        assert(get16(result.image, 48) == 2);
        assert(get16(result.image, 50) == 1);
    }
}

void test_covered_but_invalid_section_table_is_normalized() {
    Fixture fixture;
    std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
    // The seeded bytes at 0x100 are fully readable but are deliberately not a
    // valid SHT_NULL entry or valid section headers.
    put64(header, 40, 0x100);
    put16(header, 58, 64);
    put16(header, 60, 2);
    put16(header, 62, 1);
    const uint64_t original_header_hash = fnv1a64(header.data(), 64);

    ElfReconstructor::Result result;
    assert(ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result));
    assert(!result.section_headers_preserved);
    assert(result.section_headers_normalized);
    assert(get64(result.image, 40) == 0);
    assert(get16(result.image, 60) == 0);
    assert(get16(result.image, 62) == 0);
    assert(result.original_elf_header_hash == original_header_hash);
    assert(result.original_e_shoff == 0x100);
    assert(result.original_e_shnum == 2);
    assert(result.original_e_shstrndx == 1);
}

void test_nobits_section_does_not_require_file_bytes() {
    Fixture fixture;
    std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
    put64(header, 40, 0x100);
    put16(header, 58, 64);
    put16(header, 60, 3);
    put16(header, 62, 1);
    put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    put_shdr64(header, 0x140, 1, 3, 0, 0, 0x1c0, 16);
    // SHT_NOBITS describes memory, not file bytes.  Its conceptual file range
    // extends past EOF and must not make an otherwise valid SHT disappear.
    put_shdr64(header, 0x180, 11, 8, 3, 0x6000, 0x3100, 0x500,
               0, 0, 0x1000);
    put_section_names(header, 0x1c0, true);

    ElfReconstructor::Result result;
    assert(ElfReconstructor::reconstruct(
        Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
        &FakeMemory::read, &fixture.memory, &result));
    assert(result.section_headers_preserved);
    assert(!result.section_headers_normalized);
    assert(get64(result.image, 40) == 0x100);
}

void test_invalid_shstrtab_is_normalized() {
    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 2);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        // The range is inside the output image but in the unmapped gap between
        // the two PT_LOAD file ranges, so its bytes are not recovered.
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x200, 11);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
    }

    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 2);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x30fc, 11);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
    }

    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 2);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        // e_shstrndx must name SHT_STRTAB, not merely a covered section.
        put_shdr64(header, 0x140, 1, 1, 0, 0, 0x180, 11);
        put_section_names(header, 0x180);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
    }

    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 2);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x180, 11);
        put_section_names(header, 0x180);
        header[0x180] = 'X'; // string tables must start with the empty string

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(!result.section_headers_preserved);
        assert(result.section_headers_normalized);
    }
}

void test_invalid_section_fields_and_links_are_normalized() {
    const auto reconstruct_with_third_section = [](
        uint32_t type, uint64_t address, uint64_t file_offset,
        uint64_t size, uint32_t link, uint64_t alignment,
        uint64_t entry_size) {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 3);
        put16(header, 62, 1);
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x1c0, 16);
        put_shdr64(header, 0x180, 0, type, 0, address, file_offset, size,
                   link, 0, alignment, entry_size);
        put_section_names(header, 0x1c0, true);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        return result;
    };

    const ElfReconstructor::Result file_overflow =
        reconstruct_with_third_section(1, 0, UINT64_MAX - 3, 8, 0, 1, 0);
    assert(!file_overflow.section_headers_preserved);
    assert(file_overflow.section_headers_normalized);

    const ElfReconstructor::Result address_overflow =
        reconstruct_with_third_section(1, UINT64_MAX - 3, 0x1d0, 8,
                                       0, 1, 0);
    assert(!address_overflow.section_headers_preserved);
    assert(address_overflow.section_headers_normalized);

    // A standard SHT_SYMTAB link must resolve to SHT_STRTAB.  Opaque link/info
    // values remain allowed only for processor/OS/application-specific types.
    const ElfReconstructor::Result bad_symtab_link =
        reconstruct_with_third_section(2, 0, 0, 0, 99, 8, 24);
    assert(!bad_symtab_link.section_headers_preserved);
    assert(bad_symtab_link.section_headers_normalized);
}

void test_extended_section_numbering_is_validated_for_elf64_and_elf32() {
    {
        Fixture fixture;
        std::vector<uint8_t>& header = fixture.memory.spans[0].bytes;
        put64(header, 40, 0x100);
        put16(header, 58, 64);
        put16(header, 60, 0);      // count is section zero's sh_size
        put16(header, 62, 0xffff); // shstrndx is section zero's sh_link
        put_shdr64(header, 0x100, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0);
        put_shdr64(header, 0x140, 1, 3, 0, 0, 0x1c0, 16);
        put_shdr64(header, 0x180, 11, 8, 3, 0x6000, 0x3100, 0x80,
                   0, 0, 0x1000);
        put_section_names(header, 0x1c0, true);

        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            Fixture::kHeader, fixture.maps.data(), fixture.maps.size(),
            &FakeMemory::read, &fixture.memory, &result));
        assert(result.section_headers_preserved);
        assert(!result.section_headers_normalized);
        assert(get16(result.image, 60) == 0);
        assert(get16(result.image, 62) == 0xffff);
        assert(get64(result.image, 0x100 + 32) == 3);
        assert(get32(result.image, 0x100 + 40) == 1);
    }

    {
        constexpr uintptr_t kHeader = 0x34000000u;
        FakeMemory memory;
        std::vector<uint8_t> bytes(0x180, 0x5a);
        std::memcpy(bytes.data(), "\x7f" "ELF", 4);
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        put16(bytes, 16, 3);
        put16(bytes, 18, 40);
        put32(bytes, 20, 1);
        put32(bytes, 28, 52);
        put32(bytes, 32, 0x80);
        put16(bytes, 40, 52);
        put16(bytes, 42, 32);
        put16(bytes, 44, 1);
        put16(bytes, 46, 40);
        put16(bytes, 48, 0);
        put16(bytes, 50, 0xffff);
        put_phdr32(bytes, 52, 5, 0, 0, 0x180, 0x200);
        put_shdr32(bytes, 0x80, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0);
        put_shdr32(bytes, 0xa8, 1, 3, 0, 0, 0x100, 16);
        put_shdr32(bytes, 0xd0, 11, 8, 3, 0x2000, 0x180, 0x80,
                   0, 0, 0x1000);
        put_section_names(bytes, 0x100, true);
        memory.spans.push_back({kHeader, bytes});

        MapsRegion map;
        Fixture::init_map(map, kHeader, kHeader + bytes.size(), 0xa000);
        ElfReconstructor::Result result;
        assert(ElfReconstructor::reconstruct(
            kHeader, &map, 1, &FakeMemory::read, &memory, &result));
        assert(!result.is_64_bit);
        assert(result.section_headers_preserved);
        assert(!result.section_headers_normalized);
        assert(get16(result.image, 48) == 0);
        assert(get16(result.image, 50) == 0xffff);
        assert(get32(result.image, 0x80 + 20) == 3);
        assert(get32(result.image, 0x80 + 24) == 1);
    }
}

void test_nonzero_anchor_preserves_header_and_pht_prefix() {
    constexpr uintptr_t kBias = 0x41000000u;
    constexpr uintptr_t kHeader = kBias + 0x1000u;
    constexpr uintptr_t kSegment = kBias + 0x2000u;

    FakeMemory memory;
    std::vector<uint8_t> header(0x100, 0);
    std::vector<uint8_t> segment(0x100, 0xa5);
    std::memcpy(header.data(), "\x7f" "ELF", 4);
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    put16(header, 16, 3);
    put16(header, 18, 183);
    put32(header, 20, 1);
    put64(header, 32, 64);
    put16(header, 52, 64);
    put16(header, 54, 56);
    put16(header, 56, 1);
    put_phdr64(header, 64, 5, 0x1000, 0x2000,
               segment.size(), segment.size());
    memory.spans.push_back({kHeader, header});
    memory.spans.push_back({kSegment, segment});

    std::vector<MapsRegion> maps(2);
    Fixture::init_map(maps[0], kHeader, kHeader + header.size(), 0);
    Fixture::init_map(maps[1], kSegment, kSegment + segment.size(), 0x1000);

    ElfReconstructor::Result result;
    assert(ElfReconstructor::reconstruct(
        kHeader, maps.data(), maps.size(), &FakeMemory::read, &memory,
        &result));
    assert(result.load_bias == kBias);
    assert(result.complete);
    assert(result.output_size == 0x1100);
    assert(std::memcmp(result.image.data(), header.data(), 64 + 56) == 0);
    assert(std::memcmp(result.image.data() + 0x1000, segment.data(),
                       segment.size()) == 0);
}

void test_artifact_metadata_records_process_generation() {
    const char* reconstructed_path = "nhdd-elf-metadata-test.bin";
    const char* metadata_path = "nhdd-elf-metadata-test.json";
    std::remove(reconstructed_path);
    std::remove(metadata_path);

    ElfReconstructor::Result result;
    result.success = true;
    result.complete = true;
    result.is_64_bit = true;
    result.image = {0x7f, 'E', 'L', 'F'};
    result.output_size = result.image.size();
    result.expected_bytes = result.image.size();
    result.recovered_bytes = result.image.size();
    result.original_elf_header_hash = 0x4444;
    result.original_e_shoff = 0x5555;
    result.original_e_shnum = 6;
    result.original_e_shstrndx = 7;

    ElfReconstructor::ArtifactMetadata identity;
    identity.pid = 7080;
    identity.process_start_time = 38351447;
    identity.reconstructed_hash = 0x1111;
    identity.raw_layout_hash = 0x2222;
    identity.evidence_hash = 0x3333;
    assert(ElfReconstructor::write_artifacts(
        result, nullptr, reconstructed_path, metadata_path,
        "/data/app/libsame.so", &identity));

    FILE* metadata = std::fopen(metadata_path, "rb");
    assert(metadata);
    std::string json;
    char buffer[512];
    size_t count = 0;
    while ((count = std::fread(buffer, 1, sizeof(buffer), metadata)) != 0)
        json.append(buffer, count);
    std::fclose(metadata);
    assert(json.find("\"pid\": 7080") != std::string::npos);
    assert(json.find("\"process_start_time_ticks\": 38351447") !=
           std::string::npos);
    assert(json.find("\"reconstructed_hash\": \"0000000000001111\"") !=
           std::string::npos);
    assert(json.find("\"raw_layout_hash\": \"0000000000002222\"") !=
           std::string::npos);
    assert(json.find("\"original_elf_header_hash\": \"0000000000004444\"") !=
           std::string::npos);
    assert(json.find("\"original_e_shoff\": \"0x5555\"") !=
           std::string::npos);
    assert(json.find("\"original_e_shnum\": 6") != std::string::npos);
    assert(json.find("\"original_e_shstrndx\": 7") != std::string::npos);
    assert(std::remove(reconstructed_path) == 0);
    assert(std::remove(metadata_path) == 0);
}

ElfReconstructor::Result publication_fixture() {
    ElfReconstructor::Result result;
    result.success = true;
    result.complete = true;
    result.is_64_bit = true;
    result.raw_layout_available = true;
    result.image = {'n', 'e', 'w', '-', 'e', 'l', 'f'};
    result.raw_image = {'n', 'e', 'w', '-', 'r', 'a', 'w'};
    result.output_size = result.image.size();
    result.raw_span_size = result.raw_image.size();
    result.expected_bytes = result.image.size();
    result.recovered_bytes = result.image.size();
    return result;
}

void test_artifact_guard_failure_restores_existing_set() {
    const char* raw_path = "nhdd-elf-guard-existing.raw";
    const char* reconstructed_path = "nhdd-elf-guard-existing.so";
    const char* metadata_path = "nhdd-elf-guard-existing.json";
    write_test_file(raw_path, "old-raw");
    write_test_file(reconstructed_path, "old-reconstructed");
    write_test_file(metadata_path, "old-metadata");

    // The fifth check happens after all three final names have been replaced.
    PublishGuardSequence guard{{true, true, true, true, false}, 0};
    const ElfReconstructor::Result result = publication_fixture();
    assert(!ElfReconstructor::write_artifacts(
        result, raw_path, reconstructed_path, metadata_path, "/old/lib.so",
        nullptr, &sequenced_publish_guard, &guard));
    assert(read_test_file(raw_path) == "old-raw");
    assert(read_test_file(reconstructed_path) == "old-reconstructed");
    assert(read_test_file(metadata_path) == "old-metadata");
    assert_artifact_sidecars_absent(raw_path);
    assert_artifact_sidecars_absent(reconstructed_path);
    assert_artifact_sidecars_absent(metadata_path);
    assert(std::remove(raw_path) == 0);
    assert(std::remove(reconstructed_path) == 0);
    assert(std::remove(metadata_path) == 0);
}

void test_artifact_guard_failure_removes_new_set() {
    const char* raw_path = "nhdd-elf-guard-new.raw";
    const char* reconstructed_path = "nhdd-elf-guard-new.so";
    const char* metadata_path = "nhdd-elf-guard-new.json";
    std::remove(raw_path);
    std::remove(reconstructed_path);
    std::remove(metadata_path);

    PublishGuardSequence guard{{true, true, true, true, false}, 0};
    const ElfReconstructor::Result result = publication_fixture();
    assert(!ElfReconstructor::write_artifacts(
        result, raw_path, reconstructed_path, metadata_path, "/new/lib.so",
        nullptr, &sequenced_publish_guard, &guard));
    assert(!test_file_exists(raw_path));
    assert(!test_file_exists(reconstructed_path));
    assert(!test_file_exists(metadata_path));
    assert_artifact_sidecars_absent(raw_path);
    assert_artifact_sidecars_absent(reconstructed_path);
    assert_artifact_sidecars_absent(metadata_path);
}

void test_artifact_transaction_rename_failure_restores_whole_set() {
    for (size_t missing_index : {size_t{1}, size_t{2}}) {
        const std::string suffix = std::to_string(missing_index);
        std::vector<std::string> finals;
        std::vector<std::string> temporaries;
        std::vector<ArtifactTransactionEntryInline> entries;
        for (size_t i = 0; i < 3; ++i) {
            finals.push_back("nhdd-rename-failure-" + suffix + "-" +
                             std::to_string(i) + ".final");
            temporaries.push_back(artifact_sidecar_path_inline(
                finals.back().c_str(), "tmp"));
            write_test_file(finals.back().c_str(),
                            "old-" + std::to_string(i));
            if (i != missing_index) {
                write_test_file(temporaries.back().c_str(),
                                "new-" + std::to_string(i));
            } else {
                std::remove(temporaries.back().c_str());
            }
        }
        for (size_t i = 0; i < finals.size(); ++i)
            entries.emplace_back(finals[i].c_str(), temporaries[i].c_str());

        assert(!artifact_publish_transaction_inline(&entries));
        for (size_t i = 0; i < finals.size(); ++i) {
            assert(read_test_file(finals[i].c_str()) ==
                   "old-" + std::to_string(i));
            assert_artifact_sidecars_absent(finals[i].c_str());
            assert(std::remove(finals[i].c_str()) == 0);
        }
    }
}

void test_artifact_transaction_keeps_each_final_continuously_visible() {
    std::vector<std::string> finals;
    std::vector<std::string> temporaries;
    std::vector<ArtifactTransactionEntryInline> entries;
    for (size_t i = 0; i < 3; ++i) {
        finals.push_back("nhdd-visible-transaction-" + std::to_string(i));
        temporaries.push_back(
            artifact_sidecar_path_inline(finals.back().c_str(), "tmp"));
        write_test_file(finals.back().c_str(), "old-" + std::to_string(i));
        write_test_file(temporaries.back().c_str(),
                        "new-" + std::to_string(i));
    }
    for (size_t i = 0; i < finals.size(); ++i)
        entries.emplace_back(finals[i].c_str(), temporaries[i].c_str());

    VisibilityPublishGuard guard{
        finals,
        {{"old-0", "old-1", "old-2"},
         {"new-0", "old-1", "old-2"},
         {"new-0", "new-1", "old-2"},
         {"new-0", "new-1", "new-2"},
         {"new-0", "new-1", "new-2"}},
        0};
    assert(!artifact_publish_transaction_inline(
        &entries, &visibility_publish_guard, &guard));
    assert(guard.next == guard.expected_by_call.size());
    for (size_t i = 0; i < finals.size(); ++i) {
        assert(read_test_file(finals[i].c_str()) ==
               "old-" + std::to_string(i));
        assert_artifact_sidecars_absent(finals[i].c_str());
        assert(std::remove(finals[i].c_str()) == 0);
    }
}

} // namespace

int main() {
    test_file_layout_load_bias_and_bss();
    test_holes_are_reported_not_faked_as_complete();
    test_invalid_program_header_entry_size_is_rejected();
    test_program_header_range_overflow_is_rejected();
    test_total_pt_load_read_limit_is_preserved();
    test_two_apk_backed_elves_with_same_inode_are_independent();
    test_elf32_program_headers();
    test_sparse_elf64_omits_raw_layout_but_reconstructs();
    test_sparse_elf32_omits_raw_layout_but_reconstructs();
    test_unrecovered_section_table_references_are_normalized();
    test_fully_recovered_section_tables_are_preserved();
    test_covered_but_invalid_section_table_is_normalized();
    test_nobits_section_does_not_require_file_bytes();
    test_invalid_shstrtab_is_normalized();
    test_invalid_section_fields_and_links_are_normalized();
    test_extended_section_numbering_is_validated_for_elf64_and_elf32();
    test_nonzero_anchor_preserves_header_and_pht_prefix();
    test_artifact_metadata_records_process_generation();
    test_artifact_guard_failure_restores_existing_set();
    test_artifact_guard_failure_removes_new_set();
    test_artifact_transaction_rename_failure_restores_whole_set();
    test_artifact_transaction_keeps_each_final_continuously_visible();
    std::cout << "elf_reconstructor_test: all tests passed\n";
    return 0;
}
