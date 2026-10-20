// elf_reconstructor.hpp — rebuild an ELF file from its in-memory PT_LOAD layout
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "artifact_transaction.hpp"
#include "common_types.hpp"

// ElfReconstructor treats the in-memory ELF header/program headers as evidence
// and copies each PT_LOAD from load_bias + p_vaddr back to p_offset.  This
// preserves p_filesz/p_memsz (BSS) semantics and works even when the mappings
// are split across several entries or are backed by an APK, memfd, or anonymous
// memory.  The one intentional header normalization is removal of stale section
// table references when the SHT is not fully present in the reconstructed file.
class ElfReconstructor {
public:
    using ReadCallback = std::ptrdiff_t (*)(void* context, uint8_t* destination,
                                             size_t size, uintptr_t remote_address);

    struct Options {
        uint64_t max_output_size = 256u * 1024u * 1024u;
        uint64_t max_raw_span = 256u * 1024u * 1024u;
        size_t read_chunk_size = 64u * 1024u;
        uint16_t max_program_headers = 512;
    };

    struct LoadSegment {
        uint16_t program_header_index = 0;
        uint32_t flags = 0;
        uint64_t file_offset = 0;
        uint64_t virtual_address = 0;
        uint64_t file_size = 0;
        uint64_t memory_size = 0;
        uint64_t alignment = 0;
        uintptr_t remote_address = 0;
    };

    struct ReadSpan {
        uint64_t file_offset = 0;
        uint64_t size = 0;
        uintptr_t remote_address = 0;
        int map_index = -1;
    };

    struct Hole {
        uint64_t file_offset = 0;
        uint64_t size = 0;
        uintptr_t remote_address = 0;
    };

    struct Result {
        bool success = false;
        bool complete = false;
        bool is_64_bit = false;
        bool raw_layout_available = false;
        bool section_headers_preserved = false;
        bool section_headers_normalized = false;
        std::string error;

        uintptr_t elf_header_address = 0;
        uintptr_t load_bias = 0;
        uintptr_t raw_base_address = 0;
        uint64_t output_size = 0;
        uint64_t raw_span_size = 0;
        uint64_t expected_bytes = 0;
        uint64_t recovered_bytes = 0;
        uint64_t missing_bytes = 0;
        // Immutable identity from the ELF header before any section-table
        // normalization.  This remains available even when raw_image cannot
        // be retained because of the configured raw-span limit.
        uint64_t original_elf_header_hash = 0;
        uint64_t original_e_shoff = 0;
        uint16_t original_e_shnum = 0;
        uint16_t original_e_shstrndx = 0;

        std::vector<LoadSegment> segments;
        std::vector<ReadSpan> reads;
        std::vector<Hole> holes;
        std::vector<uint8_t> image;
        std::vector<uint8_t> raw_image;

        double completeness_percent() const {
            if (expected_bytes == 0) return 0.0;
            return static_cast<double>(recovered_bytes) * 100.0 /
                   static_cast<double>(expected_bytes);
        }
    };

    struct ArtifactMetadata {
        uint32_t pid = 0;
        uint64_t process_start_time = 0;
        uint64_t reconstructed_hash = 0;
        uint64_t raw_layout_hash = 0;
        uint64_t evidence_hash = 0;
    };

    using ArtifactPublishGuard = bool (*)(void*);

    static bool reconstruct(uintptr_t elf_header_address,
                            const MapsRegion* maps, size_t map_count,
                            ReadCallback reader, void* reader_context,
                            Result* result) {
        return reconstruct(elf_header_address, maps, map_count, reader,
                           reader_context, Options{}, result);
    }

    static bool reconstruct(uintptr_t elf_header_address,
                            const MapsRegion* maps, size_t map_count,
                            ReadCallback reader, void* reader_context,
                            const Options& options, Result* result) {
        if (!result) return false;
        *result = Result{};
        result->elf_header_address = elf_header_address;
        if (!reader) return fail(result, "missing memory reader");
        if (elf_header_address == 0) return fail(result, "invalid ELF header address");
        if (options.max_output_size < 64 || options.read_chunk_size == 0 ||
            options.max_program_headers == 0) {
            return fail(result, "invalid reconstruction options");
        }

        uint8_t header[64] = {};
        if (!read_fully(reader, reader_context, header, 16, elf_header_address))
            return fail(result, "cannot read ELF identification");
        if (std::memcmp(header, "\x7f" "ELF", 4) != 0)
            return fail(result, "ELF magic not present");
        if (header[4] != 1 && header[4] != 2)
            return fail(result, "unsupported ELF class");
        if (header[5] != 1)
            return fail(result, "only little-endian ELF is supported");

        const bool is64 = header[4] == 2;
        const size_t elf_header_size = is64 ? 64u : 52u;
        const uint16_t required_phentsize = is64 ? 56u : 32u;
        if (!read_fully(reader, reader_context, header, elf_header_size,
                        elf_header_address)) {
            return fail(result, "cannot read complete ELF header");
        }

        result->original_elf_header_hash =
            fnv1a64(header, elf_header_size);
        result->original_e_shoff = is64 ? read_u64(header + 40)
                                        : read_u32(header + 32);
        result->original_e_shnum = read_u16(header + (is64 ? 60 : 48));
        result->original_e_shstrndx = read_u16(header + (is64 ? 62 : 50));

        uint64_t phoff = 0;
        uint16_t ehsize = 0;
        uint16_t phentsize = 0;
        uint16_t phnum = 0;
        if (is64) {
            phoff = read_u64(header + 32);
            ehsize = read_u16(header + 52);
            phentsize = read_u16(header + 54);
            phnum = read_u16(header + 56);
        } else {
            phoff = read_u32(header + 28);
            ehsize = read_u16(header + 40);
            phentsize = read_u16(header + 42);
            phnum = read_u16(header + 44);
        }
        if (ehsize != elf_header_size)
            return fail(result, "invalid e_ehsize");
        if (phentsize != required_phentsize)
            return fail(result, "invalid e_phentsize");
        if (phoff == 0 || phnum == 0 || phnum > options.max_program_headers)
            return fail(result, "invalid program header table count/offset");

        uint64_t ph_table_size = 0;
        uint64_t ph_table_end = 0;
        if (!checked_mul(phnum, phentsize, &ph_table_size) ||
            !checked_add(phoff, ph_table_size, &ph_table_end) ||
            ph_table_size > 1024u * 1024u) {
            return fail(result, "program header table overflow");
        }
        uintptr_t ph_remote = 0;
        if (!checked_add_ptr(elf_header_address, phoff, &ph_remote))
            return fail(result, "program header address overflow");

        std::vector<uint8_t> phdrs(static_cast<size_t>(ph_table_size));
        if (!read_fully(reader, reader_context, phdrs.data(), phdrs.size(), ph_remote))
            return fail(result, "cannot read program header table");

        uint64_t output_size = 0;
        uint64_t total_load_file_bytes = 0;
        int anchor_index = -1;
        uint64_t anchor_file_offset = std::numeric_limits<uint64_t>::max();
        for (uint16_t i = 0; i < phnum; ++i) {
            const uint8_t* ph = phdrs.data() + static_cast<size_t>(i) * phentsize;
            if (read_u32(ph) != 1) continue; // PT_LOAD

            LoadSegment segment;
            segment.program_header_index = i;
            if (is64) {
                segment.flags = read_u32(ph + 4);
                segment.file_offset = read_u64(ph + 8);
                segment.virtual_address = read_u64(ph + 16);
                segment.file_size = read_u64(ph + 32);
                segment.memory_size = read_u64(ph + 40);
                segment.alignment = read_u64(ph + 48);
            } else {
                segment.file_offset = read_u32(ph + 4);
                segment.virtual_address = read_u32(ph + 8);
                segment.file_size = read_u32(ph + 16);
                segment.memory_size = read_u32(ph + 20);
                segment.flags = read_u32(ph + 24);
                segment.alignment = read_u32(ph + 28);
            }

            if (segment.file_size > segment.memory_size)
                return fail(result, "PT_LOAD p_filesz exceeds p_memsz");
            if (segment.alignment > 1) {
                if (!is_power_of_two(segment.alignment) ||
                    (segment.file_offset & (segment.alignment - 1)) !=
                    (segment.virtual_address & (segment.alignment - 1))) {
                    return fail(result, "invalid PT_LOAD alignment");
                }
            }

            uint64_t file_end = 0;
            uint64_t virtual_file_end = 0;
            uint64_t virtual_memory_end = 0;
            if (!checked_add(segment.file_offset, segment.file_size, &file_end) ||
                !checked_add(segment.virtual_address, segment.file_size,
                             &virtual_file_end) ||
                !checked_add(segment.virtual_address, segment.memory_size,
                             &virtual_memory_end)) {
                return fail(result, "PT_LOAD range overflow");
            }
            (void)virtual_file_end;
            (void)virtual_memory_end;
            if (file_end > options.max_output_size)
                return fail(result, "PT_LOAD output exceeds size limit");
            uint64_t next_total_load_file_bytes = 0;
            if (!checked_add(total_load_file_bytes, segment.file_size,
                             &next_total_load_file_bytes) ||
                next_total_load_file_bytes > options.max_output_size) {
                return fail(result, "PT_LOAD total exceeds size limit");
            }
            total_load_file_bytes = next_total_load_file_bytes;
            output_size = std::max(output_size, file_end);

            if (segment.file_offset < anchor_file_offset) {
                anchor_file_offset = segment.file_offset;
                anchor_index = static_cast<int>(result->segments.size());
            }
            result->segments.push_back(segment);
        }

        if (result->segments.empty() || anchor_index < 0)
            return fail(result, "ELF has no PT_LOAD segment");
        if (output_size == 0 || ph_table_end > output_size)
            return fail(result, "program headers are outside PT_LOAD file data");
        if (output_size > static_cast<uint64_t>(
                              std::numeric_limits<size_t>::max()))
            return fail(result, "PT_LOAD output exceeds host address space");

        // elf_header_address denotes file offset zero.  For the lowest-offset
        // PT_LOAD, runtime(file_offset) = load_bias + p_vaddr +
        // (file_offset - p_offset), hence this extrapolates the address of file
        // offset zero without assuming p_offset == p_vaddr.
        const LoadSegment& anchor = result->segments[static_cast<size_t>(anchor_index)];
        uintptr_t load_bias = 0;
        if (!bias_from_header(elf_header_address, anchor.virtual_address,
                              anchor.file_offset, &load_bias)) {
            return fail(result, "load bias underflow/overflow");
        }

        uintptr_t raw_begin = std::numeric_limits<uintptr_t>::max();
        uintptr_t raw_end = 0;
        for (LoadSegment& segment : result->segments) {
            if (!checked_add_ptr(load_bias, segment.virtual_address,
                                 &segment.remote_address)) {
                return fail(result, "PT_LOAD remote address overflow");
            }
            uintptr_t segment_end = 0;
            if (!checked_add_ptr(segment.remote_address, segment.file_size,
                                 &segment_end)) {
                return fail(result, "PT_LOAD remote range overflow");
            }
            if (segment.file_size != 0) {
                raw_begin = std::min(raw_begin, segment.remote_address);
                raw_end = std::max(raw_end, segment_end);
            }
        }
        if (raw_begin == std::numeric_limits<uintptr_t>::max() || raw_end < raw_begin)
            return fail(result, "PT_LOAD contains no file-backed bytes");

        const uint64_t raw_span = static_cast<uint64_t>(raw_end - raw_begin);
        result->is_64_bit = is64;
        result->load_bias = load_bias;
        result->output_size = output_size;
        result->raw_base_address = raw_begin;
        result->raw_span_size = raw_span;
        result->image.assign(static_cast<size_t>(output_size), 0);

        // ELF header and PHT are mandatory file evidence, even when an unusual
        // image places them in page-prefix bytes or a gap not described by a
        // PT_LOAD file range. They were read and validated above, so preserve
        // those exact bytes in the reconstructed file and account for them in
        // coverage instead of reporting a zeroed header as complete.
        std::memcpy(result->image.data(), header, elf_header_size);
        std::memcpy(result->image.data() + static_cast<size_t>(phoff),
                    phdrs.data(), phdrs.size());
        // A sparse virtual layout can place a few small PT_LOAD ranges more
        // than max_raw_span apart.  That makes a contiguous memory-order raw
        // image too expensive, but it does not make the bounded file-layout
        // reconstruction unsafe: every segment's p_offset + p_filesz was
        // already checked against max_output_size above.  Keep reconstructing
        // the useful ELF and simply omit the optional raw-layout artifact.
        // A zero cap keeps the pre-existing "do not retain raw layout"
        // behaviour instead of meaning unbounded allocation.
        const bool raw_span_within_limit =
            options.max_raw_span != 0 && raw_span <= options.max_raw_span;
        if (raw_span_within_limit &&
            raw_span <= static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
            result->raw_image.assign(static_cast<size_t>(raw_span), 0);
            result->raw_layout_available = true;
        }

        std::vector<Range> expected_ranges = {
            {0, static_cast<uint64_t>(elf_header_size)},
            {phoff, ph_table_end},
        };
        std::vector<Range> recovered_ranges = expected_ranges;
        for (const LoadSegment& segment : result->segments) {
            if (segment.file_size == 0) continue;
            expected_ranges.push_back({segment.file_offset,
                                       segment.file_offset + segment.file_size});
            capture_segment(segment, maps, map_count, reader, reader_context,
                            options, result, &recovered_ranges);
        }

        // Segment reads happen against a live process and may race mutation.
        // Keep the exact header/PHT bytes that passed validation authoritative.
        std::memcpy(result->image.data(), header, elf_header_size);
        std::memcpy(result->image.data() + static_cast<size_t>(phoff),
                    phdrs.data(), phdrs.size());

        normalize_ranges(&expected_ranges);
        normalize_ranges(&recovered_ranges);
        finalize_section_headers(result, recovered_ranges, is64);
        result->expected_bytes = range_total(expected_ranges);
        result->recovered_bytes = intersection_total(expected_ranges,
                                                     recovered_ranges);
        result->holes = subtract_ranges(expected_ranges, recovered_ranges,
                                        result->segments, load_bias);
        result->missing_bytes = range_total_holes(result->holes);
        result->complete = result->missing_bytes == 0;
        result->success = true;
        return true;
    }

    // Writes the unmodified memory-order bytes, the reconstructed ELF file,
    // and its completeness metadata to separate paths.  No input is modified.
    static bool write_artifacts(const Result& result, const char* raw_path,
                                const char* reconstructed_path,
                                const char* metadata_path,
                                const char* source_path = nullptr,
                                const ArtifactMetadata* artifact_metadata =
                                    nullptr,
                                ArtifactPublishGuard publish_guard = nullptr,
                                void* publish_guard_context = nullptr) {
        if (!result.success || !reconstructed_path || !metadata_path) return false;
        const bool publish_raw = raw_path && result.raw_layout_available;
        const std::string reconstructed_temp =
            artifact_sidecar_path_inline(reconstructed_path, "tmp");
        const std::string metadata_temp =
            artifact_sidecar_path_inline(metadata_path, "tmp");
        const std::string raw_temp = publish_raw
                                         ? artifact_sidecar_path_inline(
                                               raw_path, "tmp")
                                         : std::string();
        const auto cleanup_temporaries = [&]() {
            std::remove(reconstructed_temp.c_str());
            std::remove(metadata_temp.c_str());
            if (publish_raw) std::remove(raw_temp.c_str());
        };
        cleanup_temporaries();

        // Prepare the whole artifact set before publishing any final name.
        if (!write_file(reconstructed_temp.c_str(), result.image)) {
            cleanup_temporaries();
            return false;
        }
        if (publish_raw && !write_file(raw_temp.c_str(), result.raw_image)) {
            cleanup_temporaries();
            return false;
        }

        FILE* metadata = std::fopen(metadata_temp.c_str(), "wb");
        if (!metadata) {
            cleanup_temporaries();
            return false;
        }
        std::fprintf(metadata, "{\n  \"schema\": \"nhdd-elf-reconstruction-v1\",\n");
        std::fprintf(metadata, "  \"source_path\": ");
        write_json_string(metadata, source_path ? source_path : "");
        if (artifact_metadata) {
            std::fprintf(
                metadata,
                ",\n  \"pid\": %u,\n"
                "  \"process_start_time_ticks\": %llu,\n"
                "  \"reconstructed_hash\": \"%016llx\",\n"
                "  \"raw_layout_hash\": \"%016llx\",\n"
                "  \"evidence_hash\": \"%016llx\"",
                artifact_metadata->pid,
                static_cast<unsigned long long>(
                    artifact_metadata->process_start_time),
                static_cast<unsigned long long>(
                    artifact_metadata->reconstructed_hash),
                static_cast<unsigned long long>(
                    artifact_metadata->raw_layout_hash),
                static_cast<unsigned long long>(
                    artifact_metadata->evidence_hash));
        }
        std::fprintf(metadata,
                     ",\n  \"elf_class\": %d,\n  \"elf_header_address\": \"0x%llx\",\n"
                     "  \"load_bias\": \"0x%llx\",\n  \"output_size\": %llu,\n"
                     "  \"raw_base_address\": \"0x%llx\",\n  \"raw_span_size\": %llu,\n"
                     "  \"raw_layout_available\": %s,\n  \"complete\": %s,\n"
                     "  \"coverage_complete\": %s,\n"
                     "  \"original_elf_header_hash\": \"%016llx\",\n"
                     "  \"original_e_shoff\": \"0x%llx\",\n"
                     "  \"original_e_shnum\": %u,\n"
                     "  \"original_e_shstrndx\": %u,\n"
                     "  \"section_headers_preserved\": %s,\n"
                     "  \"section_headers_normalized\": %s,\n"
                     "  \"snapshot_consistency\": \"best_effort_live\",\n"
                     "  \"expected_bytes\": %llu,\n  \"recovered_bytes\": %llu,\n"
                     "  \"missing_bytes\": %llu,\n  \"completeness_percent\": %.4f,\n",
                     result.is_64_bit ? 64 : 32,
                     static_cast<unsigned long long>(result.elf_header_address),
                     static_cast<unsigned long long>(result.load_bias),
                     static_cast<unsigned long long>(result.output_size),
                     static_cast<unsigned long long>(result.raw_base_address),
                     static_cast<unsigned long long>(result.raw_span_size),
                     result.raw_layout_available ? "true" : "false",
                     result.complete ? "true" : "false",
                     result.complete ? "true" : "false",
                     static_cast<unsigned long long>(
                         result.original_elf_header_hash),
                     static_cast<unsigned long long>(result.original_e_shoff),
                     static_cast<unsigned>(result.original_e_shnum),
                     static_cast<unsigned>(result.original_e_shstrndx),
                     result.section_headers_preserved ? "true" : "false",
                     result.section_headers_normalized ? "true" : "false",
                     static_cast<unsigned long long>(result.expected_bytes),
                     static_cast<unsigned long long>(result.recovered_bytes),
                     static_cast<unsigned long long>(result.missing_bytes),
                     result.completeness_percent());

        std::fprintf(metadata, "  \"segments\": [");
        for (size_t i = 0; i < result.segments.size(); ++i) {
            const LoadSegment& segment = result.segments[i];
            std::fprintf(metadata,
                         "%s\n    {\"ph_index\":%u,\"flags\":%u,"
                         "\"p_offset\":%llu,\"p_vaddr\":\"0x%llx\","
                         "\"p_filesz\":%llu,\"p_memsz\":%llu,"
                         "\"remote_address\":\"0x%llx\"}",
                         i == 0 ? "" : ",", segment.program_header_index,
                         segment.flags,
                         static_cast<unsigned long long>(segment.file_offset),
                         static_cast<unsigned long long>(segment.virtual_address),
                         static_cast<unsigned long long>(segment.file_size),
                         static_cast<unsigned long long>(segment.memory_size),
                         static_cast<unsigned long long>(segment.remote_address));
        }
        std::fprintf(metadata, "\n  ],\n  \"holes\": [");
        for (size_t i = 0; i < result.holes.size(); ++i) {
            const Hole& hole = result.holes[i];
            std::fprintf(metadata,
                         "%s\n    {\"file_offset\":%llu,\"size\":%llu,"
                         "\"remote_address\":\"0x%llx\"}",
                         i == 0 ? "" : ",",
                         static_cast<unsigned long long>(hole.file_offset),
                         static_cast<unsigned long long>(hole.size),
                         static_cast<unsigned long long>(hole.remote_address));
        }
        std::fprintf(metadata, "\n  ]\n}\n");
        bool metadata_ok = std::fflush(metadata) == 0 &&
                           artifact_sync_file_inline(metadata);
        if (std::fclose(metadata) != 0) metadata_ok = false;
        if (!metadata_ok) {
            cleanup_temporaries();
            return false;
        }

        std::vector<ArtifactTransactionEntryInline> publications;
        publications.reserve(publish_raw ? 3 : 2);
        if (publish_raw) {
            publications.emplace_back(raw_path, raw_temp.c_str());
        }
        publications.emplace_back(reconstructed_path,
                                  reconstructed_temp.c_str());
        publications.emplace_back(metadata_path, metadata_temp.c_str());
        return artifact_publish_transaction_inline(
            &publications, publish_guard, publish_guard_context);
    }

private:
    struct Range {
        uint64_t begin = 0;
        uint64_t end = 0;
    };

    struct SectionHeader {
        uint32_t name = 0;
        uint32_t type = 0;
        uint64_t flags = 0;
        uint64_t address = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
        uint32_t link = 0;
        uint32_t info = 0;
        uint64_t address_alignment = 0;
        uint64_t entry_size = 0;
    };

    static bool fail(Result* result, const char* error) {
        result->success = false;
        result->error = error ? error : "unknown error";
        return false;
    }

    static uint16_t read_u16(const uint8_t* p) {
        uint16_t value = 0;
        std::memcpy(&value, p, sizeof(value));
        return value;
    }

    static uint32_t read_u32(const uint8_t* p) {
        uint32_t value = 0;
        std::memcpy(&value, p, sizeof(value));
        return value;
    }

    static uint64_t read_u64(const uint8_t* p) {
        uint64_t value = 0;
        std::memcpy(&value, p, sizeof(value));
        return value;
    }

    static uint64_t fnv1a64(const uint8_t* bytes, size_t size) {
        uint64_t hash = 14695981039346656037ULL;
        for (size_t i = 0; i < size; ++i) {
            hash ^= bytes[i];
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    static void write_u16(uint8_t* p, uint16_t value) {
        std::memcpy(p, &value, sizeof(value));
    }

    static void write_u32(uint8_t* p, uint32_t value) {
        std::memcpy(p, &value, sizeof(value));
    }

    static void write_u64(uint8_t* p, uint64_t value) {
        std::memcpy(p, &value, sizeof(value));
    }

    static bool checked_add(uint64_t a, uint64_t b, uint64_t* out) {
        if (b > std::numeric_limits<uint64_t>::max() - a) return false;
        *out = a + b;
        return true;
    }

    static bool checked_mul(uint64_t a, uint64_t b, uint64_t* out) {
        if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
        *out = a * b;
        return true;
    }

    static bool checked_add_ptr(uintptr_t a, uint64_t b, uintptr_t* out) {
        if (b > static_cast<uint64_t>(std::numeric_limits<uintptr_t>::max()) -
                    static_cast<uint64_t>(a)) {
            return false;
        }
        *out = a + static_cast<uintptr_t>(b);
        return true;
    }

    static bool bias_from_header(uintptr_t header, uint64_t virtual_address,
                                 uint64_t file_offset, uintptr_t* bias) {
        if (virtual_address >= file_offset) {
            const uint64_t delta = virtual_address - file_offset;
            if (delta > static_cast<uint64_t>(header)) return false;
            *bias = header - static_cast<uintptr_t>(delta);
            return true;
        }
        return checked_add_ptr(header, file_offset - virtual_address, bias);
    }

    static bool is_power_of_two(uint64_t value) {
        return value != 0 && (value & (value - 1)) == 0;
    }

    static bool read_fully(ReadCallback reader, void* context, uint8_t* destination,
                           size_t size, uintptr_t remote_address) {
        size_t done = 0;
        while (done < size) {
            uintptr_t current = 0;
            if (!checked_add_ptr(remote_address, done, &current)) return false;
            const std::ptrdiff_t got =
                reader(context, destination + done, size - done, current);
            if (got <= 0 || static_cast<size_t>(got) > size - done) return false;
            done += static_cast<size_t>(got);
        }
        return true;
    }

    static int find_map(const MapsRegion* maps, size_t map_count,
                        uintptr_t address) {
        if (!maps) return -1;
        for (size_t i = 0; i < map_count; ++i) {
            if (maps[i].start <= address && address < maps[i].end)
                return static_cast<int>(i);
        }
        return -1;
    }

    static uintptr_t next_map_start(const MapsRegion* maps, size_t map_count,
                                    uintptr_t address, uintptr_t limit) {
        uintptr_t next = limit;
        if (!maps) return next;
        for (size_t i = 0; i < map_count; ++i) {
            if (maps[i].start > address && maps[i].start < next)
                next = maps[i].start;
        }
        return next;
    }

    static void append_read(Result* result, uint64_t file_offset, uint64_t size,
                            uintptr_t remote_address, int map_index) {
        if (size == 0) return;
        if (!result->reads.empty()) {
            ReadSpan& previous = result->reads.back();
            uintptr_t previous_remote_end = 0;
            const bool remote_ok = checked_add_ptr(previous.remote_address,
                                                   previous.size,
                                                   &previous_remote_end);
            if (previous.map_index == map_index &&
                previous.file_offset + previous.size == file_offset &&
                remote_ok && previous_remote_end == remote_address) {
                previous.size += size;
                return;
            }
        }
        result->reads.push_back({file_offset, size, remote_address, map_index});
    }

    static void capture_segment(const LoadSegment& segment,
                                const MapsRegion* maps, size_t map_count,
                                ReadCallback reader, void* reader_context,
                                const Options& options, Result* result,
                                std::vector<Range>* recovered_ranges) {
        uint64_t segment_offset = 0;
        while (segment_offset < segment.file_size) {
            uintptr_t remote = 0;
            if (!checked_add_ptr(segment.remote_address, segment_offset, &remote))
                return;
            const uint64_t remaining = segment.file_size - segment_offset;
            int map_index = maps && map_count ? find_map(maps, map_count, remote) : -1;
            uint64_t available = remaining;
            if (maps && map_count) {
                if (map_index < 0) {
                    uintptr_t segment_end = 0;
                    if (!checked_add_ptr(remote, remaining, &segment_end)) return;
                    const uintptr_t next = next_map_start(maps, map_count, remote,
                                                         segment_end);
                    uint64_t gap = static_cast<uint64_t>(next - remote);
                    if (gap == 0) gap = 1;
                    segment_offset += std::min(gap, remaining);
                    continue;
                }
                available = std::min<uint64_t>(
                    remaining, static_cast<uint64_t>(maps[map_index].end - remote));
            }

            uint64_t in_map = 0;
            while (in_map < available) {
                const size_t request = static_cast<size_t>(std::min<uint64_t>(
                    available - in_map, options.read_chunk_size));
                const uint64_t file_offset = segment.file_offset + segment_offset + in_map;
                uintptr_t chunk_remote = 0;
                if (!checked_add_ptr(remote, in_map, &chunk_remote)) return;

                size_t got_total = 0;
                while (got_total < request) {
                    uintptr_t read_remote = 0;
                    if (!checked_add_ptr(chunk_remote, got_total, &read_remote)) break;
                    const std::ptrdiff_t got = reader(
                        reader_context,
                        result->image.data() + static_cast<size_t>(file_offset) + got_total,
                        request - got_total, read_remote);
                    if (got <= 0 || static_cast<size_t>(got) > request - got_total) break;
                    const size_t got_size = static_cast<size_t>(got);
                    if (result->raw_layout_available) {
                        const uint64_t raw_offset =
                            static_cast<uint64_t>(read_remote - result->raw_base_address);
                        std::memcpy(result->raw_image.data() + static_cast<size_t>(raw_offset),
                                    result->image.data() + static_cast<size_t>(file_offset) +
                                        got_total,
                                    got_size);
                    }
                    recovered_ranges->push_back({file_offset + got_total,
                                                 file_offset + got_total + got_size});
                    append_read(result, file_offset + got_total, got_size,
                                read_remote, map_index);
                    got_total += got_size;
                }
                // A failed subrange remains zero and will be represented by the
                // normalized holes list.  Continue at the next chunk/map.
                in_map += request;
            }
            segment_offset += available;
        }
    }

    static void normalize_ranges(std::vector<Range>* ranges) {
        std::sort(ranges->begin(), ranges->end(),
                  [](const Range& a, const Range& b) {
                      return a.begin < b.begin ||
                             (a.begin == b.begin && a.end < b.end);
                  });
        size_t output = 0;
        for (const Range& range : *ranges) {
            if (range.end <= range.begin) continue;
            if (output != 0 && (*ranges)[output - 1].end >= range.begin) {
                (*ranges)[output - 1].end =
                    std::max((*ranges)[output - 1].end, range.end);
            } else {
                (*ranges)[output++] = range;
            }
        }
        ranges->resize(output);
    }

    static bool range_fully_recovered(const std::vector<Range>& recovered,
                                      uint64_t begin, uint64_t end) {
        if (end <= begin) return false;
        uint64_t cursor = begin;
        for (const Range& range : recovered) {
            if (range.end <= cursor) continue;
            if (range.begin > cursor) return false;
            cursor = std::max(cursor, range.end);
            if (cursor >= end) return true;
        }
        return false;
    }

    static SectionHeader read_section_header(const uint8_t* section,
                                             bool is64) {
        SectionHeader header;
        header.name = read_u32(section);
        header.type = read_u32(section + 4);
        if (is64) {
            header.flags = read_u64(section + 8);
            header.address = read_u64(section + 16);
            header.offset = read_u64(section + 24);
            header.size = read_u64(section + 32);
            header.link = read_u32(section + 40);
            header.info = read_u32(section + 44);
            header.address_alignment = read_u64(section + 48);
            header.entry_size = read_u64(section + 56);
        } else {
            header.flags = read_u32(section + 8);
            header.address = read_u32(section + 12);
            header.offset = read_u32(section + 16);
            header.size = read_u32(section + 20);
            header.link = read_u32(section + 24);
            header.info = read_u32(section + 28);
            header.address_alignment = read_u32(section + 32);
            header.entry_size = read_u32(section + 36);
        }
        return header;
    }

    static bool section_zero_is_valid(const SectionHeader& section,
                                      uint16_t shnum,
                                      uint16_t shstrndx) {
        // The null section is all zero except for the three fields explicitly
        // repurposed by ELF extended numbering.  e_phnum == PN_XNUM is not
        // accepted by reconstruct(), so sh_info has no valid exception here.
        if (section.name != 0 || section.type != 0 || section.flags != 0 ||
            section.address != 0 || section.offset != 0 || section.info != 0 ||
            section.address_alignment != 0 || section.entry_size != 0) {
            return false;
        }
        if ((shnum == 0) != (section.size != 0)) return false;
        if (shnum != 0 && section.size != 0) return false;
        // Values from SHN_LORESERVE through SHN_HIRESERVE are not direct
        // e_shnum/e_shstrndx indexes.  Large values use the section-zero
        // extended-numbering fields instead.
        if (shnum >= 0xff00u) return false;
        if (shstrndx != 0xffffu && shstrndx >= 0xff00u) return false;
        if (shstrndx == 0xffffu) return true;
        return section.link == 0;
    }

    static bool section_link_is(const std::vector<SectionHeader>& sections,
                                uint32_t index, uint32_t first_type,
                                uint32_t second_type = UINT32_MAX) {
        if (index == 0 || static_cast<uint64_t>(index) >= sections.size())
            return false;
        const uint32_t type = sections[index].type;
        return type == first_type || type == second_type;
    }

    static bool section_links_are_valid(
        const std::vector<SectionHeader>& sections, bool is64) {
        constexpr uint32_t kShtSymtab = 2;
        constexpr uint32_t kShtStrtab = 3;
        constexpr uint32_t kShtRela = 4;
        constexpr uint32_t kShtHash = 5;
        constexpr uint32_t kShtDynamic = 6;
        constexpr uint32_t kShtRel = 9;
        constexpr uint32_t kShtDynsym = 11;
        constexpr uint32_t kShtInitArray = 14;
        constexpr uint32_t kShtFiniArray = 15;
        constexpr uint32_t kShtPreinitArray = 16;
        constexpr uint32_t kShtGroup = 17;
        constexpr uint32_t kShtSymtabShndx = 18;
        constexpr uint32_t kShtRelr = 19;
        constexpr uint64_t kShfInfoLink = 0x40;
        constexpr uint64_t kShfLinkOrder = 0x80;

        for (const SectionHeader& section : sections) {
            if ((section.flags & kShfLinkOrder) != 0 &&
                (section.link == 0 ||
                 static_cast<uint64_t>(section.link) >= sections.size())) {
                return false;
            }
            if ((section.flags & kShfInfoLink) != 0 &&
                static_cast<uint64_t>(section.info) >= sections.size()) {
                return false;
            }

            switch (section.type) {
                case kShtStrtab:
                    if (section.entry_size != 0) return false;
                    break;
                case kShtSymtab:
                case kShtDynsym: {
                    if (!section_link_is(sections, section.link,
                                         kShtStrtab)) {
                        return false;
                    }
                    if (section.entry_size != (is64 ? 24u : 16u))
                        return false;
                    const uint64_t entries = section.size / section.entry_size;
                    if (section.info > entries) return false;
                    break;
                }
                case kShtRela:
                    if (!section_link_is(sections, section.link, kShtSymtab,
                                         kShtDynsym) ||
                        static_cast<uint64_t>(section.info) >= sections.size() ||
                        section.entry_size != (is64 ? 24u : 12u)) {
                        return false;
                    }
                    break;
                case kShtRel:
                    if (!section_link_is(sections, section.link, kShtSymtab,
                                         kShtDynsym) ||
                        static_cast<uint64_t>(section.info) >= sections.size() ||
                        section.entry_size != (is64 ? 16u : 8u)) {
                        return false;
                    }
                    break;
                case kShtHash:
                    if (!section_link_is(sections, section.link, kShtSymtab,
                                         kShtDynsym) ||
                        section.entry_size != 4) {
                        return false;
                    }
                    break;
                case kShtDynamic:
                    if (!section_link_is(sections, section.link,
                                         kShtStrtab) ||
                        section.entry_size != (is64 ? 16u : 8u)) {
                        return false;
                    }
                    break;
                case kShtGroup:
                case kShtSymtabShndx:
                    if (!section_link_is(sections, section.link, kShtSymtab,
                                         kShtDynsym) ||
                        section.entry_size != 4) {
                        return false;
                    }
                    break;
                case kShtInitArray:
                case kShtFiniArray:
                case kShtPreinitArray:
                case kShtRelr:
                    if (section.entry_size != (is64 ? 8u : 4u))
                        return false;
                    break;
                default:
                    // Processor-, OS-, and application-specific section types
                    // define their own link/info semantics.  Do not reject
                    // those merely for using otherwise opaque values.
                    break;
            }
        }
        return true;
    }

    static bool section_table_fully_recovered(
        const Result& result, const std::vector<Range>& recovered,
        bool is64, uint64_t shoff, uint16_t shentsize,
        uint16_t shnum, uint16_t shstrndx) {
        // The all-zero triplet is the canonical representation of an ELF with
        // no section table.  Nothing needs to be normalized in that case.
        if (shoff == 0)
            return shnum == 0 && shstrndx == 0;

        const uint16_t required_shentsize = is64 ? 64u : 40u;
        if (shentsize != required_shentsize) return false;

        uint64_t first_entry_end = 0;
        if (!checked_add(shoff, shentsize, &first_entry_end) ||
            first_entry_end > result.image.size() ||
            !range_fully_recovered(recovered, shoff, first_entry_end)) {
            return false;
        }

        const uint8_t* section_zero_bytes =
            result.image.data() + static_cast<size_t>(shoff);
        const SectionHeader section_zero =
            read_section_header(section_zero_bytes, is64);
        if (!section_zero_is_valid(section_zero, shnum, shstrndx))
            return false;

        uint64_t section_count = shnum;
        if (section_count == 0) {
            // Extended section numbering stores the real count in sh_size of
            // section header zero.  Only trust it after that entry itself has
            // been proven recovered.
            section_count = section_zero.size;
            if (section_count == 0) return false;
        }

        uint64_t section_table_size = 0;
        uint64_t section_table_end = 0;
        if (!checked_mul(section_count, shentsize, &section_table_size) ||
            !checked_add(shoff, section_table_size, &section_table_end) ||
            section_table_end > result.image.size() ||
            !range_fully_recovered(recovered, shoff, section_table_end)) {
            return false;
        }

        std::vector<SectionHeader> sections;
        if (section_count > static_cast<uint64_t>(
                                std::numeric_limits<size_t>::max())) {
            return false;
        }
        sections.reserve(static_cast<size_t>(section_count));
        constexpr uint32_t kShtNobits = 8;
        for (uint64_t i = 0; i < section_count; ++i) {
            const uint64_t relative = i * shentsize; // checked by table size
            const uint8_t* bytes = result.image.data() +
                static_cast<size_t>(shoff + relative);
            const SectionHeader section = read_section_header(bytes, is64);

            // sh_size/sh_link in entry zero are extended-numbering metadata,
            // not a file range or an inter-section reference.
            if (i == 0) {
                sections.push_back(section);
                continue;
            }

            uint64_t address_end = 0;
            uint64_t file_end = 0;
            if (!checked_add(section.address, section.size, &address_end) ||
                !checked_add(section.offset, section.size, &file_end)) {
                return false;
            }
            (void)address_end;
            if (section.address_alignment != 0 &&
                (!is_power_of_two(section.address_alignment) ||
                 (section.address & (section.address_alignment - 1)) != 0)) {
                return false;
            }
            if (section.entry_size != 0 &&
                section.size % section.entry_size != 0) {
                return false;
            }
            if (section.type != kShtNobits && section.size != 0 &&
                (file_end > result.image.size() ||
                 !range_fully_recovered(recovered, section.offset,
                                        file_end))) {
                return false;
            }
            sections.push_back(section);
        }

        if (!section_links_are_valid(sections, is64)) return false;

        uint64_t string_table_index = shstrndx;
        if (shstrndx == 0xffffu) { // SHN_XINDEX
            string_table_index = section_zero.link;
        }
        if (string_table_index >= section_count) return false;

        if (string_table_index == 0) {
            // Without a section-name string table, every sh_name must denote
            // the mandatory empty name rather than an unresolvable offset.
            for (const SectionHeader& section : sections) {
                if (section.name != 0) return false;
            }
            return true;
        }

        constexpr uint32_t kShtStrtab = 3;
        const SectionHeader& string_section =
            sections[static_cast<size_t>(string_table_index)];
        if (string_section.type != kShtStrtab || string_section.size == 0)
            return false;
        uint64_t string_table_end = 0;
        if (!checked_add(string_section.offset, string_section.size,
                         &string_table_end) ||
            string_table_end > result.image.size() ||
            !range_fully_recovered(recovered, string_section.offset,
                                   string_table_end)) {
            return false;
        }
        const uint8_t* strings = result.image.data() +
            static_cast<size_t>(string_section.offset);
        const size_t string_size = static_cast<size_t>(string_section.size);
        if (strings[0] != 0 || strings[string_size - 1] != 0) return false;
        for (const SectionHeader& section : sections) {
            if (section.name >= string_section.size) return false;
            const size_t name = static_cast<size_t>(section.name);
            if (std::memchr(strings + name, 0, string_size - name) == nullptr)
                return false;
        }
        return true;
    }

    static void finalize_section_headers(Result* result,
                                         const std::vector<Range>& recovered,
                                         bool is64) {
        uint8_t* image = result->image.data();
        const uint64_t shoff = is64 ? read_u64(image + 40)
                                    : read_u32(image + 32);
        const uint16_t shentsize = read_u16(image + (is64 ? 58 : 46));
        const uint16_t shnum = read_u16(image + (is64 ? 60 : 48));
        const uint16_t shstrndx = read_u16(image + (is64 ? 62 : 50));

        if (section_table_fully_recovered(*result, recovered, is64, shoff,
                                          shentsize, shnum, shstrndx)) {
            result->section_headers_preserved = true;
            return;
        }

        // Section headers normally live after the PT_LOAD file ranges and are
        // therefore absent from a runtime-only capture.  Keeping their original
        // offsets makes otherwise useful output fail strict ELF parsers.  When
        // full recovery cannot be proven, publish the standard no-SHT triplet.
        if (is64) write_u64(image + 40, 0);
        else write_u32(image + 32, 0);
        write_u16(image + (is64 ? 60 : 48), 0);
        write_u16(image + (is64 ? 62 : 50), 0);
        result->section_headers_normalized = true;
    }

    static uint64_t range_total(const std::vector<Range>& ranges) {
        uint64_t total = 0;
        for (const Range& range : ranges) total += range.end - range.begin;
        return total;
    }

    static uint64_t intersection_total(const std::vector<Range>& expected,
                                       const std::vector<Range>& recovered) {
        uint64_t total = 0;
        size_t i = 0, j = 0;
        while (i < expected.size() && j < recovered.size()) {
            const uint64_t begin = std::max(expected[i].begin, recovered[j].begin);
            const uint64_t end = std::min(expected[i].end, recovered[j].end);
            if (end > begin) total += end - begin;
            if (expected[i].end < recovered[j].end) ++i;
            else ++j;
        }
        return total;
    }

    static uintptr_t remote_for_file_offset(const std::vector<LoadSegment>& segments,
                                            uintptr_t load_bias,
                                            uint64_t file_offset) {
        for (const LoadSegment& segment : segments) {
            if (segment.file_offset <= file_offset &&
                file_offset < segment.file_offset + segment.file_size) {
                uintptr_t remote = 0;
                const uint64_t delta = file_offset - segment.file_offset;
                if (checked_add_ptr(load_bias, segment.virtual_address, &remote) &&
                    checked_add_ptr(remote, delta, &remote)) {
                    return remote;
                }
            }
        }
        return 0;
    }

    static std::vector<Hole> subtract_ranges(
        const std::vector<Range>& expected, const std::vector<Range>& recovered,
        const std::vector<LoadSegment>& segments, uintptr_t load_bias) {
        std::vector<Hole> holes;
        size_t recovered_index = 0;
        for (const Range& wanted : expected) {
            uint64_t cursor = wanted.begin;
            while (recovered_index < recovered.size() &&
                   recovered[recovered_index].end <= cursor) {
                ++recovered_index;
            }
            size_t j = recovered_index;
            while (j < recovered.size() && recovered[j].begin < wanted.end) {
                if (recovered[j].begin > cursor) {
                    const uint64_t end = std::min(recovered[j].begin, wanted.end);
                    holes.push_back({cursor, end - cursor,
                                     remote_for_file_offset(segments, load_bias,
                                                            cursor)});
                }
                cursor = std::max(cursor, recovered[j].end);
                if (cursor >= wanted.end) break;
                ++j;
            }
            if (cursor < wanted.end) {
                holes.push_back({cursor, wanted.end - cursor,
                                 remote_for_file_offset(segments, load_bias,
                                                        cursor)});
            }
        }
        return holes;
    }

    static uint64_t range_total_holes(const std::vector<Hole>& holes) {
        uint64_t total = 0;
        for (const Hole& hole : holes) total += hole.size;
        return total;
    }

    static bool write_file(const char* path, const std::vector<uint8_t>& data) {
        if (!path) return false;
        FILE* file = std::fopen(path, "wb");
        if (!file) return false;
        const size_t written = data.empty() ? 0 :
            std::fwrite(data.data(), 1, data.size(), file);
        const bool wrote_all = written == data.size() &&
                               std::fflush(file) == 0 &&
                               artifact_sync_file_inline(file);
        const bool closed = std::fclose(file) == 0;
        return wrote_all && closed;
    }

    static void write_json_string(FILE* file, const char* value) {
        std::fputc('"', file);
        if (value) {
            for (const unsigned char* p =
                     reinterpret_cast<const unsigned char*>(value); *p; ++p) {
                switch (*p) {
                    case '"': std::fputs("\\\"", file); break;
                    case '\\': std::fputs("\\\\", file); break;
                    case '\b': std::fputs("\\b", file); break;
                    case '\f': std::fputs("\\f", file); break;
                    case '\n': std::fputs("\\n", file); break;
                    case '\r': std::fputs("\\r", file); break;
                    case '\t': std::fputs("\\t", file); break;
                    default:
                        if (*p < 0x20) std::fprintf(file, "\\u%04x", *p);
                        else std::fputc(*p, file);
                        break;
                }
            }
        }
        std::fputc('"', file);
    }
};
