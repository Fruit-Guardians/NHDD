#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../src/dedup_table.hpp"
#include "../src/so_artifact_identity.hpp"
#include "../src/so_manifest.hpp"
#include "../src/process_generation_guard.hpp"
#include "../src/jni_artifact_identity.hpp"

namespace {

SoScanManifestStatsInline baseline_scan() {
    SoScanManifestStatsInline scan;
    scan.maps = 4453;
    scan.map_start_elf_candidates = 49;
    scan.artifacts_published = 49;
    scan.coverage_complete_artifacts = 43;
    scan.partial_artifacts = 6;
    scan.skipped_system_maps = 1395;
    return scan;
}

void test_continuous_empty_increment_does_not_erase_totals() {
    SoManifestSessionInline session;
    session.record(38351447, true, baseline_scan());

    SoScanManifestStatsInline empty_increment;
    empty_increment.maps = 4598;
    empty_increment.incremental = true;
    empty_increment.scope_ranges = 2;
    session.record(38351447, true, empty_increment);

    assert(session.continuous);
    assert(session.scans_completed == 2);
    assert(session.totals.maps == 4598);
    assert(session.totals.map_start_elf_candidates == 49);
    assert(session.totals.artifacts_published == 49);
    assert(session.totals.coverage_complete_artifacts == 43);
    assert(session.totals.partial_artifacts == 6);
    assert(session.totals.skipped_system_maps == 1395);
    assert(session.last_scan.incremental);
    assert(session.last_scan.scope_ranges == 2);
    assert(session.last_scan.artifacts_published == 0);

    char path[160];
    std::snprintf(path, sizeof(path), "nhdd-so-manifest-test-%d.json",
                  so_manifest_writer_process_id_inline());
    FILE* stale = std::fopen(path, "wb");
    assert(stale);
    assert(std::fputs("stale", stale) >= 0);
    assert(std::fclose(stale) == 0);
    assert(write_so_manifest_inline(path, 7080, session));
    char temporary_path[256];
    assert(so_manifest_temporary_path_inline(
        path, 7080, temporary_path, sizeof(temporary_path)));
    FILE* temporary = std::fopen(temporary_path, "rb");
    assert(!temporary);

    FILE* input = std::fopen(path, "rb");
    assert(input);
    std::string json;
    char buffer[1024];
    size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), input)) != 0)
        json.append(buffer, read);
    std::fclose(input);
    assert(std::remove(path) == 0);

    assert(json.find("\"artifacts_published\": 49") != std::string::npos);
    assert(json.find("\"scans_completed\": 2") != std::string::npos);
    assert(json.find("\"sequence\": 2") != std::string::npos);
    assert(json.find("\"incremental\": true") != std::string::npos);
    assert(json.find("\"scope_ranges\": 2") != std::string::npos);
    // The per-scan object remains honest even though the compatible top-level
    // counters retain the session total.
    const size_t last_scan = json.find("\"last_scan\"");
    assert(last_scan != std::string::npos);
    assert(json.find("\"artifacts_published\": 0", last_scan) !=
           std::string::npos);
}

void test_process_generation_and_single_scan_reset() {
    SoManifestSessionInline continuous;
    continuous.record(100, true, baseline_scan());

    SoScanManifestStatsInline replacement;
    replacement.maps = 12;
    replacement.artifacts_published = 1;
    replacement.coverage_complete_artifacts = 1;
    continuous.record(101, true, replacement);
    assert(continuous.process_start_time == 101);
    assert(continuous.scans_completed == 1);
    assert(continuous.totals.artifacts_published == 1);
    assert(continuous.totals.partial_artifacts == 0);

    SoManifestSessionInline snapshots;
    snapshots.record(200, false, baseline_scan());
    SoScanManifestStatsInline second;
    second.maps = 99;
    snapshots.record(200, false, second);
    assert(!snapshots.continuous);
    assert(snapshots.scans_completed == 1);
    assert(snapshots.totals.maps == 99);
    assert(snapshots.totals.artifacts_published == 0);
}

void test_generation_safe_identity_and_raw_evidence() {
    const uint64_t reconstructed_hash = 0x1111222233334444ULL;
    const uint64_t raw_hash = 0xaaaabbbbccccddddULL;
    const uint64_t evidence_hash = so_combine_evidence_hash_inline(
        reconstructed_hash, raw_hash);

    SoArtifactIdentityInline first;
    first.pid = 7080;
    first.process_start_time = 100;
    first.address = 0x7aacbcd000ULL;
    first.evidence_hash = evidence_hash;
    SoArtifactIdentityInline second = first;
    second.process_start_time = 101;

    char first_key[256], second_key[256];
    char first_stem[256], second_stem[256];
    assert(so_format_dedup_key_inline(first_key, sizeof(first_key), first));
    assert(so_format_dedup_key_inline(second_key, sizeof(second_key), second));
    assert(so_format_artifact_stem_inline(
        first_stem, sizeof(first_stem), "libsame.so", first));
    assert(so_format_artifact_stem_inline(
        second_stem, sizeof(second_stem), "libsame.so", second));
    assert(std::string(first_key) != second_key);
    assert(std::string(first_stem) != second_stem);
    assert(std::string(first_stem).find("_7080_g64_") !=
           std::string::npos);
    assert(std::string(second_stem).find("_7080_g65_") !=
           std::string::npos);

    // Exercise publication with the generated stems: byte-identical
    // observations from two generations must coexist on disk.
    char first_path[512], second_path[512];
    std::snprintf(first_path, sizeof(first_path),
                  "nhdd-so-generation-test-%d-%s.bin",
                  so_manifest_writer_process_id_inline(), first_stem);
    std::snprintf(second_path, sizeof(second_path),
                  "nhdd-so-generation-test-%d-%s.bin",
                  so_manifest_writer_process_id_inline(), second_stem);
    assert(std::string(first_path) != second_path);
    FILE* first_output = std::fopen(first_path, "wb");
    assert(first_output);
    assert(std::fputs("same-bytes", first_output) >= 0);
    assert(std::fclose(first_output) == 0);
    FILE* second_output = std::fopen(second_path, "wb");
    assert(second_output);
    assert(std::fputs("same-bytes", second_output) >= 0);
    assert(std::fclose(second_output) == 0);
    FILE* first_input = std::fopen(first_path, "rb");
    FILE* second_input = std::fopen(second_path, "rb");
    assert(first_input && second_input);
    assert(std::fclose(first_input) == 0);
    assert(std::fclose(second_input) == 0);
    assert(std::remove(first_path) == 0);
    assert(std::remove(second_path) == 0);

    // Publishing generation one must not suppress byte-identical evidence
    // from a later process that reused both PID and virtual address.
    SoDedup generations(8);
    assert(!generations.seen(first_key));
    assert(!generations.remember(first_key));
    assert(!generations.seen(second_key));
    assert(!generations.remember(second_key));
    assert(generations.count() == 2);

    // A raw/original-header change remains distinct even if normalization
    // produces the same reconstructed image hash.
    SoArtifactIdentityInline raw_revision = first;
    raw_revision.evidence_hash = so_combine_evidence_hash_inline(
        reconstructed_hash, raw_hash ^ 1);
    char raw_revision_key[256];
    assert(so_format_dedup_key_inline(
        raw_revision_key, sizeof(raw_revision_key), raw_revision));
    assert(std::string(first_key) != raw_revision_key);

    const uint64_t normalized_base = so_combine_evidence_hash_inline(
        reconstructed_hash, 0);
    const uint64_t original_header_a = so_mix_original_elf_identity_inline(
        normalized_base, 0x1000, 0x2000, 8, 3);
    const uint64_t original_header_b = so_mix_original_elf_identity_inline(
        normalized_base, 0x1001, 0x2000, 8, 3);
    assert(original_header_a != original_header_b);
}

void test_so_dedup_lru_eviction() {
    SoDedup dedup(2);
    assert(!dedup.remember("a"));
    assert(!dedup.remember("b"));
    assert(dedup.count() == 2);
    assert(dedup.seen("a"));  // a is MRU; b becomes the eviction victim.
    assert(dedup.remember("c"));
    assert(dedup.eviction_count() == 1);
    assert(dedup.count() == 2);
    assert(dedup.seen("a"));
    assert(!dedup.seen("b"));
    assert(dedup.seen("c"));
    assert(!dedup.remember("c"));
    assert(dedup.eviction_count() == 1);
    dedup.reset();
    assert(dedup.count() == 0);
    assert(dedup.eviction_count() == 0);
}

void test_manifest_counters_are_64_bit() {
    SoManifestSessionInline session;
    SoScanManifestStatsInline first;
    first.artifacts_published = 0xffffffffULL;
    first.skipped_system_maps = 0xfffffffeULL;
    session.record(300, true, first);
    SoScanManifestStatsInline second;
    second.artifacts_published = 42;
    second.skipped_system_maps = 7;
    session.record(300, true, second);
    assert(session.totals.artifacts_published == 0x100000029ULL);
    assert(session.totals.skipped_system_maps == 0x100000005ULL);
}

struct FakeStartTimes {
    std::vector<uint64_t> values;
    size_t next = 0;
};

uint64_t fake_start_time_reader(void* opaque, const char*) {
    auto* source = static_cast<FakeStartTimes*>(opaque);
    if (!source || source->values.empty()) return 0;
    if (source->next >= source->values.size())
        return source->values.back();
    return source->values[source->next++];
}

void test_generation_guard_is_sticky_after_pid_reuse() {
    FakeStartTimes source{{100, 101, 100}, 0};
    ProcessGenerationGuardInline guard{
        "7080", 100, &fake_start_time_reader, &source};
    assert(guard.verify());
    assert(!guard.verify());
    assert(guard.invalid);
    const size_t reads_after_failure = source.next;
    // A later coincidental match cannot revive publication for this scan.
    assert(!guard.verify());
    assert(source.next == reads_after_failure);
}

void test_manifest_session_cache_is_generation_safe_and_bounded() {
    SoManifestSessionCacheInline cache(2);
    SoManifestSessionInline a, b, c;
    a.record(10, true, baseline_scan());
    b.record(20, true, baseline_scan());
    c.record(30, true, baseline_scan());
    cache.put({1, 10}, a);
    cache.put({2, 20}, b);
    assert(cache.size() == 2);
    cache.put({3, 30}, c);
    assert(cache.size() == 2);
    SoManifestSessionInline loaded;
    assert(!cache.get({1, 10}, &loaded));
    assert(cache.get({2, 20}, &loaded));
    assert(loaded.process_start_time == 20);

    // Reusing PID 2 immediately removes its old-generation accumulator.
    SoManifestSessionInline replacement;
    replacement.record(21, true, baseline_scan());
    cache.put({2, 21}, replacement);
    assert(!cache.get({2, 20}, nullptr));
    assert(cache.get({2, 21}, &loaded));
    assert(loaded.process_start_time == 21);
    assert(cache.size() == 2);
}

void test_manifest_io_failure_retains_retry_state_but_guard_failure_does_not() {
    SoManifestSessionCacheInline cache(4);
    const SoProcessGenerationKeyInline key{7080, 100};
    SoManifestSessionInline first;
    first.record(100, true, baseline_scan());

    // A pure I/O failure keeps the unpublished totals for the next retry.
    assert(so_manifest_retain_session_inline(&cache, key, first, false));
    SoManifestSessionInline retry;
    assert(cache.get(key, &retry));
    assert(retry.scans_completed == 1);
    assert(retry.totals.artifacts_published == 49);
    SoScanManifestStatsInline next;
    next.artifacts_published = 2;
    retry.record(100, true, next);
    assert(retry.scans_completed == 2);
    assert(retry.totals.artifacts_published == 51);

    // A guard-invalid candidate is never inserted for a reused PID.
    const SoProcessGenerationKeyInline reused{7080, 101};
    SoManifestSessionInline invalid;
    invalid.record(101, true, baseline_scan());
    assert(!so_manifest_retain_session_inline(
        &cache, reused, invalid, true));
    assert(!cache.get(reused, nullptr));
    assert(cache.get(key, &retry));
}

void test_manifest_guard_failure_preserves_previous_generation_file() {
    char path[160];
    std::snprintf(path, sizeof(path),
                  "nhdd-so-manifest-guard-test-%d.json",
                  so_manifest_writer_process_id_inline());
    FILE* previous = std::fopen(path, "wb");
    assert(previous);
    assert(std::fputs("previous", previous) >= 0);
    assert(std::fclose(previous) == 0);

    SoManifestSessionInline session;
    session.record(100, true, baseline_scan());
    // The third check fails only after the temporary manifest has replaced the
    // final name, forcing restoration from the transaction backup.
    FakeStartTimes source{{100, 100, 101}, 0};
    ProcessGenerationGuardInline guard{
        "7080", 100, &fake_start_time_reader, &source};
    assert(!write_so_manifest_inline(
        path, 7080, session, &process_generation_publish_guard_inline,
        &guard));

    FILE* input = std::fopen(path, "rb");
    assert(input);
    char bytes[32] = {};
    assert(std::fread(bytes, 1, sizeof(bytes) - 1, input) == 8);
    assert(std::fclose(input) == 0);
    assert(std::string(bytes) == "previous");
    char temporary_path[256];
    assert(so_manifest_temporary_path_inline(
        path, 7080, temporary_path, sizeof(temporary_path)));
    assert(!artifact_file_exists_inline(temporary_path));
    const std::string backup_path =
        artifact_sidecar_path_inline(path, "bak");
    assert(!artifact_file_exists_inline(backup_path.c_str()));
    assert(std::remove(path) == 0);

    // With no previous manifest, the same post-replacement failure must leave
    // no final, temporary, or backup file behind.
    FakeStartTimes no_previous_source{{100, 100, 101}, 0};
    ProcessGenerationGuardInline no_previous_guard{
        "7080", 100, &fake_start_time_reader, &no_previous_source};
    assert(!write_so_manifest_inline(
        path, 7080, session, &process_generation_publish_guard_inline,
        &no_previous_guard));
    assert(!artifact_file_exists_inline(path));
    assert(!artifact_file_exists_inline(temporary_path));
    assert(!artifact_file_exists_inline(backup_path.c_str()));

    // Failure at the first pre-publish check must not remove an older valid
    // session file either.
    previous = std::fopen(path, "wb");
    assert(previous);
    assert(std::fputs("previous", previous) >= 0);
    assert(std::fclose(previous) == 0);
    FakeStartTimes immediate_reuse{{101}, 0};
    ProcessGenerationGuardInline immediate_guard{
        "7080", 100, &fake_start_time_reader, &immediate_reuse};
    assert(!write_so_manifest_inline(
        path, 7080, session, &process_generation_publish_guard_inline,
        &immediate_guard));
    input = std::fopen(path, "rb");
    assert(input);
    std::memset(bytes, 0, sizeof(bytes));
    assert(std::fread(bytes, 1, sizeof(bytes) - 1, input) == 8);
    assert(std::fclose(input) == 0);
    assert(std::string(bytes) == "previous");
    assert(!artifact_file_exists_inline(temporary_path));
    assert(!artifact_file_exists_inline(backup_path.c_str()));
    assert(std::remove(path) == 0);
}

void test_jni_dedup_identity_is_generation_safe() {
    char first[128], same[128], next_generation[128], next_pid[128];
    assert(jni_format_dedup_key_inline(
        first, sizeof(first), 7080, 100, "nativeFoo", "()V", "libx.so",
        0x1234));
    assert(jni_format_dedup_key_inline(
        same, sizeof(same), 7080, 100, "nativeFoo", "()V", "libx.so",
        0x1234));
    assert(jni_format_dedup_key_inline(
        next_generation, sizeof(next_generation), 7080, 101, "nativeFoo",
        "()V", "libx.so", 0x1234));
    assert(jni_format_dedup_key_inline(
        next_pid, sizeof(next_pid), 7081, 100, "nativeFoo", "()V",
        "libx.so", 0x1234));
    assert(std::string(first) == same);
    assert(std::string(first) != next_generation);
    assert(std::string(first) != next_pid);
}

void test_jni_growth_preserves_old_items_and_zeros_only_new_tail() {
    struct Cell {
        uint64_t first;
        uint64_t second;
    };
    int capacity = 2;
    auto* cells = static_cast<Cell*>(
        std::calloc(static_cast<size_t>(capacity), sizeof(Cell)));
    assert(cells);
    cells[0] = {0x1111, 0x2222};
    cells[1] = {0x3333, 0x4444};
    assert(jni_grow_zeroed_buffer_inline(&cells, &capacity));
    assert(capacity == 4);
    assert(cells[0].first == 0x1111 && cells[0].second == 0x2222);
    assert(cells[1].first == 0x3333 && cells[1].second == 0x4444);
    assert(cells[2].first == 0 && cells[2].second == 0);
    assert(cells[3].first == 0 && cells[3].second == 0);
    std::free(cells);
}

}  // namespace

int main() {
    test_continuous_empty_increment_does_not_erase_totals();
    test_process_generation_and_single_scan_reset();
    test_generation_safe_identity_and_raw_evidence();
    test_so_dedup_lru_eviction();
    test_manifest_counters_are_64_bit();
    test_generation_guard_is_sticky_after_pid_reuse();
    test_manifest_session_cache_is_generation_safe_and_bounded();
    test_manifest_io_failure_retains_retry_state_but_guard_failure_does_not();
    test_manifest_guard_failure_preserves_previous_generation_file();
    test_jni_dedup_identity_is_generation_safe();
    test_jni_growth_preserves_old_items_and_zeros_only_new_tail();
    std::puts("so_manifest_test: OK");
    return 0;
}
