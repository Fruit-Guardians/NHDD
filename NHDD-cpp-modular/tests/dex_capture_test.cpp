#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include "../src/dex_capture.hpp"
#include "../src/dex_validator.hpp"

static DexCandidateIdentity identity(uintptr_t address, uint32_t size,
                                     uint64_t fingerprint = 0x1234) {
    DexCandidateIdentity id;
    id.pid = 123;
    id.process_start_time = 456;
    id.address = address;
    id.dex_size = size;
    id.header_fingerprint = fingerprint;
    return id;
}

static void test_multi_round_merge_and_holes() {
    DexCapture capture(identity(0x1000, 16), false);
    capture.observe(false);

    const uint8_t first[] = {1, 2, 3, 4, 5, 6};
    assert(capture.merge(0, first, sizeof(first)) == 6);
    const uint8_t tail[] = {11, 12, 13, 14, 15, 16};
    assert(capture.merge(10, tail, sizeof(tail)) == 6);
    assert(capture.covered_bytes() == 12);
    assert(!capture.complete());

    const auto holes = capture.holes();
    assert(holes.size() == 1);
    assert(holes[0].offset == 6 && holes[0].length == 4);

    const uint8_t middle[] = {7, 8, 9, 10};
    assert(capture.merge(6, middle, sizeof(middle)) == 4);
    assert(capture.complete());
    assert(capture.holes().empty());

    for (size_t i = 0; i < 16; ++i)
        assert(capture.data()[i] == i + 1);
}

static void test_older_bytes_are_never_overwritten() {
    DexCapture capture(identity(0x2000, 8), false);
    const uint8_t original[] = {1, 2, 3, 4};
    const uint8_t later[] = {9, 9, 9, 9, 5, 6};
    assert(capture.merge(0, original, sizeof(original)) == 4);
    assert(capture.merge(0, later, sizeof(later)) == 2);
    assert(capture.covered_bytes() == 6);
    assert(capture.data()[0] == 1 && capture.data()[3] == 4);
    assert(capture.data()[4] == 5 && capture.data()[5] == 6);
}

static void test_refresh_tracks_decrypt_in_place_revision() {
    DexCapture capture(identity(0x2800, 8), false);
    const uint8_t encrypted[] = {1, 2, 3, 4, 5, 6, 7, 8};
    assert(capture.merge(0, encrypted, sizeof(encrypted)) == 8);
    assert(capture.complete());
    const uint64_t revision_before = capture.content_revision();

    const uint8_t decrypted[] = {1, 2, 9, 9, 5, 6, 7, 8};
    const DexRefreshResult update = capture.refresh(
        0, decrypted, sizeof(decrypted));
    assert(update.new_bytes == 0);
    assert(update.changed_bytes == 2);
    assert(capture.content_revision() > revision_before);
    assert(std::memcmp(capture.data(), decrypted, sizeof(decrypted)) == 0);

    capture.mark_content_key_processed(0x1111, true);
    capture.mark_content_key_processed(0x2222, false);
    assert(capture.content_key_processed(0x1111));
    assert(capture.content_key_processed(0x2222));
    assert(!capture.content_key_processed(0x3333));
    assert(capture.ever_published());

    // Revision bookkeeping is bounded for continuous scans. Once the oldest
    // key is evicted it may be revalidated, while recent revisions remain
    // suppressed.
    for (uint64_t key = 0x3000; key < 0x3100; ++key)
        capture.mark_content_key_processed(key, false);
    assert(!capture.content_key_processed(0x1111));
    assert(capture.content_key_processed(0x30ff));
}

static void test_generation_change_discards_unread_old_pages() {
    constexpr size_t kSize = 0x50;
    std::vector<uint8_t> old_bytes(kSize);
    for (size_t i = 0; i < old_bytes.size(); ++i)
        old_bytes[i] = static_cast<uint8_t>(i + 1);

    DexCapture capture(identity(0x2900, kSize), false);
    capture.merge(0, old_bytes.data(), old_bytes.size());
    assert(capture.complete());

    DexCapture observation(capture.identity(), false);
    const uint8_t new_prefix[] = {21, 22, 23, 24};
    constexpr size_t kBodyOffset = 0x30;
    observation.merge(kBodyOffset, new_prefix, sizeof(new_prefix));
    const DexRefreshResult update = capture.apply_observation(observation);
    assert(update.changed_bytes == sizeof(new_prefix));
    assert(capture.covered_bytes() == sizeof(new_prefix));
    assert(!capture.complete());
    const auto holes = capture.holes();
    assert(holes.size() == 2);
    assert(holes[0].offset == 0);
    assert(holes[0].length == kBodyOffset);
    assert(holes[1].offset == kBodyOffset + sizeof(new_prefix));
    assert(holes[1].length == kSize - holes[1].offset);

    std::vector<uint8_t> new_bytes = old_bytes;
    std::memcpy(new_bytes.data() + kBodyOffset, new_prefix,
                sizeof(new_prefix));
    DexCapture next_observation(capture.identity(), false);
    next_observation.merge(0, new_bytes.data(), new_bytes.size());
    const DexRefreshResult completed =
        capture.apply_observation(next_observation);
    assert(completed.changed_bytes == 0);
    assert(completed.new_bytes == kSize - sizeof(new_prefix));
    assert(capture.complete());
    assert(std::memcmp(capture.data(), new_bytes.data(), new_bytes.size()) == 0);
}

static void test_volatile_header_changes_preserve_body_coverage() {
    constexpr size_t kSize = 0x60;
    constexpr size_t kVolatileHeaderSize = 0x24;
    constexpr size_t kBodyOffset = 0x40;
    const uint8_t body[] = {0xa1, 0xa2, 0xa3, 0xa4,
                            0xa5, 0xa6, 0xa7, 0xa8};
    std::vector<uint8_t> header(kVolatileHeaderSize);
    for (size_t i = 0; i < header.size(); ++i)
        header[i] = static_cast<uint8_t>(0x80 + i);

    DexCapture capture(identity(0x2980, kSize), false);
    assert(capture.merge(0, header.data(), header.size()) == header.size());
    assert(capture.merge(kBodyOffset, body, sizeof(body)) == sizeof(body));
    assert(capture.covered_bytes() == header.size() + sizeof(body));
    const uint64_t initial_revision = capture.content_revision();

    // Simulate a packer wiping magic/version, checksum, signature and
    // file_size while exposing only one small piece of a previously missing
    // body range. Existing body coverage must survive this header-only churn.
    DexCapture wiped(capture.identity(), false);
    std::vector<uint8_t> zero_header(kVolatileHeaderSize, 0);
    const uint8_t first_hole_piece[] = {0x31, 0x32, 0x33, 0x34};
    wiped.merge(0, zero_header.data(), zero_header.size());
    wiped.merge(0x30, first_hole_piece, sizeof(first_hole_piece));
    wiped.merge(kBodyOffset, body, sizeof(body));
    const DexRefreshResult wipe_update = capture.apply_observation(wiped);
    assert(wipe_update.changed_bytes == kVolatileHeaderSize);
    assert(wipe_update.new_bytes == sizeof(first_hole_piece));
    assert(capture.covered_bytes() ==
           kVolatileHeaderSize + sizeof(first_hole_piece) + sizeof(body));
    assert(capture.content_revision() > initial_revision);
    assert(std::memcmp(capture.data(), zero_header.data(),
                       zero_header.size()) == 0);
    assert(std::memcmp(capture.data() + kBodyOffset, body, sizeof(body)) == 0);

    // Restore the volatile header and fill only another slice of the holes.
    // Both the earlier slice and the old body span must remain covered.
    DexCapture restored(capture.identity(), false);
    const uint8_t second_hole_piece[] = {0x35, 0x36, 0x37, 0x38};
    restored.merge(0, header.data(), header.size());
    restored.merge(0x34, second_hole_piece, sizeof(second_hole_piece));
    restored.merge(kBodyOffset, body, sizeof(body));
    const uint64_t wiped_revision = capture.content_revision();
    const DexRefreshResult restore_update = capture.apply_observation(restored);
    assert(restore_update.changed_bytes == kVolatileHeaderSize);
    assert(restore_update.new_bytes == sizeof(second_hole_piece));
    assert(capture.covered_bytes() ==
           kVolatileHeaderSize + sizeof(first_hole_piece) +
               sizeof(second_hole_piece) + sizeof(body));
    assert(capture.content_revision() > wiped_revision);
    assert(std::memcmp(capture.data(), header.data(), header.size()) == 0);
    assert(std::memcmp(capture.data() + 0x30, first_hole_piece,
                       sizeof(first_hole_piece)) == 0);
    assert(std::memcmp(capture.data() + 0x34, second_hole_piece,
                       sizeof(second_hole_piece)) == 0);
    assert(std::memcmp(capture.data() + kBodyOffset, body, sizeof(body)) == 0);
}

static void test_page_coverage() {
    DexCapture capture(identity(0x3000, 10), false);
    const uint8_t head[] = {1, 2, 3, 4};
    const uint8_t tail[] = {9, 10};
    capture.merge(0, head, sizeof(head));
    capture.merge(8, tail, sizeof(tail));

    const DexPageCoverage pages = capture.page_coverage(4);
    assert(pages.total_pages == 3);
    assert(pages.complete_pages == 2);
    assert(pages.partial_pages == 0);
    assert(pages.missing_pages == 1);

    const uint8_t one[] = {7};
    capture.merge(6, one, sizeof(one));
    const DexPageCoverage partial = capture.page_coverage(4);
    assert(partial.complete_pages == 2);
    assert(partial.partial_pages == 1);
    assert(partial.missing_pages == 0);
}

static void test_cache_identity_and_budget() {
    uint8_t header[0x70] = {};
    for (size_t i = 0x20; i < sizeof(header); ++i)
        header[i] = static_cast<uint8_t>(i);
    const uint64_t fp = DexCaptureCache::stable_header_fingerprint(
        header, sizeof(header));

    // Changes to magic/checksum/signature do not split one candidate.
    header[0] ^= 0xff;
    header[8] ^= 0xff;
    header[0x20] ^= 0xff;
    assert(fp == DexCaptureCache::stable_header_fingerprint(
                     header, sizeof(header)));
    // A structural header change does split it.
    header[0x40] ^= 1;
    const uint64_t fp2 = DexCaptureCache::stable_header_fingerprint(
        header, sizeof(header));
    assert(fp != fp2);

    DexCaptureCache cache(2, 24);
    bool created = false;
    DexCapture* a = cache.get_or_create(identity(0x4000, 8, fp), false,
                                        &created);
    assert(a && created && a->observations() == 0);
    a->observe(false);
    DexCapture* same = cache.get_or_create(identity(0x4000, 8, fp), true,
                                           &created);
    assert(same == a && !created && a->observations() == 1);
    same->observe(true);
    assert(a->observations() == 2);
    assert(a->relaxed_detection());
    DexCapture* distinct = cache.get_or_create(identity(0x4000, 8, fp2), false);
    assert(distinct && distinct != a);
    // Capacity pressure evicts the least-recently-used entry instead of
    // permanently refusing every later candidate.
    assert(cache.get_or_create(identity(0x5000, 8, fp), false) != nullptr);
    assert(cache.size() == 2);
    assert(cache.bytes_used() == 16);
    assert(cache.get_or_create(identity(0x6000, 25, fp), false) == nullptr);

    assert(cache.discard_intersecting(123, 456, 0x4fff, 0x5009) == 1);
    assert(cache.size() == 1);

    DexCaptureCache generations(4, 64);
    DexCandidateIdentity old_mapping = identity(0x7000, 8, fp);
    old_mapping.mapping_fingerprint = 1;
    DexCandidateIdentity new_mapping = old_mapping;
    new_mapping.mapping_fingerprint = 2;
    DexCapture* old_capture = generations.get_or_create(old_mapping, false);
    DexCapture* new_capture = generations.get_or_create(new_mapping, false);
    assert(old_capture && new_capture && old_capture != new_capture);
}

static void test_first_read_wins_across_overlaps() {
    constexpr size_t kSize = 257;
    DexCapture capture(identity(0x6000, kSize), false);
    std::vector<uint8_t> expected(kSize, 0);
    std::vector<bool> present(kSize, false);

    uint32_t state = 0x12345678;
    for (size_t round = 0; round < 500; ++round) {
        state = state * 1664525u + 1013904223u;
        const size_t offset = state % kSize;
        state = state * 1664525u + 1013904223u;
        const size_t length = 1 + state % (kSize - offset);
        std::vector<uint8_t> bytes(length);
        for (size_t i = 0; i < length; ++i)
            bytes[i] = static_cast<uint8_t>((round + i) & 0xff);

        size_t expected_added = 0;
        for (size_t i = 0; i < length; ++i) {
            if (!present[offset + i]) {
                present[offset + i] = true;
                expected[offset + i] = bytes[i];
                ++expected_added;
            }
        }
        assert(capture.merge(offset, bytes.data(), bytes.size()) ==
               expected_added);
    }
    for (size_t i = 0; i < kSize; ++i) {
        assert(present[i]);
        assert(capture.data()[i] == expected[i]);
    }
    assert(capture.complete());
}

static void test_page_tail_header_is_deferred_safely() {
    const uint8_t short_header[] = {'d', 'e', 'x', '\n', '0', '3', '9', 0};
    uint32_t size = 123;
    assert(DexValidator::hit_valid(short_header, sizeof(short_header), 0,
                                   &size));
    assert(size == 0);
}

static void test_map_list_offsets_do_not_wrap() {
    uint8_t image[0x100] = {};
    const uint32_t wrapped = UINT32_MAX - 3u;
    assert(DexValidator::recover_size_from_map_buf(
               image, sizeof(image), wrapped) == 0);
    assert(!DexValidator::confirm_by_map_list(
        image, sizeof(image), wrapped, 0x70));
}

int main() {
    test_multi_round_merge_and_holes();
    test_older_bytes_are_never_overwritten();
    test_refresh_tracks_decrypt_in_place_revision();
    test_generation_change_discards_unread_old_pages();
    test_volatile_header_changes_preserve_body_coverage();
    test_page_coverage();
    test_cache_identity_and_budget();
    test_first_read_wins_across_overlaps();
    test_page_tail_header_is_deferred_safely();
    test_map_list_offsets_do_not_wrap();
    std::cout << "dex_capture_test: OK\n";
    return 0;
}
