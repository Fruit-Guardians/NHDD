// dex_capture.hpp — Pure DEX multi-round merge and coverage accounting.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

struct DexByteSpan {
    size_t offset = 0;
    size_t length = 0;

    size_t end() const { return offset + length; }
};

struct DexPageCoverage {
    size_t page_size = 4096;
    size_t total_pages = 0;
    size_t complete_pages = 0;
    size_t partial_pages = 0;
    size_t missing_pages = 0;
};

struct DexRefreshResult {
    size_t new_bytes = 0;
    size_t changed_bytes = 0;

    size_t updates() const { return new_bytes + changed_bytes; }
};

// A PID and virtual address alone are unsafe across process restarts and mapping
// reuse. Mapping identity, size and a fingerprint of stable DEX header fields
// keep unrelated candidates from being merged when an address is recycled.
struct DexCandidateIdentity {
    uint32_t pid = 0;
    uint64_t process_start_time = 0;  // /proc/<pid>/stat field 22, clock ticks
    uintptr_t address = 0;
    uint32_t dex_size = 0;
    uint64_t mapping_fingerprint = 0;
    uint64_t header_fingerprint = 0;

    bool operator==(const DexCandidateIdentity& other) const {
        return pid == other.pid &&
               process_start_time == other.process_start_time &&
               address == other.address &&
               dex_size == other.dex_size &&
               mapping_fingerprint == other.mapping_fingerprint &&
               header_fingerprint == other.header_fingerprint;
    }
};

struct DexCandidateIdentityHash {
    size_t operator()(const DexCandidateIdentity& id) const {
        // 64-bit hash-combine; also behaves correctly on a 32-bit host after
        // the final narrowing to size_t.
        uint64_t h = 1469598103934665603ULL;
        const auto mix = [&h](uint64_t value) {
            for (unsigned i = 0; i < 8; ++i) {
                h ^= static_cast<uint8_t>(value >> (i * 8));
                h *= 1099511628211ULL;
            }
        };
        mix(id.pid);
        mix(id.process_start_time);
        mix(static_cast<uint64_t>(id.address));
        mix(id.dex_size);
        mix(id.mapping_fingerprint);
        mix(id.header_fingerprint);
        return static_cast<size_t>(h);
    }
};

class DexCapture {
public:
    DexCapture(const DexCandidateIdentity& identity, bool relaxed_detection)
        : identity_(identity), data_(identity.dex_size, 0),
          relaxed_detection_(relaxed_detection) {}

    const DexCandidateIdentity& identity() const { return identity_; }
    const uint8_t* data() const { return data_.data(); }
    uint8_t* data() { return data_.data(); }
    size_t size() const { return data_.size(); }
    size_t covered_bytes() const { return covered_bytes_; }
    size_t observations() const { return observations_; }
    uint64_t content_revision() const { return content_revision_; }
    bool relaxed_detection() const { return relaxed_detection_; }
    bool complete() const { return covered_bytes_ == data_.size(); }
    bool ever_published() const { return ever_published_; }
    uint64_t last_touch() const { return last_touch_; }
    void touch(uint64_t value) { last_touch_ = value; }
    bool has_processed_revision() const { return !processed_keys_.empty(); }

    bool content_key_processed(uint64_t key) const {
        return std::find(processed_keys_.begin(), processed_keys_.end(), key) !=
               processed_keys_.end();
    }

    void mark_content_key_processed(uint64_t key, bool published) {
        if (!content_key_processed(key)) {
            // Long-running continuous scans can observe many in-place DEX
            // revisions. Keep the recent revision guard bounded just like the
            // capture cache itself; evicting an old key only permits a later
            // revalidation, it never removes an already published artifact.
            if (processed_keys_.size() >= kMaxProcessedRevisionKeys)
                processed_keys_.erase(processed_keys_.begin());
            processed_keys_.push_back(key);
        }
        ever_published_ = ever_published_ || published;
    }

    void observe(bool relaxed_detection) {
        ++observations_;
        // If either observation needed relaxed detection, preserve that fact in
        // the metadata even if a later round restores the magic bytes.
        relaxed_detection_ = relaxed_detection_ || relaxed_detection;
    }

    // Merge one successfully read, contiguous byte span.  Bytes already
    // captured in an earlier round are deliberately never overwritten.
    size_t merge(size_t offset, const uint8_t* bytes, size_t length) {
        if (!bytes || length == 0 || offset >= data_.size()) return 0;
        const size_t available = data_.size() - offset;
        if (length > available) length = available;
        const size_t end = offset + length;

        size_t cursor = offset;
        size_t added = 0;
        for (const DexByteSpan& span : spans_) {
            if (span.end() <= cursor) continue;
            if (span.offset >= end) break;
            if (span.offset > cursor) {
                const size_t copy_end = std::min(span.offset, end);
                std::copy(bytes + (cursor - offset),
                          bytes + (copy_end - offset), data_.begin() + cursor);
                added += copy_end - cursor;
            }
            cursor = std::max(cursor, span.end());
            if (cursor >= end) break;
        }
        if (cursor < end) {
            std::copy(bytes + (cursor - offset), bytes + length,
                      data_.begin() + cursor);
            added += end - cursor;
        }

        if (added != 0) {
            insert_span(offset, length);
            covered_bytes_ += added;
            ++content_revision_;
        }
        return added;
    }

    // Refresh differs from merge(): already captured bytes are compared and
    // replaced when the target changed in place, while still filling holes.
    // Packers commonly expose a fully readable buffer before all pages have
    // been decrypted, so permanently freezing the first readable bytes would
    // lock the capture to ciphertext. Earlier complete revisions remain on
    // disk; this object tracks the newest observed memory state.
    DexRefreshResult refresh(size_t offset, const uint8_t* bytes,
                             size_t length) {
        DexRefreshResult result;
        if (!bytes || length == 0 || offset >= data_.size()) return result;
        const size_t available = data_.size() - offset;
        if (length > available) length = available;
        const size_t end = offset + length;

        // Update only ranges that were covered before this call. merge() below
        // will fill every uncovered subrange without disturbing these bytes.
        for (const DexByteSpan& span : spans_) {
            if (span.end() <= offset) continue;
            if (span.offset >= end) break;
            const size_t begin = std::max(offset, span.offset);
            const size_t finish = std::min(end, span.end());
            for (size_t pos = begin; pos < finish; ++pos) {
                const uint8_t value = bytes[pos - offset];
                if (data_[pos] != value) {
                    data_[pos] = value;
                    ++result.changed_bytes;
                }
            }
        }
        if (result.changed_bytes != 0) ++content_revision_;
        result.new_bytes = merge(offset, bytes, length);
        return result;
    }

    // Merge one complete scan-round observation atomically. A change in a
    // structural/header field or body byte starts a new byte generation, so
    // older unread coverage is discarded before accepting the observation.
    // The volatile DEX identity bytes (magic/version, checksum, signature and
    // file_size, 0x00..0x23) are the exception: packers routinely wipe and
    // restore them while the body is unchanged. The independently recovered
    // size already lives in the candidate identity. Refresh these bytes in
    // place without throwing away previously recovered body pages.
    DexRefreshResult apply_observation(const DexCapture& observation) {
        DexRefreshResult result;
        if (!(identity_ == observation.identity_) || observation.covered_bytes_ == 0)
            return result;

        size_t overlap_bytes = 0;
        size_t volatile_changed_bytes = 0;
        bool generation_changed = false;
        size_t left = 0;
        size_t right = 0;
        while (left < spans_.size() && right < observation.spans_.size()) {
            const DexByteSpan& old_span = spans_[left];
            const DexByteSpan& new_span = observation.spans_[right];
            const size_t begin = std::max(old_span.offset, new_span.offset);
            const size_t end = std::min(old_span.end(), new_span.end());
            if (begin < end) {
                overlap_bytes += end - begin;
                for (size_t pos = begin; pos < end; ++pos) {
                    if (data_[pos] != observation.data_[pos]) {
                        ++result.changed_bytes;
                        if (pos < kVolatileHeaderEnd)
                            ++volatile_changed_bytes;
                        else
                            generation_changed = true;
                    }
                }
            }
            if (old_span.end() < new_span.end()) ++left;
            else ++right;
        }

        result.new_bytes = observation.covered_bytes_ - overlap_bytes;
        if (generation_changed) {
            data_ = observation.data_;
            spans_ = observation.spans_;
            covered_bytes_ = observation.covered_bytes_;
            ++content_revision_;
            return result;
        }

        if (volatile_changed_bytes != 0) {
            left = 0;
            right = 0;
            while (left < spans_.size() && right < observation.spans_.size()) {
                const DexByteSpan& old_span = spans_[left];
                const DexByteSpan& new_span = observation.spans_[right];
                const size_t begin = std::max(old_span.offset, new_span.offset);
                const size_t end = std::min(
                    std::min(old_span.end(), new_span.end()),
                    kVolatileHeaderEnd);
                if (begin < end) {
                    std::copy(observation.data_.begin() + begin,
                              observation.data_.begin() + end,
                              data_.begin() + begin);
                }
                if (old_span.end() < new_span.end()) ++left;
                else ++right;
            }
            ++content_revision_;
        }

        result.new_bytes = 0;
        for (const DexByteSpan& span : observation.spans_) {
            result.new_bytes += merge(span.offset,
                                      observation.data_.data() + span.offset,
                                      span.length);
        }
        return result;
    }

    std::vector<DexByteSpan> holes() const {
        std::vector<DexByteSpan> result;
        size_t cursor = 0;
        for (const DexByteSpan& span : spans_) {
            if (cursor < span.offset)
                result.push_back({cursor, span.offset - cursor});
            cursor = std::max(cursor, span.end());
        }
        if (cursor < data_.size())
            result.push_back({cursor, data_.size() - cursor});
        return result;
    }

    DexPageCoverage page_coverage(size_t page_size = 4096) const {
        DexPageCoverage result;
        result.page_size = page_size == 0 ? 4096 : page_size;
        if (data_.empty()) return result;
        result.total_pages = (data_.size() + result.page_size - 1) /
                             result.page_size;

        size_t span_index = 0;
        for (size_t page = 0; page < result.total_pages; ++page) {
            const size_t begin = page * result.page_size;
            const size_t end = std::min(begin + result.page_size, data_.size());
            while (span_index < spans_.size() &&
                   spans_[span_index].end() <= begin)
                ++span_index;

            size_t covered = 0;
            size_t i = span_index;
            while (i < spans_.size() && spans_[i].offset < end) {
                const size_t overlap_begin = std::max(begin, spans_[i].offset);
                const size_t overlap_end = std::min(end, spans_[i].end());
                if (overlap_end > overlap_begin)
                    covered += overlap_end - overlap_begin;
                ++i;
            }

            if (covered == 0) ++result.missing_pages;
            else if (covered == end - begin) ++result.complete_pages;
            else ++result.partial_pages;
        }
        return result;
    }

private:
    static constexpr size_t kVolatileHeaderEnd = 0x24;
    static constexpr size_t kMaxProcessedRevisionKeys = 256;

    void insert_span(size_t offset, size_t length) {
        DexByteSpan merged{offset, length};
        std::vector<DexByteSpan> next;
        next.reserve(spans_.size() + 1);
        bool inserted = false;
        for (const DexByteSpan& span : spans_) {
            if (span.end() < merged.offset) {
                next.push_back(span);
            } else if (merged.end() < span.offset) {
                if (!inserted) {
                    next.push_back(merged);
                    inserted = true;
                }
                next.push_back(span);
            } else {
                const size_t merged_end = std::max(merged.end(), span.end());
                merged.offset = std::min(merged.offset, span.offset);
                merged.length = merged_end - merged.offset;
            }
        }
        if (!inserted) next.push_back(merged);
        spans_.swap(next);
    }

    DexCandidateIdentity identity_;
    std::vector<uint8_t> data_;
    std::vector<DexByteSpan> spans_;
    size_t covered_bytes_ = 0;
    size_t observations_ = 0;
    uint64_t content_revision_ = 0;
    bool relaxed_detection_ = false;
    std::vector<uint64_t> processed_keys_;
    bool ever_published_ = false;
    uint64_t last_touch_ = 0;
};

class DexCaptureCache {
public:
    explicit DexCaptureCache(size_t max_entries = 256,
                             size_t max_bytes = 512u * 1024u * 1024u)
        : max_entries_(max_entries), max_bytes_(max_bytes) {}

    // Hash only stable structural fields.  Magic/version/checksum/signature
    // (0x00..0x1f) and file_size (0x20..0x23) are intentionally excluded
    // because packers commonly erase or restore them while the same in-memory
    // DEX is being observed.  The independently recovered size is already part
    // of DexCandidateIdentity.
    static uint64_t stable_header_fingerprint(const uint8_t* header,
                                              size_t header_size) {
        if (!header || header_size <= 0x24) return 0;
        const size_t end = std::min<size_t>(header_size, 0x70);
        uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0x24; i < end; ++i) {
            h ^= header[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    DexCapture* get_or_create(const DexCandidateIdentity& identity,
                              bool relaxed_detection, bool* created = nullptr) {
        if (created) *created = false;
        auto found = captures_.find(identity);
        if (found != captures_.end()) {
            found->second->touch(++clock_);
            return found->second.get();
        }
        if (identity.dex_size == 0 || max_entries_ == 0 ||
            identity.dex_size > max_bytes_)
            return nullptr;

        while (captures_.size() >= max_entries_ ||
               identity.dex_size >
                   max_bytes_ - std::min(max_bytes_, bytes_used_)) {
            if (!evict_one()) return nullptr;
        }

        std::unique_ptr<DexCapture> capture(
            new DexCapture(identity, relaxed_detection));
        DexCapture* result = capture.get();
        result->touch(++clock_);
        captures_.emplace(identity, std::move(capture));
        bytes_used_ += identity.dex_size;
        if (created) *created = true;
        return result;
    }

    size_t size() const { return captures_.size(); }
    size_t bytes_used() const { return bytes_used_; }

    void touch(DexCapture& capture) { capture.touch(++clock_); }

    void discard_other_process_generations(uint32_t pid,
                                           uint64_t process_start_time) {
        for (auto it = captures_.begin(); it != captures_.end();) {
            if (it->first.pid == pid &&
                it->first.process_start_time != process_start_time) {
                bytes_used_ -= it->second->size();
                it = captures_.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t discard_intersecting(uint32_t pid, uint64_t process_start_time,
                                uintptr_t start, uintptr_t end) {
        if (start >= end) return 0;
        size_t removed = 0;
        for (auto it = captures_.begin(); it != captures_.end();) {
            const DexCandidateIdentity& id = it->first;
            uintptr_t candidate_end = std::numeric_limits<uintptr_t>::max();
            if (id.dex_size <= static_cast<uint64_t>(
                                   std::numeric_limits<uintptr_t>::max() -
                                   id.address)) {
                candidate_end = id.address + static_cast<uintptr_t>(id.dex_size);
            }
            if (id.pid == pid && id.process_start_time == process_start_time &&
                id.address < end && start < candidate_end) {
                bytes_used_ -= it->second->size();
                it = captures_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    }

    template <typename Callback>
    void for_each_process(uint32_t pid, uint64_t process_start_time,
                          Callback&& callback) {
        for (auto& item : captures_) {
            const DexCandidateIdentity& id = item.first;
            if (id.pid == pid && id.process_start_time == process_start_time) {
                callback(*item.second);
            }
        }
    }

private:
    bool evict_one() {
        if (captures_.empty()) return false;
        auto victim = captures_.end();

        // Prefer a byte-complete revision that has already been published or
        // classified as a duplicate. If none exists, fall back to true LRU so
        // a hostile stream of stale partial candidates cannot permanently
        // disable discovery.
        for (auto it = captures_.begin(); it != captures_.end(); ++it) {
            if (!it->second->complete() ||
                !it->second->has_processed_revision()) continue;
            if (victim == captures_.end() ||
                it->second->last_touch() < victim->second->last_touch()) {
                victim = it;
            }
        }
        if (victim == captures_.end()) {
            for (auto it = captures_.begin(); it != captures_.end(); ++it) {
                if (victim == captures_.end() ||
                    it->second->last_touch() < victim->second->last_touch()) {
                    victim = it;
                }
            }
        }
        if (victim == captures_.end()) return false;
        bytes_used_ -= victim->second->size();
        captures_.erase(victim);
        return true;
    }

    size_t max_entries_;
    size_t max_bytes_;
    size_t bytes_used_ = 0;
    uint64_t clock_ = 0;
    std::unordered_map<DexCandidateIdentity, std::unique_ptr<DexCapture>,
                       DexCandidateIdentityHash> captures_;
};
