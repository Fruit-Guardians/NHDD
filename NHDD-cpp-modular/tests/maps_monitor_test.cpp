#include <cassert>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "../src/maps_monitor.hpp"

namespace {

MapsMonitor::MappingState mapping(uintptr_t start, uintptr_t end,
                                  const char* perms, const char* path,
                                  uint64_t offset = 0, uint64_t inode = 1) {
    MapsMonitor::MappingState value;
    value.start = start;
    value.end = end;
    value.offset = offset;
    value.inode = inode;
    value.dev_major = 8;
    value.dev_minor = 1;
    value.perms = perms;
    value.path = path;
    value.readable = perms[0] == 'r';
    value.writable = perms[1] == 'w';
    value.executable = perms[2] == 'x';
    value.source_kind = MapsMonitor::classify_source(value.path);
    return value;
}

MapsMonitor::MapsSnapshot snapshot(
        std::initializer_list<MapsMonitor::MappingState> mappings) {
    MapsMonitor::MapsSnapshot value;
    value.timestamp = 1234;
    value.process_starttime = 99;
    value.mappings = mappings;
    return value;
}

void test_added_and_removed_ranges() {
    auto old_state = snapshot({
        mapping(0x1000, 0x2000, "r--p", "/data/app/base.apk", 0, 7),
    });
    auto new_state = snapshot({
        mapping(0x3000, 0x4000, "rw-p", "", 0, 0),
    });

    auto diff = MapsMonitor::diff_snapshots(old_state, new_state);
    assert(diff.events.size() == 2);
    assert(diff.scan_ranges.size() == 1);
    assert((diff.scan_ranges[0].reasons & MAP_CHANGE_ADDED) != 0);
    assert(diff.scan_ranges[0].source_kind == MAP_SOURCE_ANONYMOUS);

    ScanScope scope = diff.make_scope();
    assert(scope.intersects(0x3800, 0x3900));
    assert(!scope.intersects(0x1000, 0x2000));
}

void test_removed_only_never_scans() {
    auto old_state = snapshot({mapping(0x1000, 0x2000, "r-xp", "/memfd:loader", 0, 0)});
    auto new_state = snapshot({});
    auto diff = MapsMonitor::diff_snapshots(old_state, new_state);
    assert(diff.events.size() == 1);
    assert(diff.events[0].reasons == MAP_CHANGE_REMOVED);
    assert(!diff.has_scannable_changes());
}

void test_permissions_and_write_to_execute() {
    auto before = mapping(0x1000, 0x2000, "rw-p", "", 0, 0);
    auto after = mapping(0x1000, 0x2000, "r-xp", "", 0, 0);
    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.events.size() == 1);
    assert((diff.events[0].reasons & MAP_CHANGE_PERMISSIONS) != 0);
    assert((diff.events[0].reasons & MAP_CHANGE_WRITE_EXEC) != 0);
    assert(diff.scan_ranges.size() == 1);
}

void test_execute_only_write_to_execute_still_scans() {
    auto before = mapping(0x1000, 0x2000, "rw-p", "", 0, 0);
    auto after = mapping(0x1000, 0x2000, "--xp", "", 0, 0);
    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.events.size() == 1);
    assert((diff.events[0].reasons & MAP_CHANGE_PERMISSIONS) != 0);
    assert((diff.events[0].reasons & MAP_CHANGE_WRITE_EXEC) != 0);
    assert(diff.scan_ranges.size() == 1);
    assert(diff.scan_ranges[0].executable);
    assert(!diff.scan_ranges[0].readable);
    assert(diff.make_scope().intersects(0x1000, 0x2000));
}

void test_split_mprotect_keeps_write_to_execute_signal() {
    auto before = mapping(0x1000, 0x3000, "rw-p", "/data/app/libstage.so", 0, 12);
    auto after = mapping(0x2000, 0x3000, "r-xp", "/data/app/libstage.so", 0x1000, 12);
    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.scan_ranges.size() == 1);
    assert((diff.scan_ranges[0].reasons & MAP_CHANGE_ADDED) != 0);
    assert((diff.scan_ranges[0].reasons & MAP_CHANGE_WRITE_EXEC) != 0);

    // Anonymous split mappings normally keep offset zero on both sides.
    auto anon_before = mapping(0x4000, 0x6000, "rw-p", "", 0, 0);
    auto anon_after = mapping(0x5000, 0x6000, "r-xp", "", 0, 0);
    auto anon_diff = MapsMonitor::diff_snapshots(
        snapshot({anon_before}), snapshot({anon_after}));
    assert(anon_diff.scan_ranges.size() == 1);
    assert((anon_diff.scan_ranges[0].reasons & MAP_CHANGE_WRITE_EXEC) != 0);
}

void test_sampled_content_change_is_explicit() {
    auto before = mapping(0x1000, 0x2000, "r--p", "/data/app/base.apk", 0, 17);
    before.fingerprint_sampled = true;
    before.sampled_fingerprint = 0x1111;
    before.sampled_bytes = 192;
    auto after = before;
    after.sampled_fingerprint = 0x2222;

    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.events.size() == 1);
    assert(diff.events[0].reasons == MAP_CHANGE_CONTENT);
    assert(diff.scan_ranges.size() == 1);
    assert(diff.scan_ranges[0].fingerprint_sampled);
}

void test_same_range_backing_identity_change() {
    auto before = mapping(0x7000, 0x8000, "r-xp", "/data/app/base.apk", 0, 23);
    auto after = mapping(0x7000, 0x8000, "r-xp", "/data/app/base.apk", 0x4000, 23);
    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.events.size() == 1);
    assert((diff.events[0].reasons & MAP_CHANGE_IDENTITY) != 0);
    assert(diff.scan_ranges.size() == 1);
    assert(diff.scan_ranges[0].source_kind == MAP_SOURCE_APK);
}

void test_sampling_diagnostics_propagate() {
    auto old_state = snapshot({
        mapping(0x1000, 0x2000, "r--p", "/data/app/base.apk", 0, 23),
    });
    auto new_state = old_state;
    new_state.content_sampling.requested = true;
    new_state.content_sampling.attempted = true;
    new_state.content_sampling.backend_opened = true;
    new_state.content_sampling.available = false;
    new_state.content_sampling.attempted_bytes = 192;
    new_state.content_sampling.sampled_bytes = 0;
    new_state.content_sampling.read_failures = 3;
    new_state.content_sampling.last_errno = EACCES;

    auto diff = MapsMonitor::diff_snapshots(old_state, new_state);
    assert(diff.capture_ok);
    assert(diff.content_sampling.requested);
    assert(diff.content_sampling.attempted);
    assert(diff.content_sampling.backend_opened);
    assert(!diff.content_sampling.available);
    assert(diff.content_sampling.attempted_bytes == 192);
    assert(diff.content_sampling.sampled_bytes == 0);
    assert(diff.content_sampling.read_failures == 3);
    assert(diff.content_sampling.last_errno == EACCES);
    assert(diff.content_sampling.all_reads_failed());

    MapsMonitor::ContentSamplingStatus open_failure;
    open_failure.requested = true;
    open_failure.attempted = true;
    open_failure.backend_opened = false;
    open_failure.available = false;
    open_failure.last_errno = EPERM;
    assert(open_failure.all_reads_failed());

    MapsMonitor::ContentSamplingStatus opened_without_eligible_ranges;
    opened_without_eligible_ranges.requested = true;
    opened_without_eligible_ranges.attempted = true;
    opened_without_eligible_ranges.backend_opened = true;
    assert(!opened_without_eligible_ranges.all_reads_failed());
}

void test_timeline_contains_before_after_identity_and_reports_failures() {
    auto before = mapping(0x7000, 0x8000, "rw-p", "/data/old.apk", 0x1000, 23);
    auto after = mapping(0x7000, 0x8000, "r-xp", "/data/new.apk", 0x2000, 42);
    auto diff = MapsMonitor::diff_snapshots(snapshot({before}), snapshot({after}));
    assert(diff.events.size() == 1);
    diff.content_sampling.requested = true;
    diff.content_sampling.attempted = true;
    diff.content_sampling.backend_opened = false;
    diff.content_sampling.available = false;
    diff.content_sampling.read_failures = 1;
    diff.content_sampling.last_errno = EPERM;

    const char* path = "maps_monitor_timeline_test.jsonl";
    std::remove(path);
    assert(MapsMonitor::write_timeline_events(path, "123", 99, diff));

    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    const std::string line((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    input.close();
    std::remove(path);

    assert(line.find("\"before_identity\":{\"path\":\"/data/old.apk\"") !=
           std::string::npos);
    assert(line.find("\"after_identity\":{\"path\":\"/data/new.apk\"") !=
           std::string::npos);
    assert(line.find("\"inode\":23") != std::string::npos);
    assert(line.find("\"dev\":\"8:1\"") != std::string::npos);
    assert(line.find("\"offset\":\"0x1000\"") != std::string::npos);
    assert(line.find("\"perms\":\"rw-p\"") != std::string::npos);
    assert(line.find("\"range\":{\"start\":\"0x7000\"") !=
           std::string::npos);
    assert(line.find("\"backend_opened\":false") != std::string::npos);
    assert(line.find("\"errno\":" + std::to_string(EPERM)) !=
           std::string::npos);

    errno = 0;
    assert(!MapsMonitor::write_timeline_events(nullptr, "123", 99, diff));
    assert(errno == EINVAL);
}

std::string read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void test_timeline_session_prepare_honors_keep() {
    const char* path = "maps_monitor_timeline_session_test.jsonl";
    std::remove(path);

    {
        std::ofstream output(path, std::ios::binary);
        output << "old-session\n";
    }
    assert(MapsMonitor::prepare_timeline_file(path, false));
    assert(read_file(path).empty());

    {
        std::ofstream output(path, std::ios::binary | std::ios::app);
        output << "kept-session\n";
    }
    assert(MapsMonitor::prepare_timeline_file(path, true));
    assert(read_file(path) == "kept-session\n");

    errno = 0;
    assert(!MapsMonitor::prepare_timeline_file(nullptr, false));
    assert(errno == EINVAL);
    std::remove(path);
}

void test_maps_parser_rejects_truncated_lines_atomically() {
    int parse_errno = 0;
    assert(MapsParser::load_maps(nullptr, &parse_errno) == nullptr);
    assert(parse_errno == EINVAL);

    FILE* stream = std::tmpfile();
    assert(stream != nullptr);

    const char* valid =
        "1000-2000 r-xp 00000000 08:01 7 /data/app/base.apk\n";
    assert(std::fputs(valid, stream) >= 0);
    std::vector<char> overlong(9000, 'x');
    assert(std::fwrite(overlong.data(), 1, overlong.size(), stream) ==
           overlong.size());
    assert(std::fputc('\n', stream) != EOF);
    assert(std::fflush(stream) == 0);
    std::rewind(stream);

    parse_errno = 0;
    MapsParser::RegionList* parsed =
        MapsParser::parse_stream(stream, &parse_errno);
    assert(parsed == nullptr);
    assert(parse_errno == EOVERFLOW);
    std::fclose(stream);

    // A newline does not make a truncated record valid. Reject both a line
    // that cannot parse the range and one that has only the first three
    // fields, without publishing the valid record that preceded it.
    for (const char* malformed : {
             "not-a-maps-record\n",
             "2000-3000 rw-p\n",
         }) {
        stream = std::tmpfile();
        assert(stream != nullptr);
        assert(std::fputs(valid, stream) >= 0);
        assert(std::fputs(malformed, stream) >= 0);
        assert(std::fflush(stream) == 0);
        std::rewind(stream);
        parse_errno = 0;
        parsed = MapsParser::parse_stream(stream, &parse_errno);
        assert(parsed == nullptr);
        assert(parse_errno == EPROTO);
        std::fclose(stream);
    }

    // A complete stream remains accepted and preserves its parsed record.
    stream = std::tmpfile();
    assert(stream != nullptr);
    assert(std::fputs(valid, stream) >= 0);
    assert(std::fflush(stream) == 0);
    std::rewind(stream);
    parse_errno = -1;
    parsed = MapsParser::parse_stream(stream, &parse_errno);
    assert(parsed != nullptr);
    assert(parse_errno == 0);
    assert(parsed->count == 1);
    assert(parsed->regs[0].start == 0x1000);
    assert(std::string(parsed->regs[0].path) == "/data/app/base.apk");
    delete parsed;
    std::fclose(stream);

    // Region storage is fixed-size. A complete input line whose path would be
    // truncated is also rejected instead of creating an ambiguous identity.
    stream = std::tmpfile();
    assert(stream != nullptr);
    const char* prefix = "3000-4000 r--p 00000000 08:01 9 /data/";
    assert(std::fputs(prefix, stream) >= 0);
    std::vector<char> long_path(600, 'p');
    assert(std::fwrite(long_path.data(), 1, long_path.size(), stream) ==
           long_path.size());
    assert(std::fputc('\n', stream) != EOF);
    assert(std::fflush(stream) == 0);
    std::rewind(stream);
    parse_errno = 0;
    parsed = MapsParser::parse_stream(stream, &parse_errno);
    assert(parsed == nullptr);
    assert(parse_errno == EOVERFLOW);
    std::fclose(stream);
}

void test_source_classification() {
    assert(MapsMonitor::classify_source("") == MAP_SOURCE_ANONYMOUS);
    assert(MapsMonitor::classify_source("[anon:dalvik-main space]") ==
           MAP_SOURCE_ANONYMOUS);
    assert(MapsMonitor::classify_source("/memfd:jit-cache (deleted)") ==
           MAP_SOURCE_MEMFD);
    assert(MapsMonitor::classify_source("/data/app/pkg/base.apk") ==
           MAP_SOURCE_APK);
    assert(MapsMonitor::classify_source("[vdso]") == MAP_SOURCE_SPECIAL);
}

void test_numeric_pid_generation_policy() {
    assert(!MapsMonitor::may_follow_new_generation(true));
    assert(MapsMonitor::may_follow_new_generation(false));

    uint64_t starttime = 0;
    errno = 0;
    assert(!MapsMonitor::read_process_starttime(nullptr, &starttime));
    assert(errno == EINVAL);

#if defined(_WIN32)
    MapsMonitor missing_process;
    assert(!missing_process.take_baseline("nhdd-no-such-pid"));
    assert(missing_process.last_capture_errno() != 0);
#endif
}

}  // namespace

int main() {
    test_added_and_removed_ranges();
    test_removed_only_never_scans();
    test_permissions_and_write_to_execute();
    test_execute_only_write_to_execute_still_scans();
    test_split_mprotect_keeps_write_to_execute_signal();
    test_sampled_content_change_is_explicit();
    test_same_range_backing_identity_change();
    test_sampling_diagnostics_propagate();
    test_timeline_contains_before_after_identity_and_reports_failures();
    test_timeline_session_prepare_honors_keep();
    test_maps_parser_rejects_truncated_lines_atomically();
    test_source_classification();
    test_numeric_pid_generation_policy();
    std::puts("maps_monitor_test: OK");
    return 0;
}
