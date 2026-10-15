// common_types.hpp — shared types for NHDD C++ OOP refactoring
#pragma once

#include <cstdint>
#include <cstddef>

// ---- Magic constants ----
constexpr uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"
constexpr uint32_t kDexEndianTag = 0x12345678;
constexpr uint32_t kDexHeaderSize = 0x70;
constexpr uint16_t kDexTypeMapList = 0x1000;

// ---- Modes ----
enum class ScanMode : int {
    DEX    = 1,
    SO     = 2,
    JNIMAP = 4,
    ALL    = 3,  // DEX | SO
};

constexpr ScanMode operator|(ScanMode a, ScanMode b) {
    return static_cast<ScanMode>(static_cast<int>(a) | static_cast<int>(b));
}
constexpr bool operator&(ScanMode a, ScanMode b) {
    return (static_cast<int>(a) & static_cast<int>(b)) != 0;
}
constexpr ScanMode operator|=(ScanMode& a, ScanMode b) {
    a = a | b; return a;
}

// ---- Limits ----
constexpr int kMaxPids = 256;
constexpr int kDedupDexMax = 1024;
constexpr int kDedupSoMax = 4096;
constexpr int kDedupJniMax = 4096;

// ---- Parsed /proc/<pid>/maps region ----
struct MapsRegion {
    uintptr_t start = 0;
    uintptr_t end = 0;
    char      perms[8] = {};
    uint64_t  offset = 0;
    uint64_t  inode = 0;
    uint32_t  dev_major = 0;
    uint32_t  dev_minor = 0;
    char      path[512] = {};
    bool      readable = false;
    bool      writable = false;
    bool      executable = false;
};

// ---- Object kind enum ----
enum ObjectKind : int {
    OBJ_UNKNOWN = 0,
    OBJ_ELF_SO,
    OBJ_ELF_EXEC,
    OBJ_DEX,
    OBJ_OAT,
    OBJ_ODEX,
    OBJ_APK_ZIP,
    OBJ_LINKER,
    OBJ_VDSO,
    OBJ_MEMFD,
    OBJ_INVALID
};

// ---- Object origin enum ----
enum ObjectOrigin : int {
    ORIGIN_UNKNOWN = 0,
    ORIGIN_APP_APK,
    ORIGIN_APP_DATA,
    ORIGIN_APP_ANON,
    ORIGIN_SYSTEM,
    ORIGIN_APEX,
    ORIGIN_VENDOR,
    ORIGIN_RUNTIME,
    ORIGIN_WEBVIEW,
    ORIGIN_SPECIAL
};

// ---- Dump policy ----
enum DumpPolicy : int {
    POLICY_SKIP = 0,
    POLICY_DUMP_MERGE,
    POLICY_DUMP_AND_FIX,
    POLICY_DUMP_AND_SOFIXER_FIX
};

// ---- Grouped mapped object ----
struct MappedObject {
    char     path[512] = {};
    char     name[256] = {};
    uint64_t inode = 0;

    uintptr_t base_addr = 0;
    uintptr_t min_start = 0;
    uintptr_t max_end = 0;
    uint64_t min_offset = 0;
    uint64_t file_size = 0;

    int region_count = 0;
    bool has_r = false;
    bool has_w = false;
    bool has_x = false;

    ObjectKind   kind = OBJ_UNKNOWN;
    ObjectOrigin origin = ORIGIN_UNKNOWN;
    DumpPolicy   policy = POLICY_SKIP;

    char reason[256] = {};
};

// ---- Counter struct ----
struct ScanCounters {
    int dex_unique = 0;
    int dex_dedup = 0;
    int dex_total = 0;
    int so_count = 0;
    int jni_count = 0;
    int procs = 0;

    int total_unique() const { return dex_unique + so_count + jni_count; }
};
