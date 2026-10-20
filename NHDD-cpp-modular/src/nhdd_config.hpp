// nhdd_config.hpp — NHDD global configuration (replaces static globals)
#pragma once

#include <cstdint>
#include <cstring>

struct NhddConfig {
    // Scan configuration
    int  region_delay_us = 0;       // usleep between regions (stealth)
    bool relaxed = false;           // scan DEX without magic (endian_tag based)
    bool art_dex = true;            // exact-build, read-only StandardDexFile discovery
    bool art_only = false;          // diagnostic: skip DEX magic/container scan
    unsigned art_scan_mb = 64;      // bounded native-heap scan per round, with resume
    bool anon_only = false;         // only scan anonymous mappings
    bool use_vm_readv = false;      // use process_vm_readv instead of /proc/pid/mem
    bool deep_so_scan = true;      // extra no-hook ELF magic scan in anonymous/app memory
    char jnimap_module[256] = {};   // filter JNI fnPtr by module name
    char target_so[256] = {};       // target SO for analysis (dump + fnptrs + maps)
    bool save_maps = false;         // save /proc/<pid>/maps snapshots
    bool dump_target_so = false;     // dump the target SO from process memory
    bool force_fnptrs = false;       // always output fnptr dump (not just fallback)
    int  jnimap_min_group = 2;      // min contiguous JNINativeMethod entries
    int  jnimap_max_region_mb = 64;  // max generic table region size; target lib data is always scanned
    bool jnimap_full_scan = false;   // scan broad readable regions, slower

    // Continuous monitoring mode
    bool continuous = false;         // --continuous: persistent maps monitoring
    bool spawn = false;
    bool spawn_restart = false;
    int spawn_timeout = 15;
    // auto: isolated tracefs if available, otherwise explicit polling fallback.
    // tracefs: fail if unavailable. poll: no kernel event source.
    char event_backend[16] = "auto";
    bool fast_capture = true;       // collector-side bounded double reads, tracefs only
    bool art_refill = true;         // validated method-only temporal composites from ART candidates
    unsigned fast_max_kb = 1024;   // per-event prefix, both reads share an 8ms budget
    int  monitor_interval = 2;      // --monitor-interval: seconds between maps checks (default 2s)
    int  monitor_duration = 0;      // --monitor-duration: total monitoring time in seconds (0=unlimited)
    bool monitor_verbose = false;    // --monitor-verbose: print every maps diff event
    bool dump_on_load = true;        // dump SO immediately when detected in maps
    bool timeline = true;            // record SO/DEX load timeline to timeline.jsonl
    // Content monitoring deliberately hashes a few small windows instead of
    // every byte.  This bounds the observer overhead while still catching the
    // common decrypt-in-place transition.
    int monitor_fingerprint_budget_kb = 256;
    int monitor_fingerprint_sample_bytes = 64;

    // Dedup table sizing
    int dedup_dex_max = 1024;
    int dedup_so_max  = 512;
    int dedup_jni_max = 4096;

    // Singleton access
    static NhddConfig& instance() {
        static NhddConfig cfg;
        return cfg;
    }

private:
    NhddConfig() = default;
};
