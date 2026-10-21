// nhdd_app.hpp — CLI application entry point and orchestration
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <chrono>
#include <csignal>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include "common_types.hpp"
#include "nhdd_config.hpp"
#include "dedup_table.hpp"
#include "process_manager.hpp"
#include "nhdd_scanner.hpp"
#include "maps_monitor.hpp"
#include "syscall_events.hpp"
#include "fast_capture_service.hpp"

inline volatile std::sig_atomic_t nhdd_stop_requested = 0;
inline void nhdd_stop_handler(int) { nhdd_stop_requested = 1; }

class NhddApp {
public:
    int run(int argc, char** argv) {
        ScanMode mode = ScanMode::DEX;
        bool mode_specified = false;
        int snapshot_rounds = 1;
        int snapshot_interval = 1;
        bool watch = false;
        int watch_dry_limit = 3;
        int max_rounds = 60;
        int max_seconds = 120;
        bool stealth = false;
        bool keep = false;
        const char* disguise = nullptr;

        const char* target = nullptr;
        const char* out_dir = nullptr;
        const char* verify_file = nullptr;

        auto& cfg = NhddConfig::instance();
        nhdd_stop_requested = 0;
        std::signal(SIGINT, nhdd_stop_handler);
        std::signal(SIGTERM, nhdd_stop_handler);

        // ---- CLI argument parsing ----
        for (int i = 1; i < argc; i++) {
            if (std::strcmp(argv[i], "--help") == 0 ||
                std::strcmp(argv[i], "-h") == 0) {
                print_usage(argv[0]);
                return 0;
            }
            if (std::strcmp(argv[i], "--verify") == 0 && i + 1 < argc) {
                verify_file = argv[++i]; continue;
            }
            if (std::strcmp(argv[i], "--so") == 0) {
                bool keep_jni = (mode & ScanMode::JNIMAP);
                mode = keep_jni ? (ScanMode::SO | ScanMode::JNIMAP) : ScanMode::SO;
                mode_specified = true;
                continue;
            }
            if (std::strcmp(argv[i], "--dex") == 0) {
                bool keep_jni = (mode & ScanMode::JNIMAP);
                mode = keep_jni ? (ScanMode::DEX | ScanMode::JNIMAP) : ScanMode::DEX;
                mode_specified = true;
                continue;
            }
            if (std::strcmp(argv[i], "--all") == 0 ||
                std::strcmp(argv[i], "--apk") == 0) {
                bool keep_jni = (mode & ScanMode::JNIMAP);
                mode = keep_jni ? (ScanMode::ALL | ScanMode::JNIMAP) : ScanMode::ALL;
                mode_specified = true;
                continue;
            }
            if (std::strcmp(argv[i], "--jnimap") == 0 ||
                std::strcmp(argv[i], "--jni") == 0) {
                if (!mode_specified) mode = ScanMode::JNIMAP;
                else mode |= ScanMode::JNIMAP;
                mode_specified = true;
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    std::snprintf(cfg.jnimap_module, sizeof(cfg.jnimap_module),
                                  "%s", argv[++i]);
                }
                continue;
            }
            if (std::strcmp(argv[i], "--jni-lib") == 0 && i + 1 < argc) {
                std::snprintf(cfg.jnimap_module, sizeof(cfg.jnimap_module),
                              "%s", argv[++i]);
                continue;
            }
            if (std::strcmp(argv[i], "--jni-min") == 0 && i + 1 < argc) {
                cfg.jnimap_min_group = std::atoi(argv[++i]);
                if (cfg.jnimap_min_group < 1) cfg.jnimap_min_group = 1;
                continue;
            }
            if (std::strcmp(argv[i], "--jni-max-region") == 0 && i + 1 < argc) {
                cfg.jnimap_max_region_mb = std::atoi(argv[++i]);
                if (cfg.jnimap_max_region_mb < 1) cfg.jnimap_max_region_mb = 1;
                continue;
            }
            if (std::strcmp(argv[i], "--jni-full") == 0) {
                cfg.jnimap_full_scan = true;
                continue;
            }
            if (std::strcmp(argv[i], "--target-so") == 0 && i + 1 < argc) {
                std::snprintf(cfg.target_so, sizeof(cfg.target_so), "%s", argv[++i]);
                cfg.save_maps = true;
                cfg.dump_target_so = true;
                cfg.force_fnptrs = true;
                continue;
            }
            if (std::strcmp(argv[i], "--analyze-so") == 0 && i + 1 < argc) {
                std::snprintf(cfg.target_so, sizeof(cfg.target_so), "%s", argv[++i]);
                std::snprintf(cfg.jnimap_module, sizeof(cfg.jnimap_module), "%s",
                              cfg.target_so);
                if (!mode_specified) { mode = ScanMode::JNIMAP; mode_specified = true; }
                else mode |= ScanMode::JNIMAP;
                cfg.save_maps = true;
                cfg.dump_target_so = true;
                cfg.force_fnptrs = true;
                cfg.jnimap_full_scan = true;
                cfg.jnimap_min_group = 1;
                continue;
            }
            if (std::strcmp(argv[i], "--save-maps") == 0) {
                cfg.save_maps = true; continue;
            }
            if (std::strcmp(argv[i], "--dump-target-so") == 0) {
                cfg.dump_target_so = true; continue;
            }
            if (std::strcmp(argv[i], "--fnptrs") == 0) {
                cfg.force_fnptrs = true; continue;
            }
            if (std::strcmp(argv[i], "--keep") == 0) { keep = true; continue; }
            if (std::strcmp(argv[i], "--snapshot") == 0 && i + 1 < argc) {
                snapshot_rounds = std::atoi(argv[++i]);
                if (snapshot_rounds < 1) snapshot_rounds = 1;
                continue;
            }
            if (std::strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
                snapshot_interval = std::atoi(argv[++i]);
                if (snapshot_interval < 0) snapshot_interval = 0;
                continue;
            }
            if (std::strcmp(argv[i], "--watch") == 0) {
                watch = true;
                if (i + 1 < argc && std::atoi(argv[i + 1]) > 0)
                    watch_dry_limit = std::atoi(argv[++i]);
                continue;
            }
            if (std::strcmp(argv[i], "--max-rounds") == 0 && i + 1 < argc) {
                max_rounds = std::atoi(argv[++i]);
                if (max_rounds < 1) max_rounds = 60;
                continue;
            }
            if (std::strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc) {
                max_seconds = std::atoi(argv[++i]);
                if (max_seconds < 1) max_seconds = 120;
                continue;
            }
            if (std::strcmp(argv[i], "--stealth") == 0) {
                stealth = true;
                continue;
            }
            if (std::strcmp(argv[i], "--stealth2") == 0) {
                cfg.use_vm_readv = true;
                continue;
            }
            if (std::strcmp(argv[i], "--no-deep-so") == 0) {
                cfg.deep_so_scan = false;
                continue;
            }
            if (std::strcmp(argv[i], "--relaxed") == 0) {
                cfg.relaxed = true;
                continue;
            }
            if (std::strcmp(argv[i], "--art-dex") == 0 && i+1<argc) {
                const char* value=argv[++i];
                if(std::strcmp(value,"auto") && std::strcmp(value,"off") && std::strcmp(value,"only")) {
                    std::fprintf(stderr,"[-] --art-dex requires auto, off or only\n");return 1;
                }
                cfg.art_dex=std::strcmp(value,"off")!=0;
                cfg.art_only=!std::strcmp(value,"only");continue;
            }
            if (std::strcmp(argv[i], "--art-scan-mb") == 0 && i+1<argc) {
                char* end=nullptr;const unsigned long value=std::strtoul(argv[++i],&end,10);
                if(!end || *end || value<1 || value>512)return 1;
                cfg.art_scan_mb=static_cast<unsigned>(value);continue;
            }
            if (std::strcmp(argv[i], "--anon") == 0) {
                cfg.anon_only = true;
                continue;
            }
            if (std::strcmp(argv[i], "--fast-capture") == 0 && i+1<argc) {
                const char* value=argv[++i];
                if(std::strcmp(value,"auto") && std::strcmp(value,"off")) {
                    std::fprintf(stderr,"[-] --fast-capture requires auto or off\n");return 1;
                }
                cfg.fast_capture=std::strcmp(value,"off")!=0;continue;
            }
            if (std::strcmp(argv[i], "--art-merge") == 0 && i+1<argc) {
                const char* value=argv[++i];
                if(std::strcmp(value,"auto") && std::strcmp(value,"off")) {
                    std::fprintf(stderr,"[-] --art-merge requires auto or off\n");return 1;
                }
                cfg.art_merge=std::strcmp(value,"off")!=0;continue;
            }
            if (std::strcmp(argv[i], "--art-refill") == 0 && i+1<argc) {
                const char* value=argv[++i];
                if(std::strcmp(value,"auto") && std::strcmp(value,"off")) {
                    std::fprintf(stderr,"[-] --art-refill requires auto or off\n");return 1;
                }
                cfg.art_refill=std::strcmp(value,"off")!=0;continue;
            }
            if (std::strcmp(argv[i], "--fast-max-kb") == 0 && i+1<argc) {
                char* end=nullptr;const unsigned long n=std::strtoul(argv[++i],&end,10);
                if(!end || *end || n<4 || n>8192) {
                    std::fprintf(stderr,"[-] --fast-max-kb requires 4..8192\n");return 1;
                }
                cfg.fast_max_kb=static_cast<unsigned>(n);continue;
            }
            if (std::strcmp(argv[i], "--region-delay") == 0 &&
                i + 1 < argc) {
                cfg.region_delay_us = std::atoi(argv[++i]) * 1000;
                continue;
            }
            if ((std::strcmp(argv[i], "--name") == 0 ||
                 std::strcmp(argv[i], "--disguise") == 0) && i + 1 < argc) {
                disguise = argv[++i];
                continue;
            }
            if (std::strcmp(argv[i], "--continuous") == 0) {
                cfg.continuous = true;
                continue;
            }
            if (std::strcmp(argv[i], "--spawn") == 0) {
                cfg.spawn = true; cfg.continuous = true; continue;
            }
            if (std::strcmp(argv[i], "--spawn-restart") == 0) {
                cfg.spawn = true; cfg.spawn_restart = true; cfg.continuous = true; continue;
            }
            if (std::strcmp(argv[i], "--spawn-timeout") == 0 && i + 1 < argc) {
                cfg.spawn_timeout = std::atoi(argv[++i]);
                if (cfg.spawn_timeout < 1 || cfg.spawn_timeout > 300) return 1;
                continue;
            }
            if (std::strcmp(argv[i], "--events") == 0 && i + 1 < argc) {
                const char* backend = argv[++i];
                if (std::strcmp(backend, "auto") && std::strcmp(backend, "tracefs") &&
                    std::strcmp(backend, "poll")) {
                    std::fprintf(stderr, "[-] --events requires auto, tracefs or poll\n"); return 1;
                }
                std::snprintf(cfg.event_backend, sizeof(cfg.event_backend), "%s", backend);
                cfg.continuous = true; continue;
            }
            if (std::strcmp(argv[i], "--monitor-interval") == 0 && i + 1 < argc) {
                cfg.monitor_interval = std::atoi(argv[++i]);
                if (cfg.monitor_interval < 1) cfg.monitor_interval = 1;
                continue;
            }
            if (std::strcmp(argv[i], "--monitor-duration") == 0 && i + 1 < argc) {
                cfg.monitor_duration = std::atoi(argv[++i]);
                continue;
            }
            if (std::strcmp(argv[i], "--monitor-verbose") == 0) {
                cfg.monitor_verbose = true;
                continue;
            }
            if (argv[i][0] == '-') {
                std::fprintf(stderr, "[-] Unknown or incomplete option: %s\n", argv[i]); return 1;
            }
            if (!target) { target = argv[i]; continue; }
            if (!out_dir) { out_dir = argv[i]; continue; }
        }

        if (verify_file) return verify_artifact(verify_file);

        // Apply stealth defaults
        if (stealth && cfg.region_delay_us == 0) cfg.region_delay_us = 1000;
        if (stealth && !disguise) disguise = "kworker/u16:2";

        // Copy strings before disguise destroys argv
        if (target) target = ::strdup(target);
        if (out_dir) out_dir = ::strdup(out_dir);
        if (disguise) disguise = ::strdup(disguise);

        // Apply disguise early
        ProcessManager::disguise_self(argc, argv, disguise);

        // ---- Validate target ----
        if (!target) {
            print_usage(argv[0]);
            return 1;
        }

        if (!out_dir) out_dir = ::strdup("/data/local/tmp/nhdd_dump");

        // ---- Resolve target to PIDs ----
        char pids[kMaxPids][16];
        int pid_count = 0;
        PackageProcessTracker package_tracker;
        auto discover_pids = [&]() {
            auto processes = ProcessManager::discover(target, package_tracker);
            if (processes.size() > kMaxPids)
                std::fprintf(stderr, "[!] Package process limit %d exceeded\n", kMaxPids);
            int count = 0;
            for (const auto& process : processes) {
                if (count == kMaxPids) break;
                std::snprintf(pids[count++], sizeof(pids[0]), "%d", process.pid);
            }
            return count;
        };
        bool is_numeric = true;
        for (const char* c = target; *c; c++) {
            if (!std::isdigit(static_cast<unsigned char>(*c))) {
                is_numeric = false;
                break;
            }
        }

        if (is_numeric) {
            if (cfg.spawn) { std::fprintf(stderr, "[-] --spawn requires a package name\n"); return 1; }
            std::snprintf(pids[0], sizeof(pids[0]), "%s", target);
            pid_count = 1;
        } else {
            if (!PackageProcessTracker::valid_package(target)) {
                std::fprintf(stderr, "[-] Invalid package name\n"); return 1;
            }
            pid_count = discover_pids();
            if (pid_count <= 0 && !cfg.continuous) {
                std::fprintf(stderr, "[-] No running process matches package '%s'\n",
                             target);
                return 1;
            }
            std::fprintf(stderr, "[*] Resolved package '%s' -> %d process(es):",
                         target, pid_count);
            for (int i = 0; i < pid_count; i++)
                std::fprintf(stderr, " %s", pids[i]);
            std::fprintf(stderr, "\n");
        }

        std::string spawn_component;
        if (cfg.spawn) {
            spawn_component = ProcessManager::resolve_activity(target);
            if (spawn_component.empty()) {
                std::fprintf(stderr, "[-] No launcher activity resolved for %s\n", target); return 1;
            }
            if (pid_count > 0 && !cfg.spawn_restart) {
                std::fprintf(stderr, "[-] Package already running; use --spawn-restart to force-stop before cold launch\n"); return 1;
            }
            if (cfg.spawn_restart && ProcessManager::command(
                    {"/system/bin/am", "force-stop", target}) != 0) {
                std::fprintf(stderr, "[-] force-stop failed for %s\n", target); return 1;
            }
            pid_count = 0;
        }

        // ---- Create output directories ----
        char dex_dir[512], so_dir[512], jni_dir[512];
        std::snprintf(dex_dir, sizeof(dex_dir), "%s/dex", out_dir);
        std::snprintf(so_dir, sizeof(so_dir), "%s/so", out_dir);
        std::snprintf(jni_dir, sizeof(jni_dir), "%s/jnimap", out_dir);
        char maps_dir[512];
        std::snprintf(maps_dir, sizeof(maps_dir), "%s/maps", out_dir);

        if (mkdir_checked(out_dir)) return 1;
        if (mode & ScanMode::DEX) { if (mkdir_checked(dex_dir)) return 1; }
        if ((mode & ScanMode::SO) || cfg.save_maps) { if (mkdir_checked(so_dir)) return 1; }
        if (mode & ScanMode::JNIMAP) { if (mkdir_checked(jni_dir)) return 1; }
        if (cfg.save_maps) { if (mkdir_checked(maps_dir)) return 1; }

        // Wipe stale output
        if (!keep) {
            if (mode & ScanMode::DEX) {
                clean_dir_ext(dex_dir, ".dex");
                clean_dir_ext(dex_dir, ".json");
                clean_dir_ext(dex_dir, ".cdex");
                clean_dir_ext(dex_dir, ".vdex");
                clean_dir_ext(dex_dir, ".oat-header.bin");
            }
            if (mode & ScanMode::SO) {
                clean_dir_ext(so_dir, ".so");
                clean_dir_ext(so_dir, ".bin");
                clean_dir_ext(so_dir, ".json");
            }
            if (mode & ScanMode::JNIMAP) clean_dir_ext(jni_dir, ".jsonl");
        }

        // ---- Print scan info ----
        if (mode & ScanMode::DEX)
            std::fprintf(stderr, "[*] Scanning for DEX files...\n");
        if (mode & ScanMode::SO)
            std::fprintf(stderr, "[*] Scanning for SO files...\n");
        if (mode & ScanMode::JNIMAP)
            std::fprintf(stderr, "[*] Scanning for JNI native maps%s%s...\n",
                         cfg.jnimap_module[0] ? " in " : "",
                         cfg.jnimap_module[0] ? cfg.jnimap_module : "");
        std::fprintf(stderr, "[*] Output directory: %s\n", out_dir);
        
        if (cfg.continuous) {
            std::fprintf(stderr,
                "[*] CONTINUOUS mode: monitoring maps every %ds%s\n",
                cfg.monitor_interval,
                cfg.monitor_duration > 0 ? 
                    (std::string(" for ") + std::to_string(cfg.monitor_duration) + "s").c_str() : 
                    " (unlimited)");
            std::fprintf(stderr,
                "[*] >>> Mapping, permission and sampled-content changes trigger incremental DEX/SO/JNI scans <<<\n");
        } else if (watch) {
            std::fprintf(stderr,
                "[*] WATCH mode: scan until %d dry rounds (max %d rounds / %ds)\n",
                watch_dry_limit, max_rounds, max_seconds);
            std::fprintf(stderr,
                "[*] >>> Now navigate the app's feature pages on the phone. <<<\n");
        } else {
            std::fprintf(stderr, "[*] Rounds: %d, interval: %ds\n",
                         snapshot_rounds, snapshot_interval);
        }

        // ---- Main scan loop ----
        ScanCounters counters;
        DexDedup dex_dedup;
        SoDedup so_dedup;
        JniDedup jni_dedup;
        NhddScanner scanner(dex_dedup, so_dedup, jni_dedup);

        int rounds_run = 0;
        int dry_rounds = 0;

        // ---- Continuous monitoring mode ----
        if (cfg.continuous) {
            char timeline_path[768];
            const int timeline_path_length = std::snprintf(
                timeline_path, sizeof(timeline_path), "%s/timeline.jsonl",
                out_dir);
            if (timeline_path_length < 0 ||
                static_cast<size_t>(timeline_path_length) >=
                    sizeof(timeline_path)) {
                std::fprintf(stderr,
                             "[-] Continuous timeline path is too long\n");
                return 1;
            }
            if (cfg.timeline &&
                !MapsMonitor::prepare_timeline_file(timeline_path, keep)) {
                const int timeline_errno = errno != 0 ? errno : EIO;
                std::fprintf(stderr,
                             "[-] Failed to %s continuous timeline %s: "
                             "%s (errno=%d)\n",
                             keep ? "open/append" : "create/truncate",
                             timeline_path, std::strerror(timeline_errno),
                             timeline_errno);
                return 1;
            }

            // A PID is not a durable identity. /proc/<pid>/stat starttime keeps
            // baselines isolated when Android recycles a numeric PID or when
            // package subprocess ordering changes between polls.
            std::unordered_map<std::string, MapsMonitor> monitors;
            bool stop_numeric_continuous = false;
            FastCaptureService fast_capture(target,is_numeric,size_t(cfg.fast_max_kb)*1024,mode & ScanMode::DEX,cfg.art_refill,cfg.art_merge,
                cfg.fast_capture && std::strcmp(cfg.event_backend,"poll")!=0);
            {
                std::vector<int> filter;
                for(int p=0;p<pid_count;++p)filter.push_back(std::atoi(pids[p]));
                fast_capture.targets(filter);
            }
            SyscallEvents kernel_events;
            if(cfg.fast_capture)kernel_events.early_lines([&](const std::string& line) {fast_capture.line(line);});
            if (std::strcmp(cfg.event_backend, "poll") != 0 && !kernel_events.start()) {
                if (std::strcmp(cfg.event_backend, "tracefs") == 0) {
                    std::fprintf(stderr, "[-] Required tracefs backend unavailable: %s\n", kernel_events.error().c_str()); return 1;
                }
                std::fprintf(stderr, "[!] Event backend unavailable: %s; using maps/content polling\n", kernel_events.error().c_str());
            }
            if(kernel_events.active() && pid_count>0) {
                std::vector<int> filter;
                for(int p=0;p<pid_count;++p)filter.push_back(std::atoi(pids[p]));
                kernel_events.filter_processes(filter);
            }
            if(std::strcmp(cfg.event_backend,"tracefs")==0 && !kernel_events.active()) {
                std::fprintf(stderr,"[-] Required tracefs backend could not establish target filtering\n");return 1;
            }
            if(cfg.fast_capture && cfg.art_refill && kernel_events.active())scanner.on_art_capture([&](const DexCapture& capture,
                const MapsRegion* maps,size_t count,const std::function<bool(uintptr_t,void*,size_t)>& read) {
                if(kernel_events.active())fast_capture.arm_art(capture,maps,count,read);
            });
            if(cfg.fast_capture && kernel_events.active() && !fast_capture.start_publication(out_dir)) {
                std::fprintf(stderr,"[-] Could not start bounded fast publication worker\n");return 1;
            }
            if(cfg.fast_capture && kernel_events.active())scanner.on_background_read([&]{fast_capture.scan_checkpoint();});
            if(cfg.fast_capture)std::fprintf(stderr,kernel_events.active()
                ? "[*] Fast local capture armed: prefix=%u KiB/event, two passes/8ms, queue=32MiB, output<=256MiB; not atomic\n"
                : "[!] Fast local capture unavailable without tracefs; polling cannot rescue vanished bytes (prefix=%u KiB)\n",
                cfg.fast_max_kb);
            ProcessManager::LaunchHelper launch_helper;
            pid_t& launch_pid = launch_helper.pid;
            if (cfg.spawn) {
                // Event source is armed before ActivityManager can start the app.
                launch_pid = ::fork();
                if (launch_pid == 0) {
                    ::execl("/system/bin/am", "am", "start", "-n", spawn_component.c_str(),
                            static_cast<char*>(nullptr));
                    ::_exit(127);
                }
                if (launch_pid < 0) { std::perror("launch fork"); return 1; }
                std::fprintf(stderr, "[*] SPAWN armed; launching %s (discovery every 100ms)\n", spawn_component.c_str());
            }

            std::fprintf(stderr, "[*] Taking baseline snapshots for %d process(es)...\n", pid_count);
            for (int p = 0; p < pid_count; p++) {
                uint64_t starttime = 0;
                if (!MapsMonitor::read_process_starttime(pids[p], &starttime)) {
                    std::fprintf(stderr, "[-] Failed to identify PID %s\n", pids[p]);
                    continue;
                }
                MapsMonitor monitor;
                if (!monitor.take_baseline(pids[p], starttime)) {
                    const int capture_errno = monitor.last_capture_errno() != 0
                                                  ? monitor.last_capture_errno()
                                                  : EIO;
                    std::fprintf(
                        stderr,
                        "[-] Failed to take /proc/%s/maps baseline: %s "
                        "(errno=%d); no partial snapshot was accepted\n",
                        pids[p], std::strerror(capture_errno), capture_errno);
                    continue;
                }
                const std::string identity = MapsMonitor::process_identity_key(
                    pids[p], monitor.process_starttime());
                monitors.emplace(identity, std::move(monitor));
            }

            // Initial full scan
            std::fprintf(stderr, "[*] Running initial full scan...\n");
            for (int p = 0; p < pid_count; p++) {
                uint64_t starttime = 0;
                if (!MapsMonitor::read_process_starttime(pids[p], &starttime)) {
                    if (is_numeric) {
                        std::fprintf(
                            stderr,
                            "[!] Numeric PID %s exited before the initial "
                            "scan; stopping continuous mode to avoid later "
                            "PID reuse\n",
                            pids[p]);
                        stop_numeric_continuous = true;
                        break;
                    }
                    continue;
                }
                const std::string identity = MapsMonitor::process_identity_key(
                    pids[p], starttime);
                if (monitors.find(identity) == monitors.end()) {
                    if (!MapsMonitor::may_follow_new_generation(is_numeric)) {
                        std::fprintf(
                            stderr,
                            "[!] Numeric PID %s now has untracked "
                            "starttime=%llu; stopping continuous mode instead "
                            "of adopting a possibly reused PID\n",
                            pids[p],
                            static_cast<unsigned long long>(starttime));
                        stop_numeric_continuous = true;
                        break;
                    }
                    continue;
                }
                scanner.scan_pid(pids[p], dex_dir, so_dir, jni_dir, mode,
                                 counters, nullptr, starttime);
            }

            time_t start_time = std::time(nullptr);
            auto next_poll = std::chrono::steady_clock::now();
            bool spawn_seen = !cfg.spawn;
            uint64_t observed_losses = 0;
            bool event_backend_was_active = kernel_events.active();
            int check_count = 0;

            if (!stop_numeric_continuous) {
                std::fprintf(
                    stderr,
                    "[*] Starting continuous monitoring (interval=%ds)...\n",
                    cfg.monitor_interval);
            }

            while (!stop_numeric_continuous && !nhdd_stop_requested) {
                // Check duration limit
                if (cfg.monitor_duration > 0) {
                    time_t elapsed = std::time(nullptr) - start_time;
                    if (elapsed >= cfg.monitor_duration) {
                        std::fprintf(stderr, "\n[*] Monitor duration limit (%ds) reached\n",
                                     cfg.monitor_duration);
                        break;
                    }
                }

                const auto resolver = [&](int tid, int* tgid, uint64_t* ticks, bool* compat) {
                    char path[64], line[256];
                    std::snprintf(path, sizeof(path), "/proc/%d/status", tid);
                    FILE* f = std::fopen(path, "r");
                    if (!f) return false;
                    int leader = 0;
                    while (std::fgets(line, sizeof(line), f))
                        if (std::sscanf(line, "Tgid: %d", &leader) == 1) break;
                    std::fclose(f);
                    TrackedProcess process;
                    if (!ProcessManager::inspect(leader, &process)) return false;
                    bool match = is_numeric ? leader == std::atoi(target) :
                        (PackageProcessTracker::matches(target, process.command) ||
                         package_tracker.contains(leader, process.starttime));
                    if (!match && !is_numeric) {
                        TrackedProcess parent;
                        match = ProcessManager::inspect(process.parent, &parent) &&
                            package_tracker.contains(parent.pid, parent.starttime) &&
                            process.starttime >= parent.starttime;
                    }
                    if (!match) return false;
                    if(is_numeric && monitors.find(MapsMonitor::process_identity_key(
                            target,process.starttime))==monitors.end())return false;
                    *tgid = leader; *ticks = process.starttime;
                    *compat = sizeof(uintptr_t) == 4;
#if defined(__aarch64__)
                    std::snprintf(path, sizeof(path), "/proc/%d/exe", leader);
                    int exe = ::open(path, O_RDONLY | O_CLOEXEC);
                    unsigned char magic[5] = {};
                    if (exe < 0) return false;
                    ssize_t got = ::read(exe, magic, sizeof(magic));
                    ::close(exe);
                    if (got != 5 || std::memcmp(magic, "\177ELF", 4)) return false;
                    *compat = magic[4] == 1;
#endif
                    return true;
                };
                auto memory_events = kernel_events.active()
                    ? kernel_events.read_events(100, resolver)
                    : std::vector<MemorySyscallEvent>{};
                if (!kernel_events.active()) ::usleep(100000);
                bool periodic = std::chrono::steady_clock::now() >= next_poll;
                if (periodic) next_poll = std::chrono::steady_clock::now() +
                    std::chrono::seconds(cfg.monitor_interval);
                const bool lost_events = kernel_events.losses() != observed_losses;
                if (lost_events) {
                    if(cfg.fast_capture && cfg.art_refill)fast_capture.invalidate_art();
                    observed_losses = kernel_events.losses();
                    std::fprintf(stderr, "[!] Kernel event loss/read failure count=%llu; reconciling full maps snapshots\n",
                                 static_cast<unsigned long long>(observed_losses));
                    periodic = true;
                }
                if (launch_pid > 0) {
                    int status = 0;
                    if (::waitpid(launch_pid, &status, WNOHANG) == launch_pid) {
                        launch_pid = -1;
                        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                            std::fprintf(stderr, "[-] ActivityManager launch command failed\n"); return 1;
                        }
                    }
                }
                check_count++;

                // Re-resolve PIDs if package name was provided
                if (!is_numeric) {
                    pid_count = discover_pids();
                    if (pid_count <= 0) {
                        if (periodic) std::fprintf(stderr, "[*] No matching process, waiting...\n");
                        pid_count = 0;
                    }
                }
                if(pid_count>0 || spawn_seen) {
                    std::vector<int> filter;
                    for(int p=0;p<pid_count;++p)filter.push_back(std::atoi(pids[p]));
                    fast_capture.targets(filter);
                    kernel_events.filter_processes(filter);
                }
                if(event_backend_was_active && !kernel_events.active()) {
                    if(cfg.fast_capture && cfg.art_refill)fast_capture.invalidate_art();
                    std::fprintf(stderr,"[!] Event source stopped: %s\n",kernel_events.error().c_str());
                    if(std::strcmp(cfg.event_backend,"tracefs")==0)return 1;
                    std::fprintf(stderr,"[!] Continuing with maps/content polling\n");
                    event_backend_was_active=false;
                }
                if (pid_count > 0) spawn_seen = true;
                if (!spawn_seen && std::time(nullptr) - start_time >= cfg.spawn_timeout) {
                    std::fprintf(stderr, "[-] Spawn timed out without discovering a package process\n"); return 1;
                }
                if (cfg.timeline && !memory_events.empty()) {
                    FILE* f = std::fopen(timeline_path, "a");
                    if (!f) std::perror("syscall timeline");
                    else {
                        for (const auto& event : memory_events) SyscallEvents::write_event(f, event);
                        if (std::fclose(f) != 0) std::perror("syscall timeline close");
                    }
                }

                bool found_change = false;
                int scans_triggered = 0;
                size_t event_count = 0;
                std::unordered_set<std::string> active_identities;

                // Check each process once. Multiple changed mappings are
                // batched into one ScanScope and one scanner invocation.
                for (int p = 0; p < pid_count; p++) {
                    uint64_t process_starttime = 0;
                    if (!MapsMonitor::read_process_starttime(
                            pids[p], &process_starttime)) {
                        if (is_numeric) {
                            std::fprintf(
                                stderr,
                                "[!] Numeric PID %s exited; stopping "
                                "continuous mode to avoid later PID reuse\n",
                                pids[p]);
                            stop_numeric_continuous = true;
                            break;
                        }
                        if (cfg.monitor_verbose)
                            std::fprintf(stderr,
                                         "[*] PID %s disappeared before maps check\n",
                                         pids[p]);
                        continue;
                    }
                    const std::string identity = MapsMonitor::process_identity_key(
                        pids[p], process_starttime);
                    active_identities.insert(identity);

                    std::vector<IncrementalScanRange> syscall_ranges;
                    for (const auto& event : memory_events) {
                        if (event.pid != std::atoi(pids[p]) || event.starttime != process_starttime) continue;
                        if ((!event.before && (event.operation == "munmap" || event.operation == "mmap")) || event.old_end > event.old_address) {
                            const uintptr_t a = event.old_end > event.old_address ? event.old_address : event.address;
                            const uintptr_t e = event.old_end > event.old_address ? event.old_end : event.end;
                            scanner.invalidate_dex_range(static_cast<uint32_t>(event.pid), event.starttime, a, e);
                        }
                        if (event.operation == "munmap" && !event.before) continue;
                        IncrementalScanRange range;
                        range.start = event.address; range.end = event.end;
                        range.reasons = MAP_CHANGE_SYSCALL;
                        range.readable = (event.protection & 1) != 0 || event.before;
                        range.writable = (event.protection & 2) != 0;
                        range.executable = (event.protection & 4) != 0;
                        syscall_ranges.push_back(range);
                    }

                    auto found = monitors.find(identity);
                    if (found == monitors.end()) {
                        if (!MapsMonitor::may_follow_new_generation(is_numeric)) {
                            std::fprintf(
                                stderr,
                                "[!] Numeric PID %s changed to untracked "
                                "starttime=%llu; stopping continuous mode "
                                "without scanning the replacement\n",
                                pids[p],
                                static_cast<unsigned long long>(
                                    process_starttime));
                            stop_numeric_continuous = true;
                            break;
                        }
                        MapsMonitor monitor;
                        if (!monitor.take_baseline(pids[p], process_starttime)) {
                            const int capture_errno =
                                monitor.last_capture_errno() != 0
                                    ? monitor.last_capture_errno()
                                    : EIO;
                            std::fprintf(
                                stderr,
                                "[-] Failed to take /proc/%s/maps baseline: "
                                "%s (errno=%d); no partial snapshot was "
                                "accepted\n",
                                pids[p], std::strerror(capture_errno),
                                capture_errno);
                            continue;
                        }
                        monitors.emplace(identity, std::move(monitor));

                        // A new process identity has no comparable old ranges;
                        // run exactly one full scan for all configured modes.
                        found_change = true;
                        scans_triggered++;
                        std::fprintf(stderr,
                                     "[+] NEW PROCESS: pid=%s starttime=%llu; "
                                     "running initial DEX/SO/JNI scan\n",
                                     pids[p],
                                     static_cast<unsigned long long>(process_starttime));
                        scanner.scan_pid(pids[p], dex_dir, so_dir, jni_dir,
                                         mode, counters, nullptr,
                                         process_starttime);
                        continue;
                    }

                    if (!periodic && syscall_ranges.empty()) continue;

                    MapsMonitor::ChangeSet changes =
                        found->second.check_changes(pids[p], process_starttime);
                    if (!changes.capture_ok) {
                        const int capture_errno = changes.capture_errno != 0
                                                      ? changes.capture_errno
                                                      : EIO;
                        std::fprintf(
                            stderr,
                            "[-] PID %s /proc maps/content snapshot failed: "
                            "%s (errno=%d); previous baseline retained\n",
                            pids[p], std::strerror(capture_errno),
                            capture_errno);
                        continue;
                    }
                    // A successful mprotect/mmap can restore exactly the old
                    // maps layout while exposing new bytes. Keep its scope even
                    // when the snapshot diff sees no change.
                    for (const auto& range : syscall_ranges) changes.scan_ranges.push_back(range);

                    if (changes.has_changes()) {
                        found_change = true;
                        event_count += changes.events.size();
                        // Mapping removal/backing replacement ends the byte
                        // generation of any overlapping cached DEX. Invalidate
                        // it even when there is no current range to scan.
                        for (const auto& event : changes.events) {
                            if ((event.reasons &
                                 (MAP_CHANGE_REMOVED | MAP_CHANGE_IDENTITY)) == 0)
                                continue;
                            if (event.has_previous) {
                                scanner.invalidate_dex_range(
                                    static_cast<uint32_t>(std::strtoul(
                                        pids[p], nullptr, 10)),
                                    changes.process_starttime,
                                    event.previous.start,
                                    event.previous.end);
                            }
                            if (event.has_current) {
                                scanner.invalidate_dex_range(
                                    static_cast<uint32_t>(std::strtoul(
                                        pids[p], nullptr, 10)),
                                    changes.process_starttime,
                                    event.current.start,
                                    event.current.end);
                            }
                        }
                        if (cfg.timeline) {
                            if (!MapsMonitor::write_timeline_events(
                                    timeline_path, pids[p],
                                    changes.process_starttime, changes)) {
                                const int timeline_errno = errno;
                                std::fprintf(
                                    stderr,
                                    "[-] Failed to append continuous timeline %s: "
                                    "%s (errno=%d)\n",
                                    timeline_path,
                                    std::strerror(timeline_errno),
                                    timeline_errno);
                            }
                        }
                        if (cfg.monitor_verbose) {
                            for (const auto& event : changes.events) {
                                const auto& mapping = event.has_current
                                                          ? event.current
                                                          : event.previous;
                                std::fprintf(stderr,
                                    "[+] MAP CHANGE pid=%s 0x%lx-0x%lx %s "
                                    "kind=%s path=%s%s\n",
                                    pids[p],
                                    static_cast<unsigned long>(mapping.start),
                                    static_cast<unsigned long>(mapping.end),
                                    MapsMonitor::reasons_string(event.reasons).c_str(),
                                    MapsMonitor::source_kind_name(mapping.source_kind),
                                    mapping.path.empty() ? "<anonymous>"
                                                         : mapping.path.c_str(),
                                    (event.reasons & MAP_CHANGE_CONTENT)
                                        ? " (sampled fingerprint)" : "");
                            }
                        }
                    }

                    // Removed-only changes never cause a read. All other
                    // changed ranges are passed together so DEX, SO and JNI
                    // modes execute at most once for this PID in this round.
                    if (changes.has_scannable_changes() || lost_events) {
                        std::sort(changes.scan_ranges.begin(),changes.scan_ranges.end(),[](const auto& a,const auto& b){return a.start<b.start;});
                        std::vector<IncrementalScanRange> merged;
                        for(const auto& range:changes.scan_ranges) {
                            if(!merged.empty() && range.start<=merged.back().end) {
                                auto& last=merged.back();last.end=std::max(last.end,range.end);
                                last.reasons|=range.reasons;last.executable=last.executable||range.executable;
                                last.readable=last.readable||range.readable;last.writable=last.writable||range.writable;
                                last.path[0]='\0';
                            } else merged.push_back(range);
                        }
                        changes.scan_ranges=std::move(merged);
                        ScanScope scope = changes.make_scope();
                        scans_triggered++;
                        scanner.scan_pid(pids[p], dex_dir, so_dir, jni_dir,
                                         mode, counters, lost_events ? nullptr : &scope,
                                         changes.process_starttime);
                    }
                }

                if (stop_numeric_continuous) break;

                // Drop exited package-process identities. Package targets may
                // later adopt a fresh generation; numeric targets stop above.
                for (auto it = monitors.begin(); it != monitors.end();) {
                    if (active_identities.find(it->first) == active_identities.end())
                        it = monitors.erase(it);
                    else
                        ++it;
                }

                if ((cfg.monitor_verbose && periodic) || found_change || !memory_events.empty()) {
                    std::fprintf(stderr,
                                 "[*] Check #%d: %s, events=%zu, scans=%d "
                                 "(elapsed=%llds, SO=%d, DEX=%d, JNI=%d)\n",
                                 check_count,
                                 found_change ? "mapping changes" : "no changes",
                                 event_count, scans_triggered,
                                 static_cast<long long>(std::time(nullptr) - start_time),
                                 counters.so_count, counters.dex_unique,
                                 counters.jni_count);
                }
            }

            kernel_events.stop(); // Join acquisition before the final frozen-buffer drain.
            scanner.on_background_read({});
            if(cfg.fast_capture) {fast_capture.stop_publication();fast_capture.diagnostics();}
            std::fprintf(stderr, "[*] Continuous monitoring stopped after %d checks\n", check_count);
            std::fprintf(stderr, "[*] Event diagnostics: lost=%llu malformed=%llu\n",
                         static_cast<unsigned long long>(kernel_events.losses()),
                         static_cast<unsigned long long>(kernel_events.malformed()));
            rounds_run = check_count + 1;  // Include the initial full scan.

            // Final summary handled below
        } else {
        // ---- Standard snapshot/watch mode ----

        time_t t_start = std::time(nullptr);
        int rounds_limit = watch ? max_rounds : snapshot_rounds;

        for (int round = 0; round < rounds_limit && !nhdd_stop_requested; round++) {
            // Wall-time cap
            if (watch && max_seconds > 0) {
                if (std::difftime(std::time(nullptr), t_start) >= max_seconds) {
                    std::fprintf(stderr, "\n[*] Max seconds (%d) reached, stopping.\n",
                                 max_seconds);
                    break;
                }
            }
            rounds_run++;
            int unique_before = counters.total_unique();
            int dex_updates_before = counters.dex_updates;

            if (rounds_limit > 1)
                std::fprintf(stderr, "\n[*] === Round %d ===\n", round + 1);

            // Re-resolve pids for package targets
            if (!is_numeric && rounds_limit > 1) {
                pid_count = discover_pids();
                if (pid_count <= 0) {
                    if (watch) {
                        std::fprintf(stderr,
                            "[*] no matching process yet, waiting...\n");
                    } else {
                        std::fprintf(stderr,
                            "[-] Round %d: no matching process\n", round + 1);
                    }
                    if (snapshot_interval > 0) sleep(snapshot_interval);
                    continue;
                }
            }

            for (int p = 0; p < pid_count; p++) {
                scanner.scan_pid(pids[p], dex_dir, so_dir, jni_dir, mode,
                                  counters);
            }

            if (watch) {
                int new_this = counters.total_unique() - unique_before;
                int dex_progress = counters.dex_updates - dex_updates_before;
                if (new_this > 0 || dex_progress > 0) dry_rounds = 0;
                else dry_rounds++;
                std::fprintf(stderr,
                    "[*] round %d: +%d new, %d DEX coverage update(s) "
                    "(DEX=%d, SO=%d, JNI=%d, dry=%d/%d)\n",
                    round + 1, new_this, dex_progress, counters.dex_unique,
                    counters.so_count, counters.jni_count, dry_rounds, watch_dry_limit);
                if (dry_rounds >= watch_dry_limit) {
                    std::fprintf(stderr,
                        "[*] stable set (%d dry rounds), stopping.\n",
                        watch_dry_limit);
                    break;
                }
            }

            if (round + 1 < rounds_limit && snapshot_interval > 0)
                sleep(snapshot_interval);
        }
        
        } // end continuous/standard mode branch

        // ---- Summary ----
        std::fprintf(stderr,
            "\n[*] Done. rounds=%d%s, procs=%d, DEX=%d (%d hits, %d dedup), SO=%d, JNI=%d\n",
            rounds_run, watch ? " (watch)" : "", counters.procs,
            counters.dex_unique, counters.dex_total, counters.dex_dedup,
            counters.so_count, counters.jni_count);

        // Clean up strdup'd strings
        std::free(const_cast<char*>(target));
        std::free(const_cast<char*>(out_dir));
        if (disguise) std::free(const_cast<char*>(disguise));

        return 0;
    }

private:
    static int verify_artifact(const char* path) {
        FILE* f = std::fopen(path, "rb");
        if (!f) { std::perror(path); return 1; }
        if (std::fseek(f,0,SEEK_END)!=0) { std::fclose(f); return 1; }
        const long length=std::ftell(f);
        if(length<0 || length>256*1024*1024) {std::fclose(f);std::fprintf(stderr,"[-] Verification input exceeds 256MiB or is not seekable\n");return 1;}
        std::rewind(f);
        if(length==0){std::fclose(f);std::fputs("{\"status\":\"invalid\",\"errors\":[\"empty_file\"]}\n",stdout);return 2;}
        std::vector<uint8_t> data(static_cast<size_t>(length));
        bool ok=std::fread(data.data(),1,data.size(),f)==data.size();
        if(std::fclose(f)!=0)ok=false;
        if(!ok)return 1;
        if(std::strcmp(RuntimeFormats::identify(data.data(),data.size()),"dex")==0) {
            const auto r=DexSemantics::validate(data.data(),data.size());
            r.write_json(stdout); std::fputc('\n',stdout);
            return !r.supported?3:((r.valid && r.checksum_valid && r.signature_valid)?0:2);
        }
        // OAT is commonly carried in an ELF .rodata segment. Report the
        // payload offset, without treating the entire ELF as a raw OAT file.
        size_t offset=0;
        if(data.size()>=4 && !std::memcmp(data.data(),"\177ELF",4)) {
            for(size_t i=4;i+8<=data.size();i+=4) if(!std::memcmp(data.data()+i,"oat\n",4)) {offset=i;break;}
        }
        const bool elf=data.size()>=4 && !std::memcmp(data.data(),"\177ELF",4);
        const auto r=RuntimeFormats::inspect(data.data()+offset,data.size()-offset,false,
                                            elf?static_cast<uint64_t>(offset):UINT64_MAX);
        std::fprintf(stdout,"{\"payload_offset\":%zu,\"validation\":",offset);
        r.write_json(stdout);std::fputs("}\n",stdout);
        return !r.supported?3:(r.valid?0:2);
    }

    static int mkdir_checked(const char* path) {
        if (mkdir(path, 0777) == 0) return 0;
        if (errno == EEXIST) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
            std::fprintf(stderr, "[-] %s exists and is not a directory\n", path);
            return -1;
        }
        std::fprintf(stderr, "[-] mkdir %s failed: %s\n", path, std::strerror(errno));
        return -1;
    }

    static void clean_dir_ext(const char* dir, const char* ext) {
        DIR* d = opendir(dir);
        if (!d) return;
        struct dirent* de;
        size_t el = std::strlen(ext);
        while ((de = readdir(d))) {
            if (de->d_type != DT_REG && de->d_type != DT_UNKNOWN) continue;
            size_t l = std::strlen(de->d_name);
            if (l < el || std::strcmp(de->d_name + l - el, ext) != 0) continue;
            char p[768];
            std::snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
            unlink(p);
        }
        closedir(d);
    }

    static void print_usage(const char* argv0) {
        std::fprintf(stderr,
            "NHDD — No-Hook DEX/SO Dumper v9.0-cpp-class\n"
            "Usage: %s <pid|package> [output_dir] [--so|--dex|--all|--jnimap [LIB]]\n"
            "       %s --verify FILE\n"
            "                       [--watch [K]] [--snapshot ROUNDS] [--interval SECS]\n"
            "                       [--continuous] [--monitor-interval SECS] [--monitor-duration SECS]\n"
            "                       [--stealth] [--stealth2] [--relaxed] [--anon] [--no-deep-so]\n"
            "                       [--region-delay MS] [--name NAME]\n"
            "                       [--max-rounds N] [--max-seconds S] [--keep]\n"
            "\n"
            "  Modes:\n"
            "    --dex     Dump DEX files only (default)\n"
            "    --so      Dump SO files only\n"
            "    --all     Dump both DEX and SO files\n"
            "    --jnimap  No-hook JNINativeMethod scan. Optional LIB filter.\n"
            "\n"
            "  Anti-detection:\n"
            "    --stealth     Region delay + auto-disguise as kworker\n"
            "    --stealth2    Use process_vm_readv() (same ptrace/SELinux permissions; not a non-root bypass)\n"
            "    --relaxed     DEX scan without magic (endian_tag based)\n"
            "    --art-dex auto|off|only  Verified-build ART DEX discovery (default auto); only skips header/container scan\n"
            "    --art-scan-mb N  Native-heap read budget per round, 1..512 MiB (default 64); resumes next round\n"
            "    --fast-capture auto|off  Early tracefs local double-read capture (default auto); continuous only\n"
            "    --art-refill auto|off  Associate ART candidates; method-only validated temporal composites (default auto)\n"
            "    --art-merge auto|off   Merge verified methods across windows; freeze on conflicts (default auto)\n"
            "    --fast-max-kb N  Per-event prefix 4..8192 KiB (default 1024), shared 8ms read budget\n"
            "    --anon        Only scan anonymous mappings\n"
            "    --region-delay MS  Pause between regions (ms)\n"
            "    --name NAME   Fake process name\n"
            "\n"
            "  Capture:\n"
            "    --watch [K]   Keep scanning until K dry rounds\n"
            "    --snapshot N  Fixed N rounds (default 1)\n"
            "    --interval T  Seconds between rounds (default 1)\n"
            "    --continuous  Incremental DEX/SO/JNI scan on mapping, permission, W->X,\n"
            "                  or sampled-content changes\n"
            "    --monitor-interval T  Seconds between maps checks in continuous mode (default 2)\n"
            "    --monitor-duration S  Total monitoring time in seconds (0=unlimited, default 0)\n"
            "    --monitor-verbose     Print every maps check event\n"
            "    --spawn       Arm events before launching a stopped package; follows package processes/descendants\n"
            "    --spawn-restart  Force-stop package, then perform --spawn\n"
            "    --spawn-timeout S  Wait for first process (1..300, default 15)\n"
            "    --events auto|tracefs|poll  Kernel syscall events with explicit fallback (default auto)\n"
            "    --verify FILE  Offline DEX/CDEX/VDEX/OAT validation to JSON; exit 0=checks passed, 2=invalid, 3=unsupported\n"
            "\n"
            "  JNIMAP:\n"
            "    --jni-lib LIB Filter fnPtr module\n"
            "    --jni-min N   Min contiguous entries (default 2)\n"
            "    --jni-max-region MB  Max generic region size to scan (default 64)\n"
            "    --jni-full    Exhaustive JNIMAP scan, slower but broader\n"
            "\n"
            "  Output:\n"
            "    --keep        Don't wipe stale output before scanning\n"
            "\n", argv0, argv0);
    }
};
