// nhdd_app.hpp — CLI application entry point and orchestration
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include "common_types.hpp"
#include "nhdd_config.hpp"
#include "dedup_table.hpp"
#include "process_manager.hpp"
#include "so_dumper.hpp"
#include "nhdd_scanner.hpp"

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

        auto& cfg = NhddConfig::instance();

        // ---- CLI argument parsing ----
        for (int i = 1; i < argc; i++) {
            if (std::strcmp(argv[i], "--help") == 0 ||
                std::strcmp(argv[i], "-h") == 0) {
                print_usage(argv[0]);
                return 0;
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
            if (std::strcmp(argv[i], "--anon") == 0) {
                cfg.anon_only = true;
                continue;
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
            if (!target) { target = argv[i]; continue; }
            if (!out_dir) { out_dir = argv[i]; continue; }
        }

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
        bool is_numeric = true;
        for (const char* c = target; *c; c++) {
            if (!std::isdigit(static_cast<unsigned char>(*c))) {
                is_numeric = false;
                break;
            }
        }

        if (is_numeric) {
            std::snprintf(pids[0], sizeof(pids[0]), "%s", target);
            pid_count = 1;
        } else {
            pid_count = ProcessManager::find_pids_for_package(
                target, pids, sizeof(pids[0]), kMaxPids);
            if (pid_count <= 0) {
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
            if (mode & ScanMode::DEX) clean_dir_ext(dex_dir, ".dex");
            if (mode & ScanMode::SO)  clean_dir_ext(so_dir, ".so");
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
        if (watch) {
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
        time_t t_start = std::time(nullptr);
        int rounds_limit = watch ? max_rounds : snapshot_rounds;

        for (int round = 0; round < rounds_limit; round++) {
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

            if (rounds_limit > 1)
                std::fprintf(stderr, "\n[*] === Round %d ===\n", round + 1);

            // Re-resolve pids for package targets
            if (!is_numeric && rounds_limit > 1) {
                pid_count = ProcessManager::find_pids_for_package(
                    target, pids, sizeof(pids[0]), kMaxPids);
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
                if (new_this > 0) dry_rounds = 0;
                else dry_rounds++;
                std::fprintf(stderr,
                    "[*] round %d: +%d new (DEX=%d, SO=%d, JNI=%d, dry=%d/%d)\n",
                    round + 1, new_this, counters.dex_unique,
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

        // ---- Summary ----
        std::fprintf(stderr,
            "\n[*] Done. rounds=%d%s, procs=%d, DEX=%d (%d hits, %d dedup), SO=%d, JNI=%d\n",
            rounds_run, watch ? " (watch)" : "", counters.procs,
            counters.dex_unique, counters.dex_total, counters.dex_dedup,
            counters.so_count, counters.jni_count);

        // ---- Auto-fix SO files ----
        if (counters.so_count > 0) {
            std::fprintf(stderr,
                "[*] Fixing %d SO files with built-in ELF repair...\n",
                counters.so_count);
            int fixed = 0, failed = 0;
            DIR* d = opendir(so_dir);
            if (d) {
                struct dirent* de;
                while ((de = readdir(d))) {
                    if (de->d_type != DT_REG && de->d_type != DT_UNKNOWN) continue;
                    size_t namelen = std::strlen(de->d_name);
                    if (namelen < 4 ||
                        std::strcmp(de->d_name + namelen - 3, ".so") != 0)
                        continue;
                    char path[768];
                    std::snprintf(path, sizeof(path), "%s/%s", so_dir, de->d_name);
                    if (SoDumper::repair_basic(path) == 0) fixed++;
                    else {
                        failed++;
                        std::fprintf(stderr, "[-] Repair failed: %s\n", de->d_name);
                    }
                }
                closedir(d);
            }
            std::fprintf(stderr, "[*] Built-in repair: %d fixed, %d failed\n",
                         fixed, failed);
        }

        // Clean up strdup'd strings
        std::free(const_cast<char*>(target));
        std::free(const_cast<char*>(out_dir));
        if (disguise) std::free(const_cast<char*>(disguise));

        return 0;
    }

private:
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
            "                       [--watch [K]] [--snapshot ROUNDS] [--interval SECS]\n"
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
            "    --stealth2    Use process_vm_readv() (avoids /proc/pid/mem)\n"
            "    --relaxed     DEX scan without magic (endian_tag based)\n"
            "    --anon        Only scan anonymous mappings\n"
            "    --region-delay MS  Pause between regions (ms)\n"
            "    --name NAME   Fake process name\n"
            "\n"
            "  Capture:\n"
            "    --watch [K]   Keep scanning until K dry rounds\n"
            "    --snapshot N  Fixed N rounds (default 1)\n"
            "    --interval T  Seconds between rounds (default 1)\n"
            "\n"
            "  JNIMAP:\n"
            "    --jni-lib LIB Filter fnPtr module\n"
            "    --jni-min N   Min contiguous entries (default 2)\n"
            "    --jni-max-region MB  Max generic region size to scan (default 64)\n"
            "    --jni-full    Exhaustive JNIMAP scan, slower but broader\n"
            "\n"
            "  Output:\n"
            "    --keep        Don't wipe stale output before scanning\n"
            "\n", argv0);
    }
};
