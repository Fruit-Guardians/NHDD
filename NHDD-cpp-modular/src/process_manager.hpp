// process_manager.hpp — Process operations: disguise, cmdline, PID resolution
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/prctl.h>
#include "common_types.hpp"

class ProcessManager {
public:
    // Disguise this process to look like a kernel worker thread
    static void disguise_self(int argc, char** argv, const char* name) {
        if (!name || !*name || argc < 1) return;

        // 1) /proc/self/comm
        char comm[16];
        std::snprintf(comm, sizeof(comm), "%s", name);
        prctl(PR_SET_NAME, reinterpret_cast<unsigned long>(comm), 0, 0, 0);

        // 2) /proc/self/cmdline — zero entire arg region, write fake name
        char* start = argv[0];
        char* end = argv[argc - 1] + std::strlen(argv[argc - 1]) + 1;
        if (end <= start) return;
        size_t cap = static_cast<size_t>(end - start);
        size_t nl = std::strlen(name);
        if (nl >= cap) nl = cap - 1;
        std::memset(start, 0, cap);
        std::memcpy(start, name, nl);
        start[nl] = '\0';
    }

    // Read /proc/<pid>/cmdline, strip colon suffix
    static int read_cmdline(const char* pid, char* out, size_t outsz) {
        char path[256];
        std::snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
        int fd = ::open(path, O_RDONLY);
        if (fd < 0) return -1;
        ssize_t r = ::read(fd, out, outsz - 1);
        ::close(fd);
        if (r <= 0) return -1;
        out[r] = '\0';
        char* colon = std::strchr(out, ':');
        if (colon) *colon = '\0';
        return 0;
    }

    // Find all PIDs whose cmdline matches the given package name
    static int find_pids_for_package(const char* pkg, char pids[][16],
                                      size_t pid_sz, int max) {
        DIR* d = opendir("/proc");
        if (!d) return 0;
        struct dirent* de;
        int count = 0;
        while ((de = readdir(d))) {
            const char* n = de->d_name;
            bool all_digit = true;
            for (const char* c = n; *c; c++)
                if (!std::isdigit(static_cast<unsigned char>(*c))) {
                    all_digit = false;
                    break;
                }
            if (!all_digit) continue;
            char cmd[256];
            if (read_cmdline(n, cmd, sizeof(cmd)) != 0) continue;
            if (std::strcmp(cmd, pkg) != 0) continue;
            if (count >= max) break;
            std::snprintf(pids[count], pid_sz, "%s", n);
            count++;
        }
        closedir(d);
        return count;
    }
};
