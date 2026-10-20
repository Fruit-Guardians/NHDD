// process_manager.hpp — Process operations: disguise, cmdline, PID resolution
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "process_tracking.hpp"
#include "common_types.hpp"

class ProcessManager {
public:
    struct LaunchHelper {
        pid_t pid = -1;
        ~LaunchHelper() {
            if(pid<=0)return;
            int status=0;
            if(::waitpid(pid,&status,WNOHANG)==0) {
                ::kill(pid,SIGKILL);
                while(::waitpid(pid,&status,0)<0 && errno==EINTR) {}
            }
        }
    };
    static bool inspect(int pid, TrackedProcess* out) {
        if (!out || pid <= 0) return false;
        char path[64], line[4096], command[512] = {};
        std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE* f = std::fopen(path, "r");
        if (!f) return false;
        bool ok = std::fgets(line, sizeof(line), f) != nullptr;
        std::fclose(f);
        char* tail = ok ? std::strrchr(line, ')') : nullptr;
        if (!tail) return false;
        char* cursor = tail + 1;
        TrackedProcess p;
        p.pid = pid;
        for (int field = 3; field <= 22; ++field) {
            while (*cursor == ' ') ++cursor;
            if (!*cursor) return false;
            char* end = cursor;
            while (*end && *end != ' ' && *end != '\n') ++end;
            if (field == 4) p.parent = std::atoi(cursor);
            if (field == 22) p.starttime = std::strtoull(cursor, nullptr, 10);
            cursor = end;
        }
        std::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = ::open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        ssize_t n = ::read(fd, command, sizeof(command) - 1);
        ::close(fd);
        if (n <= 0 || !p.starttime) return false;
        p.command = command;
        *out = std::move(p);
        return true;
    }

    static std::vector<TrackedProcess> discover(
            const char* package, PackageProcessTracker& tracker) {
        std::vector<TrackedProcess> all;
        DIR* d = ::opendir("/proc");
        if (!d) return {};
        while (auto* de = ::readdir(d)) {
            char* end = nullptr;
            long pid = std::strtol(de->d_name, &end, 10);
            if (!end || *end || pid <= 0 || pid > 0x7fffffff) continue;
            TrackedProcess p;
            if (inspect(static_cast<int>(pid), &p)) all.push_back(std::move(p));
        }
        ::closedir(d);
        return tracker.update(package, all);
    }

    // execvp receives individual arguments: package/component never enter a shell.
    static int command(const std::vector<std::string>& args, std::string* output = nullptr) {
        if (args.empty()) return -1;
        int pipefd[2];
        if (::pipe(pipefd) != 0) return -1;
        pid_t child = ::fork();
        if (child == 0) {
            ::close(pipefd[0]);
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::dup2(pipefd[1], STDERR_FILENO);
            ::close(pipefd[1]);
            std::vector<char*> argv;
            for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr);
            ::execvp(argv[0], argv.data());
            ::_exit(127);
        }
        ::close(pipefd[1]);
        if (child < 0) { ::close(pipefd[0]); return -1; }
        LaunchHelper cleanup;cleanup.pid=child;
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
        ::fcntl(pipefd[0],F_SETFL,O_NONBLOCK);
        char buffer[1024];
        int status=0;
        bool exited=false;
        while(std::chrono::steady_clock::now()<deadline) {
            pollfd input{pipefd[0],POLLIN,0};
            (void)::poll(&input,1,50);
            ssize_t n;
            while((n=::read(pipefd[0],buffer,sizeof(buffer)))>0) {
                if(output && output->size()<65536)
                    output->append(buffer,std::min(static_cast<size_t>(n),65536-output->size()));
            }
            if(::waitpid(child,&status,WNOHANG)==child){
                exited=true;
                while((n=::read(pipefd[0],buffer,sizeof(buffer)))>0)
                    if(output && output->size()<65536)
                        output->append(buffer,std::min(static_cast<size_t>(n),65536-output->size()));
                break;
            }
        }
        ::close(pipefd[0]);
        if(!exited){errno=ETIMEDOUT;return -1;}
        cleanup.pid=-1;
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    static std::string resolve_activity(const char* package) {
        std::string output;
        if (command({"/system/bin/cmd", "package", "resolve-activity", "--brief",
                     "-a", "android.intent.action.MAIN", "-c",
                     "android.intent.category.LAUNCHER", package}, &output) != 0) return {};
        size_t cursor = 0;
        while (cursor < output.size()) {
            size_t end = output.find('\n', cursor);
            std::string line = output.substr(cursor, end - cursor);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.compare(0, std::strlen(package) + 1, std::string(package) + "/") == 0 &&
                line.find_first_of(" \t") == std::string::npos) return line;
            if (end == std::string::npos) break;
            cursor = end + 1;
        }
        return {};
    }
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
