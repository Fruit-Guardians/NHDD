// process_memory.hpp — Remote process memory I/O (pread / process_vm_readv)
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include "nhdd_config.hpp"

class ProcessMemory {
public:
    ProcessMemory() = default;

    // Open the target process memory via /proc/<pid>/mem
    bool open_mem(const char* pid) {
        char path[256];
        std::snprintf(path, sizeof(path), "/proc/%s/mem", pid);
        mem_fd_ = ::open(path, O_RDONLY);
        return mem_fd_ >= 0;
    }

    // Set target pid for process_vm_readv
    void set_pid(pid_t pid) { pid_ = pid; }
    pid_t get_pid() const { return pid_; }

    // Read remote memory using the configured method
    ssize_t read(uint8_t* buf, size_t size, uintptr_t remote_addr) {
        if (NhddConfig::instance().use_vm_readv)
            return vm_readv_retry(buf, size, remote_addr);
        return pread_retry(buf, size, remote_addr);
    }

    // Check if mem fd is valid
    bool valid() const {
        return NhddConfig::instance().use_vm_readv || mem_fd_ >= 0;
    }

    void close_mem() {
        if (mem_fd_ >= 0) {
            ::close(mem_fd_);
            mem_fd_ = -1;
        }
    }

    ~ProcessMemory() { close_mem(); }

    ProcessMemory(const ProcessMemory&) = delete;
    ProcessMemory& operator=(const ProcessMemory&) = delete;

private:
    // Retry-aware pread over /proc/<pid>/mem
    ssize_t pread_retry(uint8_t* buf, size_t want, uintptr_t off) {
        size_t got = 0;
        while (got < want) {
            ssize_t r = ::pread(mem_fd_, buf + got, want - got,
                                static_cast<off_t>(off + got));
            if (r > 0) { got += static_cast<size_t>(r); continue; }
            if (r < 0 && errno == EINTR) continue;
            break;
        }
        return static_cast<ssize_t>(got);
    }

    // Retry-aware process_vm_readv (stealth2)
    ssize_t vm_readv_retry(uint8_t* buf, size_t want, uintptr_t remote_addr) {
        struct iovec local, remote;
        size_t got = 0;
        while (got < want) {
            local.iov_base = buf + got;
            local.iov_len = want - got;
            remote.iov_base = reinterpret_cast<void*>(remote_addr + got);
            remote.iov_len = want - got;
            ssize_t r = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
            if (r > 0) { got += static_cast<size_t>(r); continue; }
            if (r < 0 && errno == EINTR) continue;
            break;
        }
        return static_cast<ssize_t>(got);
    }

    int   mem_fd_ = -1;
    pid_t pid_ = 0;
};
