// An isolated tracefs instance. Never modifies the root tracer or other instances.
#pragma once
#include <algorithm>
#include <cstdlib>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <atomic>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#ifndef NHDD_TRACE_RETRY_US
#define NHDD_TRACE_RETRY_US 250
#endif
static_assert(NHDD_TRACE_RETRY_US>=50 && NHDD_TRACE_RETRY_US<=2000,"trace retry must be bounded (50..2000us)");
#ifndef NHDD_TRACE_NICE_DELTA
#define NHDD_TRACE_NICE_DELTA 2
#endif
static_assert(NHDD_TRACE_NICE_DELTA>=0 && NHDD_TRACE_NICE_DELTA<=3,"collector nice adjustment must be small (0..3)");
#include "common_types.hpp"
#if defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

struct MemorySyscallEvent {
    int pid = 0, tid = 0;
    uint64_t starttime = 0;
    std::string operation;
    bool before = false;
    double boot_seconds = 0;
    uintptr_t address = 0, end = 0;
    uint64_t protection = 0;
    uintptr_t old_address = 0, old_end = 0;
};

class SyscallEventDecoder {
public:
    struct Record {
        int tid = 0, id = -1;
        bool entry = false;
        double timestamp = 0;
        uint64_t args[6] = {};
        int64_t result = 0;
    };
    static bool parse(const std::string& line, Record* out) {
        if (!out) return false;
        const size_t bracket = line.find('[');
        const size_t marker = line.find(": sys_");
        if (bracket == std::string::npos || marker == std::string::npos) return false;
        // Default context-info: comm-TID [CPU] flags timestamp: sys_...
        // record-tgid is disabled in our instance so a comm containing '-' is safe.
        const size_t dash = line.rfind('-', bracket);
        if (dash == std::string::npos) return false;
        char* end = nullptr;
        long tid = std::strtol(line.c_str() + dash + 1, &end, 10);
        if (tid <= 0 || tid > 0x7fffffff || end == line.c_str() + dash + 1) return false;
        size_t ts = line.rfind(' ', marker);
        if (ts == std::string::npos) return false;
        Record r;
        r.tid = static_cast<int>(tid);
        r.timestamp = std::strtod(line.c_str() + ts + 1, &end);
        if (!end || end != line.c_str() + marker) return false;
        const size_t nr = line.find("NR ", marker);
        if (nr == std::string::npos) return false;
        r.entry = line.compare(marker + 2, 10, "sys_enter:") == 0;
        if (!r.entry && line.compare(marker + 2, 9, "sys_exit:") != 0) return false;
        long id = std::strtol(line.c_str() + nr + 3, &end, 10);
        if (id < 0 || id > 10000) return false;
        r.id = static_cast<int>(id);
        if (r.entry) {
            const size_t args = line.find('(', nr);
            if (args == std::string::npos) return false;
            const char* cursor = line.c_str() + args + 1;
            for (unsigned i = 0; i < 6; ++i) {
                errno = 0;
                r.args[i] = std::strtoull(cursor, &end, 16);
                if (errno || end == cursor) return false;
                while (*end == ' ') ++end;
                if (*end != (i == 5 ? ')' : ',')) return false;
                cursor = end + 1;
            }
        } else {
            const size_t equal = line.find('=', nr);
            if (equal == std::string::npos) return false;
            errno = 0;
            r.result = std::strtoll(line.c_str() + equal + 1, &end, 10);
            if (errno || end == line.c_str() + equal + 1) return false;
            while(*end==' ' || *end=='\r' || *end=='\t')++end;
            if(*end)return false;
        }
        *out = r;
        return true;
    }
    static const char* operation(int id, bool arm32 = false) {
#if defined(__aarch64__) || defined(__arm__)
        if (arm32) {
            if (id == 192) return "mmap";
            if (id == 125) return "mprotect";
            if (id == 91) return "munmap";
            if (id == 163) return "mremap";
        } else {
            if (id == 222) return "mmap";
            if (id == 226) return "mprotect";
            if (id == 215) return "munmap";
            if (id == 216) return "mremap";
        }
#else
        (void)arm32;
        if (id == 9) return "mmap";
        if (id == 10) return "mprotect";
        if (id == 11) return "munmap";
        if (id == 25) return "mremap";
#endif
        return nullptr;
    }
    static bool range(uint64_t address, uint64_t size, uintptr_t* a, uintptr_t* e) {
        const uint64_t max = std::numeric_limits<uintptr_t>::max();
        if (!size || address > max || size > max - address) return false;
        *a = static_cast<uintptr_t>(address);
        *e = static_cast<uintptr_t>(address + size);
        return true;
    }
};

class SyscallEvents {
public:
    // Resolve the TID to a currently in-scope TGID, starttime and ABI. The
    // timestamp check rejects queued events belonging to a recycled PID.
    using Resolver = std::function<bool(int, int*, uint64_t*, bool*)>;
    ~SyscallEvents() { close(); }
    SyscallEvents() = default;
    SyscallEvents(const SyscallEvents&) = delete;
    SyscallEvents& operator=(const SyscallEvents&) = delete;
    bool active() const { return fd_ >= 0; }
    uint64_t losses() const { return losses_; }
    uint64_t malformed() const { return malformed_; }
    const std::string& error() const { return error_; }
    static constexpr long retry_nanoseconds(bool early) {return early?NHDD_TRACE_RETRY_US*1000L:100000000L;}
    static constexpr int collector_nice(int base) {return base-NHDD_TRACE_NICE_DELTA < -20?-20:base-NHDD_TRACE_NICE_DELTA;}
    // Configure before start(). Called on the collector, not the scan thread.
    void early_lines(std::function<void(const std::string&)> handler) { early_line_ = std::move(handler); }
    void early_entries(bool enabled) { early_entries_ = enabled; }
    void stop() { close(); }
    std::vector<MemorySyscallEvent> ingest(const std::string& line,const Resolver& resolve) {
        std::vector<MemorySyscallEvent> result;
        consume(line,resolve,result);
        return result;
    }

    bool start() {
#if defined(__linux__)
#if !defined(__aarch64__) && !defined(__arm__) && !defined(__x86_64__)
        error_ = "tracefs syscall ABI is unsupported on this build";
        return false;
#endif
        const char* roots[] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"};
        std::string attempts;
        for (const char* root : roots) {
            instance_ = std::string(root) + "/instances/nhdd_" + std::to_string(::getpid());
            if (::mkdir(instance_.c_str(), 0700) == 0) break;
            attempts += instance_ + ": " + std::strerror(errno) + "; ";
            instance_.clear();
        }
        if (instance_.empty()) { error_ = attempts; return false; }
        bool ok = control("tracing_on", "0") &&
            control("current_tracer", "nop") &&
            control("trace_clock", "boot") &&
            control("buffer_size_kb", "1024") &&
            control("options/context-info", "1") &&
            control("options/record-tgid", "0") &&
            control("options/event-fork", "1");
        // Only our isolated instance: do not wait for half a ring buffer before
        // waking the observer. Older kernels retain a short nonblocking retry.
        if(early_line_ && !control("buffer_percent","0"))
            std::fprintf(stderr,"[!] Low-watermark trace wakeup unavailable; using %dus nonblocking retries\n",NHDD_TRACE_RETRY_US);
        std::string ids;
#if defined(__aarch64__)
        ids = "id == 222 || id == 226 || id == 215 || id == 216 || id == 192 || id == 125 || id == 91 || id == 163";
#elif defined(__arm__)
        ids = "id == 192 || id == 125 || id == 91 || id == 163";
#else
        ids = "id == 9 || id == 10 || id == 11 || id == 25";
#endif
        ok = ok && control("events/raw_syscalls/sys_enter/filter", ids) &&
            control("events/raw_syscalls/sys_exit/filter", ids) &&
            control("events/raw_syscalls/sys_enter/enable", "1") &&
            control("events/raw_syscalls/sys_exit/enable", "1");
        if (ok) {
            fd_ = ::open((instance_ + "/trace_pipe").c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            ok = fd_ >= 0 && control("tracing_on", "1");
        }
        if (!ok) {
            error_ = "tracefs setup failed: " + std::string(std::strerror(errno));
            close();
            return false;
        }
        std::fprintf(stderr, "[*] Event backend: tracefs instance=%s clock=boot (mmap/mprotect/munmap/mremap)\n", instance_.c_str());
        stopping_ = false;
        try { reader_ = std::thread([this] { collect(); }); }
        catch(const std::exception& e) {
            error_ = std::string("trace collector thread: ")+e.what();close();return false;
        }
        return true;
#else
        error_ = "tracefs requires Linux/Android";
        return false;
#endif
    }

    std::vector<MemorySyscallEvent> read_events(int timeout_ms, const Resolver& resolve) {
        std::vector<MemorySyscallEvent> result;
#if defined(__linux__)
        if (!active()) return result;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_ready_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
                return !queued_.empty() || reader_failed_.load();
            });
            if (queue_drops_) {losses_ += queue_drops_; queue_drops_=0; pending_.clear();buffered_.clear();}
            buffered_ += queued_;
            queued_.clear();
        }
        {
            size_t cursor = 0, end;
            while ((end = buffered_.find('\n', cursor)) != std::string::npos) {
                consume(buffered_.substr(cursor, end - cursor), resolve, result);
                cursor = end + 1;
            }
            buffered_.erase(0, cursor);
            if (buffered_.size() > 65536) { buffered_.clear(); pending_.clear(); ++losses_; }
        }
        if(reader_failed_) {
            ++losses_;error_="trace_pipe collector failed";close();
        }
        // A missing sys_enter must never be paired with a later reused TID.
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (now - it->second.seen > std::chrono::seconds(5)) it = pending_.erase(it);
            else ++it;
        }
#else
        (void)timeout_ms; (void)resolve;
#endif
        return result;
    }

    void filter_processes(const std::vector<int>& pids) {
#if defined(__linux__)
        if(!active())return;
        std::string tids;
        for(int pid:pids) {
            const std::string path="/proc/"+std::to_string(pid)+"/task";
            DIR* d=::opendir(path.c_str());
            if(!d)continue;
            while(auto* de=::readdir(d)) {
                char* end=nullptr;long tid=std::strtol(de->d_name,&end,10);
                if(end && !*end && tid>0) tids+=std::to_string(tid)+" ";
            }
            ::closedir(d);
        }
        if(tids.empty())tids="0"; // An empty tracefs PID filter would mean all tasks.
        if(!control("set_event_pid",tids)) {
            ++losses_;
            std::fprintf(stderr,"[!] tracefs PID filtering failed; falling back to polling: %s\n",std::strerror(errno));
            close();
        }
#else
        (void)pids;
#endif
    }

    static void write_event(FILE* f, const MemorySyscallEvent& e) {
        std::fprintf(f, "{\"event\":\"memory_syscall\",\"backend\":\"tracefs\","
            "\"pid\":%d,\"tid\":%d,\"process_starttime\":%llu,\"syscall\":\"%s\","
            "\"phase\":\"%s\",\"event_boot_seconds\":%.6f,\"start\":\"0x%llx\",\"end\":\"0x%llx\","
            "\"protection\":%llu,\"old_start\":\"0x%llx\",\"old_end\":\"0x%llx\"}\n",
            e.pid, e.tid, static_cast<unsigned long long>(e.starttime), e.operation.c_str(),
            e.before ? "enter_best_effort" : "exit_success", e.boot_seconds, static_cast<unsigned long long>(e.address),
            static_cast<unsigned long long>(e.end), static_cast<unsigned long long>(e.protection),
            static_cast<unsigned long long>(e.old_address), static_cast<unsigned long long>(e.old_end));
    }

private:
    struct Pending {
        SyscallEventDecoder::Record record;
        int pid = 0;
        uint64_t starttime = 0;
        std::string op;
        std::chrono::steady_clock::time_point seen;
    };
    void consume(const std::string& line, const Resolver& resolve,
                 std::vector<MemorySyscallEvent>& out) {
        if (line.find("LOST") != std::string::npos) {
            ++losses_; pending_.clear(); return;
        }
        SyscallEventDecoder::Record r;
        if (!SyscallEventDecoder::parse(line, &r)) {
            if (line.find(": sys_") != std::string::npos) {
                ++malformed_;
                ++losses_;
                if(malformed_<=2)std::fprintf(stderr,"[!] Unparsed trace record: %.240s\n",line.c_str());
            }
            return;
        }
        int pid = 0; uint64_t starttime = 0; bool compat = false;
        if (!resolve(r.tid, &pid, &starttime, &compat)) { pending_.erase(r.tid); return; }
#if defined(__linux__)
        const long hz = ::sysconf(_SC_CLK_TCK);
        if (hz <= 0 || r.timestamp * static_cast<double>(hz) + 1 < static_cast<double>(starttime)) return;
#endif
        const char* op = SyscallEventDecoder::operation(r.id, compat);
        if (!op) return;
        if(out.size()>=8192){++losses_;pending_.clear();return;}
        if (r.entry) {
            if (pending_.size() >= 8192) { pending_.clear(); ++losses_; }
            Pending p{r, pid, starttime, op, std::chrono::steady_clock::now()};
            pending_[r.tid] = p;
            // Capture before munmap as soon as the entry record is consumed.
            // Target is not stopped: this is explicitly best effort.
            if (p.op == "munmap" || (early_entries_ && (p.op == "mprotect" || p.op == "mremap")))
                emit(p, r, true, out);
        } else {
            auto it = pending_.find(r.tid);
            if (it == pending_.end()) return;
            Pending p = it->second;
            pending_.erase(it);
            if (p.pid == pid && p.starttime == starttime && p.record.id == r.id &&
                r.timestamp >= p.record.timestamp && !(r.result<0 && r.result>=-4095)) {
                if(compat)r.result=static_cast<uint32_t>(r.result);
                emit(p, r, false, out);
            }
        }
    }
    static void emit(const Pending& p, const SyscallEventDecoder::Record& r,
                     bool before, std::vector<MemorySyscallEvent>& out) {
        MemorySyscallEvent e;
        e.pid = p.pid; e.tid = r.tid; e.starttime = p.starttime;
        e.operation = p.op; e.before = before;e.boot_seconds=r.timestamp;
        const auto* a = p.record.args;
        uint64_t address = a[0], size = a[1];
        if (p.op == "mmap") { address = static_cast<uint64_t>(r.result); e.protection = a[2]; }
        if (p.op == "mprotect") e.protection = a[2];
        if (p.op == "mremap") {
            SyscallEventDecoder::range(a[0], a[1], &e.old_address, &e.old_end);
            if (!before) { address = static_cast<uint64_t>(r.result); size = a[2]; }
        }
        if (SyscallEventDecoder::range(address, size, &e.address, &e.end)) out.push_back(std::move(e));
    }
#if defined(__linux__)
    void collect() {
        const auto own_tid=static_cast<id_t>(::syscall(SYS_gettid));errno=0;
        const int base_nice=::getpriority(PRIO_PROCESS,own_tid);const bool base_valid=errno==0;bool priority_ok=base_valid;
        const int wanted=early_line_?collector_nice(base_nice):base_nice;
        if(priority_ok && wanted!=base_nice)priority_ok=::setpriority(PRIO_PROCESS,own_tid,wanted)==0;
        if(!priority_ok)std::fprintf(stderr,"[!] Own collector nice adjustment unavailable: %s; continuing without boost\n",std::strerror(errno));
        timespec cpu_begin{};::clock_gettime(CLOCK_THREAD_CPUTIME_ID,&cpu_begin);
        uint64_t reads=0,empty_reads=0;
        struct Report {
            timespec begin;uint64_t& reads;uint64_t& empty;bool early;id_t tid;int base;bool base_valid,priority_ok;
            ~Report() {
                timespec end{};::clock_gettime(CLOCK_THREAD_CPUTIME_ID,&end);
                const double ms=1000.0*(end.tv_sec-begin.tv_sec)+(end.tv_nsec-begin.tv_nsec)*1e-6;
                errno=0;const int current=::getpriority(PRIO_PROCESS,tid);
                const bool restore_ok=!base_valid || (errno==0 && (current==base || ::setpriority(PRIO_PROCESS,tid,base)==0));
                std::fprintf(stderr,"[*] Trace collector: retry_us=%ld reads=%llu empty_reads=%llu cpu_ms=%.3f "
                    "base_nice=%d active_nice=%d collector_priority_failures=%u restore_failed=%u (own TID only)\n",
                    retry_nanoseconds(early)/1000,static_cast<unsigned long long>(reads),static_cast<unsigned long long>(empty),ms,
                    base,current,priority_ok?0u:1u,restore_ok?0u:1u);
            }
        } report{cpu_begin,reads,empty_reads,bool(early_line_),own_tid,base_nice,base_valid,priority_ok};
        char bytes[65536];
        std::string early_buffer;
        while(!stopping_) {
            pollfd pfd{fd_,POLLIN,0};
            // poll() only accepts whole milliseconds. Even with low-watermark
            // wakeups, a nonblocking trace read may need a retry before poll
            // signals readiness; do not round a 1ms plaintext window to 2ms.
            const timespec timeout{0,retry_nanoseconds(bool(early_line_))};
            int r=::ppoll(&pfd,1,&timeout,nullptr);
            if(r<0 && errno==EINTR)continue;
            if(r<0 || (pfd.revents&(POLLERR|POLLHUP|POLLNVAL))) {reader_failed_=true;queue_ready_.notify_one();break;}
            if(!r && !early_line_)continue;
            ssize_t n=::read(fd_,bytes,sizeof(bytes));
            if(n<0 && (errno==EAGAIN || errno==EINTR)){++empty_reads;continue;}
            if(n<=0){reader_failed_=true;queue_ready_.notify_one();break;}
            ++reads;
            if (early_line_) {
                early_buffer.append(bytes, static_cast<size_t>(n));
                size_t cursor=0, end=0;
                while ((end=early_buffer.find('\n',cursor))!=std::string::npos) {
                    try {early_line_(early_buffer.substr(cursor,end-cursor));}
                    catch(const std::exception& e) {
                        std::fprintf(stderr,"[!] Early capture failed: %s\n",e.what());
                        reader_failed_=true;queue_ready_.notify_one();return;
                    }
                    cursor=end+1;
                }
                early_buffer.erase(0,cursor);
                if(early_buffer.size()>65536) { early_line_("LOST oversized early trace record");early_buffer.clear(); }
            }
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if(queued_.size()+static_cast<size_t>(n)>16*1024*1024) {
                    queued_.clear();++queue_drops_;
                    const char* newline=static_cast<const char*>(std::memchr(bytes,'\n',static_cast<size_t>(n)));
                    if(newline)queued_.append(newline+1,static_cast<size_t>(bytes+n-newline-1));
                } else queued_.append(bytes,static_cast<size_t>(n));
            }
            queue_ready_.notify_one();
        }
    }

    bool control(const std::string& name, const std::string& value) {
        int fd = ::open((instance_ + "/" + name).c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;
        const bool ok = ::write(fd, value.data(), value.size()) == static_cast<ssize_t>(value.size());
        const int saved = errno;
        ::close(fd); errno = saved;
        return ok;
    }
#endif
    void close() {
#if defined(__linux__)
        stopping_ = true;
        if(reader_.joinable())reader_.join();
        if (!instance_.empty()) {
            (void)control("tracing_on", "0");
            (void)control("events/enable", "0");
        }
        if (fd_ >= 0) ::close(fd_);
        if (!instance_.empty() && ::rmdir(instance_.c_str()) != 0)
            std::fprintf(stderr, "[!] Cannot remove inactive tracefs instance %s: %s\n", instance_.c_str(), std::strerror(errno));
#endif
        fd_ = -1; instance_.clear(); pending_.clear();
    }
    int fd_ = -1;
    std::string instance_, buffered_, error_;
    uint64_t losses_ = 0, malformed_ = 0;
    std::unordered_map<int, Pending> pending_;
    std::thread reader_;
    std::mutex queue_mutex_;
    std::condition_variable queue_ready_;
    std::string queued_;
    std::atomic<bool> stopping_{false},reader_failed_{false};
    uint64_t queue_drops_=0;
    std::function<void(const std::string&)> early_line_;
    bool early_entries_=false;
};
