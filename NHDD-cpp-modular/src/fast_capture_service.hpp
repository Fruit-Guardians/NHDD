// Collector-only acquisition; main-thread publication of frozen observations.
#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <sys/uio.h>
#include "fast_capture.hpp"
#include "syscall_events.hpp"
#include "process_manager.hpp"
#include "maps_monitor.hpp"
#include "nhdd_scanner.hpp"

class FastCaptureService {
public:
    FastCaptureService(std::string target,bool numeric,size_t cap,bool dex)
        :target_(std::move(target)),numeric_(numeric),cap_(cap),dex_(dex) { decoder_.early_entries(true); }
    void targets(const std::vector<int>& pids) {
        std::unordered_map<int,uint64_t> next;
        for(int pid:pids) {
            TrackedProcess p;if(ProcessManager::inspect(pid,&p))next[pid]=p.starttime;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if(numeric_ && !targets_.empty())return; // Numeric PID is pinned to its original generation.
        targets_=std::move(next);
    }
    void line(const std::string& text) {
        auto events=decoder_.ingest(text,[this](int tid,int* pid,uint64_t* ticks,bool* compat) {
            return resolve(tid,pid,ticks,compat);
        });
        for(const auto& event:events)acquire(event);
        early_losses_=decoder_.losses();
    }
    void publish(const char* out_dir) {
        std::deque<Snapshot> ready;
        {std::lock_guard<std::mutex> lock(mutex_);ready.swap(queue_);queued_bytes_=0;}
        if(ready.empty())return;
        const uint64_t previous=published_,previous_dex=dex_observations_;
        const std::string dir=std::string(out_dir)+"/fast";
        if(::mkdir(dir.c_str(),0700)!=0 && errno!=EEXIST) {write_failures_+=ready.size();return;}
        for(auto& snapshot:ready) {
            // Includes worst-case non-overlapping DEX raw/fixed copies and metadata.
            const size_t reserve=3*snapshot.bytes()+1024*1024;
            if(published_bytes_+reserve>256u*1024*1024) {++disk_drops_;continue;}
            last_written_=0;
            if(publish_one(dir,snapshot)) {++published_;published_bytes_+=last_written_;}
            else ++write_failures_;
        }
        if(published_!=previous)std::fprintf(stderr,"[+] Fast capture batch: saved=%llu DEX-observations=%llu dir=%s\n",
            ull(published_-previous),ull(dex_observations_-previous_dex),dir.c_str());
    }
    void diagnostics() const {
        std::fprintf(stderr,"[*] Fast capture: observed=%llu published=%llu DEX-observations=%llu "
            "queue_drops=%llu budget_drops=%llu generation_rejected=%llu unreadable=%llu "
            "early_trace_losses=%llu disk_drops=%llu write_failures=%llu (two reads, not atomic)\n",
            ull(observed_),ull(published_),ull(dex_observations_),ull(queue_drops_),ull(budget_drops_),
            ull(rejected_),ull(unreadable_),ull(early_losses_),ull(disk_drops_),ull(write_failures_));
    }
private:
    struct Snapshot {
        MemorySyscallEvent event;FastObservation observation;uint64_t sequence=0;
        size_t bytes() const {return observation.first.size()+observation.second.size();}
    };
    static unsigned long long ull(uint64_t n) {return static_cast<unsigned long long>(n);}
    static double now() {
        timespec t{};::clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;
    }
    bool generation(int pid,uint64_t expected) const {
        uint64_t ticks=0;const auto text=std::to_string(pid);
        return MapsMonitor::read_process_starttime(text.c_str(),&ticks) && ticks==expected;
    }
    bool resolve(int tid,int* pid,uint64_t* ticks,bool* compat) {
        const auto status="/proc/"+std::to_string(tid)+"/status";
        FILE* f=std::fopen(status.c_str(),"r");if(!f)return false;
        char line[256];int leader=0;
        while(std::fgets(line,sizeof(line),f))if(std::sscanf(line,"Tgid: %d",&leader)==1)break;
        std::fclose(f);
        TrackedProcess p;if(!ProcessManager::inspect(leader,&p))return false;
        bool match=false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it=targets_.find(leader);match=it!=targets_.end() && it->second==p.starttime;
            if(!match && !numeric_) {
                TrackedProcess parent;
                if(ProcessManager::inspect(p.parent,&parent)) {
                    it=targets_.find(parent.pid);
                    match=it!=targets_.end() && it->second==parent.starttime && p.starttime>=parent.starttime;
                }
            }
        }
        if(!match && !numeric_)match=PackageProcessTracker::matches(target_.c_str(),p.command);
        if(!match)return false;
        *pid=leader;*ticks=p.starttime;*compat=sizeof(uintptr_t)==4;
#if defined(__aarch64__)
        int exe=::open(("/proc/"+std::to_string(leader)+"/exe").c_str(),O_RDONLY|O_CLOEXEC);
        unsigned char magic[5]={};const ssize_t got=exe<0 ? -1 : ::read(exe,magic,5);
        if(exe>=0)::close(exe);
        if(got!=5 || std::memcmp(magic,"\177ELF",4))return false;
        *compat=magic[4]==1;
#endif
        return true;
    }
    void acquire(const MemorySyscallEvent& event) {
        if(!event.before && (event.operation=="munmap" ||
            ((event.operation=="mmap" || event.operation=="mprotect") && !(event.protection&1))))return;
        const double stamp=now();
        if(stamp-budget_epoch_>=1) {budget_epoch_=stamp;budget_bytes_=0;}
        const size_t charge=2*std::min(cap_,size_t(event.end-event.address));
        if(budget_bytes_+charge>32u*1024*1024) {++budget_drops_;return;}
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(queue_.size()>=512 || queued_bytes_+charge>32u*1024*1024) {++queue_drops_;return;}
        }
        budget_bytes_+=charge;++observed_;
        struct MemoryFd {
            int value;
            ~MemoryFd() {if(value>=0)::close(value);}
        } memory_fd{::open(("/proc/"+std::to_string(event.pid)+"/mem").c_str(),O_RDONLY|O_CLOEXEC)};
        auto read=[&](uintptr_t address,uint8_t* bytes,size_t count)->size_t {
            iovec local{bytes,count},remote{reinterpret_cast<void*>(address),count};
            ssize_t n=::process_vm_readv(event.pid,&local,1,&remote,1,0);
            if(n<=0 && memory_fd.value>=0)n=::pread(memory_fd.value,bytes,count,static_cast<off_t>(address));
            return n>0?static_cast<size_t>(n):0;
        };
        auto observation=FastObservation::capture(event.address,event.end-event.address,cap_,read,
            [&]{return generation(event.pid,event.starttime);},[]{return now();});
        if(!observation.generation_valid) {++rejected_;return;}
        if(!observation.read_bytes(0) && !observation.read_bytes(1)) {++unreadable_;return;}
        Snapshot s{event,std::move(observation),++sequence_};
        std::lock_guard<std::mutex> lock(mutex_);queued_bytes_+=s.bytes();queue_.push_back(std::move(s));
    }
    bool publish_one(const std::string& dir,const Snapshot& s) {
        const auto& o=s.observation;const auto& e=s.event;
        char name[192];std::snprintf(name,sizeof(name),"fast_%d_%llx_%llx_%d_%llu_%llu",e.pid,ull(e.starttime),
            ull(e.address),::getpid(),ull(static_cast<uint64_t>(o.begin*1e9)),ull(s.sequence));
        const std::string stem=dir+"/"+name;
        std::vector<ArtifactTransactionEntryInline> entries;
        auto stage=[&](const std::string& path,const uint8_t* bytes,size_t count) {
            const auto temp=artifact_sidecar_path_inline(path.c_str(),"tmp");
            if(!write_staged_bytes_inline(temp.c_str(),bytes,count))return false;
            last_written_+=count;
            entries.emplace_back(path.c_str(),temp.c_str());return true;
        };
        auto cleanup=[&] {for(const auto& entry:entries)(void)::unlink(entry.temporary_path.c_str());};
        if(!stage(stem+".first.bin",o.first.data(),o.first.size()) ||
           !stage(stem+".second.bin",o.second.data(),o.second.size())) {cleanup();return false;}
        const auto meta=stem+".json",temp=artifact_sidecar_path_inline(meta.c_str(),"tmp");
        FILE* f=std::fopen(temp.c_str(),"w");if(!f) {cleanup();return false;}
        std::fprintf(f,"{\"schema_version\":1,\"source\":\"early_tracefs_local_capture\",\"pid\":%d,"
            "\"process_start_time_ticks\":%llu,\"tid\":%d,\"trigger\":\"%s\",\"phase\":\"%s\","
            "\"address\":\"0x%llx\",\"event_boot_seconds\":%.9f,\"read_begin_boot_seconds\":%.9f,"
            "\"read_end_boot_seconds\":%.9f,\"event_to_read_ms\":%.3f,\"requested_bytes\":%zu,"
            "\"captured_span_bytes\":%zu,\"truncated\":%s,\"deadline_hit\":%s,"
            "\"consistency\":\"%s\",\"atomic_snapshot\":false,\"mapping_identity_verified\":false,"
            "\"generation_verified_at_capture\":true,\"cross_event_merge\":false,"
            "\"artifacts\":{\"first\":\"%s.first.bin\",\"second\":\"%s.second.bin\"},\"pages\":[",
            e.pid,ull(e.starttime),e.tid,e.operation.c_str(),e.before?"enter_best_effort":"exit_success",ull(o.address),
            e.boot_seconds,o.begin,o.end,1000*(o.begin-e.boot_seconds),o.requested,o.first.size(),
            o.truncated?"true":"false",o.deadline_hit?"true":"false",o.consistency(0,o.first.size()),name,name);
        for(size_t i=0;i<o.pages.size();++i) {
            const auto& p=o.pages[i];std::fprintf(f,"%s{\"offset\":%zu,\"length\":%zu,\"first_read\":%zu,"
                "\"second_read\":%zu,\"changed_bytes\":%zu}",i?",":"",p.offset,p.length,p.first,p.second,p.changed);
        }
        std::fputs("],\"dex_observations\":[",f);
        bool ok=true;size_t candidates=0;
        for(unsigned pass=0;dex_ && pass<2 && ok;++pass) {
            const auto& bytes=pass?o.second:o.first;
            for(size_t off=0;off+112<=bytes.size() && candidates<64;++off) {
                if(std::memcmp(bytes.data()+off,"dex\n",4) || !o.covered(pass,off,112))continue;
                uint32_t length=0;std::memcpy(&length,bytes.data()+off+32,4);
                if(!DexValidator::header_strong_valid(bytes.data()+off,length) ||
                   !o.covered(pass,off,length))continue;
                // Identical copies need only one DEX pair; both buffers remain available.
                if(pass && o.covered(0,off,length) && !std::memcmp(bytes.data()+off,o.first.data()+off,length))continue;
                const auto suffix="_"+std::to_string(off)+"_read"+std::to_string(pass+1);
                const auto raw=std::string(name)+suffix+".raw.dex",fixed=std::string(name)+suffix+".fixed.dex";
                std::vector<uint8_t> normalized(bytes.begin()+off,bytes.begin()+off+length);
                DexValidator::fix_header_and_checksums(normalized.data(),normalized.size());
                ok=stage(dir+"/"+raw,bytes.data()+off,length) && stage(dir+"/"+fixed,normalized.data(),normalized.size());
                std::fprintf(f,"%s{\"offset\":%zu,\"length\":%u,\"read\":%u,\"byte_complete\":true,"
                    "\"consistency\":\"%s\",\"raw\":\"%s\",\"fixed\":\"%s\",\"semantic_raw\":",
                    candidates?",":"",off,length,pass+1,o.consistency(off,length),raw.c_str(),fixed.c_str());
                DexSemantics::validate(bytes.data()+off,length).write_json(f);
                std::fputs(",\"semantic_fixed\":",f);DexSemantics::validate(normalized.data(),normalized.size()).write_json(f);
                std::fputc('}',f);++candidates;off+=length-1;
            }
        }
        std::fputs("]}\n",f);
        const long meta_bytes=std::ftell(f);if(meta_bytes>0)last_written_+=static_cast<size_t>(meta_bytes);
        ok=(std::fflush(f)==0 && ::fsync(::fileno(f))==0) && ok;
        if(std::fclose(f)!=0)ok=false;
        entries.emplace_back(meta.c_str(),temp.c_str());
        if(!ok) {cleanup();return false;}
        if(!artifact_publish_transaction_inline(&entries))return false;
        dex_observations_+=candidates;
        return true;
    }
    std::string target_;bool numeric_;size_t cap_;bool dex_;
    SyscallEvents decoder_;
    std::mutex mutex_;std::unordered_map<int,uint64_t> targets_;
    std::deque<Snapshot> queue_;size_t queued_bytes_=0,budget_bytes_=0;double budget_epoch_=0;
    uint64_t sequence_=0,published_=0,published_bytes_=0,dex_observations_=0,disk_drops_=0,write_failures_=0;
    size_t last_written_=0;
    std::atomic<uint64_t> observed_{0},queue_drops_{0},budget_drops_{0},rejected_{0},unreadable_{0},early_losses_{0};
};
