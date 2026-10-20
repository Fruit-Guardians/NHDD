// Independent collector and bounded publisher; scan thread never drains a batch.
#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <thread>
#include <condition_variable>
#include "fast_schedule.hpp"
#include <sys/uio.h>
#include "fast_capture.hpp"
#include "syscall_events.hpp"
#include "process_manager.hpp"
#include "maps_monitor.hpp"
#include "nhdd_scanner.hpp"
#include "art_refill_service.hpp"

class FastCaptureService {
public:
    FastCaptureService(std::string target,bool numeric,size_t cap,bool dex,bool art_refill=true,bool art_merge=true)
        :target_(std::move(target)),numeric_(numeric),cap_(cap),dex_(dex),refill_(art_refill && dex,art_merge) { decoder_.early_entries(true); }
    ~FastCaptureService() {stop_publication();}
    bool start_publication(const char* out_dir) {
        if(publisher_.joinable() || stopping_)return false;
        output_dir_=std::string(out_dir)+"/fast";
        if(::mkdir(output_dir_.c_str(),0700)!=0 && errno!=EEXIST)return false;
        try {publisher_=std::thread([this]{publication_loop();});}
        catch(const std::exception& e) {std::fprintf(stderr,"[-] Fast publisher: %s\n",e.what());return false;}
        publisher_started_=true;
        return true;
    }
    // Caller must first stop/join the trace collector. Also used by RAII on
    // early returns, where SyscallEvents is destroyed before this service.
    void stop_publication() {
        {std::lock_guard<std::mutex> lock(mutex_);stopping_=true;}
        ready_.notify_all();if(publisher_.joinable())publisher_.join();
    }
    void arm_art(const DexCapture& capture,const MapsRegion* maps,size_t count,const ArtRefillService::Read& read) {
        refill_.arm(capture,maps,count,read);
    }
    void invalidate_art() {refill_.invalidate_all();}
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
        if(decoder_.losses()!=early_losses_)refill_.invalidate_all();
        for(const auto& event:events) {refill_.event(event);acquire(event);}
        early_losses_=decoder_.losses();
    }
    void diagnostics() const {
        std::fprintf(stderr,"[*] Fast capture: observed=%llu published=%llu DEX-observations=%llu "
            "queue_drops=%llu budget_drops=%llu generation_rejected=%llu unreadable=%llu "
            "early_trace_losses=%llu disk_drops=%llu write_failures=%llu (two reads, not atomic)\n",
            ull(observed_),ull(published_),ull(dex_observations_),ull(queue_drops_),ull(budget_drops_),
            ull(rejected_),ull(unreadable_),ull(early_losses_),ull(disk_drops_),ull(write_failures_));
        refill_.diagnostics();
        std::fprintf(stderr,"[*] Fast schedule: worker=%u peak_items=%zu peak_bytes=%zu remaining=%zu "
            "retry_attempts=%llu retry_exhausted=%llu queue_wait_max_ms=%.3f worker_failed=%u\n",
            publisher_started_?1u:0u,schedule_.peak_items,schedule_.peak_bytes,schedule_.items,ull(retry_attempts_),ull(retry_exhausted_),
            queue_wait_max_ms_,publisher_failed_?1u:0u);
    }
private:
    struct Snapshot {
        MemorySyscallEvent event;FastObservation observation;uint64_t sequence=0;
        std::vector<ArtRefillService::Link> links;
        bool raw_published=false;unsigned attempts=0;double due=0;
        size_t bytes() const {return observation.first.size()+observation.second.size();}
    };
    static unsigned long long ull(uint64_t n) {return static_cast<unsigned long long>(n);}
    static double now() {
        timespec t{};::clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;
    }
    void publication_loop() {
        try {
            for(;;) {
                Snapshot s;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    for(;;) {
                        if(queue_.empty()) {if(stopping_)return;ready_.wait(lock);continue;}
                        auto fresh=queue_.end(),retry=queue_.end();double earliest=now()+1;
                        const double stamp=now();
                        for(auto it=queue_.begin();it!=queue_.end();++it) {
                            if(!it->raw_published) {if(fresh==queue_.end())fresh=it;}
                            else if(it->due<=stamp) {if(retry==queue_.end())retry=it;}
                            else earliest=std::min(earliest,it->due);
                        }
                        auto selected=schedule_.retry_turn(fresh!=queue_.end(),retry!=queue_.end())?retry:fresh;
                        if(selected==queue_.end()) {
                            ready_.wait_for(lock,std::chrono::duration<double>(std::max(0.001,earliest-stamp)));continue;
                        }
                        schedule_.dispatched(selected->raw_published);s=std::move(*selected);queue_.erase(selected);break;
                    }
                }
                const bool retry=s.raw_published;const size_t bytes=s.bytes();
                if(retry)++retry_attempts_;
                else queue_wait_max_ms_=std::max(queue_wait_max_ms_,1000*(now()-s.observation.end));
                refill_.begin_batch();last_written_=0;
                const size_t reserve=retry?0:3*bytes+1024*1024;
                bool ok=false;
                if(published_bytes_+reserve>256u*1024*1024)++disk_drops_;
                else {
                    ok=publish_one(output_dir_,s);if(!ok)++write_failures_;
                    if(ok && !retry)++published_;
                    if(ok)published_bytes_+=last_written_;
                }
                ++s.attempts;
                const bool again=ok && !s.links.empty() && FastSchedule::can_retry(s.attempts);
                if(ok && !s.links.empty() && !again)++retry_exhausted_;
                {std::lock_guard<std::mutex> lock(mutex_);
                    if(again) {s.due=now()+std::max(FastSchedule::retry_delay(s.attempts),refill_.budget_wait());queue_.push_back(std::move(s));}
                    else schedule_.release(bytes);
                }
            }
        } catch(const std::exception& e) {
            std::fprintf(stderr,"[-] Fast publisher stopped: %s\n",e.what());publisher_failed_=true;
            std::lock_guard<std::mutex> lock(mutex_);write_failures_+=schedule_.items;queue_.clear();schedule_.used=0;schedule_.items=0;
        }
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
            if(publisher_failed_ || stopping_ || !schedule_.admit(charge)) {++queue_drops_;return;}
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
        ArtRefillService::Read linked_read=[&](uintptr_t address,void* bytes,size_t count) {
            return generation(event.pid,event.starttime) &&
                read(address,static_cast<uint8_t*>(bytes),count)==count;
        };
        auto links=refill_.prepare(event,linked_read);
        auto observation=FastObservation::capture(event.address,event.end-event.address,cap_,read,
            [&]{return generation(event.pid,event.starttime);},[]{return now();});
        refill_.finish(links,linked_read);
        if(!observation.generation_valid) {++rejected_;return;}
        if(!observation.read_bytes(0) && !observation.read_bytes(1)) {++unreadable_;return;}
        Snapshot s;s.event=event;s.observation=std::move(observation);s.sequence=++sequence_;s.links=std::move(links);
        {std::lock_guard<std::mutex> lock(mutex_);
            if(publisher_failed_ || stopping_ || !schedule_.admit(s.bytes())) {++queue_drops_;return;}
            schedule_.retain(s.bytes());queue_.push_back(std::move(s));}
        ready_.notify_one();
    }
    bool publish_one(const std::string& dir,Snapshot& s) {
        const auto& o=s.observation;const auto& e=s.event;
        char name[192];std::snprintf(name,sizeof(name),"fast_%d_%llx_%llx_%d_%llu_%llu",e.pid,ull(e.starttime),
            ull(e.address),::getpid(),ull(static_cast<uint64_t>(o.begin*1e9)),ull(s.sequence));
        const std::string stem=dir+"/"+name;
        if(s.raw_published) {
            std::vector<ArtRefillService::Link> retry;
            const size_t available=256u*1024*1024-std::min(size_t(256u*1024*1024),size_t(published_bytes_));
            last_written_+=refill_.publish(stem,e,o,s.links,available,&retry,s.attempts+1);
            s.links=std::move(retry);return true;
        }
        const double publication_begin=now();
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
        std::fputs("],\"art_associations\":[",f);
        for(size_t i=0;i<s.links.size();++i) {
            const auto& link=s.links[i];const auto& b=*link.baseline;
            const auto plan=ArtRefill::plan(b,o,static_cast<uint32_t>(e.pid),e.starttime,link.before && link.after);
            std::fprintf(f,"%s{\"baseline_revision\":%llu,\"dex_address\":\"0x%llx\",\"art_object\":\"0x%llx\","
                "\"capture_anchor_before\":%s,\"capture_anchor_after\":%s,\"planning_status\":\"%s\"}",i?",":"",
                ull(b.revision),ull(b.identity.address),ull(b.object),link.before?"true":"false",
                link.after?"true":"false",plan.reason.c_str());
        }
        std::fprintf(f,"],\"publication_begin_boot\":%.9f,\"queue_wait_ms\":%.3f,\"publication_worker\":true}\n",
            publication_begin,1000*(publication_begin-o.end));
        const long meta_bytes=std::ftell(f);if(meta_bytes>0)last_written_+=static_cast<size_t>(meta_bytes);
        ok=(std::fflush(f)==0 && ::fsync(::fileno(f))==0) && ok;
        if(std::fclose(f)!=0)ok=false;
        entries.emplace_back(meta.c_str(),temp.c_str());
        if(!ok) {cleanup();return false;}
        if(!artifact_publish_transaction_inline(&entries))return false;
        dex_observations_+=candidates;
        s.raw_published=true;
        const size_t available=256u*1024*1024-std::min(size_t(256u*1024*1024),size_t(published_bytes_)+last_written_);
        std::vector<ArtRefillService::Link> retry;
        last_written_+=refill_.publish(stem,e,o,s.links,available,&retry,1);
        s.links=std::move(retry);
        return true;
    }
    std::string target_;bool numeric_;size_t cap_;bool dex_;
    SyscallEvents decoder_;
    std::mutex mutex_;std::unordered_map<int,uint64_t> targets_;
    std::deque<Snapshot> queue_;size_t budget_bytes_=0;double budget_epoch_=0;
    FastSchedule schedule_;std::condition_variable ready_;std::thread publisher_;std::string output_dir_;
    bool stopping_=false,publisher_started_=false;std::atomic<bool> publisher_failed_{false};
    uint64_t retry_attempts_=0,retry_exhausted_=0;double queue_wait_max_ms_=0;
    uint64_t sequence_=0,published_=0,published_bytes_=0,dex_observations_=0,disk_drops_=0,write_failures_=0;
    size_t last_written_=0;
    ArtRefillService refill_;
    std::atomic<uint64_t> observed_{0},queue_drops_{0},budget_drops_{0},rejected_{0},unreadable_{0},early_losses_{0};
};
