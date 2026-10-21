// Independent collector and bounded publisher; scan thread never drains a batch.
#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <sys/resource.h>
#include <sys/syscall.h>
#include "fast_schedule.hpp"
#include "fast_buffer_pool.hpp"
#include "capture_coordination.hpp"
#include "capture_tuning.hpp"
#include <sys/uio.h>
#include "fast_capture.hpp"
#include "syscall_events.hpp"
#include "process_manager.hpp"
#include "maps_monitor.hpp"
#include "nhdd_scanner.hpp"
#include "art_refill_service.hpp"

class FastCaptureService {
public:
    FastCaptureService(std::string target,bool numeric,size_t cap,bool dex,bool art_refill=true,bool art_merge=true,bool prewarm=true)
        :target_(std::move(target)),numeric_(numeric),cap_(cap),dex_(dex),buffer_pool_(prewarm?CaptureTuning::pool_slots:0),
        refill_(art_refill && dex,art_merge) { decoder_.early_entries(true); }
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
    void scan_checkpoint() {if(CaptureTuning::background_yield)scan_background_.checkpoint(coordination_);}
    void targets(const std::vector<int>& pids) {
        std::unordered_map<int,uint64_t> next;
        for(int pid:pids) {
            TrackedProcess p;if(ProcessManager::inspect(pid,&p,false))next[pid]=p.starttime;
        }
        {std::lock_guard<std::mutex> lock(target_mutex_);
            if(numeric_ && !targets_.empty())return; // Numeric PID remains generation-pinned.
            targets_.swap(next);
        } // Destroy the previous target map outside both collector queue locks.
    }
    void line(const std::string& text) {
        const double received=now();
        CaptureCoordination::Lease capture_active(coordination_);
        auto events=decoder_.ingest(text,[this](int tid,int* pid,uint64_t* ticks,bool* compat) {
            return resolve(tid,pid,ticks,compat);
        });
        if(decoder_.losses()!=early_losses_)refill_.invalidate_all();
        for(const auto& event:events) {refill_.event(event);acquire(event,received);}
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
        std::fprintf(stderr,"[*] Fast contention: buffer_hits=%llu buffer_misses=%llu handoff_contended=%llu "
            "scan_pauses=%llu publication_pauses=%llu publisher_nice=%d publisher_nice_end=%d priority_changes=%llu priority_failures=%llu (own thread only)\n",
            ull(buffer_hits_),ull(buffer_misses_),ull(handoff_contended_),ull(scan_background_.pauses),
            ull(publication_background_.pauses),publisher_nice_,publisher_nice_end_,ull(priority_changes_),ull(priority_failures_));
        std::fprintf(stderr,"[*] Fast policy: background_yield=%u nice_delta=%d pool_slots=%u adaptive_nice=%u\n",
            CaptureTuning::background_yield?1u:0u,CaptureTuning::nice_delta,buffer_pool_.capacity(),CaptureTuning::adaptive_nice?1u:0u);
        std::fprintf(stderr,"[*] Fast merge flush: enabled=%u scheduled=%llu revision_batch=%u\n",CaptureTuning::coalesce_merge?1u:0u,ull(merge_flush_jobs_),CaptureTuning::merge_batch);
    }
private:
#ifdef NHDD_TESTING
    friend struct CaptureTestAccess;
#endif
    struct Snapshot {
        MemorySyscallEvent event;FastObservation observation;uint64_t sequence=0;
        std::vector<ArtRefillService::Link> links;
        bool raw_published=false,merge_only=false;unsigned attempts=0;double due=0;
        double line_received=0,acquire_begin=0,anchors_done=0,acquire_end=0;
        size_t bytes() const {return observation.first.size()+observation.second.size();}
    };
    static unsigned long long ull(uint64_t n) {return static_cast<unsigned long long>(n);}
    static double now() {
        timespec t{};::clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;
    }
    static int own_priority() {
        const auto tid=static_cast<id_t>(::syscall(SYS_gettid));errno=0;
        const int value=::getpriority(PRIO_PROCESS,tid);return errno?20:value;
    }
    void publisher_priority(bool recent) {
        const int wanted=CaptureTuning::publisher_nice(publisher_base_nice_,CaptureTuning::nice_delta,recent);
        if(wanted==20 || wanted==publisher_current_nice_ || priority_failed_)return;
        const auto tid=static_cast<id_t>(::syscall(SYS_gettid));
        if(::setpriority(PRIO_PROCESS,tid,wanted)!=0) {
            ++priority_failures_;priority_failed_=true;
            std::fprintf(stderr,"[!] Could not set own publisher nice to %d: %s; retaining %d\n",wanted,std::strerror(errno),publisher_current_nice_);
        } else {
            publisher_current_nice_=wanted;++priority_changes_;
        }
    }
    void publication_loop() {
        struct EndPriority {int& result;~EndPriority(){result=own_priority();}} end_priority{publisher_nice_end_};
        struct Later {bool operator()(const Snapshot& a,const Snapshot& b) const {return a.due>b.due;}};
        // Publisher-private heap: never scan/move deferred jobs under the
        // producer mutex. Outstanding accounting still includes every retry.
        std::vector<Snapshot> deferred;
        try {
            publisher_base_nice_=publisher_current_nice_=own_priority();publisher_priority(true);
            if(publisher_base_nice_==20){++priority_failures_;priority_failed_=true;std::fprintf(stderr,"[!] Own publisher priority unavailable\n");}
            publisher_nice_=publisher_current_nice_;deferred.reserve(FastSchedule::max_items);
            for(;;) {
                Snapshot s;bool take_retry=false,flush_merges=false,pressure=false;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    for(;;) {
                        if(queue_.empty() && deferred.empty()) {
                            if(refill_.coalesced_pending()){flush_merges=true;break;}
                            if(stopping_)return;ready_.wait(lock);continue;
                        }
                        const double stamp=now();
                        const bool retry_due=!deferred.empty() && deferred.front().due<=stamp;
                        take_retry=schedule_.retry_turn(!queue_.empty(),retry_due);
                        if(!take_retry && queue_.empty()) {
                            ready_.wait_for(lock,std::chrono::duration<double>(std::max(0.001,deferred.front().due-stamp)));continue;
                        }
                        if(!take_retry) {s=std::move(queue_.front());queue_.pop_front();}
                        pressure=queue_.size()>=32;
                        break;
                    }
                }
                if(flush_merges) {enqueue_merge_flushes();continue;}
                if(take_retry) {
                    std::pop_heap(deferred.begin(),deferred.end(),Later{});s=std::move(deferred.back());deferred.pop_back();
                }
                schedule_.dispatched(take_retry);
                // Keep capture isolation through short gaps, but let the same
                // publisher drain at its inherited nice after a quiet 20ms.
                // Never boost above inherited priority, touch another TID, or
                // retry a denied priority change on every pending observation.
                if(CaptureTuning::adaptive_nice)publisher_priority(coordination_.busy(CaptureCoordination::now(),20000000));
                if(CaptureTuning::background_yield)publication_background_.checkpoint(coordination_);
                const bool retry=s.raw_published;const size_t bytes=s.bytes();
                if(retry) {if(!s.merge_only || s.attempts)++retry_attempts_;}
                else if(!s.merge_only)queue_wait_max_ms_=std::max(queue_wait_max_ms_,1000*(now()-s.observation.end));
                refill_.begin_batch(pressure && !s.merge_only);last_written_=0;
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
                if(again) {
                    s.due=now()+std::max(FastSchedule::retry_delay(s.attempts),refill_.budget_wait());
                    deferred.push_back(std::move(s));std::push_heap(deferred.begin(),deferred.end(),Later{});
                } else {
                    if(CaptureTuning::pool_slots && !s.merge_only)(void)buffer_pool_.give(s.observation);
                    std::lock_guard<std::mutex> lock(mutex_);schedule_.release(bytes);
                }
            }
        } catch(const std::exception& e) {
            std::fprintf(stderr,"[-] Fast publisher stopped: %s\n",e.what());publisher_failed_=true;
            std::deque<Snapshot> abandoned;
            {std::lock_guard<std::mutex> lock(mutex_);write_failures_+=schedule_.items;abandoned.swap(queue_);schedule_.used=0;schedule_.items=0;}
            // Destruction and allocator work occur after releasing the handoff.
        }
    }
    void enqueue_merge_flushes() {
        for(auto& link:refill_.take_coalesced()) {
            const auto& b=*link.baseline;Snapshot task;task.merge_only=true;task.raw_published=true;
            task.event.pid=static_cast<int>(b.identity.pid);task.event.starttime=b.identity.process_start_time;
            task.observation.address=b.identity.address;task.observation.begin=task.observation.end=now();
            task.sequence=++merge_flush_sequence_;task.links.push_back(std::move(link));
            std::lock_guard<std::mutex> lock(mutex_);
            if(!schedule_.admit(0)){++queue_drops_;continue;}
            schedule_.retain(0);queue_.push_back(std::move(task));++merge_flush_jobs_;
        }
    }
    bool generation(int pid,uint64_t expected) const {
        uint64_t ticks=0;const auto text=std::to_string(pid);
        return MapsMonitor::read_process_starttime(text.c_str(),&ticks) && ticks==expected;
    }
    bool resolve(int tid,int* pid,uint64_t* ticks,bool* compat) {
        int leader=0;
        if(numeric_) {
            // Numeric targets are already generation-pinned. Fresh task-dir
            // membership replaces status parsing, not leader/cmdline/ABI checks.
            {std::lock_guard<std::mutex> lock(target_mutex_);if(targets_.size()==1)leader=targets_.begin()->first;}
            if(!ProcessStat::member(leader,tid))return false;
        } else if(!ProcessStat::tgid(tid,&leader))return false;
        TrackedProcess p;if(!ProcessManager::inspect(leader,&p,!numeric_))return false;
        bool match=false;
        {
            std::lock_guard<std::mutex> lock(target_mutex_);
            auto it=targets_.find(leader);match=it!=targets_.end() && it->second==p.starttime;
        }
        if(!match && !numeric_) {
            TrackedProcess parent;
            if(ProcessManager::inspect(p.parent,&parent,false)) {
                std::lock_guard<std::mutex> lock(target_mutex_);
                const auto it=targets_.find(parent.pid);
                match=it!=targets_.end() && it->second==parent.starttime && p.starttime>=parent.starttime;
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
    void acquire(const MemorySyscallEvent& event,double received) {
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
            int value=-1;bool attempted=false;
            ~MemoryFd() {if(value>=0)::close(value);}
        } memory_fd;
        auto read=[&](uintptr_t address,uint8_t* bytes,size_t count)->size_t {
            iovec local{bytes,count},remote{reinterpret_cast<void*>(address),count};
            ssize_t n=::process_vm_readv(event.pid,&local,1,&remote,1,0);
            if(n<=0 && !memory_fd.attempted) {
                memory_fd.attempted=true;
                memory_fd.value=::open(("/proc/"+std::to_string(event.pid)+"/mem").c_str(),O_RDONLY|O_CLOEXEC);
            }
            if(n<=0 && memory_fd.value>=0)n=::pread(memory_fd.value,bytes,count,static_cast<off_t>(address));
            return n>0?static_cast<size_t>(n):0;
        };
        ArtRefillService::Read linked_read=[&](uintptr_t address,void* bytes,size_t count) {
            return generation(event.pid,event.starttime) &&
                read(address,static_cast<uint8_t*>(bytes),count)==count;
        };
        auto links=refill_.prepare(event,linked_read);
        const double anchors_done=now();
        FastObservation buffers;
        if(CaptureTuning::pool_slots) {
            buffers=std::move(collector_spare_);
            if(buffers.first.capacity()<4096)buffers=buffer_pool_.take();
        }
        const size_t needed=std::min(cap_,size_t(event.end-event.address));
        if(buffers.first.capacity()>=needed && buffers.second.capacity()>=needed)++buffer_hits_;else ++buffer_misses_;
        auto observation=FastObservation::capture_reusing(std::move(buffers),event.address,event.end-event.address,cap_,read,
            [&]{return generation(event.pid,event.starttime);},[]{return now();});
        refill_.finish(links,linked_read);
        auto keep_spare=[&] {
            if(CaptureTuning::pool_slots && observation.first.capacity()<=4096 && observation.second.capacity()<=4096 && observation.pages.capacity()<=1)
                collector_spare_=std::move(observation);
        };
        if(!observation.generation_valid) {++rejected_;keep_spare();return;}
        if(!observation.read_bytes(0) && !observation.read_bytes(1)) {++unreadable_;keep_spare();return;}
        Snapshot s;s.event=event;s.observation=std::move(observation);s.sequence=++sequence_;s.links=std::move(links);
        s.line_received=received;s.acquire_begin=stamp;s.anchors_done=anchors_done;s.acquire_end=now();
        {std::unique_lock<std::mutex> lock(mutex_,std::defer_lock);
            if(!lock.try_lock()) {++handoff_contended_;lock.lock();}
            if(publisher_failed_ || stopping_ || !schedule_.admit(s.bytes())) {++queue_drops_;return;}
            schedule_.retain(s.bytes());queue_.push_back(std::move(s));}
        ready_.notify_one();
    }
    bool publish_one(const std::string& dir,Snapshot& s) {
        const auto& o=s.observation;const auto& e=s.event;
        char name[192];std::snprintf(name,sizeof(name),"%s_%d_%llx_%llx_%d_%llu_%llu",s.merge_only?"fast_merge_flush":"fast",e.pid,ull(e.starttime),
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
        std::fprintf(f,"],\"publication_begin_boot\":%.9f,\"queue_wait_ms\":%.3f,\"publication_worker\":true,"
            "\"line_received_boot\":%.9f,\"acquire_begin_boot\":%.9f,\"anchors_done_boot\":%.9f,\"acquire_end_boot\":%.9f}\n",
            publication_begin,1000*(publication_begin-o.end),s.line_received,s.acquire_begin,s.anchors_done,s.acquire_end);
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
    alignas(64) std::mutex mutex_;
    alignas(64) std::mutex target_mutex_;
    std::unordered_map<int,uint64_t> targets_;
    FastBufferPool buffer_pool_;FastObservation collector_spare_;
    CaptureCoordination coordination_;CaptureCoordination::Background scan_background_,publication_background_;
    uint64_t buffer_hits_=0,buffer_misses_=0,handoff_contended_=0;int publisher_nice_=20,publisher_nice_end_=20;
    int publisher_base_nice_=20,publisher_current_nice_=20;bool priority_failed_=false;
    uint64_t priority_changes_=0,priority_failures_=0;
    std::deque<Snapshot> queue_;size_t budget_bytes_=0;double budget_epoch_=0;
    FastSchedule schedule_;std::condition_variable ready_;std::thread publisher_;std::string output_dir_;
    bool stopping_=false,publisher_started_=false;std::atomic<bool> publisher_failed_{false};
    uint64_t retry_attempts_=0,retry_exhausted_=0;double queue_wait_max_ms_=0;
    uint64_t merge_flush_sequence_=0,merge_flush_jobs_=0;
    uint64_t sequence_=0,published_=0,published_bytes_=0,dex_observations_=0,disk_drops_=0,write_failures_=0;
    size_t last_written_=0;
    ArtRefillService refill_;
    std::atomic<uint64_t> observed_{0},queue_drops_{0},budget_drops_{0},rejected_{0},unreadable_{0},early_losses_{0};
};
