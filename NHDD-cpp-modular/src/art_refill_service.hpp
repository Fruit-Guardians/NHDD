// ART candidate registry shared with the collector; publication stays on main.
#pragma once
#include <mutex>
#include <functional>
#include "art_refill.hpp"
#include "syscall_events.hpp"
#include "nhdd_scanner.hpp"

class ArtRefillService {
public:
    struct Link {
        std::shared_ptr<ArtRefillBaseline> baseline;
        bool before=false,after=false;
    };
    using Read=std::function<bool(uintptr_t,void*,size_t)>;
    explicit ArtRefillService(bool enabled=true):enabled_(enabled),budget_(std::make_shared<ArtRefillBudget>()) {}
    void arm(const DexCapture& capture,const MapsRegion* maps,size_t count,const Read& read) {
        if(!enabled_ || !capture.art_object() || !capture.complete())return;
        if(capture.size()>16u*1024*1024) {++arm_rejected_;return;}
        const auto hash=artifact_hash_inline(capture.data(),capture.size());
        std::shared_ptr<ArtRefillBaseline> existing;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for(const auto& b:baselines_)if(b->active && b->identity.pid==capture.identity().pid &&
                b->identity.address==capture.identity().address) {existing=b;break;}
        }
        if(existing) {
            const auto& old=existing->identity;const auto& id=capture.identity();
            // Pin the first baseline for this ART object/structural generation.
            // Ordinary live refresh can see plaintext and then ciphertext again;
            // rebasing on those body revisions would turn erasure into a "repair".
            if(old.process_start_time==id.process_start_time && old.dex_size==id.dex_size &&
                old.header_fingerprint==id.header_fingerprint && existing->object==capture.art_object() &&
                existing->vtable==capture.art_vtable() && ArtRefill::backing_matches(*existing,maps,count) &&
                anchors(*existing,read))return;
            existing->active=false;
        }
        const size_t charge=capture.size()+4096*sizeof(DexMethodCode)+128*sizeof(MapsRegion)+sizeof(ArtRefillBaseline);
        auto b=std::make_shared<ArtRefillBaseline>();
        size_t used=budget_->bytes.load();
        do {if(charge>64u*1024*1024-used) {++arm_rejected_;return;}}
        while(!budget_->bytes.compare_exchange_weak(used,used+charge));
        b->budget=budget_;b->charge=charge;
        b->identity=capture.identity();b->object=capture.art_object();b->vtable=capture.art_vtable();
        b->build_id=capture.art_build_id();b->hash=hash;b->raw.assign(capture.data(),capture.data()+capture.size());
        if(!ArtRefill::layout(*b)) {++arm_rejected_;return;}
        ArtDexCandidate current;
        if(b->build_id!=ArtDexDiscovery::kBuildId ||
            !ArtDexDiscovery::validate(read,maps,count,b->vtable,b->object,current) ||
            current.begin!=b->identity.address || current.size!=b->raw.size() ||
            std::memcmp(current.header.data(),b->raw.data(),112) ||
            !read(b->object,b->object_bytes.data(),128) || !read(b->vtable,b->vtable_bytes.data(),16)) {++arm_rejected_;return;}
        auto add=[&](uintptr_t address,size_t length) {
            if(length>UINTPTR_MAX-address)return false;
            const uintptr_t end=address+length;
            while(address<end) {
                const auto* m=ArtDexDiscovery::region(maps,count,address);
                if(!m || !m->readable || b->mappings.size()>=128)return false;
                auto part=*m;part.start=address;part.end=std::min(end,m->end);
                if(m->inode)part.offset+=address-m->start;
                b->mappings.push_back(part);address=part.end;
            }
            return true;
        };
        if(!add(b->identity.address,b->raw.size()) || !add(b->object,128)) {++arm_rejected_;return;}
        for(size_t i=0;i<count;++i)if(maps[i].readable && ArtDexDiscovery::library(maps[i])) {
            if(b->mappings.size()>=128) {++arm_rejected_;return;}
            b->mappings.push_back(maps[i]);
        }
        if(!anchors(*b,read)) {++arm_rejected_;return;}
        std::lock_guard<std::mutex> lock(mutex_);
        baselines_.erase(std::remove_if(baselines_.begin(),baselines_.end(),[&](const auto& old) {
            const auto pid=std::to_string(old->identity.pid);
            if(read_process_start_time_inline(pid.c_str())!=old->identity.process_start_time)old->active=false;
            return !old->active || (old->identity.pid==b->identity.pid && old->identity.address==b->identity.address);
        }),baselines_.end());
        if(baselines_.size()>=32) {++arm_rejected_;return;}
        b->revision=++revision_;b->armed_boot=boot();baselines_.push_back(b);++armed_;
        std::fprintf(stderr,"[ART-REFILL] armed pid=%u address=0x%llx baseline=%llu methods=%zu size=%zu\n",
            b->identity.pid,ull(b->identity.address),ull(b->revision),b->methods.size(),b->raw.size());
    }
    void invalidate_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        for(const auto& b:baselines_)b->active=false;
        ++trace_invalidations_;
    }
    void event(const MemorySyscallEvent& e) {
        if(!enabled_ || (e.operation!="mmap" && e.operation!="munmap" && e.operation!="mremap"))return;
        std::lock_guard<std::mutex> lock(mutex_);
        for(const auto& b:baselines_) {
            if(!b->active || b->identity.pid!=static_cast<uint32_t>(e.pid) ||
                b->identity.process_start_time!=e.starttime || e.boot_seconds<b->armed_boot)continue;
            for(const auto& m:b->mappings)if((m.start<e.end && e.address<m.end) ||
                (e.old_end>e.old_address && m.start<e.old_end && e.old_address<m.end)) {
                b->active=false;++mapping_invalidations_;break;
            }
        }
    }
    std::vector<Link> prepare(const MemorySyscallEvent& e,const Read& read) {
        std::vector<Link> links;
        if(!enabled_ || e.operation!="mprotect")return links;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for(const auto& b:baselines_)if(b->active && b->identity.pid==static_cast<uint32_t>(e.pid) &&
                b->identity.process_start_time==e.starttime && e.boot_seconds>=b->armed_boot &&
                b->identity.address<e.end && e.address<b->identity.address+b->raw.size())links.push_back({b,false,false});
        }
        if(links.size()>4) {++link_limit_;return {};}
        for(auto& link:links)link.before=anchors(*link.baseline,read);
        return links;
    }
    void finish(std::vector<Link>& links,const Read& read) {
        for(auto& link:links)link.after=anchors(*link.baseline,read);
    }
    void begin_batch() {verification_budget_=64u*1024*1024;}
    size_t publish(const std::string& source_stem,const MemorySyscallEvent& e,const FastObservation& o,
                   const std::vector<Link>& links,size_t output_budget) {
        size_t written=0;
        for(size_t i=0;i<links.size();++i) {
            const auto& link=links[i];const auto& b=*link.baseline;
            const auto stem=source_stem+"_art"+std::to_string(i);
            auto plan=ArtRefill::plan(b,o,static_cast<uint32_t>(e.pid),e.starttime,link.before && link.after);
            if(!plan.accepted()) {
                ++rejected_;
                if(plan.reason!="no_complete_changed_method") {
                    if(written<=output_budget && output_budget-written>=1024)
                        written+=record_rejection(stem,b,o,plan.reason.c_str());
                    else ++output_drops_;
                }
                continue;
            }
            const size_t reserve=3*b.raw.size()+1024*1024;
            if(written>output_budget || reserve>output_budget-written) {++output_drops_;continue;}
            if(2*b.raw.size()>verification_budget_) {++verification_drops_;continue;}
            verification_budget_-=2*b.raw.size();
            const int fd=::open(("/proc/"+std::to_string(e.pid)+"/mem").c_str(),O_RDONLY|O_CLOEXEC);
            struct Close {int fd;~Close(){if(fd>=0)::close(fd);}} close{fd};
            Read read=[&](uintptr_t address,void* p,size_t n) {
                return read_remote_retry_inline(fd,e.pid,p,n,address,fd<0)==static_cast<ssize_t>(n);
            };
            auto guard=[&] {return identity_now(b,read);};
            const double check_begin=boot();
            if(!ArtRefill::complement(b,plan,read,guard)) {
                ++rejected_;written+=record_rejection(stem,b,o,"live_complement_or_identity_changed");continue;
            }
            auto raw=ArtRefill::materialize(b,o,plan),fixed=ArtRefill::normalize(raw);
            auto report=DexSemantics::validate(fixed.data(),fixed.size());
            if(!report.valid) {++rejected_;written+=record_rejection(stem,b,o,"refilled_structure_invalid");continue;}
            std::vector<ArtifactTransactionEntryInline> files;
            size_t bytes=0;
            auto stage=[&](const std::string& path,const std::vector<uint8_t>& data) {
                const auto temp=artifact_sidecar_path_inline(path.c_str(),"tmp");
                if(!write_staged_bytes_inline(temp.c_str(),data.data(),data.size()))return false;
                files.emplace_back(path.c_str(),temp.c_str());bytes+=data.size();return true;
            };
            bool ok=stage(stem+".baseline.raw.dex",b.raw) && stage(stem+".refilled.raw.dex",raw) &&
                stage(stem+".refilled.fixed.dex",fixed);
            const auto meta=stem+".refill.json",temp=artifact_sidecar_path_inline(meta.c_str(),"tmp");
            FILE* f=ok?std::fopen(temp.c_str(),"w"):nullptr;
            if(f) {
                std::fprintf(f,"{\"schema\":\"nhdd-art-refill-v1\",\"status\":\"reconstructed_method_composite\","
                    "\"pid\":%u,\"process_start_time_ticks\":%llu,\"dex_address\":\"0x%llx\",\"dex_size\":%zu,"
                    "\"art_object\":\"0x%llx\",\"art_vtable\":\"0x%llx\",\"libdexfile_build_id\":\"%s\","
                    "\"baseline_revision\":%llu,\"baseline_content_hash\":\"%016llx\",\"baseline_armed_boot\":%.9f,"
                    "\"capture_begin_boot\":%.9f,\"capture_end_boot\":%.9f,\"verification_begin_boot\":%.9f,"
                    "\"verification_end_boot\":%.9f,\"atomic_snapshot\":false,\"temporal_composite\":true,"
                    "\"plaintext_proven\":false,\"cross_event_patch_accumulation\":false,\"capture_anchors_match\":true,"
                    "\"method_double_read\":\"match\",\"complement_passes\":2,\"backing_revalidated\":true,"
                    "\"observed_mapping_or_trace_loss_invalidates\":true,\"mapping_aba_excluded\":false,"
                    "\"header_magic_version_synthesized\":%s,\"changed_instruction_bytes\":%zu,\"patches\":[",
                    b.identity.pid,ull(b.identity.process_start_time),ull(b.identity.address),b.raw.size(),ull(b.object),ull(b.vtable),
                    b.build_id.c_str(),ull(b.revision),ull(b.hash),b.armed_boot,o.begin,o.end,check_begin,boot(),
                    ArtRefill::magic_version_valid(raw)?"false":"true",plan.changed_bytes);
                for(size_t p=0;p<plan.patches.size();++p) {
                    const auto& m=plan.patches[p];std::fprintf(f,"%s{\"method_index\":%u,\"code_offset\":%u,"
                        "\"offset\":%u,\"length\":%u}",p?",":"",m.method_index,m.code_offset,m.instructions_offset,m.bytes);
                }
                const auto name=[](const std::string& path){return path.substr(path.find_last_of('/')+1);};
                const auto short_stem=name(stem),source=name(source_stem);
                std::fprintf(f,"],\"artifacts\":{\"source\":\"%s.json\",\"baseline\":\"%s.baseline.raw.dex\","
                    "\"raw\":\"%s.refilled.raw.dex\",\"fixed\":\"%s.refilled.fixed.dex\"},\"semantic_raw\":",
                    source.c_str(),short_stem.c_str(),short_stem.c_str(),short_stem.c_str());
                DexSemantics::validate(raw.data(),raw.size()).write_json(f);
                std::fputs(",\"semantic_fixed\":",f);report.write_json(f);std::fputs("}\n",f);
                const long n=std::ftell(f);if(n>0)bytes+=static_cast<size_t>(n);
                ok=std::fflush(f)==0 && ::fsync(::fileno(f))==0;if(std::fclose(f))ok=false;
                files.emplace_back(meta.c_str(),temp.c_str());
            } else ok=false;
            struct Context {const ArtRefillBaseline* b;const Read* read;};Context context{&b,&read};
            auto publish_guard=[](void* p) {const auto& c=*static_cast<Context*>(p);return identity_now(*c.b,*c.read);};
            if(ok && artifact_publish_transaction_inline(&files,publish_guard,&context)) {
                written+=bytes;++published_;
                std::fprintf(stderr,"[ART-REFILL] published %s methods=%zu changed=%zu (temporal composite, not atomic)\n",
                    meta.c_str(),plan.patches.size(),plan.changed_bytes);
            } else {
                artifact_cleanup_temporaries_inline(files);
                if(!guard()) {++rejected_;written+=record_rejection(stem,b,o,"publication_identity_changed");}
                else ++write_failures_;
            }
        }
        return written;
    }
    void diagnostics() const {
        std::fprintf(stderr,"[*] ART refill: armed=%llu arm_rejected=%llu published=%llu rejected=%llu "
            "mapping_invalidations=%llu trace_invalidations=%llu link_limit=%llu verification_drops=%llu "
            "output_drops=%llu write_failures=%llu retained_baseline_bytes=%zu\n",ull(armed_),ull(arm_rejected_),
            ull(published_),ull(rejected_),ull(mapping_invalidations_),ull(trace_invalidations_),ull(link_limit_),
            ull(verification_drops_),ull(output_drops_),ull(write_failures_),budget_->bytes.load());
    }
private:
    static unsigned long long ull(uint64_t n){return static_cast<unsigned long long>(n);}
    static double boot(){timespec t{};::clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;}
    static bool anchors(const ArtRefillBaseline& b,const Read& read) {
        uint8_t object[128],header[112],vtable[16];
        return b.active && read(b.object,object,128) && !std::memcmp(object,b.object_bytes.data(),128) &&
            read(b.identity.address,header,112) && !std::memcmp(header,b.raw.data(),112) &&
            read(b.vtable,vtable,16) && !std::memcmp(vtable,b.vtable_bytes.data(),16);
    }
    static bool identity_now(const ArtRefillBaseline& b,const Read& read) {
        const auto pid=std::to_string(b.identity.pid);
        if(!b.active || read_process_start_time_inline(pid.c_str())!=b.identity.process_start_time)return false;
        MapsRegion* maps=nullptr;size_t count=0;
        if(load_maps_inline(pid.c_str(),&maps,&count))return false;
        const auto profile=ArtDexDiscovery::scan(read,maps,count,0,0,[](const ArtDexCandidate&){});
        ArtDexCandidate current;
        const bool ok=ArtRefill::backing_matches(b,maps,count) && profile.supported &&
            profile.build_id==b.build_id && profile.vtable==b.vtable && anchors(b,read) &&
            ArtDexDiscovery::validate(read,maps,count,b.vtable,b.object,current) &&
            current.begin==b.identity.address && current.size==b.raw.size();
        delete[] maps;
        return ok && b.active && read_process_start_time_inline(pid.c_str())==b.identity.process_start_time;
    }
    size_t record_rejection(const std::string& stem,const ArtRefillBaseline& b,const FastObservation& o,const char* reason) {
        const std::string path=stem+".rejected.json";
        char json[512];const int n=std::snprintf(json,sizeof(json),"{\"schema\":\"nhdd-art-refill-v1\","
            "\"status\":\"rejected\",\"reason\":\"%s\",\"baseline_revision\":%llu,\"capture_begin_boot\":%.9f}\n",
            reason,ull(b.revision),o.begin);
        if(n<=0 || static_cast<size_t>(n)>=sizeof(json) ||
            !write_atomic_bytes_inline(path.c_str(),reinterpret_cast<const uint8_t*>(json),static_cast<size_t>(n))) {
            ++write_failures_;return 0;
        }
        return static_cast<size_t>(n);
    }
    bool enabled_;std::shared_ptr<ArtRefillBudget> budget_;
    std::mutex mutex_;std::vector<std::shared_ptr<ArtRefillBaseline>> baselines_;uint64_t revision_=0;
    uint64_t armed_=0,arm_rejected_=0,published_=0,rejected_=0,verification_budget_=0,verification_drops_=0,output_drops_=0,write_failures_=0;
    std::atomic<uint64_t> mapping_invalidations_{0},trace_invalidations_{0},link_limit_{0};
};
