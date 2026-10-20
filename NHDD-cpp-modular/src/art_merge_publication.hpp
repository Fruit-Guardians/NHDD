// Generation-scoped aggregate publication, separate from single-event artifacts.
#pragma once
#include "art_method_merge.hpp"
#include "nhdd_scanner.hpp"

class ArtMergePublication {
public:
    enum class Status {Idle,Published,Conflict,Incompatible,Budget,Invalid,WriteFailed};
    struct Result {Status status=Status::Idle;size_t bytes=0;};
    template<class Read,class Guard>
    static Result publish(const ArtRefillBaseline& b,ArtMethodMerge& merge,const std::string& stem,
                          Read read,Guard guard,size_t output_budget,uint64_t& verification_budget,double now) {
        if(!merge.dirty() || (!merge.conflicted && merge.methods.size()<2))return {};
        size_t reserve=4096;
        for(const auto& m:merge.methods)for(const auto& v:m.variants)reserve+=v.source.refill.size()+1024;
        if(!merge.conflicted)reserve+=3*b.raw.size();
        if(reserve>output_budget)return {Status::Budget,0};
        if(!guard())return {Status::Incompatible,0};
        const double verify_begin=boot();
        if(!merge.conflicted) {
            if(2*b.raw.size()>verification_budget)return {Status::Budget,0};
            verification_budget-=2*b.raw.size();
            if(!merge.compatible(b,read,guard))return {Status::Incompatible,0};
        }
        const double verify_end=boot();
        auto raw=merge.materialize(b),fixed=ArtRefill::normalize(raw);
        auto report=DexSemantics::validate(fixed.data(),fixed.size());
        if(!merge.conflicted && !report.valid)return {Status::Invalid,0};
        std::vector<ArtifactTransactionEntryInline> entries;size_t bytes=0;
        auto stage=[&](const std::string& path,const std::vector<uint8_t>& data) {
            const auto temp=artifact_sidecar_path_inline(path.c_str(),"tmp");
            if(!write_staged_bytes_inline(temp.c_str(),data.data(),data.size()))return false;
            entries.emplace_back(path.c_str(),temp.c_str());bytes+=data.size();return true;
        };
        bool ok=true;
        if(!merge.conflicted)ok=stage(stem+".merged.baseline.raw.dex",b.raw) &&
            stage(stem+".merged.raw.dex",raw) && stage(stem+".merged.fixed.dex",fixed);
        const auto meta=stem+(merge.conflicted?".merge-conflict.json":".merge.json");
        const auto temp=artifact_sidecar_path_inline(meta.c_str(),"tmp");
        FILE* f=ok?std::fopen(temp.c_str(),"w"):nullptr;
        if(f) {
            std::fprintf(f,"{\"schema\":\"nhdd-art-method-merge-v1\",\"status\":\"%s\","
                "\"pid\":%u,\"process_start_time_ticks\":%llu,\"dex_address\":\"0x%llx\",\"dex_size\":%zu,"
                "\"art_object\":\"0x%llx\",\"art_vtable\":\"0x%llx\",\"libdexfile_build_id\":\"%s\","
                "\"baseline_revision\":%llu,\"baseline_content_hash\":\"%016llx\",\"baseline_armed_boot\":%.9f,"
                "\"merge_revision\":%llu,\"previous_published_revision\":%llu,\"method_count\":%zu,"
                "\"atomic_snapshot\":false,\"temporal_composite\":true,\"plaintext_proven\":false,"
                "\"cross_event_patch_accumulation\":true,\"conflict_policy\":\"freeze_generation_no_winner\","
                "\"supersedes_all_prior_revisions\":%s,\"conflicted\":%s,\"observation_verified_boot\":%.9f,"
                "\"verification_begin_boot\":%.9f,\"verification_end_boot\":%.9f,\"complement_passes\":%u,"
                "\"backing_revalidated\":true,\"mapping_aba_excluded\":false,"
                "\"observed_mapping_or_trace_loss_invalidates\":true,\"session\":",
                merge.conflicted?"conflict_generation_frozen":"cross_window_method_composite",
                b.identity.pid,ull(b.identity.process_start_time),ull(b.identity.address),b.raw.size(),ull(b.object),ull(b.vtable),
                b.build_id.c_str(),ull(b.revision),ull(b.hash),b.armed_boot,ull(merge.revision),ull(merge.published_revision),
                merge.methods.size(),merge.conflicted?"true":"false",merge.conflicted?"true":"false",now,
                verify_begin,verify_end,merge.conflicted?0u:2u);
            string(f,merge.session);std::fputs(",\"methods\":[",f);
            for(size_t i=0;i<merge.methods.size();++i) {
                const auto& m=merge.methods[i];
                std::fprintf(f,"%s{\"method_index\":%u,\"code_offset\":%u,\"offset\":%u,\"length\":%u,\"conflict\":%s,\"variants\":[",
                    i?",":"",m.layout.method_index,m.layout.code_offset,m.layout.instructions_offset,m.layout.bytes,
                    m.variants.size()>1?"true":"false");
                for(size_t j=0;j<m.variants.size();++j) {
                    const auto& v=m.variants[j];
                    std::fprintf(f,"%s{\"sha1\":\"%s\",\"observations_at_revision\":%llu,\"source\":",
                        j?",":"",ArtMethodMerge::digest(v.bytes).c_str(),ull(v.observations));string(f,v.source.refill);
                    std::fprintf(f,",\"capture_begin_boot\":%.9f,\"capture_end_boot\":%.9f,\"verified_boot\":%.9f}",
                        v.source.capture_begin,v.source.capture_end,v.source.verified);
                }
                std::fputs("]}",f);
            }
            std::fputs("],\"artifacts\":",f);
            if(merge.conflicted)std::fputs("null",f);
            else {
                std::fputs("{\"baseline\":",f);string(f,name(stem)+".merged.baseline.raw.dex");
                std::fputs(",\"raw\":",f);string(f,name(stem)+".merged.raw.dex");
                std::fputs(",\"fixed\":",f);string(f,name(stem)+".merged.fixed.dex");std::fputc('}',f);
                std::fputs(",\"header_magic_version_synthesized\":",f);
                std::fputs(ArtRefill::magic_version_valid(raw)?"false":"true",f);
                std::fputs(",\"semantic_raw\":",f);DexSemantics::validate(raw.data(),raw.size()).write_json(f);
                std::fputs(",\"semantic_fixed\":",f);report.write_json(f);
            }
            std::fputs("}\n",f);const long n=std::ftell(f);if(n>0)bytes+=static_cast<size_t>(n);
            ok=std::fflush(f)==0 && ::fsync(::fileno(f))==0;if(std::fclose(f))ok=false;
            entries.emplace_back(meta.c_str(),temp.c_str());
        } else ok=false;
        struct Context {Guard* guard;};Context context{&guard};
        auto check=[](void* p){return (*static_cast<Context*>(p)->guard)();};
        if(ok && bytes<=output_budget && artifact_publish_transaction_inline(&entries,check,&context)) {
            merge.published_revision=merge.revision;
            std::fprintf(stderr,"[ART-MERGE] %s %s revision=%llu methods=%zu\n",merge.conflicted?"conflict":"published",
                meta.c_str(),ull(merge.revision),merge.methods.size());
            return {merge.conflicted?Status::Conflict:Status::Published,bytes};
        }
        artifact_cleanup_temporaries_inline(entries);return {Status::WriteFailed,0};
    }
    static std::string name(const std::string& path){return path.substr(path.find_last_of("/\\")+1);}
private:
    static double boot(){timespec t{};::clock_gettime(CLOCK_BOOTTIME,&t);return double(t.tv_sec)+double(t.tv_nsec)*1e-9;}
    static unsigned long long ull(uint64_t n){return static_cast<unsigned long long>(n);}
    static void string(FILE* f,const std::string& s) {
        std::fputc('"',f);for(unsigned char c:s) {
            if(c=='"' || c=='\\') {std::fputc('\\',f);std::fputc(c,f);}
            else if(c<32)std::fprintf(f,"\\u%04x",unsigned(c));else std::fputc(c,f);
        }std::fputc('"',f);
    }
};
