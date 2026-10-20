// Android logic/integration test: deterministic budget and transaction failures.
#include <cassert>
#include "../src/art_merge_publication.hpp"

int main(int argc,char** argv) {
    assert(argc==2);FILE* input=std::fopen(argv[1],"rb");assert(input);
    assert(!std::fseek(input,0,SEEK_END));const long n=std::ftell(input);assert(n>112);std::rewind(input);
    ArtRefillBaseline b;b.raw.resize(static_cast<size_t>(n));
    assert(std::fread(b.raw.data(),1,b.raw.size(),input)==b.raw.size());std::fclose(input);
    b.identity.pid=42;b.identity.process_start_time=100;b.identity.address=0x10000;
    b.identity.dex_size=static_cast<uint32_t>(n);b.armed_boot=1;
    assert(ArtRefill::layout(b));const auto golden=b.raw;
    std::vector<DexMethodCode> selected;
    for(const auto& m:b.methods)if(m.instructions_offset>=8192 && m.bytes>=6 &&
        (selected.empty() || selected.back().instructions_offset/4096!=m.instructions_offset/4096)) {
        selected.push_back(m);if(selected.size()==3)break;
    }
    assert(selected.size()==3);std::memset(b.raw.data(),0,44);
    for(const auto& m:selected)std::memset(b.raw.data()+m.instructions_offset,0,m.bytes);
    ArtMethodMerge merge(b);merge.session="publication-test";auto memory=b.raw;
    auto read=[&](uintptr_t a,void* out,size_t size) {
        if(a<b.identity.address || a-b.identity.address>memory.size() || size>memory.size()-(a-b.identity.address))return false;
        std::memcpy(out,memory.data()+a-b.identity.address,size);return true;
    };
    auto accept=[&](size_t index,bool alternate=false) {
        const auto& m=selected[index];memory=b.raw;
        std::memcpy(memory.data()+m.instructions_offset,golden.data()+m.instructions_offset,m.bytes);
        if(alternate)memory[m.instructions_offset+m.bytes-3]^=1;
        auto reader=[&](uintptr_t a,uint8_t* out,size_t size)->size_t{return read(a,out,size)?size:0;};
        const auto o=FastObservation::capture(b.identity.address+m.instructions_offset,m.bytes,m.bytes,reader,[]{return true;},[]{return 2.;});
        const auto plan=ArtRefill::plan(b,o,42,100,true);assert(plan.accepted());
        return merge.accept(b,o,plan,{"source"+std::to_string(index)+(alternate?"-alternate":"")+".refill.json",2,2,3});
    };
    char directory[]="/data/local/tmp/nhdd-merge-publication-XXXXXX";assert(::mkdtemp(directory));
    const std::string stem=std::string(directory)+"/test";
    using Status=ArtMergePublication::Status;uint64_t budget=64u*1024*1024;
    assert(accept(0)==ArtMethodMerge::Result::Added);
    assert(ArtMergePublication::publish(b,merge,stem,read,[]{return true;},SIZE_MAX,budget,3).status==Status::Idle);
    assert(accept(1)==ArtMethodMerge::Result::Added);memory=b.raw;
    assert(ArtMergePublication::publish(b,merge,stem,read,[]{return true;},0,budget,3).status==Status::Budget);
    uint64_t tiny=1;
    assert(ArtMergePublication::publish(b,merge,stem,read,[]{return true;},SIZE_MAX,tiny,3).status==Status::Budget);
    assert(ArtMergePublication::publish(b,merge,stem,read,[]{return false;},SIZE_MAX,budget,3).status==Status::Incompatible);
    assert(merge.published_revision==0 && merge.dirty());
    assert(ArtMergePublication::publish(b,merge,stem,read,[]{return true;},SIZE_MAX,budget,3).status==Status::Published);
    assert(merge.published_revision==2 && !merge.dirty());
    assert(accept(2)==ArtMethodMerge::Result::Added);memory=b.raw;
    assert(ArtMergePublication::publish(b,merge,stem+"/missing",read,[]{return true;},SIZE_MAX,budget,3).status==Status::WriteFailed);
    unsigned guards=0;
    assert(ArtMergePublication::publish(b,merge,stem+"-rollback",read,[&]{return ++guards<7;},SIZE_MAX,budget,3).status==Status::WriteFailed);
    assert(!artifact_file_exists_inline((stem+"-rollback.merged.baseline.raw.dex").c_str()));
    assert(!artifact_file_exists_inline((stem+"-rollback.merge.json").c_str()));
    assert(merge.published_revision==2 && merge.dirty());
    assert(ArtMergePublication::publish(b,merge,stem+"-retry",read,[]{return true;},SIZE_MAX,budget,3).status==Status::Published);
    assert(merge.published_revision==3 && !merge.dirty());
    assert(ArtMergePublication::publish(b,merge,stem+"-duplicate",read,[]{return true;},SIZE_MAX,budget,3).status==Status::Idle);
    assert(accept(0,true)==ArtMethodMerge::Result::Conflict);memory=b.raw;
    assert(merge.materialize(b).empty());
    assert(ArtMergePublication::publish(b,merge,stem+"-conflict",read,[]{return true;},0,budget,3).status==Status::Budget);
    assert(merge.dirty() && merge.published_revision==3);
    assert(ArtMergePublication::publish(b,merge,stem+"-conflict",read,[]{return true;},SIZE_MAX,budget,3).status==Status::Conflict);
    assert(!artifact_file_exists_inline((stem+"-conflict.merged.raw.dex").c_str()));
    assert(artifact_file_exists_inline((stem+"-conflict.merge-conflict.json").c_str()));
    assert(merge.published_revision==4 && !merge.dirty());
    std::printf("art_merge_publication_test: OK (budget/failure/rollback/retry/conflict/no winner) evidence=%s\n",directory);
}
