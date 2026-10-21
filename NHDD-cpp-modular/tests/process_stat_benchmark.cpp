// Android-only, read-only self identity microbenchmark. All passes reopen stat.
#include <cassert>
#include <chrono>
#include <sstream>
#include <string>
#include "../src/process_stat.hpp"
static uint64_t legacy(const char* pid) {
    char path[128],line[4096];std::snprintf(path,sizeof(path),"/proc/%s/stat",pid);
    FILE* f=std::fopen(path,"r");assert(f);assert(std::fgets(line,sizeof(line),f));assert(!std::fclose(f));
    const char* paren=std::strrchr(line,')');assert(paren);
    std::istringstream stream(paren+2);std::string token;
    for(int field=3;field<=22;++field){assert(bool(stream>>token));if(field==22)return std::stoull(token);}
    return 0;
}
int main() {
    char pid[32];std::snprintf(pid,sizeof(pid),"%d",::getpid());uint64_t expected=0;
    assert(ProcessStat::starttime(pid,&expected) && expected==legacy(pid));
    for(bool stack:{false,true,true,false}) {
        const auto begin=std::chrono::steady_clock::now();
        for(unsigned i=0;i<5000;++i) {
            uint64_t actual=0;
            if(stack){assert(ProcessStat::starttime(pid,&actual));}else actual=legacy(pid);
            assert(actual==expected);
        }
        const auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-begin).count();
        std::printf("STAT_BENCH stack=%u fresh_reads=5000 elapsed_us=%lld\n",stack?1u:0u,static_cast<long long>(us));
    }
}
