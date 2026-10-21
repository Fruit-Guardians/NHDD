#include <cassert>
#include <cstdio>
#include <string>
#include <algorithm>
#include "../src/process_stat.hpp"

static std::string fixture(const std::string& ticks="456",const std::string& parent="7") {
    std::string text="123 (a ) spaced name) S "+parent;
    for(int i=5;i<22;++i)text+=" 0";
    return text+" "+ticks+" 999 888\n";
}
int main() {
    ProcessStatFields value;const auto text=fixture();
    assert(ProcessStat::parse(text.c_str(),&value));
    assert(value.pid==123 && value.parent==7 && value.starttime==456);
    assert(ProcessStat::parse(fixture("18446744073709551615").c_str(),&value) && value.starttime==UINT64_MAX);
    for(const auto& malformed:{fixture("18446744073709551616"),fixture("-1"),fixture("+1"),fixture("12x"),
            fixture("456","2147483648"),fixture("456","-1"),std::string("123 (bad) S 7\n"),
            std::string("-1 (a) S 7 0\n"),std::string("123 no-parens S 7 0\n")}) {
        value.starttime=71;assert(!ProcessStat::parse(malformed.c_str(),&value) && value.starttime==71);
    }
    assert(!ProcessStat::parse(nullptr,&value) && !ProcessStat::parse(text.c_str(),nullptr));
    int leader=77;
    assert(ProcessStat::parse_tgid("Name:\tfixture\nTgid:\t123\nPid:\t124\n",&leader) && leader==123);
    for(const char* bad:{"Tgid: 0\n","Tgid: -1\n","Tgid: 2147483648\n","Tgid: 123x\n","Tgid: 123","XTgid: 123\n"}) {
        leader=77;assert(!ProcessStat::parse_tgid(bad,&leader) && leader==77);
    }
    char bytes[4096];size_t offset=0;bool interrupted=false;
    auto reader=[&](char* out,size_t n)->ssize_t {
        if(!interrupted){interrupted=true;errno=EINTR;return -1;}
        const size_t got=std::min({n,size_t(3),text.size()-offset});
        std::memcpy(out,text.data()+offset,got);offset+=got;return static_cast<ssize_t>(got);
    };
    assert(ProcessStat::line(reader,bytes,sizeof(bytes)) && ProcessStat::parse(bytes,&value));
    assert(value.starttime==456 && offset==text.size());
    assert(!ProcessStat::line([](char*,size_t)->ssize_t{errno=EIO;return -1;},bytes,sizeof(bytes)) && errno==EIO);
    assert(!ProcessStat::line([](char*,size_t)->ssize_t{return 0;},bytes,sizeof(bytes)));
    assert(!ProcessStat::line([](char* p,size_t n)->ssize_t{std::memset(p,'x',n);return static_cast<ssize_t>(n);},bytes,8) && errno==EOVERFLOW);
    assert(!ProcessStat::line([](char* p,size_t)->ssize_t{p[0]='x';p[1]=0;return 2;},bytes,sizeof(bytes)) && errno==EPROTO);
    offset=0;const std::string eof="123 (x) S 7";
    assert(ProcessStat::line([&](char* p,size_t)->ssize_t {
        if(offset)return 0;std::memcpy(p,eof.data(),eof.size());offset=eof.size();return static_cast<ssize_t>(offset);
    },bytes,sizeof(bytes)));
    assert(!ProcessStat::parse(bytes,&value));
    uint64_t unchanged=77;assert(!ProcessStat::starttime(nullptr,&unchanged) && unchanged==77);
    assert(!ProcessStat::starttime("../self",&unchanged) && unchanged==77);
#if defined(__linux__)
    char pid[32];std::snprintf(pid,sizeof(pid),"%d",::getpid());
    assert(ProcessStat::read(pid,&value) && value.pid==::getpid() && value.parent==::getppid());
    const auto expected=value.starttime;
    for(unsigned i=0;i<100;++i){assert(ProcessStat::read(pid,&value));assert(value.starttime==expected);}
    assert(ProcessStat::tgid(static_cast<int>(::getpid()),&leader) && leader==::getpid());
#endif
    std::puts("process_stat_test: OK (strict identity/overflow/comm/short reads/EINTR/errors/truncation/fresh reads)");
}
