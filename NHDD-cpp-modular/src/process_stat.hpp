// Fresh /proc identity reads without FILE/iostream heap allocation. No FD or
// generation caching: every caller still opens and checks the current process.
#pragma once
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <fcntl.h>
#include <unistd.h>

struct ProcessStatFields {int pid=0,parent=0;uint64_t starttime=0;};
class ProcessStat {
    static bool space(char c) {return c==' ' || c=='\t' || c=='\n' || c=='\r';}
    static bool number(const char* begin,const char* end,uint64_t* result) {
        if(begin==end)return false;
        uint64_t value=0;
        for(auto p=begin;p!=end;++p) {
            if(*p<'0' || *p>'9')return false;
            const unsigned digit=static_cast<unsigned>(*p-'0');
            if(value>(std::numeric_limits<uint64_t>::max()-digit)/10)return false;
            value=value*10+digit;
        }
        *result=value;return true;
    }
public:
    static bool parse(const char* line,ProcessStatFields* out) {
        if(!line || !out){errno=EINVAL;return false;}
        const char* first=std::strchr(line,' ');const char* last=std::strrchr(line,')');
        uint64_t pid=0;
        if(!first || first[1]!='(' || !last || last<=first+1 || last[1]!=' ' ||
            !number(line,first,&pid) || !pid || pid>0x7fffffff){errno=EPROTO;return false;}
        ProcessStatFields value;value.pid=static_cast<int>(pid);const char* p=last+2;
        for(int field=3;field<=22;++field) {
            while(space(*p))++p;
            const char* end=p;while(*end && !space(*end))++end;
            if(end==p){errno=EPROTO;return false;}
            if(field==4 || field==22) {
                uint64_t n=0;
                if(!number(p,end,&n) || (field==4 && n>0x7fffffff)){errno=EPROTO;return false;}
                if(field==4)value.parent=static_cast<int>(n);else value.starttime=n;
            }
            p=end;
        }
        *out=value;return true;
    }
    // Injectable reader for short-read/EINTR/error/truncation tests. Only a
    // complete first line (or bounded EOF-terminated line) may be parsed.
    template<class Reader> static bool line(Reader read,char* bytes,size_t capacity) {
        if(!bytes || capacity<2){errno=EINVAL;return false;}
        size_t used=0;
        while(used<capacity-1) {
            const auto n=read(bytes+used,capacity-1-used);
            if(n<0){if(errno==EINTR)continue;return false;}
            if(!n){bytes[used]=0;if(used)return true;errno=EIO;return false;}
            if(static_cast<size_t>(n)>capacity-1-used){errno=EOVERFLOW;return false;}
            for(size_t i=used;i<used+static_cast<size_t>(n);++i) {
                if(!bytes[i]){errno=EPROTO;return false;}
                if(bytes[i]=='\n'){bytes[i+1]=0;return true;}
            }
            used+=static_cast<size_t>(n);
        }
        errno=EOVERFLOW;return false;
    }
    static bool read(const char* pid,ProcessStatFields* out) {
        if(!pid || !*pid || !out){errno=EINVAL;return false;}
        uint64_t expected=0;
        if(!number(pid,pid+std::strlen(pid),&expected) || !expected || expected>0x7fffffff){errno=EINVAL;return false;}
        char path[128],bytes[4096];
        const int length=std::snprintf(path,sizeof(path),"/proc/%s/stat",pid);
        if(length<0 || static_cast<size_t>(length)>=sizeof(path)){errno=ENAMETOOLONG;return false;}
        int flags=O_RDONLY;
#ifdef O_CLOEXEC
        flags|=O_CLOEXEC;
#endif
        const int fd=::open(path,flags);if(fd<0)return false;
        const bool ok=line([fd](char* p,size_t n){return ::read(fd,p,n);},bytes,sizeof(bytes));
        const int error=errno;const int closed=::close(fd);
        if(!ok){errno=error;return false;}if(closed!=0)return false;
        ProcessStatFields value;
        if(!parse(bytes,&value))return false;
        if(static_cast<uint64_t>(value.pid)!=expected){errno=EPROTO;return false;}
        *out=value;return true;
    }
    static bool starttime(const char* pid,uint64_t* out) {
        if(!out){errno=EINVAL;return false;}ProcessStatFields value;
        if(!read(pid,&value))return false;
        *out=value.starttime;return true;
    }
    static bool parse_tgid(const char* text,int* out) {
        if(!text || !out){errno=EINVAL;return false;}
        for(const char* begin=text;*begin;) {
            const char* end=std::strchr(begin,'\n');if(!end)break;
            if(end-begin>=5 && !std::memcmp(begin,"Tgid:",5)) {
                const char* p=begin+5;while(p<end && space(*p))++p;
                const char* stop=p;while(stop<end && *stop>='0' && *stop<='9')++stop;
                uint64_t value=0;
                if(!number(p,stop,&value) || !value || value>0x7fffffff){errno=EPROTO;return false;}
                for(auto tail=stop;tail<end;++tail)if(!space(*tail)){errno=EPROTO;return false;}
                *out=static_cast<int>(value);return true;
            }
            begin=end+1;
        }
        errno=EPROTO;return false;
    }
    static bool tgid(int tid,int* out) {
        if(tid<=0 || !out){errno=EINVAL;return false;}
        char path[64],bytes[4096];std::snprintf(path,sizeof(path),"/proc/%d/status",tid);
        int flags=O_RDONLY;
#ifdef O_CLOEXEC
        flags|=O_CLOEXEC;
#endif
        const int fd=::open(path,flags);if(fd<0)return false;
        size_t used=0;int value=0;bool ok=false;
        while(used<sizeof(bytes)-1) {
            const auto n=::read(fd,bytes+used,sizeof(bytes)-1-used);
            if(n<0 && errno==EINTR)continue;
            if(n<=0)break;
            if(std::memchr(bytes+used,0,static_cast<size_t>(n))){errno=EPROTO;break;}
            used+=static_cast<size_t>(n);bytes[used]=0;
            if(parse_tgid(bytes,&value)){ok=true;break;}
        }
        const int error=errno;const int closed=::close(fd);
        if(!ok){errno=error?error:EPROTO;return false;}if(closed!=0)return false;
        *out=value;return true;
    }
};
