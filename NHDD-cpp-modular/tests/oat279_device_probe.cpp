// Map a real device OAT read-only and create separate corruption-test copies.
// Usage: oat279_device_probe REAL_OAT UNIQUE_OUTPUT_PREFIX
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../src/runtime_formats.hpp"

static void write_exclusive(const std::string& path,const uint8_t* data,size_t size) {
    const int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);
    size_t done=0;
    while(done<size) {
        const ssize_t n=::write(fd,data+done,size-done);assert(n>0);
        done+=static_cast<size_t>(n);
    }
    assert(::fsync(fd)==0);assert(::close(fd)==0);
}
static void put32(std::vector<uint8_t>& data,size_t offset,uint32_t value) {
    for(unsigned i=0;i<4;++i)data[offset+i]=static_cast<uint8_t>(value>>(8*i));
}
int main(int argc,char** argv) {
    if(argc!=3)return 1;
    const int fd=::open(argv[1],O_RDONLY);assert(fd>=0);
    struct stat st{};assert(::fstat(fd,&st)==0 && st.st_size>0 && st.st_size<=256*1024*1024);
    const size_t size=static_cast<size_t>(st.st_size);
    void* mapping=::mmap(nullptr,size,PROT_READ,MAP_PRIVATE,fd,0);assert(mapping!=MAP_FAILED);
    assert(::close(fd)==0);
    const auto* bytes=static_cast<const uint8_t*>(mapping);
    size_t offset=0;
    for(size_t i=4;i+72<=size;i+=4)if(!std::memcmp(bytes+i,"oat\n279\0",8)){offset=i;break;}
    assert(offset>0);
    const auto report=RuntimeFormats::inspect(bytes+offset,size-offset,false,offset);
    assert(report.valid && report.version=="279");
    const std::string prefix=argv[2];
    write_exclusive(prefix+".header.bin",bytes+offset,static_cast<size_t>(report.extent));
    std::vector<uint8_t> copy(bytes,bytes+size);
    for(const auto& mutation:std::vector<std::pair<size_t,std::string>>{
            {68,".bad-kv.oat"},{32,".bad-base.oat"},{40,".bad-trampoline.oat"}}) {
        const uint32_t original=RuntimeFormats::u32(bytes+offset,mutation.first);
        put32(copy,offset+mutation.first,UINT32_MAX);
        write_exclusive(prefix+mutation.second,copy.data(),copy.size());
        put32(copy,offset+mutation.first,original);
    }
    std::vector<uint8_t>().swap(copy);
    const char* name="com.nhdd.oat279probe";
    const size_t capacity=std::strlen(argv[0]);assert(capacity>=std::strlen(name));
    std::memset(argv[0],0,capacity);std::memcpy(argv[0],name,std::strlen(name));
    std::printf("PROBE pid=%d mapping=%p file_bytes=%zu payload_offset=%zu\n",
                ::getpid(),mapping,size,offset);
    std::fflush(stdout);
    ::sleep(20);
    assert(::munmap(mapping,size)==0);
}
