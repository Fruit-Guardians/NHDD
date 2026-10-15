// v9_harness.cpp — primitive-level contract harness for NHDD-cpp-modular.
//
// Applies the device-side repair primitives in place over a fixture copy:
//   dex/*.dex : DexValidator::fix_header_and_checksums (header + SHA-1 + Adler32)
//   so/*.so   : SoDumper::repair_basic (ELF repair)
//
// No quarantine semantics exist on-device (that lives in the dump pipeline),
// so BAD-class expectations are not judged for this harness.
//
// Build (host, Linux/macOS): g++ -std=c++17 -O1 -I <repo>/NHDD-cpp-modular/src
// Run: v9_harness <workdir-with-dex-and-so>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "dex_validator.hpp"
#include "so_dumper.hpp"

namespace fs = std::filesystem;

static bool repair_dex(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    in.close();
    if (buf.empty()) return false;
    DexValidator::fix_header_and_checksums(buf.data(), buf.size());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char *>(buf.data()),
              static_cast<std::streamsize>(buf.size()));
    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <workdir>\n", argv[0]);
        return 2;
    }
    fs::path work(argv[1]);
    int errors = 0;

    for (const auto &e : fs::directory_iterator(work / "dex")) {
        if (!e.is_regular_file()) continue;
        if (!repair_dex(e.path())) {
            std::fprintf(stderr, "dex fail: %s\n", e.path().string().c_str());
            errors++;
        }
    }
    for (const auto &e : fs::directory_iterator(work / "so")) {
        if (!e.is_regular_file()) continue;
        if (SoDumper::repair_basic(e.path().string().c_str()) != 0) {
            // repair_basic returns -1 for <0x40 bytes; leave file untouched.
            std::fprintf(stderr, "so fail: %s\n", e.path().string().c_str());
        }
    }
    std::printf("v9_harness done errors=%d\n", errors);
    return 0;
}
