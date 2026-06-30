// main.cpp — NHDD C++ OOP entry point, v9.0-cpp-class
// No-Hook DEX/SO Dumper, class-based modular architecture
// Build: aarch64-linux-android34-clang++ -O2 -std=c++17 -static-libstdc++ -o nhdd src_oop/main.cpp

#include "nhdd_app.hpp"

int main(int argc, char** argv) {
    NhddApp app;
    return app.run(argc, argv);
}
