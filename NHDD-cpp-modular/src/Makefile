# NHDD C++ OOP Class-based build (v9.0-cpp-class)
# Android cross-compile:
#   make android CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++
# Host syntax check:
#   make host

NHDD_BIN ?= nhdd
SRC := main.cpp
CXX ?= aarch64-linux-android34-clang++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDFLAGS ?= -static-libstdc++

.PHONY: all android host clean push test

all: android

android:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(NHDD_BIN) $(LDFLAGS)

host:
	g++ -O2 -std=c++17 -Wall -Wextra $(SRC) -o $(NHDD_BIN)_host

push: android
	adb push $(NHDD_BIN) /data/local/tmp/nhdd && adb shell chmod 755 /data/local/tmp/nhdd

test: android push
	adb shell "/data/local/tmp/nhdd" >/dev/null 2>&1; echo "Exit: $$?"

clean:
	rm -f $(NHDD_BIN) $(NHDD_BIN)_host
