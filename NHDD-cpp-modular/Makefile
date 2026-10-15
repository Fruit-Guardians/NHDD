# NHDD v9.0-cpp-class — C++ OOP Build
# Android:  make android
# Host:     make host
# Push:     make push

NHDD_BIN ?= nhdd
SRC := src/main.cpp
CXX ?= aarch64-linux-android34-clang++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDFLAGS ?= -static-libstdc++

.PHONY: all android host clean push

all: android

android:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(NHDD_BIN) $(LDFLAGS)

host:
	g++ -O2 -std=c++17 -Wall -Wextra $(SRC) -o $(NHDD_BIN)_host

push: android
	adb push $(NHDD_BIN) /data/local/tmp/nhdd && adb shell chmod 755 /data/local/tmp/nhdd

clean:
	rm -f $(NHDD_BIN) $(NHDD_BIN)_host
