# NHDD C++ Modular — Android and host logic-test build
# Android:  make android
# Host:     make host
# Push:     make push

NHDD_BIN ?= nhdd
SRC := src/main.cpp
ANDROID_CXX ?= aarch64-linux-android34-clang++
HOST_CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
LDFLAGS ?= -static-libstdc++ -pthread
TEST_BIN_DIR ?= .test-bin

.PHONY: all android host test clean push

all: android

android:
	$(ANDROID_CXX) $(CXXFLAGS) $(SRC) -o $(NHDD_BIN) $(LDFLAGS)

host:
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -pthread $(SRC) -o $(NHDD_BIN)_host

test:
	mkdir -p $(TEST_BIN_DIR)
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/dex_capture_test.cpp -o $(TEST_BIN_DIR)/dex_capture_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/elf_reconstructor_test.cpp -o $(TEST_BIN_DIR)/elf_reconstructor_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/maps_monitor_test.cpp -o $(TEST_BIN_DIR)/maps_monitor_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/so_manifest_test.cpp -o $(TEST_BIN_DIR)/so_manifest_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/runtime_formats_test.cpp -o $(TEST_BIN_DIR)/runtime_formats_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/process_tracking_test.cpp -o $(TEST_BIN_DIR)/process_tracking_test
	$(HOST_CXX) -O2 -std=c++17 -Wall -Wextra -Werror tests/syscall_events_test.cpp -o $(TEST_BIN_DIR)/syscall_events_test -pthread
	$(TEST_BIN_DIR)/dex_capture_test
	$(TEST_BIN_DIR)/elf_reconstructor_test
	$(TEST_BIN_DIR)/maps_monitor_test
	$(TEST_BIN_DIR)/so_manifest_test
	$(TEST_BIN_DIR)/runtime_formats_test
	$(TEST_BIN_DIR)/process_tracking_test
	$(TEST_BIN_DIR)/syscall_events_test

push: android
	adb push $(NHDD_BIN) /data/local/tmp/nhdd && adb shell chmod 755 /data/local/tmp/nhdd

clean:
	rm -rf $(NHDD_BIN) $(NHDD_BIN)_host $(TEST_BIN_DIR)
