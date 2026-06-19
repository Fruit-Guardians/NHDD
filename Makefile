NDK_PATH ?= /lina_android/android-ndk-r27
TOOLCHAIN := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
CC := $(TOOLCHAIN)/bin/aarch64-linux-android34-clang
CFLAGS := -O2 -static
TARGET := nhdd

.PHONY: all clean push

all: $(TARGET)

$(TARGET): nhdd.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

push: $(TARGET)
	adb push $(TARGET) /data/local/tmp/nhdd
