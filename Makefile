NDK_PATH ?=
CFLAGS := -O2 -static -Wall -Wextra
TARGET := nhdd
GO ?= go
ADB ?= adb
HOST_PORT ?=
SU_CMD ?=
PYTHON ?= python3

.PHONY: all android android-auto clean push test format check check-tui doctor gui gui-dev

# Default: build Android nhdd binary
all: $(TARGET)

$(TARGET): nhdd.c
	$(PYTHON) scripts/build_nhdd_android.py $(if $(NDK_PATH),--ndk "$(NDK_PATH)",) --out "$@"

# Auto-detect NDK host tag variant when running on macOS ARM64
android android-auto: $(TARGET)

clean:
	rm -f $(TARGET)
	rm -rf gui/frontend/dist
	rm -rf gui/bin/

push: $(TARGET)
	adb push $(TARGET) /data/local/tmp/nhdd
	adb shell chmod 755 /data/local/tmp/nhdd

# TUI 依赖检查
check-tui:
	python3 -c "import importlib.metadata as m; print('rich', m.version('rich'), 'OK')" || (echo "[!] 缺少 rich: pip install rich"; exit 1)

doctor:
	$(PYTHON) scripts/doctor.py --adb "$(ADB)" $(if $(HOST_PORT),--host-port "$(HOST_PORT)",) $(if $(NDK_PATH),--ndk "$(NDK_PATH)",) $(if $(SU_CMD),--su-cmd "$(SU_CMD)",)

# GUI 构建 (需要 wails)
gui:
	cd gui && $(GO) mod tidy && wails build

# GUI 开发模式
gui-dev:
	cd gui && $(GO) mod tidy && wails dev

# 语法检查
check:
	@echo "=== nhdd.c ==="
	$(PYTHON) scripts/build_nhdd_android.py $(if $(NDK_PATH),--ndk "$(NDK_PATH)",) --check-only
	@echo "=== nhdd_tui.py ==="
	$(PYTHON) -c "import ast; ast.parse(open('nhdd_tui.py').read()); print('  syntax OK')"
	@echo "=== fix_dex_checksum.py ==="
	$(PYTHON) -c "import ast; ast.parse(open('fix_dex_checksum.py').read()); print('  syntax OK')"
	@echo "=== fix_so.py ==="
	$(PYTHON) -c "import ast; ast.parse(open('fix_so.py').read()); print('  syntax OK')"
	@echo "=== gui Go vet ==="
	cd gui && $(GO) vet ./... 2>&1 | grep -v "frontend/dist" | head -10; echo "  (OK if no output above)"

# 契约测试: Python / Go / v9 修复管线一致性 (tests/contract/compare.py)
test:
	$(PYTHON) tests/contract/compare.py

test-strict:
	$(PYTHON) tests/contract/compare.py --strict

format:
	python3 -m black --check nhdd_tui.py fix_dex_checksum.py fix_so.py 2>/dev/null || true
	cd gui && $(GO) fmt ./... 2>/dev/null || true
	@echo "format check done"
