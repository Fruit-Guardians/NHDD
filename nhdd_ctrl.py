#!/usr/bin/env python3
"""
NHDD Desktop Controller - 电脑端脱壳控制程序
通过 ADB 连接手机，选择 app → 自动重启 → dump DEX

Usage:
    python3 nhdd_ctrl.py                    # 交互式选择 app
    python3 nhdd_ctrl.py com.example.app    # 直接指定包名
    python3 nhdd_ctrl.py --list             # 列出所有第三方 app

Environment:
    NHDD_ADB    Override the adb command. Default: "adb".
                Example: NHDD_ADB="adb -H 192.168.238.1 -P 5037" python3 nhdd_ctrl.py
"""

import subprocess
import sys
import os
import time
import json
import re

# ADB command. Defaults to plain "adb" on PATH; override via NHDD_ADB env var,
# e.g. NHDD_ADB="adb -H 192.168.238.1 -P 5037" for a network adb server.
ADB = os.environ.get("NHDD_ADB", "adb")
NHDD_BIN = "/data/local/tmp/nhdd"
DEFAULT_DUMP_DIR = "/data/local/tmp/nhdd_dump"
# Golden window: most first-gen packers unload the decrypted DEX ~6s after
# launch. Scanning around 4s catches it; 8s is often too late (0 DEX).
DEFAULT_WAIT_SEC = 4
# Early-launch capture: keep scanning while the app loads and the user navigates
# its feature pages, so lazily-loaded DEX get captured. `--watch` auto-stops
# after K consecutive dry rounds. This is the key to ~100% first-gen recovery.
DEFAULT_USE_WATCH = True
DEFAULT_WATCH_DRY = 3          # stop after this many dry rounds
DEFAULT_MAX_SECONDS = 120      # safety cap


def adb_shell(cmd):
    """Execute shell command on device via ADB, return stdout."""
    result = subprocess.run(
        f'{ADB} shell "{cmd}"',
        shell=True, capture_output=True, text=True, timeout=60
    )
    return result.stdout.strip()


def adb_shell_root(cmd):
    """Execute command as root via ADB."""
    return adb_shell(cmd)


def get_third_party_apps():
    """Get list of third-party apps from device."""
    output = adb_shell("pm list packages -3")
    if not output:
        print("Error: Cannot connect to device. Check ADB connection.")
        sys.exit(1)

    apps = []
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("package:"):
            pkg = line[8:]
            # Try to get app name
            label = adb_shell(f"dumpsys package {pkg} 2>/dev/null | head -5")
            apps.append(pkg)
    return apps


def get_running_apps():
    """Get list of running third-party app PIDs."""
    output = adb_shell("ps -A -o PID,NAME 2>/dev/null || ps -A")
    running = {}
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            try:
                pid = int(parts[0])
                name = parts[-1]
                running[name] = pid
            except ValueError:
                continue
    return running


def select_app_interactive():
    """Interactive app selection with search."""
    print("Loading apps from device...")
    apps = get_third_party_apps()
    running = get_running_apps()

    if not apps:
        print("No third-party apps found.")
        sys.exit(1)

    # Build display list
    display = []
    for i, pkg in enumerate(apps):
        pid = running.get(pkg)
        status = f" (PID: {pid})" if pid else ""
        display.append((pkg, status))

    # Show list
    print(f"\n{'='*60}")
    print(f"  NHDD - {len(apps)} apps found  (running shown with PID)")
    print(f"{'='*60}")

    # Paginated display
    page_size = 20
    page = 0
    while True:
        start = page * page_size
        end = min(start + page_size, len(display))

        for i in range(start, end):
            pkg, status = display[i]
            marker = "\033[32m" + status + "\033[0m" if status else ""
            print(f"  {i+1:3d}. {pkg}{marker}")

        print(f"\n  Page {page+1}/{(len(display)-1)//page_size+1}")
        print(f"  Enter number / search keyword / n=next / p=prev / q=quit")

        try:
            choice = input("\n  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            sys.exit(0)

        if choice == 'q':
            sys.exit(0)
        elif choice == 'n':
            page = min(page + 1, (len(display)-1)//page_size)
            continue
        elif choice == 'p':
            page = max(page - 1, 0)
            continue
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(display):
                return display[idx][0]
            print("Invalid number.")
        else:
            # Search
            matches = [(i, pkg, s) for i, (pkg, s) in enumerate(display)
                       if choice.lower() in pkg.lower()]
            if len(matches) == 1:
                return matches[0][1]
            elif len(matches) > 1:
                print(f"\n  Found {len(matches)} matches:")
                for idx, pkg, s in matches[:10]:
                    marker = "\033[32m" + s + "\033[0m" if s else ""
                    print(f"  {idx+1:3d}. {pkg}{marker}")
                try:
                    sub = input("\n  Select number: ").strip()
                    if sub.isdigit():
                        sel = int(sub) - 1
                        if 0 <= sel < len(display):
                            return display[sel][0]
                except (EOFError, KeyboardInterrupt):
                    continue
            else:
                print("No matches.")


def dump_app(pkg, dump_dir=None, wait_sec=None, snapshot=None):
    """Main dump flow: force-stop -> launch -> watch-scan.

    snapshot=True (default): watch mode — keep scanning while the app loads and
    the user navigates its pages, auto-stop on stable set. Best for first-gen
    shells that lazily load DEX.
    snapshot=False: single scan after wait_sec.
    """
    if not dump_dir:
        dump_dir = DEFAULT_DUMP_DIR
    if wait_sec is None:
        wait_sec = DEFAULT_WAIT_SEC
    if snapshot is None:
        snapshot = True

    print(f"\n{'='*60}")
    print(f"  NHDD Dump: {pkg}")
    print(f"  Output: {dump_dir}  (wait={wait_sec}s, snapshot={'on' if snapshot else 'off'})")
    print(f"{'='*60}\n")

    # Step 1: Check nhdd binary
    check = adb_shell(f"ls {NHDD_BIN}")
    if "nhdd" not in check:
        print(f"Error: nhdd binary not found at {NHDD_BIN}")
        print("Push it first: adb push nhdd /data/local/tmp/nhdd")
        return False

    # Step 2: Force stop
    print("[1/5] Stopping app...")
    adb_shell(f"am force-stop {pkg}")
    time.sleep(1)

    # Step 3: Launch app
    print("[2/5] Launching app...")
    launch_result = adb_shell(
        f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null"
    )

    if snapshot:
        # Watch mode: keep scanning while the app loads and while the user
        # navigates feature pages. Lazily-loaded DEX are captured as they enter
        # memory; the scanner de-dups, so re-scanning never produces dup files.
        print(f"[3/5] WATCH scan: auto-stop after {DEFAULT_WATCH_DRY} dry rounds "
              f"(max {DEFAULT_MAX_SECONDS}s).")
        print(f"      >>> 在手机上点开 app 各功能页，按需加载的 DEX 会被逐个捕获 <<<")
        nhdd_cmd = (f"{NHDD_BIN} {pkg} {dump_dir} --watch {DEFAULT_WATCH_DRY} "
                    f"--max-seconds {DEFAULT_MAX_SECONDS}")
    else:
        # Step 4: Wait for DEX to be unpacked
        print(f"[3/5] Waiting {wait_sec}s for app to load and unpack DEX...")
        for i in range(wait_sec, 0, -1):
            print(f"       {i}s...", end="\r")
            time.sleep(1)
        print("       0s... done    ")
        nhdd_cmd = f"{NHDD_BIN} {pkg} {dump_dir}"

    # Step 5: Check PID
    pid = adb_shell(f"pidof {pkg}").strip()
    if not pid:
        print(f"Error: App {pkg} is not running! Launch may have failed.")
        print(f"       Try launching manually and run: {NHDD_BIN} {pkg} {dump_dir}")
        return False
    print(f"[4/5] App running: PID={pid}")

    # Step 6: Create output dir and run nhdd
    adb_shell(f"mkdir -p {dump_dir}")
    print(f"[5/5] Dumping DEX files...")
    print()

    # Run nhdd and capture output
    result = subprocess.run(
        f'{ADB} shell "{nhdd_cmd}"',
        shell=True, capture_output=True, text=True, timeout=180
    )

    output = result.stdout
    for line in output.split("\n"):
        if line.strip():
            print(f"  {line}")

    if result.stderr:
        for line in result.stderr.split("\n"):
            if line.strip():
                print(f"  [stderr] {line}")

    # Count results (nhdd writes DEX under {dump_dir}/dex/)
    count_output = adb_shell(f"ls {dump_dir}/dex/*.dex 2>/dev/null | wc -l")
    try:
        dex_count = int(count_output.strip())
    except ValueError:
        dex_count = 0

    # List dumped files
    if dex_count > 0:
        print(f"\n{'='*60}")
        print(f"  SUCCESS: {dex_count} DEX files dumped!")
        print(f"  Output: {dump_dir}")
        print(f"{'='*60}")

        # Pull to local
        local_dir = os.path.expanduser(f"~/nhdd_dump/{pkg}")
        print(f"\n  Pulling to local: {local_dir}")
        os.makedirs(local_dir, exist_ok=True)
        pull_result = subprocess.run(
            f'{ADB} pull {dump_dir}/. {local_dir}/',
            shell=True, capture_output=True, text=True
        )
        if pull_result.returncode == 0:
            print(f"  Pulled to: {local_dir}")
        else:
            print(f"  Pull failed. Files are on device at: {dump_dir}")
    else:
        print(f"\n  No DEX files found. App may have crashed or packer unloaded DEX.")
        print(f"  Try: increase wait time, or run manually:")
        print(f"    {ADB} shell \"{NHDD_BIN} {pkg} {dump_dir}\"")

    return dex_count > 0


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--list" or arg == "-l":
            apps = get_third_party_apps()
            running = get_running_apps()
            for pkg in sorted(apps):
                pid = running.get(pkg, "")
                marker = f" (PID: {pid})" if pid else ""
                print(f"  {pkg}{marker}")
            return
        elif arg == "--help" or arg == "-h":
            print(__doc__)
            return
        else:
            # Direct package name
            dump_dir = sys.argv[2] if len(sys.argv) > 2 else None
            dump_app(arg, dump_dir)
            return

    # Interactive mode
    pkg = select_app_interactive()
    print(f"\n  Selected: {pkg}")

    # Ask for output dir
    try:
        custom_dir = input(f"  Output dir [{DEFAULT_DUMP_DIR}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        custom_dir = ""

    dump_dir = custom_dir if custom_dir else DEFAULT_DUMP_DIR
    dump_app(pkg, dump_dir)


if __name__ == "__main__":
    main()
