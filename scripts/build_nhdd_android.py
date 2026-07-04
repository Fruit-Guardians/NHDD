#!/usr/bin/env python3
"""
Cross-platform builder for the Android-side NHDD arm64 binary.

Works on Windows, macOS, and Linux as long as Android NDK r25+ is installed.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def sdk_roots() -> list[Path]:
    roots: list[Path] = []
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(key)
        if value:
            roots.append(Path(value).expanduser())

    system = platform.system().lower()
    if system == "darwin":
        roots.append(Path.home() / "Library/Android/sdk")
    elif system == "windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            roots.append(Path(local_app_data) / "Android/Sdk")
        roots.append(Path.home() / "AppData/Local/Android/Sdk")
    else:
        roots.append(Path.home() / "Android/Sdk")

    return unique_existing(roots)


def unique_existing(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        expanded = path.expanduser()
        try:
            resolved = expanded.resolve()
        except OSError:
            resolved = expanded
        if resolved in seen:
            continue
        seen.add(resolved)
        if expanded.exists():
            result.append(expanded)
    return result


def host_tags() -> list[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        tags = []
        if machine == "arm64":
            tags.append("darwin-arm64")
        tags.append("darwin-x86_64")
        return tags
    if system == "windows":
        return ["windows-x86_64"]
    return ["linux-x86_64"]


def compiler_names(api: int) -> list[str]:
    base = f"aarch64-linux-android{api}-clang"
    if platform.system().lower() == "windows":
        return [base + ".cmd", base + ".bat", base + ".exe", base]
    return [base]


def find_clang_in_ndk(ndk: Path, api: int) -> Path | None:
    base = ndk / "toolchains/llvm/prebuilt"
    for tag in host_tags():
        for name in compiler_names(api):
            cc = base / tag / "bin" / name
            if cc.exists():
                return cc
    for name in compiler_names(api):
        matches = sorted(base.glob(f"*/bin/{name}"))
        if matches:
            return matches[0]
    return None


def candidate_ndks(explicit: str | None) -> list[Path]:
    candidates: list[Path] = []
    for value in (explicit, os.environ.get("NDK"), os.environ.get("NDK_PATH"), os.environ.get("ANDROID_NDK_HOME")):
        if value:
            candidates.append(Path(value).expanduser())

    for root in sdk_roots():
        ndk_root = root / "ndk"
        if ndk_root.exists():
            candidates.extend(sorted(ndk_root.glob("*"), reverse=True))

    return unique_existing(candidates)


def find_ndk_and_clang(explicit: str | None, api: int) -> tuple[Path | None, Path | None]:
    for ndk in candidate_ndks(explicit):
        cc = find_clang_in_ndk(ndk, api)
        if cc:
            return ndk, cc
    return None, None


def run_command(args: list[str], cwd: Path) -> int:
    print("+ " + " ".join(str(a) for a in args))
    if platform.system().lower() == "windows" and str(args[0]).lower().endswith((".cmd", ".bat")):
        return subprocess.call(subprocess.list2cmdline(args), cwd=str(cwd), shell=True)
    return subprocess.call(args, cwd=str(cwd))


def describe_output(path: Path) -> None:
    if not path.exists():
        return
    size = path.stat().st_size
    print(f"built: {path} ({size / 1024 / 1024:.2f} MiB)")
    file_cmd = shutil.which("file")
    if file_cmd:
        subprocess.call([file_cmd, str(path)])


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Android arm64 nhdd from nhdd.c.")
    parser.add_argument("--ndk", default="", help="Android NDK path. Defaults to NDK/NDK_PATH/ANDROID_HOME discovery.")
    parser.add_argument("--api", default=int(os.environ.get("API", "34")), type=int, help="Android API level")
    parser.add_argument("--out", default=os.environ.get("OUT", str(ROOT_DIR / "nhdd")), help="Output binary path")
    parser.add_argument("--source", default=str(ROOT_DIR / "nhdd.c"), help="C source path")
    parser.add_argument("--check-only", action="store_true", help="Run clang -fsyntax-only instead of building")
    args = parser.parse_args()

    ndk, cc = find_ndk_and_clang(args.ndk or None, args.api)
    if not ndk or not cc:
        print("ERROR: Android NDK clang not found.", file=sys.stderr)
        print("Set NDK, NDK_PATH, or ANDROID_HOME/ANDROID_SDK_ROOT.", file=sys.stderr)
        print('Install example: sdkmanager "ndk;27.2.12479018"', file=sys.stderr)
        return 1

    print(f"NDK: {ndk}")
    print(f"CC:  {cc}")

    source = Path(args.source)
    out = Path(args.out)
    cmd = [str(cc), "-O2", "-static", "-Wall", "-Wextra"]
    if args.check_only:
        cmd += ["-fsyntax-only", str(source)]
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd += ["-o", str(out), str(source)]

    rc = run_command(cmd, ROOT_DIR)
    if rc == 0 and not args.check_only:
        describe_output(out)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
