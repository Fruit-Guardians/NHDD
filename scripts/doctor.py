#!/usr/bin/env python3
"""
NHDD environment doctor.

Checks local build/runtime dependencies and, when an Android device is
connected, verifies root access plus the device-side /data/local/tmp/nhdd
binary.
"""

from __future__ import annotations

import argparse
import importlib.util
import importlib.metadata
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DEVICE_NHDD = "/data/local/tmp/nhdd"
ANDROID_MACHINE_AARCH64 = 183

_BUILD_SPEC = importlib.util.spec_from_file_location(
    "build_nhdd_android", ROOT_DIR / "scripts/build_nhdd_android.py"
)
if _BUILD_SPEC is None or _BUILD_SPEC.loader is None:
    raise RuntimeError("failed to load scripts/build_nhdd_android.py")
build_nhdd_android = importlib.util.module_from_spec(_BUILD_SPEC)
_BUILD_SPEC.loader.exec_module(build_nhdd_android)


@dataclass
class Finding:
    name: str
    status: str
    detail: str
    fix: str = ""


@dataclass
class Doctor:
    adb: str
    host_port: str
    su_cmd: str
    device_nhdd: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str, fix: str = "") -> None:
        self.findings.append(Finding(name, status, detail, fix))

    def adb_base(self) -> list[str]:
        args = [self.adb]
        if self.host_port:
            host, sep, port = self.host_port.partition(":")
            if sep and host and port:
                args += ["-H", host, "-P", port]
        return args


def run(args: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s: {' '.join(args)}"


def which_with_fallback(cmd: str, fallback: Path | None = None) -> str | None:
    found = shutil.which(cmd)
    if found:
        return found
    if fallback and fallback.exists():
        return str(fallback)
    return None


def version_line(args: list[str], timeout: int = 20) -> str:
    rc, out = run(args, timeout=timeout)
    if rc != 0:
        return out.splitlines()[0] if out else f"exit {rc}"
    return out.splitlines()[0] if out else "OK"


def is_path_like(value: str) -> bool:
    return any(sep in value for sep in ("/", "\\")) or (len(value) >= 2 and value[1] == ":")


def find_ndk(explicit: str | None) -> Path | None:
    ndk, _ = build_nhdd_android.find_ndk_and_clang(explicit, 34)
    return ndk


def host_tags() -> list[str]:
    return build_nhdd_android.host_tags()


def find_ndk_clang(ndk: Path) -> Path | None:
    return build_nhdd_android.find_clang_in_ndk(ndk, 34)


def check_local(doctor: Doctor, ndk_arg: str | None) -> None:
    python = sys.executable
    doctor.add("python3", "OK", f"{python} ({platform.python_version()})")

    if is_path_like(doctor.adb):
        adb_path = doctor.adb if os.access(doctor.adb, os.X_OK) else None
    else:
        adb_path = shutil.which(doctor.adb)
    if adb_path:
        doctor.add("adb", "OK", f"{adb_path}; {version_line([doctor.adb, 'version'])}")
    else:
        doctor.add(
            "adb",
            "FAIL",
            "adb not found",
            "Install Android platform-tools and add it to PATH. macOS: brew install android-platform-tools; Windows/Linux: install Android SDK platform-tools.",
        )

    sdkmanager = shutil.which("sdkmanager")
    if sdkmanager:
        doctor.add("sdkmanager", "OK", f"{sdkmanager}; {version_line(['sdkmanager', '--version'])}")
    else:
        doctor.add(
            "sdkmanager",
            "WARN",
            "sdkmanager not found",
            "Install Android command line tools. macOS: brew install --cask android-commandlinetools; Windows/Linux: install Android SDK Command-line Tools.",
        )

    ndk = find_ndk(ndk_arg)
    if ndk:
        cc = find_ndk_clang(ndk)
        detail = str(ndk)
        if cc:
            detail += f"; clang={cc}"
        doctor.add("Android NDK", "OK", detail)
    else:
        doctor.add(
            "Android NDK",
            "FAIL",
            "NDK r25+ with aarch64 clang not found",
            'Install one: sdkmanager "ndk;27.2.12479018"; then export NDK_PATH="$ANDROID_HOME/ndk/27.2.12479018"',
        )

    node = shutil.which("node")
    npm = shutil.which("npm")
    if node:
        doctor.add("node", "OK", f"{node}; {version_line(['node', '-v'])}")
    else:
        doctor.add("node", "FAIL", "node not found", "Install Node.js 18+ or newer.")
    if npm:
        doctor.add("npm", "OK", f"{npm}; {version_line(['npm', '-v'])}")
    else:
        doctor.add("npm", "FAIL", "npm not found", "Install Node.js/npm, then run: cd gui/frontend && npm install")

    wails = which_with_fallback("wails", Path.home() / "go/bin/wails")
    if not wails and platform.system().lower() == "windows":
        wails = which_with_fallback("wails.exe", Path.home() / "go/bin/wails.exe")
    if wails:
        doctor.add("Wails", "OK", f"{wails}; {version_line([wails, 'version'])}")
    else:
        doctor.add(
            "Wails",
            "FAIL",
            "wails CLI not found",
            'Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest; add GOPATH/bin to PATH.',
        )

    try:
        rich_version = importlib.metadata.version("rich")
        doctor.add("Python rich", "OK", f"rich {rich_version}")
    except importlib.metadata.PackageNotFoundError:
        doctor.add("Python rich", "FAIL", "rich not installed", "Install: python3 -m pip install rich")

    sofixer_dir = ROOT_DIR / "third_party/SoFixer"
    if sofixer_dir.exists() and any(sofixer_dir.iterdir()):
        doctor.add("SoFixer submodule", "OK", str(sofixer_dir))
    else:
        doctor.add(
            "SoFixer submodule",
            "WARN",
            "third_party/SoFixer is empty or missing",
            "Initialize: git submodule update --init --recursive",
        )

    frontend_modules = ROOT_DIR / "gui/frontend/node_modules"
    if frontend_modules.exists():
        doctor.add("frontend deps", "OK", str(frontend_modules))
    else:
        doctor.add("frontend deps", "WARN", "node_modules not found", "Install: cd gui/frontend && npm install")


def adb_shell(doctor: Doctor, command: str, timeout: int = 20) -> tuple[int, str]:
    return run(doctor.adb_base() + ["shell", command], timeout=timeout)


def root_wrap(su_cmd: str, command: str) -> str:
    quoted = sh_quote(command)
    if "{cmd}" in su_cmd:
        return su_cmd.replace("{cmd}", quoted)
    return f"{su_cmd} {quoted}"


def sh_quote(value: str) -> str:
    if not value:
        return "''"
    safe = all(c.isalnum() or c in "_-.:/+" for c in value)
    if safe:
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def parse_adb_devices(output: str) -> list[str]:
    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def check_device(doctor: Doctor) -> None:
    if not shutil.which(doctor.adb) and not is_path_like(doctor.adb):
        doctor.add("device", "SKIP", "adb missing; device checks skipped")
        return

    rc, out = run(doctor.adb_base() + ["devices"], timeout=20)
    if rc != 0:
        doctor.add("device", "FAIL", out or "adb devices failed", "Run: adb start-server; reconnect USB/Wi-Fi device.")
        return

    devices = parse_adb_devices(out)
    if not devices:
        doctor.add("device", "WARN", "no authorized Android device connected", "Enable USB debugging, then run: adb devices")
        return

    doctor.add("device", "OK", ", ".join(devices))

    if doctor.su_cmd:
        rc, out = adb_shell(doctor, root_wrap(doctor.su_cmd, "id"), timeout=20)
        if rc == 0 and ("uid=0" in out or "root" in out):
            doctor.add("root command", "OK", f"{doctor.su_cmd}: {out.splitlines()[0] if out else 'uid=0'}")
        else:
            doctor.add(
                "root command",
                "FAIL",
                f"{doctor.su_cmd!r} did not return root id: {out or 'no output'}",
                "Try --su-cmd 'su -c', --su-cmd 'kp -c', --su-cmd 'ksud -c', or test manually: adb shell su -c id",
            )
    else:
        tested = []
        for candidate in ("su -c", "kp -c", "ksud -c"):
            rc, out = adb_shell(doctor, root_wrap(candidate, "id"), timeout=10)
            tested.append(candidate)
            if rc == 0 and ("uid=0" in out or "root" in out):
                doctor.add("root command", "OK", f"{candidate}: {out.splitlines()[0] if out else 'uid=0'}")
                break
        else:
            doctor.add(
                "root command",
                "FAIL",
                f"tested: {', '.join(tested)}",
                "Pass a working wrapper: make doctor SU_CMD='kp -c' or python3 scripts/doctor.py --su-cmd 'ksud -c'",
            )

    rc, out = adb_shell(doctor, f"test -f {sh_quote(doctor.device_nhdd)} && echo OK || echo MISSING", timeout=20)
    if rc != 0 or "OK" not in out:
        doctor.add(
            "device nhdd",
            "FAIL",
            f"{doctor.device_nhdd} missing",
            "Build and push: make android push",
        )
        return

    doctor.add("device nhdd", "OK", doctor.device_nhdd)
    check_remote_nhdd_arch(doctor)


def read_elf_info(path: Path) -> tuple[bool, str]:
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return False, "not an ELF file"
    elf_class = data[4]
    endian = data[5]
    if endian != 1:
        return False, "ELF is not little-endian"
    machine = int.from_bytes(data[18:20], "little")
    if elf_class != 2:
        return False, f"ELF class is {elf_class}, expected 64-bit"
    if machine != ANDROID_MACHINE_AARCH64:
        return False, f"ELF machine is {machine}, expected AArch64 ({ANDROID_MACHINE_AARCH64})"
    return True, "ELF64 AArch64"


def check_remote_nhdd_arch(doctor: Doctor) -> None:
    with tempfile.TemporaryDirectory(prefix="nhdd-doctor-") as tmp:
        local = Path(tmp) / "nhdd"
        rc, out = run(doctor.adb_base() + ["pull", doctor.device_nhdd, str(local)], timeout=60)
        if rc != 0:
            doctor.add(
                "device nhdd arch",
                "WARN",
                f"could not pull {doctor.device_nhdd}: {out}",
                "Check permissions manually or re-push: adb push ./nhdd /data/local/tmp/nhdd",
            )
            return
        ok, detail = read_elf_info(local)
        doctor.add(
            "device nhdd arch",
            "OK" if ok else "FAIL",
            detail,
            "" if ok else "Rebuild for arm64 and push: make android push",
        )


def print_report(findings: list[Finding]) -> int:
    name_width = max([len(f.name) for f in findings] + [10])
    print("NHDD Doctor")
    print("=" * 40)
    for finding in findings:
        print(f"[{finding.status:<4}] {finding.name:<{name_width}} {finding.detail}")
        if finding.fix:
            print(f"       fix: {finding.fix}")

    fail_count = sum(1 for f in findings if f.status == "FAIL")
    warn_count = sum(1 for f in findings if f.status == "WARN")
    print("=" * 40)
    print(f"Summary: {fail_count} fail, {warn_count} warn")
    return 1 if fail_count else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check NHDD local and Android device environment.")
    parser.add_argument("--adb", default=os.environ.get("NHDD_ADB", "adb"), help="ADB executable path")
    parser.add_argument("--host-port", default=os.environ.get("NHDD_ADB_HOST_PORT", ""), help="ADB host:port")
    parser.add_argument("--ndk", default="", help="Android NDK path")
    parser.add_argument("--su-cmd", default=os.environ.get("NHDD_SU_CMD", ""), help="Root wrapper, e.g. 'su -c', 'kp -c', or template containing {cmd}")
    parser.add_argument("--device-nhdd", default=DEFAULT_DEVICE_NHDD, help="Device-side nhdd path")
    args = parser.parse_args()

    doctor = Doctor(
        adb=args.adb,
        host_port=args.host_port,
        su_cmd=args.su_cmd.strip(),
        device_nhdd=args.device_nhdd,
    )
    check_local(doctor, args.ndk or None)
    check_device(doctor)
    return print_report(doctor.findings)


if __name__ == "__main__":
    raise SystemExit(main())
