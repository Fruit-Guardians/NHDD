#!/usr/bin/env python3
"""
APK 重打包脚本：将 dump 目录中修复后的 DEX/SO 替换回原始 APK。
产物可直接丢 jadx 分析，不签名、不安装。

用法:
    python scripts/repack_apk.py <pkg> <dump_dir> [-o output.apk] [--adb adb_path] [--host host:port]
    python scripts/repack_apk.py --from-local <original.apk> <dump_dir> -o output.apk

示例:
    python scripts/repack_apk.py com.example.app ./nhdd_output/com.example.app
    python scripts/repack_apk.py --from-local base.apk ./dump_dir -o repacked.apk
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

# 复用项目根目录的 fix_dex_checksum.py 和 fix_so.py 的校验函数
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fix_dex_checksum import validate_dex_deep_bool, DEX_HEADER_SIZE
from fix_so import validate_elf_deep, SO_MIN_SIZE


def get_apk_path(adb, host, pkg):
    """通过 adb pm path 获取设备上的 APK 路径"""
    args = ["adb"]
    if host:
        parts = host.split(":")
        if len(parts) == 2:
            args += ["-H", parts[0], "-P", parts[1]]
    args += ["shell", "pm", "path", pkg]

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"pm path 失败: {result.stderr.strip()}")
        return None

    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line.startswith("package:") and line.endswith("/base.apk"):
            return line[len("package:"):]
    # 取第一个结果
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line.startswith("package:"):
            return line[len("package:"):]
    return None


def pull_apk(adb, host, pkg, output_dir):
    """从设备拉取 APK"""
    apk_path = get_apk_path(adb, host, pkg)
    if not apk_path:
        print(f"错误: 无法获取 {pkg} 的 APK 路径")
        return None

    local_path = os.path.join(output_dir, "original.apk")
    args = ["adb"]
    if host:
        parts = host.split(":")
        if len(parts) == 2:
            args += ["-H", parts[0], "-P", parts[1]]
    args += ["pull", apk_path, local_path]

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"adb pull 失败: {result.stderr.strip()}")
        return None

    print(f"  已拉取: {local_path}")
    return local_path


def extract_apk(apk_path):
    """解压 APK 到临时目录"""
    tmp_dir = tempfile.mkdtemp(prefix="nhdd_apk_")
    with zipfile.ZipFile(apk_path, 'r') as zf:
        zf.extractall(tmp_dir)
    return tmp_dir


def remove_signature_files(apk_dir):
    """删除 META-INF/ 下的签名文件"""
    meta_dir = os.path.join(apk_dir, "META-INF")
    if not os.path.isdir(meta_dir):
        return
    for f in os.listdir(meta_dir):
        name = f.upper()
        if name.endswith(".RSA") or name.endswith(".SF") or name.endswith(".MF"):
            os.remove(os.path.join(meta_dir, f))


def collect_valid_dex(dump_dir):
    """收集 dump 目录中有效的 DEX 文件"""
    all_dex = []
    for root, dirs, files in os.walk(dump_dir):
        # 跳过 bad/ 目录
        dirs[:] = [d for d in dirs if d != "bad"]
        for f in files:
            if f.lower().endswith(".dex"):
                all_dex.append(os.path.join(root, f))

    valid = []
    for path in all_dex:
        if os.path.getsize(path) < DEX_HEADER_SIZE:
            continue
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic != b'dex\n':
                continue
        try:
            with open(path, 'rb') as f:
                data = bytearray(f.read())
            if not validate_dex_deep_bool(data):
                continue
        except Exception:
            continue
        valid.append((path, os.path.getsize(path)))

    # 按大小降序
    valid.sort(key=lambda x: x[1], reverse=True)
    return [p for p, _ in valid]


def replace_dex_files(apk_dir, dump_dir):
    """NEW: 删除所有 classes*.dex，把有效 dump DEX 全部放入"""
    valid_dex = collect_valid_dex(dump_dir)
    print(f"  有效 DEX: {len(valid_dex)} 个")

    # 删除所有原始 DEX
    for f in list(os.listdir(apk_dir)):
        if f.lower().startswith("classes") and f.lower().endswith(".dex"):
            os.remove(os.path.join(apk_dir, f))

    # 按大小降序放入所有有效 dump DEX
    replaced = 0
    for i, src in enumerate(valid_dex):
        target_name = "classes.dex" if i == 0 else f"classes{i+1}.dex"
        dst = os.path.join(apk_dir, target_name)
        shutil.copy2(src, dst)
        replaced += 1

    return replaced, 0  # 不再有跳过


def collect_valid_so(dump_dir):
    """收集 dump 目录中有效的 SO 文件"""
    so_by_name = {}
    for root, dirs, files in os.walk(dump_dir):
        dirs[:] = [d for d in dirs if d != "bad"]
        for f in files:
            if not f.lower().endswith(".so"):
                continue
            path = os.path.join(root, f)
            if os.path.getsize(path) < SO_MIN_SIZE:
                continue
            try:
                with open(path, 'rb') as fh:
                    data = fh.read()
                if not validate_elf_deep(data):
                    continue
            except Exception:
                continue
            so_by_name[f.lower()] = path
    return so_by_name


def replace_so_files(apk_dir, dump_dir):
    """NEW: 删除所有 lib/<abi>/*.so，只放回匹配的 dump SO"""
    so_map = collect_valid_so(dump_dir)
    print(f"  有效 SO: {len(so_map)} 个")

    lib_dir = os.path.join(apk_dir, "lib")
    if not os.path.isdir(lib_dir):
        print("  APK 无 native lib")
        return 0, 0

    replaced = 0
    for root, dirs, files in os.walk(lib_dir):
        for f in list(files):
            if not f.lower().endswith(".so"):
                continue
            path = os.path.join(root, f)
            key = f.lower()
            if key in so_map:
                shutil.copy2(so_map[key], path)
                replaced += 1
            else:
                os.remove(path)  # 旧保护壳 SO 不保留

    return replaced, 0


def repack_apk(apk_dir, output_path):
    """将目录重压缩为 APK"""
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_STORED) as zf:
        for root, dirs, files in os.walk(apk_dir):
            for f in files:
                file_path = os.path.join(root, f)
                arcname = os.path.relpath(file_path, apk_dir).replace("\\", "/")
                zf.write(file_path, arcname)
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="APK 重打包：替换 DEX/SO 后重新打包（供 jadx 静态分析）",
    )
    parser.add_argument("pkg_or_apk", nargs="?", help="包名 或 --from-local 时的 APK 路径")
    parser.add_argument("dump_dir", nargs="?", help="dump 输出目录")
    parser.add_argument("-o", "--output", help="输出 APK 路径")
    parser.add_argument("--adb", default="adb", help="ADB 路径 (默认: adb)")
    parser.add_argument("--host", default="", help="ADB remote host:port")
    parser.add_argument("--from-local", action="store_true",
                        help="从本地 APK 文件而非设备拉取")
    parser.add_argument("--work-dir", default="", help="工作目录 (默认: dump_dir/repack/)")

    args = parser.parse_args()

    if not args.pkg_or_apk or not args.dump_dir:
        parser.print_help()
        sys.exit(1)

    dump_dir = os.path.abspath(args.dump_dir)
    if not os.path.isdir(dump_dir):
        print(f"错误: dump 目录不存在: {dump_dir}")
        sys.exit(1)

    work_dir = args.work_dir or os.path.join(dump_dir, "repack")
    os.makedirs(work_dir, exist_ok=True)

    # Step 1: 获取 APK
    print("[1/4] 原 APK...")
    if args.from_local:
        apk_path = args.pkg_or_apk
        if not os.path.exists(apk_path):
            print(f"错误: APK 文件不存在: {apk_path}")
            sys.exit(1)
    else:
        apk_path = pull_apk(args.adb, args.host, args.pkg_or_apk, work_dir)
        if not apk_path:
            sys.exit(1)

    # Step 2: 解压
    print("[2/4] 解压 APK...")
    extract_dir = extract_apk(apk_path)
    try:
        # Step 3: 清签名
        print("[3/4] 清理签名文件...")
        remove_signature_files(extract_dir)

        # Step 4: 替换 DEX (不处理SO)
        print("[4/4] 替换 DEX 文件...")
        rep_dex, skip_dex = replace_dex_files(extract_dir, dump_dir)
        print(f"  DEX: {rep_dex} 替换, {skip_dex} 跳过")

        # 重压缩
        pkg_name = args.pkg_or_apk if not args.from_local else os.path.splitext(os.path.basename(args.pkg_or_apk))[0]
        output_path = args.output or os.path.join(work_dir, f"{pkg_name}_repacked.apk")
        output_path = os.path.abspath(output_path)
        repack_apk(extract_dir, output_path)
        print(f"  完成: {output_path}")
        print(f"\n可直接拖入 jadx: {output_path}")

    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
