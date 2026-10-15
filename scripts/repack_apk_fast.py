#!/usr/bin/env python3
"""
APK 重打包脚本：将 dump 目录中修复后的 DEX/SO 替换回原始 APK。
产物用于 jadx 静态分析，不签名、不安装。

主要优化：
1. DEX 候选目录只选择最高优先级的一个，避免 dex/jadx-ready、dex/fixed、dex 被重复扫描。
2. duplicate_classes / dex_manifest 改为可选 --report，默认不做类名全量解析。
3. 类名解析使用 bytes.find，避免每个类都切片扫描整个 DEX。
4. 支持 --quick-dex-check，跳过深度 DEX 校验，仅做 header 快检 + SHA-1。
5. 支持 --dex-only，生成只包含 classes*.dex 的 APK/ZIP，给 jadx 分析最快。
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fix_dex_checksum import validate_dex_deep_bool, DEX_HEADER_SIZE
from fix_so import validate_elf_deep, SO_MIN_SIZE


SKIP_DIRS = {"bad", "invalid", "repack", "backup", "raw", "__pycache__"}
DEX_CANDIDATE_SUBDIRS = ["dex/jadx-ready", "dex/fixed", "dex"]


def get_apk_path(adb, host, pkg):
    args = [adb]
    if host:
        parts = host.split(":")
        if len(parts) == 2:
            args += ["-H", parts[0], "-P", parts[1]]
    args += ["shell", "pm", "path", pkg]

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"pm path 失败: {result.stderr.strip()}")
        return None

    lines = [x.strip() for x in result.stdout.splitlines() if x.strip().startswith("package:")]
    for line in lines:
        if line.endswith("/base.apk"):
            return line[len("package:"):]
    return lines[0][len("package:"):] if lines else None


def pull_apk(adb, host, pkg, output_dir):
    apk_path = get_apk_path(adb, host, pkg)
    if not apk_path:
        print(f"错误: 无法获取 {pkg} 的 APK 路径")
        return None

    local_path = os.path.join(output_dir, "original.apk")
    args = [adb]
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
    tmp_dir = tempfile.mkdtemp(prefix="nhdd_apk_")
    with zipfile.ZipFile(apk_path, "r") as zf:
        zf.extractall(tmp_dir)
    return tmp_dir


def remove_signature_files(apk_dir):
    meta_dir = os.path.join(apk_dir, "META-INF")
    if not os.path.isdir(meta_dir):
        return
    for f in os.listdir(meta_dir):
        name = f.upper()
        if name.endswith((".RSA", ".SF", ".MF", ".DSA", ".EC")):
            os.remove(os.path.join(meta_dir, f))


def _walk_files(root_dir, suffix):
    out = []
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.lower().endswith(suffix):
                out.append(os.path.join(root, f))
    return out


def find_dex_candidates(dump_dir):
    """按优先级只选择一个 DEX 来源目录，避免嵌套目录重复扫描。"""
    for sub in DEX_CANDIDATE_SUBDIRS:
        sub_path = os.path.join(dump_dir, sub)
        if not os.path.isdir(sub_path):
            continue
        files = _walk_files(sub_path, ".dex")
        if files:
            print(f"  DEX 来源: {sub} ({len(files)} 个候选)")
            return files

    files = _walk_files(dump_dir, ".dex")
    print(f"  DEX 来源: dump_dir fallback ({len(files)} 个候选)")
    return files


def file_sha1(path, chunk_size=1024 * 1024):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def quick_validate_dex(path, size):
    if size < DEX_HEADER_SIZE:
        return False
    try:
        with open(path, "rb") as f:
            hdr = f.read(DEX_HEADER_SIZE)
        if hdr[:4] != b"dex\n":
            return False
        if struct.unpack_from("<I", hdr, 0x24)[0] != DEX_HEADER_SIZE:
            return False
        declared_size = struct.unpack_from("<I", hdr, 0x20)[0]
        return 0 < declared_size <= size
    except Exception:
        return False


def collect_valid_dex(dump_dir, dedup=True, quick=False):
    candidates = find_dex_candidates(dump_dir)

    # 路径级去重：防止同一文件经由不同候选目录被重复加入。
    uniq = []
    seen_path = set()
    for path in candidates:
        real = os.path.realpath(path)
        if real in seen_path:
            continue
        seen_path.add(real)
        uniq.append(path)

    valid = []
    seen_sha1 = set()
    dedup_skipped = 0

    for path in uniq:
        try:
            size = os.path.getsize(path)
        except OSError:
            continue

        if quick:
            if not quick_validate_dex(path, size):
                continue
            sha1 = file_sha1(path)
        else:
            if size < DEX_HEADER_SIZE:
                continue
            try:
                with open(path, "rb") as f:
                    data = f.read()
                if data[:4] != b"dex\n":
                    continue
                if not validate_dex_deep_bool(bytearray(data)):
                    continue
                sha1 = hashlib.sha1(data).hexdigest()
            except Exception:
                continue

        if dedup:
            if sha1 in seen_sha1:
                dedup_skipped += 1
                continue
            seen_sha1.add(sha1)

        valid.append((path, size, sha1))

    if dedup_skipped:
        print(f"  SHA-1 去重跳过: {dedup_skipped} 个重复 DEX")

    valid.sort(key=lambda x: x[1], reverse=True)
    return valid


def _read_uleb128(data, offset):
    result = 0
    shift = 0
    while offset < len(data) and shift <= 28:
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            return result, offset
        shift += 7
    return result, offset


def extract_class_names(dex_path):
    with open(dex_path, "rb") as f:
        data = f.read()
    if len(data) < DEX_HEADER_SIZE:
        return set()

    try:
        string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]
        string_ids_size = struct.unpack_from("<I", data, 0x40)[0]
        type_ids_off = struct.unpack_from("<I", data, 0x44)[0]
        type_ids_size = struct.unpack_from("<I", data, 0x48)[0]
        class_defs_off = struct.unpack_from("<I", data, 0x64)[0]
        class_defs_size = struct.unpack_from("<I", data, 0x68)[0]
    except struct.error:
        return set()

    if class_defs_size == 0 or string_ids_size == 0 or type_ids_size == 0:
        return set()
    if any(v >= len(data) for v in (string_ids_off, type_ids_off, class_defs_off)):
        return set()

    max_type_items = min(type_ids_size, (len(data) - type_ids_off) // 4)
    type_list = [struct.unpack_from("<I", data, type_ids_off + i * 4)[0]
                 for i in range(max_type_items)]

    classes = set()
    entry_size = 32
    max_class_items = min(class_defs_size, (len(data) - class_defs_off) // entry_size)
    for i in range(max_class_items):
        entry = class_defs_off + i * entry_size
        class_idx = struct.unpack_from("<I", data, entry)[0]
        if class_idx >= len(type_list):
            continue
        string_idx = type_list[class_idx]
        if string_idx >= string_ids_size:
            continue
        sid_off = string_ids_off + string_idx * 4
        if sid_off + 4 > len(data):
            continue
        stroff = struct.unpack_from("<I", data, sid_off)[0]
        if stroff >= len(data):
            continue
        _, desc_start = _read_uleb128(data, stroff)
        desc_end = data.find(b"\x00", desc_start)
        if desc_end < 0:
            continue
        desc = data[desc_start:desc_end].decode("utf-8", errors="replace")
        if desc.startswith("L") and desc.endswith(";"):
            classes.add(desc)

    return classes


def build_class_cache(valid_dex):
    cache = {}
    for path, _, _ in valid_dex:
        try:
            cache[path] = extract_class_names(path)
        except Exception:
            cache[path] = set()
    return cache


def apply_strict_class_file_dedup(valid_dex, class_cache):
    """保守 class-level 去重：只跳过完全不贡献新类的 DEX，不重写 DEX 内部类。"""
    kept = []
    seen_classes = set()
    skipped = 0
    for item in valid_dex:
        path = item[0]
        classes = class_cache.get(path, set())
        if classes and classes.issubset(seen_classes):
            skipped += 1
            continue
        kept.append(item)
        seen_classes.update(classes)
    if skipped:
        print(f"  class-level 文件去重跳过: {skipped} 个不贡献新类的 DEX")
    return kept


def write_dex_manifest(valid_dex, work_dir, class_cache):
    manifest = {"total_dex": len(valid_dex), "dex_files": []}
    for i, (path, size, sha1) in enumerate(valid_dex):
        manifest["dex_files"].append({
            "name": "classes.dex" if i == 0 else f"classes{i + 1}.dex",
            "source": os.path.basename(path),
            "sha1": sha1,
            "size": size,
            "class_count": len(class_cache.get(path, set())),
        })
    path = os.path.join(work_dir, "dex_manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"  dex_manifest.json → {path}")


def write_duplicate_class_report(valid_dex, work_dir, class_cache):
    class_to_files = {}
    for dex_path, _, _ in valid_dex:
        for cls in class_cache.get(dex_path, set()):
            class_to_files.setdefault(cls, []).append(os.path.basename(dex_path))

    dups = {k: v for k, v in class_to_files.items() if len(v) > 1}
    if not dups:
        return 0

    path = os.path.join(work_dir, "duplicate_classes.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"重复类报告 ({len(dups)} 个类出现在多个 DEX 中)\n")
        f.write("=" * 60 + "\n\n")
        for cls, files in sorted(dups.items()):
            f.write(f"{cls}\n")
            for fn in files:
                f.write(f"  ← {fn}\n")
            f.write("\n")
    print(f"  duplicate_classes.txt → {path}")
    return len(dups)


def collect_valid_so(dump_dir):
    so_by_name = {}
    for root, dirs, files in os.walk(dump_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not f.lower().endswith(".so"):
                continue
            path = os.path.join(root, f)
            try:
                if os.path.getsize(path) < SO_MIN_SIZE:
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
                if not validate_elf_deep(data):
                    continue
            except Exception:
                continue
            so_by_name[f.lower()] = path
    return so_by_name


def replace_so_files(apk_dir, dump_dir, drop_unmatched=False):
    so_map = collect_valid_so(dump_dir)
    print(f"  有效 SO: {len(so_map)} 个")

    lib_dir = os.path.join(apk_dir, "lib")
    if not os.path.isdir(lib_dir):
        print("  APK 无 native lib")
        return 0, 0

    replaced = 0
    kept = 0
    for root, _, files in os.walk(lib_dir):
        for f in list(files):
            if not f.lower().endswith(".so"):
                continue
            path = os.path.join(root, f)
            key = f.lower()
            if key in so_map:
                shutil.copy2(so_map[key], path)
                replaced += 1
            elif drop_unmatched:
                os.remove(path)
            else:
                kept += 1
    return replaced, kept


def remove_original_dex_files(extract_dir):
    for f in list(os.listdir(extract_dir)):
        if f.lower().startswith("classes") and f.lower().endswith(".dex"):
            os.remove(os.path.join(extract_dir, f))


def copy_dex_to_dir(valid_dex, extract_dir):
    for i, (src, _, _) in enumerate(valid_dex):
        target_name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
        shutil.copy2(src, os.path.join(extract_dir, target_name))


def repack_apk(apk_dir, output_path):
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_STORED) as zf:
        for root, dirs, files in os.walk(apk_dir):
            dirs.sort()
            files.sort()
            for f in files:
                file_path = os.path.join(root, f)
                arcname = os.path.relpath(file_path, apk_dir).replace("\\", "/")
                zf.write(file_path, arcname)
    return output_path


def write_dex_only_apk(valid_dex, output_path):
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_STORED) as zf:
        for i, (src, _, _) in enumerate(valid_dex):
            arcname = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            zf.write(src, arcname)
    return output_path


def default_output_path(args, work_dir):
    if args.output:
        return os.path.abspath(args.output)
    if args.from_local:
        base = os.path.splitext(os.path.basename(args.pkg_or_apk))[0]
    else:
        base = args.pkg_or_apk
    suffix = "_dexonly.apk" if args.dex_only else "_repacked.apk"
    return os.path.abspath(os.path.join(work_dir, f"{base}{suffix}"))


def main():
    parser = argparse.ArgumentParser(description="APK 重打包：替换 DEX/SO 后重新打包，供 jadx 静态分析")
    parser.add_argument("pkg_or_apk", nargs="?", help="包名 或 --from-local 时的 APK 路径")
    parser.add_argument("dump_dir", nargs="?", help="dump 输出目录")
    parser.add_argument("-o", "--output", help="输出 APK 路径")
    parser.add_argument("--adb", default="adb", help="ADB 路径 (默认: adb)")
    parser.add_argument("--host", default="", help="ADB remote host:port")
    parser.add_argument("--from-local", action="store_true", help="从本地 APK 文件而非设备拉取")
    parser.add_argument("--work-dir", default="", help="工作目录 (默认: dump_dir/repack/)")
    parser.add_argument("--replace-so", action="store_true", help="替换 dump SO 到 APK（默认不处理）")
    parser.add_argument("--drop-unmatched-so", action="store_true", help="删除未匹配的原始 SO（默认保留）")
    parser.add_argument("--keep-all-dex", action="store_true", help="全部 DEX 塞入，不做 SHA-1 去重")
    parser.add_argument("--quick-dex-check", action="store_true", help="只做 DEX header 快检，跳过深度校验，速度更快")
    parser.add_argument("--report", action="store_true", help="生成 dex_manifest/duplicate_classes，较慢，默认关闭")
    parser.add_argument("--strict-classes", action="store_true", help="跳过不贡献新类的 DEX，实验性，会解析所有类，较慢")
    parser.add_argument("--dex-only", action="store_true", help="只输出 classes*.dex 的 APK/ZIP，给 jadx 分析最快")

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
    output_path = default_output_path(args, work_dir)

    print("[1/6] 收集 DEX 文件...")
    valid_dex = collect_valid_dex(
        dump_dir,
        dedup=not args.keep_all_dex,
        quick=args.quick_dex_check,
    )
    print(f"  有效 DEX: {len(valid_dex)} 个")

    class_cache = None
    if args.report or args.strict_classes:
        print("[2/6] 解析 DEX 类名...")
        class_cache = build_class_cache(valid_dex)
        if args.strict_classes:
            valid_dex = apply_strict_class_file_dedup(valid_dex, class_cache)
            print(f"  class-level 去重后 DEX: {len(valid_dex)} 个")
        if args.report:
            write_dex_manifest(valid_dex, work_dir, class_cache)
            dups = write_duplicate_class_report(valid_dex, work_dir, class_cache)
            if dups:
                print(f"  重复类报告: {dups} 个类出现在多个 DEX 中")
    else:
        print("[2/6] 跳过类名报告（使用 --report 启用）")

    if args.dex_only:
        print("[3/6] 生成 dex-only APK...")
        write_dex_only_apk(valid_dex, output_path)
        print(f"  完成: {output_path}")
        print(f"\n可直接拖入 jadx: {output_path}")
        return

    print("[3/6] 原 APK...")
    if args.from_local:
        apk_path = args.pkg_or_apk
        if not os.path.exists(apk_path):
            print(f"错误: APK 文件不存在: {apk_path}")
            sys.exit(1)
    else:
        apk_path = pull_apk(args.adb, args.host, args.pkg_or_apk, work_dir)
        if not apk_path:
            sys.exit(1)

    print("[4/6] 解压 APK...")
    extract_dir = extract_apk(apk_path)
    try:
        print("[5/6] 替换 DEX/SO...")
        remove_signature_files(extract_dir)
        remove_original_dex_files(extract_dir)
        copy_dex_to_dir(valid_dex, extract_dir)
        print(f"  DEX: {len(valid_dex)} 个放入 APK")

        if args.replace_so:
            rep_so, skip_so = replace_so_files(extract_dir, dump_dir, args.drop_unmatched_so)
            print(f"  SO: {rep_so} 替换, {skip_so} 保留")
        else:
            print("  跳过 SO 替换 (使用 --replace-so 启用)")

        print("[6/6] 重压缩 APK...")
        repack_apk(extract_dir, output_path)
        print(f"  完成: {output_path}")
        print(f"\n可直接拖入 jadx: {output_path}")
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
