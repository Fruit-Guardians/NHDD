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
import hashlib
import json
import os
import re
import shutil
import struct
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


# 收集时跳过的目录
SKIP_DIRS = {"bad", "invalid", "repack", "backup", "raw", "__pycache__"}
# DEX 收集优先级子目录
DEX_CANDIDATE_SUBDIRS = ["dex/jadx-ready", "dex/fixed", "dex"]


def collect_valid_dex(dump_dir, dedup=True):
    """收集 dump 目录中有效的 DEX 文件。dedup=True 时文件级 SHA-1 去重。"""
    all_dex = []
    # 优先从候选子目录收集
    for sub in DEX_CANDIDATE_SUBDIRS:
        sub_path = os.path.join(dump_dir, sub)
        if os.path.isdir(sub_path):
            for root, dirs, files in os.walk(sub_path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    if f.lower().endswith(".dex"):
                        all_dex.append(os.path.join(root, f))
    # 如果候选目录没有，fallback 到整个 dump_dir
    if not all_dex:
        for root, dirs, files in os.walk(dump_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                if f.lower().endswith(".dex"):
                    all_dex.append(os.path.join(root, f))

    valid = []
    seen_sha1 = set()
    dedup_skipped = 0

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

        # SHA-1 去重（默认开启，--keep-all-dex 关闭）
        if dedup:
            sha1 = hashlib.sha1(data).hexdigest()
            if sha1 in seen_sha1:
                dedup_skipped += 1
                continue
            seen_sha1.add(sha1)
            valid.append((path, os.path.getsize(path), sha1))
        else:
            valid.append((path, os.path.getsize(path), hashlib.sha1(data).hexdigest()))

    if dedup_skipped:
        print(f"  SHA-1 去重跳过: {dedup_skipped} 个重复 DEX")

    # 按大小降序
    valid.sort(key=lambda x: x[1], reverse=True)
    return [(p, s, h) for p, s, h in valid]


# ---------------------------------------------------------------------------
# DEX 类名提取 + 重复报告
# ---------------------------------------------------------------------------
def _read_uleb128(data, offset):
    """读取 ULEB128 编码值, 返回 (value, next_offset)。"""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7f) << shift
        offset += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset


def extract_class_names(dex_path):
    """解析 DEX class_defs → type_ids → string_ids, 提取类描述符集合。"""
    with open(dex_path, 'rb') as f:
        data = f.read()
    if len(data) < 0x70:
        return set()

    # 读取 DEX header 关键字段
    string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
    string_ids_size = struct.unpack_from('<I', data, 0x40)[0]
    type_ids_off = struct.unpack_from('<I', data, 0x44)[0]
    type_ids_size = struct.unpack_from('<I', data, 0x48)[0]
    class_defs_off = struct.unpack_from('<I', data, 0x64)[0]
    class_defs_size = struct.unpack_from('<I', data, 0x68)[0]

    if any(v >= len(data) for v in [string_ids_off, type_ids_off, class_defs_off]):
        return set()
    if class_defs_size == 0 or string_ids_size == 0 or type_ids_size == 0:
        return set()

    # 读取 type_ids (每个是 string_ids 索引)
    type_list = []
    for i in range(min(type_ids_size, (len(data) - type_ids_off) // 4)):
        type_list.append(struct.unpack_from('<I', data, type_ids_off + i * 4)[0])

    classes = set()
    entry_size = 32  # class_def_item 固定 32 字节
    for i in range(min(class_defs_size, (len(data) - class_defs_off) // entry_size)):
        entry = class_defs_off + i * entry_size
        class_idx = struct.unpack_from('<I', data, entry)[0]
        if class_idx >= len(type_list):
            continue
        string_idx = type_list[class_idx]
        # 边界检查: string_ids 表访问必须在文件内
        sid_off = string_ids_off + string_idx * 4
        if sid_off + 4 > len(data):
            continue
        stroff = struct.unpack_from('<I', data, sid_off)[0]
        if stroff >= len(data):
            continue
        _, desc_start = _read_uleb128(data, stroff)
        desc_end = data.index(0, desc_start) if 0 in data[desc_start:] else len(data)
        desc = data[desc_start:desc_end].decode('utf-8', errors='replace')
        if desc.startswith('L') and desc.endswith(';'):
            classes.add(desc)

    return classes


def _write_dex_manifest(valid_dex, work_dir):
    """生成 dex_manifest.json"""
    manifest = {
        "total_dex": len(valid_dex),
        "dex_files": []
    }
    for i, (path, size, sha1) in enumerate(valid_dex):
        try:
            classes = extract_class_names(path)
        except Exception:
            classes = set()  # 单个 DEX 解析失败不阻塞整体报告
        manifest["dex_files"].append({
            "name": f"classes{'.dex' if i == 0 else str(i+1) + '.dex'}",
            "source": os.path.basename(path),
            "sha1": sha1,
            "size": size,
            "class_count": len(classes),
        })
    path = os.path.join(work_dir, "dex_manifest.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"  dex_manifest.json → {path}")
    return manifest


def _write_duplicate_class_report(valid_paths, work_dir):
    """生成 duplicate_classes.txt"""
    class_to_files = {}
    for dex_path in valid_paths:
        classes = extract_class_names(dex_path)
        for cls in classes:
            class_to_files.setdefault(cls, []).append(os.path.basename(dex_path))

    # 只列出出现在多个 DEX 中的类
    dups = {k: v for k, v in class_to_files.items() if len(v) > 1}
    if not dups:
        return 0

    path = os.path.join(work_dir, "duplicate_classes.txt")
    with open(path, 'w', encoding='utf-8') as f:
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


def replace_so_files(apk_dir, dump_dir, drop_unmatched=False):
    """替换 APK 中匹配的 SO, 不匹配的默认保留。--drop-unmatched-so 才删除。"""
    so_map = collect_valid_so(dump_dir)
    print(f"  有效 SO: {len(so_map)} 个")

    lib_dir = os.path.join(apk_dir, "lib")
    if not os.path.isdir(lib_dir):
        print("  APK 无 native lib")
        return 0, 0

    replaced = 0
    kept = 0
    for root, dirs, files in os.walk(lib_dir):
        for f in list(files):
            if not f.lower().endswith(".so"):
                continue
            path = os.path.join(root, f)
            key = f.lower()
            if key in so_map:
                shutil.copy2(so_map[key], path)
                replaced += 1
            elif drop_unmatched:
                os.remove(path)  # 显式要求才删除
            else:
                kept += 1  # 默认保留原始 SO

    return replaced, kept


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
    parser.add_argument("--replace-so", action="store_true",
                        help="替换 dump SO 到 APK（默认不处理）")
    parser.add_argument("--drop-unmatched-so", action="store_true",
                        help="删除未匹配的原始 SO（默认保留）")
    parser.add_argument("--keep-all-dex", action="store_true",
                        help="全部 DEX 塞入，不做 SHA-1 去重（默认: 文件级去重）")
    parser.add_argument("--strict-classes", action="store_true",
                        help="class-level 去重（同 descriptor 只保留一个版本，实验性）")

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

        # Step 4: 收集并替换 DEX
        print("[4/5] 收集 DEX 文件...")
        dedup = not args.keep_all_dex
        valid_dex = collect_valid_dex(dump_dir, dedup=dedup)
        print(f"  有效 DEX: {len(valid_dex)} 个")

        # 删除原始 DEX，放入 dump DEX
        for f in list(os.listdir(extract_dir)):
            if f.lower().startswith("classes") and f.lower().endswith(".dex"):
                os.remove(os.path.join(extract_dir, f))
        for i, (src, size, sha1) in enumerate(valid_dex):
            target_name = "classes.dex" if i == 0 else f"classes{i+1}.dex"
            shutil.copy2(src, os.path.join(extract_dir, target_name))
        print(f"  DEX: {len(valid_dex)} 个放入 APK")

        # 生成分析报告
        if valid_dex:
            try:
                _write_dex_manifest(valid_dex, work_dir)
            except Exception as e:
                print(f"  [warning] dex_manifest.json 生成失败: {e}")
            try:
                dups = _write_duplicate_class_report([p for p, _, _ in valid_dex], work_dir)
                if dups:
                    print(f"  重复类报告: {dups} 个类出现在多个 DEX 中")
            except Exception as e:
                print(f"  [warning] duplicate_classes.txt 生成失败: {e}")

        # Step 5: (可选) 替换 SO
        if args.replace_so:
            print("[5/5] 替换 SO 文件...")
            rep_so, skip_so = replace_so_files(extract_dir, dump_dir, args.drop_unmatched_so)
            print(f"  SO: {rep_so} 替换, {skip_so} 保留")
        else:
            print("[5/5] 跳过 SO 替换 (使用 --replace-so 启用)")

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
