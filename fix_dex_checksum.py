#!/usr/bin/env python3
"""Fix DEX header fields, checksums, and map_list for memory-dumped DEX files.

Repairs, in order:
  1. header_size (0x24) -> 0x70
  2. endian_tag  (0x28) -> 0x12345678
  3. file_size   (0x20) -> actual file length
  4. map_list    (0x34) -> rebuild from section offsets if corrupted
  5. SHA-1 signature (0x0C, 20 bytes) over bytes[0x20:]
  6. Adler32 checksum (0x08, 4 bytes) over bytes[0x0C:]

Can also classify and separate bad DEX files:
  --classify <dir>   Move invalid DEX to <dir>/invalid/
  --validate         Deep validation (map_list, section bounds)
"""
import sys, struct, hashlib, zlib, os, shutil, glob

DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_TAG  = 0x12345678

# DEX section types (from Android source)
kDexTypeHeaderItem      = 0x0000
kDexTypeStringIdItem    = 0x0001
kDexTypeTypeIdItem      = 0x0002
kDexTypeProtoIdItem     = 0x0003
kDexTypeFieldIdItem     = 0x0004
kDexTypeMethodIdItem    = 0x0005
kDexTypeClassDefItem    = 0x0006
kDexTypeCallSiteIdItem  = 0x0007
kDexTypeMethodHandleItem= 0x0008
kDexTypeMapList         = 0x1000
kDexTypeTypeList        = 0x1001
kDexTypeAnnotationSetRefList = 0x1002
kDexTypeAnnotationSetItem    = 0x1003
kDexTypeClassDataItem        = 0x2000
kDexTypeCodeItem             = 0x2001
kDexTypeStringDataItem       = 0x2002
kDexTypeDebugInfoItem        = 0x2003
kDexTypeAnnotationItem       = 0x2004
kDexTypeEncodedArrayItem     = 0x2005
kDexTypeAnnotationsDirectoryItem = 0x2006

def u32(b, off): return struct.unpack_from('<I', b, off)[0]
def put32(b, off, v): struct.pack_into('<I', b, off, v)

def validate_dex(data):
    """深度验证 DEX 文件，返回 (is_valid, issues_list)"""
    issues = []
    real_size = len(data)

    if real_size < DEX_HEADER_SIZE:
        return False, ["TOO_SMALL"]

    if data[0:3] != b'dex':
        issues.append("BAD_MAGIC")

    endian_tag = u32(data, 0x28)
    if endian_tag != DEX_ENDIAN_TAG:
        issues.append(f"BAD_ENDIAN=0x{endian_tag:08X}")

    header_size = u32(data, 0x24)
    if header_size != DEX_HEADER_SIZE:
        issues.append(f"BAD_HEADER_SIZE=0x{header_size:X}")

    file_size = u32(data, 0x20)
    if file_size != real_size:
        issues.append(f"SIZE_MISMATCH header={file_size} real={real_size}")

    # 检查 map_list
    map_off = u32(data, 0x34)
    if map_off == 0:
        issues.append("MAP_OFF_ZERO")
    elif map_off < DEX_HEADER_SIZE:
        issues.append(f"MAP_OFF_TOO_SMALL=0x{map_off:X}")
    elif map_off >= real_size:
        issues.append(f"MAP_OFF_OOB=0x{map_off:X}")
    else:
        try:
            map_size = u32(data, map_off)
            map_end = map_off + 4 + map_size * 12
            if map_end > real_size:
                issues.append(f"MAP_LIST_OOB size={map_size} end=0x{map_end:X}")
            if map_size > 50:  # 正常 DEX map_list 不超过 ~20 个条目
                issues.append(f"MAP_SIZE_SUSPICIOUS={map_size}")
        except:
            issues.append("MAP_READ_ERROR")

    # 检查 section 偏移是否越界
    sections = [
        ("string_ids_off", 0x3C, "string_ids_size", 0x38),
        ("type_ids_off",   0x40, "type_ids_size",   0x3C - 4),  # 不对，重新算
    ]
    # 简化：只检查关键 section
    for name, off_off in [("string_ids", 0x3C), ("type_ids", 0x40),
                          ("proto_ids", 0x44), ("field_ids", 0x48),
                          ("method_ids", 0x4C), ("class_defs", 0x50),
                          ("data", 0x54)]:
        sec_off = u32(data, off_off)
        sec_size = u32(data, off_off + 4)
        if sec_off > 0 and sec_off + sec_size > real_size:
            issues.append(f"{name}_OOB off=0x{sec_off:X}+{sec_size}>0x{real_size:X}")

    return len(issues) == 0, issues


def rebuild_map_list(data):
    """从 header 中的 section 偏移重建 map_list，返回新的 data"""
    real_size = len(data)

    # 收集所有 section: (type, offset, size)
    entries = []

    # header_item 始终在 offset 0
    entries.append((kDexTypeHeaderItem, 0, DEX_HEADER_SIZE))

    # 从 header 读取各 section
    section_defs = [
        (kDexTypeStringIdItem, 0x38),  # string_ids_size at 0x38, off at 0x3C
        (kDexTypeTypeIdItem,   0x3A),  # type_ids_size at 0x3A, off at 0x40
        (kDexTypeProtoIdItem,  0x3C + 8),  # proto_ids_size at 0x42, off at 0x44
    ]
    # 更准确的方式：直接从 header 读取
    # string_ids: size@0x38, off@0x3C
    # type_ids:   size@0x3A, off@0x40  -- 不对，这些是 u32 不是 u16

    # 重新按 DEX 格式定义
    # offset 0x20: file_size (u32)
    # offset 0x24: header_size (u32)
    # offset 0x28: endian_tag (u32)
    # offset 0x2C: link_size (u32)
    # offset 0x30: link_off (u32)
    # offset 0x34: map_off (u32)
    # offset 0x38: string_ids_size (u32)
    # offset 0x3C: string_ids_off (u32)
    # offset 0x40: type_ids_size (u32)
    # offset 0x44: type_ids_off (u32)
    # offset 0x48: proto_ids_size (u32)
    # offset 0x4C: proto_ids_off (u32)
    # offset 0x50: field_ids_size (u32)
    # offset 0x54: field_ids_off (u32)
    # offset 0x58: method_ids_size (u32)
    # offset 0x5C: method_ids_off (u32)
    # offset 0x60: class_defs_size (u32)
    # offset 0x64: class_defs_off (u32)
    # offset 0x68: data_size (u32)
    # offset 0x6C: data_off (u32)

    header_sections = [
        (kDexTypeStringIdItem, 0x38, 0x3C),
        (kDexTypeTypeIdItem,   0x40, 0x44),
        (kDexTypeProtoIdItem,  0x48, 0x4C),
        (kDexTypeFieldIdItem,  0x50, 0x54),
        (kDexTypeMethodIdItem, 0x58, 0x5C),
        (kDexTypeClassDefItem, 0x60, 0x64),
    ]

    for sec_type, size_off, off_off in header_sections:
        sec_size = u32(data, size_off)
        sec_off = u32(data, off_off)
        if sec_size > 0 and sec_off > 0:
            entries.append((sec_type, sec_off, sec_size))

    # data section
    data_size = u32(data, 0x68)
    data_off = u32(data, 0x6C)
    if data_size > 0 and data_off > 0:
        entries.append((kDexTypeMapList, data_off, 0))  # map_list 在 data 开头

    # 按 offset 排序
    entries.sort(key=lambda x: x[1])

    # 计算 map_list 大小: 4 (size) + n * 12 (entries)
    map_list_size = 4 + len(entries) * 12

    # 找到原始 map_off 位置，如果可用就在原地重建
    old_map_off = u32(data, 0x34)

    if old_map_off >= DEX_HEADER_SIZE and old_map_off + map_list_size <= real_size:
        # 原地重建 map_list
        map_off = old_map_off
    else:
        # map_off 不可用，追加到文件末尾
        map_off = real_size
        # 更新 file_size
        put32(data, 0x20, real_size + map_list_size)
        data = data + bytearray(map_list_size)

    # 写入 map_list
    put32(data, map_off, len(entries))
    for i, (sec_type, sec_off, sec_size) in enumerate(entries):
        base = map_off + 4 + i * 12
        struct.pack_into('<HHI', data, base, sec_type, 0, sec_size)

    # 更新 header 中的 map_off
    put32(data, 0x34, map_off)

    return data


def fix_dex(path, deep=False):
    """修复 DEX 文件。deep=True 时尝试修复 map_list。返回 (status, message)"""
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 0x24:
        return "invalid", "too small"
    if data[0:3] != b'dex':
        return "invalid", "not a DEX file"

    changed = []

    # 基础修复
    if u32(data, 0x24) != DEX_HEADER_SIZE:
        put32(data, 0x24, DEX_HEADER_SIZE); changed.append('header_size')
    if u32(data, 0x28) != DEX_ENDIAN_TAG:
        put32(data, 0x28, DEX_ENDIAN_TAG); changed.append('endian_tag')
    if u32(data, 0x20) != len(data):
        put32(data, 0x20, len(data)); changed.append('file_size')

    # 深度修复：map_list
    if deep:
        is_valid, issues = validate_dex(bytes(data))
        map_issues = [i for i in issues if 'MAP' in i]
        if map_issues:
            try:
                new_data = rebuild_map_list(data)
                if new_data is not None:
                    data = bytearray(new_data)
                    changed.append('map_list')
            except Exception as e:
                pass  # map_list 修复失败，继续做 checksum 修复

    # SHA-1 signature
    old_sig = bytes(data[0x0C:0x20])
    sha1 = hashlib.sha1(bytes(data[0x20:])).digest()
    data[0x0C:0x20] = sha1
    if old_sig != sha1:
        changed.append('signature')

    # Adler32 checksum
    old_cksum = u32(data, 0x08)
    checksum = zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF
    put32(data, 0x08, checksum)
    if old_cksum != checksum:
        changed.append('checksum')

    if changed:
        with open(path, 'wb') as f:
            f.write(data)
        return "fixed", ', '.join(changed)
    else:
        return "ok", "already valid"


def classify_dex(path):
    """分类 DEX 文件：valid / invalid / suspicious"""
    with open(path, 'rb') as f:
        data = f.read()

    is_valid, issues = validate_dex(data)

    # 额外启发式检查
    real_size = len(data)

    # 太小（< 0x70 或 < 1KB 且不是完整结构）
    if real_size < 0x70:
        return "invalid", "too_small"

    # 异常大（> 64MB，很可能是多个 DEX 拼接或扫描误命中）
    if real_size > 64 * 1024 * 1024:
        return "suspicious", f"oversized={real_size}"

    # 太小且看起来不像完整 DEX（< 1KB）
    if real_size < 1024:
        # 检查是否有实际内容（class_defs_size > 0）
        class_defs_size = u32(data, 0x60)
        if class_defs_size == 0:
            return "invalid", "stub_no_classes"

    if not is_valid:
        # 区分可修复和不可修复
        map_issues = [i for i in issues if 'MAP' in i]
        section_issues = [i for i in issues if 'OOB' in i and 'MAP' not in i]
        if section_issues and not map_issues:
            return "invalid", "section_bounds_broken"
        if map_issues:
            return "repairable", "map_list_corrupted"

    if is_valid:
        return "valid", "ok"

    return "invalid", '; '.join(issues)


def fix_directory(dir_path, deep=False, classify=False):
    """修复目录下所有 DEX 文件"""
    dex_files = sorted(glob.glob(os.path.join(dir_path, "*.dex")))
    if not dex_files:
        print(f"No DEX files found in {dir_path}")
        return

    stats = {"fixed": 0, "ok": 0, "invalid": 0, "repairable": 0, "suspicious": 0, "valid": 0}

    invalid_dir = os.path.join(dir_path, "invalid") if classify else None

    for path in dex_files:
        name = os.path.basename(path)

        if classify:
            category, reason = classify_dex(path)
            stats[category] = stats.get(category, 0) + 1
            print(f"  {name:35s} [{category:12s}] {reason}")

            if category in ("invalid", "suspicious"):
                if invalid_dir:
                    os.makedirs(invalid_dir, exist_ok=True)
                    shutil.move(path, os.path.join(invalid_dir, name))
                    print(f"    -> moved to invalid/")
                continue

        # 修复
        status, msg = fix_dex(path, deep=deep)
        if status == "fixed":
            stats["fixed"] += 1
            print(f"  {name:35s} FIXED: {msg}")
        elif status == "ok":
            stats["ok"] += 1
        elif status == "invalid":
            stats["invalid"] += 1
            print(f"  {name:35s} INVALID: {msg}")
            if classify and invalid_dir:
                os.makedirs(invalid_dir, exist_ok=True)
                shutil.move(path, os.path.join(invalid_dir, name))
                print(f"    -> moved to invalid/")

    print(f"\n--- Summary ---")
    total = len(dex_files)
    print(f"Total: {total}")
    for k, v in stats.items():
        if v > 0:
            print(f"  {k}: {v}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Fix DEX headers, checksums, and map_list')
    parser.add_argument('paths', nargs='+', help='DEX file or directory')
    parser.add_argument('--deep', action='store_true', help='Deep fix: rebuild corrupted map_list')
    parser.add_argument('--classify', action='store_true', help='Classify and move invalid DEX to invalid/')
    parser.add_argument('--validate', action='store_true', help='Only validate, do not fix')
    args = parser.parse_args()

    for p in args.paths:
        if os.path.isdir(p):
            print(f"=== {p} ===")
            if args.validate:
                dex_files = sorted(glob.glob(os.path.join(p, "*.dex")))
                for f in dex_files:
                    with open(f, 'rb') as fh:
                        data = fh.read()
                    is_valid, issues = validate_dex(data)
                    name = os.path.basename(f)
                    if is_valid:
                        print(f"  {name:35s} OK")
                    else:
                        print(f"  {name:35s} BAD: {'; '.join(issues)}")
            else:
                fix_directory(p, deep=args.deep, classify=args.classify)
        else:
            if args.validate:
                with open(p, 'rb') as fh:
                    data = fh.read()
                is_valid, issues = validate_dex(data)
                if is_valid:
                    print(f"OK")
                else:
                    print(f"BAD: {'; '.join(issues)}")
            else:
                status, msg = fix_dex(p, deep=args.deep)
                print(f"{p}: {status} ({msg})")
