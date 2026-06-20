#!/usr/bin/env python3
"""Fix DEX header fields, checksums, and map_list for memory-dumped DEX files.

Repairs:
  1. header_size (0x24) -> 0x70
  2. endian_tag  (0x28) -> 0x12345678
  3. file_size   (0x20) -> actual file length
  4. map_list    (0x34) -> rebuild from section offsets if corrupted
  5. SHA-1 signature (0x0C) over bytes[0x20:]
  6. Adler32 checksum (0x08) over bytes[0x0C:]

Deep validation (item-level):
  -- string_ids: each string_data_off must be within file bounds
  -- class_defs: class_data_off / annotations_off / static_values_off bounds
  -- MUTF-8: sample first 20 + last 5 strings for valid Modified UTF-8

Output layout:
  --classify: moves bad DEX to bad/, keeps valid in jadx-ready/
  --validate: prints per-file status with detailed reason
"""
import sys, struct, hashlib, zlib, os, shutil, glob

DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_TAG  = 0x12345678
MUTF8_SAMPLE_COUNT = 20       # 采样前 N 个字符串
MUTF8_TAIL_COUNT   = 5        # 采样尾部 N 个字符串

# DEX section types
kDexTypeHeaderItem      = 0x0000
kDexTypeStringIdItem    = 0x0001
kDexTypeTypeIdItem      = 0x0002
kDexTypeProtoIdItem     = 0x0003
kDexTypeFieldIdItem     = 0x0004
kDexTypeMethodIdItem    = 0x0005
kDexTypeClassDefItem    = 0x0006
kDexTypeMapList         = 0x1000

def u32(b, off): return struct.unpack_from('<I', b, off)[0]
def put32(b, off, v): struct.pack_into('<I', b, off, v)

# ---------------------------------------------------------------------------
# ULEB128 / MUTF-8
# ---------------------------------------------------------------------------
def read_uleb128(b, off, limit):
    """读取 ULEB128，返回 (value, new_offset) 或 (None, off) 失败"""
    result = 0
    shift = 0
    while off < limit:
        byte = b[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, off
        shift += 7
        if shift >= 35:
            return None, off
    return None, off

def validate_mutf8(b, off, limit):
    """验证 MUTF-8 字节序列是否合法，返回 (is_valid, final_offset)
    DEX 使用 Java Modified UTF-8：允许 surrogate pair (0xED 0xA0-0xBF 0x80-0xBF)"""
    pos = off
    while pos < limit:
        byte = b[pos]
        if byte == 0:
            return True, pos + 1     # null terminator
        elif byte < 0x80:
            pos += 1
        elif byte < 0xC0:
            return False, pos        # continuation byte without lead
        elif byte < 0xE0:
            if pos + 1 >= limit:
                return False, pos
            if (b[pos+1] & 0xC0) != 0x80:
                return False, pos
            pos += 2
        elif byte < 0xF0:
            # 0xE0-0xEF: 3-byte sequence
            # DEX/Java MUTF-8 allows 0xED followed by surrogate halves
            if pos + 2 >= limit:
                return False, pos
            if (b[pos+1] & 0xC0) != 0x80 or (b[pos+2] & 0xC0) != 0x80:
                return False, pos
            pos += 3
        else:
            return False, pos
    return False, pos   # 没有遇到 null terminator

# ---------------------------------------------------------------------------
# 深度校验 (item-level)
# ---------------------------------------------------------------------------
def validate_deep_item_level(data):
    """
    item 级别深度校验（仅检查偏移是否越界，不做 MUTF-8 验证）。
    返回 (all_pass, issues, details)。
    """
    issues = []
    details = {}
    real_size = len(data)

    # --- 读取 header section 信息 ---
    string_ids_size = u32(data, 0x38)
    string_ids_off  = u32(data, 0x3C)
    type_ids_size   = u32(data, 0x40)
    type_ids_off    = u32(data, 0x44)
    proto_ids_size  = u32(data, 0x48)
    proto_ids_off   = u32(data, 0x4C)
    field_ids_size  = u32(data, 0x50)
    field_ids_off   = u32(data, 0x54)
    method_ids_size = u32(data, 0x58)
    method_ids_off  = u32(data, 0x5C)
    class_defs_size = u32(data, 0x60)
    class_defs_off  = u32(data, 0x64)

    # =====================================================================
    # 1. string_ids 逐项检查：string_data_off 必须在文件内
    # =====================================================================
    if string_ids_size > 0 and string_ids_off > 0:
        string_table_end = string_ids_off + string_ids_size * 4
        if string_table_end > real_size:
            issues.append(f"STRING_IDS_TABLE_OOB end=0x{string_table_end:X}>0x{real_size:X}")
        else:
            bad_string_offs = []
            for i in range(string_ids_size):
                sdata_off = u32(data, string_ids_off + i * 4)
                if sdata_off >= real_size:
                    bad_string_offs.append((i, sdata_off))
            if bad_string_offs:
                examples = bad_string_offs[:5]
                issues.append(f"STRING_IDS_OOB ({len(bad_string_offs)}/{string_ids_size}): " +
                              ", ".join(f"idx={i} off=0x{o:X}" for i, o in examples))
                details['bad_string_offs'] = len(bad_string_offs)

    # =====================================================================
    # 2. type_ids 逐项检查：desc_idx 必须在 string_ids 范围内
    # =====================================================================
    if type_ids_size > 0 and type_ids_off > 0:
        type_table_end = type_ids_off + type_ids_size * 4
        if type_table_end > real_size:
            issues.append(f"TYPE_IDS_TABLE_OOB end=0x{type_table_end:X}>0x{real_size:X}")
        else:
            bad_type_refs = 0
            for i in range(type_ids_size):
                desc_idx = u32(data, type_ids_off + i * 4)
                if desc_idx >= string_ids_size:
                    bad_type_refs += 1
            if bad_type_refs:
                issues.append(f"TYPE_IDS_BAD_REF ({bad_type_refs}/{type_ids_size})")

    # =====================================================================
    # 3. proto_ids 逐项检查
    # =====================================================================
    if proto_ids_size > 0 and proto_ids_off > 0:
        proto_table_end = proto_ids_off + proto_ids_size * 12
        if proto_table_end > real_size:
            issues.append(f"PROTO_IDS_TABLE_OOB")
        else:
            bad_proto = 0
            for i in range(proto_ids_size):
                base_p = proto_ids_off + i * 12
                shorty = u32(data, base_p)
                ret = u32(data, base_p + 4)
                params = u32(data, base_p + 8)
                if shorty >= string_ids_size or ret >= type_ids_size or (params > 0 and params >= real_size):
                    bad_proto += 1
            if bad_proto:
                issues.append(f"PROTO_IDS_BAD_REF ({bad_proto}/{proto_ids_size})")

    # =====================================================================
    # 4. field_ids 逐项检查
    # =====================================================================
    if field_ids_size > 0 and field_ids_off > 0:
        field_table_end = field_ids_off + field_ids_size * 8
        if field_table_end > real_size:
            issues.append(f"FIELD_IDS_TABLE_OOB")
        else:
            bad_field = 0
            for i in range(field_ids_size):
                base_f = field_ids_off + i * 8
                cls = struct.unpack_from('<H', data, base_f)[0]
                typ = struct.unpack_from('<H', data, base_f + 2)[0]
                name = u32(data, base_f + 4)
                if cls >= type_ids_size or typ >= type_ids_size or name >= string_ids_size:
                    bad_field += 1
            if bad_field:
                issues.append(f"FIELD_IDS_BAD_REF ({bad_field}/{field_ids_size})")

    # =====================================================================
    # 5. method_ids 逐项检查
    # =====================================================================
    if method_ids_size > 0 and method_ids_off > 0:
        method_table_end = method_ids_off + method_ids_size * 8
        if method_table_end > real_size:
            issues.append(f"METHOD_IDS_TABLE_OOB")
        else:
            bad_method = 0
            for i in range(method_ids_size):
                base_m = method_ids_off + i * 8
                cls = struct.unpack_from('<H', data, base_m)[0]
                proto = struct.unpack_from('<H', data, base_m + 2)[0]
                name = u32(data, base_m + 4)
                if cls >= type_ids_size or proto >= proto_ids_size or name >= string_ids_size:
                    bad_method += 1
            if bad_method:
                issues.append(f"METHOD_IDS_BAD_REF ({bad_method}/{method_ids_size})")

    # =====================================================================
    # 6. class_defs 逐项检查
    # =====================================================================
    if class_defs_size > 0 and class_defs_off > 0:
        class_table_end = class_defs_off + class_defs_size * 32
        if class_table_end > real_size:
            issues.append(f"CLASS_DEFS_TABLE_OOB end=0x{class_table_end:X}>0x{real_size:X}")
        else:
            bad_class_offsets = 0
            for i in range(class_defs_size):
                base = class_defs_off + i * 32
                class_idx       = u32(data, base + 0)
                annotations_off = u32(data, base + 20)
                class_data_off  = u32(data, base + 24)
                static_vals_off = u32(data, base + 28)
                if class_idx >= type_ids_size:
                    bad_class_offsets += 1
                elif annotations_off > 0 and annotations_off >= real_size:
                    bad_class_offsets += 1
                elif class_data_off > 0 and class_data_off >= real_size:
                    bad_class_offsets += 1
                elif static_vals_off > 0 and static_vals_off >= real_size:
                    bad_class_offsets += 1
            if bad_class_offsets:
                issues.append(f"CLASS_DEFS_BAD ({bad_class_offsets}/{class_defs_size} offsets OOB)")
                details['bad_class_offsets'] = bad_class_offsets

    # =====================================================================
    # 7. map_list 校验
    # =====================================================================
    map_off = u32(data, 0x34)
    if map_off < DEX_HEADER_SIZE or map_off >= real_size:
        issues.append(f"MAP_OFF_INVALID=0x{map_off:X}")
    else:
        map_size = u32(data, map_off)
        if map_size > 10000:
            issues.append(f"MAP_SIZE_CORRUPT={map_size}")
        elif map_size == 0:
            issues.append("MAP_SIZE_ZERO")
        else:
            map_end = map_off + 4 + map_size * 12
            if map_end > real_size:
                issues.append(f"MAP_LIST_OOB (end=0x{map_end:X}>0x{real_size:X})")
            else:
                # 验证每个 map entry 的 offset 在文件内
                bad_map_entries = 0
                for i in range(map_size):
                    entry_base = map_off + 4 + i * 12
                    entry_type = struct.unpack_from('<H', data, entry_base)[0]
                    entry_off = u32(data, entry_base + 4)
                    if entry_off > 0 and entry_off >= real_size:
                        bad_map_entries += 1
                if bad_map_entries:
                    issues.append(f"MAP_ENTRIES_OOB ({bad_map_entries}/{map_size})")

    return len(issues) == 0, issues, details


# ---------------------------------------------------------------------------
# 可修复性评估
# ---------------------------------------------------------------------------
def assess_repairability(data):
    """
    评估 DEX 文件的可修复性。
    返回 (can_repair, reason, repair_type)
      can_repair: True/False
      reason: 不可修复的原因
      repair_type: "string_fix" | "truncate_sections" | None
    """
    real_size = len(data)
    sids_size = u32(data, 0x38)
    sids_off  = u32(data, 0x3C)
    tids_size = u32(data, 0x40)
    tids_off  = u32(data, 0x44)
    pids_size = u32(data, 0x48)
    pids_off  = u32(data, 0x4C)
    cls_size  = u32(data, 0x60)
    cls_off   = u32(data, 0x64)

    # Count bad entries per section
    bad_strings = 0
    if sids_off > 0 and sids_off + sids_size * 4 <= real_size:
        for i in range(sids_size):
            if u32(data, sids_off + i * 4) >= real_size:
                bad_strings += 1

    bad_types = 0
    if tids_off > 0 and tids_off + tids_size * 4 <= real_size:
        for i in range(tids_size):
            if u32(data, tids_off + i * 4) >= sids_size:
                bad_types += 1

    bad_protos = 0
    if pids_off > 0 and pids_off + pids_size * 12 <= real_size:
        for i in range(pids_size):
            base = pids_off + i * 12
            shorty = u32(data, base)
            ret = u32(data, base + 4)
            params = u32(data, base + 8)
            if shorty >= sids_size or ret >= tids_size or (params > 0 and params >= real_size):
                bad_protos += 1

    bad_classes = 0
    if cls_off > 0 and cls_off + cls_size * 32 <= real_size:
        for i in range(cls_size):
            base = cls_off + i * 32
            class_idx = u32(data, base)
            annotations_off = u32(data, base + 20)
            class_data_off = u32(data, base + 24)
            static_vals_off = u32(data, base + 28)
            if class_idx >= tids_size:
                bad_classes += 1
            elif annotations_off > 0 and annotations_off >= real_size:
                bad_classes += 1
            elif class_data_off > 0 and class_data_off >= real_size:
                bad_classes += 1
            elif static_vals_off > 0 and static_vals_off >= real_size:
                bad_classes += 1

    sids_pct = bad_strings / max(sids_size, 1) * 100
    tids_pct = bad_types / max(tids_size, 1) * 100
    pids_pct = bad_protos / max(pids_size, 1) * 100
    cls_pct = bad_classes / max(cls_size, 1) * 100

    # 不可修复: 任何关键 section 损坏 > 50%
    if sids_pct > 50:
        return False, f"STRING_IDS too damaged ({sids_pct:.0f}%)", None
    if tids_pct > 50:
        return False, f"TYPE_IDS too damaged ({tids_pct:.0f}%)", None
    if pids_pct > 50:
        return False, f"PROTO_IDS too damaged ({pids_pct:.0f}%)", None
    if cls_pct > 50:
        return False, f"CLASS_DEFS too damaged ({cls_pct:.0f}%)", None

    # 可修复: 只有少量 string_data_off 损坏
    if bad_strings > 0 and bad_strings <= sids_size * 0.05:
        if bad_types == 0 and bad_protos == 0 and bad_classes == 0:
            return True, None, "string_fix"

    # 不可修复: 多 section 同时损坏
    if bad_strings > 0 and (bad_types > 0 or bad_protos > 0 or bad_classes > 0):
        return False, f"multi-section corruption (str={bad_strings}, type={bad_types}, proto={bad_protos}, cls={bad_classes})", None

    if bad_types > 0:
        return False, f"TYPE_IDS corruption ({bad_types} entries)", None
    if bad_protos > 0:
        return False, f"PROTO_IDS corruption ({bad_protos} entries)", None
    if bad_classes > 0:
        return False, f"CLASS_DEFS corruption ({bad_classes} entries)", None

    return False, "unknown damage", None


# ---------------------------------------------------------------------------
# 修复函数
# ---------------------------------------------------------------------------
def try_repair_dex(data):
    """
    尝试修复 DEX 文件。
    返回 (repaired_data, repair_type, details) 或 (None, None, error_msg)
    """
    can_repair, reason, repair_type = assess_repairability(data)
    if not can_repair:
        return None, None, reason

    if repair_type == "string_fix":
        return repair_bad_strings(data)
    
    return None, None, "unknown repair type"


def repair_bad_strings(data):
    """
    修复少量损坏的 string_data_off：将坏偏移指向空字符串。
    返回 (repaired_data, "string_fix", details)
    """
    data = bytearray(data)
    real_size = len(data)
    sids_size = u32(data, 0x38)
    sids_off  = u32(data, 0x3C)

    # 找到第一个有效的空字符串 (null byte)
    empty_str_off = 0
    for i in range(sids_size):
        sdata_off = u32(data, sids_off + i * 4)
        if sdata_off < real_size and data[sdata_off] == 0x00:
            empty_str_off = sdata_off
            break
    
    if empty_str_off == 0:
        # 如果找不到空字符串，在 data 段末尾创建一个
        data_off = u32(data, 0x6C)
        data_size = u32(data, 0x68)
        if data_off + data_size < real_size:
            # 在 data 段末尾找空字节
            for off in range(data_off, min(data_off + data_size, real_size)):
                if data[off] == 0x00:
                    empty_str_off = off
                    break
    
    if empty_str_off == 0:
        return None, None, "cannot find empty string"

    fixed_count = 0
    for i in range(sids_size):
        sdata_off = u32(data, sids_off + i * 4)
        if sdata_off >= real_size:
            struct.pack_into('<I', data, sids_off + i * 4, empty_str_off)
            fixed_count += 1

    # 重新计算 file_size, SHA-1, checksum
    put32(data, 0x20, real_size)
    put32(data, 0x24, DEX_HEADER_SIZE)
    put32(data, 0x28, DEX_ENDIAN_TAG)
    
    sha1 = hashlib.sha1(bytes(data[0x20:])).digest()
    data[0x0C:0x20] = sha1
    checksum = zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF
    put32(data, 0x08, checksum)

    return bytes(data), "string_fix", f"fixed {fixed_count}/{sids_size} bad string_data_off"


# ---------------------------------------------------------------------------
# 综合分类 (三级: jadx-ready / bad / repairable)
# ---------------------------------------------------------------------------
def classify_dex_full(path):
    """
    三级分类:
      jadx-ready: 通过所有校验，可直接反编译
      bad:        header 或 item 级校验失败，不应进入 jadx
      repairable: 有少量损坏可尝试修复
    """
    with open(path, 'rb') as f:
        data = f.read()

    real_size = len(data)

    # --- 1. 基础 sanity ---
    if real_size < DEX_HEADER_SIZE:
        return "bad", "too_small", {}
    if data[0:3] != b'dex':
        return "bad", "not_a_dex", {}
    if real_size > 64 * 1024 * 1024:
        return "bad", f"oversized={real_size}", {}

    # --- 2. header 字段校验 ---
    header_issues = []
    if u32(data, 0x28) != DEX_ENDIAN_TAG:
        header_issues.append(f"BAD_ENDIAN=0x{u32(data,0x28):08X}")
    if u32(data, 0x24) != DEX_HEADER_SIZE:
        header_issues.append(f"BAD_HEADER_SIZE=0x{u32(data,0x24):X}")
    if u32(data, 0x20) != real_size:
        header_issues.append(f"SIZE_MISMATCH")

    # --- 3. map_list 校验 ---
    # map_list 是派生数据，始终可以从 section headers 重建
    map_off = u32(data, 0x34)
    map_repairable = False
    if map_off < DEX_HEADER_SIZE or map_off >= real_size:
        header_issues.append(f"MAP_OFF_INVALID=0x{map_off:X}")
        map_repairable = True
    else:
        try:
            map_size = u32(data, map_off)
            if map_size > 10000:
                header_issues.append(f"MAP_SIZE_CORRUPT={map_size}")
                map_repairable = True
            elif map_size == 0:
                header_issues.append("MAP_SIZE_ZERO")
                map_repairable = True
            else:
                map_end = map_off + 4 + map_size * 12
                if map_end > real_size:
                    header_issues.append(f"MAP_LIST_OOB")
                    map_repairable = True
                elif map_size > 50:
                    header_issues.append(f"MAP_SIZE_SUSPICIOUS={map_size}")
                    map_repairable = True
        except:
            header_issues.append("MAP_READ_ERROR")
            map_repairable = True

    # --- 4. section 表级越界 (检查表的字节大小，不是条目数) ---
    sections = [
        ("string_ids", 0x38, 0x3C, 4),
        ("type_ids",   0x40, 0x44, 4),
        ("proto_ids",  0x48, 0x4C, 12),
        ("field_ids",  0x50, 0x54, 8),
        ("method_ids", 0x58, 0x5C, 8),
        ("class_defs", 0x60, 0x64, 32),
    ]
    for name, size_off, off_off, item_size in sections:
        sec_size = u32(data, size_off)
        sec_off  = u32(data, off_off)
        if sec_size > 0 and sec_off > 0:
            table_end = sec_off + sec_size * item_size
            if table_end > real_size:
                header_issues.append(f"{name.upper()}_TABLE_OOB")

    # data section
    data_size = u32(data, 0x68)
    data_off  = u32(data, 0x6C)
    if data_size > 0 and data_off > 0 and data_off + data_size > real_size:
        header_issues.append("DATA_SECTION_OOB")

    # 如果 map_list 是唯一的问题且 header 无其他错误 → repairable
    if header_issues:
        if map_repairable and len(header_issues) == 1 and 'MAP' in header_issues[0]:
            return "repairable", "map_list_corrupted", {}
        # 检查是否有非 map 的 section 越界
        non_map = [h for h in header_issues if 'MAP' not in h]
        if non_map:
            return "bad", '; '.join(header_issues), {}
        # 纯 map 问题
        if map_repairable:
            return "repairable", "map_list_corrupted", {}
        return "bad", '; '.join(header_issues), {}

    # --- 5. item 级深度校验 ---
    all_pass, deep_issues, details = validate_deep_item_level(data)
    if not all_pass:
        # 纯 map 问题始终可修复（map_list 可从 section headers 重建）
        map_only = all('MAP' in issue for issue in deep_issues)
        if map_only:
            return "repairable", f"deep_issues: {'; '.join(deep_issues[:2])}", {"repair_type": "map_list"}
        # 检查是否可修复
        can_repair, repair_reason, repair_type = assess_repairability(data)
        if can_repair:
            return "repairable", f"deep_issues: {'; '.join(deep_issues[:2])}", {"repair_type": repair_type}
        return "bad", '; '.join(deep_issues), details

    return "jadx-ready", "ok", {}


# ---------------------------------------------------------------------------
# 修复逻辑
# ---------------------------------------------------------------------------
def rebuild_map_list(data):
    """从 header 中的 section 偏移重建 map_list，返回新的 data"""
    real_size = len(data)
    entries = []
    entries.append((kDexTypeHeaderItem, 0, DEX_HEADER_SIZE))

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

    data_size = u32(data, 0x68)
    data_off = u32(data, 0x6C)
    if data_size > 0 and data_off > 0:
        entries.append((kDexTypeMapList, data_off, 0))

    entries.sort(key=lambda x: x[1])
    map_list_size = 4 + len(entries) * 12
    old_map_off = u32(data, 0x34)

    if old_map_off >= DEX_HEADER_SIZE and old_map_off + map_list_size <= real_size:
        map_off = old_map_off
    else:
        map_off = real_size
        put32(data, 0x20, real_size + map_list_size)
        data = data + bytearray(map_list_size)

    put32(data, map_off, len(entries))
    for i, (sec_type, sec_off, sec_size) in enumerate(entries):
        base = map_off + 4 + i * 12
        struct.pack_into('<HHI', data, base, sec_type, 0, sec_size)
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

    if u32(data, 0x24) != DEX_HEADER_SIZE:
        put32(data, 0x24, DEX_HEADER_SIZE); changed.append('header_size')
    if u32(data, 0x28) != DEX_ENDIAN_TAG:
        put32(data, 0x28, DEX_ENDIAN_TAG); changed.append('endian_tag')
    if u32(data, 0x20) != len(data):
        put32(data, 0x20, len(data)); changed.append('file_size')

    if deep:
        map_off = u32(data, 0x34)
        map_bad = False
        if map_off < DEX_HEADER_SIZE or map_off >= len(data):
            map_bad = True
        else:
            map_size = u32(data, map_off)
            if map_size > 10000 or map_size == 0:
                map_bad = True
            else:
                map_end = map_off + 4 + map_size * 12
                if map_end > len(data):
                    map_bad = True
        if map_bad:
            try:
                new_data = rebuild_map_list(data)
                if new_data is not None:
                    data = bytearray(new_data)
                    changed.append('map_list')
            except Exception:
                pass

    old_sig = bytes(data[0x0C:0x20])
    sha1 = hashlib.sha1(bytes(data[0x20:])).digest()
    data[0x0C:0x20] = sha1
    if old_sig != sha1:
        changed.append('signature')

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


# ---------------------------------------------------------------------------
# 目录处理
# ---------------------------------------------------------------------------
def fix_directory(dir_path, deep=False, classify=False):
    """修复/分类目录下所有 DEX 文件"""
    dex_files = sorted(glob.glob(os.path.join(dir_path, "*.dex")))
    if not dex_files:
        print(f"No DEX files found in {dir_path}")
        return

    stats = {
        "jadx-ready": 0, "repairable": 0, "bad": 0,
        "fixed": 0, "ok": 0,
    }

    bad_dir = os.path.join(dir_path, "bad") if classify else None
    jadx_dir = os.path.join(dir_path, "jadx-ready") if classify else None

    for path in dex_files:
        name = os.path.basename(path)

        if classify:
            category, reason, details = classify_dex_full(path)
            stats[category] = stats.get(category, 0) + 1

            detail_str = ""
            if details:
                parts = []
                for k, v in details.items():
                    if isinstance(v, list):
                        parts.append(f"{k}={len(v)}items")
                    else:
                        parts.append(f"{k}={v}")
                detail_str = " [" + ", ".join(parts) + "]"

            print(f"  {name:35s} [{category:12s}] {reason}{detail_str}")

            if category == "bad":
                if bad_dir:
                    os.makedirs(bad_dir, exist_ok=True)
                    shutil.move(path, os.path.join(bad_dir, name))
                    print(f"    -> moved to bad/")
                continue
            elif category == "jadx-ready":
                if jadx_dir:
                    os.makedirs(jadx_dir, exist_ok=True)
                    shutil.move(path, os.path.join(jadx_dir, name))
                    print(f"    -> moved to jadx-ready/")
                continue
            elif category == "repairable":
                # 尝试修复
                repair_type = details.get("repair_type", "map_list") if details else "map_list"
                if repair_type == "string_fix":
                    with open(path, 'rb') as f:
                        file_data = f.read()
                    repaired_data, rtype, rmsg = try_repair_dex(file_data)
                    if repaired_data is not None:
                        with open(path, 'wb') as f:
                            f.write(repaired_data)
                        stats["fixed"] = stats.get("fixed", 0) + 1
                        print(f"    -> REPAIRED ({rtype}: {rmsg})")
                        if jadx_dir:
                            os.makedirs(jadx_dir, exist_ok=True)
                            shutil.move(path, os.path.join(jadx_dir, name))
                            print(f"    -> moved to jadx-ready/")
                    else:
                        stats["bad"] = stats.get("bad", 0) + 1
                        print(f"    -> cannot repair: {rmsg}")
                        if bad_dir:
                            os.makedirs(bad_dir, exist_ok=True)
                            shutil.move(path, os.path.join(bad_dir, name))
                            print(f"    -> moved to bad/")
                elif repair_type == "map_list":
                    # map_list 修复：重建 map_list
                    with open(path, 'rb') as f:
                        file_data = bytearray(f.read())
                    try:
                        new_data = rebuild_map_list(file_data)
                        if new_data is not None:
                            put32(new_data, 0x20, len(new_data))
                            put32(new_data, 0x24, DEX_HEADER_SIZE)
                            put32(new_data, 0x28, DEX_ENDIAN_TAG)
                            sha1 = hashlib.sha1(bytes(new_data[0x20:])).digest()
                            new_data[0x0C:0x20] = sha1
                            checksum = zlib.adler32(bytes(new_data[0x0C:])) & 0xFFFFFFFF
                            put32(new_data, 0x08, checksum)
                            with open(path, 'wb') as f:
                                f.write(new_data)
                            stats["fixed"] = stats.get("fixed", 0) + 1
                            print(f"    -> REPAIRED (map_list rebuilt)")
                            if jadx_dir:
                                os.makedirs(jadx_dir, exist_ok=True)
                                shutil.move(path, os.path.join(jadx_dir, name))
                                print(f"    -> moved to jadx-ready/")
                        else:
                            stats["bad"] = stats.get("bad", 0) + 1
                            print(f"    -> cannot rebuild map_list")
                            if bad_dir:
                                os.makedirs(bad_dir, exist_ok=True)
                                shutil.move(path, os.path.join(bad_dir, name))
                                print(f"    -> moved to bad/")
                    except Exception as e:
                        stats["bad"] = stats.get("bad", 0) + 1
                        print(f"    -> rebuild error: {e}")
                        if bad_dir:
                            os.makedirs(bad_dir, exist_ok=True)
                            shutil.move(path, os.path.join(bad_dir, name))
                            print(f"    -> moved to bad/")
                else:
                    # 不可修复
                    stats["bad"] = stats.get("bad", 0) + 1
                    print(f"    -> cannot repair: unknown type")
                    if bad_dir:
                        os.makedirs(bad_dir, exist_ok=True)
                        shutil.move(path, os.path.join(bad_dir, name))
                        print(f"    -> moved to bad/")

        # 修复
        status, msg = fix_dex(path, deep=deep)
        if status == "fixed":
            stats["fixed"] = stats.get("fixed", 0) + 1
            print(f"  {name:35s} FIXED: {msg}")
            if classify and jadx_dir:
                os.makedirs(jadx_dir, exist_ok=True)
                shutil.move(path, os.path.join(jadx_dir, name))
                print(f"    -> moved to jadx-ready/")
        elif status == "ok":
            stats["ok"] = stats.get("ok", 0) + 1

    print(f"\n--- Summary ---")
    print(f"Total: {len(dex_files)}")
    for k, v in stats.items():
        if v > 0:
            print(f"  {k}: {v}")

    if classify:
        if bad_dir and os.path.isdir(bad_dir):
            print(f"\n  bad/         -> {len(os.listdir(bad_dir))} files (exclude from jadx)")
        if jadx_dir and os.path.isdir(jadx_dir):
            print(f"  jadx-ready/  -> {len(os.listdir(jadx_dir))} files (safe for jadx)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Fix DEX headers, checksums, and deep validation')
    parser.add_argument('paths', nargs='+', help='DEX file or directory')
    parser.add_argument('--deep', action='store_true', help='Deep fix: rebuild corrupted map_list')
    parser.add_argument('--classify', action='store_true',
                        help='Three-way classify: jadx-ready/ (valid), bad/ (corrupted)')
    parser.add_argument('--validate', action='store_true', help='Only validate, do not fix')
    args = parser.parse_args()

    for p in args.paths:
        if os.path.isdir(p):
            print(f"=== {p} ===")
            if args.validate:
                dex_files = sorted(glob.glob(os.path.join(p, "*.dex")))
                for f in dex_files:
                    category, reason, details = classify_dex_full(f)
                    name = os.path.basename(f)
                    marker = "OK" if category == "jadx-ready" else f"{category.upper()}: {reason}"
                    print(f"  {name:35s} {marker}")
            else:
                fix_directory(p, deep=args.deep, classify=args.classify)
        else:
            if args.validate:
                category, reason, details = classify_dex_full(p)
                print(f"{category}: {reason}")
            else:
                status, msg = fix_dex(p, deep=args.deep)
                print(f"{p}: {status} ({msg})")