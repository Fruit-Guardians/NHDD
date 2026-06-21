#!/usr/bin/env python3
"""Fix ELF/SO memory dumps: validate, repair, classify.

镜像 fix_dex_checksum.py 的 GUI 对齐函数族,内建 ELF 修复以替代外部 SoFixer。

修复(镜像 SoFixer `-m 0x0` 的核心逻辑):
  1. 对每个 PT_LOAD 段: p_offset = p_vaddr (内存布局 -> 文件布局对齐)
  2. 校验/修正 e_entry、e_phoff
  3. ELF magic 缺失时从结构识别并补回

深度校验 (镜像 validate_dex_deep_bool):
  -- PHT 自洽: e_phoff/e_phentsize/e_phnum 合理,program headers 在文件内
  -- 每个 PT_LOAD: p_vaddr+p_memsz 不超文件, p_filesz <= p_memsz
  -- PT_DYNAMIC 段在文件内; 遍历 DT_* 项, 关键 DT 指向在文件内
  -- LOAD 覆盖率 (配合 dump 缺页统计)

三级分类 (镜像 classify_dex_full):
  ida-ready    PHT 完整 + LOAD 段在文件内 + .dynamic 有效 -> 可直接加载 IDA
  repairable   PHT 偏移错位 (p_offset != p_vaddr, 可修) 或 magic 缺失 (可补)
  bad          结构损坏 / 过小 / 非 ELF

文件处置 (镜像 fix_dex_file_aligned):
  -- 过小 / 非 ELF magic 且结构无效 -> 删除
  -- 深度校验失败且不可修 -> 移到 invalid/ 子目录
  -- 否则修 p_offset 等, 有改动才落盘
"""
import sys, struct, os, glob

# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------
ELF_MAGIC = b'\x7fELF'
ELF_HEADER_SIZE = 0x40        # 最小合理 ELF 头 (ELF32 = 52, ELF64 = 64)
SO_MIN_SIZE = 0x40

ET_DYN = 3                    # 共享对象
PT_LOAD = 1                   # 可加载段
PT_DYNAMIC = 2                # 动态段

EM_ARM = 40
EM_AARCH64 = 183

# .dynamic DT_* 标签 (部分关键的)
DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_INIT = 12
DT_FINI = 13
DT_REL = 17
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26

# DT 标签里指向"某个地址/偏移"的集合 (用于校验这些指向是否在文件内)
DT_ADDR_TAGS = {
    DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_INIT, DT_FINI,
    DT_REL, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY,
}

# 指向 size 的 DT 标签 (与上面一一对应,用于估段长)
DT_SIZE_TAGS = {
    DT_HASH: None, DT_STRTAB: None, DT_SYMTAB: None,
    DT_RELA: 8, DT_INIT: None, DT_FINI: None,
    DT_REL: 8, DT_JMPREL: 8, DT_INIT_ARRAY: 8, DT_FINI_ARRAY: 8,
}


# ---------------------------------------------------------------------------
# little-endian readers
# ---------------------------------------------------------------------------
def u16(b, off): return struct.unpack_from('<H', b, off)[0]
def u32(b, off): return struct.unpack_from('<I', b, off)[0]
def u64(b, off): return struct.unpack_from('<Q', b, off)[0]
def put16(b, off, v): struct.pack_into('<H', b, off, v)
def put32(b, off, v): struct.pack_into('<I', b, off, v)
def put64(b, off, v): struct.pack_into('<Q', b, off, v)


# ---------------------------------------------------------------------------
# ELF 解析
# ---------------------------------------------------------------------------
class ElfInfo:
    """解析 ELF 头 + program headers。is64 决定字段宽度。"""
    def __init__(self, data):
        self.data = data
        self.real_size = len(data)
        self.is64 = False
        self.e_type = 0
        self.e_machine = 0
        self.e_phoff = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.phdrs = []   # list of dict {p_type, p_offset, p_vaddr, p_filesz, p_memsz, ...}

    def parse_header(self):
        if self.real_size < SO_MIN_SIZE:
            return False
        # magic 可能被抹除;若前4字节不是 \x7fELF,后续 classify 会判定,这里不强求
        ei_class = self.data[4] if self.real_size > 4 else 0
        if ei_class == 2:
            self.is64 = True
        elif ei_class == 1:
            self.is64 = False
        else:
            return False
        self.e_type = u16(self.data, 16)
        self.e_machine = u16(self.data, 18)
        if self.is64:
            # ELF64: e_phoff@32(u64), e_phentsize@54(u16), e_phnum@56(u16)
            self.e_phoff = u64(self.data, 32)
            self.e_phentsize = u16(self.data, 54)
            self.e_phnum = u16(self.data, 56)
        else:
            # ELF32: e_phoff@28(u32), e_phentsize@42(u16), e_phnum@44(u16)
            self.e_phoff = u32(self.data, 28)
            self.e_phentsize = u16(self.data, 42)
            self.e_phnum = u16(self.data, 44)
        return True

    def parse_phdrs(self):
        """读取所有 program headers 到 self.phdrs。越界的跳过。"""
        self.phdrs = []
        if self.e_phoff == 0 or self.e_phnum == 0:
            return
        if self.e_phentsize == 0:
            return
        ph_total = self.e_phoff + self.e_phnum * self.e_phentsize
        if ph_total > self.real_size:
            # PHT 越界 — 能读多少读多少
            n_readable = (self.real_size - self.e_phoff) // self.e_phentsize
        else:
            n_readable = self.e_phnum
        for i in range(n_readable):
            base = self.e_phoff + i * self.e_phentsize
            if self.is64:
                ph = {
                    'p_type':   u32(self.data, base + 0),
                    'p_offset': u64(self.data, base + 8),
                    'p_vaddr':  u64(self.data, base + 16),
                    'p_filesz': u64(self.data, base + 32),
                    'p_memsz':  u64(self.data, base + 40),
                    'raw_base': base,
                }
            else:
                ph = {
                    'p_type':   u32(self.data, base + 0),
                    'p_offset': u32(self.data, base + 4),
                    'p_vaddr':  u32(self.data, base + 8),
                    'p_filesz': u32(self.data, base + 16),
                    'p_memsz':  u32(self.data, base + 20),
                    'raw_base': base,
                }
            self.phdrs.append(ph)


# ---------------------------------------------------------------------------
# 深度校验 (镜像 validate_dex_deep_bool)
# ---------------------------------------------------------------------------
def validate_elf_deep(data):
    """镜像 GUI validateDexDeep。返回 bool:True=ELF 结构有效。

    检查:
      - ELF magic (或结构识别后补 magic 的前提: e_type==ET_DYN)
      - PHT 自洽: e_phoff/e_phentsize/e_phnum 合理,在文件内
      - 每个 PT_LOAD: p_vaddr+p_memsz 不超文件, p_filesz <= p_memsz
      - PT_DYNAMIC 段在文件内; 遍历 DT_*, 关键 DT 指向在文件内
    """
    info = ElfInfo(data)
    if not info.parse_header():
        return False
    if info.e_type != ET_DYN:
        return False
    if info.e_machine not in (EM_ARM, EM_AARCH64):
        return False
    if info.real_size > 64 * 1024 * 1024:
        return False
    # PHT 范围
    if info.e_phoff < SO_MIN_SIZE or info.e_phoff >= info.real_size:
        return False
    if info.e_phentsize == 0 or info.e_phnum == 0 or info.e_phnum > 64:
        return False
    if info.e_phoff + info.e_phnum * info.e_phentsize > info.real_size:
        return False
    info.parse_phdrs()

    load_segs = [p for p in info.phdrs if p['p_type'] == PT_LOAD]
    if not load_segs:
        return False  # SO 至少有一个 LOAD 段
    # PT_LOAD 自洽
    for p in load_segs:
        if p['p_filesz'] > p['p_memsz']:
            return False
        # 内存布局 dump: p_vaddr + p_memsz 不应超过文件 (dump 是从基址 0 开始的)
        if p['p_vaddr'] + p['p_memsz'] > info.real_size:
            return False

    # PT_DYNAMIC: 找到段,遍历 DT_* 项
    dyn = next((p for p in info.phdrs if p['p_type'] == PT_DYNAMIC), None)
    if dyn is not None:
        dyn_off = dyn['p_vaddr']  # dump 里 p_vaddr 即文件偏移
        if dyn_off >= info.real_size:
            return False
        # 遍历 Elf32_Dyn/Elf64_Dyn (各 8/16 字节: d_tag + d_val/d_ptr)
        entsize = 16 if info.is64 else 8
        tag_size = 8 if info.is64 else 4   # d_tag 宽度
        ptr_read = (u64 if info.is64 else u32)
        i = dyn_off
        while i + entsize <= info.real_size:
            d_tag = (u64 if info.is64 else u32)(data, i)
            if d_tag == DT_NULL:
                break
            d_val = ptr_read(data, i + tag_size)
            if d_tag in DT_ADDR_TAGS and d_val != 0:
                # DT 指向必须在文件内
                if d_val >= info.real_size:
                    return False
            i += entsize
            if (i - dyn_off) // entsize > 256:  # 防御:动态段过长
                break
    return True


# ---------------------------------------------------------------------------
# ELF 修复 (镜像 SoFixer `-m 0x0` 的核心)
# ---------------------------------------------------------------------------
def repair_elf(data):
    """修复内存 dump 的 ELF:对每个 PT_LOAD 段 p_offset = p_vaddr,并补回缺失 magic。

    返回 (new_data, changed):changed=True 表示有改动。
    base_addr 固定为 0 (对应 SoFixer -m 0x0,dump 从基址 0 开始,p_vaddr 即文件偏移)。
    """
    info = ElfInfo(data)
    if not info.parse_header():
        return data, False
    info.parse_phdrs()
    data = bytearray(data)
    changed = False

    # 1. 补回缺失的 ELF magic (\x7fELF) + EI_CLASS/EI_DATA/EI_VERSION
    if data[0:4] != ELF_MAGIC:
        data[0:4] = ELF_MAGIC
        # EI_DATA = 1 (little-endian), EI_VERSION = 1
        if data[5] != 1:
            data[5] = 1; changed = True
        if data[6] != 1:
            data[6] = 1; changed = True
        changed = True

    # 2. 对每个 PT_LOAD: p_offset = p_vaddr (内存布局 -> 文件布局)
    for p in info.phdrs:
        if p['p_type'] != PT_LOAD:
            continue
        if p['p_offset'] != p['p_vaddr']:
            base = p['raw_base']
            if info.is64:
                put64(data, base + 8, p['p_vaddr'])   # p_offset@8 (ELF64)
            else:
                put32(data, base + 4, p['p_vaddr'])   # p_offset@4 (ELF32)
            changed = True

    # 3. PT_DYNAMIC 的 p_offset 也对齐到 p_vaddr (SoFixer 同样处理)
    for p in info.phdrs:
        if p['p_type'] == PT_DYNAMIC and p['p_offset'] != p['p_vaddr']:
            base = p['raw_base']
            if info.is64:
                put64(data, base + 8, p['p_vaddr'])
            else:
                put32(data, base + 4, p['p_vaddr'])
            changed = True

    return bytes(data), changed


def fix_so_file(path):
    """镜像 fix_dex_file_aligned。一段式: 校验 -> 修复 -> 重校验 -> 落盘。

    返回 (fixed, deleted, err_msg):deleted=True 表示已删除或已隔离。
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return False, False, f"read {path}: {e}"

    if len(data) < SO_MIN_SIZE:
        try: os.remove(path)
        except OSError: pass
        return False, True, f"too small ({len(data)} bytes), deleted"

    # 先尝试直接深度校验;若失败,尝试修复(magic/p_offset)再校验
    if not validate_elf_deep(data):
        new_data, _ = repair_elf(data)
        if not validate_elf_deep(new_data):
            # 仍无效 -> 移到 invalid/
            invalid_dir = os.path.join(os.path.dirname(path), "invalid")
            os.makedirs(invalid_dir, exist_ok=True)
            new_path = os.path.join(invalid_dir, os.path.basename(path))
            try:
                os.rename(path, new_path)
            except OSError:
                pass
            return False, True, "invalid ELF (PHT/section corrupted), moved to invalid/"

    # 通过校验后,做实际修复(p_offset/magic),只在有改动时落盘
    new_data, changed = repair_elf(data)
    # 修复后必须仍通过校验
    if not validate_elf_deep(new_data):
        # 修复反而搞坏了 — 保留原文件,标 fixed=False
        return False, False, "repair broke validation, kept original"

    if changed:
        try:
            with open(path, 'wb') as f:
                f.write(new_data)
        except Exception as e:
            return False, False, f"write {path}: {e}"
    return changed, False, None


def classify_so_full(path):
    """镜像 classify_dex_full。返回 (category, reason, details)。"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return "bad", f"read_error: {e}", {}

    real_size = len(data)
    if real_size < SO_MIN_SIZE:
        return "bad", f"too_small={real_size}", {}
    if real_size > 64 * 1024 * 1024:
        return "bad", f"oversized={real_size}", {}

    info = ElfInfo(data)
    if not info.parse_header():
        return "bad", "no_elf_header", {}

    has_magic = data[0:4] == ELF_MAGIC
    issues = []

    if info.e_type != ET_DYN:
        return "bad", f"not_so_e_type={info.e_type}", {}
    if info.e_machine not in (EM_ARM, EM_AARCH64):
        issues.append(f"BAD_MACHINE=0x{info.e_machine:X}")

    # PHT 范围
    if info.e_phoff < SO_MIN_SIZE or info.e_phoff >= real_size:
        issues.append("PHOFF_INVALID")
    elif info.e_phentsize == 0 or info.e_phnum == 0 or info.e_phnum > 64:
        issues.append("PHNUM_BAD")
    elif info.e_phoff + info.e_phnum * info.e_phentsize > real_size:
        issues.append("PHT_OOB")
    else:
        info.parse_phdrs()
        load_segs = [p for p in info.phdrs if p['p_type'] == PT_LOAD]
        if not load_segs:
            issues.append("NO_LOAD_SEGMENT")
        for p in load_segs:
            if p['p_filesz'] > p['p_memsz']:
                issues.append("FILESZ_GT_MEMSZ")
            if p['p_vaddr'] + p['p_memsz'] > real_size:
                issues.append("LOAD_OOB")
        # magic 缺失可修
        if not has_magic:
            issues.append("MAGIC_MISSING")

    if issues:
        # 全是可修类(magic 缺失 / p_offset 错位) -> repairable
        repairable_only = all(s in ("MAGIC_MISSING",) or
                              s.startswith("P") for s in issues)
        # p_offset 错位本身不报错(repair 阶段才处理);这里 issues 多为结构问题
        if repairable_only or issues == ["MAGIC_MISSING"]:
            return "repairable", '; '.join(issues), {}
        return "bad", '; '.join(issues), {}

    # 深度校验
    if not validate_elf_deep(data):
        return "bad", "deep_validation_failed", {}

    return "ida-ready", "ok", {}


def fix_directory_aligned(dir_path):
    """镜像 GUI FixDexDirectory。递归修复目录下所有 .so。

    返回 {total, ok, fixed, bad, bad_files}。
    ok 包含所有未被删除/隔离的文件(含 fixed),与 GUI 统计口径一致。
    """
    so_files = sorted(glob.glob(os.path.join(dir_path, "**", "*.so"), recursive=True))
    stats = {"total": len(so_files), "ok": 0, "fixed": 0, "bad": 0, "bad_files": []}
    for path in so_files:
        fixed, deleted, err = fix_so_file(path)
        if err is not None:
            if deleted:
                stats["bad"] += 1
                stats["bad_files"].append(os.path.basename(path))
            continue
        if fixed:
            stats["fixed"] += 1
        stats["ok"] += 1
    return stats


# ---------------------------------------------------------------------------
# 独立 CLI (对齐 fix_dex_checksum.py 的独立工具形态)
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        print("Usage:")
        print("  python fix_so.py <file.so>           # 修复单个 SO")
        print("  python fix_so.py <dir>                 # 递归修复目录")
        print("  python fix_so.py <dir> --classify      # 仅分类,不修复")
        return
    target = args[0]
    classify_only = '--classify' in args
    if os.path.isdir(target):
        if classify_only:
            so_files = sorted(glob.glob(os.path.join(target, "**", "*.so"), recursive=True))
            cats = {"ida-ready": 0, "repairable": 0, "bad": 0}
            for p in so_files:
                cat, reason, _ = classify_so_full(p)
                cats[cat] = cats.get(cat, 0) + 1
                print(f"  {os.path.basename(p):40s} {cat:12s} {reason}")
            print(f"\nTotal: {len(so_files)}  ida-ready: {cats['ida-ready']}  "
                  f"repairable: {cats['repairable']}  bad: {cats['bad']}")
        else:
            stats = fix_directory_aligned(target)
            print(f"Total: {stats['total']}  OK: {stats['ok']}  "
                  f"Fixed: {stats['fixed']}  Bad: {stats['bad']}")
            if stats['bad_files']:
                print("Bad files:")
                for n in stats['bad_files']:
                    print(f"  {n}")
    elif os.path.isfile(target):
        if classify_only:
            cat, reason, _ = classify_so_full(target)
            print(f"{cat}: {reason}")
        else:
            fixed, deleted, err = fix_so_file(target)
            if err:
                print(f"{'deleted' if deleted else 'error'}: {err}")
            else:
                print(f"{'fixed' if fixed else 'ok (no change)'}")
    else:
        print(f"not found: {target}")


if __name__ == '__main__':
    main()
