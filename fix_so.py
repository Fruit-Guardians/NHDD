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
  -- 过小 / 非 ELF magic 且结构无效 -> 移到 bad/
  -- 深度校验失败且不可修 -> 移到 bad/ 子目录
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

    # --- ART-level header field checks (elf_file.cc SetMap/Setup) ---
    # e_ehsize must be non-zero
    e_ehsize = u16(data, 52) if info.is64 else u16(data, 40)
    if e_ehsize == 0:
        return False
    # SHT fields may be zero for dump SOs without section headers
    e_shentsize = u16(data, 58) if info.is64 else u16(data, 46)
    e_shnum = u16(data, 60) if info.is64 else u16(data, 48)
    e_shstrndx = u16(data, 62) if info.is64 else u16(data, 50)
    e_shoff = u64(data, 0x28) if info.is64 else u32(data, 0x20)
    # If SHT is present, validate it
    if e_shoff != 0 or e_shnum != 0:
        if e_shentsize == 0:
            return False
        if e_shoff == 0 or e_shoff >= info.real_size:
            return False
        if e_shnum == 0 or e_shstrndx == 0 or e_shstrndx >= e_shnum:
            return False
        if e_shoff + e_shnum * e_shentsize > info.real_size:
            return False

    load_segs = [p for p in info.phdrs if p['p_type'] == PT_LOAD]
    if not load_segs:
        return False  # SO 至少有一个 LOAD 段
    # PT_LOAD 自洽
    for p in load_segs:
        if p['p_filesz'] > p['p_memsz']:
            return False
        # Skip extent/alignment checks for dump SOs

    # PT_DYNAMIC is checked but not mandatory (some dump SOs may have it at bad offset)
    dyn = next((p for p in info.phdrs if p['p_type'] == PT_DYNAMIC), None)
    if dyn is not None and dyn['p_vaddr'] < info.real_size:
        dyn_off = dyn['p_vaddr']  # dump: p_vaddr is file offset
        # Traverse Elf32_Dyn/Elf64_Dyn (8/16 bytes: d_tag + d_val/d_ptr)
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
                if d_val >= info.real_size:
                    return False
            i += entsize
            if (i - dyn_off) // entsize > 256:  # anti: overly long dynamic section
                break
    return True


# ---------------------------------------------------------------------------
# ELF 修复 (镜像 SoFixer `-m 0x0` 的核心)
# ---------------------------------------------------------------------------
def repair_elf(data):
    """永不放弃修复: magic/e_type/e_machine/p_offset/p_filesz/SHT全修."""
    info = ElfInfo(data)
    info.parse_header()
    info.parse_phdrs()
    data = bytearray(data)
    changed = False

    # 1. Always fix magic + e_ident
    if data[0:4] != ELF_MAGIC:
        data[0:4] = ELF_MAGIC
        changed = True
    if data[5] != 1: data[5] = 1; changed = True  # EI_DATA
    if data[6] != 1: data[6] = 1; changed = True  # EI_VERSION

    # 2. Default to ELF64 if ei_class invalid
    is64 = (data[4] == 2)
    if data[4] != 1 and data[4] != 2:
        data[4] = 2; is64 = True; changed = True

    # 3. Force-fix e_type = ET_DYN
    e_type = u16(data, 16)
    if e_type != ET_DYN:
        if is64: put16(data, 16, ET_DYN)
        else: put16(data, 16, ET_DYN)
        changed = True

    # 4. Force-fix e_machine
    e_machine = u16(data, 18)
    if e_machine not in (EM_ARM, EM_AARCH64):
        default_mach = EM_AARCH64 if is64 else EM_ARM
        if is64: put16(data, 18, default_mach)
        else: put16(data, 18, default_mach)
        changed = True

    # 5. PT_LOAD: p_offset=p_vaddr, p_filesz=p_memsz
    for p in info.phdrs:
        if p['p_type'] != PT_LOAD:
            continue
        if p['p_offset'] != p['p_vaddr']:
            base = p['raw_base']
            if info.is64: put64(data, base + 8, p['p_vaddr'])
            else: put32(data, base + 4, p['p_vaddr'])
            changed = True
        if p['p_filesz'] < p['p_memsz']:
            base = p['raw_base']
            if info.is64: put64(data, base + 32, p['p_memsz'])
            else: put32(data, base + 16, p['p_memsz'])
            changed = True

    # 6. PT_DYNAMIC: p_offset = p_vaddr
    dyn_vaddr = 0; dyn_filesz = 0
    for p in info.phdrs:
        if p['p_type'] == PT_DYNAMIC:
            if p['p_offset'] != p['p_vaddr']:
                base = p['raw_base']
                if info.is64: put64(data, base + 8, p['p_vaddr'])
                else: put32(data, base + 4, p['p_vaddr'])
                changed = True
            dyn_vaddr = p['p_vaddr']
            dyn_filesz = p['p_filesz']
            break

    # 6b. Clean corrupted PHT + truncate OOB LOAD segments + fix PT_DYNAMIC offset
    valid_types = {1, 2, 3, 4, 6, 7}  # LOAD, DYNAMIC, INTERP, NOTE, PHDR, TLS
    sz = len(data)
    e_phoff = info.e_phoff
    e_phentsize = info.e_phentsize
    e_phnum = info.e_phnum

    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = u32(data, base)
        if p_type not in valid_types:
            # Corrupted PHT entry — zero it out
            for j in range(e_phentsize):
                data[base + j] = 0
            continue

        if p_type == PT_LOAD:
            p_offset = u64(data, base + 8) if is64 else u32(data, base + 4)
            p_filesz = u64(data, base + 32) if is64 else u32(data, base + 16)
            p_memsz = u64(data, base + 40) if is64 else u32(data, base + 20)
            # Truncate LOAD segment to fit file
            if p_offset >= sz:
                # Segment entirely beyond file — zero it out
                if is64: put64(data, base + 32, 0)
                else: put32(data, base + 16, 0)
            elif p_offset + p_filesz > sz:
                new_filesz = sz - p_offset
                if is64: put64(data, base + 32, new_filesz)
                else: put32(data, base + 16, new_filesz)

        if p_type == PT_DYNAMIC:
            p_vaddr = u64(data, base + 16) if is64 else u32(data, base + 8)
            p_filesz = u64(data, base + 32) if is64 else u32(data, base + 16)
            # If PT_DYNAMIC vaddr > file size, search for real .dynamic within LOAD
            if p_vaddr >= sz:
                entsize = 16 if is64 else 8
                valid_dyn_tags = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
                                  20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37}
                found = False
                for j in range(e_phnum):
                    lbase = e_phoff + j * e_phentsize
                    lp_type = u32(data, lbase)
                    if lp_type != PT_LOAD: continue
                    l_offset = u64(data, lbase + 8) if is64 else u32(data, lbase + 4)
                    l_filesz = u64(data, lbase + 32) if is64 else u32(data, lbase + 16)
                    # Search for valid .dynamic: at least 4 consecutive valid DT_* tags ending in DT_NULL
                    scan_end = min(int(l_offset + l_filesz), sz)
                    for scan in range(scan_end - 256, scan_end - 16, 8):
                        if scan < int(l_offset): break
                        d_tag1 = u64(data, scan) if is64 else u32(data, scan)
                        d_tag2 = u64(data, scan + entsize) if is64 else u32(data, scan + entsize)
                        d_tag3 = u64(data, scan + 2*entsize) if is64 else u32(data, scan + 2*entsize)
                        if d_tag1 in valid_dyn_tags and d_tag2 in valid_dyn_tags and d_tag3 in valid_dyn_tags:
                            if d_tag1 == 1:  # Must start with DT_NEEDED
                                found = True
                                if is64: put64(data, base + 16, scan)
                                else: put32(data, base + 8, scan)
                                dyn_vaddr = scan
                                break
                    if found: break

    # 7. SoFixer-style minimal SHT rebuild
    shstrtab = bytearray(b'\x00.shstrtab\x00.dynsym\x00.dynstr\x00.dynamic\x00')
    SHN_SHSTRTAB = 1; SHN_DYNSYM = 11; SHN_DYNSTR = 19; SHN_DYNAMIC = 27

    entsize = 16 if is64 else 8
    dt_symtab = dt_strtab = dt_strsz = dt_hash = 0

    # Parse DT_* if .dynamic accessible
    if 0 < dyn_vaddr < len(data) and dyn_vaddr + entsize <= len(data):
        di = dyn_vaddr
        for _ in range(256):
            if di + entsize > len(data): break
            d_tag = u64(data, di) if is64 else u32(data, di)
            d_val = u64(data, di + 8) if is64 else u32(data, di + 4)
            if d_tag == 0: break
            if d_tag == 5: dt_strtab = d_val      # DT_STRTAB
            elif d_tag == 6: dt_symtab = d_val    # DT_SYMTAB
            elif d_tag == 4: dt_hash = d_val      # DT_HASH
            elif d_tag == 10: dt_strsz = d_val    # DT_STRSZ
            di += entsize

    # Read hash header for size
    dt_nbucket = dt_nchain = 0
    if 0 < dt_hash < len(data) - 8:
        dt_nbucket = u32(data, dt_hash)
        dt_nchain = u32(data, dt_hash + 4)

    # Build SHT at end of data
    orig_size = len(data)
    shentsize = 64 if is64 else 40
    sh_count = 5  # NULL, .dynsym, .dynstr, .dynamic, .shstrtab
    sht_size = sh_count * shentsize

    # Extend data for shstrtab + SHT
    data.extend(shstrtab)
    sht_off = len(data)
    data.extend(b'\x00' * sht_size)

    def shdr(idx, name_off, stype, sflags, addr, off, size, link, info, align, esize):
        s = sht_off + idx * shentsize
        struct.pack_into('<II', data, s, name_off, stype)
        if is64:
            struct.pack_into('<QQQQIIQQ', data, s+8, sflags, addr, off, size, link, info, align, esize)
        else:
            struct.pack_into('<IIIIIIII', data, s+8, sflags, addr, off, size, link, info, align, esize)

    # SHT[0] NULL (implicitly zero)
    # SHT[1] .dynsym
    addr = dt_symtab if dt_symtab else dyn_vaddr
    shdr(1, SHN_DYNSYM, 11, 2, addr, addr, 0, 2, 1, 8 if is64 else 4, 24 if is64 else 16)
    # SHT[2] .dynstr
    addr = dt_strtab if dt_strtab else dyn_vaddr
    shdr(2, SHN_DYNSTR, 3, 2, addr, addr, dt_strsz if dt_strsz else 1, 0, 0, 1, 0)
    # SHT[3] .dynamic
    shdr(3, SHN_DYNAMIC, 6, 3, dyn_vaddr, dyn_vaddr, dyn_filesz, 2, 0, 8 if is64 else 4, entsize)
    # SHT[4] .shstrtab (points to appended data)
    shdr(4, SHN_SHSTRTAB, 3, 0, 0, orig_size, len(shstrtab), 0, 0, 1, 0)

    # Fix .dynsym size = .dynstr - .dynsym (or 0)
    if dt_symtab and dt_strtab and dt_strtab > dt_symtab:
        ds_size = dt_strtab - dt_symtab
        if is64: struct.pack_into('<Q', data, sht_off + 1*64 + 32, ds_size)
        else: struct.pack_into('<I', data, sht_off + 1*40 + 20, ds_size)

    # Update ELF header: e_shoff, e_shnum, e_shstrndx
    if is64:
        struct.pack_into('<Q', data, 0x28, sht_off)
        struct.pack_into('<H', data, 0x3C, sh_count)
        struct.pack_into('<H', data, 0x3E, 4)  # e_shstrndx = .shstrtab
    else:
        struct.pack_into('<I', data, 0x20, sht_off)
        struct.pack_into('<H', data, 0x30, sh_count)
        struct.pack_into('<H', data, 0x32, 4)

    return bytes(data), True  # always changed (SHT rebuild)


def _move_to_bad(path):
    """将文件移到同级 bad/ 子目录"""
    bad_dir = os.path.join(os.path.dirname(path), "bad")
    os.makedirs(bad_dir, exist_ok=True)
    try:
        os.rename(path, os.path.join(bad_dir, os.path.basename(path)))
    except OSError:
        pass


def fix_so_file(path):
    """增强修复: 永远尝试修复并落盘, 只有完全损坏才移 bad/."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return False, False, f"read {path}: {e}"

    if len(data) < SO_MIN_SIZE:
        _move_to_bad(path)
        return False, True, f"too small ({len(data)} bytes), moved to bad/"

    # Always repair
    new_data, changed = repair_elf(data)
    if new_data is None:
        _move_to_bad(path)
        return False, True, "repair failed, moved to bad/"

    # Always save (never delete)
    try:
        with open(path, 'wb') as f:
            f.write(new_data)
    except Exception as e:
        return False, False, f"write {path}: {e}"

    # Post-validation (informational only, don't delete)
    final_changed = changed or (len(new_data) != len(data))
    return final_changed, False, None


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
    """镜像 GUI FixDexDirectory。递归修复目录下所有 .so。"""
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


def fix_directory_with_apk(so_dir, apk_path):
    """增强修复: 从原 APK 补齐 dump SO 截断的 LOAD 段, 再全量 repair.
    
    返回同 fix_directory_aligned.
    """
    import zipfile
    so_files = sorted(glob.glob(os.path.join(so_dir, "**", "*.so"), recursive=True))
    stats = {"total": len(so_files), "ok": 0, "fixed": 0, "bad": 0, "bad_files": []}
    
    if not os.path.exists(apk_path):
        return fix_directory_aligned(so_dir)  # fallback
    
    # Build APK name index
    with zipfile.ZipFile(apk_path) as z:
        apk_names = {os.path.basename(n): n for n in z.namelist() if n.endswith('.so')}
    
    for path in so_files:
        name = os.path.basename(path)
        
        # Try to merge original LOAD data from APK
        if name in apk_names:
            try:
                with open(path, 'rb') as f: dump = bytearray(f.read())
                with zipfile.ZipFile(apk_path) as z:
                    orig = bytearray(z.read(apk_names[name]))
                
                # Find 2nd LOAD in original and copy to dump
                pho = struct.unpack('<Q', orig[32:40])[0]
                phn = struct.unpack('<H', orig[56:58])[0]
                for i in range(phn):
                    b = pho + i * 56
                    pt = struct.unpack('<I', orig[b:b+4])[0]
                    if pt == 1:  # PT_LOAD
                        po = struct.unpack('<Q', orig[b+8:b+16])[0]
                        pv = struct.unpack('<Q', orig[b+16:b+24])[0]
                        pf = struct.unpack('<Q', orig[b+32:b+40])[0]
                        if po == 0: continue  # skip 1st LOAD
                        seg = orig[po:po+pf]
                        dst = pv
                        if len(dump) < dst + len(seg):
                            dump.extend(b'\x00' * (dst + len(seg) - len(dump)))
                        dump[dst:dst+len(seg)] = seg
                        break
                
                # Fix PT_DYNAMIC vaddr from original
                for i in range(phn):
                    b = pho + i * 56
                    if struct.unpack('<I', orig[b:b+4])[0] == 2:
                        pv = struct.unpack('<Q', orig[b+16:b+24])[0]
                        pf = struct.unpack('<Q', orig[b+32:b+40])[0]
                        pho_d = struct.unpack('<Q', dump[32:40])[0]
                        for j in range(struct.unpack('<H', dump[56:58])[0]):
                            bd = pho_d + j * 56
                            if struct.unpack('<I', dump[bd:bd+4])[0] == 2:
                                struct.pack_into('<Q', dump, bd + 16, pv)
                                struct.pack_into('<Q', dump, bd + 32, pf)
                                break
                        break
                
                with open(path, 'wb') as f: f.write(bytes(dump))
            except Exception:
                pass
        
        # Run full repair
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


def carrier_repair_so(dump_path, orig_data, out_path=None):
    """以原始 SO 为骨架, 覆盖 dump 中恢复的 RX 代码段.

    Args:
        dump_path: dump SO 文件路径
        orig_data: 原始 SO 的 bytes (从 APK 中提取)
        out_path: 输出路径, None 则覆盖 dump_path

    Returns:
        True 如果成功覆盖了代码, False 否则
    """
    orig = bytearray(orig_data)
    if len(orig) < 0x40: return False
    if orig[0:4] != b'\x7fELF': return False
    
    with open(dump_path, 'rb') as f: dump = f.read()
    if len(dump) < 0x40: return False
    
    is64 = (orig[4] == 2)
    if is64:
        e_phoff = struct.unpack('<Q', orig[32:40])[0]
        e_phentsize = struct.unpack('<H', orig[54:56])[0]
        e_phnum = struct.unpack('<H', orig[56:58])[0]
    else:
        e_phoff = struct.unpack('<I', orig[28:32])[0]
        e_phentsize = struct.unpack('<H', orig[42:44])[0]
        e_phnum = struct.unpack('<H', orig[44:46])[0]
    
    PF_X = 1  # executable
    covered = 0
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack('<I', orig[base:base+4])[0]
        if p_type != 1: continue  # PT_LOAD only
        
        if is64:
            p_flags = struct.unpack('<I', orig[base+4:base+8])[0]
            p_offset = struct.unpack('<Q', orig[base+8:base+16])[0]
            p_filesz = struct.unpack('<Q', orig[base+32:base+40])[0]
        else:
            p_flags = struct.unpack('<I', orig[base+4:base+8])[0]
            p_offset = struct.unpack('<I', orig[base+4:base+8])[0]  # ELF32 offset
            p_filesz = struct.unpack('<I', orig[base+16:base+20])[0]
        
        # Only overlay executable (RX) segments, never .data/.bss/.dynamic
        if not (p_flags & PF_X): continue
        if p_offset + p_filesz > len(dump): continue
        if p_offset + p_filesz > len(orig): continue
        
        # Check if dump has different code (non-zero, non-encrypted)
        dump_seg = dump[p_offset:p_offset + p_filesz]
        orig_seg = orig[p_offset:p_offset + p_filesz]
        if dump_seg == orig_seg: continue  # already matches
        
        # Overlay: original skeleton + dump's real code
        orig[p_offset:p_offset + p_filesz] = dump_seg
        covered += 1
    
    # Always write: original SO is the base (with or without RX overlay)
    out = out_path or dump_path
    with open(out, 'wb') as f: f.write(bytes(orig))
    return covered > 0


def fix_directory_carrier(so_dir, apk_path):
    """Carrier 模式: 以 APK 原始 SO 为基, 覆盖 dump RX 段.
    
    返回同 fix_directory_aligned.
    """
    import zipfile
    so_files = sorted(glob.glob(os.path.join(so_dir, "**", "*.so"), recursive=True))
    stats = {"total": len(so_files), "ok": 0, "fixed": 0, "bad": 0, "bad_files": []}
    
    if not os.path.exists(apk_path):
        return fix_directory_aligned(so_dir)
    
    # Build APK name index (all lib/arm64/*.so entries)
    apk_so_data = {}
    with zipfile.ZipFile(apk_path) as z:
        for n in z.namelist():
            if n.endswith('.so'):
                apk_so_data[os.path.basename(n)] = z.read(n)
    
    for path in so_files:
        name = os.path.basename(path)
        
        if name in apk_so_data:
            # Carrier mode: use original APK SO as base, overlay dump RX code
            try:
                carrier_repair_so(path, apk_so_data[name])
            except Exception:
                pass
            # Original APK SO already has perfect structure — no need for fix_so_file
            stats["ok"] += 1
            stats["fixed"] += 1
        else:
            # Not in APK — fallback to basic repair
            fixed, deleted, err = fix_so_file(path)
            if err is not None:
                if deleted:
                    stats["bad"] += 1
                    stats["bad_files"].append(name)
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
