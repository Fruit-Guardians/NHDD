#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_so_v3.py - 修复 Android SO 内存 dump 的 ELF 结构，优先保证 IDA/Ghidra 可稳定加载。

核心原则：
1. Program Header / PT_LOAD 是运行时 dump 的主结构，优先修 PHT。
2. Section Header 对运行时加载不是必需项；坏 SHT 比没有 SHT 更糟，默认清掉坏 SHT。
3. 对截断 dump 自动裁剪越界 p_filesz，避免 IDA 的 SHT/Data size 报错。
3. 不再无条件执行 p_offset = p_vaddr；会自动把 SoFixer 风格的内存布局还原为合理 file-layout。
4. PT_DYNAMIC 能恢复就恢复；恢复不了才可选降级为 PT_NULL，避免 IDA 被坏 dynamic 误导。

用法：
  python fix_so_v2.py libxxx.so --out libxxx.fixed.so
  python fix_so_v2.py libxxx.so --in-place
  python fix_so_v2.py so_dir --in-place
  python fix_so_v2.py so_dir --classify
  python fix_so_v2.py so_dir --apk app.apk --carrier --in-place
"""

import argparse
import glob
import os
import shutil
import struct
import sys
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ELF_MAGIC = b"\x7fELF"
ET_DYN = 3
EM_ARM = 40
EM_AARCH64 = 183

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 1

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_FLAGS = 30
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_RELACOUNT = 0x6FFFFFF9
DT_FLAGS_1 = 0x6FFFFFFB
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
# 常见但旧脚本未覆盖的动态段 tag：Android/NDK 新版 SO 可能包含这些。
# 如果不允许这些 tag，会把正常 SO 的 .dynamic 误判成坏段，甚至降级成 PT_NULL。
DT_RPATH = 15
DT_DEBUG = 21
DT_TEXTREL = 22
DT_BIND_NOW = 24
DT_RUNPATH = 29
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_SYMTAB_SHNDX = 34
DT_RELRSZ = 35
DT_RELR = 36
DT_RELRENT = 37

VALID_DT_TAGS = {
    DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW,
    DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ,
    DT_FLAGS, DT_RUNPATH, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
    DT_SYMTAB_SHNDX, DT_RELRSZ, DT_RELR, DT_RELRENT,
    DT_GNU_HASH, DT_VERSYM, DT_RELACOUNT, DT_FLAGS_1,
    DT_VERDEF, DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM,
}

PT_GNU_PROPERTY = 0x6474E553
PT_ARM_EXIDX = 0x70000001

VALID_PH_TYPES = {
    PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR, PT_TLS,
    PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO, PT_GNU_PROPERTY,
    PT_ARM_EXIDX,
}


def is_plausible_ph_type(p_type: int) -> bool:
    # ELF OS/processor specific Program Header 类型不应直接判死刑。
    # ARM32 的 PT_ARM_EXIDX、GNU/Android 扩展都可能落在这些范围。
    return p_type in VALID_PH_TYPES or 0x60000000 <= p_type <= 0x7FFFFFFF


def is_plausible_dynamic_tag(tag: int) -> bool:
    # Android/LLVM 会引入 OS/GNU 扩展 tag；未知扩展 tag 可以参与评分，
    # 但随机 64-bit 垃圾 tag 仍会被拒绝。
    return tag in VALID_DT_TAGS or 0x60000000 <= tag <= 0x7FFFFFFF


def is_plausible_sh_type(sh_type: int) -> bool:
    return sh_type in VALID_SH_TYPES or 0x60000000 <= sh_type <= 0x7FFFFFFF


SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_GNU_HASH = 0x6FFFFFF6
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF
SHT_RELR = 19

VALID_SH_TYPES = {
    SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH,
    SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL, SHT_DYNSYM,
    SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_GNU_HASH, SHT_GNU_VERDEF,
    SHT_GNU_VERNEED, SHT_GNU_VERSYM, SHT_RELR,
}

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4



def u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def p16(b: bytearray, off: int, val: int) -> None:
    struct.pack_into("<H", b, off, val & 0xFFFF)


def p32(b: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", b, off, val & 0xFFFFFFFF)


def p64(b: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", b, off, val & 0xFFFFFFFFFFFFFFFF)


def align_to_mod(value: int, align: int, mod: int) -> int:
    if align <= 1:
        return value
    mod %= align
    if value <= mod:
        return mod
    return ((value - mod + align - 1) // align) * align + mod


@dataclass
class Phdr:
    idx: int
    base: int
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass
class Shdr:
    idx: int
    base: int
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int


class ElfInfo:
    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)
        self.is64 = False
        self.valid_header = False
        self.e_type = 0
        self.e_machine = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0
        self.phdrs: List[Phdr] = []
        self.shdrs: List[Shdr] = []
        self.parse()

    def parse(self) -> None:
        d = self.data
        if len(d) < 0x40:
            return
        if d[4] == 2:
            self.is64 = True
        elif d[4] == 1:
            self.is64 = False
        else:
            return
        if d[5] != 1:  # little-endian only; Android ARM/ARM64 normally LE
            return
        self.e_type = u16(d, 16)
        self.e_machine = u16(d, 18)
        if self.is64:
            self.e_entry = u64(d, 24)
            self.e_phoff = u64(d, 32)
            self.e_shoff = u64(d, 40)
            self.e_ehsize = u16(d, 52)
            self.e_phentsize = u16(d, 54)
            self.e_phnum = u16(d, 56)
            self.e_shentsize = u16(d, 58)
            self.e_shnum = u16(d, 60)
            self.e_shstrndx = u16(d, 62)
        else:
            self.e_entry = u32(d, 24)
            self.e_phoff = u32(d, 28)
            self.e_shoff = u32(d, 32)
            self.e_ehsize = u16(d, 40)
            self.e_phentsize = u16(d, 42)
            self.e_phnum = u16(d, 44)
            self.e_shentsize = u16(d, 46)
            self.e_shnum = u16(d, 48)
            self.e_shstrndx = u16(d, 50)
        self.valid_header = True
        self.phdrs = self._parse_phdrs()
        self.shdrs = self._parse_shdrs()

    def _parse_phdrs(self) -> List[Phdr]:
        out: List[Phdr] = []
        if self.e_phoff == 0 or self.e_phentsize == 0 or self.e_phnum == 0:
            return out
        if self.e_phoff >= self.size:
            return out
        max_n = min(self.e_phnum, (self.size - self.e_phoff) // self.e_phentsize)
        for i in range(max_n):
            base = self.e_phoff + i * self.e_phentsize
            if self.is64:
                if base + 56 > self.size:
                    break
                out.append(Phdr(
                    idx=i,
                    base=base,
                    p_type=u32(self.data, base),
                    p_flags=u32(self.data, base + 4),
                    p_offset=u64(self.data, base + 8),
                    p_vaddr=u64(self.data, base + 16),
                    p_paddr=u64(self.data, base + 24),
                    p_filesz=u64(self.data, base + 32),
                    p_memsz=u64(self.data, base + 40),
                    p_align=u64(self.data, base + 48),
                ))
            else:
                if base + 32 > self.size:
                    break
                out.append(Phdr(
                    idx=i,
                    base=base,
                    p_type=u32(self.data, base),
                    p_offset=u32(self.data, base + 4),
                    p_vaddr=u32(self.data, base + 8),
                    p_paddr=u32(self.data, base + 12),
                    p_filesz=u32(self.data, base + 16),
                    p_memsz=u32(self.data, base + 20),
                    p_flags=u32(self.data, base + 24),
                    p_align=u32(self.data, base + 28),
                ))
        return out

    def _parse_shdrs(self) -> List[Shdr]:
        out: List[Shdr] = []
        if self.e_shoff == 0 or self.e_shentsize == 0 or self.e_shnum == 0:
            return out
        if self.e_shoff >= self.size:
            return out
        max_n = min(self.e_shnum, (self.size - self.e_shoff) // self.e_shentsize)
        for i in range(max_n):
            base = self.e_shoff + i * self.e_shentsize
            if self.is64:
                if base + 64 > self.size:
                    break
                out.append(Shdr(
                    idx=i,
                    base=base,
                    sh_name=u32(self.data, base),
                    sh_type=u32(self.data, base + 4),
                    sh_flags=u64(self.data, base + 8),
                    sh_addr=u64(self.data, base + 16),
                    sh_offset=u64(self.data, base + 24),
                    sh_size=u64(self.data, base + 32),
                    sh_link=u32(self.data, base + 40),
                    sh_info=u32(self.data, base + 44),
                    sh_addralign=u64(self.data, base + 48),
                    sh_entsize=u64(self.data, base + 56),
                ))
            else:
                if base + 40 > self.size:
                    break
                out.append(Shdr(
                    idx=i,
                    base=base,
                    sh_name=u32(self.data, base),
                    sh_type=u32(self.data, base + 4),
                    sh_flags=u32(self.data, base + 8),
                    sh_addr=u32(self.data, base + 12),
                    sh_offset=u32(self.data, base + 16),
                    sh_size=u32(self.data, base + 20),
                    sh_link=u32(self.data, base + 24),
                    sh_info=u32(self.data, base + 28),
                    sh_addralign=u32(self.data, base + 32),
                    sh_entsize=u32(self.data, base + 36),
                ))
        return out

    def loads(self) -> List[Phdr]:
        return sorted([p for p in self.phdrs if p.p_type == PT_LOAD], key=lambda x: x.p_vaddr)

    def dynamic(self) -> Optional[Phdr]:
        return next((p for p in self.phdrs if p.p_type == PT_DYNAMIC), None)


def set_ph_offset(data: bytearray, info: ElfInfo, ph: Phdr, new_offset: int) -> None:
    if info.is64:
        p64(data, ph.base + 8, new_offset)
    else:
        p32(data, ph.base + 4, new_offset)


def set_ph_type(data: bytearray, ph: Phdr, new_type: int) -> None:
    p32(data, ph.base, new_type)


def set_ph_filesz(data: bytearray, info: ElfInfo, ph: Phdr, new_filesz: int) -> None:
    if info.is64:
        p64(data, ph.base + 32, new_filesz)
    else:
        p32(data, ph.base + 16, new_filesz)


def set_ph_memsz(data: bytearray, info: ElfInfo, ph: Phdr, new_memsz: int) -> None:
    if info.is64:
        p64(data, ph.base + 40, new_memsz)
    else:
        p32(data, ph.base + 20, new_memsz)


RECOVERABLE_PHT_ERRORS = {
    "MAGIC_MISSING",
    "LOAD_FILESZ_OOB",
    "LOAD_OFFSET_OOB",
    "FILESZ_GT_MEMSZ",
}


def pht_error_is_recoverable(reason: str) -> bool:
    return reason in RECOVERABLE_PHT_ERRORS


def pht_extent_issues(info: ElfInfo) -> List[str]:
    issues: List[str] = []
    for p in info.phdrs:
        if p.p_filesz == 0:
            continue
        if p.p_offset >= info.size:
            issues.append(f"PHDR[{p.idx}].offset_oob")
        elif p.p_offset + p.p_filesz > info.size:
            issues.append(f"PHDR[{p.idx}].filesz_oob")
        if p.p_filesz > p.p_memsz and p.p_type == PT_LOAD:
            issues.append(f"PT_LOAD[{p.idx}].filesz_gt_memsz")
    return issues


def clamp_phdr_file_extents(data: bytearray, info: ElfInfo) -> List[str]:
    """Clamp p_filesz fields that point past EOF.

    Memory dumps are often truncated at the last readable page. A stale p_filesz
    makes IDA/Ghidra emit errors such as "Data size is incorrect, maximum
    possible value is ...".  For static analysis it is safer to keep p_memsz
    as the runtime size and reduce only p_filesz to the bytes actually present.
    """
    actions: List[str] = []
    for ph in info.phdrs:
        if ph.p_filesz == 0:
            continue
        if ph.p_offset >= info.size:
            if ph.p_filesz != 0:
                set_ph_filesz(data, info, ph, 0)
                actions.append(f"PHDR[{ph.idx}].p_filesz: 0x{ph.p_filesz:x} -> 0x0 (offset past EOF)")
            continue
        max_filesz = max(0, info.size - ph.p_offset)
        effective_filesz = ph.p_filesz
        if ph.p_filesz > max_filesz:
            effective_filesz = max_filesz
            set_ph_filesz(data, info, ph, effective_filesz)
            actions.append(f"PHDR[{ph.idx}].p_filesz: 0x{ph.p_filesz:x} -> 0x{effective_filesz:x} (clamp to EOF)")
        if ph.p_type == PT_LOAD and effective_filesz > ph.p_memsz:
            # Last-resort consistency fix for malformed dumps.
            # 注意这里必须使用裁剪后的 effective_filesz，不能再用旧 ph.p_filesz。
            set_ph_memsz(data, info, ph, effective_filesz)
            actions.append(f"PT_LOAD[{ph.idx}].p_memsz: 0x{ph.p_memsz:x} -> 0x{effective_filesz:x} (filesz > memsz)")
    return actions


def pht_valid(info: ElfInfo) -> Tuple[bool, str]:
    if not info.valid_header:
        return False, "BAD_EI_CLASS_OR_ENDIAN"
    if info.data[:4] != ELF_MAGIC:
        return False, "MAGIC_MISSING"
    if info.e_type != ET_DYN:
        return False, f"NOT_SO_ET_{info.e_type}"
    if info.e_machine not in (EM_ARM, EM_AARCH64):
        return False, f"BAD_MACHINE_{info.e_machine}"
    if info.e_ehsize == 0:
        return False, "BAD_EHSIZE"
    if info.e_phoff < (64 if info.is64 else 52) or info.e_phoff >= info.size:
        return False, "PHOFF_INVALID"
    if info.e_phentsize < (56 if info.is64 else 32):
        return False, "PHENTSIZE_INVALID"
    if info.e_phnum == 0 or info.e_phnum > 128:
        return False, "PHNUM_INVALID"
    if info.e_phoff + info.e_phnum * info.e_phentsize > info.size:
        return False, "PHT_OOB"
    if len(info.phdrs) != info.e_phnum:
        return False, "PHT_TRUNCATED"
    if any(not is_plausible_ph_type(p.p_type) for p in info.phdrs):
        return False, "UNKNOWN_PHDR_TYPE"
    loads = info.loads()
    if not loads:
        return False, "NO_LOAD"
    for p in loads:
        if p.p_filesz > p.p_memsz:
            return False, "FILESZ_GT_MEMSZ"
        if p.p_offset >= info.size and p.p_filesz > 0:
            return False, "LOAD_OFFSET_OOB"
        if p.p_offset + p.p_filesz > info.size:
            return False, "LOAD_FILESZ_OOB"
    return True, "ok"


def vaddr_to_offset(loads: List[Phdr], vaddr: int, use_current_offsets: bool = True,
                    offset_map: Optional[Dict[int, int]] = None) -> Optional[int]:
    for p in loads:
        start = p.p_vaddr
        end = p.p_vaddr + max(p.p_memsz, p.p_filesz)
        if start <= vaddr < end:
            base_off = offset_map[p.idx] if offset_map and p.idx in offset_map else p.p_offset
            return base_off + (vaddr - start)
    return None


def dynamic_score(data: bytes, off: int, is64: bool, limit: int = 0x4000) -> Tuple[int, Optional[int]]:
    """返回疑似 .dynamic 的可信分数，以及 DT_NULL 结束偏移。"""
    entsize = 16 if is64 else 8
    if off <= 0 or off + entsize > len(data):
        return 0, None
    score = 0
    seen_null = False
    seen_needed = False
    seen_strtab = False
    seen_symtab = False
    seen_hash = False
    end_off = None
    max_entries = min(512, limit // entsize)
    for i in range(max_entries):
        pos = off + i * entsize
        if pos + entsize > len(data):
            break
        tag = u64(data, pos) if is64 else u32(data, pos)
        val = u64(data, pos + 8) if is64 else u32(data, pos + 4)
        if tag == DT_NULL:
            seen_null = True
            end_off = pos + entsize
            score += 3
            break
        if not is_plausible_dynamic_tag(tag):
            return 0, None
        # 已知标准 tag 分数更高；OS/GNU/processor 扩展 tag 只给低分，
        # 避免随机数据因为碰巧落在扩展范围而被过度认可。
        score += 1 if tag in VALID_DT_TAGS else 0
        if tag == DT_NEEDED:
            seen_needed = True
            if val > 0x1000000:
                score -= 1
        elif tag == DT_STRTAB:
            seen_strtab = True
        elif tag == DT_SYMTAB:
            seen_symtab = True
        elif tag in (DT_HASH, DT_GNU_HASH):
            seen_hash = True
    if not seen_null:
        return 0, None
    if seen_needed:
        score += 3
    if seen_strtab and seen_symtab:
        score += 4
    if seen_hash:
        score += 1
    return score, end_off


def dynamic_valid(info: ElfInfo) -> Tuple[bool, str]:
    dyn = info.dynamic()
    if dyn is None:
        return True, "NO_DYNAMIC"
    if dyn.p_offset <= 0 or dyn.p_offset + min(dyn.p_filesz, 16) > info.size:
        return False, "DYNAMIC_OFFSET_OOB"
    score, _ = dynamic_score(info.data, dyn.p_offset, info.is64, max(dyn.p_filesz, 0x1000))
    if score < 8:
        return False, f"DYNAMIC_INVALID_SCORE_{score}"
    return True, "ok"


def sht_valid(info: ElfInfo) -> Tuple[bool, str]:
    if info.e_shoff == 0 and info.e_shnum == 0:
        return True, "NO_SHT"
    if info.e_shoff == 0 or info.e_shentsize == 0 or info.e_shnum == 0:
        return False, "SHT_HEADER_INCOMPLETE"
    if info.e_shoff >= info.size or info.e_shoff + info.e_shnum * info.e_shentsize > info.size:
        return False, "SHT_OOB"
    if len(info.shdrs) != info.e_shnum:
        return False, "SHT_TRUNCATED"
    if info.e_shstrndx == 0 or info.e_shstrndx >= info.e_shnum:
        return False, "SHSTRNDX_INVALID"
    shstr = info.shdrs[info.e_shstrndx]
    if shstr.sh_type != SHT_STRTAB:
        return False, "SHSTRTAB_TYPE_INVALID"
    if shstr.sh_offset + shstr.sh_size > info.size:
        return False, "SHSTRTAB_OOB"
    if shstr.sh_size <= 1:
        # 典型错误：只写了一个 \0，其他 sh_name 全部越界
        if any(s.sh_name != 0 for s in info.shdrs[1:]):
            return False, "SHSTRTAB_TOO_SMALL"
    table = info.data[shstr.sh_offset:shstr.sh_offset + shstr.sh_size]
    for sh in info.shdrs:
        if not is_plausible_sh_type(sh.sh_type):
            return False, f"SHTYPE_INVALID_{sh.sh_type}"
        if sh.sh_name >= shstr.sh_size:
            return False, "SH_NAME_OOB"
        if sh.sh_name != 0:
            end = table.find(b"\x00", sh.sh_name)
            if end < 0:
                return False, "SH_NAME_UNTERMINATED"
        if sh.sh_type != SHT_NOBITS and sh.sh_offset + sh.sh_size > info.size:
            return False, "SECTION_OOB"

        # 关键修复：内存 dump 修完 PHT 后，旧 SHT 可能仍是 memory-layout，
        # 即 sh_offset == sh_addr / p_vaddr。readelf 只要范围没越界就会认为
        # SHT 合法，但 IDA/Ghidra 会按错误的 section offset 读取 .dynamic、
        # .dynsym、.dynstr，表现为只有 NULL 动态项、符号表为空或非法 section。
        # 对 SHF_ALLOC 且有文件内容的 section，sh_addr 必须能通过 PT_LOAD
        # 映射回同一个 sh_offset；否则应判为坏 SHT 并重建。
        if (sh.sh_flags & SHF_ALLOC) and sh.sh_type != SHT_NOBITS and sh.sh_size > 0:
            mapped = vaddr_to_offset(info.loads(), sh.sh_addr)
            if mapped is None:
                return False, "SECTION_ADDR_UNMAPPED"
            if mapped != sh.sh_offset:
                return False, "SECTION_ADDR_OFFSET_MISMATCH"
    return True, "ok"


def infer_file_layout_offsets(info: ElfInfo) -> Dict[int, int]:
    """把 SoFixer/memory-layout dump 还原为更合理的 file-layout offset。"""
    loads = info.loads()
    if not loads:
        return {}
    new_offsets: Dict[int, int] = {}
    prev_end = 0
    for n, ph in enumerate(loads):
        align = ph.p_align or 1
        if n == 0:
            cand = ph.p_offset
        else:
            cand = align_to_mod(prev_end, align, ph.p_vaddr % align)
            # 只在明显是 p_offset == p_vaddr 且候选值更靠前时修正。
            # 这能修复 p_offset=p_vaddr 导致 .dynamic 读到运行时指针的问题。
            if not (ph.p_offset == ph.p_vaddr and cand < ph.p_offset):
                cand = ph.p_offset
        new_offsets[ph.idx] = cand
        prev_end = cand + ph.p_filesz
    return new_offsets


def find_dynamic_offset(info: ElfInfo, offset_map: Optional[Dict[int, int]] = None) -> Optional[int]:
    dyn = info.dynamic()
    if dyn is None:
        return None
    candidates: List[int] = []
    candidates.append(dyn.p_offset)
    mapped = vaddr_to_offset(info.loads(), dyn.p_vaddr, offset_map=offset_map)
    if mapped is not None:
        candidates.append(mapped)
    # 扫描 RW LOAD 附近，兼容 p_offset 被错误改成 p_vaddr 的情况
    for ph in info.loads():
        if not (ph.p_flags & 2):
            continue
        base_off = offset_map.get(ph.idx, ph.p_offset) if offset_map else ph.p_offset
        start = max(0, base_off)
        end = min(info.size, base_off + ph.p_filesz)
        # 16 字节对齐扫描即可，.dynamic 通常是 16 对齐。
        for off in range(start, max(start, end - 16), 16):
            # 只取高分位置，避免扫描太慢。
            score, _ = dynamic_score(info.data, off, info.is64, 0x800)
            if score >= 16:
                candidates.append(off)
                break
    best = None
    best_score = 0
    for off in dict.fromkeys(candidates):
        score, _ = dynamic_score(info.data, off, info.is64, 0x4000)
        if score > best_score:
            best_score = score
            best = off
    if best_score >= 8:
        return best
    return None


def clear_sht(data: bytearray, info: ElfInfo) -> None:
    if info.is64:
        p64(data, 0x28, 0)  # e_shoff
        p16(data, 0x3A, 0)  # e_shentsize
        p16(data, 0x3C, 0)  # e_shnum
        p16(data, 0x3E, 0)  # e_shstrndx
    else:
        p32(data, 0x20, 0)
        p16(data, 0x2E, 0)
        p16(data, 0x30, 0)
        p16(data, 0x32, 0)


def align_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) & ~(align - 1)


def set_e_shdr_info(data: bytearray, info: ElfInfo, shoff: int, shentsize: int,
                    shnum: int, shstrndx: int) -> None:
    if info.is64:
        p64(data, 0x28, shoff)
        p16(data, 0x3A, shentsize)
        p16(data, 0x3C, shnum)
        p16(data, 0x3E, shstrndx)
    else:
        p32(data, 0x20, shoff)
        p16(data, 0x2E, shentsize)
        p16(data, 0x30, shnum)
        p16(data, 0x32, shstrndx)


def parse_dynamic_entries(info: ElfInfo) -> List[Tuple[int, int]]:
    dyn = info.dynamic()
    if dyn is None or dyn.p_offset <= 0 or dyn.p_offset >= info.size:
        return []
    entsize = 16 if info.is64 else 8
    max_bytes = min(dyn.p_filesz or 0x4000, info.size - dyn.p_offset, 0x10000)
    entries: List[Tuple[int, int]] = []
    for pos in range(dyn.p_offset, dyn.p_offset + max_bytes, entsize):
        if pos + entsize > info.size:
            break
        tag = u64(info.data, pos) if info.is64 else u32(info.data, pos)
        val = u64(info.data, pos + 8) if info.is64 else u32(info.data, pos + 4)
        entries.append((tag, val))
        if tag == DT_NULL:
            break
    return entries


def dyn_tag_values(entries: List[Tuple[int, int]]) -> Dict[int, List[int]]:
    out: Dict[int, List[int]] = {}
    for tag, val in entries:
        out.setdefault(tag, []).append(val)
    return out


def first_dyn_value(tags: Dict[int, List[int]], tag: int, default: int = 0) -> int:
    vals = tags.get(tag)
    return vals[0] if vals else default


def dyn_vaddr_to_offset(info: ElfInfo, vaddr: int) -> Optional[int]:
    return vaddr_to_offset(info.loads(), vaddr)


def infer_dynsym_count(info: ElfInfo, tags: Dict[int, List[int]], sym_vaddr: int,
                       str_vaddr: int, syment: int) -> int:
    if syment <= 0:
        syment = 24 if info.is64 else 16
    # SYSV .hash: nbucket, nchain. nchain 就是 dynsym 数量。
    for hv in tags.get(DT_HASH, []):
        hoff = dyn_vaddr_to_offset(info, hv)
        if hoff is not None and hoff + 8 <= info.size:
            _nbucket = u32(info.data, hoff)
            nchain = u32(info.data, hoff + 4)
            if 0 < nchain < 0x100000:
                return nchain
    sym_off = dyn_vaddr_to_offset(info, sym_vaddr)
    str_off = dyn_vaddr_to_offset(info, str_vaddr)
    if sym_off is not None and str_off is not None and str_off > sym_off:
        return max(0, (str_off - sym_off) // syment)
    return 0


@dataclass
class NewSection:
    name: str
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link_name: str
    sh_info: int
    sh_addralign: int
    sh_entsize: int


def _valid_file_range(info: ElfInfo, off: Optional[int], size: int, allow_zero: bool = False) -> bool:
    if off is None or off < 0 or size < 0:
        return False
    if size == 0:
        return allow_zero
    return off + size <= info.size




def patch_dynsym_section_indices(data: bytearray, info: ElfInfo, sections: List[NewSection],
                                 index_by_name: Dict[str, int], sym_off: Optional[int],
                                 sym_count: int, syment: int) -> int:
    if sym_off is None or sym_count <= 0 or syment <= 0:
        return 0
    if sym_off + sym_count * syment > len(data):
        return 0
    # 只选择真正占地址空间的 section。动态元数据也可以成为 object 的目标，
    # 但 FUNC 优先落到可执行 section。
    candidates: List[Tuple[int, NewSection]] = []
    for sec in sections:
        idx = index_by_name.get(sec.name, 0)
        if idx == 0 or not (sec.sh_flags & SHF_ALLOC):
            continue
        if sec.sh_size == 0:
            continue
        if sec.sh_type in (SHT_DYNSYM, SHT_STRTAB, SHT_HASH, SHT_GNU_HASH, SHT_RELA, SHT_REL):
            continue
        candidates.append((idx, sec))

    def choose(value: int, st_type: int) -> int:
        hits = [(idx, sec) for idx, sec in candidates
                if sec.sh_addr <= value < sec.sh_addr + max(sec.sh_size, 1)]
        if not hits:
            return 0
        if st_type == 2:  # STT_FUNC
            exec_hits = [(idx, sec) for idx, sec in hits if sec.sh_flags & SHF_EXECINSTR]
            if exec_hits:
                return min(exec_hits, key=lambda x: x[1].sh_size)[0]
        non_exec_hits = [(idx, sec) for idx, sec in hits if not (sec.sh_flags & SHF_EXECINSTR)]
        if non_exec_hits:
            return min(non_exec_hits, key=lambda x: x[1].sh_size)[0]
        return min(hits, key=lambda x: x[1].sh_size)[0]

    patched = 0
    for i in range(sym_count):
        pos = sym_off + i * syment
        if info.is64:
            st_info = data[pos + 4]
            st_shndx = struct.unpack_from('<H', data, pos + 6)[0]
            st_value = struct.unpack_from('<Q', data, pos + 8)[0]
        else:
            st_value = struct.unpack_from('<I', data, pos + 4)[0]
            st_info = data[pos + 12]
            st_shndx = struct.unpack_from('<H', data, pos + 14)[0]
        if st_shndx == 0 or st_shndx >= 0xFF00:
            continue
        target = choose(st_value, st_info & 0x0F)
        if target and target != st_shndx:
            if info.is64:
                struct.pack_into('<H', data, pos + 6, target)
            else:
                struct.pack_into('<H', data, pos + 14, target)
            patched += 1
    return patched

def rebuild_minimal_sht(data: bytearray, info: ElfInfo) -> List[str]:
    """从 PHT + .dynamic 重建最小可用 SHT。

    v6 目标：
    1) 不再用整段 RX LOAD 伪造 .text，避免 .text 与 .hash/.dynsym/.dynstr 等元数据大面积重叠；
    2) 按 DT_HASH / DT_GNU_HASH / DT_VERSYM / DT_VERNEED 推断更准确的动态 section；
    3) 再为剩余可执行/RW 文件范围补 .text/.data，用于 IDA/Ghidra 稳定分析。
    """
    actions: List[str] = []
    if not info.valid_header or not info.loads():
        return actions

    dv, _ = dynamic_valid(info)
    entries = parse_dynamic_entries(info) if dv else []
    tags = dyn_tag_values(entries)
    sections: List[NewSection] = []
    used_names = set()

    def unique_name(base: str) -> str:
        if base not in used_names:
            return base
        i = 2
        while f"{base}{i}" in used_names:
            i += 1
        return f"{base}{i}"

    def add(sec: NewSection, *, allow_zero: bool = False, unique: bool = False) -> None:
        if sec.sh_size == 0 and not allow_zero:
            return
        if sec.sh_type != SHT_NOBITS and not _valid_file_range(info, sec.sh_offset, sec.sh_size, allow_zero=allow_zero):
            return
        name = unique_name(sec.name) if unique else sec.name
        if name in used_names:
            return
        if name != sec.name:
            sec = NewSection(name, sec.sh_type, sec.sh_flags, sec.sh_addr, sec.sh_offset,
                             sec.sh_size, sec.sh_link_name, sec.sh_info,
                             sec.sh_addralign, sec.sh_entsize)
        sections.append(sec)
        used_names.add(sec.name)

    def tag_off(tag: int) -> Optional[int]:
        v = first_dyn_value(tags, tag)
        return dyn_vaddr_to_offset(info, v) if v else None

    def tag_v(tag: int) -> int:
        return first_dyn_value(tags, tag)

    # 所有已知动态对象起点，用来裁剪可变长度 section，避免 .gnu.hash/.hash 等互相覆盖。
    known_starts = set()
    for t in (DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_REL, DT_JMPREL,
              DT_INIT_ARRAY, DT_FINI_ARRAY, DT_DYNAMIC if False else DT_NULL,
              DT_VERSYM, DT_VERNEED, DT_VERDEF, DT_RELR):
        if t == DT_NULL:
            continue
        off = tag_off(t)
        if off is not None:
            known_starts.add(off)
    dyn = info.dynamic()
    if dyn is not None and dyn.p_offset > 0:
        known_starts.add(dyn.p_offset)
    for ph in info.phdrs:
        if ph.p_type in (PT_NOTE, PT_GNU_EH_FRAME) and ph.p_filesz > 0:
            known_starts.add(ph.p_offset)

    def next_start_after(off: int, default: int) -> int:
        later = [x for x in known_starts if x > off]
        end = min(later) if later else default
        return min(end, info.size)

    syment = first_dyn_value(tags, DT_SYMENT, 24 if info.is64 else 16)
    relaent = first_dyn_value(tags, DT_RELAENT, 24 if info.is64 else 12)
    relent = first_dyn_value(tags, DT_RELENT, 16 if info.is64 else 8)
    sym_v = tag_v(DT_SYMTAB)
    str_v = tag_v(DT_STRTAB)
    sym_off = dyn_vaddr_to_offset(info, sym_v) if sym_v else None
    str_off = dyn_vaddr_to_offset(info, str_v) if str_v else None
    sym_count = infer_dynsym_count(info, tags, sym_v, str_v, syment) if sym_v else 0

    # 1) 先恢复动态元数据 section。
    # NOTE / EH_FRAME_HDR
    note_idx = 0
    for ph in info.phdrs:
        if ph.p_type == PT_NOTE and ph.p_filesz > 0:
            note_idx += 1
            add(NewSection('.note' if note_idx == 1 else f'.note{note_idx}',
                           SHT_NOTE, SHF_ALLOC if ph.p_vaddr else 0,
                           ph.p_vaddr, ph.p_offset, ph.p_filesz, '', 0, 4, 0), unique=False)
        elif ph.p_type == PT_GNU_EH_FRAME and ph.p_filesz > 0:
            add(NewSection('.eh_frame_hdr', SHT_PROGBITS, SHF_ALLOC,
                           ph.p_vaddr, ph.p_offset, ph.p_filesz, '', 0, 4, 0))

    # GNU hash：按 GNU hash header + bloom + buckets + chains 推断，且裁剪到下一个已知 section。
    gnu_hash_v = tag_v(DT_GNU_HASH)
    gnu_hash_off = dyn_vaddr_to_offset(info, gnu_hash_v) if gnu_hash_v else None
    if gnu_hash_off is not None and gnu_hash_off + 16 <= info.size:
        nbuckets = u32(info.data, gnu_hash_off)
        symoffset = u32(info.data, gnu_hash_off + 4)
        bloom_size = u32(info.data, gnu_hash_off + 8)
        ptr_size = 8 if info.is64 else 4
        if 0 < nbuckets < 0x100000 and 0 < bloom_size < 0x100000:
            base_size = 16 + bloom_size * ptr_size + nbuckets * 4
            chain_count = max(0, sym_count - symoffset) if sym_count else 0
            gnu_size = base_size + chain_count * 4
            hard_end = next_start_after(gnu_hash_off, gnu_hash_off + max(gnu_size, base_size))
            gnu_size = min(max(base_size, gnu_size), max(0, hard_end - gnu_hash_off))
            add(NewSection('.gnu.hash', SHT_GNU_HASH, SHF_ALLOC, gnu_hash_v, gnu_hash_off,
                           gnu_size, '.dynsym', 0, 8 if info.is64 else 4, 0))

    # SYSV hash：nbucket/nchain 可以直接算完整大小，也裁剪到下一个已知起点。
    hash_v = tag_v(DT_HASH)
    hash_off = dyn_vaddr_to_offset(info, hash_v) if hash_v else None
    if hash_off is not None and hash_off + 8 <= info.size:
        nbucket = u32(info.data, hash_off)
        nchain = u32(info.data, hash_off + 4)
        if 0 < nbucket < 0x100000 and 0 < nchain < 0x100000:
            hash_size = 8 + (nbucket + nchain) * 4
            hard_end = next_start_after(hash_off, hash_off + hash_size)
            hash_size = min(hash_size, max(0, hard_end - hash_off))
            add(NewSection('.hash', SHT_HASH, SHF_ALLOC, hash_v, hash_off, hash_size,
                           '.dynsym', 0, 4, 4))

    strsz = first_dyn_value(tags, DT_STRSZ)
    if str_off is not None and strsz > 0:
        add(NewSection('.dynstr', SHT_STRTAB, SHF_ALLOC, str_v, str_off, strsz,
                       '', 0, 1, 0))

    if sym_off is not None and sym_count > 0:
        add(NewSection('.dynsym', SHT_DYNSYM, SHF_ALLOC, sym_v, sym_off,
                       sym_count * syment, '.dynstr', sym_count, 8 if info.is64 else 4, syment))

    versym_v = tag_v(DT_VERSYM)
    versym_off = dyn_vaddr_to_offset(info, versym_v) if versym_v else None
    if versym_off is not None and sym_count > 0:
        versym_size = sym_count * 2
        hard_end = next_start_after(versym_off, versym_off + versym_size)
        versym_size = min(versym_size, max(0, hard_end - versym_off))
        add(NewSection('.gnu.version', SHT_GNU_VERSYM, SHF_ALLOC, versym_v, versym_off,
                       versym_size, '.dynsym', 0, 2, 2))

    verneed_v = tag_v(DT_VERNEED)
    verneed_off = dyn_vaddr_to_offset(info, verneed_v) if verneed_v else None
    verneed_num = first_dyn_value(tags, DT_VERNEEDNUM)
    if verneed_off is not None:
        hard_end = next_start_after(verneed_off, verneed_off + 0x1000)
        verneed_size = max(0, hard_end - verneed_off)
        add(NewSection('.gnu.version_r', SHT_GNU_VERNEED, SHF_ALLOC, verneed_v, verneed_off,
                       verneed_size, '.dynstr', verneed_num, 4, 0))

    verdef_v = tag_v(DT_VERDEF)
    verdef_off = dyn_vaddr_to_offset(info, verdef_v) if verdef_v else None
    verdef_num = first_dyn_value(tags, DT_VERDEFNUM)
    if verdef_off is not None:
        hard_end = next_start_after(verdef_off, verdef_off + 0x1000)
        verdef_size = max(0, hard_end - verdef_off)
        add(NewSection('.gnu.version_d', SHT_GNU_VERDEF, SHF_ALLOC, verdef_v, verdef_off,
                       verdef_size, '.dynstr', verdef_num, 4, 0))

    rela_v = tag_v(DT_RELA)
    rela_sz = first_dyn_value(tags, DT_RELASZ)
    rela_off = dyn_vaddr_to_offset(info, rela_v) if rela_v else None
    if rela_off is not None and rela_sz > 0:
        add(NewSection('.rela.dyn', SHT_RELA, SHF_ALLOC, rela_v, rela_off, rela_sz,
                       '.dynsym', 0, 8 if info.is64 else 4, relaent))

    rel_v = tag_v(DT_REL)
    rel_sz = first_dyn_value(tags, DT_RELSZ)
    rel_off = dyn_vaddr_to_offset(info, rel_v) if rel_v else None
    if rel_off is not None and rel_sz > 0:
        add(NewSection('.rel.dyn', SHT_REL, SHF_ALLOC, rel_v, rel_off, rel_sz,
                       '.dynsym', 0, 8 if info.is64 else 4, relent))

    relr_v = tag_v(DT_RELR)
    relr_sz = first_dyn_value(tags, DT_RELRSZ)
    relr_off = dyn_vaddr_to_offset(info, relr_v) if relr_v else None
    relrent = first_dyn_value(tags, DT_RELRENT, 8 if info.is64 else 4)
    if relr_off is not None and relr_sz > 0:
        add(NewSection('.relr.dyn', SHT_RELR, SHF_ALLOC, relr_v, relr_off, relr_sz,
                       '', 0, 8 if info.is64 else 4, relrent))

    jmp_v = tag_v(DT_JMPREL)
    plt_sz = first_dyn_value(tags, DT_PLTRELSZ)
    plt_rel = first_dyn_value(tags, DT_PLTREL)
    jmp_off = dyn_vaddr_to_offset(info, jmp_v) if jmp_v else None
    if jmp_off is not None and plt_sz > 0:
        if plt_rel == DT_RELA:
            add(NewSection('.rela.plt', SHT_RELA, SHF_ALLOC, jmp_v, jmp_off, plt_sz,
                           '.dynsym', 0, 8 if info.is64 else 4, relaent))
        else:
            add(NewSection('.rel.plt', SHT_REL, SHF_ALLOC, jmp_v, jmp_off, plt_sz,
                           '.dynsym', 0, 8 if info.is64 else 4, relent))

    init_v = tag_v(DT_INIT_ARRAY)
    init_sz = first_dyn_value(tags, DT_INIT_ARRAYSZ)
    init_off = dyn_vaddr_to_offset(info, init_v) if init_v else None
    if init_off is not None and init_sz > 0:
        add(NewSection('.init_array', SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE,
                       init_v, init_off, init_sz, '', 0, 8 if info.is64 else 4,
                       8 if info.is64 else 4))

    fini_v = tag_v(DT_FINI_ARRAY)
    fini_sz = first_dyn_value(tags, DT_FINI_ARRAYSZ)
    fini_off = dyn_vaddr_to_offset(info, fini_v) if fini_v else None
    if fini_off is not None and fini_sz > 0:
        add(NewSection('.fini_array', SHT_FINI_ARRAY, SHF_ALLOC | SHF_WRITE,
                       fini_v, fini_off, fini_sz, '', 0, 8 if info.is64 else 4,
                       8 if info.is64 else 4))

    if dyn is not None and dyn.p_offset > 0 and dyn.p_filesz > 0:
        add(NewSection('.dynamic', SHT_DYNAMIC,
                       SHF_ALLOC | (SHF_WRITE if (dyn.p_flags & 2) else 0),
                       dyn.p_vaddr, dyn.p_offset, dyn.p_filesz, '.dynstr', 0,
                       8 if info.is64 else 4, 16 if info.is64 else 8))

    # 2) 再补 LOAD 中未被上述动态元数据覆盖的可分析 section。
    def overlaps_for_load(ph: Phdr) -> List[Tuple[int, int]]:
        ranges = []
        lo = ph.p_offset
        hi = ph.p_offset + ph.p_filesz
        for sec in sections:
            if not (sec.sh_flags & SHF_ALLOC) or sec.sh_type == SHT_NOBITS:
                continue
            a = max(lo, sec.sh_offset)
            b = min(hi, sec.sh_offset + sec.sh_size)
            if a < b:
                ranges.append((a, b))
        return sorted(ranges)

    def add_gap_sections(ph: Phdr, base_name: str, flags: int, min_start_off: Optional[int] = None) -> None:
        lo = ph.p_offset
        hi = ph.p_offset + ph.p_filesz
        if min_start_off is not None:
            lo = max(lo, min_start_off)
        if lo >= hi:
            return
        cur = lo
        for a, b in overlaps_for_load(ph):
            if b <= cur:
                continue
            if a > cur:
                size = a - cur
                add(NewSection(base_name, SHT_PROGBITS, flags,
                               ph.p_vaddr + (cur - ph.p_offset), cur, size, '', 0,
                               16 if (flags & SHF_EXECINSTR) else (8 if info.is64 else 4), 0), unique=True)
            cur = max(cur, b)
        if cur < hi:
            add(NewSection(base_name, SHT_PROGBITS, flags,
                           ph.p_vaddr + (cur - ph.p_offset), cur, hi - cur, '', 0,
                           16 if (flags & SHF_EXECINSTR) else (8 if info.is64 else 4), 0), unique=True)

    # 可执行段的起点：优先从最后一个已知元数据末尾开始，覆盖 PLT；如果没有元数据，就从 entry/函数最小值附近开始。
    func_values: List[int] = []
    if info.e_entry:
        func_values.append(info.e_entry)
    if sym_off is not None and sym_count > 0 and syment > 0 and sym_off + sym_count * syment <= len(data):
        for i in range(sym_count):
            pos = sym_off + i * syment
            if info.is64:
                st_info = data[pos + 4]
                st_value = struct.unpack_from('<Q', data, pos + 8)[0]
            else:
                st_value = struct.unpack_from('<I', data, pos + 4)[0]
                st_info = data[pos + 12]
            if (st_info & 0x0F) == 2 and st_value:
                func_values.append(st_value)

    # 如果存在 PT_GNU_EH_FRAME，.eh_frame_hdr 后到首个代码入口之间通常是 .eh_frame。
    # v5 会把这段误并进 .text，导致 objdump/IDA 从 unwind 数据开始反汇编。
    # v6 先补 .eh_frame，再补 .text。
    for eh in [p for p in info.phdrs if p.p_type == PT_GNU_EH_FRAME and p.p_filesz > 0]:
        eh_end = eh.p_offset + eh.p_filesz
        for ph in info.loads():
            if not (ph.p_flags & PF_X):
                continue
            if not (ph.p_offset <= eh_end < ph.p_offset + ph.p_filesz):
                continue
            code_candidates = [ph.p_offset + (v - ph.p_vaddr)
                               for v in func_values
                               if ph.p_vaddr <= v < ph.p_vaddr + ph.p_filesz]
            if not code_candidates:
                continue
            code_start = min(code_candidates)
            if eh_end < code_start and _valid_file_range(info, eh_end, code_start - eh_end):
                add(NewSection('.eh_frame', SHT_PROGBITS, SHF_ALLOC,
                               ph.p_vaddr + (eh_end - ph.p_offset), eh_end,
                               code_start - eh_end, '', 0, 8 if info.is64 else 4, 0))

    for ph in info.loads():
        if ph.p_filesz <= 0:
            continue
        if ph.p_flags & PF_X:
            known_end = ph.p_offset
            for sec in sections:
                if sec.sh_type == SHT_NOBITS:
                    continue
                if ph.p_offset <= sec.sh_offset < ph.p_offset + ph.p_filesz:
                    known_end = max(known_end, sec.sh_offset + sec.sh_size)
            candidate_vs = [v for v in func_values if ph.p_vaddr <= v < ph.p_vaddr + ph.p_filesz]
            if candidate_vs:
                code_start = ph.p_offset + (min(candidate_vs) - ph.p_vaddr)
                # 已知元数据可能只覆盖到 .eh_frame_hdr，但真正代码从 entry/func 起。
                min_start = max(known_end, code_start)
            elif known_end > ph.p_offset:
                min_start = known_end
            else:
                min_start = ph.p_offset
            # 不要从 ELF header/PHT 开始伪造 .text。
            min_start = max(min_start, info.e_phoff + info.e_phnum * info.e_phentsize)
            add_gap_sections(ph, '.text', SHF_ALLOC | SHF_EXECINSTR, min_start)
        elif ph.p_flags & 2:
            add_gap_sections(ph, '.data', SHF_ALLOC | SHF_WRITE, None)
        else:
            add_gap_sections(ph, '.rodata', SHF_ALLOC, None)

    if not sections:
        return actions

    # 尽量按文件偏移排序，让 readelf/IDA 映射更自然；NULL section 后从小到大。
    sections.sort(key=lambda s: (s.sh_offset, s.sh_addr, s.name))

    # NULL section + 实际 section + .shstrtab。
    names = [''] + [s.name for s in sections] + ['.shstrtab']
    shstr = bytearray(b'\x00')
    name_off: Dict[str, int] = {'': 0}
    for name in names[1:]:
        if name not in name_off:
            name_off[name] = len(shstr)
            shstr += name.encode('ascii') + b'\x00'

    shstr_off = align_up(len(data), 8 if info.is64 else 4)
    if len(data) < shstr_off:
        data.extend(b'\x00' * (shstr_off - len(data)))
    data.extend(shstr)
    shoff = align_up(len(data), 8 if info.is64 else 4)
    if len(data) < shoff:
        data.extend(b'\x00' * (shoff - len(data)))

    shentsize = 64 if info.is64 else 40
    shnum = len(sections) + 2
    shstrndx = shnum - 1
    table = bytearray(shentsize * shnum)

    index_by_name = {s.name: i + 1 for i, s in enumerate(sections)}
    index_by_name['.shstrtab'] = shstrndx

    patched_syms = patch_dynsym_section_indices(data, info, sections, index_by_name,
                                                sym_off, sym_count, syment)
    if patched_syms:
        actions.append(f'patch dynsym st_shndx: {patched_syms}')

    def sec_link(sec: NewSection) -> int:
        return index_by_name.get(sec.sh_link_name, 0) if sec.sh_link_name else 0

    def write_one(idx: int, sec: NewSection) -> None:
        base = idx * shentsize
        if info.is64:
            struct.pack_into('<IIQQQQIIQQ', table, base,
                             name_off[sec.name], sec.sh_type, sec.sh_flags, sec.sh_addr,
                             sec.sh_offset, sec.sh_size, sec_link(sec), sec.sh_info,
                             sec.sh_addralign, sec.sh_entsize)
        else:
            struct.pack_into('<IIIIIIIIII', table, base,
                             name_off[sec.name], sec.sh_type, sec.sh_flags & 0xFFFFFFFF,
                             sec.sh_addr & 0xFFFFFFFF, sec.sh_offset & 0xFFFFFFFF,
                             sec.sh_size & 0xFFFFFFFF, sec_link(sec), sec.sh_info,
                             sec.sh_addralign & 0xFFFFFFFF, sec.sh_entsize & 0xFFFFFFFF)

    for i, sec in enumerate(sections, 1):
        write_one(i, sec)
    shstr_sec = NewSection('.shstrtab', SHT_STRTAB, 0, 0, shstr_off, len(shstr), '', 0, 1, 0)
    write_one(shstrndx, shstr_sec)
    data.extend(table)
    set_e_shdr_info(data, info, shoff, shentsize, shnum, shstrndx)
    actions.append(f'rebuild minimal SHT: {shnum} sections')
    return actions


def patch_basic_header(data: bytearray, info: ElfInfo) -> None:
    if data[:4] != ELF_MAGIC:
        data[:4] = ELF_MAGIC
    data[5] = 1  # little-endian
    data[6] = 1  # version
    if info.is64:
        p16(data, 0x34, 64)
    else:
        p16(data, 0x28, 52)


def repair_elf(data_in: bytes, *, strip_bad_sht: bool = True, rebuild_bad_sht: bool = True, drop_unrecoverable_dynamic: bool = True) -> Tuple[bytes, List[str]]:
    data = bytearray(data_in)
    actions: List[str] = []
    info = ElfInfo(bytes(data))
    if not info.valid_header:
        raise ValueError("not a recognizable little-endian ELF32/ELF64")

    patch_basic_header(data, info)
    info = ElfInfo(bytes(data))

    ok, reason = pht_valid(info)
    if not ok and not pht_error_is_recoverable(reason):
        raise ValueError(f"fatal PHT error: {reason}")
    if not ok:
        actions.append(f"recoverable PHT issue: {reason}")

    # 1) 修复 LOAD p_offset：从 memory-layout/p_offset=p_vaddr 还原为更合理的 file-layout。
    #    注意：这一步必须允许 LOAD_FILESZ_OOB 继续往下走，否则 liball_in_one 这类
    #    “offset/size 同时错”的 dump 会在清 SHT 前被直接判死。
    offset_map = infer_file_layout_offsets(info)
    for ph in info.loads():
        new_off = offset_map.get(ph.idx, ph.p_offset)
        if new_off != ph.p_offset:
            set_ph_offset(data, info, ph, new_off)
            actions.append(f"PT_LOAD[{ph.idx}].p_offset: 0x{ph.p_offset:x} -> 0x{new_off:x}")

    # 1.2) 修复非 LOAD Program Header 的 p_offset。
    #      旧逻辑只修 PT_DYNAMIC；但 PT_NOTE/PT_TLS/PT_GNU_RELRO/PT_ARM_EXIDX
    #      也可能被 dump 成 p_offset == p_vaddr，IDA 会继续报段范围或映射异常。
    info_ph = ElfInfo(bytes(data))
    mapped_loads = info_ph.loads()
    for ph in info_ph.phdrs:
        if ph.p_type in (PT_NULL, PT_LOAD, PT_GNU_STACK) or ph.p_filesz == 0:
            continue
        mapped = vaddr_to_offset(mapped_loads, ph.p_vaddr)
        if mapped is None:
            continue
        # 只修明显的 memory-layout / 越界 / 内容明显更可信的情况。
        if ph.p_offset == ph.p_vaddr or ph.p_offset >= info_ph.size or ph.p_offset + ph.p_filesz > info_ph.size:
            if mapped != ph.p_offset and mapped + min(ph.p_filesz, 1) <= info_ph.size:
                set_ph_offset(data, info_ph, ph, mapped)
                actions.append(f"PHDR[{ph.idx}].p_offset: 0x{ph.p_offset:x} -> 0x{mapped:x}")

    # 1.5) 修复所有 PHDR 的文件范围越界。
    #      典型 IDA 报错：Data size 706016 is incorrect, maximum possible value is 363912。
    #      对 dump 来说，p_memsz 代表运行时范围，p_filesz 代表文件中实际可读范围；
    #      所以只裁 p_filesz，不裁 p_memsz。
    info_extent = ElfInfo(bytes(data))
    actions.extend(clamp_phdr_file_extents(data, info_extent))

    # 2) 修复 PT_DYNAMIC p_offset：使用 p_vaddr 经 LOAD 映射后的真实文件偏移。
    info2 = ElfInfo(bytes(data))
    offset_map2 = infer_file_layout_offsets(info2)
    dyn = info2.dynamic()
    dyn_off = find_dynamic_offset(info2, offset_map2)
    if dyn is not None:
        if dyn_off is not None:
            if dyn.p_offset != dyn_off:
                set_ph_offset(data, info2, dyn, dyn_off)
                actions.append(f"PT_DYNAMIC.p_offset: 0x{dyn.p_offset:x} -> 0x{dyn_off:x}")
        elif drop_unrecoverable_dynamic:
            set_ph_type(data, dyn, PT_NULL)
            actions.append("PT_DYNAMIC invalid and unrecoverable -> PT_NULL")

    # 3) Section Header 修复：坏 SHT 不能保留。
    #    旧版本直接 clear_sht，虽然能让 readelf/IDA 不再被坏表误导，
    #    但 IDA/Ghidra 中会变成 no sections。现在优先从 PHT + .dynamic
    #    重建最小 SHT；重建失败才清空。
    info3 = ElfInfo(bytes(data))
    sv, sreason = sht_valid(info3)
    if strip_bad_sht and (not sv or (rebuild_bad_sht and sreason == "NO_SHT")):
        if rebuild_bad_sht:
            rebuild_actions = rebuild_minimal_sht(data, info3)
            if rebuild_actions:
                actions.append(f"replace invalid SHT: {sreason}" if not sv else "add missing SHT")
                actions.extend(rebuild_actions)
            else:
                clear_sht(data, info3)
                actions.append(f"clear invalid SHT: {sreason}")
        else:
            clear_sht(data, info3)
            actions.append(f"clear invalid SHT: {sreason}")

    # 4) 再做一次 PHDR 裁剪，覆盖 Dynamic p_offset 变化或其他 PHDR 边界变化。
    info4 = ElfInfo(bytes(data))
    actions.extend(clamp_phdr_file_extents(data, info4))

    # 5) 如果 dynamic 仍然坏，最后降级，避免 IDA/readelf 被误导。
    info5 = ElfInfo(bytes(data))
    dv, dreason = dynamic_valid(info5)
    if not dv and drop_unrecoverable_dynamic:
        dyn = info5.dynamic()
        if dyn is not None:
            set_ph_type(data, dyn, PT_NULL)
            actions.append(f"PT_DYNAMIC still invalid ({dreason}) -> PT_NULL")

    # 6) 最终校验：如果还存在 PHDR 文件范围越界，继续裁剪一次。
    info6 = ElfInfo(bytes(data))
    extent_issues = pht_extent_issues(info6)
    if extent_issues:
        actions.append("remaining PHDR extent issues: " + ",".join(extent_issues))
        actions.extend(clamp_phdr_file_extents(data, info6))

    if not actions:
        actions.append("no structural change")
    return bytes(data), actions

SO_MIN_SIZE = 0x40  # 最小 ELF 头大小，用于快速跳过明显非 ELF 文件


def validate_elf_deep(data: bytes) -> bool:
    """深度校验 ELF/SO 结构是否可信。兼容 repack_apk.py 的导入。

    检查: EI_CLASS / EI_DATA / e_type / e_machine / PHT / PT_LOAD。
    """
    try:
        info = ElfInfo(data)
    except Exception:
        return False
    if not info.valid_header:
        return False
    if info.e_type != ET_DYN:
        return False
    if info.e_machine not in (EM_ARM, EM_AARCH64):
        return False
    # PHT 基本自洽
    if info.e_phoff == 0 or info.e_phnum == 0:
        return False
    if info.e_phentsize == 0:
        return False
    if info.e_phoff + info.e_phnum * info.e_phentsize > info.size:
        return False
    # 至少一个 PT_LOAD
    if not any(p.p_type == PT_LOAD for p in info.phdrs):
        return False
    return True


def classify_bytes(data: bytes) -> Tuple[str, str]:
    info = ElfInfo(data)
    ok, preason = pht_valid(info)
    fatal_pht = bool(not ok and not pht_error_is_recoverable(preason))
    if fatal_pht:
        return "bad", preason

    dv, dreason = dynamic_valid(info)
    sv, sreason = sht_valid(info)
    offset_map = infer_file_layout_offsets(info)
    load_mismatch = any(offset_map.get(p.idx, p.p_offset) != p.p_offset for p in info.loads())
    extent_issues = pht_extent_issues(info)
    dyn_recoverable = False
    if not dv:
        dyn_recoverable = find_dynamic_offset(info, offset_map) is not None

    issues = []
    if not ok:
        issues.append(preason)
    if load_mismatch:
        issues.append("LOAD_MEMORY_LAYOUT")
    if extent_issues:
        issues.extend(extent_issues)
    if not dv:
        issues.append("DYNAMIC_RECOVERABLE" if dyn_recoverable else dreason)
    if not sv:
        issues.append(sreason)
    if issues:
        return "repairable", ";".join(issues)
    return "ida-ready", "ok"

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def repair_file(path: str, out: Optional[str], in_place: bool, backup: bool, rebuild_sht: bool = True) -> Tuple[str, List[str]]:
    data = read_file(path)
    fixed, actions = repair_elf(data, rebuild_bad_sht=rebuild_sht)
    dst = path if in_place else (out or default_out_path(path))
    if in_place and backup:
        bak = path + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(path, bak)
    write_file(dst, fixed)
    return dst, actions


def default_out_path(path: str) -> str:
    root, ext = os.path.splitext(path)
    if ext.lower() == ".so":
        return root + ".fixed.so"
    return path + ".fixed"


def _carrier_repair_so_v2(dump_path: str, orig_data: bytes, out_path: Optional[str] = None) -> Tuple[bool, int]:
    """以 APK 原始 SO 为骨架，只覆盖 dump 中可信的 RX 页。"""
    dump = read_file(dump_path)
    orig_info = ElfInfo(orig_data)
    dump_info = ElfInfo(dump)
    ok, _ = pht_valid(orig_info)
    if not ok:
        return False, 0
    if not dump_info.valid_header:
        return False, 0

    orig = bytearray(orig_data)
    pages = 0
    for ph in orig_info.loads():
        if not (ph.p_flags & PF_X):
            continue
        if ph.p_offset + ph.p_filesz > len(orig):
            continue
        # dump 可能是 file-layout，也可能是 memory-layout；优先按 vaddr 映射，失败再按原 offset。
        dump_off = vaddr_to_offset(dump_info.loads(), ph.p_vaddr)
        if dump_off is None or dump_off + ph.p_filesz > len(dump):
            dump_off = ph.p_offset
        if dump_off + ph.p_filesz > len(dump):
            continue
        page_size = 0x1000
        for rel in range(0, ph.p_filesz, page_size):
            chunk = dump[dump_off + rel: dump_off + rel + page_size]
            if not chunk:
                break
            if chunk == b"\x00" * len(chunk):
                continue
            # 代码页不能用过严的 30% 零比例过滤，AArch64 代码/rodata 中 00 很常见；只过滤极端空洞页。
            if chunk.count(0) / len(chunk) > 0.85:
                continue
            dst = ph.p_offset + rel
            orig[dst: dst + len(chunk)] = chunk
            pages += 1

    write_file(out_path or dump_path, bytes(orig))
    return pages > 0, pages


def build_apk_so_index(apk_path: str) -> Dict[Tuple[str, str], bytes]:
    out: Dict[Tuple[str, str], bytes] = {}
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            if not name.endswith(".so"):
                continue
            parts = name.split("/")
            if len(parts) >= 3 and parts[-3] == "lib":
                abi = parts[-2]
                base = parts[-1]
                out[(abi, base)] = z.read(name)
    return out


def abi_from_data(data: bytes) -> str:
    info = ElfInfo(data)
    if info.e_machine == EM_AARCH64:
        return "arm64-v8a"
    if info.e_machine == EM_ARM:
        return "armeabi-v7a"
    return "unknown"


def iter_so_files(target: str) -> List[str]:
    if os.path.isdir(target):
        return sorted(glob.glob(os.path.join(target, "**", "*.so"), recursive=True))
    return [target]




# ---------------------------------------------------------------------------
# Compatibility API for existing NHDD GUI/TUI
# ---------------------------------------------------------------------------
def _move_to_bad(path: str) -> None:
    bad_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "bad")
    os.makedirs(bad_dir, exist_ok=True)
    dst = os.path.join(bad_dir, os.path.basename(path))
    if os.path.abspath(path) == os.path.abspath(dst):
        return
    try:
        if os.path.exists(dst):
            os.remove(dst)
        os.replace(path, dst)
    except OSError:
        pass


def classify_so_full(path: str, layout: str = "file") -> Tuple[str, str, Dict[str, str]]:
    """兼容旧版 fix_so.py：返回 (category, reason, details)。

    category 取值：ida-ready / repairable / bad。
    layout 参数保留用于兼容旧 GUI/TUI；新版会自动判断 file-layout / memory-layout。
    """
    try:
        data = read_file(path)
        cat, reason = classify_bytes(data)
        return cat, reason, {}
    except Exception as e:
        return "bad", f"read_or_parse_error: {e}", {}


def fix_so_file(path: str, layout: str = "file") -> Tuple[bool, bool, Optional[str]]:
    """兼容旧版 fix_so.py：返回 (fixed, deleted, err)。

    fixed: 文件是否被修改；deleted: 是否移动到 bad/；err: None 或错误说明。
    """
    try:
        old = read_file(path)
    except Exception as e:
        return False, False, f"read {path}: {e}"

    cat, reason = classify_bytes(old)
    if cat == "bad":
        _move_to_bad(path)
        return False, True, f"bad: {reason}, moved to bad/"

    try:
        new, actions = repair_elf(old)
    except Exception as e:
        _move_to_bad(path)
        return False, True, f"repair failed: {e}, moved to bad/"

    changed = new != old
    if changed:
        try:
            write_file(path, new)
        except Exception as e:
            return False, False, f"write {path}: {e}"
    return changed, False, None


def fix_directory_aligned(dir_path: str) -> Dict[str, object]:
    """兼容旧版 fix_so.py：递归修复目录下所有 .so，返回 stats 字典。"""
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


def carrier_repair_so(dump_path: str, orig_data: bytes, out_path: Optional[str] = None) -> bool:
    """兼容旧版 fix_so.py：以原 APK SO 为 carrier，返回是否覆盖了 RX 页。"""
    changed, _pages = _carrier_repair_so_v2(dump_path, orig_data, out_path)
    return changed


def fix_directory_carrier(so_dir: str, apk_path: str) -> Dict[str, object]:
    """兼容旧版 fix_so.py：以 APK 原始 SO 为骨架，覆盖 dump RX 段。"""
    so_files = sorted(glob.glob(os.path.join(so_dir, "**", "*.so"), recursive=True))
    stats = {"total": len(so_files), "ok": 0, "fixed": 0, "bad": 0, "bad_files": []}
    if not os.path.exists(apk_path):
        return fix_directory_aligned(so_dir)

    try:
        apk_sos = build_apk_so_index(apk_path)
    except Exception:
        return fix_directory_aligned(so_dir)

    for path in so_files:
        name = os.path.basename(path)
        try:
            data = read_file(path)
            abi = abi_from_data(data)
            orig = apk_sos.get((abi, name))
        except Exception:
            orig = None

        if orig is None:
            fixed, deleted, err = fix_so_file(path)
            if err is not None:
                if deleted:
                    stats["bad"] += 1
                    stats["bad_files"].append(name)
                continue
            if fixed:
                stats["fixed"] += 1
            stats["ok"] += 1
            continue

        try:
            changed, pages = _carrier_repair_so_v2(path, orig, path)
            stats["ok"] += 1
            if changed or pages > 0:
                stats["fixed"] += 1
        except Exception as e:
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


def fix_directory_with_apk(so_dir: str, apk_path: str) -> Dict[str, object]:
    """兼容旧版 fix_so.py：新版统一走 carrier 优先策略。"""
    return fix_directory_carrier(so_dir, apk_path)


def main() -> int:
    ap = argparse.ArgumentParser(description="Repair Android ELF/SO memory dumps for static analysis.")
    ap.add_argument("target", help=".so file or directory")
    ap.add_argument("--out", help="output path for single-file mode")
    ap.add_argument("--in-place", action="store_true", help="overwrite input file")
    ap.add_argument("--no-backup", action="store_true", help="do not create .bak when --in-place")
    ap.add_argument("--classify", action="store_true", help="only classify; do not write")
    ap.add_argument("--apk", help="original APK path for carrier mode")
    ap.add_argument("--carrier", action="store_true", help="use original APK SO as carrier, overlay dump RX pages")
    ap.add_argument("--no-rebuild-sht", action="store_true", help="clear bad SHT instead of rebuilding minimal sections")
    args = ap.parse_args()

    files = iter_so_files(args.target)
    if not files or any(not os.path.exists(p) for p in files):
        print(f"not found: {args.target}", file=sys.stderr)
        return 2

    if args.classify:
        counts: Dict[str, int] = {}
        for path in files:
            cat, reason = classify_bytes(read_file(path))
            counts[cat] = counts.get(cat, 0) + 1
            print(f"{cat:12s} {reason:45s} {path}")
        print("summary:", " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        return 0

    if args.carrier:
        if not args.apk:
            print("--carrier requires --apk app.apk", file=sys.stderr)
            return 2
        apk_sos = build_apk_so_index(args.apk)
        for path in files:
            data = read_file(path)
            abi = abi_from_data(data)
            orig = apk_sos.get((abi, os.path.basename(path)))
            if orig is None:
                print(f"carrier-miss {path}; fallback basic repair")
                dst, actions = repair_file(path, args.out, args.in_place, not args.no_backup, not args.no_rebuild_sht)
                print(f"written: {dst}")
                for a in actions:
                    print(f"  - {a}")
                continue
            dst = path if args.in_place else (args.out or default_out_path(path))
            changed, pages = _carrier_repair_so_v2(path, orig, dst)
            print(f"written: {dst}")
            print(f"  - carrier overlay RX pages: {pages}; changed={changed}")
        return 0

    if os.path.isdir(args.target) and args.out:
        print("--out is only valid for single-file mode", file=sys.stderr)
        return 2

    for path in files:
        try:
            dst, actions = repair_file(path, args.out, args.in_place, not args.no_backup, not args.no_rebuild_sht)
            print(f"written: {dst}")
            for a in actions:
                print(f"  - {a}")
        except Exception as e:
            print(f"error: {path}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
