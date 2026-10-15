#!/usr/bin/env python3
"""Deterministic fixture generator for the NHDD repair-pipeline contract tests.

Generates tests/fixtures/dex/*.dex and tests/fixtures/so/*.so plus manifest.json.
Byte-for-byte reproducible: fixed patterns only, no timestamps or randomness.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIXDIR = os.path.join(HERE, "fixtures")
DEXDIR = os.path.join(FIXDIR, "dex")
SODIR = os.path.join(FIXDIR, "so")


def u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def u16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


# ---------------------------------------------------------------------------
# DEX builder
# ---------------------------------------------------------------------------
def build_dex() -> bytearray:
    """Structurally valid minimal DEX: header 0x70 + map_list(2 entries) @0x70.

    Total size 0x8C = 0x70 + 4 + 2*12. All section sizes are 0 so both
    validators' per-item loops are vacuously satisfied.
    """
    body = bytearray(0x8C)
    body[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", body, 0x20, 0x8C)        # file_size
    struct.pack_into("<I", body, 0x24, 0x70)        # header_size
    struct.pack_into("<I", body, 0x28, 0x12345678)  # endian_tag
    struct.pack_into("<I", body, 0x34, 0x70)        # map_off
    body[0x70:0x74] = u32(2)                        # map_size = 2
    body[0x74:0x80] = u16(0x0000) + u16(0) + u32(1) + u32(0)       # header_item
    body[0x80:0x8C] = u16(0x1000) + u16(0) + u32(1) + u32(0x70)   # map_list
    # signature = sha1(data[0x20:]) with sig field zeroed, then checksum
    # over data[0x0c:] — same order as both repair pipelines.
    sig = hashlib.sha1(bytes(body[0x20:])).digest()
    body[0x0C:0x20] = sig
    body[0x08:0x0C] = u32(zlib.adler32(bytes(body[0x0C:])) & 0xFFFFFFFF)
    return body


def dex_fixtures() -> dict:
    base = build_dex()
    fx = {"dex_valid.dex": bytes(base)}

    def mutated(fn):
        b = bytearray(base)
        fn(b)
        return bytes(b)

    fx["dex_bad_adler32.dex"] = mutated(lambda b: b.__setitem__(slice(0x08, 0x0C), u32(1)))
    fx["dex_bad_sha1.dex"] = mutated(lambda b: b.__setitem__(0x0C, b[0x0C] ^ 0xFF))
    fx["dex_filesize_low.dex"] = mutated(lambda b: struct.pack_into("<I", b, 0x20, 0x80))
    fx["dex_header_size_bad.dex"] = mutated(lambda b: struct.pack_into("<I", b, 0x24, 0x68))
    fx["dex_endian_bad.dex"] = mutated(lambda b: struct.pack_into("<I", b, 0x28, 0x78563412))
    fx["dex_maplist_off_bad.dex"] = mutated(lambda b: struct.pack_into("<I", b, 0x34, 0xDEADBEEF))
    fx["dex_maplist_count_huge.dex"] = mutated(lambda b: struct.pack_into("<I", b, 0x70, 0xFFFF))
    fx["dex_too_small.dex"] = b"D" * 0x60
    fx["dex_magic_erased.dex"] = mutated(lambda b: b.__setitem__(slice(0, 4), b"\x00\x00\x00\x00"))
    return fx


# ---------------------------------------------------------------------------
# SO builder (ELF64 / aarch64 / ET_DYN, dump-style: no SHT, offset==vaddr)
# ---------------------------------------------------------------------------
def build_so() -> bytearray:
    f = bytearray(0x200)
    f[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # ident: ELF64 LE v1 Linux
    struct.pack_into("<HHI", f, 16, 3, 183, 1)   # e_type=ET_DYN e_machine=EM_AARCH64 e_version
    struct.pack_into("<Q", f, 24, 0)             # e_entry
    struct.pack_into("<Q", f, 32, 64)            # e_phoff
    struct.pack_into("<Q", f, 40, 0)             # e_shoff (no SHT — typical mem dump)
    struct.pack_into("<I", f, 48, 0)             # e_flags
    struct.pack_into("<HHHHHH", f, 52, 64, 56, 2, 0, 0, 0)
    # phdr0 @64: PT_LOAD covering whole file, offset == vaddr (dump alignment)
    struct.pack_into("<IIQQQQQQ", f, 64, 1, 5, 0, 0, 0, 0x200, 0x200, 0x1000)
    # phdr1 @120: PT_DYNAMIC at 0x100
    struct.pack_into("<IIQQQQQQ", f, 120, 2, 6, 0x100, 0x100, 0x100, 0x80, 0x80, 8)
    dyn = [
        (4, 0x140),    # DT_HASH
        (5, 0x148),    # DT_STRTAB
        (6, 0x130),    # DT_SYMTAB
        (10, 0x10),    # DT_STRSZ
        (11, 24),      # DT_SYMENT
        (17, 0x150),   # DT_REL
        (0, 0),        # DT_NULL
    ]
    off = 0x100
    for tag, val in dyn:
        struct.pack_into("<qq", f, off, tag, val)
        off += 16
    assert off == 0x170 or off <= 0x180
    return f


def so_fixtures() -> dict:
    base = build_so()
    fx = {"so_valid.so": bytes(base)}

    def mutated(fn):
        b = bytearray(base)
        fn(b)
        return bytes(b)

    fx["so_magic_erased.so"] = mutated(lambda b: b.__setitem__(slice(0, 4), b"\x00\x00\x00\x00"))

    def skew(b):
        struct.pack_into("<Q", b, 64 + 8, 0x1000)    # phdr0 p_offset (vaddr stays 0)
        struct.pack_into("<Q", b, 120 + 8, 0x1100)   # phdr1 p_offset (vaddr stays 0x100)
    fx["so_offset_skew.so"] = mutated(skew)
    fx["so_et_exec.so"] = mutated(lambda b: struct.pack_into("<H", b, 16, 2))
    fx["so_phnum_bogus.so"] = mutated(lambda b: struct.pack_into("<H", b, 56, 0xFFFF))
    fx["so_tiny.so"] = b"\x7fELF" + b"\x00" * 0x2C
    fx["so_not_elf.so"] = bytes(((i * 7 + 3) & 0xFF) for i in range(0x200))
    return fx


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
# predictions: expected on-disk class per implementation.
#   OK/FIXED/BAD  = committed prediction, "?" = unknown (report only),
#   "N/A"         = not applicable for that implementation (skip judgement).
# v9 column = primitive-level harness (no quarantine semantics), hence N/A
# wherever the baseline would quarantine a file.
FIXTURE_META = [
    # (name, kind, intent, go, python, v9, final_equiv)
    ("dex_valid.dex", "dex", "structurally valid minimal DEX", "OK", "OK", "OK", None),
    ("dex_bad_adler32.dex", "dex", "checksum field corrupted (dumped header)", "FIXED", "FIXED", "FIXED", "dex_valid.dex"),
    ("dex_bad_sha1.dex", "dex", "SHA-1 signature corrupted", "FIXED", "FIXED", "FIXED", "dex_valid.dex"),
    ("dex_filesize_low.dex", "dex", "file_size smaller than actual length", "FIXED", "FIXED", "FIXED", "dex_valid.dex"),
    ("dex_header_size_bad.dex", "dex", "header_size != 0x70", "FIXED", "FIXED", "FIXED", "dex_valid.dex"),
    ("dex_endian_bad.dex", "dex", "endian_tag wrong", "FIXED", "FIXED", "FIXED", "dex_valid.dex"),
    ("dex_maplist_off_bad.dex", "dex", "map_off out of bounds -> needs rebuild", "FIXED", "FIXED", "?", None),
    ("dex_maplist_count_huge.dex", "dex", "map_size 0xFFFF -> needs rebuild", "FIXED", "FIXED", "?", None),
    ("dex_too_small.dex", "dex", "0x60 bytes: quarantine to bad/", "BAD", "BAD", "N/A", None),
    ("dex_magic_erased.dex", "dex", "magic erased: host-level quarantine", "BAD", "BAD", "N/A", None),
    ("so_valid.so", "so", "valid dump-style ELF64 ET_DYN (no SHT)", "OK", "FIXED", "OK", None),
    ("so_magic_erased.so", "so", "ELF magic erased", "FIXED", "FIXED", "FIXED", "so_valid.so"),
    ("so_offset_skew.so", "so", "p_offset != p_vaddr (raw mem dump)", "FIXED", "FIXED", "FIXED", "so_valid.so"),
    ("so_et_exec.so", "so", "ET_EXEC: Go baseline quarantines", "BAD", "BAD", "N/A", None),
    ("so_tiny.so", "so", "0x30 bytes: quarantine", "BAD", "BAD", "N/A", None),
    ("so_not_elf.so", "so", "non-ELF garbage: quarantine", "BAD", "BAD", "N/A", None),
    ("so_phnum_bogus.so", "so", "e_phnum=0xFFFF: PHT bogus", "BAD", "BAD", "N/A", None),
]


def main() -> None:
    dex = dex_fixtures()
    so = so_fixtures()
    os.makedirs(DEXDIR, exist_ok=True)
    os.makedirs(SODIR, exist_ok=True)

    entries = []
    for name, kind, intent, g, p, v, feq in FIXTURE_META:
        data = dex[name] if kind == "dex" else so[name]
        target = os.path.join(DEXDIR if kind == "dex" else SODIR, name)
        with open(target, "wb") as fh:
            fh.write(data)
        entry = {
            "name": name,
            "kind": kind,
            "intent": intent,
            "orig_sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "predict": {"go": g, "python": p, "v9": v},
        }
        if feq:
            entry["final_equiv"] = feq
        entries.append(entry)

    manifest = {"schema": 1, "fixtures": entries}
    with open(os.path.join(FIXDIR, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"generated {len(entries)} fixtures under {FIXDIR}")


if __name__ == "__main__":
    main()
