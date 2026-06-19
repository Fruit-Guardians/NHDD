#!/usr/bin/env python3
"""Fix DEX header fields and checksums for memory-dumped DEX files.

Aligns with the C engine (nhdd.c::fix_dex_header_and_checksums) and the Go
desktop GUI (gui/dexfix.go::FixDexFile). Repairs, in order:

  1. header_size (0x24) -> 0x70
  2. endian_tag  (0x28) -> 0x12345678
  3. file_size   (0x20) -> actual file length
  4. SHA-1 signature (0x0C, 20 bytes) over bytes[0x20:]
  5. Adler32 checksum (0x08, 4 bytes) over bytes[0x0C:]

Order matters: Adler32 covers the SHA-1 field, so SHA-1 must be recomputed first.
"""
import sys, struct, hashlib, zlib

DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_TAG  = 0x12345678

def u32(b, off): return struct.unpack_from('<I', b, off)[0]
def put32(b, off, v): struct.pack_into('<I', b, off, v)

def fix_dex(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < 0x24:
        print(f"  SKIP: too small"); return False
    if data[0:3] != b'dex':
        print(f"  SKIP: not a DEX file"); return False

    changed = []
    if u32(data, 0x24) != DEX_HEADER_SIZE:
        put32(data, 0x24, DEX_HEADER_SIZE); changed.append('header_size')
    if u32(data, 0x28) != DEX_ENDIAN_TAG:
        put32(data, 0x28, DEX_ENDIAN_TAG); changed.append('endian_tag')
    if u32(data, 0x20) != len(data):
        put32(data, 0x20, len(data)); changed.append('file_size')

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
        with open(path, 'wb') as f: f.write(data)
        print(f"  FIXED: {', '.join(changed)} (cksum 0x{old_cksum:08x} -> 0x{checksum:08x})")
        return True
    else:
        print(f"  OK: already valid")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2: print(f"Usage: {sys.argv[0]} <dex_file>"); sys.exit(1)
    for path in sys.argv[1:]: print(f"Fixing: {path}"); fix_dex(path)
