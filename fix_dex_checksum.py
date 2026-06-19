#!/usr/bin/env python3
"""Fix DEX file checksum and signature for memory-dumped DEX files."""
import sys, struct, hashlib, zlib

def fix_dex(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if len(data) < 0x24: print(f"  SKIP: too small"); return False
    if data[0:3] != b'dex': print(f"  SKIP: not a DEX file"); return False
    sha1 = hashlib.sha1(bytes(data[0x20:])).digest()
    old_sig = bytes(data[0x0C:0x20])
    data[0x0C:0x20] = sha1
    checksum = zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF
    old_cksum = struct.unpack_from('<I', data, 0x08)[0]
    struct.pack_into('<I', data, 0x08, checksum)
    sig_fixed = old_sig != sha1
    cksum_fixed = old_cksum != checksum
    if sig_fixed or cksum_fixed:
        with open(path, 'wb') as f: f.write(data)
        print(f"  FIXED: checksum 0x{old_cksum:08x} -> 0x{checksum:08x}, sig {'changed' if sig_fixed else 'ok'}")
        return True
    else: print(f"  OK: already valid"); return False

if __name__ == '__main__':
    if len(sys.argv) < 2: print(f"Usage: {sys.argv[0]} <dex_file>"); sys.exit(1)
    for path in sys.argv[1:]: print(f"Fixing: {path}"); fix_dex(path)
