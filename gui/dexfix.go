package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"os"
	"path/filepath"
	"strings"
)

const (
	dexMagic       = "dex\n"
	dexHeaderSize  = 0x70
	dexEndianTag   = 0x12345678
	dexMinSize     = 0x70 // minimum valid DEX size = header size
)

// FixDexFile fixes all known DEX header issues and checksums.
// Returns (fixed, deleted, error).
// fixed=true if any repair was made, deleted=true if file was too corrupt to keep.
func FixDexFile(path string) (bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, fmt.Errorf("read %s: %w", path, err)
	}

	// Too small to be a valid DEX - delete it
	if len(data) < dexMinSize {
		os.Remove(path)
		return false, true, fmt.Errorf("too small (%d bytes), deleted", len(data))
	}

	// Not a DEX file (no magic) - delete it
	if string(data[0:4]) != dexMagic {
		os.Remove(path)
		return false, true, fmt.Errorf("not a DEX file, deleted")
	}

	fixed := false

	// Fix header_size (offset 0x24, uint32 LE) - should be 0x70
	headerSize := binary.LittleEndian.Uint32(data[0x24:0x28])
	if headerSize != dexHeaderSize {
		binary.LittleEndian.PutUint32(data[0x24:0x28], dexHeaderSize)
		fixed = true
	}

	// Fix endian_tag (offset 0x28, uint32 LE) - should be 0x12345678
	endianTag := binary.LittleEndian.Uint32(data[0x28:0x2C])
	if endianTag != dexEndianTag {
		binary.LittleEndian.PutUint32(data[0x28:0x2C], dexEndianTag)
		fixed = true
	}

	// Fix file_size (offset 0x20, uint32 LE) - should match actual file size
	fileSize := binary.LittleEndian.Uint32(data[0x20:0x24])
	if fileSize != uint32(len(data)) {
		binary.LittleEndian.PutUint32(data[0x20:0x24], uint32(len(data)))
		fixed = true
	}

	// Fix SHA-1 signature (offset 0x0C, 20 bytes) - computed from bytes[0x20:]
	sig := sha1.Sum(data[0x20:])
	oldSig := make([]byte, 20)
	copy(oldSig, data[0x0C:0x20])
	if !equalBytes(oldSig, sig[:]) {
		copy(data[0x0C:0x20], sig[:])
		fixed = true
	}

	// Fix Adler32 checksum (offset 0x08, uint32 LE) - computed from bytes[0x0C:]
	checksum := adler32.Checksum(data[0x0C:])
	oldChecksum := binary.LittleEndian.Uint32(data[0x08:0x0C])
	if oldChecksum != checksum {
		binary.LittleEndian.PutUint32(data[0x08:0x0C], checksum)
		fixed = true
	}

	if fixed {
		err = os.WriteFile(path, data, 0644)
		if err != nil {
			return false, false, fmt.Errorf("write %s: %w", path, err)
		}
	}

	return fixed, false, nil
}

// FixDexDirectory fixes all .dex files in a directory (non-recursive).
// Returns (fixed_count, deleted_count, total_count, error).
func FixDexDirectory(dir string) (int, int, int, error) {
	dexFiles, err := findDexFiles(dir)
	if err != nil {
		return 0, 0, 0, err
	}

	totalCount := len(dexFiles)
	fixedCount := 0
	deletedCount := 0

	for _, f := range dexFiles {
		fixed, deleted, err := FixDexFile(f)
		if err != nil {
			if deleted {
				deletedCount++
			}
			continue
		}
		if fixed {
			fixedCount++
		}
	}

	return fixedCount, deletedCount, totalCount, nil
}

// findDexFiles finds all .dex files in a directory (non-recursive).
func findDexFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var dexFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".dex") {
			dexFiles = append(dexFiles, filepath.Join(dir, entry.Name()))
		}
	}
	return dexFiles, nil
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
