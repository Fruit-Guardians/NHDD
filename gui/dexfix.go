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
	dexMagic      = "dex\n"
	dexHeaderSize = 0x70
	dexEndianTag  = 0x12345678
	dexMinSize    = 0x70
)

// FixDexFile 修复 DEX 头和校验和，返回 (已修复, 已删除, 错误)
func FixDexFile(path string) (bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, fmt.Errorf("read %s: %w", path, err)
	}

	if len(data) < dexMinSize {
		os.Remove(path)
		return false, true, fmt.Errorf("too small (%d bytes), deleted", len(data))
	}

	if string(data[0:4]) != dexMagic {
		os.Remove(path)
		return false, true, fmt.Errorf("not a DEX file, deleted")
	}

	fixed := false

	headerSize := binary.LittleEndian.Uint32(data[0x24:0x28])
	if headerSize != dexHeaderSize {
		binary.LittleEndian.PutUint32(data[0x24:0x28], dexHeaderSize)
		fixed = true
	}

	endianTag := binary.LittleEndian.Uint32(data[0x28:0x2C])
	if endianTag != dexEndianTag {
		binary.LittleEndian.PutUint32(data[0x28:0x2C], dexEndianTag)
		fixed = true
	}

	fileSize := binary.LittleEndian.Uint32(data[0x20:0x24])
	if fileSize != uint32(len(data)) {
		binary.LittleEndian.PutUint32(data[0x20:0x24], uint32(len(data)))
		fixed = true
	}

	sig := sha1.Sum(data[0x20:])
	oldSig := make([]byte, 20)
	copy(oldSig, data[0x0C:0x20])
	if !equalBytes(oldSig, sig[:]) {
		copy(data[0x0C:0x20], sig[:])
		fixed = true
	}

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

// FixDexDirectory 递归修复目录中所有 .dex 文件
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

func findDexFiles(dir string) ([]string, error) {
	return findFilesByExt(dir, ".dex")
}

func findFilesByExt(dir, ext string) ([]string, error) {
	ext = strings.ToLower(ext)
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ext) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

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
