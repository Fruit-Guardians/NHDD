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

	// 深度验证：检查 map_list 和 section bounds
	if !validateDexDeep(data) {
		// map_list 或 section 损坏，移到 invalid 子目录
		invalidDir := filepath.Join(filepath.Dir(path), "invalid")
		os.MkdirAll(invalidDir, 0755)
		newPath := filepath.Join(invalidDir, filepath.Base(path))
		os.Rename(path, newPath)
		return false, true, fmt.Errorf("invalid DEX (map_list/section corrupted), moved to invalid/")
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

// validateDexDeep 深度验证 DEX 文件结构
func validateDexDeep(data []byte) bool {
	realSize := uint32(len(data))
	if realSize < dexHeaderSize {
		return false
	}

	// 检查 map_list
	mapOff := binary.LittleEndian.Uint32(data[0x34:0x38])
	if mapOff < dexHeaderSize || mapOff >= realSize {
		return false
	}

	// 检查 map_size 合理性
	mapSize := binary.LittleEndian.Uint32(data[mapOff : mapOff+4])
	if mapSize > 50 {
		return false // 正常 DEX map_list 不超过 ~20 个条目
	}

	mapEnd := mapOff + 4 + mapSize*12
	if mapEnd > realSize {
		return false
	}

	// 检查关键 section 偏移是否越界
	sections := []struct {
		name   string
		offOff uint32
	}{
		{"string_ids", 0x3C},
		{"type_ids", 0x44},
		{"proto_ids", 0x4C},
		{"field_ids", 0x54},
		{"method_ids", 0x5C},
		{"class_defs", 0x64},
	}
	for _, sec := range sections {
		secOff := binary.LittleEndian.Uint32(data[sec.offOff : sec.offOff+4])
		secSize := binary.LittleEndian.Uint32(data[sec.offOff+4 : sec.offOff+8])
		if secOff > 0 && secOff+secSize > realSize {
			return false
		}
	}

	// 检查异常大文件（> 64MB 可能是多个 DEX 拼接）
	if realSize > 64*1024*1024 {
		return false
	}

	return true
}
