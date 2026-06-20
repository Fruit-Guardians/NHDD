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
		// 尝试重建 map_list
		if newData := RebuildMapList(data); newData != nil {
			data = newData
			// 重建后重新验证
			if !validateDexDeep(data) {
				os.Remove(path)
				return false, true, fmt.Errorf("still invalid after map_list rebuild, deleted")
			}
		} else {
			// 无法修复，移到 invalid/ 子目录
			invalidDir := filepath.Join(filepath.Dir(path), "invalid")
			os.MkdirAll(invalidDir, 0755)
			newPath := filepath.Join(invalidDir, filepath.Base(path))
			os.Rename(path, newPath)
			return false, true, fmt.Errorf("invalid DEX (map_list/section corrupted), moved to invalid/")
		}
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

// DexStats DEX 修复统计
type DexStats struct {
	Total    int
	OK       int
	Fixed    int
	Bad      int
	BadFiles []string
}

// FixDexDirectory 递归修复目录中所有 .dex 文件，返回分类统计
func FixDexDirectory(dir string) (*DexStats, error) {
	dexFiles, err := findDexFiles(dir)
	if err != nil {
		return nil, err
	}

	stats := &DexStats{Total: len(dexFiles)}
	badDir := filepath.Join(dir, "bad")

	for _, f := range dexFiles {
		fixed, deleted, err := FixDexFile(f)
		if err != nil {
			if deleted {
				stats.Bad++
				stats.BadFiles = append(stats.BadFiles, filepath.Base(f))
			}
			continue
		}
		if fixed {
			stats.Fixed++
		}
		stats.OK++
	}

	// 统计 bad/ 目录
	if entries, err := os.ReadDir(badDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dex") {
				stats.BadFiles = append(stats.BadFiles, e.Name())
			}
		}
	}

	return stats, nil
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

// validateDexDeep 深度验证 DEX 文件结构（item 级偏移越界检查，不做 MUTF-8 验证）
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

	mapSize := binary.LittleEndian.Uint32(data[mapOff : mapOff+4])
	if mapSize > 50 {
		return false
	}

	mapEnd := mapOff + 4 + mapSize*12
	if mapEnd > realSize {
		return false
	}

	// 检查异常大文件（> 64MB）
	if realSize > 64*1024*1024 {
		return false
	}

	// 读取 section 信息
	sidsSize := binary.LittleEndian.Uint32(data[0x38:0x3C])
	sidsOff := binary.LittleEndian.Uint32(data[0x3C:0x40])
	tidsSize := binary.LittleEndian.Uint32(data[0x40:0x44])
	tidsOff := binary.LittleEndian.Uint32(data[0x44:0x48])
	pidsSize := binary.LittleEndian.Uint32(data[0x48:0x4C])
	pidsOff := binary.LittleEndian.Uint32(data[0x4C:0x50])
	fidsSize := binary.LittleEndian.Uint32(data[0x50:0x54])
	fidsOff := binary.LittleEndian.Uint32(data[0x54:0x58])
	midsSize := binary.LittleEndian.Uint32(data[0x58:0x5C])
	midsOff := binary.LittleEndian.Uint32(data[0x5C:0x60])
	clsSize := binary.LittleEndian.Uint32(data[0x60:0x64])
	clsOff := binary.LittleEndian.Uint32(data[0x64:0x68])

	// 检查 section 表是否越界
	if sidsSize > 0 && sidsOff > 0 && sidsOff+sidsSize*4 > realSize {
		return false
	}
	if tidsSize > 0 && tidsOff > 0 && tidsOff+tidsSize*4 > realSize {
		return false
	}
	if pidsSize > 0 && pidsOff > 0 && pidsOff+pidsSize*12 > realSize {
		return false
	}
	if fidsSize > 0 && fidsOff > 0 && fidsOff+fidsSize*8 > realSize {
		return false
	}
	if midsSize > 0 && midsOff > 0 && midsOff+midsSize*8 > realSize {
		return false
	}
	if clsSize > 0 && clsOff > 0 && clsOff+clsSize*32 > realSize {
		return false
	}

	// 1. string_ids 逐项检查：string_data_off 必须在文件内
	if sidsSize > 0 && sidsOff > 0 {
		for i := uint32(0); i < sidsSize; i++ {
			sdataOff := binary.LittleEndian.Uint32(data[sidsOff+i*4 : sidsOff+i*4+4])
			if sdataOff >= realSize {
				return false
			}
		}
	}

	// 2. type_ids 逐项检查：desc_idx 必须在 string_ids 范围内
	if tidsSize > 0 && tidsOff > 0 {
		for i := uint32(0); i < tidsSize; i++ {
			descIdx := binary.LittleEndian.Uint32(data[tidsOff+i*4 : tidsOff+i*4+4])
			if descIdx >= sidsSize {
				return false
			}
		}
	}

	// 3. proto_ids 逐项检查
	if pidsSize > 0 && pidsOff > 0 {
		for i := uint32(0); i < pidsSize; i++ {
			base := pidsOff + i*12
			shorty := binary.LittleEndian.Uint32(data[base : base+4])
			ret := binary.LittleEndian.Uint32(data[base+4 : base+8])
			params := binary.LittleEndian.Uint32(data[base+8 : base+12])
			if shorty >= sidsSize || ret >= tidsSize || (params > 0 && params >= realSize) {
				return false
			}
		}
	}

	// 4. field_ids 逐项检查
	if fidsSize > 0 && fidsOff > 0 {
		for i := uint32(0); i < fidsSize; i++ {
			base := fidsOff + i*8
			cls := binary.LittleEndian.Uint16(data[base : base+2])
			typ := binary.LittleEndian.Uint16(data[base+2 : base+4])
			name := binary.LittleEndian.Uint32(data[base+4 : base+8])
			if uint32(cls) >= tidsSize || uint32(typ) >= tidsSize || name >= sidsSize {
				return false
			}
		}
	}

	// 5. method_ids 逐项检查
	if midsSize > 0 && midsOff > 0 {
		for i := uint32(0); i < midsSize; i++ {
			base := midsOff + i*8
			cls := binary.LittleEndian.Uint16(data[base : base+2])
			proto := binary.LittleEndian.Uint16(data[base+2 : base+4])
			name := binary.LittleEndian.Uint32(data[base+4 : base+8])
			if uint32(cls) >= tidsSize || uint32(proto) >= pidsSize || name >= sidsSize {
				return false
			}
		}
	}

	// 6. class_defs 逐项检查：annotations_off / class_data_off / static_values_off
	if clsSize > 0 && clsOff > 0 {
		for i := uint32(0); i < clsSize; i++ {
			base := clsOff + i*32
			classIdx := binary.LittleEndian.Uint32(data[base : base+4])
			annotOff := binary.LittleEndian.Uint32(data[base+20 : base+24])
			cdOff := binary.LittleEndian.Uint32(data[base+24 : base+28])
			svOff := binary.LittleEndian.Uint32(data[base+28 : base+32])
			if classIdx >= tidsSize {
				return false
			}
			if annotOff > 0 && annotOff >= realSize {
				return false
			}
			if cdOff > 0 && cdOff >= realSize {
				return false
			}
			if svOff > 0 && svOff >= realSize {
				return false
			}
		}
	}

	return true
}

// DEX map_list type constants
const (
	dexTypeHeaderItem   = 0x0000
	dexTypeStringIdItem = 0x0001
	dexTypeTypeIdItem   = 0x0002
	dexTypeProtoIdItem  = 0x0003
	dexTypeFieldIdItem  = 0x0004
	dexTypeMethodIdItem = 0x0005
	dexTypeClassDefItem = 0x0006
	dexTypeMapList      = 0x1000
)

// mapEntry represents a single map_list entry
type mapEntry struct {
	typ   uint16
	off   uint32
	count uint32
}

// RebuildMapList 从 section headers 重建 map_list
// 返回新的 data 切片，如果无法重建则返回 nil
func RebuildMapList(data []byte) []byte {
	realSize := uint32(len(data))
	if realSize < dexHeaderSize {
		return nil
	}

	// 收集 section 信息
	var entries []mapEntry
	entries = append(entries, mapEntry{dexTypeHeaderItem, 0, dexHeaderSize})

	sections := []struct {
		typ     uint16
		sizeOff uint32
		offOff  uint32
	}{
		{dexTypeStringIdItem, 0x38, 0x3C},
		{dexTypeTypeIdItem, 0x40, 0x44},
		{dexTypeProtoIdItem, 0x48, 0x4C},
		{dexTypeFieldIdItem, 0x50, 0x54},
		{dexTypeMethodIdItem, 0x58, 0x5C},
		{dexTypeClassDefItem, 0x60, 0x64},
	}

	for _, s := range sections {
		secSize := binary.LittleEndian.Uint32(data[s.sizeOff : s.sizeOff+4])
		secOff := binary.LittleEndian.Uint32(data[s.offOff : s.offOff+4])
		if secSize > 0 && secOff > 0 && secOff < realSize {
			entries = append(entries, mapEntry{s.typ, secOff, secSize})
		}
	}

	dataSectionSize := binary.LittleEndian.Uint32(data[0x68:0x6C])
	dataSectionOff := binary.LittleEndian.Uint32(data[0x6C:0x70])
	if dataSectionSize > 0 && dataSectionOff > 0 && dataSectionOff < realSize {
		entries = append(entries, mapEntry{dexTypeMapList, dataSectionOff, 0})
	}

	if len(entries) == 0 {
		return nil
	}

	// 按 offset 排序
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].off > entries[j].off {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	mapListSize := 4 + len(entries)*12
	oldMapOff := binary.LittleEndian.Uint32(data[0x34:0x38])

	var mapOff uint32
	if oldMapOff >= dexHeaderSize && oldMapOff+uint32(mapListSize) <= realSize {
		mapOff = oldMapOff
	} else {
		// 追加到文件末尾
		mapOff = realSize
		newData := make([]byte, realSize+uint32(mapListSize))
		copy(newData, data)
		data = newData
		binary.LittleEndian.PutUint32(data[0x20:0x24], uint32(len(data)))
	}

	// 写入 map_list
	binary.LittleEndian.PutUint32(data[mapOff:mapOff+4], uint32(len(entries)))
	for i, e := range entries {
		base := mapOff + 4 + uint32(i)*12
		binary.LittleEndian.PutUint16(data[base:base+2], e.typ)
		// unused (2 bytes) = 0
		binary.LittleEndian.PutUint16(data[base+2:base+4], 0)
		binary.LittleEndian.PutUint32(data[base+4:base+8], e.count)
		binary.LittleEndian.PutUint32(data[base+8:base+12], e.off)
	}

	// 更新 header 中的 map_off
	binary.LittleEndian.PutUint32(data[0x34:0x38], mapOff)

	return data
}
