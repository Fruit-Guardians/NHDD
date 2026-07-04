package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
)

// 镜像 fix_so.py 的 GUI 对齐实现:内建 ELF 修复 (替代外部 SoFixer) + 深度校验。
// 与 dexfix.go 的 DEX 修复保持同样的处置口径:过小/非ELF 删除,不可修移 invalid/。

const (
	soMagic      = "\x7fELF"
	soMinSize    = 0x40
	elfEtDyn     = 3
	elfEmArm     = 40
	elfEmAarch64 = 183
	elfPtLoad    = 1
	elfPtDynamic = 2
)

// FixSoFile 修复单个 SO (内存 dump):p_offset=p_vaddr 对齐 + 补回 magic。
// 返回 (已修复, 已删除, 错误)。
func FixSoFile(path string) (bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	if len(data) < soMinSize {
		os.Remove(path)
		return false, true, nil
	}

	if !validateSoDeep(data) {
		// 尝试修复后再校验
		if newData, _ := repairSo(data); newData != nil {
			if validateSoDeep(newData) {
				data = newData
			} else {
				// 仍无效 -> 移到 invalid/
				invalidDir := filepath.Join(filepath.Dir(path), "invalid")
				os.MkdirAll(invalidDir, 0755)
				newPath := filepath.Join(invalidDir, filepath.Base(path))
				os.Rename(path, newPath)
				return false, true, nil
			}
		} else {
			invalidDir := filepath.Join(filepath.Dir(path), "invalid")
			os.MkdirAll(invalidDir, 0755)
			newPath := filepath.Join(invalidDir, filepath.Base(path))
			os.Rename(path, newPath)
			return false, true, nil
		}
	}

	newData, changed := repairSo(data)
	if !validateSoDeep(newData) {
		return false, false, nil // 保留原文件
	}
	if changed {
		if err := os.WriteFile(path, newData, 0644); err != nil {
			return false, false, err
		}
	}
	return changed, false, nil
}

// FixSoDirectory 递归修复目录中所有 .so 文件,返回统计 (复用 DexStats 结构)。
func FixSoDirectory(dir string) (*DexStats, error) {
	soFiles, err := findFilesByExt(dir, ".so")
	if err != nil {
		return nil, err
	}
	stats := &DexStats{Total: len(soFiles)}
	for _, f := range soFiles {
		fixed, deleted, err := FixSoFile(f)
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
	return stats, nil
}

func repairSo(data []byte) ([]byte, bool) {
	if len(data) < soMinSize {
		return nil, false
	}
	is64 := data[4] == 2
	if data[4] != 1 && data[4] != 2 {
		return nil, false
	}
	var ePhoff uint64
	var ePhentsize, ePhnum uint16
	if is64 {
		ePhoff = binary.LittleEndian.Uint64(data[32:40])
		ePhentsize = binary.LittleEndian.Uint16(data[54:56])
		ePhnum = binary.LittleEndian.Uint16(data[56:58])
	} else {
		ePhoff = uint64(binary.LittleEndian.Uint32(data[28:32]))
		ePhentsize = binary.LittleEndian.Uint16(data[42:44])
		ePhnum = binary.LittleEndian.Uint16(data[44:46])
	}
	if ePhnum == 0 || ePhentsize == 0 {
		return nil, false
	}
	if uint64(ePhoff)+uint64(ePhnum)*uint64(ePhentsize) > uint64(len(data)) {
		return nil, false
	}

	out := make([]byte, len(data))
	copy(out, data)
	changed := false

	// 补回 magic
	if string(out[0:4]) != soMagic {
		copy(out[0:4], soMagic)
		out[5] = 1 // EI_DATA little-endian
		out[6] = 1 // EI_VERSION
		changed = true
	}

	for i := uint16(0); i < ePhnum; i++ {
		base := uint64(ePhoff) + uint64(i)*uint64(ePhentsize)
		var pType uint32
		var pOffset, pVaddr uint64
		var pRaw uint64
		if is64 {
			pType = binary.LittleEndian.Uint32(out[base : base+4])
			pOffset = binary.LittleEndian.Uint64(out[base+8 : base+16])
			pVaddr = binary.LittleEndian.Uint64(out[base+16 : base+24])
			pRaw = base + 8
		} else {
			pType = binary.LittleEndian.Uint32(out[base : base+4])
			pOffset = uint64(binary.LittleEndian.Uint32(out[base+4 : base+8]))
			pVaddr = uint64(binary.LittleEndian.Uint32(out[base+8 : base+12]))
			pRaw = base + 4
		}
		if pType == elfPtLoad || pType == elfPtDynamic {
			if pOffset != pVaddr {
				if is64 {
					binary.LittleEndian.PutUint64(out[pRaw:pRaw+8], pVaddr)
				} else {
					binary.LittleEndian.PutUint32(out[pRaw:pRaw+4], uint32(pVaddr))
				}
				changed = true
			}
		}
	}
	if !changed {
		return data, false
	}
	return out, true
}

// validateSoDeep 镜像 fix_so.py validate_elf_deep:ET_DYN + PHT 自洽 + LOAD 自洽 + .dynamic DT 指向。
func validateSoDeep(data []byte) bool {
	realSize := len(data)
	if realSize < soMinSize || realSize > 64*1024*1024 {
		return false
	}
	is64 := data[4] == 2
	if data[4] != 1 && data[4] != 2 {
		return false
	}
	eType := binary.LittleEndian.Uint16(data[16:18])
	if eType != elfEtDyn {
		return false
	}
	eMachine := binary.LittleEndian.Uint16(data[18:20])
	if eMachine != elfEmArm && eMachine != elfEmAarch64 {
		return false
	}
	var ePhoff uint64
	var ePhentsize, ePhnum uint16
	if is64 {
		ePhoff = binary.LittleEndian.Uint64(data[32:40])
		ePhentsize = binary.LittleEndian.Uint16(data[54:56])
		ePhnum = binary.LittleEndian.Uint16(data[56:58])
	} else {
		ePhoff = uint64(binary.LittleEndian.Uint32(data[28:32]))
		ePhentsize = binary.LittleEndian.Uint16(data[42:44])
		ePhnum = binary.LittleEndian.Uint16(data[44:46])
	}
	if ePhoff < soMinSize || ePhoff >= uint64(realSize) {
		return false
	}
	if ePhentsize == 0 || ePhnum == 0 || ePhnum > 64 {
		return false
	}
	if ePhoff+uint64(ePhnum)*uint64(ePhentsize) > uint64(realSize) {
		return false
	}

	hasLoad := false
	var dynVaddr uint64
	var dynFound bool
	for i := uint16(0); i < ePhnum; i++ {
		base := uint64(ePhoff) + uint64(i)*uint64(ePhentsize)
		var pType uint32
		var pVaddr, pFilesz, pMemsz uint64
		if is64 {
			pType = binary.LittleEndian.Uint32(data[base : base+4])
			pVaddr = binary.LittleEndian.Uint64(data[base+16 : base+24])
			pFilesz = binary.LittleEndian.Uint64(data[base+32 : base+40])
			pMemsz = binary.LittleEndian.Uint64(data[base+40 : base+48])
		} else {
			pType = binary.LittleEndian.Uint32(data[base : base+4])
			pVaddr = uint64(binary.LittleEndian.Uint32(data[base+8 : base+12]))
			pFilesz = uint64(binary.LittleEndian.Uint32(data[base+16 : base+20]))
			pMemsz = uint64(binary.LittleEndian.Uint32(data[base+20 : base+24]))
		}
		if pType == elfPtLoad {
			hasLoad = true
			if pFilesz > pMemsz {
				return false
			}
			if pVaddr+pMemsz > uint64(realSize) {
				return false
			}
		} else if pType == elfPtDynamic {
			dynVaddr = pVaddr
			dynFound = true
		}
	}
	if !hasLoad {
		return false
	}
	// 遍历 .dynamic DT_* 项,校验关键 DT 指向在文件内
	if dynFound && dynVaddr < uint64(realSize) {
		entsize := uint64(16)
		if !is64 {
			entsize = 8
		}
		i := dynVaddr
		count := uint64(0)
		for i+entsize <= uint64(realSize) && count < 256 {
			var dTag uint64
			var dVal uint64
			if is64 {
				dTag = binary.LittleEndian.Uint64(data[i : i+8])
				dVal = binary.LittleEndian.Uint64(data[i+8 : i+16])
			} else {
				dTag = uint64(binary.LittleEndian.Uint32(data[i : i+4]))
				dVal = uint64(binary.LittleEndian.Uint32(data[i+4 : i+8]))
			}
			if dTag == 0 { // DT_NULL
				break
			}
			// 关键 DT 指向必须在文件内 (DT_STRTAB=5, DT_SYMTAB=6, DT_INIT=12, ...)
			if isDynAddrTag(uint32(dTag)) && dVal != 0 && dVal >= uint64(realSize) {
				return false
			}
			i += entsize
			count++
		}
	}
	return true
}

func isDynAddrTag(tag uint32) bool {
	switch tag {
	case 4, 5, 6, 7, 12, 13, 17, 23, 25, 26: // DT_HASH/STRTAB/SYMTAB/RELA/INIT/FINI/REL/JMPREL/INIT_ARRAY/FINI_ARRAY
		return true
	}
	return false
}
