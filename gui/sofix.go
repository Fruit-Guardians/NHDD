package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
)

// 镜像 fix_so.py 的 GUI 对齐实现:内建 ELF 修复 (替代外部 SoFixer) + 深度校验。
// 与 dexfix.go 的 DEX 修复保持同样的处置口径:过小/非ELF 删除,不可修移 invalid/。

const (
	soMagic       = "\x7fELF"
	soMinSize     = 0x40
	elfEtDyn      = 3
	elfEmArm      = 40
	elfEmAarch64  = 183
	elfPtLoad     = 1
	elfPtDynamic  = 2
)

// FixSoFile 修复单个 SO (内存 dump):p_offset=p_vaddr 对齐 + 补回 magic。
// 返回 (已修复, 已隔离, 错误)。无效文件移到 bad/ 子目录，不删除。
func FixSoFile(path string) (bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	if len(data) < soMinSize {
		moveToBadDir(path)
		return false, true, nil
	}

	// 尝试修复 (repairSo 返回 nil 表示无法修复)
	repaired := repairSo(data)
	if repaired == nil {
		moveToBadDir(path)
		return false, true, nil
	}

	if !validateSoDeep(repaired) {
		moveToBadDir(path)
		return false, true, nil
	}

	// 判断是否实际有修改 (切片地址不同)
	if &repaired[0] != &data[0] {
		if err := os.WriteFile(path, repaired, 0644); err != nil {
			return false, false, err
		}
		return true, false, nil
	}
	return false, false, nil
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

func repairSo(data []byte) []byte {
	if len(data) < soMinSize {
		return nil
	}
	is64 := data[4] == 2
	if data[4] != 1 && data[4] != 2 {
		return nil
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
		return nil
	}
	if uint64(ePhoff)+uint64(ePhnum)*uint64(ePhentsize) > uint64(len(data)) {
		return nil
	}

	out := make([]byte, len(data))
	copy(out, data)
	changed := false

	// 补回 magic + e_ident
	if string(out[0:4]) != soMagic {
		copy(out[0:4], soMagic)
		changed = true
	}
	// ART-required: always fix EI_DATA=1, EI_VERSION=1
	if out[5] != 1 {
		out[5] = 1 // ELFDATA2LSB
		changed = true
	}
	if out[6] != 1 {
		out[6] = 1 // EV_CURRENT
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
			// SoFixer parity: set p_filesz = p_memsz for PT_LOAD to eliminate gaps
			if pType == elfPtLoad {
				var fRaw, mRaw uint64
				var pFilesz, pMemsz uint64
				if is64 {
					fRaw = base + 32
					mRaw = base + 40
					pFilesz = binary.LittleEndian.Uint64(out[fRaw : fRaw+8])
					pMemsz = binary.LittleEndian.Uint64(out[mRaw : mRaw+8])
				} else {
					fRaw = base + 16
					mRaw = base + 20
					pFilesz = uint64(binary.LittleEndian.Uint32(out[fRaw : fRaw+4]))
					pMemsz = uint64(binary.LittleEndian.Uint32(out[mRaw : mRaw+4]))
				}
				if pFilesz < pMemsz {
					if is64 {
						binary.LittleEndian.PutUint64(out[fRaw:fRaw+8], pMemsz)
					} else {
						binary.LittleEndian.PutUint32(out[fRaw:fRaw+4], uint32(pMemsz))
					}
					changed = true
				}
			}
		}
	}
	if !changed {
		return data
	}
	return out
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

	// --- ART-level header field checks (elf_file.cc SetMap/Setup) ---

	// e_ehsize must be non-zero
	var eEhsize uint16
	if is64 {
		eEhsize = binary.LittleEndian.Uint16(data[52:54])
	} else {
		eEhsize = binary.LittleEndian.Uint16(data[40:42])
	}
	if eEhsize == 0 {
		return false
	}

	// e_shentsize / e_shnum / e_shstrndx — may be zero for dump SOs without SHT
	var eShentsize uint16
	if is64 {
		eShentsize = binary.LittleEndian.Uint16(data[58:60])
	} else {
		eShentsize = binary.LittleEndian.Uint16(data[46:48])
	}

	// e_shnum must be non-zero if SHT present
	var eShnum uint16
	if is64 {
		eShnum = binary.LittleEndian.Uint16(data[60:62])
	} else {
		eShnum = binary.LittleEndian.Uint16(data[48:50])
	}

	// e_shstrndx
	var eShstrndx uint16
	if is64 {
		eShstrndx = binary.LittleEndian.Uint16(data[62:64])
	} else {
		eShstrndx = binary.LittleEndian.Uint16(data[50:52])
	}

	// e_shoff — if zero, dump SO has no section headers (tolerable)
	var eShoff uint64
	if is64 {
		eShoff = binary.LittleEndian.Uint64(data[0x28:0x30])
	} else {
		eShoff = uint64(binary.LittleEndian.Uint32(data[0x20:0x24]))
	}
	// If SHT is present, validate it
	if eShoff != 0 || eShnum != 0 {
		if eShoff == 0 || eShoff >= uint64(realSize) {
			return false
		}
		if eShnum == 0 || eShstrndx == 0 || eShstrndx >= eShnum {
			return false
		}
		shEnd := eShoff + uint64(eShnum)*uint64(eShentsize)
		if shEnd > uint64(realSize) {
			return false
		}

	// shstrtab section header must be accessible
	shstrtabOff := eShoff + uint64(eShstrndx)*uint64(eShentsize)
	if shstrtabOff+uint64(eShentsize) > uint64(realSize) {
		return false
	}
	} // end if SHT present

	hasLoad := false
	var dynVaddr uint64
	var dynFound bool
	for i := uint16(0); i < ePhnum; i++ {
		base := uint64(ePhoff) + uint64(i)*uint64(ePhentsize)
		var pType uint32
		var pOffset, pVaddr, pFilesz, pMemsz uint64
		if is64 {
			pType = binary.LittleEndian.Uint32(data[base : base+4])
			pOffset = binary.LittleEndian.Uint64(data[base+8 : base+16])
			pVaddr = binary.LittleEndian.Uint64(data[base+16 : base+24])
			pFilesz = binary.LittleEndian.Uint64(data[base+32 : base+40])
			pMemsz = binary.LittleEndian.Uint64(data[base+40 : base+48])
		} else {
			pType = binary.LittleEndian.Uint32(data[base : base+4])
			pOffset = uint64(binary.LittleEndian.Uint32(data[base+4 : base+8]))
			pVaddr = uint64(binary.LittleEndian.Uint32(data[base+8 : base+12]))
			pFilesz = uint64(binary.LittleEndian.Uint32(data[base+16 : base+20]))
			pMemsz = uint64(binary.LittleEndian.Uint32(data[base+20 : base+24]))
		}
		if pType == elfPtLoad {
			hasLoad = true
			if pFilesz > pMemsz {
				return false
			}
			// Skip pVaddr+pMemsz extent: truncated dumps are normal
			// Skip pFilesz alignment: .bss segments legitimately unaligned
		} else if pType == elfPtDynamic {
			dynVaddr = pVaddr
			dynFound = true
		}
	}
	if !hasLoad {
		return false
	}
	// PT_DYNAMIC is checked but not mandatory (some dump SOs may have it at bad offset)
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
