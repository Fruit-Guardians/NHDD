package main

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RepackParams APK 重打包参数
type RepackParams struct {
	Package  string `json:"package"`
	DumpDir  string `json:"dumpDir"`
	OutputDir string `json:"outputDir"`
	AdbPath  string `json:"adbPath"`
	HostPort string `json:"hostPort"`
}

// RepackResult APK 重打包结果
type RepackResult struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	OutputAPK   string `json:"outputApk"`
	ReplacedDex int    `json:"replacedDex"`
	SkippedDex  int    `json:"skippedDex"`
	ReplacedSo  int    `json:"replacedSo"`
	SkippedSo   int    `json:"skippedSo"`
}

// GetAPKPath 通过 pm path 获取设备上 base.apk 的路径
func GetAPKPath(adbPath, hostPort, pkg string) (string, error) {
	out, err := RunADB(adbPath, hostPort, "shell", "pm", "path", pkg)
	if err != nil {
		return "", fmt.Errorf("pm path failed: %w", err)
	}
	// 输出示例: package:/data/app/~~xxx==/com.example.app-xxx==/base.apk
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") && strings.HasSuffix(line, "/base.apk") {
			return strings.TrimPrefix(line, "package:"), nil
		}
	}
	// 没找到 base.apk，取第一个结果
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			return strings.TrimPrefix(line, "package:"), nil
		}
	}
	return "", fmt.Errorf("no APK path found for %s", pkg)
}

// PullOriginalAPK 从设备拉取原始 APK 到本地
func PullOriginalAPK(adbPath, hostPort, pkg, outputDir string) (string, error) {
	apkPath, err := GetAPKPath(adbPath, hostPort, pkg)
	if err != nil {
		return "", err
	}

	os.MkdirAll(outputDir, 0755)
	localPath := filepath.Join(outputDir, "original.apk")

	out, err := RunADB(adbPath, hostPort, "pull", apkPath, localPath)
	if err != nil {
		return "", fmt.Errorf("adb pull failed: %w%s", err, trimOutput(out))
	}
	return localPath, nil
}

// ExtractAPK 解压 APK 到临时目录，返回解压目录路径
func ExtractAPK(apkPath string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "nhdd_apk_*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("open APK: %w", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		destPath := filepath.Join(tmpDir, f.Name)

		// 安全校验：防止 ZipSlip
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(destPath), 0755)

		rc, err := f.Open()
		if err != nil {
			return tmpDir, fmt.Errorf("open %s in zip: %w", f.Name, err)
		}

		outFile, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return tmpDir, fmt.Errorf("create %s: %w", destPath, err)
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return tmpDir, fmt.Errorf("extract %s: %w", f.Name, err)
		}
	}

	return tmpDir, nil
}

// RemoveSignatureFiles 删除 META-INF/ 下的签名文件（*.RSA, *.SF, *.MF）
func RemoveSignatureFiles(apkDir string) error {
	metaDir := filepath.Join(apkDir, "META-INF")
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		// META-INF 不存在不是错误
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToUpper(e.Name())
		if strings.HasSuffix(name, ".RSA") ||
			strings.HasSuffix(name, ".SF") ||
			strings.HasSuffix(name, ".MF") {
			os.Remove(filepath.Join(metaDir, e.Name()))
		}
	}
	return nil
}

// dexFileInfo dump 目录中的有效 DEX 文件信息
type dexFileInfo struct {
	path string
	size int64
}

// collectValidDex 收集 dump 目录中有效的 DEX 文件（不在 bad/ 内，通过深度校验）
func collectValidDex(dumpDir string) ([]dexFileInfo, error) {
	allDex, err := findDexFiles(dumpDir)
	if err != nil {
		return nil, err
	}

	var valid []dexFileInfo
	for _, path := range allDex {
		// 跳过 bad/ 子目录
		if strings.Contains(strings.ReplaceAll(path, "\\", "/"), "/bad/") {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) < dexMinSize || string(data[0:4]) != dexMagic {
			continue
		}
		if !validateDexDeep(data) {
			continue
		}

		info, _ := os.Stat(path)
		if info != nil {
			valid = append(valid, dexFileInfo{path: path, size: info.Size()})
		}
	}

	// 按文件大小降序排列：最大的对应 classes.dex（主 DEX）
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].size > valid[j].size
	})

	return valid, nil
}

// ReplaceDexFiles 用修复后的 DEX 替换 APK 中的 DEX
// NEW: 删除所有原始 classes*.dex，把有效 dump DEX 全部放入
func ReplaceDexFiles(apkDir, dumpDir string) (int, int, error) {
	validDex, err := collectValidDex(dumpDir)
	if err != nil {
		return 0, 0, err
	}

	// 删除 APK 中所有现有 classes*.dex
	entries, err := os.ReadDir(apkDir)
	if err != nil {
		return 0, 0, fmt.Errorf("read apk dir: %w", err)
	}
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") {
			os.Remove(filepath.Join(apkDir, e.Name()))
		}
	}

	// 按大小降序放入所有有效 dump DEX
	replaced := 0
	for i, dex := range validDex {
		var targetName string
		if i == 0 {
			targetName = "classes.dex"
		} else {
			targetName = fmt.Sprintf("classes%d.dex", i+1)
		}
		dstPath := filepath.Join(apkDir, targetName)

		srcData, err := os.ReadFile(dex.path)
		if err != nil {
			continue
		}
		if err := os.WriteFile(dstPath, srcData, 0644); err != nil {
			continue
		}
		replaced++
	}

	return replaced, 0, nil
}

// soFileInfo dump 目录中的有效 SO 文件信息
type soFileInfo struct {
	path string
	name string
	size int64
}

// collectValidSo 收集 dump 目录中有效的 SO 文件（不在 bad/ 内，通过校验）
func collectValidSo(dumpDir string) []soFileInfo {
	allSo, _ := findFilesByExt(dumpDir, ".so")
	var valid []soFileInfo
	for _, path := range allSo {
		if strings.Contains(strings.ReplaceAll(path, "\\", "/"), "/bad/") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) < soMinSize {
			continue
		}
		if !validateSoDeep(data) {
			continue
		}
		info, _ := os.Stat(path)
		if info != nil {
			valid = append(valid, soFileInfo{
				path: path,
				name: filepath.Base(path),
				size: info.Size(),
			})
		}
	}
	return valid
}

// ReplaceSoFiles 用修复后的 SO 替换 APK 中的 SO
// NEW: 删除所有 lib/<abi>/*.so，只放回匹配的 dump SO
func ReplaceSoFiles(apkDir, dumpDir string) (int, int, error) {
	validSos := collectValidSo(dumpDir)
	soByName := make(map[string]soFileInfo)
	for _, s := range validSos {
		soByName[strings.ToLower(s.name)] = s
	}

	libDir := filepath.Join(apkDir, "lib")
	if _, err := os.Stat(libDir); os.IsNotExist(err) {
		return 0, 0, nil
	}

	replaced := 0
	// 遍历 APK 原生库，删除所有 .so，匹配的则替换
	err := filepath.WalkDir(libDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".so") {
			return nil
		}
		key := strings.ToLower(entry.Name())
		if match, ok := soByName[key]; ok {
			srcData, err := os.ReadFile(match.path)
			if err != nil {
				return nil
			}
			if err := os.WriteFile(path, srcData, 0644); err != nil {
				return nil
			}
			replaced++
		} else {
			// 无匹配 dump SO — 删除原 SO（旧保护壳 SO 不保留）
			os.Remove(path)
		}
		return nil
	})

	return replaced, 0, err
}

// RepackAPK 将解压目录重压缩为 .apk 文件
func RepackAPK(apkDir, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output apk: %w", err)
	}
	defer outFile.Close()

	writer := zip.NewWriter(outFile)
	defer writer.Close()

	// Use store (no compression) for speed — APK is for jadx analysis, not deployment
	writer.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.NoCompression)
	})

	err = filepath.WalkDir(apkDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(apkDir, path)
		if err != nil {
			return err
		}
		// Windows 路径转正斜杠
		relPath = strings.ReplaceAll(relPath, "\\", "/")

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fw, err := writer.Create(relPath)
		if err != nil {
			return err
		}
		_, err = fw.Write(data)
		return err
	})

	return err
}

// DoRepackAPK 执行完整的 APK 重打包流程（不签名，纯静态分析用）
// 流程: 拉取 APK -> 解压 -> 清理签名 -> 替换 DEX -> 重压缩 (跳过SO)
func DoRepackAPK(params RepackParams, logFn func(string)) (*RepackResult, error) {
	log := func(msg string) {
		if logFn != nil {
			logFn(msg)
		}
	}

	log("[Repack 1/4] 从设备拉取原始 APK...")
	origDir := filepath.Join(params.OutputDir, params.Package, "repack")
	os.MkdirAll(origDir, 0755)

	apkPath, err := PullOriginalAPK(params.AdbPath, params.HostPort, params.Package, origDir)
	if err != nil {
		return &RepackResult{Success: false, Message: fmt.Sprintf("拉取 APK 失败: %v", err)}, err
	}
	log(fmt.Sprintf("[Repack 1/4] 原始 APK: %s", apkPath))

	log("[Repack 2/4] 解压 APK...")
	extractDir, err := ExtractAPK(apkPath)
	if err != nil {
		return &RepackResult{Success: false, Message: fmt.Sprintf("解压 APK 失败: %v", err)}, err
	}
	defer os.RemoveAll(extractDir)

	log("[Repack 3/4] 清理签名文件...")
	RemoveSignatureFiles(extractDir)

	log("[Repack 4/4] 替换 DEX 文件 (跳过SO)...")
	replacedDex, skippedDex, err := ReplaceDexFiles(extractDir, params.DumpDir)
	if err != nil {
		return &RepackResult{Success: false, Message: fmt.Sprintf("替换 DEX 失败: %v", err)}, err
	}
	log(fmt.Sprintf("[Repack 4/4] DEX: %d 替换, %d 跳过", replacedDex, skippedDex))

	outputPath := filepath.Join(origDir, params.Package+"_repacked.apk")
	if err := RepackAPK(extractDir, outputPath); err != nil {
		return &RepackResult{Success: false, Message: fmt.Sprintf("重压缩失败: %v", err)}, err
	}
	log(fmt.Sprintf("完成: %s", outputPath))
	log(fmt.Sprintf("可直接拖入 jadx 分析: %s", outputPath))

	return &RepackResult{
		Success:     true,
		Message:     "重打包完成",
		OutputAPK:   outputPath,
		ReplacedDex: replacedDex,
		SkippedDex:  skippedDex,
	}, nil
}
