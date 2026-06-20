package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const deviceDumpDir = "/data/local/tmp/nhdd_dump"

// RunADB 执行 adb 命令，支持可选的 -H/-P 参数
func RunADB(adbPath string, hostPort string, args ...string) (string, error) {
	var cmdArgs []string
	if hostPort != "" {
		parts := strings.SplitN(hostPort, ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
			cmdArgs = append(cmdArgs, "-H", strings.TrimSpace(parts[0]), "-P", strings.TrimSpace(parts[1]))
		}
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(adbPath, cmdArgs...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func trimOutput(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	if len(out) > 800 {
		out = out[:800] + "..."
	}
	return ": " + out
}

// shellQuote 为 Android /system/bin/sh 引用字符串
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == ':' || r == '/' || r == '+' ||
			(r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// RunShell 执行 Android shell 命令
func RunShell(adbPath, hostPort, command string) (string, error) {
	return RunADB(adbPath, hostPort, "shell", command)
}

// RunShellMaybeRoot 通过 su/kp/ksud 执行命令
func RunShellMaybeRoot(adbPath, hostPort, suCmd, command string) (string, error) {
	suCmd = strings.TrimSpace(suCmd)
	if suCmd == "" {
		return RunShell(adbPath, hostPort, command)
	}
	quoted := shellQuote(command)
	if strings.Contains(suCmd, "{cmd}") {
		return RunShell(adbPath, hostPort, strings.ReplaceAll(suCmd, "{cmd}", quoted))
	}
	return RunShell(adbPath, hostPort, suCmd+" "+quoted)
}

// GetDeviceList 返回已连接设备列表
func GetDeviceList(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "devices")
	if err != nil {
		return nil, fmt.Errorf("adb devices failed: %w%s", err, trimOutput(out))
	}
	var devices []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "device" {
			devices = append(devices, fields[0])
		}
	}
	return devices, nil
}

// GetAppListInternal 返回第三方应用包名列表
func GetAppListInternal(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "shell", "pm", "list", "packages", "-3")
	if err != nil {
		return nil, fmt.Errorf("pm list packages failed: %w%s", err, trimOutput(out))
	}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkgs = append(pkgs, strings.TrimPrefix(line, "package:"))
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

// PushNhdd 推送 nhdd 二进制到设备
func PushNhdd(adbPath, hostPort, localPath string) error {
	if _, err := os.Stat(localPath); err != nil {
		return fmt.Errorf("local nhdd not found at %s: %w", localPath, err)
	}
	out, err := RunADB(adbPath, hostPort, "push", localPath, "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("adb push nhdd failed: %w%s", err, trimOutput(out))
	}
	out, err = RunADB(adbPath, hostPort, "shell", "chmod", "755", "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("chmod nhdd failed: %w%s", err, trimOutput(out))
	}
	return nil
}

// DumpApp 执行 force-stop -> clean -> launch -> wait -> nhdd
func DumpApp(adbPath, hostPort, suCmd, pkg string, waitSec int, mode string) (string, error) {
	out, err := RunADB(adbPath, hostPort, "shell", "am", "force-stop", pkg)
	if err != nil {
		return out, fmt.Errorf("force-stop failed: %w%s", err, trimOutput(out))
	}

	_, _ = RunShell(adbPath, hostPort, "rm -rf "+shellQuote(deviceDumpDir))
	_, _ = RunShell(adbPath, hostPort, "mkdir -p "+shellQuote(deviceDumpDir))

	out, err = RunADB(adbPath, hostPort, "shell", "monkey", "-p", pkg,
		"-c", "android.intent.category.LAUNCHER", "1")
	if err != nil {
		return out, fmt.Errorf("launch app failed: %w%s", err, trimOutput(out))
	}

	time.Sleep(time.Duration(waitSec) * time.Second)

	modeArg := "--dex"
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "so", "--so":
		modeArg = "--so"
	case "all", "--all":
		modeArg = "--all"
	}

	pidOut, _ := RunADB(adbPath, hostPort, "shell", "pidof", pkg)
	pidFields := strings.Fields(pidOut)
	target := pkg
	if len(pidFields) > 0 {
		target = pidFields[0]
	}

	nhddCmd := fmt.Sprintf("/data/local/tmp/nhdd %s %s %s", shellQuote(target), shellQuote(deviceDumpDir), modeArg)
	out, err = RunShellMaybeRoot(adbPath, hostPort, suCmd, nhddCmd)
	if err != nil {
		return out, fmt.Errorf("nhdd failed: %w%s", err, trimOutput(out))
	}
	return out, nil
}

// PullDumpFiles 拉取 dump 文件到本地，返回 DEX 和 SO 数量
func PullDumpFiles(adbPath, hostPort, localDir, pkg string) (int, int, error) {
	targetDir := filepath.Join(localDir, pkg)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return 0, 0, fmt.Errorf("create output dir failed: %w", err)
	}

	out, err := RunADB(adbPath, hostPort, "pull", deviceDumpDir+"/.", targetDir+string(os.PathSeparator))
	if err != nil {
		return 0, 0, fmt.Errorf("adb pull failed: %w%s", err, trimOutput(out))
	}

	_, _ = RunShell(adbPath, hostPort, "rm -rf "+shellQuote(deviceDumpDir))

	dexFiles, err := findDexFiles(targetDir)
	if err != nil {
		return 0, 0, err
	}
	soFiles, err := findFilesByExt(targetDir, ".so")
	if err != nil {
		return len(dexFiles), 0, err
	}
	return len(dexFiles), len(soFiles), nil
}
