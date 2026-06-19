package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// RunADB executes an adb command with optional -H/-P flags, returns stdout.
func RunADB(adbPath string, hostPort string, args ...string) (string, error) {
	var cmdArgs []string
	if hostPort != "" {
		parts := strings.SplitN(hostPort, ":", 2)
		if len(parts) == 2 {
			cmdArgs = append(cmdArgs, "-H", parts[0], "-P", parts[1])
		}
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(adbPath, cmdArgs...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// GetDeviceList returns list of connected device IDs.
func GetDeviceList(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "devices")
	if err != nil {
		return nil, fmt.Errorf("adb devices failed: %w", err)
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

// GetAppList returns list of 3rd party package names.
func GetAppList(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "shell", "pm", "list", "packages", "-3")
	if err != nil {
		return nil, fmt.Errorf("pm list packages failed: %w", err)
	}
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkgs = append(pkgs, strings.TrimPrefix(line, "package:"))
		}
	}
	return pkgs, nil
}

// PushNhdd pushes the nhdd binary to /data/local/tmp/nhdd and chmod 755.
func PushNhdd(adbPath, hostPort, localPath string) error {
	_, err := RunADB(adbPath, hostPort, "push", localPath, "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("adb push nhdd failed: %w", err)
	}
	_, err = RunADB(adbPath, hostPort, "shell", "chmod", "755", "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("chmod nhdd failed: %w", err)
	}
	return nil
}

// DumpApp executes the full dump flow on the phone, returns nhdd output.
func DumpApp(adbPath, hostPort, suCmd, pkg string, waitSec int) (string, error) {
	// Force stop
	_, err := RunADB(adbPath, hostPort, "shell", "am", "force-stop", pkg)
	if err != nil {
		return "", fmt.Errorf("force-stop failed: %w", err)
	}

	// Clear previous dump directory
	_, _ = RunADB(adbPath, hostPort, "shell", "rm", "-rf", "/data/local/tmp/nhdd_dump")

	// Launch app
	_, err = RunADB(adbPath, hostPort, "shell", "monkey", "-p", pkg,
		"-c", "android.intent.category.LAUNCHER", "1")
	if err != nil {
		return "", fmt.Errorf("launch app failed: %w", err)
	}

	// Wait for app to load and unpack DEX
	waitForSeconds(waitSec)

	// Create dump directory on device
	_, _ = RunADB(adbPath, hostPort, "shell", "mkdir", "-p", "/data/local/tmp/nhdd_dump")

	// Run nhdd - use PID directly to avoid pidof returning wrong process
	// First get PID
	pidOut, _ := RunADB(adbPath, hostPort, "shell", "pidof", pkg)
	pid := strings.Fields(pidOut) // may return multiple PIDs, take first (main process)
	pidStr := ""
	if len(pid) > 0 {
		pidStr = pid[0] // first PID is usually the main process
	}

	var nhddCmd string
	if pidStr != "" {
		// Use PID directly for more reliable targeting
		nhddCmd = fmt.Sprintf("/data/local/tmp/nhdd %s /data/local/tmp/nhdd_dump", pidStr)
	} else {
		// Fallback to package name
		nhddCmd = fmt.Sprintf("/data/local/tmp/nhdd %s /data/local/tmp/nhdd_dump", pkg)
	}

	var out string
	if suCmd != "" {
		out, err = RunADB(adbPath, hostPort, "shell", suCmd, nhddCmd)
	} else {
		out, err = RunADB(adbPath, hostPort, "shell", nhddCmd)
	}
	if err != nil {
		return out, fmt.Errorf("nhdd failed: %w", err)
	}
	return out, nil
}

// PullDexFiles pulls /data/local/tmp/nhdd_dump/ to localDir/pkg/,
// then cleans up the dump directory on the phone.
// Returns count of .dex files pulled.
func PullDexFiles(adbPath, hostPort, localDir, pkg string) (int, error) {
	targetDir := localDir + "/" + pkg
	_, err := RunADB(adbPath, hostPort, "pull", "/data/local/tmp/nhdd_dump/.", targetDir+"/")
	if err != nil {
		return 0, fmt.Errorf("adb pull failed: %w", err)
	}

	// Clean up phone dump directory after successful pull
	_, _ = RunADB(adbPath, hostPort, "shell", "rm", "-rf", "/data/local/tmp/nhdd_dump")

	// Count .dex files
	dexFiles, err := findDexFiles(targetDir)
	if err != nil {
		return 0, err
	}
	return len(dexFiles), nil
}
