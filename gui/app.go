package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App 主应用结构体
type App struct {
	ctx     context.Context
	mu      sync.Mutex
	dumping bool
}

// NewApp 创建新的 App 实例
func NewApp() *App {
	return &App{}
}

// startup Wails 启动回调
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// nhddBinaryPath 查找 nhdd 二进制文件路径
func nhddBinaryPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "nhdd"
	}
	candidate := filepath.Join(filepath.Dir(exePath), "nhdd")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	candidate = filepath.Join(filepath.Dir(exePath), "..", "nhdd")
	if abs, err := filepath.Abs(candidate); err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return "nhdd"
}

// ConnectADB 连接 ADB 设备，返回设备列表
func (a *App) ConnectADB(adbPath, hostPort string) ([]string, error) {
	return GetDeviceList(adbPath, hostPort)
}

// GetAppListResult 获取应用列表的结果
type GetAppListResult struct {
	Packages []string `json:"packages"`
	Error    string   `json:"error,omitempty"`
}

// GetAppList 获取第三方应用列表
func (a *App) GetAppList(adbPath, hostPort string) *GetAppListResult {
	pkgs, err := GetAppListInternal(adbPath, hostPort)
	if err != nil {
		return &GetAppListResult{Error: err.Error()}
	}
	return &GetAppListResult{Packages: pkgs}
}

// DumpParams 脱壳参数（对齐 TUI 的全部配置）
type DumpParams struct {
	Package       string `json:"package"`
	SuCmd         string `json:"suCmd"`
	OutputDir     string `json:"outputDir"`
	AdbPath       string `json:"adbPath"`
	HostPort      string `json:"hostPort"`
	Mode          string `json:"mode"`          // dex, so, all
	Restart       bool   `json:"restart"`       // 是否重启 app
	Watch         bool   `json:"watch"`         // 是否启用 watch
	DryLimit      int    `json:"dryLimit"`      // watch 连续几轮无新 DEX 停止
	MaxSeconds    int    `json:"maxSeconds"`    // watch 最大运行秒数
	MaxRounds     int    `json:"maxRounds"`     // watch 最大轮数
	Stealth       bool   `json:"stealth"`       // 是否启用 stealth
	Stealth2      bool   `json:"stealth2"`      // 使用 process_vm_readv 替代 /proc/pid/mem（反检测）
	Relaxed       bool   `json:"relaxed"`       // 宽松 DEX 验证（endian_tag，不依赖 magic）
	RelaxedSO     bool   `json:"relaxedSo"`     // 宽松 SO 识别（ELF magic 抹除时用结构识别）
	Anon          bool   `json:"anon"`          // 仅扫描匿名内存映射
	RegionDelayMs int    `json:"regionDelayMs"` // 区域延时毫秒
}

// DumpResult 脱壳结果
type DumpResult struct {
	Success    bool     `json:"success"`
	Message    string   `json:"message"`
	DexCount   int      `json:"dexCount"`
	SoCount    int      `json:"soCount"`
	FixedCount int      `json:"fixedCount"`
	BadCount   int      `json:"badCount"`
	BadFiles   []string `json:"badFiles"`
	TotalSize  int64    `json:"totalSize"`
	OutputDir  string   `json:"outputDir"`
	Rounds     int      `json:"rounds"`
	Processes  int      `json:"processes"`
}

// WatchProgress watch 实时进度
type WatchProgress struct {
	Round     int  `json:"round"`
	NewThis   int  `json:"newThis"`
	Total     int  `json:"total"`
	Dedup     int  `json:"dedup"`
	Dry       int  `json:"dry"`
	DryLimit  int  `json:"dryLimit"`
	Processes int  `json:"processes"`
	DexFiles  int  `json:"dexFiles"`
	SoFiles   int  `json:"soFiles"`
	Done      bool `json:"done"`
}

// nhdd 输出解析正则
var (
	reRound   = regexp.MustCompile(`round\s+(\d+):\s*\+(\d+)\s+new unique DEX\s+\(total=(\d+),\s*dry=(\d+)/(\d+)`)
	reProc    = regexp.MustCompile(`Resolved.*->\s*(\d+)\s+process`)
	reDone    = regexp.MustCompile(`Done\..*DEX unique=(\d+).*dedup_skipped=(\d+).*SO=(\d+)`)
	reDexFile = regexp.MustCompile(`^\[\+\]\s+DEX:`)
	reSoFile  = regexp.MustCompile(`^\[\+\]\s+SO:`)
)

// StartDump 执行脱壳流程（对齐 TUI 逻辑）
func (a *App) StartDump(params DumpParams) *DumpResult {
	a.mu.Lock()
	if a.dumping {
		a.mu.Unlock()
		return &DumpResult{Success: false, Message: "正在脱壳中，请等待..."}
	}
	a.dumping = true
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.dumping = false
		a.mu.Unlock()
	}()

	// 默认值
	if params.Mode == "" {
		params.Mode = "dex"
	}
	if params.OutputDir == "" {
		params.OutputDir = "./nhdd_output"
	}
	if params.DryLimit == 0 {
		params.DryLimit = 3
	}
	if params.MaxSeconds == 0 {
		params.MaxSeconds = 120
	}
	if params.MaxRounds == 0 {
		params.MaxRounds = 60
	}

	adbPath := params.AdbPath
	hostPort := params.HostPort
	pkg := params.Package
	suCmd := params.SuCmd
	outputDir := params.OutputDir

	// Step 1: Push nhdd binary
	a.log("[1/6] 推送 nhdd 到设备...")
	nhddPath := nhddBinaryPath()
	if err := PushNhdd(adbPath, hostPort, nhddPath); err != nil {
		a.log(fmt.Sprintf("推送 nhdd 失败: %v", err))
		return &DumpResult{Success: false, Message: fmt.Sprintf("推送 nhdd 失败: %v", err)}
	}
	a.log("[1/6] nhdd 已推送")

	// Step 2: 清理设备端输出目录
	a.log("[2/6] 清理设备端输出目录...")
	_, _ = RunShellMaybeRoot(adbPath, hostPort, suCmd, fmt.Sprintf("rm -rf %s; mkdir -p %s", shellQuote(deviceDumpDir), shellQuote(deviceDumpDir)))

	// Step 3: 可选重启 app
	if params.Restart {
		a.log(fmt.Sprintf("[3/6] 强制停止 %s ...", pkg))
		RunADB(adbPath, hostPort, "shell", "am", "force-stop", pkg)
		a.log(fmt.Sprintf("[3/6] 启动 %s ...", pkg))
		RunADB(adbPath, hostPort, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1")
		a.log("[3/6] 等待 3 秒让壳解密...")
		time.Sleep(3 * time.Second)
	} else {
		a.log("[3/6] 跳过重启(扫当前进程 — 强对抗壳推荐)")
	}

	// Step 4: 构建 nhdd 命令并执行（带 watch 实时进度）
	a.log("[4/6] 运行 nhdd...")

	modeArg := "--dex"
	switch strings.ToLower(strings.TrimSpace(params.Mode)) {
	case "so":
		modeArg = "--so"
	case "all":
		modeArg = "--all"
	}

	nhddCmdParts := []string{"/data/local/tmp/nhdd", pkg, deviceDumpDir, modeArg}
	if params.Watch {
		nhddCmdParts = append(nhddCmdParts, "--watch", strconv.Itoa(params.DryLimit),
			"--max-seconds", strconv.Itoa(params.MaxSeconds),
			"--max-rounds", strconv.Itoa(params.MaxRounds))
	}
	if params.Stealth {
		nhddCmdParts = append(nhddCmdParts, "--stealth")
		if params.RegionDelayMs > 0 {
			nhddCmdParts = append(nhddCmdParts, "--region-delay", strconv.Itoa(params.RegionDelayMs))
		}
	}
	if params.Stealth2 {
		nhddCmdParts = append(nhddCmdParts, "--stealth2")
	}
	if params.Relaxed {
		nhddCmdParts = append(nhddCmdParts, "--relaxed")
	}
	if params.RelaxedSO {
		nhddCmdParts = append(nhddCmdParts, "--relaxed-so")
	}
	if params.Anon {
		nhddCmdParts = append(nhddCmdParts, "--anon")
	}

	nhddCmdStr := strings.Join(nhddCmdParts, " ")
	var fullShellCmd string
	if suCmd != "" {
		su := strings.TrimSpace(suCmd)
		if strings.Contains(su, "{cmd}") {
			fullShellCmd = strings.ReplaceAll(su, "{cmd}", shellQuote(nhddCmdStr))
		} else {
			fullShellCmd = su + " " + shellQuote(nhddCmdStr)
		}
	} else {
		fullShellCmd = nhddCmdStr
	}

	// 执行 adb shell 命令，实时解析输出
	progress := &WatchProgress{DryLimit: params.DryLimit}
	if !params.Watch {
		progress.DryLimit = 1
	}

	var cmdArgs []string
	if hostPort != "" {
		parts := strings.SplitN(hostPort, ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
			cmdArgs = append(cmdArgs, "-H", strings.TrimSpace(parts[0]), "-P", strings.TrimSpace(parts[1]))
		}
	}
	cmdArgs = append(cmdArgs, "shell", fullShellCmd)

	cmd := exec.Command(adbPath, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	cmd.Start()

	// 解析 stderr（进度信息）和 stdout（文件列表）
	done := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			a.log(fmt.Sprintf("  nhdd: %s", line))
			parseNhddLine(line, progress)
			wailsRuntime.EventsEmit(a.ctx, "watch-progress", progress)
		}
		close(done)
	}()

	// stdout 也解析
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			a.log(fmt.Sprintf("  nhdd: %s", line))
			parseNhddLine(line, progress)
			wailsRuntime.EventsEmit(a.ctx, "watch-progress", progress)
		}
	}()

	cmd.Wait()
	<-done

	progress.Done = true
	wailsRuntime.EventsEmit(a.ctx, "watch-progress", progress)
	a.log("[4/6] nhdd 执行完成")

	// Step 5: 拉取 dump 文件
	a.log("[5/6] 拉取 dump 文件...")
	targetDir := filepath.Join(outputDir, pkg)
	os.MkdirAll(targetDir, 0755)

	dexCount, soCount, err := PullDumpFiles(adbPath, hostPort, outputDir, pkg, suCmd)
	if err != nil {
		a.log(fmt.Sprintf("拉取 dump 文件失败: %v", err))
		return &DumpResult{Success: false, Message: fmt.Sprintf("拉取失败: %v", err)}
	}
	a.log(fmt.Sprintf("[5/6] 已拉取 %d 个 DEX, %d 个 SO", dexCount, soCount))

	if dexCount == 0 {
		a.log("未发现 DEX 文件：请检查目标是否已启动、root 命令是否正确")
	}

	// Step 6: 修复 DEX
	a.log("[6/6] 修复 DEX 文件...")
	stats, err := FixDexDirectory(targetDir)
	if err != nil {
		a.log(fmt.Sprintf("修复 DEX 出错: %v", err))
	} else {
		a.log(fmt.Sprintf("[6/6] 修复完成: %d OK, %d 修复, %d 损坏已隔离", stats.OK, stats.Fixed, stats.Bad))
		if stats.Bad > 0 {
			a.log(fmt.Sprintf("  [警告] 损坏文件: %v", stats.BadFiles))
		}
	}
	fixedCount := 0
	badCount := 0
	var badFiles []string
	if stats != nil {
		fixedCount = stats.Fixed
		badCount = stats.Bad
		badFiles = stats.BadFiles
	}

	// Step 6b: 修复 SO (内建 ELF 修复, 替代外部 SoFixer)
	if soCount > 0 {
		a.log("[6b] 修复 SO 文件...")
		soStats, soErr := FixSoDirectory(targetDir)
		if soErr != nil {
			a.log(fmt.Sprintf("修复 SO 出错: %v", soErr))
		} else {
			a.log(fmt.Sprintf("[6b] SO 修复完成: %d OK, %d 修复, %d 损坏已隔离", soStats.OK, soStats.Fixed, soStats.Bad))
			if soStats.Bad > 0 {
				a.log(fmt.Sprintf("  [警告] 损坏 SO: %v", soStats.BadFiles))
			}
			fixedCount += soStats.Fixed
			badCount += soStats.Bad
			badFiles = append(badFiles, soStats.BadFiles...)
		}
	}

	// 计算总大小
	var totalSize int64
	filepath.WalkDir(targetDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, err := entry.Info(); err == nil {
			totalSize += info.Size()
		}
		return nil
	})

	a.log(fmt.Sprintf("脱壳完成! %d DEX, %d SO, %.2f KB, 输出: %s",
		dexCount, soCount, float64(totalSize)/1024.0, targetDir))

	return &DumpResult{
		Success:    true,
		DexCount:   dexCount,
		SoCount:    soCount,
		FixedCount: fixedCount,
		BadCount:   badCount,
		BadFiles:   badFiles,
		TotalSize:  totalSize,
		OutputDir:  targetDir,
		Rounds:     progress.Round,
		Processes:  progress.Processes,
	}
}

// parseNhddLine 解析 nhdd 输出行，更新进度
func parseNhddLine(line string, progress *WatchProgress) {
	if m := reRound.FindStringSubmatch(line); m != nil {
		progress.Round, _ = strconv.Atoi(m[1])
		progress.NewThis, _ = strconv.Atoi(m[2])
		progress.Total, _ = strconv.Atoi(m[3])
		progress.Dry, _ = strconv.Atoi(m[4])
		progress.DryLimit, _ = strconv.Atoi(m[5])
		return
	}
	if m := reProc.FindStringSubmatch(line); m != nil {
		progress.Processes, _ = strconv.Atoi(m[1])
		return
	}
	if m := reDone.FindStringSubmatch(line); m != nil {
		progress.Total, _ = strconv.Atoi(m[1])
		progress.Dedup, _ = strconv.Atoi(m[2])
		progress.SoFiles, _ = strconv.Atoi(m[3])
		return
	}
	if reDexFile.MatchString(line) {
		progress.DexFiles++
		return
	}
	if reSoFile.MatchString(line) {
		progress.SoFiles++
	}
}

// SelectDirectory 打开目录选择对话框
func (a *App) SelectDirectory() string {
	dir, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "选择输出目录",
	})
	if err != nil {
		return ""
	}
	return dir
}

// GetNhddPath 获取 nhdd 二进制路径
func (a *App) GetNhddPath() string {
	return nhddBinaryPath()
}

// IsDumping 返回当前是否正在脱壳
func (a *App) IsDumping() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dumping
}

// log 发送日志事件到前端
func (a *App) log(msg string) {
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "log", fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	}
}
