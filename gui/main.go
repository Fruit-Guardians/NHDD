package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func waitForSeconds(sec int) {
	time.Sleep(time.Duration(sec) * time.Second)
}

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

type nhddApp struct {
	window fyne.Window

	// ADB settings
	adbPathEntry  *widget.Entry
	hostPortEntry *widget.Entry
	connectBtn    *widget.Button
	deviceLabel   *widget.Label

	// App list
	appList      *widget.List
	appSearch    *widget.Entry
	refreshBtn   *widget.Button
	packages     []string
	filteredPkgs []string
	selectedPkg  string

	// Config
	suCmdEntry     *widget.Entry
	outputDirEntry *widget.Entry
	waitSlider     *widget.Slider
	waitLabel      *widget.Label

	// Dump
	dumpBtn *widget.Button

	// Status
	statusLog *widget.Entry
	logScroll *container.Scroll

	// State
	dumping bool
}

func main() {
	a := app.New()
	w := a.NewWindow("NHDD - No-Hook DEX Dumper")
	w.Resize(fyne.NewSize(1000, 700))

	gui := &nhddApp{
		window: w,
	}

	gui.buildUI()
	w.ShowAndRun()
}

func (app *nhddApp) buildUI() {
	// ---- Top bar: ADB settings ----
	app.adbPathEntry = widget.NewEntry()
	app.adbPathEntry.SetPlaceHolder("adb")
	app.adbPathEntry.SetText("adb")

	app.hostPortEntry = widget.NewEntry()
	app.hostPortEntry.SetPlaceHolder("192.168.238.1:5037")

	app.connectBtn = widget.NewButton("Connect", app.onConnect)
	app.connectBtn.Importance = widget.HighImportance

	app.deviceLabel = widget.NewLabel("No device")

	// Grid: 8 columns - label:min, entry:3x, label:min, entry:2x, btn, label
	adbRow := container.New(layout.NewGridLayoutWithColumns(8),
		container.NewVBox(widget.NewLabel("ADB路径:")),
		app.adbPathEntry,
		container.NewVBox(widget.NewLabel("Host:Port:")),
		app.hostPortEntry,
		app.connectBtn,
		app.deviceLabel,
		layout.NewSpacer(),
		layout.NewSpacer(),
	)

	// ---- Middle left: App list ----
	app.appSearch = widget.NewEntry()
	app.appSearch.SetPlaceHolder("搜索应用包名...")
	app.appSearch.OnChanged = app.onSearchChanged

	app.refreshBtn = widget.NewButtonWithIcon("刷新", theme.ViewRefreshIcon(), app.onRefresh)

	searchRow := container.NewBorder(nil, nil, nil, app.refreshBtn, app.appSearch)

	app.appList = widget.NewList(
		func() int { return len(app.filteredPkgs) },
		func() fyne.CanvasObject {
			return widget.NewLabel("com.example.package.name.here")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			if id < len(app.filteredPkgs) {
				label.SetText(app.filteredPkgs[id])
			}
		},
	)
	app.appList.OnSelected = func(id widget.ListItemID) {
		if id < len(app.filteredPkgs) {
			app.selectedPkg = app.filteredPkgs[id]
			app.log(fmt.Sprintf("已选择: %s", app.selectedPkg))
		}
	}

	appListPanel := container.NewBorder(searchRow, nil, nil, nil, app.appList)

	// ---- Middle right: Config panel ----
	app.suCmdEntry = widget.NewEntry()
	app.suCmdEntry.SetPlaceHolder("留空=普通shell, 或 su -c / kp")

	app.outputDirEntry = widget.NewEntry()
	app.outputDirEntry.SetPlaceHolder("输出目录")
	app.outputDirEntry.SetText("./nhdd_output")

	app.waitSlider = widget.NewSlider(2, 10)
	app.waitSlider.SetValue(4)
	app.waitSlider.Step = 1
	app.waitLabel = widget.NewLabel("4秒")
	app.waitSlider.OnChanged = func(v float64) {
		app.waitLabel.SetText(fmt.Sprintf("%.0f秒", v))
	}

	nhddLabel := widget.NewLabel("nhdd: " + nhddBinaryPath())

	configForm := container.NewVBox(
		widget.NewLabel("脱壳配置"),
		widget.NewSeparator(),
		widget.NewLabel("SU命令:"),
		app.suCmdEntry,
		widget.NewLabel("PC输出目录:"),
		app.outputDirEntry,
		widget.NewLabel("等待时间:"),
		container.NewBorder(nil, nil, nil, app.waitLabel, app.waitSlider),
		widget.NewSeparator(),
		nhddLabel,
	)

	// ---- Bottom: DUMP button + Status log ----
	app.dumpBtn = widget.NewButton("DUMP!", app.onDump)
	app.dumpBtn.Importance = widget.HighImportance

	app.statusLog = widget.NewEntry()
	app.statusLog.MultiLine = true
	app.statusLog.Wrapping = fyne.TextWrapWord
	app.statusLog.SetPlaceHolder("等待操作...")

	app.logScroll = container.NewVScroll(app.statusLog)
	app.logScroll.SetMinSize(fyne.NewSize(0, 150))

	// DUMP button on left, log on right, both full width
	bottomBar := container.NewBorder(nil, nil, app.dumpBtn, nil, app.logScroll)

	// ---- Main layout ----
	middle := container.NewHSplit(
		appListPanel,
		container.NewVScroll(configForm),
	)
	middle.SetOffset(0.7)

	content := container.NewBorder(
		adbRow,
		bottomBar,
		nil, nil,
		middle,
	)

	app.window.SetContent(content)
}

func (app *nhddApp) log(msg string) {
	current := app.statusLog.Text
	if current != "" {
		current += "\n"
	}
	current += fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	app.statusLog.SetText(current)
	app.logScroll.ScrollToBottom()
}

func (app *nhddApp) adbPath() string {
	p := strings.TrimSpace(app.adbPathEntry.Text)
	if p == "" {
		return "adb"
	}
	return p
}

func (app *nhddApp) hostPort() string {
	return strings.TrimSpace(app.hostPortEntry.Text)
}

func (app *nhddApp) onConnect() {
	app.log("正在连接ADB...")
	go func() {
		devices, err := GetDeviceList(app.adbPath(), app.hostPort())
		if err != nil {
			app.log(fmt.Sprintf("连接失败: %v", err))
			app.deviceLabel.SetText("连接失败")
			return
		}
		if len(devices) == 0 {
			app.log("未发现设备")
			app.deviceLabel.SetText("无设备")
			return
		}
		app.log(fmt.Sprintf("已连接 %d 个设备: %s", len(devices), strings.Join(devices, ", ")))
		app.deviceLabel.SetText(fmt.Sprintf("已连接: %s", devices[0]))
	}()
}

func (app *nhddApp) onRefresh() {
	app.log("正在加载应用列表...")
	go func() {
		pkgs, err := GetAppList(app.adbPath(), app.hostPort())
		if err != nil {
			app.log(fmt.Sprintf("加载应用失败: %v", err))
			return
		}
		app.packages = pkgs
		app.filteredPkgs = pkgs
		app.appList.Refresh()
		app.log(fmt.Sprintf("已加载 %d 个第三方应用", len(pkgs)))
	}()
}

func (app *nhddApp) onSearchChanged(text string) {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		app.filteredPkgs = app.packages
	} else {
		var filtered []string
		for _, pkg := range app.packages {
			if strings.Contains(strings.ToLower(pkg), text) {
				filtered = append(filtered, pkg)
			}
		}
		app.filteredPkgs = filtered
	}
	app.appList.Refresh()
}

func (app *nhddApp) onDump() {
	if app.dumping {
		app.log("正在脱壳中，请等待...")
		return
	}

	if app.selectedPkg == "" {
		dialog.ShowInformation("提示", "请先选择一个应用", app.window)
		return
	}

	app.dumping = true
	app.dumpBtn.Disable()
	app.dumpBtn.SetText("脱壳中...")

	pkg := app.selectedPkg
	suCmd := strings.TrimSpace(app.suCmdEntry.Text)
	outputDir := strings.TrimSpace(app.outputDirEntry.Text)
	if outputDir == "" {
		outputDir = "./nhdd_output"
	}
	waitSec := int(app.waitSlider.Value)
	adbPath := app.adbPath()
	hostPort := app.hostPort()
	nhddPath := nhddBinaryPath()

	go func() {
		defer func() {
			app.dumping = false
			app.dumpBtn.Enable()
			app.dumpBtn.SetText("DUMP!")
		}()

		// Step 1: Push nhdd binary
		app.log(fmt.Sprintf("[1/7] 推送 nhdd 到设备..."))
		if err := PushNhdd(adbPath, hostPort, nhddPath); err != nil {
			app.log(fmt.Sprintf("推送 nhdd 失败: %v", err))
			return
		}
		app.log("[1/7] nhdd 已推送")

		// Step 2: Force stop + Launch + Wait + Run nhdd
		app.log(fmt.Sprintf("[2/7] 强制停止 %s ...", pkg))
		app.log(fmt.Sprintf("[3/7] 启动应用 %s ...", pkg))
		app.log(fmt.Sprintf("[4/7] 等待 %d 秒让应用加载并解包DEX...", waitSec))
		nhddOut, err := DumpApp(adbPath, hostPort, suCmd, pkg, waitSec)
		if nhddOut != "" {
			for _, line := range strings.Split(nhddOut, "\n") {
				if strings.TrimSpace(line) != "" {
					app.log(fmt.Sprintf("  nhdd: %s", line))
				}
			}
		}
		if err != nil {
			app.log(fmt.Sprintf("脱壳失败: %v", err))
			return
		}
		app.log("[5/7] nhdd 执行完成")

		// Step 3: Create output directory
		os.MkdirAll(filepath.Join(outputDir, pkg), 0755)

		// Step 4: Pull DEX files
		app.log(fmt.Sprintf("[6/7] 拉取DEX文件到 %s/%s/ ...", outputDir, pkg))
		dexCount, err := PullDexFiles(adbPath, hostPort, outputDir, pkg)
		if err != nil {
			app.log(fmt.Sprintf("拉取DEX文件失败: %v", err))
			return
		}
		app.log(fmt.Sprintf("[6/7] 已拉取 %d 个DEX文件", dexCount))

		if dexCount == 0 {
			app.log("未发现DEX文件，应用可能已崩溃或壳未解包DEX")
			return
		}

		// Step 5: Fix DEX headers + checksums
		app.log("[7/7] 修复DEX文件...")
		targetDir := filepath.Join(outputDir, pkg)
		fixedCount, deletedCount, totalCount, err := FixDexDirectory(targetDir)
		if err != nil {
			app.log(fmt.Sprintf("修复DEX出错: %v", err))
		} else {
			app.log(fmt.Sprintf("[7/7] 修复完成: %d/%d 已修复, %d 无效已删除", fixedCount, totalCount, deletedCount))
		}

		// Calculate total size (after deletion of invalid files)
		var totalSize int64
		var validCount int
		dexFiles, _ := findDexFiles(targetDir)
		for _, f := range dexFiles {
			if info, err := os.Stat(f); err == nil {
				totalSize += info.Size()
				validCount++
			}
		}

		app.log(fmt.Sprintf("脱壳完成! %d 个有效DEX文件, 总大小: %.2f KB, 输出: %s",
			validCount, float64(totalSize)/1024.0, targetDir))
	}()
}
