package main

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/adler32"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const appTitle = "NHDD Windows GUI - 漫宿骄盛"

type AppState struct {
	mu      sync.Mutex
	logs    []string
	running bool
}

var state = &AppState{}

func main() {
	logFile := initLogFile()
	if logFile != nil {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/devices", devicesHandler)
	mux.HandleFunc("/api/apps", appsHandler)
	mux.HandleFunc("/api/dump", dumpHandler)
	mux.HandleFunc("/api/logs", logsHandler)
	mux.HandleFunc("/api/status", statusHandler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	url := "http://" + ln.Addr().String() + "/"
	state.addLog("GUI started: " + url)
	go func() {
		_ = openBrowser(url)
	}()

	server := &http.Server{Handler: mux}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func initLogFile() *os.File {
	dir := os.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "nhdd-gui.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	return f
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func (s *AppState) addLog(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	s.logs = append(s.logs, line)
	if len(s.logs) > 2000 {
		s.logs = s.logs[len(s.logs)-2000:]
	}
	log.Println(line)
}

func (s *AppState) allLogs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.logs))
	copy(out, s.logs)
	return out
}

func (s *AppState) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *AppState) tryStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	return true
}

func (s *AppState) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, map[string]string{
		"Title": appTitle,
	})
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	adb := cleanPath(r.URL.Query().Get("adb"))
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if adb == "" {
		adb = "adb"
	}
	devices, err := GetDeviceList(adb, host)
	writeJSON(w, map[string]any{"ok": err == nil, "devices": devices, "error": errString(err)})
}

func appsHandler(w http.ResponseWriter, r *http.Request) {
	adb := cleanPath(r.URL.Query().Get("adb"))
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if adb == "" {
		adb = "adb"
	}
	pkgs, err := GetAppList(adb, host)
	writeJSON(w, map[string]any{"ok": err == nil, "packages": pkgs, "error": errString(err)})
}

type DumpRequest struct {
	ADBPath   string `json:"adbPath"`
	HostPort  string `json:"hostPort"`
	SUCommand string `json:"suCommand"`
	Package   string `json:"package"`
	WaitSec   int    `json:"waitSec"`
	OutputDir string `json:"outputDir"`
	Mode      string `json:"mode"`
}

func dumpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req DumpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	req.ADBPath = cleanPath(req.ADBPath)
	if req.ADBPath == "" {
		req.ADBPath = "adb"
	}
	req.HostPort = strings.TrimSpace(req.HostPort)
	req.SUCommand = strings.TrimSpace(req.SUCommand)
	req.Package = strings.TrimSpace(req.Package)
	if req.Package == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "package is required"})
		return
	}
	if req.WaitSec < 0 || req.WaitSec > 60 {
		req.WaitSec = 4
	}
	if req.OutputDir == "" {
		req.OutputDir = ".\\nhdd_output"
	}
	if req.Mode == "" {
		req.Mode = "dex"
	}
	if !state.tryStart() {
		writeJSON(w, map[string]any{"ok": false, "error": "dump is already running"})
		return
	}
	go runDump(req)
	writeJSON(w, map[string]any{"ok": true})
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"logs": state.allLogs(), "running": state.isRunning()})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"running": state.isRunning()})
}

func runDump(req DumpRequest) {
	defer state.finish()
	state.addLog("Selected package: " + req.Package)
	state.addLog("ADB: " + req.ADBPath)
	if req.HostPort != "" {
		state.addLog("ADB host:port: " + req.HostPort)
	}

	nhddPath := nhddBinaryPath()
	if _, err := os.Stat(nhddPath); err != nil {
		state.addLog("ERROR: cannot find Android nhdd binary next to this exe. Put file named 'nhdd' in the same directory as nhdd-gui-web.exe")
		return
	}
	state.addLog("nhdd binary: " + nhddPath)

	state.addLog("[1/7] pushing nhdd to /data/local/tmp/nhdd ...")
	if err := PushNhdd(req.ADBPath, req.HostPort, nhddPath); err != nil {
		state.addLog("ERROR: push nhdd failed: " + err.Error())
		return
	}
	state.addLog("[1/7] nhdd pushed")

	modeArg := "--dex"
	switch strings.ToLower(req.Mode) {
	case "so":
		modeArg = "--so"
	case "all":
		modeArg = "--all"
	}

	state.addLog("[2/7] force-stop " + req.Package)
	if out, err := RunADB(req.ADBPath, req.HostPort, "shell", "am", "force-stop", req.Package); err != nil {
		state.addLog("WARN: force-stop failed: " + err.Error() + trimOut(out))
	}

	_, _ = RunADB(req.ADBPath, req.HostPort, "shell", "rm", "-rf", "/data/local/tmp/nhdd_dump")
	_, _ = RunADB(req.ADBPath, req.HostPort, "shell", "mkdir", "-p", "/data/local/tmp/nhdd_dump")

	state.addLog("[3/7] launch app")
	if out, err := RunADB(req.ADBPath, req.HostPort, "shell", "monkey", "-p", req.Package, "-c", "android.intent.category.LAUNCHER", "1"); err != nil {
		state.addLog("ERROR: launch failed: " + err.Error() + trimOut(out))
		return
	}

	state.addLog(fmt.Sprintf("[4/7] wait %d seconds", req.WaitSec))
	time.Sleep(time.Duration(req.WaitSec) * time.Second)

	pidOut, _ := RunADB(req.ADBPath, req.HostPort, "shell", "pidof", req.Package)
	pidFields := strings.Fields(pidOut)
	target := req.Package
	if len(pidFields) > 0 {
		target = pidFields[0]
		state.addLog("PID: " + target)
	} else {
		state.addLog("WARN: pidof did not return PID, fallback to package name")
	}

	cmd := fmt.Sprintf("/data/local/tmp/nhdd %s /data/local/tmp/nhdd_dump %s", shellQuote(target), modeArg)
	state.addLog("[5/7] run nhdd: " + cmd)
	out, err := RunADBShellMaybeRoot(req.ADBPath, req.HostPort, req.SUCommand, cmd)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			state.addLog("nhdd: " + line)
		}
	}
	if err != nil {
		state.addLog("ERROR: nhdd failed: " + err.Error())
		return
	}

	targetDir := filepath.Join(req.OutputDir, req.Package)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		state.addLog("ERROR: create output directory failed: " + err.Error())
		return
	}
	state.addLog("[6/7] pull dump files to " + targetDir)
	if out, err := RunADB(req.ADBPath, req.HostPort, "pull", "/data/local/tmp/nhdd_dump/.", targetDir+string(os.PathSeparator)); err != nil {
		state.addLog("ERROR: adb pull failed: " + err.Error() + trimOut(out))
		return
	}
	_, _ = RunADB(req.ADBPath, req.HostPort, "shell", "rm", "-rf", "/data/local/tmp/nhdd_dump")

	dexFiles, _ := findFilesByExtRecursive(targetDir, ".dex")
	soFiles, _ := findFilesByExtRecursive(targetDir, ".so")
	state.addLog(fmt.Sprintf("[6/7] pulled: %d dex, %d so", len(dexFiles), len(soFiles)))

	if len(dexFiles) > 0 {
		state.addLog("[7/7] fix DEX headers/checksums recursively")
		fixed, deleted, total := FixDexDirectoryRecursive(targetDir)
		state.addLog(fmt.Sprintf("[7/7] DEX fix done: fixed=%d total=%d deleted=%d", fixed, total, deleted))
	} else {
		state.addLog("[7/7] no DEX files found to fix")
	}

	var totalSize int64
	_ = filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			totalSize += info.Size()
		}
		return nil
	})
	state.addLog(fmt.Sprintf("DONE: output=%s, dex=%d, so=%d, size=%.2f KB", targetDir, len(dexFiles), len(soFiles), float64(totalSize)/1024.0))
}

func trimOut(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	if len(out) > 500 {
		out = out[:500] + "..."
	}
	return " | output: " + out
}

func cleanPath(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\"")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func RunADB(adbPath string, hostPort string, args ...string) (string, error) {
	var cmdArgs []string
	if hostPort != "" {
		parts := strings.SplitN(hostPort, ":", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			cmdArgs = append(cmdArgs, "-H", parts[0], "-P", parts[1])
		}
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(adbPath, cmdArgs...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func RunADBShellMaybeRoot(adbPath, hostPort, suCmd, command string) (string, error) {
	if strings.TrimSpace(suCmd) == "" {
		return RunADB(adbPath, hostPort, "shell", command)
	}
	fields := strings.Fields(suCmd)
	args := []string{"shell"}
	args = append(args, fields...)
	// Common cases: su -c <cmd>, ksud -c <cmd>. If user only enters "su", add -c.
	if len(fields) == 1 && (fields[0] == "su" || fields[0] == "ksud") {
		args = append(args, "-c", command)
	} else {
		args = append(args, command)
	}
	return RunADB(adbPath, hostPort, args...)
}

func GetDeviceList(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "devices")
	if err != nil {
		return nil, fmt.Errorf("adb devices failed: %w%s", err, trimOut(out))
	}
	var devices []string
	for _, line := range strings.Split(out, "\n") {
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

func GetAppList(adbPath, hostPort string) ([]string, error) {
	out, err := RunADB(adbPath, hostPort, "shell", "pm", "list", "packages", "-3")
	if err != nil {
		return nil, fmt.Errorf("pm list packages failed: %w%s", err, trimOut(out))
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

func PushNhdd(adbPath, hostPort, localPath string) error {
	out, err := RunADB(adbPath, hostPort, "push", localPath, "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("adb push nhdd failed: %w%s", err, trimOut(out))
	}
	out, err = RunADB(adbPath, hostPort, "shell", "chmod", "755", "/data/local/tmp/nhdd")
	if err != nil {
		return fmt.Errorf("chmod nhdd failed: %w%s", err, trimOut(out))
	}
	return nil
}

func nhddBinaryPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "nhdd"
	}
	dir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(dir, "nhdd"),
		filepath.Join(dir, "bin", "nhdd"),
		filepath.Join(dir, "..", "nhdd"),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return filepath.Join(dir, "nhdd")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == ':' || r == '/' || r == '+' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

const (
	dexHeaderSize = 0x70
	dexEndianTag  = 0x12345678
)

func FixDexFile(path string) (fixed bool, deleted bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	if len(data) < dexHeaderSize || string(data[:4]) != "dex\n" {
		_ = os.Remove(path)
		return false, true, fmt.Errorf("invalid dex deleted")
	}
	if binary.LittleEndian.Uint32(data[0x24:0x28]) != dexHeaderSize {
		binary.LittleEndian.PutUint32(data[0x24:0x28], dexHeaderSize)
		fixed = true
	}
	if binary.LittleEndian.Uint32(data[0x28:0x2c]) != dexEndianTag {
		binary.LittleEndian.PutUint32(data[0x28:0x2c], dexEndianTag)
		fixed = true
	}
	if binary.LittleEndian.Uint32(data[0x20:0x24]) != uint32(len(data)) {
		binary.LittleEndian.PutUint32(data[0x20:0x24], uint32(len(data)))
		fixed = true
	}
	sig := sha1.Sum(data[0x20:])
	if string(data[0x0c:0x20]) != string(sig[:]) {
		copy(data[0x0c:0x20], sig[:])
		fixed = true
	}
	checksum := adler32.Checksum(data[0x0c:])
	if binary.LittleEndian.Uint32(data[0x08:0x0c]) != checksum {
		binary.LittleEndian.PutUint32(data[0x08:0x0c], checksum)
		fixed = true
	}
	if fixed {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return false, false, err
		}
	}
	return fixed, false, nil
}

func FixDexDirectoryRecursive(dir string) (fixedCount, deletedCount, totalCount int) {
	files, _ := findFilesByExtRecursive(dir, ".dex")
	totalCount = len(files)
	for _, f := range files {
		fixed, deleted, _ := FixDexFile(f)
		if fixed {
			fixedCount++
		}
		if deleted {
			deletedCount++
		}
	}
	return
}

func findFilesByExtRecursive(dir, ext string) ([]string, error) {
	var files []string
	ext = strings.ToLower(ext)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ext) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{font-family:system-ui,-apple-system,"Segoe UI",Arial,"Microsoft YaHei",sans-serif;color:#17202a;background:#f5f7fb}body{margin:0}.top{background:#111827;color:#fff;padding:14px 20px}.top h1{font-size:18px;margin:0}.top .meta{margin-top:6px;font-size:13px;color:#cbd5e1}.top a{color:#93c5fd;text-decoration:none}.top a:hover{text-decoration:underline}.wrap{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;padding:16px}.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.04);padding:14px}.row{display:grid;grid-template-columns:110px 1fr;gap:10px;align-items:center;margin:8px 0}input,select,button{font:inherit;border-radius:8px;border:1px solid #d1d5db;padding:8px}button{cursor:pointer;background:#f9fafb}button.primary{background:#2563eb;color:#fff;border-color:#2563eb}button.danger{background:#dc2626;color:#fff;border-color:#dc2626}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.packages{height:390px;overflow:auto;border:1px solid #e5e7eb;border-radius:8px}.pkg{padding:7px 10px;border-bottom:1px solid #f1f5f9;cursor:pointer}.pkg:hover{background:#eff6ff}.pkg.sel{background:#dbeafe;font-weight:600}.log{height:250px;overflow:auto;background:#0b1020;color:#d1e7ff;border-radius:10px;padding:10px;font-family:Consolas,monospace;font-size:13px;white-space:pre-wrap}.hint{font-size:12px;color:#64748b}.notice p{margin:8px 0}.notice a{color:#2563eb}.disclaimer{line-height:1.55;color:#475569}.status{font-weight:600}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}@media(max-width:900px){.wrap{grid-template-columns:1fr}.packages{height:260px}}
</style>
</head>
<body>
<div class="top"><h1>NHDD Windows GUI</h1><div class="meta">作者：漫宿骄盛 · GitHub：<a href="https://github.com/mansujiaosheng/NHDD" target="_blank" rel="noopener noreferrer">https://github.com/mansujiaosheng/NHDD</a></div></div>
<div class="wrap">
  <div class="card">
    <h2>应用列表</h2>
    <div class="grid2">
      <input id="adb" value="adb" placeholder="adb 或 C:\\Android\\platform-tools\\adb.exe">
      <input id="host" placeholder="Host:Port，普通 Windows 本机 adb 留空">
    </div>
    <div class="actions">
      <button onclick="connect()">连接设备</button>
      <button onclick="refreshApps()">刷新第三方应用</button>
      <span id="dev" class="status">未连接</span>
    </div>
    <input id="search" placeholder="搜索包名..." oninput="renderPackages()" style="width:calc(100% - 18px); margin-bottom:8px">
    <div id="packages" class="packages"></div>
  </div>

  <div class="card notice">
    <h2>项目信息</h2>
    <p><b>作者：</b>漫宿骄盛</p>
    <p><b>GitHub：</b><a href="https://github.com/mansujiaosheng/NHDD" target="_blank" rel="noopener noreferrer">https://github.com/mansujiaosheng/NHDD</a></p>
    <p class="disclaimer"><b>免责声明：</b>本工具仅用于合法授权的安全研究、逆向分析与自有应用调试。使用者需确保已取得目标应用和设备授权。作者不对任何未授权使用、数据泄露、业务损失或法律责任负责。</p>
  </div>

  <div class="card">
    <h2>脱壳配置</h2>
    <div class="row"><label>目标包名</label><input id="pkg" placeholder="从左侧选择或手填"></div>
    <div class="row"><label>SU命令</label><input id="su" value="su -c" placeholder="su -c / ksud -c / 留空"></div>
    <div class="row"><label>等待秒数</label><input id="wait" type="number" min="0" max="60" value="4"></div>
    <div class="row"><label>输出目录</label><input id="out" value=".\nhdd_output"></div>
    <div class="row"><label>Dump模式</label><select id="mode"><option value="dex">DEX</option><option value="so">SO</option><option value="all">DEX + SO</option></select></div>
    <p class="hint">要求：把 Android ARM64 版 <b>nhdd</b> 放在本 exe 同目录；Windows 已能调用 adb；设备已 root。</p>
    <button id="dump" class="primary" onclick="startDump()">开始 DUMP</button>
  </div>

  <div class="card" style="grid-column:1/-1">
    <h2>日志</h2>
    <div id="log" class="log"></div>
  </div>
</div>
<script>
let packages=[], selected="";
function q(id){return document.getElementById(id)}
function enc(v){return encodeURIComponent(v)}
async function connect(){
  q('dev').textContent='连接中...';
  const r=await fetch('/api/devices?adb='+enc(q('adb').value)+'&host='+enc(q('host').value));
  const j=await r.json();
  q('dev').textContent=j.ok ? (j.devices.length ? '已连接: '+j.devices.join(', ') : '无设备') : '失败: '+j.error;
  pollLogs();
}
async function refreshApps(){
  const r=await fetch('/api/apps?adb='+enc(q('adb').value)+'&host='+enc(q('host').value));
  const j=await r.json();
  if(!j.ok){alert(j.error); return;}
  packages=j.packages||[]; renderPackages(); pollLogs();
}
function renderPackages(){
  const s=q('search').value.toLowerCase();
  const box=q('packages'); box.innerHTML='';
  packages.filter(p=>p.toLowerCase().includes(s)).forEach(p=>{
    const d=document.createElement('div'); d.className='pkg'+(p===selected?' sel':''); d.textContent=p;
    d.onclick=()=>{selected=p; q('pkg').value=p; renderPackages();};
    box.appendChild(d);
  });
}
async function startDump(){
  const body={adbPath:q('adb').value,hostPort:q('host').value,suCommand:q('su').value,package:q('pkg').value,waitSec:parseInt(q('wait').value||'4'),outputDir:q('out').value,mode:q('mode').value};
  const r=await fetch('/api/dump',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!j.ok){alert(j.error);}
  pollLogs();
}
async function pollLogs(){
  try{
    const r=await fetch('/api/logs'); const j=await r.json();
    q('dump').disabled=!!j.running; q('dump').textContent=j.running?'脱壳中...':'开始 DUMP';
    q('log').textContent=(j.logs||[]).join('\n'); q('log').scrollTop=q('log').scrollHeight;
    if(j.running) setTimeout(pollLogs, 1000);
  }catch(e){setTimeout(pollLogs, 2000)}
}
setInterval(pollLogs, 3000); pollLogs();
</script>
</body>
</html>`))

// keep strconv referenced in old Go toolchains that optimize imports differently
var _ = strconv.IntSize
