#!/usr/bin/env python3
"""
NHDD 终端版 (TUI) — No-Hook DEX/SO Dumper Terminal Interface

交互式终端界面:logo → 设备 → 应用列表 → 配置 → watch 实时进度 → 结果统计。
复用设备端 nhdd 二进制 + ADB,展示层用 rich。

Usage:
    python nhdd_tui.py                 # 交互式选 app
    python nhdd_tui.py com.example.app # 直接指定包名
    python nhdd_tui.py --logo          # 只打印 logo
    python nhdd_tui.py com.example.app -o D:\\dumps   # 指定输出目录(绝对路径最佳)
    python nhdd_tui.py com.example.app --cli --repack-dex-only --repack-quick

Options:
    -o, --output DIR       本地输出目录(默认 ./nhdd_output)。填绝对路径可避免随运行目录漂移。
    --repack               非 APK 模式下也强制生成 jadx 分析 APK。
    --no-repack            APK 模式下跳过自动重打包。
    --repack-dex-only      只打包 classes*.dex，最快，适合 jadx 分析。
    --repack-full          保留原 APK 结构后替换 DEX。
    --repack-quick         重打包阶段只做 DEX header 快检，速度最快。
    --repack-deep          重打包阶段做深度 DEX 校验，较慢。
    --repack-report        生成 dex_manifest / duplicate_classes 报告，较慢。
    --replace-so           full repack 时把修复后的 SO 替换回 APK。
"""

import os
import re
import sys
import shlex
import time
import subprocess
import threading
from collections import deque

# 强制 stdout/stderr 为 UTF-8,确保方块字 logo 在 Windows (GBK) 控制台正确显示
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.live import Live
    from rich.align import Align
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
except ImportError:
    sys.stderr.write(
        "[!] 缺少依赖 rich。请先安装:  pip install rich\n"
        "[!] 或:  python -m pip install rich\n"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
ADB = os.environ.get("NHDD_ADB", "adb")
NHDD_BIN = "/data/local/tmp/nhdd"
DEVICE_DUMP_DIR = "/data/local/tmp/.cache/nhdd"
VERSION = "9.0-cpp-class"
_device_serial = None  # set after device selection
console = Console()

# 方块大字 logo (figlet ansi_shadow 字体,权威生成,确保 NHDD 正确)
LOGO = r"""
███╗   ██╗██╗  ██╗██████╗ ██████╗
████╗  ██║██║  ██║██╔══██╗██╔══██╗
██╔██╗ ██║███████║██║  ██║██║  ██║
██║╚██╗██║██╔══██║██║  ██║██║  ██║
██║ ╚████║██║  ██║██████╔╝██████╔╝
╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═════╝
"""

TAGLINE = "No-Hook DEX/SO/JNI Dumper   ·   C++类重构 · 无注入 · 反检测"
AUTHORS = "漫宿骄盛、weixiao"
REPO_URL = "https://github.com/mansujiaosheng/NHDD"
DISCLAIMER = "免责声明：本工具仅用于合法授权的安全研究、逆向分析与自有应用调试。请勿用于未授权访问、绕过商业授权、窃取代码或数据、侵犯第三方权益等行为。"


# ---------------------------------------------------------------------------
# Logo
# ---------------------------------------------------------------------------
def show_logo():
    logo_text = Text(LOGO.rstrip(), style="bold cyan")
    tag = Text(TAGLINE, style="dim")
    ver = Text(f"v{VERSION}", style="bold yellow")
    authors = Text(f"Authors: {AUTHORS}", style="dim cyan")
    repo = Text(f"Repo: {REPO_URL}", style="dim")
    disclaimer = Text(DISCLAIMER, style="dim yellow")
    console.print()
    console.print(Align.center(logo_text))
    console.print(Align.center(Text.assemble(ver, "   ", tag)))
    console.print(Align.center(authors))
    console.print(Align.center(repo))
    console.print(Align.center(disclaimer))
    console.print()


# ---------------------------------------------------------------------------
# ADB helpers (复用 nhdd_ctrl.py 逻辑)
# ---------------------------------------------------------------------------
def adb(*args, timeout=60):
    """执行 adb 命令,返回 (rc, stdout+stderr)。list 调用,支持多设备。"""
    cmd = shlex.split(ADB)
    if _device_serial:
        cmd += ["-s", _device_serial]
    cmd += list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout + r.stderr).strip()


def adb_shell(cmd, timeout=60):
    """在设备 shell 中执行命令。list 调用,不嵌套引号。"""
    adb_cmd = shlex.split(ADB)
    if _device_serial:
        adb_cmd += ["-s", _device_serial]
    adb_cmd += ["shell", cmd]
    r = subprocess.run(adb_cmd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout + r.stderr).strip()


def check_device():
    """返回已连接设备列表。"""
    rc, out = adb("devices")
    devices = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def select_device(devices):
    """选择设备并设置全局 _device_serial。单设备自动选,多设备交互选。"""
    global _device_serial
    if len(devices) == 1:
        _device_serial = devices[0]
        console.print(f"[green]设备:[/] {_device_serial}")
        return _device_serial
    if not devices:
        return None

    console.print("\n[bold yellow]检测到多个设备:[/]")
    for i, d in enumerate(devices):
        rc, info = adb("shell", "getprop ro.product.model")
        model = info.strip() if rc == 0 else "unknown"
        console.print(f"  [{i+1}] {d} ({model})")

    choice = IntPrompt.ask("选择设备序号", default=1)
    if 1 <= choice <= len(devices):
        _device_serial = devices[choice - 1]
        console.print(f"[green]已选择:[/] {_device_serial}")
        return _device_serial
    return None


def check_nhdd_binary():
    rc, out = adb_shell(f"ls {NHDD_BIN}")
    return "nhdd" in out


def push_nhdd_if_missing(local_nhdd=None):
    """若设备上没有 nhdd,尝试从本地推。始终确保可执行。"""
    if not local_nhdd or not os.path.exists(local_nhdd):
        return check_nhdd_binary()
    # Always push to ensure latest binary and correct permissions
    adb("push", local_nhdd, NHDD_BIN)
    adb_shell(f"chmod 755 {NHDD_BIN}")
    return check_nhdd_binary()


def get_third_party_apps():
    rc, out = adb_shell("pm list packages -3")
    apps = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            apps.append(line[8:])
    return sorted(apps)


def get_running_pids(pkg):
    rc, out = adb_shell(f"pidof {pkg}")
    return [p for p in out.split() if p.isdigit()]


# ---------------------------------------------------------------------------
# 交互:选 app
# ---------------------------------------------------------------------------
def select_app(default_pkg=None):
    """分页 + 搜索选择第三方 app。"""
    if default_pkg:
        return default_pkg
    console.print(Rule("加载应用列表", style="cyan"))
    apps = get_third_party_apps()
    if not apps:
        console.print("[red]未取到第三方应用列表,请检查设备连接。[/]")
        return None

    page_size = 25
    page = 0
    search = ""
    while True:
        shown = [a for a in apps if search.lower() in a.lower()] if search else apps
        total_pages = max(1, (len(shown) + page_size - 1) // page_size)
        page = min(page, total_pages - 1)
        start = page * page_size
        end = min(start + page_size, len(shown))

        tbl = Table(title=f"第三方应用 ({len(shown)} 个 · 页 {page+1}/{total_pages})",
                    box=box.ROUNDED, show_lines=False)
        tbl.add_column("#", style="dim", width=5)
        tbl.add_column("包名", style="cyan")
        for i in range(start, end):
            tbl.add_row(str(i + 1), shown[i])
        console.print(tbl)

        console.print(
            "\n[dim]输入:序号选择 | 关键词搜索 | n=下一页 p=上一页 | q=退出[/]"
        )
        choice = Prompt.ask("[bold]选择", default="").strip()
        if not choice:
            continue
        if choice in ("q", "quit", "exit"):
            return None
        if choice == "n":
            page = min(page + 1, total_pages - 1)
            continue
        if choice == "p":
            page = max(page - 1, 0)
            continue
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(shown):
                return shown[idx]
            console.print("[red]序号超出范围[/]")
        else:
            search = choice
            page = 0


# ---------------------------------------------------------------------------
# 交互:配置
# ---------------------------------------------------------------------------
def gather_config():
    console.print(Rule("脱壳配置", style="cyan"))
    mode = Prompt.ask("Dump 模式", choices=["apk", "dex", "so", "jnimap"], default="apk")
    if not mode or mode not in ("apk", "dex", "so", "jnimap"):
        mode = "apk"

    # 实测重启后命中率更高 → 默认重启
    restart = Confirm.ask("重启 app 再扫?", default=True)
    use_watch = Confirm.ask("启用 watch 监听(推荐,捕获懒加载 DEX)", default=True)
    cfg = {
        "mode": mode,
        "restart": restart,
        "watch": use_watch,
        "dry_limit": 3,
        "max_seconds": 120,
        "max_rounds": 60,
        "stealth": False,
        "stealth2": False,
        "relaxed": False,
        "anon": False,
        "region_delay_ms": 0,
        "su_cmd": "",
        "output_dir": "./nhdd_output",
        # JNIMAP (独立模式 or 叠加模式)
        "jnimap": False,       # 叠加模式下的 checkbox
        "jni_lib": "",
        "jni_min": 2,
        # repack_apk_fast.py 对接参数。默认走 dex-only + quick，避免 APK 模式尾部卡很久。
        "repack_enabled": mode == "apk",
        "repack_dex_only": True,
        "repack_quick": True,
        "repack_report": False,
        "repack_keep_all_dex": False,
        "repack_strict_classes": False,
        "repack_replace_so": False,
        "repack_drop_unmatched_so": False,
    }
    if use_watch:
        cfg["dry_limit"] = IntPrompt.ask("  连续几轮无新 DEX 自动停 (dry K)", default=3)
        cfg["max_seconds"] = IntPrompt.ask("  最大运行秒数", default=120)
    stealth = Confirm.ask("启用 stealth(区域间延时,降低被检测概率)", default=True)
    cfg["stealth"] = stealth
    if stealth:
        cfg["region_delay_ms"] = IntPrompt.ask("  区域延时 (ms)", default=2)
    stealth2 = Confirm.ask("启用 stealth2(process_vm_readv 反检测,二代壳推荐)", default=True)
    cfg["stealth2"] = stealth2
    relaxed = Confirm.ask("启用 relaxed(宽松 DEX 验证,不依赖 magic,二代壳推荐)", default=True)
    cfg["relaxed"] = relaxed
    anon = Confirm.ask("启用 anon(仅扫描匿名内存映射)", default=False)
    cfg["anon"] = anon

    # JNIMAP: 独立模式 or 叠加到 DEX/SO 模式
    if mode == "jnimap":
        cfg["jnimap"] = True
        jni_lib = Prompt.ask("  过滤库名(留空=全部扫描, 如 libnative-lib.so)", default="")
        cfg["jni_lib"] = jni_lib.strip()
        if not jni_lib.strip():
            cfg["jni_min"] = IntPrompt.ask("  最小连续 JNI 条目数", default=2)
    else:
        jnimap_default = mode in ("apk", "so")
        use_jnimap = Confirm.ask(
            "启用 JNIMAP(Native方法扫描, 叠加到当前模式)" +
            (" [dump SO 时推荐]" if jnimap_default else ""),
            default=jnimap_default)
        cfg["jnimap"] = use_jnimap
        if use_jnimap:
            jni_lib = Prompt.ask("  过滤库名(留空=全部扫描, 如 libnative-lib.so)", default="")
            cfg["jni_lib"] = jni_lib.strip()
            if not jni_lib.strip():
                cfg["jni_min"] = IntPrompt.ask("  最小连续 JNI 条目数", default=2)

    su = Prompt.ask("SU 命令(读其他进程内存需要 root:留空=普通shell 或 su -c / ksud -c / kp -c)",
                    default="su -c")
    cfg["su_cmd"] = su.strip()
    if mode == "apk":
        console.print(Rule("重打包配置", style="cyan"))
        cfg["repack_enabled"] = Confirm.ask("Dump 后自动生成 jadx 分析 APK?", default=True)
        if cfg["repack_enabled"]:
            cfg["repack_dex_only"] = Confirm.ask("使用 dex-only 快速打包?", default=True)
            cfg["repack_quick"] = Confirm.ask("重打包阶段使用 DEX 快检?", default=True)
            cfg["repack_report"] = Confirm.ask("生成 dex_manifest/duplicate_classes 报告?", default=False)
            if not cfg["repack_dex_only"]:
                cfg["repack_replace_so"] = Confirm.ask("full repack 时替换 SO?", default=False)

    out = Prompt.ask("本地输出目录", default="./nhdd_output")
    # 去除首尾空白和可能的成对引号(用户手输时容易带上 "" 或 '')
    out = out.strip().strip('"').strip("'").strip()
    cfg["output_dir"] = out or "./nhdd_output"
    return cfg


# ---------------------------------------------------------------------------
# 执行:watch 实时进度面板
# ---------------------------------------------------------------------------
def build_nhdd_cmd(pkg, cfg):
    if cfg["mode"] == "jnimap":
        jni_lib = cfg.get("jni_lib", "")
        if jni_lib:
            # 指定了库名 → 用 --analyze-so 一键模式 (maps + dump + fnptrs)
            parts = [NHDD_BIN, pkg, DEVICE_DUMP_DIR, "--analyze-so", jni_lib]
        else:
            parts = [NHDD_BIN, pkg, DEVICE_DUMP_DIR, "--jnimap"]
        jni_min = cfg.get("jni_min")
        if jni_min:
            parts += ["--jni-min", str(jni_min)]
    else:
        mode_arg = {"dex": "--dex", "so": "--so", "apk": "--all"}[cfg["mode"]]
        parts = [NHDD_BIN, pkg, DEVICE_DUMP_DIR, mode_arg]
        if cfg.get("jnimap"):
            jni_lib = cfg.get("jni_lib", "")
            if jni_lib:
                parts += ["--jnimap", "--jni-lib", jni_lib, "--save-maps"]
            else:
                parts += ["--jnimap"]
            jni_min = cfg.get("jni_min")
            if jni_min:
                parts += ["--jni-min", str(jni_min)]
    if cfg["watch"]:
        parts += ["--watch", str(cfg["dry_limit"]),
                  "--max-seconds", str(cfg["max_seconds"]),
                  "--max-rounds", str(cfg["max_rounds"])]
    if cfg["stealth"]:
        parts += ["--stealth"]
        if cfg["region_delay_ms"]:
            parts += ["--region-delay", str(cfg["region_delay_ms"])]
    if cfg.get("stealth2"):
        parts += ["--stealth2"]
    if cfg.get("relaxed"):
        parts += ["--relaxed"]
    if cfg.get("anon"):
        parts += ["--anon"]
    nhdd_cmd = " ".join(parts)
    # 包装到 root shell
    if cfg["su_cmd"]:
        su = cfg["su_cmd"].strip()
        if "{cmd}" in su:
            return f"{su.replace('{cmd}', repr(nhdd_cmd))}"
        return f"{su} {repr(nhdd_cmd)}"
    return nhdd_cmd


# 进度面板状态
class DashState:
    def __init__(self):
        self.round = 0
        self.new_this = 0
        self.total = 0       # DEX unique count
        self.so_total = 0    # SO count from round log
        self.jni_total = 0   # JNI count
        self.dedup = 0
        self.dry = 0
        self.dry_limit = 3
        self.processes = 0
        self.done = False
        self.dex_files = 0
        self.so_files = 0
        self.last_lines = deque(maxlen=12)
        self.all_lines = []  # 完整日志用于写入 log.txt
        self.finished_summary = ""


# 兼容新旧 nhdd 输出格式:
# v9.0: round N: +X new (DEX=Y, SO=Z, dry=a/b)
# v9.0: round N: +X new unique (DEX=Y, SO=Z, dry=a/b)
# v8.0: round N: +X new unique DEX (total=Y, dry=a/b)
RE_ROUND_V9 = re.compile(
    r"round\s+(\d+):\s*\+(\d+)\s+new\s*(?:unique\s+)?\(DEX=(\d+),\s*SO=(\d+),\s*dry=(\d+)/(\d+)"
)
RE_ROUND_OLD = re.compile(
    r"round\s+(\d+):\s*\+(\d+)\s+new unique DEX\s+\(total=(\d+),\s*dry=(\d+)/(\d+)"
)
RE_PROC = re.compile(r"Resolved.*->\s*(\d+)\s+process")
# v9.0: Done. rounds=N, procs=N, DEX=N (N hits, N dedup), SO=N, JNI=N
# v8.0: Done..DEX unique=N..dedup_skipped=N..SO=N
RE_DONE_V9 = re.compile(
    r"Done\..*rounds=(\d+).*procs=(\d+).*DEX=(\d+)\s*\((\d+)\s*hits.*?(\d+)\s*dedup\).*SO=(\d+).*JNI=(\d+)"
)
RE_DONE_OLD = re.compile(r"Done\..*DEX unique=(\d+).*dedup_skipped=(\d+).*SO=(\d+)")
RE_DEXFILE = re.compile(r"^\[\+\]\s+DEX")
RE_SOFILE = re.compile(r"^\[\+\]\s+SO")  # match [+] SO: and [+] SO(memelf):


def render_dashboard(st: DashState, pkg: str):
    """构造实时面板:返回一个纵向叠加的 Group(main + 日志)。"""
    # 统计行
    stat = Table.grid(padding=(0, 2))
    stat.add_column(style="bold")
    stat.add_column()
    stat.add_row("目标", f"[cyan]{pkg}[/]")
    stat.add_row("进程数", f"[yellow]{st.processes}[/]")
    stat.add_row("当前轮次", f"[magenta]{st.round}[/]")
    stat.add_row("本轮新增", f"[green]+{st.new_this}[/]")
    stat.add_row("累计唯一 DEX", f"[bold green]{st.total}[/]")
    stat.add_row("累计 SO", f"[bold cyan]{st.so_total}[/]")
    if st.jni_total:
        stat.add_row("累计 JNI", f"[bold magenta]{st.jni_total}[/]")
    stat.add_row("去重跳过", f"[dim]{st.dedup}[/]")
    dry_color = "red" if st.dry else "yellow"
    stat.add_row("稳定集 dry", f"[{dry_color}]{st.dry}/{st.dry_limit}[/]")

    # 进度条 (dry 计数占满即停)
    bar_len = 30
    filled = min(st.dry, st.dry_limit) * bar_len // max(st.dry_limit, 1)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = min(st.dry, st.dry_limit) * 100 // max(st.dry_limit, 1)
    progress_line = f"[{bar}] {pct}%  (连续 dry 轮: {st.dry}/{st.dry_limit})"

    # 日志
    log_text = Text("\n".join(st.last_lines) if st.last_lines else "(等待 nhdd 输出...)",
                    style="dim")
    log_panel = Panel(log_text, title="[bold]nhdd 实时日志[/]", border_style="blue",
                      box=box.ROUNDED, height=16)

    title = "[bold cyan]NHDD watch 监听中[/]" if not st.done else "[bold green]NHDD 完成[/]"
    main = Table.grid(padding=(1, 1))
    main.add_row(stat, Text(progress_line, style="bold"))
    main_panel = Panel(
        Align.center(main),
        title=title, border_style="cyan", box=box.DOUBLE,
        padding=(1, 2),
    )
    from rich.console import Group
    return Group(main_panel, log_panel)


def adb_shell_root(cmd, su_cmd=""):
    """以 root 执行 shell 命令(nhdd 用 su 写的文件需 root 才能删)。"""
    su = (su_cmd or "").strip()
    if not su:
        return adb_shell(cmd)
    if "{cmd}" in su:
        return adb_shell(su.replace("{cmd}", repr(cmd)))
    return adb_shell(f"{su} {cmd!r}")


def run_dump(pkg, cfg):
    """执行 dump,带 Live 进度面板。cfg['restart'] 控制是否重启 app。"""
    # 清理:nhdd 用 su 写的文件是 root 属主,普通 shell 的 rm 会 Permission denied
    # → 残留跨次累积,污染下一次输出。故带 su 清理。
    console.print(Rule("准备", style="cyan"))
    adb_shell_root(f"rm -rf {DEVICE_DUMP_DIR}; mkdir -p {DEVICE_DUMP_DIR}", cfg.get("su_cmd"))

    if cfg.get("restart"):
        adb_shell(f"am force-stop {pkg}")
        console.print(f"[1] 已停止 {pkg}")
        adb_shell(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")
        console.print(f"[2] 已启动 {pkg}")
        time.sleep(3)  # 给壳时间解密加载
    else:
        console.print(f"[1] 跳过重启(扫当前进程 — 强对抗壳推荐)")

    pids = get_running_pids(pkg)
    console.print(f"[3] 当前进程: {pids if pids else '(无)'}")
    if not pids:
        console.print("[yellow]目标未运行。建议:先手动打开 app,或配置里开启重启。[/]")
        return DashState()

    cmd = build_nhdd_cmd(pkg, cfg)
    adb_cmd = shlex.split(ADB)
    if _device_serial:
        adb_cmd += ["-s", _device_serial]
    adb_cmd += ["shell", cmd]
    full = f'{ADB}{" -s "+_device_serial if _device_serial else ""} shell "{cmd}"'
    console.print(f"[4] 运行: [dim]{full}[/]\n")

    st = DashState()
    st.dry_limit = cfg["dry_limit"] if cfg["watch"] else 1

    proc = subprocess.Popen(adb_cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1,
                            encoding="utf-8", errors="replace")
    # nhdd 进度在 stderr,结果文件行在 stdout
    out_th = threading.Thread(target=_pump, args=(proc.stdout, st, False), daemon=True)
    out_th.start()

    with Live(render_dashboard(st, pkg), console=console, refresh_per_second=8,
              screen=False) as live:
        for line in iter(proc.stderr.readline, ""):
            _parse_line(line.rstrip(), st)
            live.update(render_dashboard(st, pkg), refresh=True)
        proc.wait()
        out_th.join(timeout=2)
        st.done = True
        live.update(render_dashboard(st, pkg), refresh=True)

    console.print()
    if st.finished_summary:
        console.print(Panel(st.finished_summary, title="[bold green]结果[/]",
                            border_style="green", box=box.ROUNDED))
    return st


def _parse_line(line, st: DashState):
    if not line:
        return
    st.last_lines.append(line)
    st.all_lines.append(line)
    # v9.0 format: round N: +X new (DEX=Y, SO=Z, dry=a/b)
    m = RE_ROUND_V9.search(line)
    if m:
        st.round = int(m.group(1))
        st.new_this = int(m.group(2))
        st.total = int(m.group(3))
        st.so_total = int(m.group(4))
        st.dry = int(m.group(5))
        st.dry_limit = int(m.group(6))
        return
    # v8.0 format: round N: +X new unique DEX (total=Y, dry=a/b)
    m = RE_ROUND_OLD.search(line)
    if m:
        st.round = int(m.group(1))
        st.new_this = int(m.group(2))
        st.total = int(m.group(3))
        st.so_total = 0  # 旧格式无 SO
        st.dry = int(m.group(4))
        st.dry_limit = int(m.group(5))
        return
    m = RE_PROC.search(line)
    if m:
        st.processes = int(m.group(1))
        return
    # v9.0: Done. rounds=N, procs=N, DEX=N (N hits, N dedup), SO=N, JNI=N
    m = RE_DONE_V9.search(line)
    if m:
        st.round = int(m.group(1))
        st.processes = int(m.group(2))
        st.total = int(m.group(3))
        st.dedup = int(m.group(5))
        st.so_total = int(m.group(6))
        st.jni_total = int(m.group(7))
        st.finished_summary = (line.replace("Done.", "完成").strip())
        return
    # v8.0: Done..DEX unique=N..dedup_skipped=N..SO=N
    m = RE_DONE_OLD.search(line)
    if m:
        st.total = int(m.group(1))
        st.dedup = int(m.group(2))
        st.so_total = int(m.group(3))
        st.finished_summary = (line.replace("Done.", "完成").strip())
        return
    if RE_DEXFILE.match(line):
        st.dex_files += 1
        return
    if RE_SOFILE.match(line):
        st.so_files += 1


def _pump(stream, st: DashState, is_stderr):
    for line in iter(stream.readline, ""):
        _parse_line(line.rstrip(), st)


# ---------------------------------------------------------------------------
# 结果:pull + 统计
# ---------------------------------------------------------------------------
def auto_classify_and_fix(dex_dir, local_dir):
    """对齐 GUI FixDexDirectory:一段式 校验→重建→重校验→修头+校验和。

    文件处置与 GUI 一致:过小/非DEX 移 bad/,不可重建移 bad/,否则修头+校验和。
    统计口径与 GUI 一致:OK(含已修复)/修复/损坏已隔离。
    """
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "fix_dex", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fix_dex_checksum.py"))
        fix_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fix_mod)
    except Exception as e:
        console.print(f"[yellow]无法加载 fix_dex_checksum: {e}[/]")
        return

    stats = fix_mod.fix_directory_aligned(dex_dir)
    # stats: {total, ok, fixed, bad, bad_files}
    if stats["total"] == 0:
        return

    ct = Table(title="DEX 校验分类", box=box.ROUNDED, border_style="cyan")
    ct.add_column("类别", style="bold")
    ct.add_column("数量", style="cyan")
    ct.add_column("说明", style="dim")
    ct.add_row("[green]OK[/]", str(stats["ok"]),
               "通过所有校验,可直接反编译(含已修复)")
    ct.add_row("[yellow]修复[/]", str(stats["fixed"]),
               "map_list 已重建 / header+校验和已修复")
    ct.add_row("[red]损坏已隔离[/]", str(stats["bad"]),
               "过小/非DEX 已移至 bad/,不可重建已移至 bad/")
    ct.add_row("[bold]总计[/]", str(stats["total"]), "")
    console.print()
    console.print(ct)

    if stats["bad"]:
        console.print(f"\n[red]损坏文件:[/] {', '.join(stats['bad_files'])}")
    if stats["bad"] == 0:
        console.print("\n[bold green]全部 DEX 通过校验！[/]")

    # 写日志
    log_path = os.path.join(local_dir, "log.txt")
    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write("DEX Validation Report\n")
            lf.write(f"{'='*40}\n")
            lf.write(f"Total: {stats['total']}  OK: {stats['ok']}  "
                     f"Fixed: {stats['fixed']}  Bad: {stats['bad']}\n\n")
            if stats["bad_files"]:
                lf.write("Bad files:\n")
                for name in stats["bad_files"]:
                    lf.write(f"  {name}\n")
    except OSError:
        pass


def auto_classify_and_fix_so(so_dir, local_dir, apk_path=None):
    """Carrier 模式: 以原 APK SO 为骨架, 覆盖 dump RX 代码段."""

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "fix_so", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fix_so.py"))
        fix_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fix_mod)
    except Exception as e:
        console.print(f"[yellow]无法加载 fix_so: {e}[/]")
        return

    carrier_mode = bool(apk_path and os.path.exists(apk_path))
    if carrier_mode:
        stats = fix_mod.fix_directory_carrier(so_dir, apk_path)
    else:
        stats = fix_mod.fix_directory_aligned(so_dir)
    if stats["total"] == 0:
        return

    title = "SO Carrier 修复" if carrier_mode else "SO 结构修复"
    ct = Table(title=title, box=box.ROUNDED, border_style="magenta")
    ct.add_column("类别", style="bold")
    ct.add_column("数量", style="cyan")
    ct.add_column("说明", style="dim")
    if carrier_mode:
        ct.add_row("[green]已处理[/]", str(stats["ok"]),
                   "结构以原 APK SO 为准, dump RX 段已尝试覆盖")
        ct.add_row("[yellow]代码已合入[/]", str(stats["fixed"]),
                   "至少有 RX 页被覆盖到原始 SO")
    else:
        ct.add_row("[green]OK[/]", str(stats["ok"]),
                   "PHT/DYNAMIC/SHT 已校验或修复，可用于 IDA/Ghidra")
        ct.add_row("[yellow]修复[/]", str(stats["fixed"]),
                   "p_offset / dynamic / section header 已调整")
    ct.add_row("[red]损坏[/]", str(stats["bad"]),
               "过小/无ELF结构, 已移至 bad/")
    ct.add_row("[bold]总计[/]", str(stats["total"]), "")
    console.print()
    console.print(ct)

    if stats["bad"]:
        console.print(f"\n[red]无法修复:[/] {', '.join(stats['bad_files'])}")
    if stats["bad"] == 0:
        if carrier_mode:
            console.print("\n[bold green]SO Carrier 处理完成: 请结合 IDA/Ghidra 验证代码段覆盖质量[/]")
        else:
            console.print("\n[bold green]SO 结构修复完成: 请结合 IDA/Ghidra 验证代码段覆盖质量[/]")

    # 追加到同一日志
    log_path = os.path.join(local_dir, "log.txt")
    try:
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"\nSO Validation Report\n")
            lf.write(f"{'='*40}\n")
            lf.write(f"Total: {stats['total']}  OK: {stats['ok']}  "
                     f"Fixed: {stats['fixed']}  Bad: {stats['bad']}\n\n")
            if stats["bad_files"]:
                lf.write("Bad files:\n")
                for name in stats["bad_files"]:
                    lf.write(f"  {name}\n")
    except OSError:
        pass


def pull_and_summarize(pkg, st: DashState, output_dir, su_cmd="", mode="dex"):
    local = os.path.join(output_dir, pkg)
    os.makedirs(local, exist_ok=True)
    # 防御:拉取前清空本地 dex/so/jnimap 子目录的旧文件,避免上次同 app 结果残留合并进来。
    for sub, exts in (("dex", (".dex",)), ("so", (".so", ".bin")), ("jnimap", (".jsonl",)), ("maps", (".txt",))):
        sub_local = os.path.join(local, sub)
        if os.path.isdir(sub_local):
            for fn in os.listdir(sub_local):
                if any(fn.endswith(e) for e in exts):
                    try: os.remove(os.path.join(sub_local, fn))
                    except OSError: pass
    rc, out = adb("pull", f"{DEVICE_DUMP_DIR}/.", local + os.sep)
    pulled_ok = rc == 0

    # 拉取成功后清理设备端 dump 文件
    if pulled_ok:
        console.print("[dim]清理设备端 dump 文件...[/]")
        adb_shell_root(f"rm -rf {DEVICE_DUMP_DIR}", su_cmd)
        console.print("[dim]设备端 dump 文件已清理[/]")

    # 统计本地文件
    dex_count = so_count = jni_count = 0
    total_size = 0
    for root, _, files in os.walk(local):
        for f in files:
            p = os.path.join(root, f)
            total_size += os.path.getsize(p)
            if f.endswith(".dex"):
                dex_count += 1
            elif f.endswith(".so"):
                so_count += 1
            elif f.endswith(".jsonl"):
                jni_count += 1
    size_mb = total_size / 1024 / 1024

    tbl = Table(title="脱壳结果", box=box.DOUBLE, border_style="green")
    tbl.add_column("项目", style="bold")
    tbl.add_column("值", style="cyan")
    tbl.add_row("应用", pkg)
    tbl.add_row("扫描轮次", str(st.round))
    tbl.add_row("解析进程数", str(st.processes))
    tbl.add_row("DEX 文件", f"{dex_count} (去重后唯一)")
    tbl.add_row("SO 文件", f"{so_count} 本地 / {st.so_files} 日志")
    if jni_count:
        tbl.add_row("JNI map", f"{jni_count} jsonl / {st.jni_total} 条目")
    tbl.add_row("总大小", f"{size_mb:.1f} MB")
    tbl.add_row("本地路径", local)
    console.print()
    console.print(tbl)

    # 写 nhdd 实时日志到 log.txt（在校验结果之前）
    log_path = os.path.join(local, "log.txt")
    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write("=== NHDD 实时日志 ===\n\n")
            if st and st.all_lines:
                for line in st.all_lines:
                    lf.write(line + "\n")
            lf.write("\n")
    except OSError:
        pass

    # 自动修复 + 分类（会追加到 log.txt）
    dex_dir = os.path.join(local, "dex")
    if os.path.isdir(dex_dir) and dex_count > 0:
        auto_classify_and_fix(dex_dir, local)
    so_dir = os.path.join(local, "so")
    if os.path.isdir(so_dir) and so_count > 0:
        # 尝试拉取原 APK 做 Carrier 修复 (以原 APK SO 为骨架覆盖 dump RX 段)
        apk_for_so = None
        if mode in ("apk", "so"):
            repack_tmp = os.path.join(local, "repack")
            apk_for_so = pull_original_apk_for_repack(pkg, repack_tmp)
        auto_classify_and_fix_so(so_dir, local, apk_for_so)
    if not pulled_ok:
        console.print(f"[yellow]注意: adb pull 返回非零,文件可能仍在设备 {DEVICE_DUMP_DIR}[/]")
    return local



# ---------------------------------------------------------------------------
# Repack: 对接 scripts/repack_apk_fast.py
# ---------------------------------------------------------------------------
def _parse_pm_path_output(out):
    """从 pm path 输出里取 APK 路径，优先 base.apk。"""
    paths = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):])
    for p in paths:
        if p.endswith("/base.apk"):
            return p
    return paths[0] if paths else None


def pull_original_apk_for_repack(pkg, output_dir):
    """按 TUI 当前选择的设备拉取原 APK，避免旧实现忽略 -s 设备序列号。"""
    os.makedirs(output_dir, exist_ok=True)
    rc, out = adb_shell(f"pm path {pkg}")
    if rc != 0:
        console.print(f"[red]pm path 失败:[/] {out}")
        return None
    remote_apk = _parse_pm_path_output(out)
    if not remote_apk:
        console.print(f"[red]无法获取 {pkg} 的 APK 路径[/]")
        return None
    local_apk = os.path.join(output_dir, "original.apk")
    rc, out = adb("pull", remote_apk, local_apk, timeout=180)
    if rc != 0:
        console.print(f"[red]adb pull APK 失败:[/] {out}")
        return None
    console.print(f"  已拉取: {local_apk}")
    return local_apk


def resolve_repack_script():
    """优先使用快版脚本；兼容 scripts/ 下或 TUI 同目录下放置。"""
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "scripts", "repack_apk_fast.py"),
        os.path.join(base, "repack_apk_fast.py"),
        os.path.join(base, "scripts", "repack_apk.py"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def run_repack_flow(pkg, cfg, force=False):
    """生成 jadx 分析 APK。默认使用 repack_apk_fast.py 的 dex-only + quick 路径。"""
    if not (force or cfg.get("mode") == "apk" or cfg.get("repack_enabled")):
        return
    if cfg.get("mode") == "apk" and not cfg.get("repack_enabled", True):
        console.print("[yellow]已跳过自动重打包。[/]")
        return

    pkg_local = os.path.join(cfg["output_dir"], pkg)
    repack_dir = os.path.join(pkg_local, "repack")
    os.makedirs(repack_dir, exist_ok=True)
    script = resolve_repack_script()
    if not os.path.exists(script):
        console.print(f"[red]未找到重打包脚本:[/] {script}")
        console.print("[yellow]请把 repack_apk_fast.py 放到 scripts/ 目录，或放到 nhdd_tui.py 同目录。[/]")
        return

    use_fast = os.path.basename(script) == "repack_apk_fast.py"
    dump_dir = pkg_local
    output_name = f"{pkg}_dexonly.apk" if cfg.get("repack_dex_only", True) else f"{pkg}_repacked.apk"
    output_apk = os.path.join(repack_dir, output_name)

    console.print("[bold]生成 jadx 分析 APK...[/]")
    console.print(f"[dim]repack script: {script}[/]")

    cmd = [sys.executable, script]
    need_original_apk = not cfg.get("repack_dex_only", True) or not use_fast
    apk_path = None

    if cfg.get("repack_dex_only", True) and use_fast:
        # 最快路径：不拉原 APK，不解压原 APK，只生成 classes*.dex 容器。
        cmd += [pkg, dump_dir, "--dex-only"]
    else:
        console.print("[bold dim]拉取原 APK...[/]")
        apk_path = pull_original_apk_for_repack(pkg, repack_dir)
        if not apk_path or not os.path.exists(apk_path):
            console.print("[red]拉取原 APK 失败，跳过 repack。[/]")
            return
        # SO carrier 仍然在 full repack 前做，保持原 TUI 语义。
        so_dir = os.path.join(pkg_local, "so")
        if os.path.isdir(so_dir):
            auto_classify_and_fix_so(so_dir, pkg_local, apk_path)
        cmd += ["--from-local", apk_path, dump_dir]

    cmd += ["-o", output_apk, "--work-dir", repack_dir]

    if use_fast:
        if cfg.get("repack_quick", True):
            cmd.append("--quick-dex-check")
        if cfg.get("repack_report", False):
            cmd.append("--report")
        if cfg.get("repack_keep_all_dex", False):
            cmd.append("--keep-all-dex")
        if cfg.get("repack_strict_classes", False):
            cmd.append("--strict-classes")
    if cfg.get("repack_replace_so", False) and not cfg.get("repack_dex_only", True):
        cmd.append("--replace-so")
    if cfg.get("repack_drop_unmatched_so", False) and not cfg.get("repack_dex_only", True):
        cmd.append("--drop-unmatched-so")

    console.print(f"[dim]repack cmd: {' '.join(shlex.quote(x) for x in cmd)}[/]")
    try:
        subprocess.run(cmd, check=True)
        console.print(f"[bold green]jadx APK:[/] {output_apk}")
    except Exception as e:
        console.print(f"[red]repack 失败: {e}[/]")
    console.print()

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if "--logo" in args:
        show_logo()
        return
    if "-h" in args or "--help" in args:
        print(__doc__)
        return

    # 解析 -o/--output:指定本地输出目录(绝对路径最佳,避免随运行目录漂移)
    output_override = None
    cli_mode = False
    repack_flag = False
    no_repack_flag = False
    repack_dex_only_override = None
    repack_quick_override = None
    repack_report_flag = False
    repack_keep_all_dex_flag = False
    repack_strict_classes_flag = False
    repack_replace_so_flag = False
    repack_drop_unmatched_so_flag = False
    su_cmd_override = None
    filtered = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--output") and i + 1 < len(args):
            output_override = args[i + 1]
            i += 2
            continue
        if a.startswith("--output="):
            output_override = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--cli":
            cli_mode = True
            i += 1
            continue
        if a in ("--su-cmd", "--su") and i + 1 < len(args):
            su_cmd_override = args[i + 1]
            i += 2
            continue
        if a.startswith("--su-cmd="):
            su_cmd_override = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--repack":
            repack_flag = True
            i += 1
            continue
        if a == "--no-repack":
            no_repack_flag = True
            i += 1
            continue
        if a == "--repack-dex-only":
            repack_dex_only_override = True
            i += 1
            continue
        if a == "--repack-full":
            repack_dex_only_override = False
            i += 1
            continue
        if a == "--repack-quick":
            repack_quick_override = True
            i += 1
            continue
        if a == "--repack-deep":
            repack_quick_override = False
            i += 1
            continue
        if a == "--repack-report":
            repack_report_flag = True
            i += 1
            continue
        if a == "--repack-keep-all-dex":
            repack_keep_all_dex_flag = True
            i += 1
            continue
        if a == "--repack-strict-classes":
            repack_strict_classes_flag = True
            i += 1
            continue
        if a == "--replace-so":
            repack_replace_so_flag = True
            i += 1
            continue
        if a == "--drop-unmatched-so":
            repack_drop_unmatched_so_flag = True
            i += 1
            continue
        filtered.append(a)
        i += 1
    args = filtered

    show_logo()

    # 设备
    console.print(Rule("设备", style="cyan"))
    devices = check_device()
    if not devices:
        console.print("[red]未发现已连接设备。请检查 adb / USB 调试 / NHDD_ADB。[/]")
        sys.exit(1)
    console.print(f"[green]已连接设备:[/] {', '.join(devices)}")
    if not select_device(devices):
        console.print("[red]设备选择失败。[/]")
        sys.exit(1)
    console.print()

    # nhdd 二进制: 优先查找 C++ OOP 版本, 其次旧版本
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "NHDD-cpp-modular", "src", "nhdd"),
        os.path.join(base_dir, "nhdd"),
    ]
    local_nhdd = None
    for c in candidates:
        if os.path.exists(c):
            local_nhdd = c
            break
    if local_nhdd:
        push_nhdd_if_missing(local_nhdd)
    elif not check_nhdd_binary():
        console.print(f"[red]设备上无 {NHDD_BIN} 且本地未找到 nhdd 二进制。请先编译: make -C NHDD-cpp-modular android[/]")
        sys.exit(1)
    console.print(f"[green]nhdd 就绪:[/] {NHDD_BIN}")

    pkg_arg = next((a for a in args if not a.startswith("-")), None)
    pkg = select_app(pkg_arg)
    if not pkg:
        console.print("[yellow]未选择应用,退出。[/]")
        return
    console.print(f"\n[bold]已选择:[/] [cyan]{pkg}[/]\n")

    if cli_mode:
        # CLI 非交互模式:使用默认最佳配置(stealth2+relaxed,适合二代壳)
        cfg = {
            "mode": "apk",
            "restart": False,
            "watch": True,
            "dry_limit": 3,
            "max_seconds": 120,
            "max_rounds": 60,
            "stealth": True,
            "stealth2": True,
            "relaxed": True,
            "anon": False,
            "jnimap": True,
            "jni_lib": "",
            "jni_min": 2,
            "region_delay_ms": 2,
            "su_cmd": su_cmd_override or "kp -c",
            "output_dir": "./nhdd_output",
            "repack_enabled": True,
            "repack_dex_only": True,
            "repack_quick": True,
            "repack_report": False,
            "repack_keep_all_dex": False,
            "repack_strict_classes": False,
            "repack_replace_so": False,
            "repack_drop_unmatched_so": False,
        }
        console.print("[bold]CLI 模式:[/] stealth2 + relaxed + stealth (二代壳推荐)")
    else:
        cfg = gather_config()

    if output_override:
        cfg["output_dir"] = output_override
        console.print(f"[green]输出目录(命令行指定):[/] {output_override}")
    if su_cmd_override:
        cfg["su_cmd"] = su_cmd_override
        console.print(f"[green]SU 命令:[/] {su_cmd_override}")

    if repack_flag:
        cfg["repack_enabled"] = True
    if no_repack_flag:
        cfg["repack_enabled"] = False
    if repack_dex_only_override is not None:
        cfg["repack_dex_only"] = repack_dex_only_override
    if repack_quick_override is not None:
        cfg["repack_quick"] = repack_quick_override
    if repack_report_flag:
        cfg["repack_report"] = True
    if repack_keep_all_dex_flag:
        cfg["repack_keep_all_dex"] = True
    if repack_strict_classes_flag:
        cfg["repack_strict_classes"] = True
    if repack_replace_so_flag:
        cfg["repack_replace_so"] = True
    if repack_drop_unmatched_so_flag:
        cfg["repack_drop_unmatched_so"] = True

    st = run_dump(pkg, cfg)
    if st.processes == 0:
        console.print("[yellow]未扫描到任何进程(目标未运行或被杀),跳过拉取。[/]")
        console.print("[yellow]建议:先手动打开 app 再扫,或在配置里开启「重启 app 再扫」。[/]")
        return
    pull_and_summarize(pkg, st, cfg["output_dir"], cfg.get("su_cmd", ""), cfg["mode"])

    # APK 模式 / --repack: 对接 repack_apk_fast.py。
    run_repack_flow(pkg, cfg, force=repack_flag)

    console.print("\n[bold green]全部完成。[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断。[/]")
        sys.exit(130)
