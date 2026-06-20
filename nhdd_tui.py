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

Options:
    -o, --output DIR   本地输出目录(默认 ./nhdd_output)。填绝对路径可避免随运行目录漂移。
"""

import os
import re
import sys
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
DEVICE_DUMP_DIR = "/data/local/tmp/nhdd_tui"
VERSION = "8.0"
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

TAGLINE = "No-Hook DEX/SO Dumper   ·   无注入 · 反检测 · 一二代壳"


# ---------------------------------------------------------------------------
# Logo
# ---------------------------------------------------------------------------
def show_logo():
    logo_text = Text(LOGO.rstrip(), style="bold cyan")
    tag = Text(TAGLINE, style="dim")
    ver = Text(f"v{VERSION}", style="bold yellow")
    console.print()
    console.print(Align.center(logo_text))
    console.print(Align.center(Text.assemble(ver, "   ", tag)))
    console.print()


# ---------------------------------------------------------------------------
# ADB helpers (复用 nhdd_ctrl.py 逻辑)
# ---------------------------------------------------------------------------
def adb(*args, timeout=60):
    """执行 adb 命令,返回 (rc, stdout+stderr)。"""
    cmd = f"{ADB} " + " ".join(args)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def adb_shell(cmd, timeout=60):
    return adb("shell", f'"{cmd}"', timeout=timeout)


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


def check_nhdd_binary():
    rc, out = adb_shell(f"ls {NHDD_BIN}")
    return "nhdd" in out


def push_nhdd_if_missing(local_nhdd=None):
    """若设备上没有 nhdd,尝试从本地推一个(若提供)。"""
    if check_nhdd_binary():
        return True
    if local_nhdd and os.path.exists(local_nhdd):
        console.print(f"[yellow]设备上无 nhdd,从本地推送 {local_nhdd}[/]")
        adb("push", local_nhdd, NHDD_BIN)
        adb_shell(f"chmod 755 {NHDD_BIN}")
        return check_nhdd_binary()
    return False


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
    mode = Prompt.ask("Dump 模式", choices=["dex", "so", "all"], default="dex")

    # 强对抗壳冷启动时反内存读取检测更活跃,会秒杀刚重启的进程 → 冷启动扫常 0 DEX。
    # 扫「已稳定运行的进程」命中率最高。默认不重启。
    restart = Confirm.ask("重启 app 再扫?(强对抗壳建议[否],直接扫当前进程)", default=False)
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
    }
    if use_watch:
        cfg["dry_limit"] = IntPrompt.ask("  连续几轮无新 DEX 自动停 (dry K)", default=3)
        cfg["max_seconds"] = IntPrompt.ask("  最大运行秒数", default=120)
    stealth = Confirm.ask("启用 stealth(区域间延时,降低被检测概率)", default=False)
    cfg["stealth"] = stealth
    if stealth:
        cfg["region_delay_ms"] = IntPrompt.ask("  区域延时 (ms)", default=2)
    stealth2 = Confirm.ask("启用 stealth2(process_vm_readv 反检测,二代壳推荐)", default=False)
    cfg["stealth2"] = stealth2
    relaxed = Confirm.ask("启用 relaxed(宽松 DEX 验证,不依赖 magic,二代壳推荐)", default=False)
    cfg["relaxed"] = relaxed
    anon = Confirm.ask("启用 anon(仅扫描匿名内存映射)", default=False)
    cfg["anon"] = anon
    su = Prompt.ask("SU 命令(读其他进程内存需要 root:留空=普通shell 或 su -c / ksud -c / kp -c)",
                    default="su -c")
    cfg["su_cmd"] = su.strip()
    out = Prompt.ask("本地输出目录", default="./nhdd_output")
    # 去除首尾空白和可能的成对引号(用户手输时容易带上 "" 或 '')
    out = out.strip().strip('"').strip("'").strip()
    cfg["output_dir"] = out or "./nhdd_output"
    return cfg


# ---------------------------------------------------------------------------
# 执行:watch 实时进度面板
# ---------------------------------------------------------------------------
def build_nhdd_cmd(pkg, cfg):
    mode_arg = {"dex": "--dex", "so": "--so", "all": "--all"}[cfg["mode"]]
    parts = [NHDD_BIN, pkg, DEVICE_DUMP_DIR, mode_arg]
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
        self.total = 0
        self.dedup = 0
        self.dry = 0
        self.dry_limit = 3
        self.processes = 0
        self.done = False
        self.dex_files = 0
        self.so_files = 0
        self.last_lines = deque(maxlen=12)
        self.finished_summary = ""


RE_ROUND = re.compile(r"round\s+(\d+):\s*\+(\d+)\s+new unique DEX\s+\(total=(\d+),\s*dry=(\d+)/(\d+)")
RE_PROC = re.compile(r"Resolved.*->\s*(\d+)\s+process")
RE_DONE = re.compile(r"Done\..*DEX unique=(\d+).*dedup_skipped=(\d+).*SO=(\d+)")
RE_DEXFILE = re.compile(r"^\[\+\]\s+DEX:")
RE_SOFILE = re.compile(r"^\[\+\]\s+SO:")


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
    full = f'{ADB} shell "{cmd}"'
    console.print(f"[4] 运行: [dim]{full}[/]\n")

    st = DashState()
    st.dry_limit = cfg["dry_limit"] if cfg["watch"] else 1

    proc = subprocess.Popen(full, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
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
    m = RE_ROUND.search(line)
    if m:
        st.round = int(m.group(1))
        st.new_this = int(m.group(2))
        st.total = int(m.group(3))
        st.dry = int(m.group(4))
        st.dry_limit = int(m.group(5))
        return
    m = RE_PROC.search(line)
    if m:
        st.processes = int(m.group(1))
        return
    m = RE_DONE.search(line)
    if m:
        st.total = int(m.group(1))
        st.dedup = int(m.group(2))
        st.so_files = int(m.group(3))
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
def pull_and_summarize(pkg, st: DashState, output_dir):
    local = os.path.join(output_dir, pkg)
    os.makedirs(local, exist_ok=True)
    # 防御:拉取前清空本地 dex/so 子目录的旧文件,避免上次同 app 结果残留合并进来。
    for sub, exts in (("dex", (".dex",)), ("so", (".so",))):
        sub_local = os.path.join(local, sub)
        if os.path.isdir(sub_local):
            for fn in os.listdir(sub_local):
                if any(fn.endswith(e) for e in exts):
                    try: os.remove(os.path.join(sub_local, fn))
                    except OSError: pass
    rc, out = adb("pull", f"{DEVICE_DUMP_DIR}/.", local + os.sep)
    pulled_ok = rc == 0

    # 统计本地文件
    dex_count = so_count = 0
    total_size = 0
    for root, _, files in os.walk(local):
        for f in files:
            p = os.path.join(root, f)
            total_size += os.path.getsize(p)
            if f.endswith(".dex"):
                dex_count += 1
            elif f.endswith(".so"):
                so_count += 1
    size_mb = total_size / 1024 / 1024

    tbl = Table(title="脱壳结果", box=box.DOUBLE, border_style="green")
    tbl.add_column("项目", style="bold")
    tbl.add_column("值", style="cyan")
    tbl.add_row("应用", pkg)
    tbl.add_row("扫描轮次", str(st.round))
    tbl.add_row("解析进程数", str(st.processes))
    tbl.add_row("DEX 文件", f"{dex_count} (去重后唯一)")
    tbl.add_row("SO 文件", str(st.so_files))
    tbl.add_row("总大小", f"{size_mb:.1f} MB")
    tbl.add_row("本地路径", local)
    console.print()
    console.print(tbl)
    if not pulled_ok:
        console.print(f"[yellow]注意: adb pull 返回非零,文件可能仍在设备 {DEVICE_DUMP_DIR}[/]")
    return local


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

    # nhdd 二进制
    local_nhdd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nhdd")
    if not check_nhdd_binary():
        if os.path.exists(local_nhdd):
            push_nhdd_if_missing(local_nhdd)
        if not check_nhdd_binary():
            console.print(f"[red]设备上无 {NHDD_BIN}。请先编译并 adb push。[/]")
            sys.exit(1)
    console.print(f"[green]nhdd 就绪:[/] {NHDD_BIN}")

    pkg_arg = next((a for a in args if not a.startswith("-")), None)
    pkg = select_app(pkg_arg)
    if not pkg:
        console.print("[yellow]未选择应用,退出。[/]")
        return
    console.print(f"\n[bold]已选择:[/] [cyan]{pkg}[/]\n")

    cfg = gather_config()
    if output_override:
        cfg["output_dir"] = output_override
        console.print(f"[green]输出目录(命令行指定):[/] {output_override}")

    st = run_dump(pkg, cfg)
    if st.procs == 0:
        console.print("[yellow]未扫描到任何进程(目标未运行或被杀),跳过拉取。[/]")
        console.print("[yellow]建议:先手动打开 app 再扫,或在配置里开启「重启 app 再扫」。[/]")
        return
    pull_and_summarize(pkg, st, cfg["output_dir"])
    console.print("\n[bold green]全部完成。[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断。[/]")
        sys.exit(130)
