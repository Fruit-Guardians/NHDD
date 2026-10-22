"""Export real Rich TUI views with deterministic fixtures, without using ADB.

Run from any directory: python scripts/capture_tui.py
The generated views illustrate the interface, not device capture results.
"""
import io
from pathlib import Path
import re
import runpy
from unittest.mock import patch
import xml.etree.ElementTree as ET

from rich.cells import cell_len
from rich.console import Console, CONSOLE_SVG_FORMAT
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.text import Text

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "NHDD-cpp-modular/assets/screenshots"
LABEL = "界面演示 / DEMO · 合成应用与日志，非真机捕获结果"
APPS = ["com.example.demo", "com.example.native", "com.example.reader"]
LOG_LINES = (
    "Resolved com.example.demo -> 2 processes",
    "round 1: +3 new (DEX=3, SO=1, dry=0/3)",
    "round 2: +2 new (DEX=5, SO=2, dry=0/3)",
    "round 3: +3 new (DEX=8, SO=3, dry=0/3)",
    "round 4: +0 new (DEX=8, SO=3, dry=1/3)",
)


def render_previews():
    """Return SVG artifacts and configuration exercised by the setup preview."""
    namespace = runpy.run_path(str(ROOT / "nhdd_tui.py"))
    ui = namespace["render_dashboard"].__globals__
    output = {}

    def forbidden(*args, **kwargs):
        raise AssertionError("Documentation previews must not access devices or subprocesses")

    def recorded_console():
        console = Console(record=True, width=120, height=40, file=io.StringIO(),
                          force_terminal=True, legacy_windows=False, color_system="truecolor")
        console.print(Text(LABEL, style="bold yellow"))
        console.print()
        return console

    def export(console, title):
        # Keep the export self-contained. GitHub image rendering does not need
        # remote font requests, and local CJK fallbacks must retain cell widths.
        template = re.sub(r"    @font-face \{\{.*?    \}\}\n", "", CONSOLE_SVG_FORMAT,
                          flags=re.DOTALL)
        template = template.replace("Fira Code, monospace", 'Consolas, "Noto Sans Mono CJK SC", "Microsoft YaHei", monospace')
        svg = console.export_svg(title=title, unique_id=title.replace(" ", "-"),
                                 code_format=template)
        ET.register_namespace("", "http://www.w3.org/2000/svg")
        root = ET.fromstring(svg)
        for element in root.iter("{http://www.w3.org/2000/svg}text"):
            if "textLength" in element.attrib:
                # Rich uses len(text) here, which compresses double-width CJK
                # glyphs. Match the same terminal-cell positions as its layout.
                element.set("textLength", f"{cell_len(element.text or '') * 12.2:g}")
                element.set("lengthAdjust", "spacingAndGlyphs")
        ET.indent(root)
        svg = ET.tostring(root, encoding="unicode")
        return "\n".join(line.rstrip() for line in svg.splitlines()) + "\n"

    # Call the existing selection/configuration functions, including real Rich
    # prompts. Only their input and application inventory are synthetic.
    console = recorded_console()
    answers = iter(("1", "dex", "n", "y", "3", "120", "n", "n", "n", "n",
                    "n", "su -c", "./nhdd_output"))

    def fixture_input(*args, **kwargs):
        answer = next(answers)
        console.print(Text(answer))  # echo what a user would type
        return answer

    prompt_ask, int_ask, confirm_ask = Prompt.ask, IntPrompt.ask, Confirm.ask
    with patch.dict(ui, console=console, get_third_party_apps=lambda: list(APPS),
                    adb=forbidden, adb_shell=forbidden), \
            patch.object(ui["subprocess"], "Popen", side_effect=forbidden), \
            patch("builtins.input", side_effect=fixture_input), \
            patch.object(Prompt, "ask", side_effect=lambda *a, **k: prompt_ask(*a, console=console, **k)), \
            patch.object(IntPrompt, "ask", side_effect=lambda *a, **k: int_ask(*a, console=console, **k)), \
            patch.object(Confirm, "ask", side_effect=lambda *a, **k: confirm_ask(*a, console=console, **k)):
        package = ui["select_app"]()
        config = ui["gather_config"]()
    if next(answers, None) is not None:
        raise AssertionError("Unused fixture answers: update the preview for the current TUI")
    output["tui-setup.svg"] = export(console, "NHDD TUI Setup")

    # Feed fixture log lines through the production parser, then use exactly
    # the renderer used by Live during a real watch run.
    state = ui["DashState"]()
    for line in LOG_LINES:
        ui["_parse_line"](line, state)
    console = recorded_console()
    console.print(ui["render_dashboard"](state, package))
    output["tui.svg"] = export(console, "NHDD TUI Watch")
    return output, config, state


def main():
    artifacts, _, _ = render_previews()
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for name, svg in artifacts.items():
        (DESTINATION / name).write_text(svg, encoding="utf-8", newline="\n")
        print(f"Generated assets/screenshots/{name} (synthetic preview; no ADB)")


if __name__ == "__main__":
    main()
