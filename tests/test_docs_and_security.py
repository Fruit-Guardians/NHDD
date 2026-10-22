"""Regression floors complement, but never replace, live vulnerability scans."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def version(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError("Expected a pinned stable version")
    return tuple(map(int, match.groups()))


class DocsAndSecurityTests(unittest.TestCase):
    def test_go_security_floors_and_shared_tool_graph(self):
        text = (ROOT / "gui/go.mod").read_text(encoding="utf-8")
        for module, minimum in {"golang.org/x/crypto": "0.58.0",
                                "golang.org/x/net": "0.61.0",
                                "github.com/labstack/echo/v4": "4.16.0"}.items():
            found = re.search(r"(?m)^\s*" + re.escape(module) + r"\s+(v\S+)", text)
            self.assertIsNotNone(found, module)
            self.assertGreaterEqual(version(found.group(1)), version(minimum))
        self.assertIn("tool github.com/wailsapp/wails/v2/cmd/wails", text)
        script = (ROOT / "NHDD-cpp-modular/release/build-desktop.ps1").read_text(encoding="utf-8")
        self.assertIn("& $Go tool wails build", script)
        self.assertNotIn("& $Wails build", script)

    def test_npm_security_floors(self):
        packages = json.loads((ROOT / "gui/frontend/package-lock.json").read_text())["packages"]
        floors = {"vite": "7.3.7", "postcss": "8.5.23", "nanoid": "3.3.18",
                  "source-map-js": "1.2.2", "esbuild": "0.25.0"}
        for name, minimum in floors.items():
            installed = packages["node_modules/" + name]["version"]
            self.assertGreaterEqual(version(installed), version(minimum), name)

    def test_concise_readmes_and_local_links(self):
        for name in ("README.md", "README.zh-CN.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertLessEqual(len(text.splitlines()), 110)
            self.assertIn("~~~mermaid", text)
            self.assertIn("assets/screenshots/gui.png", text)
            self.assertIn("assets/screenshots/tui.svg", text)
            self.assertIn("assets/screenshots/tui-setup.svg", text)
            self.assertIn("python nhdd_tui.py", text)
            for relative in re.findall(r'(?:\]\(|src=")(\./[^)"#]+)', text):
                self.assertTrue((ROOT / relative).is_file(), relative)

    def test_baseline_is_traceable_and_sdk_doc_is_portable(self):
        data = json.loads((ROOT / "NHDD-cpp-modular/docs/dependency-advisories.json").read_text())
        self.assertEqual(len(data["advisories"]), 39)
        self.assertEqual(sum(a["severity"] == "critical" for a in data["advisories"]), 7)
        text = (ROOT / "NHDD-cpp-modular/docs/releasing.md").read_text(encoding="utf-8")
        self.assertIn("$env:ANDROID_NDK_ROOT", text)
        self.assertFalse(re.search(r"[A-Za-z]:[/\\]", text))


if __name__ == "__main__":
    unittest.main()
