"""Documentation must use the real TUI, with explicit non-device fixtures."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("capture_tui", ROOT / "scripts/capture_tui.py")
PREVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIEW)


class TuiPreviewTests(unittest.TestCase):
    def test_rendered_views_are_current_deterministic_and_offline(self):
        with patch("subprocess.run", side_effect=AssertionError("No subprocesses allowed")):
            artifacts, config, state = PREVIEW.render_previews()
            again, _, _ = PREVIEW.render_previews()
        self.assertEqual(artifacts, again)
        self.assertEqual((state.processes, state.round, state.total, state.so_total, state.dry),
                         (2, 4, 8, 3, 1))
        self.assertEqual(config["mode"], "dex")
        self.assertTrue(config["watch"])
        self.assertFalse(config["relaxed"])
        for name, svg in artifacts.items():
            with self.subTest(name=name):
                ET.fromstring(svg)
                self.assertIn("DEMO", svg)
                self.assertIn("非真机捕获结果", svg)
                self.assertIn("com.example.demo", svg)
                self.assertNotIn(str(ROOT), svg)
                self.assertNotIn("cdnjs.cloudflare.com", svg)
                self.assertIn('lengthAdjust="spacingAndGlyphs"', svg)
                # Rich serializers may differ across supported dependency
                # versions; validate committed assets without pinning bytes.
                committed = (PREVIEW.DESTINATION / name).read_text(encoding="utf-8")
                ET.fromstring(committed)
                self.assertIn("DEMO", committed)
                self.assertIn("非真机捕获结果", committed)


if __name__ == "__main__":
    unittest.main()
