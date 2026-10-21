"""Public metadata regressions; never encode the removed identities here."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_publication", ROOT / "scripts/audit_publication.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PublicMetadataTests(unittest.TestCase):
    def test_tui_metadata_and_syntax(self):
        tree = ast.parse((ROOT / "nhdd_tui.py").read_text(encoding="utf-8"))
        assignments = {node.targets[0].id: ast.literal_eval(node.value)
                       for node in tree.body if isinstance(node, ast.Assign)
                       and isinstance(node.targets[0], ast.Name)
                       and isinstance(node.value, ast.Constant)}
        self.assertNotIn("AUTHORS", assignments)
        self.assertEqual(assignments["REPO_URL"], "https://github.com/Fruit-Guardians/NHDD")

    def test_tui_display_only_commands(self):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "COLUMNS": "240",
               "NHDD_ADB": str(ROOT / "tests/no-adb-for-metadata-test")}
        for option in ("--logo", "--version", "-v", "--help"):
            with self.subTest(option=option):
                result = subprocess.run([sys.executable, str(ROOT / "nhdd_tui.py"), option],
                                        cwd=ROOT, env=env, capture_output=True, encoding="utf-8", timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Authors:", result.stdout)
                self.assertNotIn("作者：", result.stdout)
                if option != "--help":
                    self.assertIn("https://github.com/Fruit-Guardians/NHDD", result.stdout)

    def test_gui_and_readmes(self):
        config = json.loads((ROOT / "gui/wails.json").read_text(encoding="utf-8"))
        self.assertNotIn("author", config)
        self.assertEqual(config["info"]["companyName"], "NHDD contributors")
        for path in ("gui/frontend/src/App.vue", "README.md", "README.zh-CN.md"):
            text = (ROOT / path).read_text(encoding="utf-8")
            self.assertFalse(audit.AUTHOR_FIELD.search(text), path)
            self.assertIn("https://github.com/Fruit-Guardians/NHDD", text)

    def test_redaction_and_credential_detection(self):
        token = "ghp_" + "A" * 36
        hits = audit.inspect(token.encode(), "sample.txt", "test")
        self.assertEqual(hits[0]["category"], "credential_pattern")
        self.assertNotIn(token, json.dumps(hits))
        key = "-----" + "BEGIN PRIVATE KEY" + "-----"
        self.assertTrue(audit.inspect(key.encode(), "sample.txt", "test"))
        self.assertTrue(audit.inspect(b"", ".env", "test"))
        self.assertEqual(audit.inspect(b"", ".env.example", "test"), [])

    def test_new_guards_do_not_reintroduce_private_literals(self):
        for path in ("scripts/audit_publication.py", "tests/test_public_metadata.py"):
            self.assertEqual(audit.inspect((ROOT / path).read_bytes(), path, "test"), [])

    def test_private_file_ignore_rules(self):
        private = (".env", ".env.local", "local.keystore", "device.log", "id_ed25519")
        for path in private:
            self.assertEqual(subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT).returncode, 0)
        for path in (".env.example", ".env.sample", "LICENSE"):
            self.assertEqual(subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT).returncode, 1)

    def test_home_paths_and_third_party_attribution(self):
        for prefix in ("C:" + "/Users/", "/mnt/c/" + "Users/", "/" + "home/", "/" + "Users/"):
            hits = audit.inspect((prefix + "example-person/sdk").encode(), "sample.txt", "test")
            self.assertTrue(any(h["category"] == "personal_home_path" for h in hits))
        self.assertEqual(audit.inspect(b'"author": "Third-party contributor"',
                                     "gui/frontend/wailsjs/runtime/package.json", "test"), [])
        self.assertEqual(audit.inspect(b"Copyright 2026 NHDD contributors", "LICENSE", "test"), [])

    def test_gui_release_build_flags(self):
        script = (ROOT / "NHDD-cpp-modular/release/build-desktop.ps1").read_text(encoding="utf-8")
        self.assertIn("build -trimpath -ldflags '-s -w -buildid=' -m", script)
        self.assertIn("$env:GOFLAGS='-buildvcs=false'", script)
        self.assertIn("-trimpath=true", script)
        self.assertIn("THIRD-PARTY/GO/", script)


if __name__ == "__main__":
    unittest.main()
