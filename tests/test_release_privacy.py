import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("audit_release", ROOT / "scripts/audit_release.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ReleasePrivacyTests(unittest.TestCase):
    def test_binary_encodings_and_redaction(self):
        private = "synthetic-private-marker"
        for encoding in ("utf-8", "utf-16le", "utf-16be"):
            hits = audit.inspect_payload(private.encode(encoding), "gui.exe", [private])
            self.assertTrue(hits)
            self.assertNotIn(private, str(hits))

    def test_paths_credentials_and_urls(self):
        values = ["C:" + "/Users/" + "synthetic-person/source.go",
                  "github.com/" + "synthetic-person/NHDD",
                  "ghp_" + "A" * 36]
        for value in values:
            for encoding in ("utf-8", "utf-16le", "utf-16be"):
                self.assertTrue(audit.inspect_payload(value.encode(encoding), "app.exe", []))
        self.assertEqual(audit.inspect_payload(b"https://github.com/Fruit-Guardians/NHDD", "README.md", []), [])

    def test_prefixed_source_metadata_and_notices(self):
        self.assertTrue(audit.inspect_payload(b'AUTHORS = "synthetic"', "NHDD-v1-source/nhdd_tui.py", []))
        self.assertEqual(audit.inspect_payload(b'"author": "Third-party contributor"',
                         "gui/frontend/wailsjs/runtime/package.json", []), [])

    def test_zip_is_read_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.zip"
            with zipfile.ZipFile(path, "w") as package:
                package.writestr("../escape", b"test")
                package.writestr("safe/README.md", b"safe")
            self.assertEqual(audit.inspect_asset(path, [])[0]["category"], "unsafe_archive_entry")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_contract_report_redacts_build_roots(self):
        spec = importlib.util.spec_from_file_location("contract_compare", ROOT / "tests/contract/compare.py")
        compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(compare)
        private = str(ROOT) + os.sep + "tests/example.c"
        cleaned = compare.public_report(private + "\n" + str(Path.home()) + os.sep + "sdk")
        self.assertNotIn(str(ROOT), cleaned)
        self.assertNotIn(str(Path.home()), cleaned)
        self.assertIn("<repo>", cleaned)
        self.assertIn("<home>", cleaned)


if __name__ == "__main__":
    unittest.main()
