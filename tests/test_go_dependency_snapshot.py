"""Complete selected modules, including unused/tool modules, must be submitted."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("snapshot", ROOT / "scripts/go_dependency_snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.modules = [{"Path": "gui", "Main": True},
                        {"Path": "example.org/desktop", "Version": "v1.0.0"},
                        {"Path": "example.org/build-tool", "Version": "v2.0.0"},
                        {"Path": "golang.org/x/crypto", "Version": "v0.58.0"}]
        self.require = [{"Path": "example.org/desktop", "Version": "v1.0.0"},
                        {"Path": "example.org/build-tool", "Version": "v2.0.0", "Indirect": True}]

    def test_all_modules_and_mvs_edges_including_tool_dependencies(self):
        manifest = SNAPSHOT.resolved_manifest(self.modules, self.require,
            "example.org/build-tool@v2.0.0 golang.org/x/crypto@v0.33.0\n"
            "example.org/build-tool@v1.0.0 example.org/not-selected@v1.0.0\n")
        resolved = manifest["resolved"]
        self.assertEqual(len(resolved), 3)
        self.assertEqual(manifest["file"]["source_location"], "gui/go.mod")
        self.assertEqual(resolved["pkg:golang/example.org/build-tool@v2.0.0"]["dependencies"],
                         ["pkg:golang/golang.org/x/crypto@v0.58.0"])
        self.assertEqual(resolved["pkg:golang/example.org/desktop@v1.0.0"]["relationship"], "direct")
        self.assertNotIn("v0.33.0", str(resolved))
        self.assertTrue(all("scope" not in item for item in resolved.values()))

    def test_rejects_partial_error_replaced_duplicate_or_unversioned_graph(self):
        invalid = [self.modules[:2], [],
                   self.modules + [{"Path": "bad", "Error": "unresolved"}],
                   self.modules + [{"Path": "local", "Replace": {"Dir": "/local"}}],
                   self.modules + [self.modules[-1]],
                   self.modules + [{"Path": "missing-version"}]]
        for modules in invalid:
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                SNAPSHOT.resolved_manifest(modules, self.require, "")

    def test_keeps_selected_version_above_declared_minimum_and_decodes_stream(self):
        minimum = [{"Path": "example.org/desktop", "Version": "v0.1.0"}]
        manifest = SNAPSHOT.resolved_manifest(self.modules, minimum, "")
        self.assertIn("pkg:golang/example.org/desktop@v1.0.0", manifest["resolved"])
        self.assertEqual(SNAPSHOT.json_stream(' {"a":1}\n {"b":2} \n'), [{"a": 1}, {"b": 2}])


if __name__ == "__main__":
    unittest.main()
