"""Submit-ready, complete Go MVS module graph; never updates or dismisses alerts.

This deliberately inventories all selected modules, including tools and tests,
not just imports reachable in a production GUI build. It does not execute them.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def json_stream(text):
    decoder = json.JSONDecoder()
    result = []
    while text.strip():
        text = text.lstrip()
        item, end = decoder.raw_decode(text)
        result.append(item)
        text = text[end:]
    return result


def resolved_manifest(modules, requirements, graph):
    """Convert MVS-selected versions, not every historical go.mod minimum."""
    selected = {}
    for module in modules:
        if module.get("Error") or module.get("Replace"):
            raise ValueError("Incomplete graph or replacement: refuse partial submission")
        if module.get("Main"):
            continue
        name, version = module["Path"], module.get("Version", "")
        if not version or name in selected:
            raise ValueError("Missing version or duplicate selected module")
        selected[name] = module
    required = {item["Path"]: item for item in requirements}
    if not selected or not required.keys() <= selected.keys():
        raise ValueError("Selected graph must include every go.mod requirement")
    # go.mod requirements are minimums. Go's authoritative MVS output may
    # select a newer version, so do not replace it with the declared minimum.
    urls = {name: f"pkg:golang/{quote(name, safe='/')}@{quote(item['Version'], safe='')}"
            for name, item in selected.items()}
    children = {name: set() for name in selected}
    for line in graph.splitlines():
        parent, child = line.split()
        parent_name, _, parent_version = parent.partition("@")
        child_name = child.partition("@")[0]
        # Go's graph includes old minimum versions. Only selected parent
        # versions contribute edges; child edges resolve to the MVS version.
        if (parent_name in selected and child_name in selected
                and selected[parent_name]["Version"] == parent_version
                and parent_name != child_name):
            children[parent_name].add(urls[child_name])
    return {
        "name": "gui/go.mod",
        "file": {"source_location": "gui/go.mod"},
        "resolved": {
            urls[name]: {
                "package_url": urls[name],
                "relationship": "direct" if name in required and not required[name].get("Indirect") else "indirect",
                # Do not label the entire graph as runtime: it includes tools
                # and tests. Scope is intentionally left unspecified.
                "dependencies": sorted(children[name]),
            }
            for name in sorted(selected)
        },
    }


def run(*args, cwd=ROOT):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--default-branch", required=True)
    args = parser.parse_args()
    sha, ref = os.environ["GITHUB_SHA"], os.environ["GITHUB_REF"]
    repository = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or run("git", "rev-parse", "HEAD").strip() != sha:
        raise ValueError("Snapshot must describe the checked-out commit")
    if ref != f"refs/heads/{args.default_branch}":
        raise ValueError("Only the default branch may publish this dependency snapshot")
    if run("git", "status", "--porcelain", "--", "gui/go.mod", "gui/go.sum").strip():
        raise ValueError("Module inputs must match the checked-out commit")
    # Ignore inherited workspaces/GOFLAGS so this inventories this committed
    # module, not a developer's local workspace or a filtered build target.
    os.environ.update(GOWORK="off", GOFLAGS="-mod=readonly")
    go_cwd = ROOT / "gui"
    modules = json_stream(run("go", "list", "-m", "-json", "all", cwd=go_cwd))
    declared = json.loads(run("go", "mod", "edit", "-json", cwd=go_cwd))
    manifest = resolved_manifest(modules, declared.get("Require", []),
                                 run("go", "mod", "graph", cwd=go_cwd))
    # Detect a tool unexpectedly modifying module inputs during resolution.
    if run("git", "status", "--porcelain", "--", "gui/go.mod", "gui/go.sum").strip():
        raise ValueError("Module inputs changed while resolving the snapshot")
    snapshot = {
        "version": 0, "sha": sha, "ref": ref,
        "job": {"id": run_id, "correlator": "dependency-graph_go-modules_gui",
                "html_url": f"https://github.com/{repository}/actions/runs/{run_id}"},
        "detector": {"name": "nhdd-go-module-graph", "version": "1.0.0",
                     "url": f"https://github.com/{repository}/blob/{sha}/scripts/go_dependency_snapshot.py"},
        "scanned": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifests": {"gui/go.mod": manifest},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"Resolved {len(manifest['resolved'])} selected modules (including tools/tests)")


if __name__ == "__main__":
    main()
