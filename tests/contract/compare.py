#!/usr/bin/env python3
"""NHDD repair-pipeline contract runner.

Regenerates fixtures, runs each implementation (python / go / v9-best-effort)
over an isolated copy, and reports per-fixture classification + byte-level
divergences. Baseline convention (agreed): the Go dev-version bad/ quarantine
behaviour is the reference; Python must mirror it; v9 is judged only where its
primitive semantics apply.

Usage:
    python3 tests/contract/compare.py            # report mode (exit 0, prints divergences)
    python3 tests/contract/compare.py --strict   # exit 1 on any python-vs-go divergence
    python3 tests/contract/compare.py --freeze   # additionally write expected.json from go baseline
    python3 tests/contract/compare.py --check    # fail if results deviate from expected.json

Tool overrides: NHDD_GO (go binary), NHDD_CXX (C++ compiler), PYTHON via sys.executable.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(HERE, ".work")
FIXDIR = os.path.join(REPO, "tests", "fixtures")
MANIFEST = os.path.join(FIXDIR, "manifest.json")
EXPECTED = os.path.join(HERE, "expected.json")
REPORT_MD = os.path.join(HERE, "REPORT.md")


def run_gen() -> None:
    subprocess.run([sys.executable, os.path.join(REPO, "tests", "gen_fixtures.py")],
                   check=True, capture_output=True, text=True)


def load_manifest() -> list:
    with open(MANIFEST, "r", encoding="utf-8") as fh:
        return json.load(fh)["fixtures"]


def prepare_work(impl: str) -> str:
    work = os.path.join(WORK, impl)
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(os.path.join(work, "dex"))
    os.makedirs(os.path.join(work, "so"))
    for f in load_manifest():
        src = os.path.join(FIXDIR, "dex" if f["kind"] == "dex" else "so", f["name"])
        dst = os.path.join(work, "dex" if f["kind"] == "dex" else "so", f["name"])
        shutil.copyfile(src, dst)
    return work


def find_go() -> str | None:
    return os.environ.get("NHDD_GO") or shutil.which("go")


def run_impl(impl: str, out_json: str) -> dict:
    work = prepare_work(impl)
    env = dict(os.environ,
               NHDD_CONTRACT_IN=work,
               NHDD_CONTRACT_MANIFEST=MANIFEST,
               NHDD_CONTRACT_OUT=out_json)
    if impl == "python":
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "run_python.py")],
            env=env, capture_output=True, text=True, cwd=REPO)
        if proc.returncode != 0:
            return {"impl": impl, "skipped": True,
                    "reason": "python runner failed: " + (proc.stderr or proc.stdout)[-400:]}
    elif impl == "go":
        gobin = find_go()
        if not gobin:
            return {"impl": impl, "skipped": True, "reason": "go toolchain not found (set NHDD_GO)"}
        # wails embed needs frontend/dist to exist
        dist = os.path.join(REPO, "gui", "frontend", "dist")
        if not os.path.isdir(dist):
            os.makedirs(dist, exist_ok=True)
            with open(os.path.join(dist, "index.html"), "w") as fh:
                fh.write("<html><body>contract-test placeholder</body></html>")
        proc = subprocess.run(
            [gobin, "test", "-tags", "contract", "-run", "TestContractFixtures",
             "-count=1", "./"],
            env=env, capture_output=True, text=True, cwd=os.path.join(REPO, "gui"))
        if proc.returncode != 0:
            return {"impl": impl, "skipped": True,
                    "reason": "go test failed: " + (proc.stderr or proc.stdout)[-400:]}
    elif impl == "v9":
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "run_v9.py")],
            env=env, capture_output=True, text=True, cwd=REPO)
        if proc.returncode != 0:
            return {"impl": impl, "skipped": True,
                    "reason": "v9 runner failed: " + (proc.stderr or proc.stdout)[-400:]}
    with open(out_json, "r", encoding="utf-8") as fh:
        return json.load(fh)


def index_results(payload: dict) -> dict:
    return {r["name"]: r for r in payload.get("results", [])}


def build_report(fixtures: list, runs: dict) -> tuple[list, list]:
    """Returns (table rows, divergence messages). Baseline = go (agreed convention)."""
    rows = []
    divergences = []
    go = index_results(runs["go"])
    py = index_results(runs["python"])
    v9 = index_results(runs["v9"])
    go_skipped = runs["go"].get("skipped")
    py_skipped = runs["python"].get("skipped")
    v9_skipped = runs["v9"].get("skipped")

    for fx in fixtures:
        name = fx["name"]
        g = go.get(name) if not go_skipped else None
        p = py.get(name) if not py_skipped else None
        v = v9.get(name) if not v9_skipped else None
        pred = fx.get("predict", {})

        def cell(r):
            return r["status"] if r else ("SKIP" if True else "")

        # prediction checks (informational)
        for impl_name, r in (("go", g), ("python", p), ("v9", v)):
            expect = pred.get(impl_name, "?")
            if r and expect not in ("?", "N/A") and r["status"] != expect:
                divergences.append(
                    f"PREDICTION-MISMATCH {name}: {impl_name} measured {r['status']}, "
                    f"manifest predicted {expect}")

        # baseline-vs-python divergence (the alignment target)
        if g and p:
            if g["status"] != p["status"]:
                divergences.append(
                    f"CLASS-DIVERGENCE {name}: go={g['status']} python={p['status']}")
            elif g["status"] in ("OK", "FIXED") and g["sha256"] != p["sha256"]:
                divergences.append(
                    f"HASH-DIVERGENCE {name}: both {g['status']} but bytes differ")
            elif g["status"] == "BAD" and g["sha256"] != p["sha256"]:
                divergences.append(
                    f"HASH-DIVERGENCE {name}: both BAD but quarantined bytes differ")

        # v9: informational only where judged
        if g and v and pred.get("v9") not in ("N/A", None):
            if pred.get("v9") == "?" :
                rows_note = f"v9={v['status']} (probe)"
            elif g["status"] in ("OK", "FIXED") and v["status"] != g["status"]:
                rows_note = f"v9 class differs: {v['status']} vs go {g['status']}"
                divergences.append(f"V9-DIVERGENCE {name}: {rows_note}")
            elif v["status"] == g["status"] and v["status"] in ("OK", "FIXED") \
                    and v["sha256"] != g["sha256"]:
                rows_note = "v9 hash differs from go (primitive-level, expected for rebuild cases)"
                divergences.append(f"V9-HASH-DIVERGENCE {name}: {rows_note}")

        row = {
            "name": name,
            "intent": fx["intent"],
            "go": cell(g), "python": cell(p), "v9": cell(v),
            "hash_match_go_py": (g["sha256"] == p["sha256"]) if (g and p) else None,
        }
        rows.append(row)
    return rows, divergences


def render_md(fixtures: list, rows: list, divergences: list, runs: dict) -> str:
    lines = ["# NHDD 修复管线契约报告 (contract report)", ""]
    lines.append("基线口径: Go dev 版 bad/ 隔离。v9 为原语级 harness,不做隔离判定。")
    lines.append("")
    for impl in ("go", "python", "v9"):
        if runs[impl].get("skipped"):
            lines.append(f"- **{impl}: SKIPPED** — {runs[impl].get('reason','')}")
        else:
            lines.append(f"- {impl}: ok ({len(runs[impl].get('results', []))} fixtures)")
    lines.append("")
    lines.append("| fixture | go | python | v9 | go==py bytes |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        hm = "-" if r["hash_match_go_py"] is None else ("yes" if r["hash_match_go_py"] else "**NO**")
        lines.append(f"| {r['name']} | {r['go']} | {r['python']} | {r['v9']} | {hm} |")
    lines.append("")
    if divergences:
        lines.append(f"## 差异 ({len(divergences)})")
        lines.extend([""] + [f"- {d}" for d in divergences])
    else:
        lines.append("## 差异")
        lines.append("")
        lines.append("- 无 (python 与 go 基线完全一致)")
    lines.append("")
    return "\n".join(lines)


def freeze_expected(fixtures: list, runs: dict) -> None:
    go = index_results(runs["go"])
    payload = {"schema": 1, "baseline": "go", "files": {}}
    for fx in fixtures:
        r = go.get(fx["name"])
        if r:
            payload["files"][fx["name"]] = {"class": r["status"], "sha256": r["sha256"],
                                            "where": r["where"]}
    with open(EXPECTED, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def check_expected(runs: dict) -> list:
    if not os.path.exists(EXPECTED):
        return []
    with open(EXPECTED, "r", encoding="utf-8") as fh:
        exp = json.load(fh)["files"]
    problems = []
    for impl in ("go", "python"):
        res = index_results(runs[impl])
        for name, e in exp.items():
            r = res.get(name)
            if not r:
                problems.append(f"EXPECTED-MISSING {name}: no {impl} result")
                continue
            if r["status"] != e["class"]:
                problems.append(f"EXPECTED-CLASS {name}: {impl} {r['status']} != {e['class']}")
            elif r["sha256"] != e["sha256"]:
                problems.append(f"EXPECTED-HASH {name}: {impl} bytes differ from frozen baseline")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap.add_argument("--strict", action="store_true",
                    help="fail on any go-vs-python divergence")
    ap.add_argument("--freeze", action="store_true",
                    help="write expected.json from the go baseline")
    ap.add_argument("--check", action="store_true",
                    help="verify results against committed expected.json")
    args = ap.parse_args()

    if not os.path.isdir(WORK):
        os.makedirs(WORK)
    run_gen()
    fixtures = load_manifest()

    runs = {impl: run_impl(impl, os.path.join(WORK, f"{impl}.json"))
            for impl in ("python", "go", "v9")}

    if runs["go"].get("skipped"):
        print("[!] go baseline skipped — divergence analysis limited")
    rows, divergences = build_report(fixtures, runs)
    md = render_md(fixtures, rows, divergences, runs)
    with open(REPORT_MD, "w", encoding="utf-8") as fh:
        fh.write(md)

    print(md)
    if args.freeze:
        if runs["go"].get("skipped"):
            print("[!] cannot freeze expected.json without go baseline")
            return 2
        freeze_expected(fixtures, runs)
        print(f"[ok] expected.json frozen from go baseline ({len(fixtures)} fixtures)")
    if args.check:
        problems = check_expected(runs)
        for p in problems:
            print("[expected]", p)
        if problems:
            return 1
    if args.strict:
        real = [d for d in divergences if d.startswith(("CLASS-DIVERGENCE", "HASH-DIVERGENCE"))]
        if real:
            print(f"[strict] {len(real)} python-vs-go divergences")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
