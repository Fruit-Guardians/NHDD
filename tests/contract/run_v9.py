#!/usr/bin/env python3
"""Build + run the v9 primitive harness over a fixture work dir.

Emits a classification JSON, or {"skipped": true, "reason": ...} when no
usable C++17 compiler / the build fails (honest degradation: CI on Linux
covers v9, Windows dev machines may skip it).

Env: NHDD_CONTRACT_IN, NHDD_CONTRACT_MANIFEST, NHDD_CONTRACT_OUT,
     NHDD_CXX (optional compiler override).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

from classify import classify, load_manifest, write_result  # noqa: E402


def find_cxx() -> str | None:
    if os.environ.get("NHDD_CXX"):
        return os.environ["NHDD_CXX"]
    for cand in ("g++", "clang++", "c++"):
        path = shutil.which(cand)
        if path:
            return path
    return None


def main() -> int:
    work = os.environ["NHDD_CONTRACT_IN"]
    manifest = os.environ["NHDD_CONTRACT_MANIFEST"]
    out = os.environ["NHDD_CONTRACT_OUT"]
    workdir = os.path.dirname(work.rstrip(os.sep))  # .work/<impl>
    os.makedirs(workdir, exist_ok=True)

    cxx = find_cxx()
    if not cxx:
        write_result(out, "v9", [], extra={"skipped": True,
                                           "reason": "no C++ compiler found"})
        return 0

    exe = os.path.join(workdir, "v9_harness" + (".exe" if os.name == "nt" else ""))
    cmd = [cxx, "-std=c++17", "-O1",
           "-I", os.path.join(REPO, "NHDD-cpp-modular", "src"),
           os.path.join(HERE, "v9_harness.cpp"), "-o", exe]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        write_result(out, "v9", [], extra={"skipped": True,
                                           "reason": "build failed: "
                                                     + (proc.stderr or "").strip()[:400]})
        return 0

    run = subprocess.run([exe, work], capture_output=True, text=True)
    if run.returncode != 0:
        write_result(out, "v9", [], extra={"skipped": True,
                                           "reason": "run failed: "
                                                     + (run.stderr or "").strip()[:400]})
        return 0

    fixtures = load_manifest(manifest)
    write_result(out, "v9", classify(work, fixtures))
    return 0


if __name__ == "__main__":
    sys.exit(main())
