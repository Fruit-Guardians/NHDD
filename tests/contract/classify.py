#!/usr/bin/env python3
"""Shared helpers for contract-test runners: classify post-run file states."""
from __future__ import annotations

import hashlib
import json
import os


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: str) -> list:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)["fixtures"]


def classify(work: str, fixtures: list) -> list:
    """For each fixture: OK (in place, unchanged), FIXED (in place, changed),
    BAD (moved to <subdir>/bad/), MISSING (gone without quarantine)."""
    results = []
    for fx in fixtures:
        sub = "dex" if fx["kind"] == "dex" else "so"
        d = os.path.join(work, sub)
        inplace = os.path.join(d, fx["name"])
        quarantined = os.path.join(d, "bad", fx["name"])
        if os.path.exists(inplace):
            sha = sha256_file(inplace)
            status = "OK" if sha == fx["orig_sha256"] else "FIXED"
            results.append({"name": fx["name"], "status": status,
                            "sha256": sha, "where": "inplace"})
        elif os.path.exists(quarantined):
            results.append({"name": fx["name"], "status": "BAD",
                            "sha256": sha256_file(quarantined), "where": "bad/"})
        else:
            results.append({"name": fx["name"], "status": "MISSING",
                            "sha256": "", "where": ""})
    return results


def write_result(path: str, impl: str, results: list, extra: dict | None = None) -> None:
    payload = {"impl": impl, "results": results}
    if extra:
        payload.update(extra)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
