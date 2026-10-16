#!/usr/bin/env python3
"""Run the Python CLI full-repair path (fix_so.repair_elf, SoFixer-style)
over a fixture work dir and emit classification + invariant JSON.

Mirrors what `python3 fix_so.py <dir>` does per file (classify -> repair_elf),
writing results in place. Unlike the aligned pipeline this path INTENTIONALLY
rebuilds SHT etc., so it gets its own frozen golden set (expected.json
"python_cli" section) plus hard invariants:

  - output of a non-rejected file must pass validate_elf_deep
  - a PT_DYNAMIC present in the input must survive the repair

Env: NHDD_CONTRACT_IN, NHDD_CONTRACT_MANIFEST, NHDD_CONTRACT_OUT.
"""
from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

from classify import load_manifest, write_result  # noqa: E402

import fix_so  # noqa: E402


def main() -> int:
    work = os.environ["NHDD_CONTRACT_IN"]
    out = os.environ["NHDD_CONTRACT_OUT"]
    fixtures = load_manifest(os.environ["NHDD_CONTRACT_MANIFEST"])

    results = []
    for fx in fixtures:
        if fx["kind"] != "so":
            continue
        path = os.path.join(work, "so", fx["name"])
        old = fix_so.read_file(path)
        entry = {"name": fx["name"]}
        cat, reason = fix_so.classify_bytes(old)
        if cat == "bad":
            entry.update({"status": "REJECTED", "sha256": fx["orig_sha256"],
                          "reason": reason})
            results.append(entry)
            continue
        new, actions = fix_so.repair_elf(old)
        with open(path, "wb") as fh:
            fh.write(new)
        dyn_in = fix_so.ElfInfo(old).dynamic() is not None
        dyn_out = fix_so.ElfInfo(new).dynamic() is not None
        entry.update({
            "status": "OK" if new == old else "FIXED",
            "sha256": hashlib.sha256(new).hexdigest(),
            "deep_valid": fix_so.validate_elf_deep(new),
            "dynamic_kept": (not dyn_in) or dyn_out,
        })
        results.append(entry)

    write_result(out, "python_cli", results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
