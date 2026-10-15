#!/usr/bin/env python3
"""Run the Python repair pipelines (fix_dex_checksum.py + fix_so.py) over a
fixture work dir and emit a classification JSON.

Env: NHDD_CONTRACT_IN (work dir with dex/ and so/), NHDD_CONTRACT_MANIFEST,
     NHDD_CONTRACT_OUT (result JSON path).
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

from classify import classify, load_manifest, write_result  # noqa: E402


def main() -> int:
    work = os.environ["NHDD_CONTRACT_IN"]
    manifest = os.environ["NHDD_CONTRACT_MANIFEST"]
    out = os.environ["NHDD_CONTRACT_OUT"]

    import fix_dex_checksum
    import fix_so

    stats = {}
    stats["dex"] = fix_dex_checksum.fix_directory_aligned(os.path.join(work, "dex"))
    stats["so"] = fix_so.fix_directory_aligned(os.path.join(work, "so"))

    fixtures = load_manifest(manifest)
    write_result(out, "python", classify(work, fixtures), extra={"stats": stats})
    return 0


if __name__ == "__main__":
    sys.exit(main())
