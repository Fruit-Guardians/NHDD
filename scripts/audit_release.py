#!/usr/bin/env python3
"""Read-only ZIP/binary privacy gate. Findings never include matched values.

Heuristic only: cannot prove anonymity or detect every credential format.
Use --deny-file with a private JSON string list for known identities/build roots;
never commit that file. Third-party copyright and license notices are retained.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

from audit_publication import inspect


def inspect_payload(data: bytes, path: str, deny: list[str]) -> list[dict]:
    hits = []
    # ZIP source archives may have a single release-directory prefix.
    metadata_path = path.split("/", 1)[-1] if path.startswith("NHDD-v") else path
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        text = data.decode(encoding, errors="replace")
        for hit in inspect(text.encode("utf-8"), metadata_path, "release"):
            hits.append({"category": hit["category"], "path": path, "encoding": encoding})
        if re.search(r"github\.com[/\\]+(?!Fruit-Guardians[/\\])[^/\\\s\"'<>]+[/\\]+NHDD(?:\b|/)", text, re.I):
            hits.append({"category": "noncanonical_project_url", "path": path, "encoding": encoding})
    if any(value.encode(encoding) in data for value in deny
           for encoding in ("utf-8", "utf-16le", "utf-16be")):
        hits.append({"category": "private_denylist_match", "path": path})
    return hits


def inspect_asset(file: Path, deny: list[str]) -> list[dict]:
    if file.suffix.lower() != ".zip":
        return inspect_payload(file.read_bytes(), file.name, deny)
    hits = []
    with zipfile.ZipFile(file) as package:
        seen = set()
        for entry in package.infolist():
            path = PurePosixPath(entry.filename)
            if (entry.filename in seen or path.is_absolute() or ".." in path.parts
                    or "\\" in entry.filename or ":" in entry.filename
                    or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                hits.append({"category": "unsafe_archive_entry", "path": "<entry-redacted>"})
                continue
            seen.add(entry.filename)
            if not entry.is_dir():
                hits.extend(inspect_payload(package.read(entry), entry.filename, deny))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", nargs="+", type=Path)
    parser.add_argument("--deny-file", type=Path)
    args = parser.parse_args()
    deny = json.loads(args.deny_file.read_text(encoding="utf-8")) if args.deny_file else []
    if not isinstance(deny, list) or any(not isinstance(v, str) or not v for v in deny):
        parser.error("Deny file must be a JSON list of nonempty strings")
    findings = []
    for asset in args.assets:
        findings.extend({"asset": asset.name, **hit} for hit in inspect_asset(asset, deny))
    print(json.dumps({"assets_scanned": len(args.assets), "findings": findings}, ensure_ascii=True, indent=2))
    return int(bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
