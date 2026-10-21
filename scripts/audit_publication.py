#!/usr/bin/env python3
"""Offline, redacted publication audit. No credential values are printed.

Scans Git-tracked working files by default; --history also examines blobs/commits
reachable from local refs. This is a heuristic check, not a complete secret
scanner, credential-validity test, or guarantee that the repository is clean.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "credential_pattern": re.compile(
        r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,}|"
        r"sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{32,}|"
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "personal_home_path": re.compile(
        r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/mnt/[a-z]/Users/|/Users/|/home/)"
        r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
    ),
    "credential_assignment_review": re.compile(
        r"(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token)"
        r"\s*[:=]\s*[\"']([^\r\n\"']{8,})[\"']"
    ),
}
FIRST_PARTY_METADATA = {
    "nhdd_tui.py", "gui/wails.json", "gui/frontend/src/App.vue",
    "README.md", "README.zh-CN.md",
}
AUTHOR_FIELD = re.compile(
    r'(?m)^\s*(?:AUTHORS\s*=|#{1,3} (?:Authors|作者)\s*$|'
    r'.*<div>作者[：:]|"author"\s*:)'
)
SENSITIVE_FILE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[^/]+)?|\.npmrc|\.pypirc|id_rsa|"
    r"id_ed25519|credentials\.json)$|\.(?:p12|pfx|jks|keystore|pem|key)$"
)


def git(*args: str, data: bytes | None = None) -> bytes:
    result = subprocess.run(["git", "-C", str(ROOT), *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("Git audit command failed; no command output disclosed")
    return result.stdout


def inspect(data: bytes, path: str, scope: str, blob: str = "") -> list[dict]:
    text = data.decode("utf-8", errors="replace")
    hits = []
    for category, pattern in RULES.items():
        for match in pattern.finditer(text):
            if category == "credential_assignment_review" and re.search(
                r"(?i)example|placeholder|redacted|your[_ -]|dummy|<|>|\$\{", match.group(1)
            ):
                continue
            hits.append({"scope": scope, "category": category, "path": path,
                         "line": text.count("\n", 0, match.start()) + 1,
                         "blob": blob[:12]})
    if path in FIRST_PARTY_METADATA:
        for match in AUTHOR_FIELD.finditer(text):
            hits.append({"scope": scope, "category": "personal_author_field",
                         "path": path, "line": text.count("\n", 0, match.start()) + 1,
                         "blob": blob[:12]})
    if SENSITIVE_FILE.search(path) and Path(path).name not in (".env.example", ".env.sample"):
        hits.append({"scope": scope, "category": "sensitive_filename_review",
                     "path": path, "line": 0, "blob": blob[:12]})
    return hits


def history_objects():
    objects = {}
    for line in git("rev-list", "--objects", "--all").splitlines():
        oid, _, path = line.partition(b" ")
        objects[oid] = path.decode("utf-8", errors="replace")
    payload = git("cat-file", "--batch", data=b"\n".join(objects) + b"\n")
    cursor = 0
    while cursor < len(payload):
        end = payload.index(b"\n", cursor)
        oid, kind, length = payload[cursor:end].split()
        start = end + 1
        stop = start + int(length)
        if kind in (b"blob", b"commit"):
            yield kind, oid.decode("ascii"), objects.get(oid, "<commit>"), payload[start:stop]
        cursor = stop + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    hits = []
    files = git("ls-files", "-z").decode("utf-8").split("\0")
    scanned = 0
    for path in filter(None, files):
        file = ROOT / path
        if file.is_symlink() or not file.is_file():
            continue
        scanned += 1
        hits.extend(inspect(file.read_bytes(), path, "working_tree"))
    blobs = commits = 0
    identities = None
    if args.history:
        for kind, oid, path, data in history_objects():
            if kind == b"blob":
                blobs += 1
            else:
                commits += 1
            hits.extend(inspect(data, path, "history", oid))
        identities = len(set(git("log", "--all", "--format=%aN <%aE>").splitlines()))
    report = {"tracked_files_scanned": scanned, "reachable_blobs_scanned": blobs,
              "reachable_commits_scanned": commits,
              "historical_author_identity_count": identities, "findings": hits,
              "scope": "Local refs and tracked working files only; values redacted. "
              "Does not inspect remote-only refs, release binaries, gitignored captures, "
              "images' metadata, arbitrary credential formats, or revoke credentials."}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Tracked files: {scanned}; reachable blobs: {blobs}; commits: {commits}; findings: {len(hits)}")
        for hit in hits:
            print(f"{hit['scope']} {hit['category']} {hit['path']}:{hit['line']} {hit['blob']}")
        if identities is not None:
            print(f"Historical author identities: {identities} (names/emails withheld)")
        print(report["scope"])
    return int(bool(hits))


if __name__ == "__main__":
    raise SystemExit(main())
