#!/usr/bin/env python3
"""Build a reviewed NHDD DEX/SO repack plan and optionally an unsigned APK.

The default mode only writes a JSON plan.  Applying the plan is deliberately
explicit because anonymous/runtime candidates are evidence, not proof that a
file belongs in the package.  The generated APK is unsigned and must be
verified and signed by the caller before installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SOURCE_CLASSES = {
    "package_apk": "package_apk",
    "app_data": "app_data",
    "anonymous": "anonymous_runtime",
    "system": "system_runtime",
    "vendor": "vendor_runtime",
    "runtime": "runtime_support",
    "unknown": "unknown",
}


def classify_source(path: str, package: str) -> Tuple[str, str]:
    value = (path or "").strip()
    lower = value.lower()
    package_lower = package.lower()
    if not value or lower.startswith(("[anon", "[stack", "[heap", "memfd:", "/dev/ashmem")):
        return "anonymous", "no stable file backing"
    if any(lower.startswith(prefix) for prefix in ("/system/", "/apex/", "/product/")):
        if "boot.oat" in lower or "/system/framework/" in lower:
            return "runtime", "ART/framework runtime path"
        return "system", "system partition path"
    if lower.startswith(("/vendor/", "/odm/")):
        return "vendor", "vendor partition path"
    if "/data/app/" in lower or lower.endswith("/base.apk"):
        return "package_apk", "installed APK backing path"
    if package_lower and package_lower in lower and lower.startswith(("/data/", "/mnt/")):
        return "app_data", "package name in app-private path"
    if lower.startswith(("/data/user/", "/data/data/", "/data/misc/")):
        return "app_data", "application data path"
    if "boot." in lower or lower.endswith((".oat", ".odex", ".vdex")):
        return "runtime", "runtime format backing path"
    return "unknown", "unclassified backing path"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_metadata(root: Path, suffix: str, pattern: str = "*.meta.json") -> Iterable[Tuple[Path, Dict[str, Any]]]:
    for meta in sorted((root / suffix).glob(pattern)):
        try:
            yield meta, json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue


def dex_candidates(root: Path, package: str, include_anonymous: bool) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for meta_path, meta in iter_metadata(root, "dex"):
        status = meta.get("status", "unknown")
        mapping = meta.get("mapping", {}) or {}
        mapping_path = mapping.get("path", "")
        source, reason = classify_source(mapping_path, package)
        complete = status == "byte_complete" and meta.get("coverage", {}).get("ratio", 0) >= 0.9999
        artifact = meta.get("artifacts", {}).get("fixed")
        artifact_path = (root / "dex" / artifact) if artifact else None
        eligible_source = source in {"package_apk", "app_data"} or (include_anonymous and source == "anonymous")
        eligible = bool(complete and artifact_path and artifact_path.is_file() and eligible_source)
        result.append({
            "kind": "dex",
            "metadata": str(meta_path),
            "artifact": str(artifact_path) if artifact_path else None,
            "status": status,
            "source_class": source,
            "source_reason": reason,
            "mapping_path": mapping_path,
            "complete": complete,
            "eligible": eligible,
            "reject_reason": None if eligible else ("anonymous/runtime source" if not eligible_source else "incomplete or missing fixed artifact"),
        })
    return result


def so_candidates(root: Path, package: str) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for meta_path, meta in iter_metadata(root, "so", "*.json"):
        if meta.get("schema") != "nhdd-elf-reconstruction-v1":
            continue
        source_path = meta.get("source_path", "")
        source, reason = classify_source(source_path, package)
        complete = bool(meta.get("complete") and meta.get("coverage_complete"))
        artifact = meta_path.with_name(meta_path.stem + ".reconstructed.so")
        eligible = bool(complete and artifact.is_file() and source in {"package_apk", "app_data"})
        result.append({
            "kind": "so",
            "metadata": str(meta_path),
            "artifact": str(artifact) if artifact.is_file() else None,
            "status": "complete" if complete else "partial",
            "source_class": source,
            "source_reason": reason,
            "source_path": source_path,
            "complete": complete,
            "eligible": eligible,
            "reject_reason": None if eligible else "runtime/anonymous/partial SO",
        })
    return result


def collect_plan(apk: Path, dump: Path, package: str, include_anonymous: bool) -> Dict[str, Any]:
    dex = dex_candidates(dump, package, include_anonymous)
    so = so_candidates(dump, package)
    return {
        "schema": "nhdd-repack-plan-v1",
        "package": package,
        "original_apk": str(apk),
        "original_apk_sha256": sha256(apk),
        "candidates": dex + so,
        "summary": {
            "dex_total": len(dex),
            "dex_eligible": sum(1 for item in dex if item["eligible"]),
            "so_total": len(so),
            "so_eligible": sum(1 for item in so if item["eligible"]),
        },
        "apply_policy": {
            "requires_explicit_apply": True,
            "unsigned_output": True,
            "anonymous_dex_included": include_anonymous,
        },
    }


def apply_plan(plan: Dict[str, Any], output: Path) -> None:
    apk = Path(plan["original_apk"])
    dex = [Path(item["artifact"]) for item in plan["candidates"]
           if item["kind"] == "dex" and item["eligible"]]
    so = [item for item in plan["candidates"] if item["kind"] == "so" and item["eligible"]]
    if not dex and not so:
        raise SystemExit("no eligible package-owned artifacts; refusing to create an empty repack")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="nhdd-repack-", suffix=".apk", dir=output.parent, delete=False) as temp:
        temp_path = Path(temp.name)
    try:
        with zipfile.ZipFile(apk, "r") as source, zipfile.ZipFile(temp_path, "w") as target:
            replacements: Dict[str, Path] = {}
            for index, artifact in enumerate(dex, start=1):
                replacements["classes.dex" if index == 1 else f"classes{index}.dex"] = artifact
            # Native replacement is conservative: only replace an existing
            # basename in an original lib/ entry. Unknown ABI placement is
            # left in the plan instead of inventing an ABI directory.
            for item in so:
                artifact = Path(item["artifact"])
                basename = Path(item.get("source_path", "")).name
                matches = [name for name in source.namelist() if name.startswith("lib/") and Path(name).name == basename]
                if len(matches) == 1:
                    replacements[matches[0]] = artifact
            for info in source.infolist():
                if info.filename in replacements:
                    target.writestr(info, replacements[info.filename].read_bytes())
                else:
                    target.writestr(info, source.read(info.filename))
            existing = {info.filename for info in source.infolist()}
            for name, artifact in replacements.items():
                if name not in existing:
                    target.writestr(name, artifact.read_bytes())
        shutil.move(str(temp_path), str(output))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--apply", type=Path, help="write an unsigned APK after generating the plan")
    parser.add_argument("--include-anonymous", action="store_true")
    args = parser.parse_args()
    if not args.apk.is_file() or not args.dump.is_dir():
        parser.error("--apk must be a file and --dump must be a directory")
    plan = collect_plan(args.apk, args.dump, args.package, args.include_anonymous)
    args.plan.parent.mkdir(parents=True, exist_ok=True)
    args.plan.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.apply:
        apply_plan(plan, args.apply)
        print(f"wrote unsigned APK: {args.apply}")
    print(json.dumps(plan["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
