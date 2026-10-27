# NHDD host-side repack plan

`nhdd_repack.py` classifies DEX/SO evidence before any APK rewrite. The
default output is a reviewable JSON plan; anonymous/runtime candidates stay
rejected until explicitly allowed.

```powershell
py -3 tools/nhdd_repack.py `
  --apk original.apk `
  --dump nhdd-output `
  --package com.example.app `
  --plan repack-plan.json
```

To create an unsigned APK after reviewing the plan, add `--apply
repacked-unsigned.apk`. The tool only replaces complete, package-owned DEX
and SO entries that match existing APK entries. It does not sign the APK and
does not automatically include anonymous runtime DEX. If a reviewed plan
proves that an anonymous DEX belongs to the package, use
`--include-anonymous` explicitly when generating the plan and applying it.
