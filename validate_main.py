#!/usr/bin/env python3
"""validate_main.py — Structural checks for Argus main.py. Exit 0 on pass."""
import ast
import inspect
import sys

try:
    import main
except Exception as exc:
    print(f"FAIL — import: {exc}")
    sys.exit(1)

errors: list[str] = []
warnings: list[str] = []

def check(cond: bool, msg: str) -> None:
    if not cond:
        errors.append(msg)

meta_keys   = set(main.STAGE_META)
runner_keys = set(main.RUNNERS)

# ── 1. STAGE_META ↔ RUNNERS must be in perfect sync
check(meta_keys == runner_keys,
      f"STAGE_META vs RUNNERS mismatch "
      f"(meta-only: {meta_keys - runner_keys}, "
      f"runner-only: {runner_keys - meta_keys})")

# ── 2. STAGE_GROUPS references only real stages
for group, members in main.STAGE_GROUPS.items():
    for m in members:
        check(m in meta_keys,
              f"STAGE_GROUPS['{group}'] references unknown stage '{m}'")

# ── 3. STAGE_DEPS keys/values must be real stages
#     (missing entry is fine — .get(key) → None)
for stage, dep in main.STAGE_DEPS.items():
    check(stage in meta_keys,
          f"STAGE_DEPS has unknown key '{stage}'")
    if dep is not None:
        check(dep in meta_keys,
              f"STAGE_DEPS['{stage}'] references unknown dep '{dep}'")

# ── 4. Every *JSON_MAP / _SPECIAL_SYNC_STAGES references real stages
for name in ("FINDINGS_JSON_MAP", "RECON_JSON_MAP", "_SPECIAL_SYNC_STAGES"):
    mapping = getattr(main, name)
    for stage in mapping:
        check(stage in meta_keys,
              f"{name} has unknown stage '{stage}'")

# ── 5. Sync-path overlaps
#     FINDINGS_JSON_MAP ∩ RECON_JSON_MAP is INTENTIONAL for aggregation —
#     RECON routing wins in _sync_stage_artifacts, so the FINDINGS entry is
#     only read by _aggregate_severity / _top_findings. Warn, don't error.
#     _SPECIAL_SYNC_STAGES must not overlap either map (early `return` would
#     skip the generic `findings` row).
KNOWN_RECON_OVERLAP = {"nuclei", "takeover", "js"}

f_s = set(main.FINDINGS_JSON_MAP) & set(main._SPECIAL_SYNC_STAGES)
r_s = set(main.RECON_JSON_MAP)    & set(main._SPECIAL_SYNC_STAGES)
f_r = set(main.FINDINGS_JSON_MAP) & set(main.RECON_JSON_MAP)

check(not f_s, f"FINDINGS_JSON_MAP ∩ _SPECIAL_SYNC_STAGES: {f_s}")
check(not r_s, f"RECON_JSON_MAP    ∩ _SPECIAL_SYNC_STAGES: {r_s}")

unexpected = f_r - KNOWN_RECON_OVERLAP
check(not unexpected,
      f"FINDINGS_JSON_MAP ∩ RECON_JSON_MAP (unexpected): {unexpected}")
if f_r:
    warnings.append(
        f"intentional aggregation overlap: {sorted(f_r)}"
    )

# ── 6. _to_auth_payload must be called (regression guard)
src = inspect.getsource(main)
check(src.count("_to_auth_payload") >= 2,
      "_to_auth_payload is defined but never called — "
      "auth sync will silently skip category/target_host derivation")

# ── 7. RUNNERS values must be callable
for k, v in main.RUNNERS.items():
    check(callable(v), f"RUNNERS['{k}'] is not callable")

# ── 8. Entry-point helpers (optional — warn if missing)
for fn in ("_install_signal_handlers", "_silence_broken_pipe"):
    if hasattr(main, fn):
        check(callable(getattr(main, fn)), f"{fn} is not callable")
    else:
        warnings.append(f"missing {fn}() — entry point will exit less cleanly")

# ── 9. No duplicate top-level names (catches duplicate RUNNERS, globals)
tree = ast.parse(src)
seen: dict[str, int] = {}
for node in tree.body:
    names: list[str] = []
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        names = [node.name]
    elif isinstance(node, ast.Assign):
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        names = [node.target.id]
    for n in names:
        if n in seen:
            errors.append(
                f"duplicate top-level name '{n}' "
                f"(lines {seen[n]} and {node.lineno})"
            )
        else:
            seen[n] = node.lineno

# ── Report
for w in warnings:
    print(f"  ⚠  {w}")

if errors:
    print(f"\nFAIL — {len(errors)} error(s):")
    for e in errors:
        print(f"  ✗  {e}")
    sys.exit(1)

print(
    f"\nPASS — "
    f"{len(meta_keys)} stages · "
    f"{len(main.STAGE_GROUPS)} groups · "
    f"{len(main.FINDINGS_JSON_MAP)} findings maps · "
    f"{len(main.RECON_JSON_MAP)} recon maps · "
    f"{len(main._SPECIAL_SYNC_STAGES)} special-stage tables"
)
