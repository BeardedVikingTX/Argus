#!/usr/bin/env python3
"""
validate_all.py — Argus full-stack validator (v2)
═══════════════════════════════════════════════════════════════════════════════

Ten tiers of validation across the entire project:

  Tier  1  Syntax         — py_compile every .py (parallel, venv excluded)
  Tier  2  PHP syntax     — php -l on api.php (auto-located or --api-path)
  Tier  3  Import         — import required modules + main + db
  Tier  4  Structure      — required functions/classes/attributes present
  Tier  5  Signatures     — run_*_audit and _self_sync accept expected kwargs
  Tier  6  DB methods     — upsert_*_findings + get_*_findings on DB singleton
  Tier  7  main.py wiring — every _run_* passes scan_id=_CURRENT_SCAN_ID,
                            STAGE_META ↔ RUNNERS in sync
  Tier  8  api.php actions — every action registered AND case-handled
  Tier  9  Cross-module   — has _self_sync → must have _db_now, etc.
  Tier 10  validate_main  — optional structural check for main.py

Usage:
    python3 validate_all.py                       run all tiers
    python3 validate_all.py --quiet               errors + warnings only
    python3 validate_all.py --quick               syntax + import only (pre-commit)
    python3 validate_all.py --strict              missing files are failures
    python3 validate_all.py --check-db            attempt a bridge ping
    python3 validate_all.py --api-path PATH       override api.php location
    python3 validate_all.py --no-php              skip PHP checks
    python3 validate_all.py --list-checks         show what will be checked
    python3 validate_all.py --report out.txt      write output to file
    python3 validate_all.py --json                structured JSON output

Exit codes:
    0  all checks passed
    1  one or more checks failed
    2  catastrophic error (couldn't even start)
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import importlib
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

BASE = Path(__file__).resolve().parent


# ═════════════════════════════════════════════════════════════════════════════
#  MANIFEST
# ═════════════════════════════════════════════════════════════════════════════

# Directories pruned from auto-discovery (avoid walking venv / caches)
SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", ".pytest_cache",
             "node_modules", "env", "build", "dist", ".tox"}

# Files that MUST exist (missing → failure in --strict, warning otherwise)
REQUIRED_ROOT_FILES = [
    "main.py",
    "db.py",
    "config.py",
]

# Extra directories to auto-discover .py files in (root is always walked)
SCAN_DIRS = ["auditing_tools", "recon_tools"]

# Modules that MUST import successfully (the "v3 core")
REQUIRED_MODULES = [
    "main",
    "db",
    "auditing_tools.idor_finder",
    "auditing_tools.open_redirect_finder",
    "auditing_tools.race_condition",
    "auditing_tools.smuggling_finder",
    "auditing_tools.site_mapping",
]

# Full structural requirement map per module
MODULE_REQUIREMENTS: dict[str, dict] = {
    "auditing_tools.idor_finder": {
        "entry": ["run_idor_audit"],
        "helpers": ["_self_sync", "_cfg", "_db_now", "_load_urls"],
        "classes": {
            "IDORFinding": ["to_dict", "finding_hash"],
            "ObjectSurface": ["to_dict"],
        },
    },
    "auditing_tools.open_redirect_finder": {
        "entry": ["run_open_redirect_audit"],
        "helpers": ["_self_sync", "_cfg", "_db_now", "_load_urls"],
        "classes": {
            "OpenRedirectFinding": ["to_dict", "finding_hash"],
            "RedirectSurface": ["to_dict"],
        },
    },
    "auditing_tools.race_condition": {
        "entry": ["run_race_audit"],
        "helpers": ["_self_sync", "_cfg", "_db_now", "_load_urls"],
        "classes": {
            "RaceCandidate": ["to_dict", "finding_hash"],
        },
    },
    "auditing_tools.smuggling_finder": {
        "entry": ["run_smuggling_audit"],
        "helpers": ["_self_sync", "_cfg", "_db_now"],
        "classes": {
            "SmugglingFinding": ["to_dict", "finding_hash"],
        },
    },
    "auditing_tools.site_mapping": {
        "entry": ["run_site_mapping"],
        "helpers": ["_self_sync", "_cfg"],
        "classes": {
            "HostNode": ["to_dict"],
            "EndpointNode": ["to_dict"],
        },
    },
}

# Signature contracts: function → required keyword args
SIGNATURE_CONTRACTS: dict[str, dict[str, list[str]]] = {
    "auditing_tools.idor_finder": {
        "run_idor_audit": ["scan_id"],
        "_self_sync": ["scan_id"],   # positional OK
    },
    "auditing_tools.open_redirect_finder": {
        "run_open_redirect_audit": ["scan_id"],
        "_self_sync": ["scan_id"],
    },
    "auditing_tools.race_condition": {
        "run_race_audit": ["scan_id"],
        "_self_sync": ["scan_id"],
    },
    "auditing_tools.smuggling_finder": {
        "run_smuggling_audit": ["scan_id"],
        "_self_sync": ["scan_id"],
    },
    "auditing_tools.site_mapping": {
        "run_site_mapping": ["scan_id"],
        "_self_sync": ["scan_id"],
    },
}

# db.py methods required per dedicated table
DB_METHODS = {
    "idor":      ("upsert_idor_findings", "get_idor_findings"),
    "redirect":  ("upsert_open_redirect_findings", "get_open_redirect_findings"),
    "race":      ("upsert_race_findings", "get_race_findings"),
    "smuggling": ("upsert_smuggling_findings", "get_smuggling_findings"),
    "mapping":   ("upsert_site_map_hosts", "get_site_map_hosts"),
}

# Every _run_* must pass scan_id=_CURRENT_SCAN_ID
MAIN_WIRING = {
    "_run_idor":      "idor",
    "_run_redirect":  "redirect",
    "_run_race":      "race",
    "_run_smuggling": "smuggling",
    "_run_mapping":   "mapping",
}

# Actions that must be in $known_actions AND have a case handler
API_ACTIONS = [
    "idor_findings.upsert",       "query.idor_findings",
    "open_redirect_findings.upsert","query.open_redirect_findings",
    "race_findings.upsert",       "query.race_findings",
    "smuggling_findings.upsert",  "query.smuggling_findings",
    "site_map_hosts.upsert",      "query.site_map_hosts",
]

# SQL tables that must exist for the pipeline to persist
SQL_TABLES = [
    "idor_findings", "open_redirect_findings", "race_findings",
    "smuggling_findings", "site_map_hosts",
]

# Auto-lookup candidates for api.php (tried in order)
API_PATH_CANDIDATES = [
    Path.home() / "bug-bounty.beardedviking.org" / "api.php",
    Path.home() / "public_html" / "api.php",
    Path.home() / "www" / "api.php",
]

# Expected attributes on main.py
MAIN_ATTRS = [
    "_CURRENT_SCAN_ID", "_DB_FAIL_COUNT", "_DB_MAX_FAILURES",
    "RUNNERS", "STAGE_META", "STAGE_GROUPS", "STAGE_DEPS",
    "FINDINGS_JSON_MAP", "RECON_JSON_MAP", "_SPECIAL_SYNC_STAGES",
    "show_banner", "show_briefing", "show_final_briefing", "run_one",
]


# ═════════════════════════════════════════════════════════════════════════════
#  RESULT MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Tier:
    name: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    skipped: bool = False
    duration_ms: int = 0

    @property
    def status(self) -> str:
        if self.skipped:
            return "SKIP"
        if self.failed:
            return "FAIL"
        if self.warnings:
            return "PASS"
        return "PASS"


@dataclass
class Context:
    """Shared state passed to every check."""
    base: Path
    api_path: Optional[Path] = None
    strict: bool = False
    no_php: bool = False
    check_db: bool = False
    quick: bool = False
    modules: dict[str, Any] = field(default_factory=dict)
    py_files: list[Path] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _discover_py_files(base: Path) -> list[Path]:
    """Auto-discover all project .py files, pruned of skip dirs."""
    files: list[Path] = []
    for root, dirs, filenames in os.walk(base):
        # Prune skip directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(Path(root) / fn)
    # Deterministic order
    files.sort()
    return files


def _resolve_api_path(explicit: Optional[Path]) -> Optional[Path]:
    """Locate api.php: explicit arg → BASE → parent → known server locations."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(BASE / "api.php")
    candidates.append(BASE.parent / "api.php")
    candidates.extend(API_PATH_CANDIDATES)

    for c in candidates:
        try:
            if c.exists() and c.is_file():
                return c
        except (OSError, PermissionError):
            continue
    return None


def _read_file(path: Path, max_bytes: int = 5_000_000) -> Optional[str]:
    """Read a file as UTF-8, truncating on size to avoid hangs."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            with path.open("rb") as f:
                data = f.read(max_bytes)
        else:
            data = path.read_bytes()
        return data.decode("utf-8", errors="ignore")
    except (OSError, PermissionError):
        return None


def _has_kwarg(fn: Any, kwarg: str) -> bool:
    """True if `fn` accepts `kwarg` (as positional, keyword, or **kwargs)."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return False
    for param in sig.parameters.values():
        if param.name == kwarg:
            return True
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 1 — SYNTAX (parallel)
# ═════════════════════════════════════════════════════════════════════════════

def _compile_one(path: Path) -> tuple[Path, bool, str]:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return path, True, ""
        err = (result.stderr or "").strip()
        last = err.splitlines()[-1] if err else "compile failed"
        return path, False, last
    except subprocess.TimeoutExpired:
        return path, False, "compile timeout (>15s)"
    except Exception as e:
        return path, False, f"{type(e).__name__}: {e}"


def check_syntax(ctx: Context) -> Tier:
    tier = Tier(name="Syntax (Python)")
    if not ctx.py_files:
        tier.skipped = True
        return tier

    start = time.monotonic()
    failures: dict[Path, str] = {}

    workers = min(8, max(1, len(ctx.py_files)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_compile_one, p) for p in ctx.py_files]
        for fut in concurrent.futures.as_completed(futures):
            path, ok, msg = fut.result()
            rel = path.relative_to(ctx.base)
            if ok:
                tier.passed.append(str(rel))
            else:
                failures[path] = msg
                tier.failed.append(f"{rel} — {msg}")

    tier.duration_ms = int((time.monotonic() - start) * 1000)
    tier.info.append(
        f"{len(ctx.py_files)} file(s) checked, "
        f"{len(failures)} failure(s), {tier.duration_ms}ms"
    )
    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 2 — PHP SYNTAX
# ═════════════════════════════════════════════════════════════════════════════

def check_php_syntax(ctx: Context) -> Tier:
    tier = Tier(name="Syntax (PHP)")

    if ctx.no_php:
        tier.skipped = True
        tier.info.append("skipped (--no-php)")
        return tier

    php = shutil.which("php")
    if not php:
        tier.warnings.append(
            "php binary not found — skipping (install php-cli for full coverage)"
        )
        return tier

    if ctx.api_path is None:
        if ctx.strict:
            tier.failed.append("api.php — not found (use --api-path)")
        else:
            tier.warnings.append("api.php — not found locally (server-only?) — skipped")
        return tier

    result = subprocess.run(
        [php, "-l", str(ctx.api_path)],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0:
        tier.passed.append(f"{ctx.api_path.name} (php -l)")
    else:
        out = (result.stdout + result.stderr).strip().splitlines()
        tier.failed.append(f"{ctx.api_path.name} — {out[-1] if out else 'php -l failed'}")
    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 3 — IMPORT
# ═════════════════════════════════════════════════════════════════════════════

def check_imports(ctx: Context) -> Tier:
    tier = Tier(name="Import")

    if str(ctx.base) not in sys.path:
        sys.path.insert(0, str(ctx.base))

    for mod_name in REQUIRED_MODULES:
        try:
            mod = importlib.import_module(mod_name)
            ctx.modules[mod_name] = mod
            tier.passed.append(mod_name)
        except ModuleNotFoundError as e:
            # Distinguish "our module missing" from "our module's dep missing"
            missing = e.name or ""
            if missing and missing.startswith(("auditing_tools", "recon_tools")):
                tier.failed.append(f"{mod_name} — file missing or not importable")
            elif missing in (mod_name, mod_name.split(".")[0]):
                tier.failed.append(f"{mod_name} — module not found")
            else:
                tier.failed.append(
                    f"{mod_name} — missing dependency: {missing} "
                    f"(pip install {missing})"
                )
        except Exception as e:
            tier.failed.append(f"{mod_name} — {type(e).__name__}: {e}")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 4 — STRUCTURE
# ═════════════════════════════════════════════════════════════════════════════

def check_structure(ctx: Context) -> Tier:
    tier = Tier(name="Structure")

    for mod_name, req in MODULE_REQUIREMENTS.items():
        mod = ctx.modules.get(mod_name)
        if mod is None:
            tier.failed.append(f"{mod_name} — not imported (see Tier 3)")
            continue

        # Entry points
        for fn_name in req.get("entry", []):
            fn = getattr(mod, fn_name, None)
            if fn is not None and callable(fn):
                tier.passed.append(f"{mod_name}.{fn_name}")
            else:
                tier.failed.append(f"{mod_name}.{fn_name} — missing or not callable")

        # Helpers
        for fn_name in req.get("helpers", []):
            if hasattr(mod, fn_name):
                tier.passed.append(f"{mod_name}.{fn_name}")
            else:
                tier.failed.append(f"{mod_name}.{fn_name} — missing")

        # Classes + methods
        for cls_name, methods in req.get("classes", {}).items():
            cls = getattr(mod, cls_name, None)
            if cls is None:
                tier.failed.append(f"{mod_name}.{cls_name} — missing")
                continue
            for m in methods:
                if hasattr(cls, m):
                    tier.passed.append(f"{mod_name}.{cls_name}.{m}")
                else:
                    tier.failed.append(f"{mod_name}.{cls_name}.{m} — missing")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 5 — SIGNATURES
# ═════════════════════════════════════════════════════════════════════════════

def check_signatures(ctx: Context) -> Tier:
    tier = Tier(name="Signatures")

    for mod_name, contracts in SIGNATURE_CONTRACTS.items():
        mod = ctx.modules.get(mod_name)
        if mod is None:
            tier.failed.append(f"{mod_name} — not imported")
            continue

        for fn_name, required_kwargs in contracts.items():
            fn = getattr(mod, fn_name, None)
            if fn is None or not callable(fn):
                tier.failed.append(f"{mod_name}.{fn_name}() — missing")
                continue
            missing = [k for k in required_kwargs if not _has_kwarg(fn, k)]
            if missing:
                tier.failed.append(
                    f"{mod_name}.{fn_name}() — missing kwargs: {', '.join(missing)}"
                )
            else:
                tier.passed.append(f"{mod_name}.{fn_name}(...)")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 6 — DB METHODS
# ═════════════════════════════════════════════════════════════════════════════

def check_db_methods(ctx: Context) -> Tier:
    tier = Tier(name="db.py methods")
    db_mod = ctx.modules.get("db")
    if db_mod is None:
        tier.failed.append("db — not imported")
        return tier

    db_instance = getattr(db_mod, "DB", None)
    if db_instance is None:
        tier.failed.append("db.DB — singleton not found")
        return tier

    for label, (upsert, get) in DB_METHODS.items():
        for method_name in (upsert, get):
            attr = getattr(db_instance, method_name, None)
            if attr is not None and callable(attr):
                tier.passed.append(f"DB.{method_name}")
            else:
                tier.failed.append(f"DB.{method_name} — missing ({label})")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 7 — main.py WIRING
# ═════════════════════════════════════════════════════════════════════════════

def check_main_wiring(ctx: Context) -> Tier:
    tier = Tier(name="main.py wiring")
    main_mod = ctx.modules.get("main")
    if main_mod is None:
        tier.failed.append("main — not imported")
        return tier

    # ── Required attributes
    for attr in MAIN_ATTRS:
        if hasattr(main_mod, attr):
            tier.passed.append(f"main.{attr}")
        else:
            tier.failed.append(f"main.{attr} — missing")

    # ── Wiring: each _run_* passes scan_id
    for fn_name, label in MAIN_WIRING.items():
        fn = getattr(main_mod, fn_name, None)
        if fn is None:
            tier.failed.append(f"main.{fn_name} — missing")
            continue
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            tier.warnings.append(f"main.{fn_name} — could not read source")
            continue
        if re.search(r"scan_id\s*=\s*_CURRENT_SCAN_ID", src):
            tier.passed.append(f"main.{fn_name} → scan_id ({label})")
        else:
            tier.failed.append(
                f"main.{fn_name} — does not pass scan_id=_CURRENT_SCAN_ID ({label})"
            )

    # ── Auto-discovery: every RUNNERS entry must be callable
    runners = getattr(main_mod, "RUNNERS", {})
    if not isinstance(runners, dict):
        tier.failed.append("main.RUNNERS — not a dict")
        return tier

    non_callable = [k for k, v in runners.items() if not callable(v)]
    if non_callable:
        tier.failed.append(f"RUNNERS — non-callable entries: {', '.join(non_callable)}")
    else:
        tier.passed.append(f"RUNNERS — all {len(runners)} entries callable")

    # ── STAGE_META ↔ RUNNERS sync
    stage_meta = getattr(main_mod, "STAGE_META", {})
    if isinstance(stage_meta, dict) and isinstance(runners, dict):
        meta_keys = set(stage_meta.keys())
        runner_keys = set(runners.keys())
        if meta_keys == runner_keys:
            tier.passed.append(f"STAGE_META ↔ RUNNERS in sync ({len(meta_keys)} stages)")
        else:
            only_meta = meta_keys - runner_keys
            only_runner = runner_keys - meta_keys
            tier.failed.append(
                f"STAGE_META ↔ RUNNERS mismatch: "
                f"meta-only={sorted(only_meta)}, runner-only={sorted(only_runner)}"
            )

    # ── Every _run_* must be reachable from RUNNERS
    all_runners = set()
    for k, v in runners.items():
        if callable(v):
            all_runners.add(getattr(v, "__name__", ""))

    run_functions = [
        name for name in dir(main_mod)
        if name.startswith("_run_") and callable(getattr(main_mod, name, None))
    ]
    unreachable = [n for n in run_functions if n not in all_runners]
    if unreachable:
        tier.warnings.append(
            f"_run_* functions not in RUNNERS: {', '.join(sorted(unreachable))}"
        )
    else:
        tier.passed.append(f"All {len(run_functions)} _run_* functions reachable")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 8 — api.php ACTIONS
# ═════════════════════════════════════════════════════════════════════════════

def check_api_actions(ctx: Context) -> Tier:
    tier = Tier(name="api.php actions")

    if ctx.api_path is None:
        if ctx.strict:
            tier.failed.append("api.php — not found")
        else:
            tier.warnings.append("api.php — not found locally (server-only?) — skipped")
        return tier

    content = _read_file(ctx.api_path)
    if content is None:
        tier.failed.append(f"{ctx.api_path} — could not read")
        return tier

    # Parse $known_actions
    known_match = re.search(
        r"\$known_actions\s*=\s*\[(.*?)\]\s*;",
        content, re.DOTALL,
    )
    registered: set[str] = set()
    if known_match:
        registered = set(re.findall(r"'([^']+)'", known_match.group(1)))
        tier.passed.append(f"$known_actions parsed ({len(registered)} entries)")
    else:
        tier.failed.append("could not parse $known_actions")
        return tier

    # Parse case handlers
    cases = set(re.findall(r"case\s+'([^']+)'\s*:", content))
    tier.passed.append(f"case handlers parsed ({len(cases)} entries)")

    # Every expected action must be in both
    for action in API_ACTIONS:
        in_reg = action in registered
        in_case = action in cases
        if in_reg and in_case:
            tier.passed.append(action)
        elif not in_reg and not in_case:
            tier.failed.append(f"{action} — neither registered nor case-handled")
        elif not in_reg:
            tier.failed.append(f"{action} — has case but not in $known_actions")
        else:
            tier.failed.append(f"{action} — in $known_actions but missing case handler")

    # ── Symmetry check: any upsert.* action should have a query.* sibling
    upserts = {a for a in registered if a.endswith(".upsert")}
    queries = {a for a in registered if a.startswith("query.")}
    for up in upserts:
        # idor_findings.upsert → query.idor_findings
        expected_query = "query." + up.rsplit(".", 1)[0]
        if expected_query not in queries and up.startswith(("idor", "open_redirect",
                                                            "race", "smuggling",
                                                            "site_map")):
            tier.warnings.append(
                f"{up} has no query sibling ({expected_query}) — "
                f"results won't be retrievable"
            )

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 9 — CROSS-MODULE CONSISTENCY
# ═════════════════════════════════════════════════════════════════════════════

def check_cross_module(ctx: Context) -> Tier:
    tier = Tier(name="Cross-module")

    # Every module with _self_sync must have _db_now (for timestamp safety)
    for mod_name, mod in ctx.modules.items():
        if not mod_name.startswith("auditing_tools."):
            continue
        has_self_sync = hasattr(mod, "_self_sync")
        has_db_now = hasattr(mod, "_db_now")

        if has_self_sync and not has_db_now:
            tier.failed.append(
                f"{mod_name} — has _self_sync but missing _db_now "
                f"(ISO 8601 timestamps will break MySQL)"
            )
        elif has_self_sync and has_db_now:
            tier.passed.append(f"{mod_name} — _self_sync + _db_now ✓")

    # Every v3 module should declare a Finding dataclass
    for mod_name, req in MODULE_REQUIREMENTS.items():
        mod = ctx.modules.get(mod_name)
        if mod is None:
            continue
        classes = req.get("classes", {})
        has_finding_class = any(
            "Finding" in cls_name or "Candidate" in cls_name
            for cls_name in classes
        )
        if has_finding_class:
            # Cross-check: has to_dict, has finding_hash
            for cls_name in classes:
                if "Finding" in cls_name or "Candidate" in cls_name:
                    cls = getattr(mod, cls_name, None)
                    if cls and hasattr(cls, "to_dict") and hasattr(cls, "finding_hash"):
                        tier.passed.append(f"{mod_name}.{cls_name} — wire contract OK")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  TIER 10 — SQL TABLES (informational)
# ═════════════════════════════════════════════════════════════════════════════

def check_sql_tables(ctx: Context) -> Tier:
    tier = Tier(name="SQL tables (informational)")
    for table in SQL_TABLES:
        tier.info.append(table)

    if not ctx.check_db:
        tier.info.append("run with --check-db to ping bridge")
        return tier

    db_mod = ctx.modules.get("db")
    db_instance = getattr(db_mod, "DB", None) if db_mod else None
    if db_instance is None:
        tier.warnings.append("--check-db: DB singleton unavailable")
        return tier

    if not getattr(db_instance, "available", False):
        tier.warnings.append("--check-db: bridge not configured")
        return tier

    try:
        start = time.monotonic()
        if db_instance.ping():
            elapsed_ms = int((time.monotonic() - start) * 1000)
            tier.passed.append(f"bridge ping OK ({elapsed_ms}ms)")
        else:
            tier.failed.append("bridge ping returned False")
    except Exception as e:
        tier.failed.append(f"bridge ping failed: {type(e).__name__}: {e}")

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  BONUS — validate_main.py
# ═════════════════════════════════════════════════════════════════════════════

def check_validate_main(ctx: Context) -> Tier:
    tier = Tier(name="validate_main.py")
    vm = ctx.base / "validate_main.py"
    if not vm.exists():
        if ctx.strict:
            tier.failed.append("validate_main.py — not present (--strict)")
        else:
            tier.warnings.append("validate_main.py not present — skipped")
        return tier

    try:
        result = subprocess.run(
            [sys.executable, str(vm)],
            capture_output=True, text=True, cwd=str(ctx.base), timeout=15,
        )
    except subprocess.TimeoutExpired:
        tier.failed.append("validate_main.py — timeout (>15s)")
        return tier

    if result.returncode == 0:
        line = (result.stdout.strip().splitlines() or ["PASS"])[-1]
        tier.passed.append(line)
    else:
        for line in (result.stdout + result.stderr).strip().splitlines():
            if line.strip():
                tier.failed.append(line.strip())

    return tier


# ═════════════════════════════════════════════════════════════════════════════
#  REPORTING
# ═════════════════════════════════════════════════════════════════════════════

COLORS = {
    "reset":  "\033[0m",
    "green":  "\033[32m",
    "red":    "\033[31m",
    "yellow": "\033[33m",
    "cyan":   "\033[36m",
    "dim":    "\033[90m",
    "bold":   "\033[1m",
}


class Reporter:
    def __init__(self, use_color: bool, quiet: bool, report_path: Optional[Path]):
        self.use_color = use_color
        self.quiet = quiet
        self.lines: list[str] = []
        self.report_path = report_path

    def _c(self, color: str, text: str) -> str:
        if not self.use_color:
            return text
        return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

    def out(self, line: str = "") -> None:
        self.lines.append(line)
        print(line)

    def tier(self, tier: Tier) -> None:
        failed = len(tier.failed)
        warn = len(tier.warnings)

        if tier.skipped:
            status = self._c("dim", "SKIP")
        elif failed:
            status = self._c("red", f"FAIL ({failed} error(s))")
        elif warn:
            status = self._c("yellow", f"PASS ({warn} warning(s))")
        else:
            status = self._c("green", "PASS")

        duration = f"  {self._c('dim', f'[{tier.duration_ms}ms]')}" if tier.duration_ms else ""
        self.out(f"  {self._c('cyan', tier.name):<32} {status}{duration}")

        if self.quiet and failed == 0 and warn == 0:
            self.out()
            return

        for item in tier.passed:
            if not self.quiet:
                self.out(f"    {self._c('green', '✓')} {item}")
        for item in tier.warnings:
            self.out(f"    {self._c('yellow', '⚠')} {item}")
        for item in tier.failed:
            self.out(f"    {self._c('red', '✗')} {item}")
        for item in tier.info:
            if not self.quiet:
                self.out(f"    {self._c('dim', 'ℹ')} {item}")

        self.out()

    def summary(self, tiers: list[Tier]) -> int:
        total_pass = sum(len(t.passed) for t in tiers)
        total_fail = sum(len(t.failed) for t in tiers)
        total_warn = sum(len(t.warnings) for t in tiers)
        total_skip = sum(1 for t in tiers if t.skipped)

        self.out("  " + "─" * 66)
        self.out(
            f"  {self._c('bold', 'Total:')} "
            f"{self._c('green', str(total_pass) + ' passed')}  ·  "
            f"{self._c('red' if total_fail else 'dim', str(total_fail) + ' failed')}  ·  "
            f"{self._c('yellow' if total_warn else 'dim', str(total_warn) + ' warning(s)')}"
            + (f"  ·  {self._c('dim', str(total_skip) + ' skipped')}" if total_skip else "")
        )
        self.out()

        if self.report_path:
            try:
                self.report_path.write_text("\n".join(self.lines) + "\n")
            except Exception as e:
                self.out(f"  {self._c('red', '✗')} could not write report: {e}")

        return 0 if total_fail == 0 else 1


# ═════════════════════════════════════════════════════════════════════════════
#  JSON OUTPUT
# ═════════════════════════════════════════════════════════════════════════════

def report_json(tiers: list[Tier]) -> dict:
    return {
        "passed": sum(len(t.passed) for t in tiers),
        "failed": sum(len(t.failed) for t in tiers),
        "warnings": sum(len(t.warnings) for t in tiers),
        "tiers": [
            {
                "name":        t.name,
                "status":      t.status,
                "passed":      t.passed,
                "failed":      t.failed,
                "warnings":    t.warnings,
                "info":        t.info,
                "duration_ms": t.duration_ms,
                "skipped":     t.skipped,
            }
            for t in tiers
        ],
    }


# ═════════════════════════════════════════════════════════════════════════════
#  --list-checks
# ═════════════════════════════════════════════════════════════════════════════

def list_checks() -> None:
    print()
    print("  Checks that will run:")
    print()
    checks = [
        ("Syntax (Python)",       "py_compile every project .py (parallel)"),
        ("Syntax (PHP)",          "php -l on api.php"),
        ("Import",                "import required modules + main + db"),
        ("Structure",             "required functions/classes present"),
        ("Signatures",            "entry points accept scan_id= kwarg"),
        ("db.py methods",         "upsert_*_findings / get_*_findings exist"),
        ("main.py wiring",        "_run_* pass scan_id, STAGE_META ↔ RUNNERS"),
        ("api.php actions",       "actions registered AND case-handled"),
        ("Cross-module",          "_self_sync → _db_now, wire contracts"),
        ("SQL tables",            "informational + optional bridge ping"),
        ("validate_main.py",      "runs if present"),
    ]
    for name, desc in checks:
        print(f"    {name:<32} {desc}")
    print()
    print("  Modules required:")
    for m in REQUIRED_MODULES:
        print(f"    {m}")
    print()
    print(f"  api.php lookup order:")
    print(f"    --api-path → {BASE / 'api.php'} → {BASE.parent / 'api.php'}")
    for c in API_PATH_CANDIDATES:
        print(f"                → {c}")
    print()


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Argus full-stack validator (v2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else "",
    )
    parser.add_argument("--quiet", action="store_true",
                        help="show only failures and warnings")
    parser.add_argument("--quick", action="store_true",
                        help="syntax + import only (fast pre-commit)")
    parser.add_argument("--strict", action="store_true",
                        help="missing files are failures (CI mode)")
    parser.add_argument("--check-db", action="store_true",
                        help="attempt a bridge ping (needs BRIDGE_ENABLED)")
    parser.add_argument("--api-path", type=Path, default=None,
                        help="explicit path to api.php")
    parser.add_argument("--no-php", action="store_true",
                        help="skip php -l")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI color output")
    parser.add_argument("--list-checks", action="store_true",
                        help="list checks and exit")
    parser.add_argument("--report", type=Path, default=None,
                        help="write the report to a file")
    parser.add_argument("--json", action="store_true",
                        help="emit structured JSON to stdout (implies --quiet)")
    args = parser.parse_args(argv)

    if args.list_checks:
        list_checks()
        return 0

    use_color = (
        not args.no_color
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )
    quiet = args.quiet or args.json

    ctx = Context(
        base=BASE,
        api_path=_resolve_api_path(args.api_path),
        strict=args.strict,
        no_php=args.no_php,
        check_db=args.check_db,
        quick=args.quick,
    )
    ctx.py_files = _discover_py_files(BASE)

    reporter = Reporter(use_color, quiet, args.report)
    tiers: list[Tier] = []

    try:
        tiers.append(check_syntax(ctx))

        if not args.quick:
            tiers.append(check_php_syntax(ctx))

        import_tier = check_imports(ctx)
        tiers.append(import_tier)

        if not args.quick:
            tiers.append(check_structure(ctx))
            tiers.append(check_signatures(ctx))
            tiers.append(check_db_methods(ctx))
            tiers.append(check_main_wiring(ctx))
            tiers.append(check_api_actions(ctx))
            tiers.append(check_cross_module(ctx))
            tiers.append(check_sql_tables(ctx))
            tiers.append(check_validate_main(ctx))

    except Exception as e:
        print(f"{COLORS['red']}catastrophic failure: {e}{COLORS['reset']}")
        traceback.print_exc()
        return 2

    if args.json:
        print(json.dumps(report_json(tiers), indent=2))
        return 0 if sum(len(t.failed) for t in tiers) == 0 else 1

    reporter.out()
    if ctx.api_path:
        reporter.out(f"  {reporter._c('dim', 'api.php:')} {ctx.api_path}")
    else:
        reporter.out(f"  {reporter._c('yellow', 'api.php:')} not found locally "
                     f"(use --api-path)")
    reporter.out(f"  {reporter._c('dim', 'python:')} {sys.executable}")
    reporter.out(f"  {reporter._c('dim', 'files:')}  {len(ctx.py_files)} .py, "
                 f"{len(REQUIRED_MODULES)} required modules")
    reporter.out()

    for tier in tiers:
        reporter.tier(tier)

    return reporter.summary(tiers)


if __name__ == "__main__":
    sys.exit(main())
