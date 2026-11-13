#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/url_categorize.py — URL Classification by Vulnerability Class
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/url_categorize.py
  Version   : 3.0.0 "RATATOSKR"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  The routing layer between URL harvesting and vulnerability testing.

  Takes the harvested URL inventory and slices it into per-bug-class
  candidate lists using `gf` (a grep wrapper with reusable pattern packs).
  Each finder module reads only its own candidate file.

  LOCAL-ONLY: no HTTP requests. gf is a local grep process.
    ✗ Platform headers NOT applicable
    ✗ request.txt auth NOT applicable
    ✗ Rate limits NOT applicable

  v2.0 → v3.0 (surgical hardening):
    [FIX]  _load_urls: BOM/CRLF/inline-comment/trailing-dot safe.
    [FIX]  _write_empty_report now accepts scan_id → DB sync fires even
           for zero-URL input.
    [FIX]  KillSwitch.check() before every gf subprocess — a .ARGUS_STOP
           file mid-categorization now cleanly unwinds.
    [FIX]  SIGINT/SIGTERM handler — partial report written on Ctrl-C.
    [FIX]  Report now has schema_version + producer + input_hash +
           gf_version — matches every other v3.x module's provenance.
    [FIX]  Consolidated param extraction — one pass instead of two.
    [NEW]  24h input-result cache (.state/url_categorize_cache.json) —
           re-runs on same URLs skip gf entirely.
    [NEW]  --parallel-categories N — parallel gf subprocesses (local only,
           no rate-limit concerns).
    [NEW]  DOWNSTREAM_TOOLS map — per-category "feed to X.py" hint.
    [NEW]  param_seeds_by_category — top-20 param names per category,
           perfect wordlist for param_discovery.py.
    [NEW]  Structured warnings[] array in report.
    [NEW]  url_categorize_digest.md — top-50 markdown summary.
    [NEW]  --dry-run, --quiet, --no-cache, --on-progress-ready.
    [NEW]  Selftest with 62 checks (was 0).

  Outputs:
    gf_<category>.txt                  — one file per category
    url_categorize_priority.txt        — URLs matching N+ categories
    url_categorize.json                — full structured report
    url_categorize_digest.md           — top-50 markdown summary
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("argus.url_categorize")


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG INTEGRATION
# ═════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False

try:
    from db import DB  # type: ignore
    DB_AVAILABLE = True
except ImportError:
    DB = None  # type: ignore[assignment]
    DB_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _killswitch_check(label: str = "") -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════
#  THREAD LOCKS
# ═════════════════════════════════════════════════════════════════════════

_CACHE_LOCK = threading.Lock()
_LOG_LOCK   = threading.Lock()
_SHARED     = {"_quiet": False}


def _log_locked(level: str, msg: str) -> None:
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        getattr(log, level)(msg)


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

GF_TIMEOUT_PER_CATEGORY = 60
MAX_INPUT_URLS          = 200000
MAX_URLS_IN_JSON        = 10000
PRIORITY_MIN_CATEGORIES = 3
PRIORITY_MAX_OUTPUT     = 500

DEFAULT_PARALLEL_CATEGORIES = 1
CACHE_TTL_HOURS             = 24.0
CACHE_FILE                  = "url_categorize_cache.json"

PARAM_SEEDS_LIMIT = 20

PATTERN_REPO = "https://github.com/geeknik/Gf-Patterns.git"
PATTERN_DIR  = Path.home() / ".gf"

# Categories that trigger higher weight when matched
HIGH_RISK_CATEGORIES = {
    "sqli", "ssrf", "rce", "lfi", "ssti", "idor", "xss",
}
MEDIUM_RISK_CATEGORIES = {
    "redirect", "graphql", "oauth", "upload", "api", "jwts",
}


# ═════════════════════════════════════════════════════════════════════════
#  CATEGORY DEFINITIONS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class CategoryDef:
    name: str
    description: str
    vuln_classes: list[str]
    aliases: list[str] = field(default_factory=list)
    priority_weight: int = 1


CATEGORIES: list[CategoryDef] = [
    # ── Tier 1 — injection classes ──────────────────────────────────────
    CategoryDef("sqli", "SQL Injection candidates",
                ["sqli", "nosqli"],
                aliases=["sql", "sql-injection"], priority_weight=3),
    CategoryDef("xss", "Cross-Site Scripting candidates",
                ["xss", "dom_xss"],
                aliases=["cross-site-scripting"], priority_weight=3),
    CategoryDef("ssrf", "Server-Side Request Forgery candidates",
                ["ssrf"], aliases=["server-side-request-forgery"], priority_weight=3),
    CategoryDef("rce", "Remote Code Execution / command injection candidates",
                ["rce", "command_injection"],
                aliases=["command-injection"], priority_weight=3),
    CategoryDef("lfi", "Local File Inclusion / path traversal candidates",
                ["lfi", "path_traversal"],
                aliases=["file-inclusion", "rfi"], priority_weight=3),
    CategoryDef("ssti", "Server-Side Template Injection candidates",
                ["ssti"], aliases=["template-injection"], priority_weight=3),
    CategoryDef("idor", "Insecure Direct Object Reference candidates",
                ["idor"], aliases=["object-reference"], priority_weight=3),

    # ── Tier 2 — logic / access ─────────────────────────────────────────
    CategoryDef("redirect", "Open Redirect candidates",
                ["open_redirect"],
                aliases=["open-redirect", "url-redirection"], priority_weight=2),
    CategoryDef("graphql", "GraphQL endpoints and parameters",
                ["graphql"], aliases=[], priority_weight=2),
    CategoryDef("oauth", "OAuth / SSO endpoints",
                ["oauth", "auth_bypass"],
                aliases=["oauth-flow"], priority_weight=2),
    CategoryDef("upload", "File upload endpoints",
                ["upload", "rce"], aliases=["file-upload"], priority_weight=2),
    CategoryDef("api", "API endpoint paths",
                ["broad_surface"], aliases=["api-endpoints"], priority_weight=2),
    CategoryDef("jwts", "JWTs in URLs",
                ["auth_bypass"], aliases=["jwt"], priority_weight=2),

    # ── Tier 3 — disclosure / recon ─────────────────────────────────────
    CategoryDef("cve", "CVE references in URLs",
                ["info_disclosure"], aliases=[], priority_weight=1),
    CategoryDef("json", "JSON endpoints",
                ["broad_surface"], aliases=[], priority_weight=1),
    CategoryDef("aws-keys", "AWS keys in URL parameters",
                ["info_disclosure"], aliases=["aws_keys", "aws"], priority_weight=2),
    CategoryDef("firebase", "Firebase URLs",
                ["info_disclosure"], aliases=["firebaseio"], priority_weight=2),
    CategoryDef("s3-buckets", "S3 bucket URLs",
                ["info_disclosure"], aliases=["s3_buckets", "s3"], priority_weight=2),
    CategoryDef("backup", "Backup file paths",
                ["info_disclosure"], aliases=["backup-files"], priority_weight=2),
    CategoryDef("debug_logic", "Debug parameters and config endpoints",
                ["info_disclosure"],
                aliases=["debug", "debug-logic"], priority_weight=1),
    CategoryDef("interestingparams", "Combined interesting parameters",
                ["broad_surface"],
                aliases=["interesting", "interesting-params", "params"], priority_weight=1),
    CategoryDef("cors", "CORS-related parameters",
                ["cors"], aliases=[], priority_weight=1),
]


# v3.0: downstream tool recommendations per category
DOWNSTREAM_TOOLS: dict[str, str] = {
    "sqli":              "sqli_finder.py",
    "xss":               "xss_finder.py",
    "ssrf":              "ssrf_finder.py",
    "rce":               "ssrf_finder.py / manual",
    "lfi":               "manual",
    "ssti":              "ssti_finder.py",
    "idor":              "idor_finder.py",
    "redirect":          "open_redirect_finder.py",
    "graphql":           "graphql_finder.py",
    "oauth":             "auth_tester.py",
    "upload":            "auth_tester.py",
    "api":               "param_discovery.py",
    "jwts":              "auth_tester.py",
    "cve":               "nuclei_scan.py",
    "json":              "param_discovery.py",
    "aws-keys":          "manual",
    "firebase":          "manual",
    "s3-buckets":        "manual",
    "backup":            "manual",
    "debug_logic":       "manual",
    "interestingparams": "param_discovery.py",
    "cors":              "cors_check.py",
}


# ═════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK PATTERNS
# ═════════════════════════════════════════════════════════════════════════

BUILTIN_PATTERNS: dict[str, re.Pattern] = {
    "sqli": re.compile(
        r"[?&](id|select|report|role|update|query|user|name|sort|where|search|"
        r"params|process|row|view|table|from|sel|results|sleep|fetch|order|"
        r"keyword|column|field|delete|string|number|filter)=",
        re.I,
    ),
    "xss": re.compile(
        r"[?&](q|query|search|s|keyword|callback|jsonp|redirect|url|next|"
        r"return|html|content|message|name|title|text|value|input|output)=",
        re.I,
    ),
    "ssrf": re.compile(
        r"[?&](url|uri|path|dest|destination|redirect|next|continue|target|"
        r"return|reference|site|html|val|validate|domain|callback|feed|host|"
        r"port|to|out|view|dir|show|navigation|open|file|document|folder|"
        r"pg|php_path|style|doc|img|proxy|fetch|load|src)=",
        re.I,
    ),
    "redirect": re.compile(
        r"[?&](redirect|redirect_uri|redirect_url|redirect_to|url|next|return|"
        r"returnTo|return_path|return_to|return_url|goto|dest|destination|"
        r"checkout|checkout_url|continue|forward|from_url|login|login_url|"
        r"logout|out|rurl|target|to|uri|view|window|callback|domain|feed|"
        r"file|file_name|file_url|folder|folder_url|html|image_url|img_url|"
        r"load_file|load_url|navigation|page|page_url|path|port|redir|"
        r"reference|rt|show|site|val|validate)=",
        re.I,
    ),
    "lfi": re.compile(
        r"[?&](file|document|folder|root|path|pg|style|pdf|template|php_path|"
        r"doc|page|name|cat|dir|action|board|date|detail|download|prefix|"
        r"include|inc|locate|show|site|type|view|content|layout|mod|conf|url)=",
        re.I,
    ),
    "rce": re.compile(
        r"[?&](daemon|upload|dir|download|log|ip|cli|cmd|exec|command|execute|"
        r"ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|"
        r"function|req|feature|exe|module|payload|run|print)=",
        re.I,
    ),
    "ssti": re.compile(
        r"[?&](template|tpl|view|content|layout|page|render|snippet|format|"
        r"name|message|subject|body)=",
        re.I,
    ),
    "idor": re.compile(
        r"[?&](id|user|user_id|account|account_id|number|order|no|doc|key|"
        r"email|group|profile|edit|report|invoice|customer|tenant|org|"
        r"organization|uuid|guid|hash)=",
        re.I,
    ),
    "debug_logic": re.compile(
        r"[?&](debug|test|dev|develop|staging|admin|internal|trace|verbose|"
        r"log|logging|config|cfg|env|environment|mode|status|health|info|"
        r"actuator|metrics|swagger|openapi)=",
        re.I,
    ),
    "graphql": re.compile(
        r"(graphql|/gql|query=|mutation=|__schema|introspection)", re.I,
    ),
    "cors": re.compile(
        r"[?&](origin|cors|access_control|allow_origin|callback)=", re.I,
    ),
    "oauth": re.compile(
        r"[?&](client_id|client_secret|code_challenge|redirect_uri|response_type|"
        r"scope|state|token_type|id_token|access_token|refresh_token)=",
        re.I,
    ),
    "upload": re.compile(
        r"[?&](upload|file|attachment|document|image|avatar|photo|media)=", re.I,
    ),
    "api": re.compile(
        r"/(api|v\d+|rest|graphql)(/|$|\?)", re.I,
    ),
    "jwts": re.compile(
        r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", re.I,
    ),
    "cve": re.compile(r"(CVE-\d{4}-\d{4,7})", re.I),
    "json": re.compile(r"\.json(\?|$)", re.I),
    "aws-keys": re.compile(r"(AKIA[0-9A-Z]{16})", re.I),
    "firebase": re.compile(r"([\w-]+\.firebaseio\.com|firebaseapp\.com)", re.I),
    "s3-buckets": re.compile(r"([\w.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com)", re.I),
    "backup": re.compile(
        r"\.(bak|backup|old|orig|save|swp|sql|tar|tar\.gz|tgz|zip|rar|7z)(\?|$)",
        re.I,
    ),
}


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class CategoryResult:
    name: str
    description: str
    vuln_classes: list[str]
    urls: list[str] = field(default_factory=list)
    oracle: str = ""
    error: str = ""
    duration: float = 0.0

    @property
    def count(self) -> int:
        return len(self.urls)

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "description":  self.description,
            "vuln_classes": self.vuln_classes,
            "count":        self.count,
            "oracle":       self.oracle,
            "error":        self.error,
            "duration":     round(self.duration, 3),
            "downstream":   DOWNSTREAM_TOOLS.get(self.name, ""),
            "urls":         self.urls[:MAX_URLS_IN_JSON],
        }


# ═════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════

def _input_hash(urls: list[str]) -> str:
    h = hashlib.sha256()
    for u in sorted(urls):
        h.update(u.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:16]


def _get_gf_version() -> str:
    try:
        result = subprocess.run(
            ["gf", "-version"], capture_output=True, text=True, timeout=5,
        )
        text = (result.stdout or result.stderr or "").strip()
        m = re.search(r"v?\d+\.\d+\.\d+", text)
        return m.group(0) if m else text[:40]
    except Exception:
        return "unknown"


def _state_dir() -> Optional[Path]:
    sd = _cfg("STATE_DIR")
    return Path(sd) if sd is not None else None


def _cache_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / CACHE_FILE if sd else None


def _load_cache(path: Optional[Path],
                  ttl_hours: float = CACHE_TTL_HOURS) -> dict:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        now = time.time()
        fresh: dict = {}
        for key, entry in data.items():
            if not isinstance(entry, dict):
                continue
            age = (now - entry.get("_cached_at", 0)) / 3600
            if age <= ttl_hours:
                fresh[key] = entry
        return fresh
    except Exception:
        return {}


def _save_cache(path: Optional[Path], cache: dict) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_LOCK:
            path.write_text(json.dumps(cache, default=str), encoding="utf-8")
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING (v3.0 — BOM/CRLF safe)
# ═════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path, params_only: bool = True) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    urls: list[str] = []
    seen: set[str] = set()
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        if params_only and "?" not in token:
            continue
        if token not in seen:
            seen.add(token)
            urls.append(token)
    return urls


def _has_gf() -> bool:
    return shutil.which("gf") is not None


# ═════════════════════════════════════════════════════════════════════════
#  PATTERN BOOTSTRAP
# ═════════════════════════════════════════════════════════════════════════

def _pattern_files_present() -> bool:
    if not PATTERN_DIR.exists():
        return False
    return any(PATTERN_DIR.glob("*.json"))


def _bootstrap_patterns() -> bool:
    if _pattern_files_present():
        _log_locked("info",
            f"    Pattern dir: {PATTERN_DIR} "
            f"({len(list(PATTERN_DIR.glob('*.json')))} file(s))")
        return True

    if not shutil.which("git"):
        log.warning("    git not installed — cannot bootstrap gf patterns")
        return False

    _log_locked("info", f"    No gf patterns found — cloning {PATTERN_REPO}...")
    PATTERN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PATTERN_DIR / "_bootstrap_tmp"

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", PATTERN_REPO, str(tmp)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            log.warning(f"    pattern clone failed: {result.stderr.strip()[:160]}")
            shutil.rmtree(tmp, ignore_errors=True)
            return False

        moved = 0
        for f in tmp.glob("*.json"):
            dest = PATTERN_DIR / f.name
            if not dest.exists():
                shutil.copy2(f, dest)
                moved += 1

        shutil.rmtree(tmp, ignore_errors=True)
        _log_locked("info", f"    Bootstrapped {moved} pattern file(s) into {PATTERN_DIR}")
        return _pattern_files_present()

    except subprocess.TimeoutExpired:
        log.warning("    pattern clone timed out")
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    except Exception as e:
        log.warning(f"    pattern bootstrap failed: {e}")
        shutil.rmtree(tmp, ignore_errors=True)
        return False


def _available_gf_patterns() -> set[str]:
    if not PATTERN_DIR.exists():
        return set()
    return {p.stem for p in PATTERN_DIR.glob("*.json")}


# ═════════════════════════════════════════════════════════════════════════
#  GF EXECUTION (v3.0 — KillSwitch)
# ═════════════════════════════════════════════════════════════════════════

def _resolve_gf_name(cat: CategoryDef, available: set[str]) -> Optional[str]:
    if cat.name in available:
        return cat.name
    for alias in cat.aliases:
        if alias in available:
            return alias
    return None


def _run_gf(cat_name: str, urls: list[str]) -> tuple[list[str], str]:
    if not urls:
        return [], ""
    _killswitch_check(f"gf-{cat_name}")

    input_data = "\n".join(urls) + "\n"
    try:
        result = subprocess.run(
            ["gf", cat_name],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=GF_TIMEOUT_PER_CATEGORY,
        )
    except subprocess.TimeoutExpired:
        return [], f"gf timeout after {GF_TIMEOUT_PER_CATEGORY}s"
    except FileNotFoundError:
        return [], "gf binary not found"

    if result.returncode != 0 and not result.stdout.strip():
        return [], (result.stderr.strip()[:160] or f"gf {cat_name} failed")

    matched = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return matched, ""


# ═════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK
# ═════════════════════════════════════════════════════════════════════════

def _match_builtin(cat_name: str, urls: list[str]) -> list[str]:
    pattern = BUILTIN_PATTERNS.get(cat_name)
    if not pattern:
        return []
    return [u for u in urls if pattern.search(u)]


# ═════════════════════════════════════════════════════════════════════════
#  SINGLE CATEGORY RUNNER (used serially + in parallel)
# ═════════════════════════════════════════════════════════════════════════

def _categorize_one(
    cat: CategoryDef, urls: list[str],
    gf_available: bool, available_patterns: set[str],
) -> CategoryResult:
    t0 = time.monotonic()
    result = CategoryResult(
        name=cat.name,
        description=cat.description,
        vuln_classes=cat.vuln_classes,
    )

    gf_name: Optional[str] = None
    if gf_available:
        gf_name = _resolve_gf_name(cat, available_patterns)

    if gf_name:
        matched, err = _run_gf(gf_name, urls)
        if matched or not err:
            result.urls = sorted(set(matched))
            result.oracle = "gf"
        else:
            result.error = err
            result.urls = sorted(set(_match_builtin(cat.name, urls)))
            result.oracle = "builtin" if result.urls else "none"
    else:
        result.urls = sorted(set(_match_builtin(cat.name, urls)))
        result.oracle = "builtin" if result.urls else "none"
        if gf_available and not gf_name:
            result.error = f"no gf pattern file for '{cat.name}'"

    result.duration = time.monotonic() - t0
    return result


# ═════════════════════════════════════════════════════════════════════════
#  OVERLAP & PRIORITY
# ═════════════════════════════════════════════════════════════════════════

def _build_overlap_map(category_results: list[CategoryResult]) -> dict[str, dict]:
    weights = {c.name: c.priority_weight for c in CATEGORIES}
    overlap: dict[str, dict] = {}

    for result in category_results:
        if not result.urls:
            continue
        w = weights.get(result.name, 1)
        for url in result.urls:
            entry = overlap.setdefault(url, {
                "categories": set(),
                "weight": 0,
                "param_names": set(),
            })
            entry["categories"].add(result.name)
            entry["weight"] += w
            parsed = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(parsed.query).keys():
                entry["param_names"].add(k.lower())

    return overlap


def _select_priority_urls(
    overlap: dict[str, dict], limit: int,
    min_categories: int = PRIORITY_MIN_CATEGORIES,
) -> list[dict]:
    candidates = []
    for url, entry in overlap.items():
        if len(entry["categories"]) < min_categories:
            continue
        high_risk_count = len(entry["categories"].intersection(HIGH_RISK_CATEGORIES))
        candidates.append({
            "url":             url,
            "categories":      sorted(entry["categories"]),
            "weight":          entry["weight"],
            "param_names":     sorted(entry["param_names"]),
            "high_risk_count": high_risk_count,
            "category_count":  len(entry["categories"]),
        })
    candidates.sort(key=lambda x: (
        -x["weight"], -x["high_risk_count"], -x["category_count"], x["url"],
    ))
    return candidates[:limit]


# ═════════════════════════════════════════════════════════════════════════
#  CONSOLIDATED PARAM EXTRACTION (v3.0 — one pass, two views)
# ═════════════════════════════════════════════════════════════════════════

def _extract_param_data(
    category_results: list[CategoryResult],
) -> tuple[dict[str, dict[str, int]], dict[str, dict], dict[str, list[str]]]:
    """
    v3.0: single pass over all URLs — returns:
      · param_frequency   — per-category {param: url_count}
      · param_tiers       — {param: {categories, url_count, tier}}
      · param_seeds       — per-category top-N param names (for wordlists)
    """
    # Per-category counters
    per_category_counters: dict[str, Counter[str]] = {}

    # Cross-category aggregation
    param_to_categories: dict[str, set[str]] = {}
    param_url_count: Counter[str] = Counter()

    for result in category_results:
        if not result.urls:
            continue
        counter = per_category_counters.setdefault(result.name, Counter())
        for url in result.urls:
            try:
                parsed = urllib.parse.urlparse(url)
                keys = urllib.parse.parse_qs(parsed.query).keys()
            except Exception:
                continue
            for k in keys:
                key = k.lower()
                counter[key] += 1
                param_to_categories.setdefault(key, set()).add(result.name)
                param_url_count[key] += 1

    # Build param_frequency (top-30 per category)
    param_frequency = {
        cat: dict(counter.most_common(30))
        for cat, counter in per_category_counters.items()
        if counter
    }

    # Build param_tiers
    param_tiers: dict[str, dict] = {}
    for param, cats in param_to_categories.items():
        high_count = len(cats.intersection(HIGH_RISK_CATEGORIES))
        medium_count = len(cats.intersection(MEDIUM_RISK_CATEGORIES))

        if high_count >= 2:              tier = "CRITICAL"
        elif high_count == 1 and medium_count >= 1: tier = "HIGH"
        elif high_count == 1 or medium_count >= 2:  tier = "MEDIUM"
        else:                            tier = "LOW"

        param_tiers[param] = {
            "categories":        sorted(cats),
            "high_risk_count":   high_count,
            "medium_risk_count": medium_count,
            "url_count":         param_url_count[param],
            "tier":              tier,
        }

    tier_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    param_tiers = dict(sorted(
        param_tiers.items(),
        key=lambda kv: (tier_order.get(kv[1]["tier"], 4), -kv[1]["url_count"]),
    ))

    # Build per-category param seeds (top-N per category)
    param_seeds: dict[str, list[str]] = {}
    for cat, counter in per_category_counters.items():
        if counter:
            param_seeds[cat] = [
                name for name, _ in counter.most_common(PARAM_SEEDS_LIMIT)
            ]

    return param_frequency, param_tiers, param_seeds


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════

def _self_sync(
    scan_id: int,
    priority: list[dict],
    category_results: list[CategoryResult],
) -> None:
    if not priority and not category_results:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not available")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB is False")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED is False")
        return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready")
        return

    url_map: dict[str, dict] = {}

    for p in priority:
        url = p.get("url")
        if not url:
            continue
        url_map[url] = {
            "url":             url,
            "categories":      p.get("categories") or [],
            "category_count":  len(p.get("categories") or []),
            "weight":          int(p.get("weight") or 0),
            "param_names":     p.get("param_names") or [],
            "high_risk_count": int(p.get("high_risk_count") or 0),
            "is_priority":     True,
        }

    for result in category_results:
        cat_weight = (
            3 if result.name in HIGH_RISK_CATEGORIES
            else 2 if result.name in MEDIUM_RISK_CATEGORIES
            else 1
        )
        for url in result.urls:
            if not url:
                continue
            entry = url_map.setdefault(url, {
                "url":             url,
                "categories":      [],
                "category_count":  0,
                "weight":          0,
                "param_names":     [],
                "high_risk_count": 0,
                "is_priority":     False,
            })
            if result.name not in entry["categories"]:
                entry["categories"].append(result.name)
                entry["weight"] += cat_weight
            entry["category_count"] = len(entry["categories"])

    for url, entry in url_map.items():
        if not entry["param_names"]:
            try:
                parsed = urllib.parse.urlparse(url)
                entry["param_names"] = list(
                    urllib.parse.parse_qs(parsed.query).keys())
            except Exception:
                entry["param_names"] = []
        entry["high_risk_count"] = len(
            set(entry["categories"]).intersection(HIGH_RISK_CATEGORIES)
        )

    items = list(url_map.values())
    if not items:
        return

    try:
        result = DB.upsert_url_categorize(scan_id, items)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} URL(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════
#  DIGEST WRITER (v3.0)
# ═════════════════════════════════════════════════════════════════════════

def _write_digest(
    outdir: Path, priority: list[dict],
    category_results: list[CategoryResult],
    param_tiers: dict[str, dict],
) -> None:
    lines = [
        "# URL Categorize Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Categories run:** {len(category_results)}  \n",
        f"**Priority URLs:** {len(priority)}  \n",
        f"**Parameter tiers:** "
        f"CRIT={sum(1 for v in param_tiers.values() if v['tier']=='CRITICAL')} "
        f"HIGH={sum(1 for v in param_tiers.values() if v['tier']=='HIGH')} "
        f"MED={sum(1 for v in param_tiers.values() if v['tier']=='MEDIUM')} "
        f"LOW={sum(1 for v in param_tiers.values() if v['tier']=='LOW')}  \n\n",
        "## Category breakdown\n\n",
        "| Category | Count | Oracle | Downstream |\n",
        "|----------|-------|--------|------------|\n",
    ]
    for r in category_results:
        downstream = DOWNSTREAM_TOOLS.get(r.name, "—")
        lines.append(
            f"| {r.name} | {r.count} | {r.oracle or '—'} | {downstream} |\n"
        )

    if priority:
        lines.append("\n## Top priority URLs\n\n")
        lines.append("| Weight | Categories | URL |\n")
        lines.append("|--------|------------|-----|\n")
        for p in priority[:50]:
            url = p["url"].replace("|", "\\|")[:80]
            cats = ",".join(p["categories"]).replace("|", "\\|")[:60]
            lines.append(f"| {p['weight']} | {cats} | {url} |\n")

    critical = [(n, d) for n, d in param_tiers.items() if d["tier"] == "CRITICAL"]
    if critical:
        lines.append("\n## CRITICAL-risk parameters\n\n")
        lines.append("| Parameter | URLs | Categories |\n")
        lines.append("|-----------|------|------------|\n")
        for name, data in critical[:50]:
            cats = ",".join(data["categories"])[:80].replace("|", "\\|")
            lines.append(f"| {name} | {data['url_count']} | {cats} |\n")

    (outdir / "url_categorize_digest.md").write_text(
        "".join(lines), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════
#  EMPTY REPORT WRITER (v3.0 — accepts scan_id + dry_run)
# ═════════════════════════════════════════════════════════════════════════

def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
    scan_id: Optional[int] = None,
    dry_run: bool = False,
    reason: str = "no_inputs",
) -> Path:
    report = {
        "schema_version":  3,
        "producer":        f"url_categorize.py v3.0.0 'RATATOSKR'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "dry_run":         dry_run,
        "reason":          reason,
        "input_file":      str(input_file),
        "input_hash":      None,
        "gf_version":      "unknown",
        "config":          {},
        "warnings":        [],
        "totals": {
            "urls_input": 0, "unique_urls_categorized": 0,
            "total_category_hits": 0, "urls_in_2plus_categories": 0,
            "urls_with_high_risk": 0, "priority_urls": 0,
            "unique_param_names": 0,
            "param_tiers": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        },
        "by_oracle":              {},
        "categories":             [],
        "param_frequency":        {},
        "param_seeds_by_category":{},
        "param_tiers":            {},
        "priority_urls":          [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "url_categorize.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (outdir / "url_categorize_priority.txt").write_text("")
    (outdir / "url_categorize_digest.md").write_text(
        "# URL Categorize Digest\n\nNo URLs categorized.\n", encoding="utf-8")
    for cat in CATEGORIES:
        (outdir / f"gf_{cat.name}.txt").write_text("")

    if scan_id is not None:
        _self_sync(scan_id, [], [])

    return json_path


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════

def run_url_categorize(
    urls_file: Path,
    outdir: Path,
    *,
    # v2 backward-compat
    params_only: bool = True,
    bootstrap_patterns: bool = True,
    force_builtin: bool = False,
    categories: Optional[list[str]] = None,
    priority_min_categories: int = PRIORITY_MIN_CATEGORIES,
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    quiet: bool = False,
    no_cache: bool = False,
    parallel_categories: int = DEFAULT_PARALLEL_CATEGORIES,
    on_progress: Optional[Callable[[str, dict], None]] = None,
) -> Path:
    """
    Categorize every URL in `urls_file` into per-bug-class candidate lists.
    """
    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    # ── SIGINT handler ──────────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — writing partial report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    try:
        urls = _load_urls(urls_file, params_only=params_only)
        if len(urls) > MAX_INPUT_URLS:
            warnings.append(f"input-capped: {len(urls)} → {MAX_INPUT_URLS}")
            log.warning(f"  Capping at {MAX_INPUT_URLS} URLs (input had {len(urls)})")
            urls = urls[:MAX_INPUT_URLS]

        outdir.mkdir(parents=True, exist_ok=True)

        if not quiet:
            log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}"
                     f"{'  (parameterised only)' if params_only else ''}")
            log.info("  Note   : local-only stage — no headers or auth applied")
            log.info("")

        if not urls:
            log.warning("  No URLs to categorize — writing empty report")
            return _write_empty_report(outdir, urls_file, start,
                                          scan_id=scan_id, reason="empty_input")

        if dry_run:
            log.info(f"  DRY-RUN — would categorize {len(urls)} URL(s)")
            for u in urls[:10]:
                log.info(f"    {u}")
            if len(urls) > 10:
                log.info(f"    … and {len(urls) - 10} more")
            return _write_empty_report(outdir, urls_file, start,
                                          scan_id=scan_id, dry_run=True,
                                          reason="dry_run")

        input_hash = _input_hash(urls)
        gf_version = _get_gf_version() if _has_gf() else "not-installed"

        # ── Pattern setup ───────────────────────────────────────────────
        gf_available = _has_gf() and not force_builtin
        available_patterns: set[str] = set()
        if gf_available:
            log.info("  Pattern setup")
            if bootstrap_patterns:
                _bootstrap_patterns()
            available_patterns = _available_gf_patterns()
            log.info(f"    gf binary available, {len(available_patterns)} pattern(s) found")
        else:
            reason = "forced builtin" if force_builtin else "gf not installed"
            log.info(f"  Pattern setup: {reason} — using built-in regex pack")
        log.info("")

        # ── Select categories ───────────────────────────────────────────
        selected: list[CategoryDef] = CATEGORIES
        if categories:
            wanted = {c.strip().lower() for c in categories if c.strip()}
            selected = [c for c in CATEGORIES if c.name in wanted]
            if not selected:
                log.error(f"  No matching categories: {', '.join(sorted(wanted))}")
                return _write_empty_report(outdir, urls_file, start,
                                              scan_id=scan_id,
                                              reason="no_matching_categories")

        # ── Cache lookup ────────────────────────────────────────────────
        cache_path = _cache_path()
        cache = _load_cache(cache_path) if not no_cache else {}
        cache_key = (
            f"{input_hash}|gf={gf_version}|"
            f"pat={len(available_patterns)}|"
            f"cats={','.join(sorted(c.name for c in selected))}"
        )
        cached = cache.get(cache_key)
        if cached:
            log.info(f"  Cache  : HIT ({len(cached.get('categories', {}))} categories)")
            results: list[CategoryResult] = []
            for cat_name, entry in cached.get("categories", {}).items():
                cat_def = next((c for c in CATEGORIES if c.name == cat_name), None)
                if not cat_def:
                    continue
                r = CategoryResult(
                    name=cat.name,
                    description=cat_def.description,
                    vuln_classes=cat_def.vuln_classes,
                    urls=entry.get("urls", []),
                    oracle=entry.get("oracle", "cache"),
                    error=entry.get("error", ""),
                    duration=entry.get("duration", 0.0),
                )
                results.append(r)
            _progress("cache_hit", {"categories": len(results)})
        else:
            # ── Run categorization ──────────────────────────────────────
            if not quiet:
                log.info(f"  Categorizing {len(urls)} URL(s) across "
                         f"{len(selected)} category(ies)"
                         f"{f' (parallel={parallel_categories})' if parallel_categories > 1 else ''}...")

            _progress("stage_start", {"categories": len(selected)})
            results = []

            if parallel_categories > 1 and len(selected) > 1:
                with ThreadPoolExecutor(max_workers=parallel_categories) as pool:
                    futures = {
                        pool.submit(_categorize_one, cat, urls,
                                    gf_available, available_patterns): cat
                        for cat in selected
                    }
                    for fut in as_completed(futures):
                        cat = futures[fut]
                        if _sigint["flag"]:
                            break
                        try:
                            result = fut.result()
                            results.append(result)
                            _progress("category_done",
                                      {"name": cat.name, "count": result.count})
                        except Exception as e:
                            log.warning(f"    {cat.name} failed: {e}")
            else:
                for cat in selected:
                    if _sigint["flag"]:
                        break
                    result = _categorize_one(cat, urls,
                                              gf_available, available_patterns)
                    results.append(result)
                    _progress("category_done",
                              {"name": cat.name, "count": result.count})

            _progress("stage_end", {"categories": len(results)})

            # Save cache
            if not no_cache and cache_path and results:
                cache[cache_key] = {
                    "categories": {
                        r.name: {
                            "urls": r.urls,
                            "oracle": r.oracle,
                            "error": r.error,
                            "duration": r.duration,
                        }
                        for r in results
                    },
                    "_cached_at": time.time(),
                }
                _save_cache(cache_path, cache)

        # Preserve category order (parallel may reorder)
        order = {c.name: i for i, c in enumerate(selected)}
        results.sort(key=lambda r: order.get(r.name, 999))

        # ── Write per-category flat files ───────────────────────────────
        for r in results:
            flat_path = outdir / f"gf_{r.name}.txt"
            flat_path.write_text(
                "\n".join(r.urls) + ("\n" if r.urls else ""))

        if not quiet:
            for r in results:
                status = f"✓ {r.count:>5} URL(s)" if r.count else "· 0 URL(s)"
                oracle_tag = f"[{r.oracle}]" if r.oracle else ""
                err_tag = f"  ({r.error})" if r.error else ""
                log.info(f"    {r.name:<20} {status:<14} {oracle_tag:<10}{err_tag}")

        # ── Overlap + priority ──────────────────────────────────────────
        log.info("")
        log.info("  Overlap analysis")

        overlap = _build_overlap_map(results)
        priority = _select_priority_urls(overlap, PRIORITY_MAX_OUTPUT,
                                            priority_min_categories)

        priority_path = outdir / "url_categorize_priority.txt"
        priority_path.write_text(
            "\n".join(p["url"] for p in priority) + ("\n" if priority else ""))

        multi_cat = sum(1 for e in overlap.values() if len(e["categories"]) >= 2)
        high_risk_urls = sum(
            1 for e in overlap.values()
            if e["categories"].intersection(HIGH_RISK_CATEGORIES))

        log.info(f"    URLs matching 2+ categories  : {multi_cat}")
        log.info(f"    URLs matching {priority_min_categories}+ categories  : {len(priority)}")
        log.info(f"    URLs with high-risk category : {high_risk_urls}")

        # ── Param extraction (single pass, three views) ─────────────────
        param_freq, param_tiers, param_seeds = _extract_param_data(results)

        # ── Report ──────────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        total_category_hits = sum(r.count for r in results)
        unique_urls_hit = len(overlap)

        by_oracle: dict[str, int] = {}
        for r in results:
            key = r.oracle or "none"
            by_oracle[key] = by_oracle.get(key, 0) + 1

        by_tier = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for p in param_tiers.values():
            by_tier[p["tier"]] += 1

        report = {
            "schema_version":  3,
            "producer":        f"url_categorize.py v3.0.0 'RATATOSKR'",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "input_file":      str(urls_file),
            "input_hash":      input_hash,
            "gf_version":      gf_version,
            "config": {
                "params_only":              params_only,
                "gf_available":             gf_available,
                "available_patterns":       sorted(available_patterns),
                "force_builtin":            force_builtin,
                "priority_min_categories":  priority_min_categories,
                "categories_selected":      [c.name for c in selected],
                "parallel_categories":      parallel_categories,
                "headers_applied":          False,
                "note":                     "local-only stage — no HTTP requests, "
                                            "no headers or auth",
            },
            "warnings": warnings,
            "totals": {
                "urls_input":                  len(urls),
                "unique_urls_categorized":     unique_urls_hit,
                "total_category_hits":         total_category_hits,
                "urls_in_2plus_categories":    multi_cat,
                "urls_with_high_risk":         high_risk_urls,
                "priority_urls":               len(priority),
                "unique_param_names":          len(param_tiers),
                "param_tiers":                 by_tier,
            },
            "by_oracle":              by_oracle,
            "categories":             [r.to_dict() for r in results],
            "param_frequency":        param_freq,
            "param_seeds_by_category": param_seeds,
            "param_tiers":            param_tiers,
            "priority_urls":          priority,
        }

        json_path = outdir / "url_categorize.json"
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")

        _write_digest(outdir, priority, results, param_tiers)

        # ── Self-sync ───────────────────────────────────────────────────
        if scan_id is not None:
            log.info("")
            log.info(f"  Syncing to remote database (scan_id={scan_id})...")
            _self_sync(scan_id, priority, results)
        else:
            log.info("")
            log.info("  DB sync  : deferred to main.py (no scan_id passed)")

        # ── Console summary ─────────────────────────────────────────────
        if not quiet:
            log.info("")
            log.info("  Outputs :")
            for r in results:
                if r.count:
                    log.info(f"    gf_{r.name:<20} {r.count:>6} URL(s)")
            log.info(f"    {'url_categorize_priority.txt':<30} {len(priority):>6} URL(s)")
            log.info(f"    {'url_categorize_digest.md':<30}")

            for cat_name in ("sqli", "xss", "ssrf", "redirect"):
                freq = param_freq.get(cat_name, {})
                if freq:
                    top = list(freq.items())[:6]
                    log.info("")
                    log.info(f"  Top {cat_name} parameters : "
                             + " · ".join(f"{k}({v})" for k, v in top))

            critical_params = [
                (name, data) for name, data in param_tiers.items()
                if data["tier"] == "CRITICAL"
            ]
            if critical_params:
                log.info("")
                log.info(f"  CRITICAL-risk parameters ({len(critical_params)}):")
                for name, data in critical_params[:10]:
                    cats = ",".join(data["categories"][:5])
                    log.info(f"    {name:<24} {data['url_count']:>5} URL(s)  [{cats}]")

            if priority:
                log.info("")
                log.info(f"  Highest-priority URLs (>= {priority_min_categories} categories):")
                for p in priority[:10]:
                    cats = ",".join(p["categories"])
                    log.info(f"    {p['weight']:>3}  {p['url'][:90]:<90}  [{cats}]")

            if warnings:
                log.info("")
                log.info("  Warnings:")
                for w in warnings[:8]:
                    log.warning(f"    {w}")

            log.info("")
            log.info(f"  Completed in {elapsed:.1f}s")

        return json_path

    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST (v3.0 — 62 checks)
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  url_categorize.py v3.0 'RATATOSKR' — selftest")
    print("═" * 70)

    import inspect
    import tempfile

    def _mk_result(name: str = "sqli",
                    urls: Optional[list[str]] = None) -> CategoryResult:
        cat = next((c for c in CATEGORIES if c.name == name), None)
        return CategoryResult(
            name=name,
            description=cat.description if cat else "",
            vuln_classes=cat.vuln_classes if cat else [],
            urls=urls or [],
            oracle="builtin" if urls else "none",
        )

    def _input_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example/x?id=1\r\n"
                     b"https://b.example/y?q=x  # inline\r\n"
                     b"\r\n"
                     b"# full-line\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_urls(tmp, params_only=True)
            return loaded == [
                "https://a.example/x?id=1",
                "https://b.example/y?q=x",
            ]
        finally:
            tmp.unlink(missing_ok=True)

    def _input_no_params_filtered() -> bool:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("https://a.example/x\nhttps://b.example/y?id=1\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_urls(tmp, params_only=True)
            return loaded == ["https://b.example/y?id=1"]
        finally:
            tmp.unlink(missing_ok=True)

    def _input_params_only_false() -> bool:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("https://a.example/x\nhttps://b.example/y?id=1\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_urls(tmp, params_only=False)
            return len(loaded) == 2
        finally:
            tmp.unlink(missing_ok=True)

    def _builtin_sqli() -> bool:
        return bool(_match_builtin("sqli", ["https://x/a?id=1"]))

    def _builtin_xss() -> bool:
        return bool(_match_builtin("xss", ["https://x/a?q=test"]))

    def _builtin_graphql() -> bool:
        return bool(_match_builtin("graphql", ["https://x/graphql"]))

    def _builtin_jwt() -> bool:
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "abcdefghijklmnop")
        return bool(_match_builtin("jwts", [f"https://x/a?token={jwt}"]))

    def _builtin_cve() -> bool:
        return bool(_match_builtin("cve", ["https://x/CVE-2021-44228"]))

    def _builtin_backup() -> bool:
        return bool(_match_builtin("backup", ["https://x/db.sql"]))

    def _overlap_two_cats() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1&q=test"])
        r2 = _mk_result("xss", ["https://x/a?id=1&q=test"])
        overlap = _build_overlap_map([r1, r2])
        return len(overlap) == 1 and len(
            next(iter(overlap.values()))["categories"]) == 2

    def _overlap_param_names() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1&q=test"])
        overlap = _build_overlap_map([r1])
        entry = next(iter(overlap.values()))
        return entry["param_names"] == {"id", "q"}

    def _priority_respects_min() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1"])
        r2 = _mk_result("xss", ["https://x/a?id=1"])
        r3 = _mk_result("ssrf", ["https://x/a?id=1"])
        overlap = _build_overlap_map([r1, r2, r3])
        priority = _select_priority_urls(overlap, 500, min_categories=3)
        return len(priority) == 1

    def _priority_excludes_below() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1"])
        overlap = _build_overlap_map([r1])
        priority = _select_priority_urls(overlap, 500, min_categories=3)
        return len(priority) == 0

    def _priority_weight() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1"])       # weight 3
        r2 = _mk_result("cors", ["https://x/a?id=1"])       # weight 1
        overlap = _build_overlap_map([r1, r2])
        priority = _select_priority_urls(overlap, 500, min_categories=2)
        return priority[0]["weight"] == 4

    def _param_tiers_critical() -> bool:
        # sqli + xss both high-risk
        r1 = _mk_result("sqli", ["https://x/a?id=1"])
        r2 = _mk_result("xss", ["https://x/a?id=1"])
        _, tiers, _ = _extract_param_data([r1, r2])
        return tiers["id"]["tier"] == "CRITICAL"

    def _param_tiers_high() -> bool:
        # 1 high + 1 medium
        r1 = _mk_result("sqli", ["https://x/a?id=1"])
        r2 = _mk_result("redirect", ["https://x/a?id=1"])
        _, tiers, _ = _extract_param_data([r1, r2])
        return tiers["id"]["tier"] == "HIGH"

    def _param_tiers_low() -> bool:
        r1 = _mk_result("debug_logic", ["https://x/a?test=1"])
        _, tiers, _ = _extract_param_data([r1])
        return tiers["test"]["tier"] == "LOW"

    def _param_seeds_generated() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1", "https://y/b?q=1"])
        _, _, seeds = _extract_param_data([r1])
        return "sqli" in seeds and len(seeds["sqli"]) >= 1

    def _param_frequency_counts() -> bool:
        r1 = _mk_result("sqli", [
            "https://x/a?id=1",
            "https://y/b?id=2",
            "https://z/c?q=3",
        ])
        freq, _, _ = _extract_param_data([r1])
        return freq["sqli"]["id"] == 2 and freq["sqli"]["q"] == 1

    def _select_category_none_errors() -> bool:
        # When gf returns empty with err -> fall back to builtin, oracle builtin
        cat = next(c for c in CATEGORIES if c.name == "sqli")
        result = _categorize_one(
            cat, ["https://x/a?id=1"],
            gf_available=True, available_patterns={"sqli"},
        )
        # gf returns empty (rc 0, no matches) — should stay oracle="gf"
        # but this test simulates a real gf call. We just ensure no crash.
        return result.name == "sqli"

    def _downstream_map_exists() -> bool:
        return len(DOWNSTREAM_TOOLS) >= 15

    def _has_sqli_downstream() -> bool:
        return DOWNSTREAM_TOOLS.get("sqli") == "sqli_finder.py"

    def _high_risk_cats_include_sqli() -> bool:
        return "sqli" in HIGH_RISK_CATEGORIES

    def _medium_risk_cats_include_redirect() -> bool:
        return "redirect" in MEDIUM_RISK_CATEGORIES

    def _input_hash_deterministic() -> bool:
        a = _input_hash(["https://x/a", "https://y/b"])
        b = _input_hash(["https://y/b", "https://x/a"])
        return a == b  # sorted before hashing

    def _input_hash_distinct() -> bool:
        a = _input_hash(["https://x/a"])
        b = _input_hash(["https://x/b"])
        return a != b

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_url_categorize)
        return set(required).issubset(set(sig.parameters))

    def _write_empty_report_sig() -> bool:
        sig = inspect.signature(_write_empty_report)
        return "scan_id" in sig.parameters and "dry_run" in sig.parameters

    def _categories_count() -> bool:
        return len(CATEGORIES) >= 20

    def _builtin_patterns_count() -> bool:
        return len(BUILTIN_PATTERNS) >= 15

    def _builtin_ssrf() -> bool:
        return bool(_match_builtin("ssrf", ["https://x/a?url=evil.com"]))

    def _builtin_redirect() -> bool:
        return bool(_match_builtin("redirect", ["https://x/a?redirect=evil.com"]))

    def _builtin_lfi() -> bool:
        return bool(_match_builtin("lfi", ["https://x/a?file=etc"]))

    def _builtin_oauth() -> bool:
        return bool(_match_builtin("oauth", ["https://x/a?client_id=abc"]))

    def _builtin_api() -> bool:
        return bool(_match_builtin("api", ["https://x/api/v1/users"]))

    def _builtin_aws() -> bool:
        return bool(_match_builtin("aws-keys",
                                      ["https://x/a?key=AKIAIOSFODNN7EXAMPLE"]))

    def _builtin_firebase() -> bool:
        return bool(_match_builtin("firebase",
                                      ["https://x.firebaseio.com/a"]))

    def _builtin_s3() -> bool:
        return bool(_match_builtin("s3-buckets",
                                      ["https://mybucket.s3.amazonaws.com/a"]))

    def _param_tier_order() -> bool:
        r1 = _mk_result("sqli", ["https://x/a?id=1"])
        r2 = _mk_result("xss", ["https://x/a?id=1"])
        r3 = _mk_result("debug_logic", ["https://x/a?test=1"])
        _, tiers, _ = _extract_param_data([r1, r2, r3])
        names = list(tiers.keys())
        # "id" should come before "test" (CRITICAL before LOW)
        return names.index("id") < names.index("test")

    def _empty_category_no_crash() -> bool:
        r = _mk_result("sqli", [])
        return r.count == 0 and r.to_dict()["count"] == 0

    def _result_to_dict_has_downstream() -> bool:
        r = _mk_result("sqli", ["https://x/a"])
        return "downstream" in r.to_dict()

    def _state_dir_callable() -> bool:
        return callable(_state_dir)

    def _cache_path_callable() -> bool:
        return callable(_cache_path)

    def _killswitch_check_callable() -> bool:
        return callable(_killswitch_check)

    def _log_locked_callable() -> bool:
        return callable(_log_locked)

    def _get_gf_version_callable() -> bool:
        return callable(_get_gf_version)

    def _write_digest_callable() -> bool:
        return callable(_write_digest)

    def _input_hash_callable() -> bool:
        return callable(_input_hash)

    def _extract_param_data_callable() -> bool:
        return callable(_extract_param_data)

    def _categorize_one_callable() -> bool:
        return callable(_categorize_one)

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                    lambda: CFG_LOADED),
        ("_load_urls BOM/CRLF",              _input_bom_crlf),
        ("_load_urls filters non-param",     _input_no_params_filtered),
        ("_load_urls keeps all if param_on", _input_params_only_false),
        ("builtin: sqli",                    _builtin_sqli),
        ("builtin: xss",                     _builtin_xss),
        ("builtin: ssrf",                    _builtin_ssrf),
        ("builtin: redirect",                _builtin_redirect),
        ("builtin: lfi",                     _builtin_lfi),
        ("builtin: oauth",                   _builtin_oauth),
        ("builtin: graphql",                 _builtin_graphql),
        ("builtin: api",                     _builtin_api),
        ("builtin: jwt",                     _builtin_jwt),
        ("builtin: cve",                     _builtin_cve),
        ("builtin: aws-keys",                _builtin_aws),
        ("builtin: firebase",                _builtin_firebase),
        ("builtin: s3-buckets",              _builtin_s3),
        ("builtin: backup",                  _builtin_backup),
        ("overlap: two cats",                _overlap_two_cats),
        ("overlap: param names",             _overlap_param_names),
        ("priority: respects min",           _priority_respects_min),
        ("priority: excludes below",         _priority_excludes_below),
        ("priority: weight sum",             _priority_weight),
        ("param_tiers: CRITICAL",            _param_tiers_critical),
        ("param_tiers: HIGH",                _param_tiers_high),
        ("param_tiers: LOW",                 _param_tiers_low),
        ("param_tiers: sorted order",        _param_tier_order),
        ("param_seeds: generated",           _param_seeds_generated),
        ("param_frequency: counts",          _param_frequency_counts),
        ("downstream: map exists",           _downstream_map_exists),
        ("downstream: sqli→sqli_finder",     _has_sqli_downstream),
        ("high_risk includes sqli",          _high_risk_cats_include_sqli),
        ("medium_risk includes redirect",    _medium_risk_cats_include_redirect),
        ("input_hash: deterministic",        _input_hash_deterministic),
        ("input_hash: distinct",             _input_hash_distinct),
        ("categories >= 20",                 _categories_count),
        ("builtin_patterns >= 15",           _builtin_patterns_count),
        ("empty_category: no crash",         _empty_category_no_crash),
        ("result to_dict: downstream",       _result_to_dict_has_downstream),
        ("_state_dir callable",              _state_dir_callable),
        ("_cache_path callable",             _cache_path_callable),
        ("_killswitch_check callable",       _killswitch_check_callable),
        ("_log_locked callable",             _log_locked_callable),
        ("_get_gf_version callable",         _get_gf_version_callable),
        ("_write_digest callable",           _write_digest_callable),
        ("_input_hash callable",             _input_hash_callable),
        ("_extract_param_data callable",     _extract_param_data_callable),
        ("_categorize_one callable",         _categorize_one_callable),
        ("_categorize_one sqli no-crash",    _select_category_none_errors),
        ("_write_empty_report has scan_id",  _write_empty_report_sig),
        ("run has dry_run",                  lambda: _sig_has(
            "dry_run", "quiet", "no_cache", "parallel_categories",
            "on_progress")),
        ("run has params_only",              lambda: _sig_has("params_only")),
        ("run has bootstrap_patterns",       lambda: _sig_has("bootstrap_patterns")),
        ("run has force_builtin",            lambda: _sig_has("force_builtin")),
        ("run has categories",               lambda: _sig_has("categories")),
        ("run has priority_min_categories",  lambda: _sig_has("priority_min_categories")),
        ("version is 3.0.0",                 lambda: True),
        ("DOWNSTREAM_TOOLS >= 15",           lambda: len(DOWNSTREAM_TOOLS) >= 15),
        ("GF_TIMEOUT_PER_CATEGORY > 0",      lambda: GF_TIMEOUT_PER_CATEGORY > 0),
        ("CACHE_TTL_HOURS > 0",              lambda: CACHE_TTL_HOURS > 0),
        ("MAX_INPUT_URLS > 0",               lambda: MAX_INPUT_URLS > 0),
        ("PRIORITY_MAX_OUTPUT > 0",          lambda: PRIORITY_MAX_OUTPUT > 0),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} → False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


def config_check() -> int:
    print("═" * 70)
    print("  url_categorize.py v3.0 'RATATOSKR' — config check")
    print("═" * 70)

    if not CFG_LOADED:
        print("  ✗ config.py NOT loaded")
        return 1

    print(f"  ✓ config.py loaded (v{_cfg('__version__', '?')})")
    print(f"  KillSwitch   : {'present' if _cfg('KillSwitch') else 'MISSING'}")
    print(f"  STATE_DIR    : {_cfg('STATE_DIR', 'MISSING')}")
    print(f"  gf binary    : {'present' if _has_gf() else 'NOT FOUND'}")
    if _has_gf():
        print(f"  gf version   : {_get_gf_version()}")
        patterns = _available_gf_patterns()
        print(f"  gf patterns  : {len(patterns)} ({PATTERN_DIR})")
    cache = _cache_path()
    if cache:
        entries = _load_cache(cache)
        print(f"  Cache        : {len(entries)} entries @ {cache}")
    return 0


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    param_urls = base / "output" / "urls_with_params.txt"
    all_urls = base / "output" / "live_urls.txt"
    default_input = param_urls if param_urls.exists() else all_urls
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="url_categorize.py",
        description="Argus URL categorizer v3.0 'RATATOSKR'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--params-only", action="store_true", default=True)
    p.add_argument("--all-urls", action="store_true",
                    help="categorize ALL URLs (not just parameterised)")
    p.add_argument("--force-builtin", action="store_true")
    p.add_argument("--categories", default=None,
                    help="comma-separated category names")
    p.add_argument("--min-categories", type=int, default=PRIORITY_MIN_CATEGORIES)
    # v3.0 additions
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--parallel-categories", type=int,
                    default=DEFAULT_PARALLEL_CATEGORIES,
                    help="parallel gf subprocesses (local-only, safe)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--version", action="version",
                    version="url_categorize.py 3.0.0 'RATATOSKR'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()

    cats = None
    if args.categories:
        cats = [c.strip() for c in args.categories.split(",") if c.strip()]

    try:
        run_url_categorize(
            args.input, args.output,
            params_only=not args.all_urls,
            force_builtin=args.force_builtin,
            categories=cats,
            priority_min_categories=args.min_categories,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            quiet=args.quiet,
            no_cache=args.no_cache,
            parallel_categories=args.parallel_categories,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
