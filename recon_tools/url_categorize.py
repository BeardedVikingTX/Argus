#!/usr/bin/env python3
"""
recon_tools/url_categorize.py — URL Classification by Vulnerability Class
═══════════════════════════════════════════════════════════════════════════════

The routing layer between URL harvesting and vulnerability testing.

Takes the harvested URL inventory and slices it into per-bug-class candidate
lists using `gf` (a grep wrapper with reusable pattern packs). Each finder
module then reads only its own candidate file instead of scanning the entire
URL list.

THIS IS LOCAL-ONLY. No HTTP requests are made.
──────────────────────────────────────────────
  ✗ Platform headers (ACTIVE_HEADERS) are NOT applicable — gf is local
  ✗ request.txt auth (AUTH_HEADERS, AUTH_COOKIES) is NOT applicable
  ✗ Rate limits are NOT applicable — gf is a local grep process

Config integration (config.py):
  • SYNC_TO_DB, BRIDGE_* → remote database sync

Categories are driven by `gf` pattern files in ~/.gf. If no pattern files are
present, the module can bootstrap a community set (geeknik/Gf-Patterns) or
fall back to built-in regex packs.

Outputs (into `outdir`):
  • gf_sqli.txt, gf_xss.txt, ...       — one file per category
  • url_categorize_priority.txt        — URLs matching 3+ categories
  • url_categorize.json                — full structured report

Remote DB (if scan_id is provided):
  • url_categorize table               — one row per URL with its category data

Integration:
  main.py → run_one("categorize") → run_url_categorize(urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.url_categorize")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═════════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None
    CFG_LOADED = False

try:
    from db import DB
    DB_AVAILABLE = True
except ImportError:
    DB = None
    DB_AVAILABLE = False


def _cfg(key: str, default=None):
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

GF_TIMEOUT_PER_CATEGORY = 60
MAX_INPUT_URLS          = 200000
MAX_URLS_IN_JSON        = 10000
PRIORITY_MIN_CATEGORIES = 3
PRIORITY_MAX_OUTPUT     = 500

PATTERN_REPO = "https://github.com/geeknik/Gf-Patterns.git"
PATTERN_DIR  = Path.home() / ".gf"

# Categories that trigger higher weight when matched
HIGH_RISK_CATEGORIES = {
    "sqli", "ssrf", "rce", "lfi", "ssti", "idor", "xss",
}
MEDIUM_RISK_CATEGORIES = {
    "redirect", "graphql", "oauth", "upload", "api", "jwts",
}


# ═════════════════════════════════════════════════════════════════════════════
#  CATEGORY DEFINITIONS (expanded)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CategoryDef:
    name: str
    description: str
    vuln_classes: list[str]
    aliases: list[str] = field(default_factory=list)
    priority_weight: int = 1


CATEGORIES: list[CategoryDef] = [
    # ── Tier 1 — injection classes ─────────────────────────────────────────
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

    # ── Tier 2 — logic / access ────────────────────────────────────────────
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

    # ── Tier 3 — disclosure / recon ────────────────────────────────────────
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


# ═════════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK PATTERNS
# ═════════════════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

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
            "urls":         self.urls[:MAX_URLS_IN_JSON],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path, params_only: bool = True) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    urls: list[str] = []
    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
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


# ═════════════════════════════════════════════════════════════════════════════
#  PATTERN BOOTSTRAP
# ═════════════════════════════════════════════════════════════════════════════

def _pattern_files_present() -> bool:
    if not PATTERN_DIR.exists():
        return False
    return any(PATTERN_DIR.glob("*.json"))


def _bootstrap_patterns() -> bool:
    if _pattern_files_present():
        log.info(f"    Pattern dir: {PATTERN_DIR} "
                 f"({len(list(PATTERN_DIR.glob('*.json')))} file(s))")
        return True

    if not shutil.which("git"):
        log.warning("    git not installed — cannot bootstrap gf patterns")
        return False

    log.info(f"    No gf patterns found — cloning {PATTERN_REPO}...")
    PATTERN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PATTERN_DIR / "_bootstrap_tmp"

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", PATTERN_REPO, str(tmp)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            log.warning(f"    pattern clone failed: {result.stderr.strip()[:160]}")
            return False

        moved = 0
        for f in tmp.glob("*.json"):
            dest = PATTERN_DIR / f.name
            if not dest.exists():
                shutil.copy2(f, dest)
                moved += 1

        shutil.rmtree(tmp, ignore_errors=True)
        log.info(f"    Bootstrapped {moved} pattern file(s) into {PATTERN_DIR}")
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


# ═════════════════════════════════════════════════════════════════════════════
#  GF EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK
# ═════════════════════════════════════════════════════════════════════════════

def _match_builtin(cat_name: str, urls: list[str]) -> list[str]:
    pattern = BUILTIN_PATTERNS.get(cat_name)
    if not pattern:
        return []
    return [u for u in urls if pattern.search(u)]


# ═════════════════════════════════════════════════════════════════════════════
#  OVERLAP & PRIORITY
# ═════════════════════════════════════════════════════════════════════════════

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
    overlap: dict[str, dict], limit: int, min_categories: int = PRIORITY_MIN_CATEGORIES,
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

    # Sort by (weight, high_risk_count, category_count) then by URL
    candidates.sort(key=lambda x: (
        -x["weight"], -x["high_risk_count"], -x["category_count"], x["url"],
    ))
    return candidates[:limit]


# ═════════════════════════════════════════════════════════════════════════════
#  PARAMETER FREQUENCY + RISK TIERS
# ═════════════════════════════════════════════════════════════════════════════

def _param_frequency(category_results: list[CategoryResult]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for result in category_results:
        counter: Counter[str] = Counter()
        for url in result.urls:
            parsed = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(parsed.query).keys():
                counter[k.lower()] += 1
        if counter:
            out[result.name] = dict(counter.most_common(30))
    return out


def _param_risk_tiers(
    category_results: list[CategoryResult],
) -> dict[str, dict]:
    """
    For each unique parameter name across all categories, compute:
      • categories — which vuln classes it appears in
      • total_urls — how many URLs total carry this param
      • tier       — CRITICAL | HIGH | MEDIUM | LOW based on category spread

    A param that appears in sqli + xss + ssrf across 50 URLs is CRITICAL.
    A param that only appears in `interestingparams` is LOW.
    """
    param_to_categories: dict[str, set[str]] = {}
    param_url_count: Counter[str] = Counter()

    for result in category_results:
        if not result.urls:
            continue
        for url in result.urls:
            parsed = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(parsed.query).keys():
                key = k.lower()
                param_to_categories.setdefault(key, set()).add(result.name)
                param_url_count[key] += 1

    out: dict[str, dict] = {}
    for param, cats in param_to_categories.items():
        high_count = len(cats.intersection(HIGH_RISK_CATEGORIES))
        medium_count = len(cats.intersection(MEDIUM_RISK_CATEGORIES))

        if high_count >= 2:
            tier = "CRITICAL"
        elif high_count == 1 and medium_count >= 1:
            tier = "HIGH"
        elif high_count == 1 or medium_count >= 2:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        out[param] = {
            "categories":     sorted(cats),
            "high_risk_count": high_count,
            "medium_risk_count": medium_count,
            "url_count":      param_url_count[param],
            "tier":           tier,
        }

    # Sort by tier then url_count
    tier_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out = dict(sorted(
        out.items(),
        key=lambda kv: (tier_order.get(kv[1]["tier"], 4), -kv[1]["url_count"]),
    ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

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
    if not DB.available:
        log.warning("  DB sync: bridge client not ready")
        return

    # Build URL → entry map from priority list + per-category lists
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
        cat_weight = 3 if result.name in HIGH_RISK_CATEGORIES else (
            2 if result.name in MEDIUM_RISK_CATEGORIES else 1
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

    # Fill in param_names if missing, recompute high_risk_count
    for url, entry in url_map.items():
        if not entry["param_names"]:
            parsed = urllib.parse.urlparse(url)
            entry["param_names"] = list(urllib.parse.parse_qs(parsed.query).keys())
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


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_url_categorize(
    urls_file: Path,
    outdir: Path,
    *,
    params_only: bool = True,
    bootstrap_patterns: bool = True,
    force_builtin: bool = False,
    categories: Optional[list[str]] = None,
    priority_min_categories: int = PRIORITY_MIN_CATEGORIES,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Categorize every URL in `urls_file` into per-bug-class candidate lists.

    Returns the path to `url_categorize.json`.
    """
    start = time.monotonic()

    urls = _load_urls(urls_file, params_only=params_only)
    if len(urls) > MAX_INPUT_URLS:
        log.warning(f"  Capping at {MAX_INPUT_URLS} URLs (input had {len(urls)})")
        urls = urls[:MAX_INPUT_URLS]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}"
             f"{'  (parameterised only)' if params_only else ''}")
    log.info(f"  Note   : local-only stage — no headers or auth applied "
             f"(gf runs locally)")
    log.info("")

    if not urls:
        log.warning("  No URLs to categorize — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    # ── Pattern setup ───────────────────────────────────────────────────────
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

    # ── Select categories ───────────────────────────────────────────────────
    selected: list[CategoryDef] = CATEGORIES
    if categories:
        wanted = {c.strip().lower() for c in categories if c.strip()}
        selected = [c for c in CATEGORIES if c.name in wanted]
        if not selected:
            log.error(f"  No matching categories: {', '.join(sorted(wanted))}")
            return _write_empty_report(outdir, urls_file, start)

    # ── Run categorization ──────────────────────────────────────────────────
    log.info(f"  Categorizing {len(urls)} URL(s) across {len(selected)} category(ies)...")

    results: list[CategoryResult] = []
    for cat in selected:
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
        results.append(result)

        # Write per-category flat file
        flat_path = outdir / f"gf_{cat.name}.txt"
        flat_path.write_text(
            "\n".join(result.urls) + ("\n" if result.urls else "")
        )

        status = f"✓ {result.count:>5} URL(s)" if result.count else "· 0 URL(s)"
        oracle_tag = f"[{result.oracle}]" if result.oracle else ""
        err_tag = f"  ({result.error})" if result.error else ""
        log.info(f"    {cat.name:<20} {status:<14} {oracle_tag:<10}{err_tag}")

    # ── Overlap analysis ────────────────────────────────────────────────────
    log.info("")
    log.info("  Overlap analysis")

    overlap = _build_overlap_map(results)
    priority = _select_priority_urls(overlap, PRIORITY_MAX_OUTPUT, priority_min_categories)

    priority_path = outdir / "url_categorize_priority.txt"
    priority_path.write_text(
        "\n".join(p["url"] for p in priority) + ("\n" if priority else "")
    )

    multi_cat = sum(1 for e in overlap.values() if len(e["categories"]) >= 2)
    high_risk_urls = sum(
        1 for e in overlap.values()
        if e["categories"].intersection(HIGH_RISK_CATEGORIES)
    )

    log.info(f"    URLs matching 2+ categories  : {multi_cat}")
    log.info(f"    URLs matching {priority_min_categories}+ categories  : {len(priority)}")
    log.info(f"    URLs with high-risk category : {high_risk_urls}")

    # ── Param frequency + risk tiers ────────────────────────────────────────
    param_freq = _param_frequency(results)
    param_tiers = _param_risk_tiers(results)

    # ── Report ──────────────────────────────────────────────────────────────
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "params_only":              params_only,
            "gf_available":             gf_available,
            "available_patterns":       sorted(available_patterns),
            "force_builtin":            force_builtin,
            "priority_min_categories":  priority_min_categories,
            "categories_selected":      [c.name for c in selected],
            "headers_applied":          False,
            "note":                     "local-only stage — no HTTP requests, "
                                        "no headers or auth",
        },
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
        "by_oracle": by_oracle,
        "categories": [r.to_dict() for r in results],
        "param_frequency": param_freq,
        "param_tiers": param_tiers,
        "priority_urls": priority,
    }

    json_path = outdir / "url_categorize.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, priority, results)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    for r in results:
        if r.count:
            log.info(f"    gf_{r.name:<20} {r.count:>6} URL(s)")
    log.info(f"    {'url_categorize_priority.txt':<30} {len(priority):>6} URL(s)")

    # Top parameters per high-value category
    for cat_name in ("sqli", "xss", "ssrf", "redirect"):
        freq = param_freq.get(cat_name, {})
        if freq:
            top = list(freq.items())[:6]
            log.info("")
            log.info(f"  Top {cat_name} parameters : "
                     + " · ".join(f"{k}({v})" for k, v in top))

    # Top risk-tier parameters
    critical_params = [
        (name, data) for name, data in param_tiers.items() if data["tier"] == "CRITICAL"
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

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(input_file),
        "config":          {},
        "totals": {
            "urls_input": 0, "unique_urls_categorized": 0,
            "total_category_hits": 0, "urls_in_2plus_categories": 0,
            "urls_with_high_risk": 0, "priority_urls": 0,
            "unique_param_names": 0, "param_tiers": {},
        },
        "by_oracle":       {},
        "categories":      [],
        "param_frequency": {},
        "param_tiers":     {},
        "priority_urls":   [],
    }
    path = outdir / "url_categorize.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "url_categorize_priority.txt").write_text("")
    for cat in CATEGORIES:
        (outdir / f"gf_{cat.name}.txt").write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE TEST
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    param_urls = base / "output" / "urls_with_params.txt"
    all_urls   = base / "output" / "all_urls.txt"
    default_input = param_urls if param_urls.exists() else all_urls
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus URL categorize (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--params-only", action="store_true", default=True)
    parser.add_argument("--all-urls", action="store_true",
                        help="categorize ALL URLs, not just parameterised")
    parser.add_argument("--force-builtin", action="store_true")
    parser.add_argument("--categories", help="comma-separated category names")
    parser.add_argument("--min-categories", type=int, default=PRIORITY_MIN_CATEGORIES)
    args = parser.parse_args()

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
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
