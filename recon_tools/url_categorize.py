#!/usr/bin/env python3
"""
recon_tools/url_categorize.py — URL Classification by Vulnerability Class
═══════════════════════════════════════════════════════════════════════════════

The routing layer between URL harvesting and vulnerability testing.

Takes the harvested URL inventory and slices it into per-bug-class candidate
lists using `gf` (a grep wrapper with reusable pattern packs). Each finder
module then reads only its own candidate file instead of scanning the entire
URL list.

Why this exists:

  Without categorization:
    sqli_finder  → scans 5,000 URLs
    xss_finder   → scans 5,000 URLs
    ssrf_finder  → scans 5,000 URLs

  With categorization:
    sqli_finder  → reads gf_sqli.txt     (~80 URLs)
    xss_finder   → reads gf_xss.txt      (~120 URLs)
    ssrf_finder  → reads gf_ssrf.txt     (~60 URLs)

Same testing logic, dramatically better signal-to-noise ratio.

Categories are driven by `gf` pattern files in ~/.gf. If no pattern files are
present, the module can bootstrap a community set (geeknik/Gf-Patterns) or
fall back to built-in regex packs for the core bug classes.

Outputs (into `outdir`):
  • gf_sqli.txt, gf_xss.txt, gf_ssrf.txt, ...   — one file per category
  • url_categorize_priority.txt                 — URLs matching 3+ categories
  • url_categorize.json                         — full structured report

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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

GF_TIMEOUT_PER_CATEGORY = 60
MAX_INPUT_URLS          = 200000
MAX_URLS_IN_JSON        = 10000   # cap per-category URL lists in the JSON report
PRIORITY_MIN_CATEGORIES = 3      # URLs matching >= N categories go to priority list
PRIORITY_MAX_OUTPUT     = 500

# Community pattern repo used for bootstrapping
PATTERN_REPO = "https://github.com/geeknik/Gf-Patterns.git"
PATTERN_DIR  = Path.home() / ".gf"

# ── Category definitions ───────────────────────────────────────────────────
# `name` must match the gf pattern filename (name.json in ~/.gf).
# `aliases` are alternative gf names some pattern packs use.
@dataclass
class CategoryDef:
    name: str
    description: str
    vuln_classes: list[str]
    aliases: list[str] = field(default_factory=list)
    priority_weight: int = 1      # multiplier for overlap scoring


CATEGORIES: list[CategoryDef] = [
    CategoryDef(
        "sqli", "SQL Injection candidates",
        ["sqli", "nosqli"],
        aliases=["sql", "sql-injection"], priority_weight=3,
    ),
    CategoryDef(
        "xss", "Cross-Site Scripting candidates",
        ["xss", "dom_xss"],
        aliases=["cross-site-scripting"], priority_weight=3,
    ),
    CategoryDef(
        "ssrf", "Server-Side Request Forgery candidates",
        ["ssrf"], aliases=["server-side-request-forgery"], priority_weight=3,
    ),
    CategoryDef(
        "redirect", "Open Redirect candidates",
        ["open_redirect"], aliases=["open-redirect", "url-redirection"], priority_weight=2,
    ),
    CategoryDef(
        "lfi", "Local File Inclusion candidates",
        ["lfi", "path_traversal"], aliases=["file-inclusion"], priority_weight=3,
    ),
    CategoryDef(
        "rce", "Remote Code Execution candidates",
        ["rce", "command_injection"], aliases=["command-injection"], priority_weight=3,
    ),
    CategoryDef(
        "ssti", "Server-Side Template Injection candidates",
        ["ssti"], aliases=["template-injection"], priority_weight=3,
    ),
    CategoryDef(
        "idor", "Insecure Direct Object Reference candidates",
        ["idor"], aliases=["object-reference"], priority_weight=2,
    ),
    CategoryDef(
        "debug_logic", "Debug parameters and config endpoints",
        ["info_disclosure"], aliases=["debug", "debug-logic"], priority_weight=1,
    ),
    CategoryDef(
        "interestingparams", "Combined interesting parameters",
        ["broad_surface"], aliases=["interesting", "interesting-params"], priority_weight=1,
    ),
    CategoryDef(
        "graphql", "GraphQL endpoints and parameters",
        ["graphql"], aliases=[], priority_weight=2,
    ),
    CategoryDef(
        "cors", "CORS-related parameters",
        ["cors"], aliases=[], priority_weight=1,
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK PATTERNS
# ═════════════════════════════════════════════════════════════════════════════

# Used when gf is unavailable or a pattern file is missing. These are
# intentionally conservative — they match parameter NAMES, not values, to
# avoid false positives from URL-encoded content.
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
    oracle: str = ""           # "gf" | "builtin" | "none"
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
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path, params_only: bool = True) -> list[str]:
    """Load URLs from file. If params_only, keep only URLs with a query string."""
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
    """
    Clone the community pattern set into ~/.gf if no patterns exist.
    Returns True if patterns are available after the attempt.
    """
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
    """Return the set of gf pattern names available in ~/.gf."""
    if not PATTERN_DIR.exists():
        return set()
    return {p.stem for p in PATTERN_DIR.glob("*.json")}


# ═════════════════════════════════════════════════════════════════════════════
#  GF EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_gf_name(cat: CategoryDef, available: set[str]) -> Optional[str]:
    """Find the best matching gf pattern name for a category."""
    if cat.name in available:
        return cat.name
    for alias in cat.aliases:
        if alias in available:
            return alias
    return None


def _run_gf(cat_name: str, urls: list[str]) -> tuple[list[str], str]:
    """
    Run `gf <cat_name>` against the URL list.
    Returns (matched_urls, error_string).
    """
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

    matched = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    return matched, ""


# ═════════════════════════════════════════════════════════════════════════════
#  BUILT-IN FALLBACK MATCHER
# ═════════════════════════════════════════════════════════════════════════════

def _match_builtin(cat_name: str, urls: list[str]) -> list[str]:
    """Match URLs against the built-in regex pack for a category."""
    pattern = BUILTIN_PATTERNS.get(cat_name)
    if not pattern:
        return []
    return [u for u in urls if pattern.search(u)]


# ═════════════════════════════════════════════════════════════════════════════
#  OVERLAP & PRIORITY SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _build_overlap_map(category_results: list[CategoryResult]) -> dict[str, dict]:
    """
    Build a map of URL → {categories, weight, param_names}.
    URLs matching multiple high-weight categories are the highest priority.
    """
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
            # Extract parameter names
            parsed = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(parsed.query).keys():
                entry["param_names"].add(k.lower())

    return overlap


def _select_priority_urls(overlap: dict[str, dict], limit: int) -> list[dict]:
    """
    Select URLs that match >= PRIORITY_MIN_CATEGORIES categories, sorted by
    weight descending. Returns a list of dicts ready for JSON.
    """
    candidates = []
    for url, entry in overlap.items():
        if len(entry["categories"]) < PRIORITY_MIN_CATEGORIES:
            continue
        candidates.append({
            "url":         url,
            "categories":  sorted(entry["categories"]),
            "weight":      entry["weight"],
            "param_names": sorted(entry["param_names"]),
        })

    candidates.sort(key=lambda x: (-x["weight"], -len(x["categories"]), x["url"]))
    return candidates[:limit]


# ═════════════════════════════════════════════════════════════════════════════
#  PARAMETER FREQUENCY ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _param_frequency(category_results: list[CategoryResult]) -> dict[str, dict[str, int]]:
    """
    For each category, count the most frequent parameter names in its URLs.
    Tells you which parameters are the strongest recurring signal.
    """
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
) -> Path:
    """
    Categorize every URL in `urls_file` into per-bug-class candidate lists.

    Returns the path to `url_categorize.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    urls = _load_urls(urls_file, params_only=params_only)
    if len(urls) > MAX_INPUT_URLS:
        log.warning(f"  Capping at {MAX_INPUT_URLS} URLs (input had {len(urls)})")
        urls = urls[:MAX_INPUT_URLS]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}"
             f"{'  (parameterised only)' if params_only else ''}")
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
                # Fall through to builtin
                result.urls = sorted(set(_match_builtin(cat.name, urls)))
                result.oracle = "builtin" if result.urls else "none"
        else:
            result.urls = sorted(set(_match_builtin(cat.name, urls)))
            result.oracle = "builtin" if result.urls else "none"
            if gf_available and not gf_name:
                result.error = f"no gf pattern file for '{cat.name}'"

        result.duration = time.monotonic() - t0
        results.append(result)

        # Write the flat per-category file regardless of oracle
        flat_path = outdir / f"gf_{cat.name}.txt"
        flat_path.write_text(
            "\n".join(result.urls) + ("\n" if result.urls else "")
        )

        status = (
            f"✓ {result.count:>5} URL(s)"
            if result.count
            else "· 0 URL(s)"
        )
        oracle_tag = f"[{result.oracle}]" if result.oracle else ""
        err_tag = f"  ({result.error})" if result.error else ""
        log.info(f"    {cat.name:<18} {status:<14} {oracle_tag:<10}{err_tag}")

    # ── Overlap analysis ────────────────────────────────────────────────────
    log.info("")
    log.info("  Overlap analysis")

    overlap = _build_overlap_map(results)
    priority = _select_priority_urls(overlap, PRIORITY_MAX_OUTPUT)

    priority_path = outdir / "url_categorize_priority.txt"
    priority_path.write_text(
        "\n".join(p["url"] for p in priority) + ("\n" if priority else "")
    )

    multi_cat = sum(1 for e in overlap.values() if len(e["categories"]) >= 2)
    log.info(f"    URLs matching 2+ categories : {multi_cat}")
    log.info(f"    URLs matching 3+ categories : {len(priority)}")

    # ── Parameter frequency ─────────────────────────────────────────────────
    param_freq = _param_frequency(results)

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start

    total_category_hits = sum(r.count for r in results)
    unique_urls_hit = len(overlap)

    by_oracle: dict[str, int] = {}
    for r in results:
        key = r.oracle or "none"
        by_oracle[key] = by_oracle.get(key, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "params_only":         params_only,
            "gf_available":        gf_available,
            "available_patterns":  sorted(available_patterns),
            "force_builtin":       force_builtin,
            "priority_min_categories": PRIORITY_MIN_CATEGORIES,
            "categories_selected": [c.name for c in selected],
        },
        "totals": {
            "urls_input":            len(urls),
            "unique_urls_categorized": unique_urls_hit,
            "total_category_hits":   total_category_hits,
            "urls_in_2plus_categories": multi_cat,
            "priority_urls":         len(priority),
        },
        "by_oracle": by_oracle,
        "categories": [r.to_dict() for r in results],
        "param_frequency": param_freq,
        "priority_urls": priority,
    }

    json_path = outdir / "url_categorize.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    for r in results:
        log.info(f"    gf_{r.name:<18} {r.count:>6} URL(s)")
    log.info(f"    {'url_categorize_priority.txt':<28} {len(priority):>6} URL(s)")

    # Top parameters per high-value category
    for cat_name in ("sqli", "xss", "ssrf", "redirect"):
        freq = param_freq.get(cat_name, {})
        if freq:
            top = list(freq.items())[:6]
            log.info("")
            log.info(f"  Top {cat_name} parameters : "
                     + " · ".join(f"{k}({v})" for k, v in top))

    if priority:
        log.info("")
        log.info("  Highest-priority URLs (3+ category overlap):")
        for p in priority[:10]:
            cats = ",".join(p["categories"])
            log.info(f"    {p['weight']:>3}  {p['url'][:90]:<90}  [{cats}]")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": 0, "unique_urls_categorized": 0,
            "total_category_hits": 0, "urls_in_2plus_categories": 0,
            "priority_urls": 0,
        },
        "by_oracle": {},
        "categories": [],
        "param_frequency": {},
        "priority_urls": [],
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
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    # Prefer the parameterised list, fall back to all URLs
    param_urls = base / "output" / "urls_with_params.txt"
    all_urls   = base / "output" / "all_urls.txt"
    source = param_urls if param_urls.exists() else all_urls
    out = base / "output"

    try:
        run_url_categorize(source, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
