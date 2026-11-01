#!/usr/bin/env python3
"""
main.py — A R G U S  v3.0
═══════════════════════════════════════════════════════════════════════════════

The all-seeing watchman of the digital longship.

Pipeline (26 stages):
    RECON     :  subs → dns → takeover → live → nmap
    HARVEST   :  urls → categorize
    DISCOVER  :  js → params → graphql → fuzz
    SCAN      :  nuclei → cors → smuggling → cache
    AUDIT     :  auth → idor → redirect → race
                 → sqli → xss → ssrf → ssti → xxe
    REPORT    :  mapping → triage

Persistence:
    Every stage writes local JSON to output/ (always).
    If config.py + db.py are present and the bridge is reachable,
    the same findings are synced to the remote MySQL database
    via bug-bounty.beardedviking.org/api.php (opt-in).

Argus does not exploit. Argus surfaces. Every finding is a candidate — a
flag on a map that says "look here, human." Manual triage is the point.

Usage:
    python3 main.py                          run all stages
    python3 main.py --stage recon            recon group only
    python3 main.py --stage audit            all audit stages
    python3 main.py --stage quick            fast pass: recon → urls → triage
    python3 main.py --stage all --skip fuzz  full run minus the loud stages
    python3 main.py --dry-run                preview, no execution
    python3 main.py --stages                 list stage identifiers
    python3 main.py --scan-id <uuid>         resume an existing scan
    python3 main.py --no-db                  skip remote DB sync
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import urllib.parse
import uuid as _uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG — optional, graceful degradation
# ═════════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None
    CFG_LOADED = False

try:
    from db import DB, ArgusDB
    DB_MODULE_AVAILABLE = True
except ImportError:
    DB = None
    ArgusDB = None  # type: ignore
    DB_MODULE_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    """Read a config value with a fallback."""
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


# ═════════════════════════════════════════════════════════════════════════════
#  METADATA
# ═════════════════════════════════════════════════════════════════════════════

VERSION  = "3.0.0"
CODENAME = "Raven's Flight"
AUTHOR   = "BeardedVikingTX"
REPO     = "https://github.com/BeardedVikingTX/Argus"

# ═════════════════════════════════════════════════════════════════════════════
#  PATHS
# ═════════════════════════════════════════════════════════════════════════════

BASE_DIR      = Path(__file__).parent
OUTPUT_DIR    = BASE_DIR / "output"
WILDCARD_FILE = Path(_cfg("SCOPE_FILE", BASE_DIR / "wildcard.txt"))
LOG_FILE      = OUTPUT_DIR / "argus.log"

# ═════════════════════════════════════════════════════════════════════════════
#  TERMINAL PALETTE
# ═════════════════════════════════════════════════════════════════════════════

_USE_COLOR = True

C = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[90m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "blue":    "\033[34m",
    "cyan":    "\033[36m",
    "magenta": "\033[35m",
    "white":   "\033[97m",
}

S = {
    "sword":      "⚔",
    "shield":     "⛨",
    "rune_odin":  "ᛟ",
    "rune_thur":  "ᚦ",
    "rune_algiz": "ᛉ",
    "arrow_r":    "▸",
    "arrow_l":    "◂",
    "check":      "✓",
    "cross":      "✗",
    "warn":       "⚠",
    "dot_full":   "●",
    "dot_empty":  "○",
    "db":         "⛁",
}

RUNES = "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃᛇᛈᛉᛊᛏᛒᛖᛗᛚᛜᛞᛟ"

ARGUS_ART = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""


def c(color: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{C.get(color, '')}{text}{C['reset']}"

def bold(t):    return c("bold", t)
def dim(t):     return c("dim", t)
def cyan(t):    return c("cyan", t)
def yellow(t):  return c("yellow", t)
def green(t):   return c("green", t)
def red(t):     return c("red", t)
def magenta(t): return c("magenta", t)

def hline(char="═", width=71, color="cyan"):
    return c(color, char * width)

def gap():
    print()


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE DEFINITIONS — all 26 stages
# ═════════════════════════════════════════════════════════════════════════════

STAGE_META = {
    # ── Recon ───────────────────────────────────────────────────────────────
    "subs":       ("RECON",     "Subdomain Enumeration"),
    "dns":        ("RECON",     "DNS Resolution"),
    "takeover":   ("RECON",     "Subdomain Takeover Check"),
    "live":       ("RECON",     "Live Host Discovery"),
    "nmap":       ("RECON",     "Port & Service Scan"),
    # ── Harvest ─────────────────────────────────────────────────────────────
    "urls":       ("HARVEST",   "URL Harvesting"),
    "categorize": ("HARVEST",   "URL Categorization"),
    "crawl":      ("HARVEST",   "Site Crawler"),
    # ── Discover ────────────────────────────────────────────────────────────
    "js":         ("DISCOVER",  "JavaScript Analysis"),
    "params":     ("DISCOVER",  "Parameter Discovery"),
    "graphql":    ("DISCOVER",  "GraphQL Audit"),
    "fuzz":       ("DISCOVER",  "Content Fuzzing"),
    # ── Scan ────────────────────────────────────────────────────────────────
    "nuclei":     ("SCAN",      "Vulnerability Scanning"),
    "cors":       ("SCAN",      "CORS Misconfiguration Check"),
    "smuggling":  ("SCAN",      "HTTP Request Smuggling"),
    "cache":      ("SCAN",      "Cache Poisoning & Deception"),
    # ── Audit ───────────────────────────────────────────────────────────────
    "auth":       ("AUDIT",     "Authentication Testing"),
    "idor":       ("AUDIT",     "IDOR / BOLA Audit"),
    "redirect":   ("AUDIT",     "Open Redirect Audit"),
    "race":       ("AUDIT",     "Race Condition Surface"),
    "sqli":       ("AUDIT",     "SQL Injection Audit"),
    "xss":        ("AUDIT",     "XSS Audit"),
    "ssrf":       ("AUDIT",     "SSRF Audit"),
    "ssti":       ("AUDIT",     "SSTI Audit"),
    "xxe":        ("AUDIT",     "XXE Audit"),
    # ── Report ──────────────────────────────────────────────────────────────
    "mapping":    ("REPORT",    "Site Map Consolidation"),
    "triage":     ("REPORT",    "Finding Aggregation & Prioritization"),
}

STAGE_GROUPS = {
    "recon":    ["subs", "dns", "takeover", "live", "nmap"],
    "harvest":  ["urls", "categorize"],
    "discover": ["js", "params", "graphql", "fuzz"],
    "scan":     ["nuclei", "cors", "smuggling", "cache"],
    "audit":    ["auth", "idor", "redirect", "race",
                 "sqli", "xss", "ssrf", "ssti", "xxe"],
    "report":   ["mapping", "triage"],
    "quick":    ["subs", "dns", "live", "urls", "categorize", "triage"],
    "all": [
        "subs", "dns", "takeover", "live", "nmap",
        "urls", "categorize",
        "js", "params", "graphql", "crawl", "fuzz",
        "nuclei", "cors", "smuggling", "cache",
        "auth", "idor", "redirect", "race",
        "sqli", "xss", "ssrf", "ssti", "xxe",
        "mapping", "triage",
    ],
}

STAGE_DEPS = {
    "dns":        "subs",
    "takeover":   "subs",
    "live":       "subs",
    "nmap":       "live",
    "crawl":      "live",
    "urls":       "live",
    "categorize": "urls",
    "js":         "urls",
    "params":     "urls",
    "graphql":    "urls",
    "fuzz":       "live",
    "nuclei":     "live",
    "cors":       "live",
    "smuggling":  "live",
    "cache":      "urls",
    "auth":       "live",
    "idor":       "urls",
    "redirect":   "urls",
    "race":       "urls",
    "sqli":       "urls",
    "xss":        "urls",
    "ssrf":       "urls",
    "ssti":       "urls",
    "xxe":        "urls",
    "mapping":    "live",
    "triage":     None,
}

GROUP_ORDER = ["RECON", "HARVEST", "DISCOVER", "SCAN", "AUDIT", "REPORT"]

# Stages that produce a findings JSON the DB cares about
# Routing — only stages that fall through to the generic `findings` table.
# MUST NOT overlap RECON_JSON_MAP or _SPECIAL_SYNC_STAGES.
FINDINGS_JSON_MAP = {
    "cors":      "cors_findings.json",
    "smuggling": "smuggling_findings.json",
    "idor":      "idor_findings.json",
    "redirect":  "open_redirect_findings.json",
    "race":      "race_findings.json",
    "sqli":      "sqli_findings.json",
    "xss":       "xss_findings.json",
    "ssrf":      "ssrf_findings.json",
    "ssti":      "ssti_findings.json",
    "xxe":       "xxe_findings.json",
}

# Aggregation — every findings-shaped JSON, regardless of DB routing.
# Used only by _aggregate_severity() and _top_findings().
AGGREGATION_JSON_MAP = {
    **FINDINGS_JSON_MAP,
    "takeover": "takeover_findings.json",
    "js":       "js_findings.json",
    "nuclei":   "nuclei_findings.json",
}

# Artifacts each stage typically writes — used for stage records and the final briefing
STAGE_ARTIFACTS = {
    "subs":       ["all_subs.txt", "subdomains.json", "subs_resolved.txt"],
    "dns":        ["dns_resolve.json", "dns_resolved.txt",
                   "dns_wildcard_filtered.txt", "dns_takeover_candidates.txt"],
    "takeover":   ["takeover_findings.json", "takeover_vulnerable.txt",
                   "takeover_potential.txt", "takeover_cnames.txt"],
    "live":       ["live_hosts.json", "live_hosts.txt", "live_urls.txt"],
    "nmap":       ["nmap_scan.json", "nmap_open_ports.txt", "nmap_interesting.txt"],
    "urls":       ["url_harvest.json", "all_urls.txt", "urls_with_params.txt",
                   "urls_js_files.txt", "urls_interesting.txt"],
    "categorize": ["url_categorize.json", "url_categorize_priority.txt"],
    "js":         ["js_findings.json", "js_endpoints.txt", "js_secrets.txt",
                   "js_sourcemaps.txt"],
    "params":     ["param_findings.json", "params_by_endpoint.txt"],
    "graphql":    ["graphql_findings.json", "graphql_schema.json"],
    "fuzz":       ["content_fuzz.json", "fuzzed_directories.txt",
                   "fuzzed_interesting.txt"],
    "nuclei":     ["nuclei_findings.json", "nuclei_critical.txt", "nuclei_all.txt"],
    "cors":       ["cors_findings.json", "cors_critical.txt"],
    "smuggling":  ["smuggling_findings.json", "smuggling_candidates.txt"],
    "cache":      ["cache_findings.json", "cache_candidates.txt"],
    "auth":       ["auth_findings.json", "auth_candidates.txt"],
    "idor":       ["idor_findings.json", "idor_candidates.txt", "idor_confirmed.txt"],
    "redirect":   ["open_redirect_findings.json", "open_redirect_candidates.txt"],
    "race":       ["race_findings.json", "race_candidates.txt"],
    "sqli":       ["sqli_findings.json", "sqli_candidates.txt", "sqli_confirmed.txt"],
    "xss":        ["xss_findings.json", "xss_candidates.txt", "xss_confirmed.txt"],
    "ssrf":       ["ssrf_findings.json", "ssrf_candidates.txt", "ssrf_confirmed.txt"],
    "ssti":       ["ssti_findings.json", "ssti_candidates.txt", "ssti_confirmed.txt"],
    "xxe":        ["xxe_findings.json", "xxe_candidates.txt", "xxe_confirmed.txt"],
    "mapping":    ["site_map.json", "site_map.md", "site_map_hosts.txt"],
    "triage":     ["triage_report.json", "triage_priority.md",
                   "triage_next_steps.txt"],
    "crawl":      ["site_pages.json", "site_pages.txt", "auth_pages.txt"],
}

# Recon artifacts use a different schema than findings.
# Keyed by stage → (json filename, DB table kind).
RECON_JSON_MAP: dict[str, tuple[str, str]] = {
    "subs":       ("subdomains.json",        "subdomains"),
    "dns":        ("dns_resolve.json",       "dns_records"),
    "takeover":   ("takeover_findings.json", "takeover_findings"),
    "live":       ("live_hosts.json",        "live_hosts"),
    "urls":       ("url_harvest.json",       "urls"),
    "categorize": ("url_categorize.json",    "url_categorize"),
    "crawl":      ("site_pages.json",        "site_pages"),
    "fuzz":       ("content_fuzz.json",      "content_fuzz"),
    "js":         ("js_findings.json",       "js_findings"),
    "nmap":       ("nmap_scan.json",         "nmap"),
    "nuclei":     ("nuclei_findings.json",   "nuclei"),
    "params":     ("param_findings.json",    "param_findings"),
}

def resolve_stages(arg: str) -> list[str]:
    if arg in STAGE_GROUPS:
        return list(STAGE_GROUPS[arg])
    if arg in STAGE_META:
        return [arg]
    if "," in arg:
        result: list[str] = []
        for piece in arg.split(","):
            piece = piece.strip()
            if not piece:
                continue
            if piece in STAGE_GROUPS:
                result.extend(STAGE_GROUPS[piece])
            elif piece in STAGE_META:
                result.append(piece)
            else:
                raise ValueError(f"Unknown stage or group: {piece}")
        seen: set[str] = set()
        deduped: list[str] = []
        for s in result:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        return deduped
    raise ValueError(f"Unknown stage or group: {arg}")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER / BRIEFING PANELS
# ═════════════════════════════════════════════════════════════════════════════

def show_banner():
    gap()
    for line in ARGUS_ART.strip("\n").splitlines():
        print("   " + c("cyan", line))
    gap()
    print("      " + yellow(f"{S['sword']}  the all-seeing watchman of the digital longship  {S['sword']}"))
    print("              " + dim(RUNES))
    gap()
    print("   " + dim(f"v{VERSION}  ·  {CODENAME}  ·  {AUTHOR}"))
    print("   " + dim(REPO))
    gap()


def show_briefing(wildcards, stage_list, outdir, dry_run, fail_fast,
                  db_status: str, platform: str):

    gap()
    print("  " + hline("═", 71, "cyan"))
    print("  " + bold(f"{S['sword']}  RAID BRIEFING"))
    print("  " + hline("═", 71, "cyan"))
    gap()

    print(f"  {cyan(S['shield'])}  Wildcards    : {bold(str(len(wildcards)))} domain(s)")
    for w in wildcards:
        print(f"                  {dim('·')} {w}")

    mode = "DRY-RUN" if dry_run else "LIVE-FIRE"
    mode_fn = yellow if dry_run else red

    print(f"  {cyan(S['shield'])}  Mode         : {mode_fn(mode)}")
    if fail_fast:
        print(f"  {cyan(S['shield'])}  On failure   : {yellow('FAIL-FAST')}")

    print(f"  {cyan(S['shield'])}  Platform     : {bold(platform) if platform else dim('(none)')}")
    print(f"  {cyan(S['shield'])}  Database     : {db_status}")
    print(f"  {cyan(S['shield'])}  Stage(s)     : {bold(str(len(stage_list)))} sub-stage(s)")
    print(f"  {cyan(S['shield'])}  Output       : {dim(str(outdir))}")
    print(f"  {cyan(S['shield'])}  Log          : {dim(str(LOG_FILE))}")
    gap()

    preview = " → ".join(stage_list)
    if len(preview) > 66:
        preview = preview[:63] + "..."
    print(f"  {cyan(S['shield'])}  Pipeline     : {dim(preview)}")
    gap()

    print("  " + hline("─", 71, "dim"))
    print(f"  {magenta(S['rune_odin'])}  Raid begins at {bold(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print("  " + hline("═", 71, "cyan"))
    gap()


def show_stage_header(index: int, total: int, key: str) -> None:
    category, title = STAGE_META[key]
    gap()
    print("  " + hline("═", 71, "cyan"))
    print(f"  {c('cyan', S['sword'])}  [{bold(f'{index:02d}')} / {bold(f'{total:02d}')}]   "
          f"{c('magenta', category):<20}   ::   {bold(title)}")
    print("  " + hline("═", 71, "cyan"))
    gap()


def show_stage_result(key: str, result: str) -> None:
    _, title = STAGE_META[key]
    if result == "ok":
        print(f"\n  {green(S['check'])}  {title}  {dim('complete')}")
    elif result == "skipped":
        print(f"\n  {dim(S['arrow_r'])}  {title}  {dim('skipped')}")
    elif result == "missing":
        print(f"\n  {yellow(S['warn'])}  {title}  {dim('module not yet implemented')}")
    else:
        print(f"\n  {red(S['cross'])}  {title}  {red('FAILED')}")
    gap()


ARTIFACT_GROUPS = {
    "RECON": [
        ("all_subs.txt",                "Subdomains"),
        ("subdomains.json",             "Subdomain attribution"),
        ("dns_wildcard_filtered.txt",   "DNS (clean)"),
        ("takeover_vulnerable.txt",     "Takeover CONFIRMED"),
        ("live_hosts.txt",              "Live hosts"),
        ("live_hosts.json",             "Live hosts (JSON)"),
        ("nmap_interesting.txt",        "Interesting hosts"),
        ("nmap_open_ports.txt",         "Open ports"),
    ],
    "HARVEST": [
        ("all_urls.txt",                "All URLs"),
        ("urls_with_params.txt",        "URLs w/ params"),
        ("urls_js_files.txt",           "JS files"),
        ("urls_interesting.txt",        "Interesting URLs"),
        ("url_categorize_priority.txt", "Priority URLs"),
    ],
    "DISCOVER": [
        ("js_secrets.txt",              "JS secrets"),
        ("js_endpoints.txt",            "JS endpoints"),
        ("params_by_endpoint.txt",      "Parameters"),
        ("graphql_findings.json",       "GraphQL report"),
        ("site_pages.json",             "Crawled pages"),
        ("auth_pages.txt",              "Auth pages found"),
        ("fuzzed_interesting.txt",      "Interesting paths"),
    ],
    "SCAN": [
        ("nuclei_critical.txt",         "Nuclei CRIT/HIGH"),
        ("cors_critical.txt",           "CORS CRIT/HIGH"),
        ("smuggling_confirmed.txt",     "Smuggling confirmed"),
        ("cache_findings.json",         "Cache findings"),
    ],
    "AUDIT": [
        ("auth_findings.json",          "Auth findings"),
        ("idor_confirmed.txt",          "IDOR confirmed"),
        ("open_redirect_findings.json", "Redirect findings"),
        ("race_candidates.txt",         "Race candidates"),
        ("sqli_confirmed.txt",          "SQLi confirmed"),
        ("xss_confirmed.txt",           "XSS confirmed"),
        ("ssrf_confirmed.txt",          "SSRF confirmed"),
        ("ssti_confirmed.txt",          "SSTI confirmed"),
        ("xxe_confirmed.txt",           "XXE confirmed"),
    ],
    "REPORT": [
        ("site_map.md",                 "Site map (markdown)"),
        ("triage_priority.md",          "Triage markdown"),
        ("triage_report.json",          "Triage report"),
        ("triage_next_steps.txt",       "Next steps"),
    ],
}


# ═════════════════════════════════════════════════════════════════════════════
#  FINDINGS AGGREGATION FOR THE FINAL BRIEFING
# ═════════════════════════════════════════════════════════════════════════════

def _aggregate_severity(outdir: Path) -> dict[str, int]:
    """Sum up CRITICAL/HIGH/MEDIUM/LOW/INFO across every finder JSON."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for stage, fname in AGGREGATION_JSON_MAP.items():    # ← was FINDINGS_JSON_MAP
        p = outdir / fname
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        raw = data.get("findings") or data.get("candidates") or []
        if not isinstance(raw, list):
            continue
        for f in raw:
            if not isinstance(f, dict):
                continue
            sev = (f.get("severity") or "INFO").upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1
    return counts


def _top_findings(outdir: Path, n: int = 5) -> list[dict]:
    """Pull the top N findings by severity across all finder JSONs."""
    all_findings: list[dict] = []
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for stage, fname in AGGREGATION_JSON_MAP.items():    # ← was FINDINGS_JSON_MAP
        p = outdir / fname
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        raw = data.get("findings") or data.get("candidates") or []
        if not isinstance(raw, list):
            continue
        for f in raw:
            if not isinstance(f, dict):
                continue
            all_findings.append({
                "stage":    stage,
                "severity": (f.get("severity") or "INFO").upper(),
                "type":     f.get("vuln_type") or f.get("technique")
                            or f.get("template_id") or stage,
                "target":   f.get("target") or f.get("matched_at")
                            or f.get("url") or "",
                "evidence": (f.get("evidence") or "")[:100],
            })

    all_findings.sort(key=lambda x: (
        sev_rank.get(x["severity"], 5),
        x["target"],
    ))
    return all_findings[:n]


def show_final_briefing(results: dict[str, str], outdir: Path,
                        scan_uuid: str, db_scan_id: Optional[int],
                        db_failures: int) -> None:
    gap()
    print("  " + hline("═", 71, "cyan"))
    print("  " + bold(f"{S['sword']}  RAID COMPLETE"))
    print("  " + hline("═", 71, "cyan"))
    gap()

    counts: dict[str, int] = {"ok": 0, "skipped": 0, "missing": 0, "failed": 0}
    for r in results.values():
        counts[r] = counts.get(r, 0) + 1

    print(f"  {green(S['check'])}  Completed    :  {bold(str(counts['ok']))}")
    if counts["skipped"]:
        print(f"  {dim(S['arrow_r'])}  Skipped      :  {dim(str(counts['skipped']))}")
    if counts["missing"]:
        print(f"  {yellow(S['warn'])}  Not ready    :  {yellow(str(counts['missing']))}")
    if counts["failed"]:
        print(f"  {red(S['cross'])}  Failed       :  {red(str(counts['failed']))}")

    failed_keys = [k for k, v in results.items() if v == "failed"]
    if failed_keys:
        gap()
        print(f"  {red(S['cross'])}  Failed stages: {red(', '.join(failed_keys))}")

    # ── Scan identity + persistence status ──────────────────────────────────
    gap()
    print("  " + hline("─", 71, "dim"))
    print(f"  {cyan(S['shield'])}  Scan UUID    : {dim(scan_uuid)}")
    if db_scan_id:
        print(f"  {cyan(S['db'])}  Database     : {green(f'synced (id={db_scan_id})')}")
        summary = _sync_summary()                                    # ← add
        if summary != "not synced":                                  # ← add
            print(f"  {cyan(S['db'])}  Sync detail  : {dim(summary)}")  # ← add
    elif db_failures:
        print(f"  {cyan(S['db'])}  Database     : {yellow(f'unreachable ({db_failures} failure(s))')}")
    elif not DB_MODULE_AVAILABLE:
        print(f"  {cyan(S['db'])}  Database     : {dim('disabled (db.py not found)')}")
    elif not _cfg("BRIDGE_ENABLED", False):
        print(f"  {cyan(S['db'])}  Database     : {dim('disabled (BRIDGE_ENABLED=False)')}")
    else:
        print(f"  {cyan(S['db'])}  Database     : {yellow('not synced')}")

    # ── Findings aggregate ──────────────────────────────────────────────────
    sev = _aggregate_severity(outdir)
    total = sum(sev.values())
    if total:
        gap()
        print(f"  {cyan(S['shield'])}  Findings     : {bold(str(total))} across all stages")
        print(f"      {red('CRITICAL')} {sev['CRITICAL']:>4}   "
              f"{yellow('HIGH')} {sev['HIGH']:>4}   "
              f"{cyan('MEDIUM')} {sev['MEDIUM']:>4}   "
              f"{dim('LOW')} {sev['LOW']:>4}   "
              f"{dim('INFO')} {sev['INFO']:>4}")

        top = _top_findings(outdir, 5)
        if top:
            gap()
            print(f"  {magenta(S['rune_odin'])}  Top findings:")
            for f in top:
                sev_color = {
                    "CRITICAL": "red", "HIGH": "yellow",
                    "MEDIUM": "cyan", "LOW": "dim", "INFO": "dim",
                }.get(f["severity"], "dim")
                print(f"    {c(sev_color, f'[{f["severity"]:<8}]')} "
                      f"{f['stage']:<10} {f['type']:<24} "
                      f"{dim(f['target'][:40])}")

    # ── Artifacts, grouped by phase ─────────────────────────────────────────
    gap()
    print("  " + hline("─", 71, "dim"))
    print(f"  {cyan(S['shield'])}  Artifacts in {dim(str(outdir))}:")
    gap()

    shown_any = False
    for group in GROUP_ORDER:
        files = ARTIFACT_GROUPS.get(group, [])
        present = [
            (fname, label) for fname, label in files
            if (outdir / fname).exists() and (outdir / fname).stat().st_size > 0
        ]
        if not present:
            continue

        shown_any = True
        print(f"  {magenta(group)}")
        for fname, label in present:
            p = outdir / fname
            size = p.stat().st_size
            if fname.endswith((".json", ".md")):
                print(
                    f"      {green(S['dot_full'])} {label:<24} "
                    f"{dim(fname):<34} {dim(f'{size:>9,} bytes')}"
                )
            else:
                try:
                    line_count = sum(1 for _ in p.open("r", errors="ignore"))
                except OSError:
                    line_count = 0
                print(
                    f"      {green(S['dot_full'])} {label:<24} "
                    f"{dim(fname):<34} {dim(f'{line_count:>6} lines'):<14} "
                    f"{dim(f'{size:>9,} bytes')}"
                )
        gap()

    if not shown_any:
        print(f"      {dim(S['dot_empty'])} {dim('(no artifacts produced)')}")
        gap()

    # ── Next step ───────────────────────────────────────────────────────────
    triage_md = outdir / "triage_priority.md"
    if triage_md.exists() and triage_md.stat().st_size > 0:
        print("  " + hline("─", 71, "dim"))
        print(f"  {magenta(S['rune_odin'])}  Next step: {bold('open triage_priority.md')}")
        print(f"             {dim('Ranked findings with evidence and cross-references.')}")
        gap()

    print("  " + hline("═", 71, "cyan"))
    print(f"  {magenta(S['rune_odin'])}  Log: {dim(str(LOG_FILE))}")
    print("  " + hline("═", 71, "cyan"))
    gap()


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT / CONFIG HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _pick_existing(outdir: Path, candidates: list[str]) -> Path:
    for name in candidates:
        p = outdir / name
        if p.exists() and p.stat().st_size > 0:
            return p
    tried = ", ".join(candidates)
    raise FileNotFoundError(f"no input file found (tried: {tried})")


def _platform_headers() -> dict[str, str]:
    """
    Return merged headers for target traffic.

    Priority: auth headers (from request.txt) override platform headers.
    """
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _module_rate(stage: str) -> dict[str, Any]:
    """Return the per-module rate limit overrides."""
    overrides = _cfg("MODULE_RATE_LIMITS", {})
    return overrides.get(stage, {}) if overrides else {}


def _oob_domain() -> Optional[str]:
    """Return the OOB domain if configured, else None."""
    mode = _cfg("OAST_MODE", "disabled")
    if mode == "disabled":
        return None
    return _cfg("OAST_DOMAIN") or None


def _oob_interactsh() -> bool:
    return _cfg("OAST_MODE", "disabled") == "interactsh"


def _test_account(slot: str) -> dict:
    return (_cfg("TEST_ACCOUNTS", {}) or {}).get(slot, {})


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE RUNNERS — lazy imports, input fallback, honest errors
# ═════════════════════════════════════════════════════════════════════════════

def _run_subs(outdir: Path) -> None:
    from recon_tools.subs import enumerate_subdomains
    enumerate_subdomains(WILDCARD_FILE, outdir)


def _run_dns(outdir: Path) -> None:
    from recon_tools.dns_resolve import resolve_dns
    source = _pick_existing(outdir, ["all_subs.txt"])
    r = _module_rate("dns")
    resolve_dns(
        source, outdir,
        wildcard_file=WILDCARD_FILE,
        threads=r.get("concurrency", 10),
        rate_limit=r.get("rate_limit", 20),
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_takeover(outdir: Path) -> None:
    from recon_tools.takeover_check import run_takeover_check
    source = _pick_existing(
        outdir, ["dns_wildcard_filtered.txt", "dns_resolved.txt", "all_subs.txt"],
    )
    r = _module_rate("takeover")
    run_takeover_check(
        source, outdir,
        http_threads=r.get("concurrency", 15),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_live(outdir: Path) -> None:
    from recon_tools.sub_discover import discover_live
    source = _pick_existing(outdir, ["dns_wildcard_filtered.txt", "all_subs.txt"])
    r = _module_rate("live")
    discover_live(
        source, outdir,
        threads=r.get("concurrency", 50),
        rate_limit=r.get("rate_limit", 150),
    )


def _run_nmap(outdir: Path) -> None:
    from recon_tools.nmap import run_nmap_scan
    source = _pick_existing(outdir, ["live_urls.txt", "live_hosts.txt"])
    r = _module_rate("nmap")
    # nmap has its own timing — rate_limit maps to --max-rate
    # concurrency is ignored (single-process)
    max_rate = r.get("rate_limit", 0) or None
    run_nmap_scan(
        source, outdir,
        deep_max_rate=max_rate,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_urls(outdir: Path) -> None:
    from recon_tools.url_harvester import run_url_harvest
    source = _pick_existing(outdir, ["live_urls.txt"])
    r = _module_rate("urls")
    run_url_harvest(
        source, outdir, wildcard_file=WILDCARD_FILE,
        katana_rate_limit=r.get("rate_limit", 50),
        katana_concurrency=r.get("concurrency", 10),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )

def _run_categorize(outdir: Path) -> None:
    from recon_tools.url_categorize import run_url_categorize
    source = _pick_existing(outdir, ["urls_with_params.txt", "all_urls.txt"])
    run_url_categorize(source, outdir, scan_id=_CURRENT_SCAN_ID)


def _run_crawl(outdir: Path) -> None:                # ← paste here
    from auditing_tools.site_crawler import run_site_crawl
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_site_crawl(source, outdir)


def _run_js(outdir: Path) -> None:
    from recon_tools.js_analysis import run_js_analysis
    source = _pick_existing(outdir, ["urls_js_files.txt", "live_urls.txt"])
    r = _module_rate("js")
    run_js_analysis(
        source, outdir,
        download_threads=r.get("concurrency", 15),
        rate_limit=r.get("rate_limit", 5),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_params(outdir: Path) -> None:
    from recon_tools.param_discovery import run_param_discovery
    source = _pick_existing(outdir, ["urls_with_params.txt", "live_urls.txt"])
    r = _module_rate("params")
    run_param_discovery(
        source, outdir,
        wildcard_file=WILDCARD_FILE,
        rate_limit=r.get("rate_limit", 3),
        stable=r.get("stable", False),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_graphql(outdir: Path) -> None:
    from auditing_tools.graphql_finder import run_graphql_audit
    source = _pick_existing(outdir, ["urls_with_params.txt", "all_urls.txt", "live_urls.txt"])
    user_a = _test_account("user_a")
    user_b = _test_account("user_b")
    r = _module_rate("graphql")
    run_graphql_audit(
        source, outdir,
        rate_limit=r.get("rate_limit", 2),
        concurrency=r.get("concurrency", 2),
        headers=_platform_headers() or None,
        user_a_cookie=user_a.get("cookie") or None,
        user_b_cookie=user_b.get("cookie") or None,
        user_b_id=user_b.get("user_id") or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_fuzz(outdir: Path) -> None:
    from recon_tools.content_fuzz import run_content_fuzz
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_content_fuzz(source, outdir)


def _run_nuclei(outdir: Path) -> None:
    from recon_tools.nuclei_scan import run_nuclei_scan
    source = _pick_existing(outdir, ["live_urls.txt"])
    r = _module_rate("nuclei")
    run_nuclei_scan(
        source, outdir,
        rate_limit=r.get("rate_limit", 5),
        concurrency=r.get("concurrency", 10),
        bulk_size=r.get("bulk_size", 5),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_cors(outdir: Path) -> None:
    from recon_tools.cors_check import run_cors_check
    source = _pick_existing(outdir, ["live_urls.txt"])
    r = _module_rate("cors")
    run_cors_check(
        source, outdir,
        threads=r.get("concurrency", 10),
        rate_limit=r.get("rate_limit", 100),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_smuggling(outdir: Path) -> None:
    from auditing_tools.smuggling_finder import run_smuggling_audit
    source = _pick_existing(outdir, ["live_urls.txt"])
    r = _module_rate("smuggling")
    run_smuggling_audit(
        source, outdir,
        headers=_platform_headers() or None,
        rate_limit=r.get("rate_limit", 20),
        concurrency=r.get("concurrency", 5),
        timeout=r.get("timeout", 10),
        max_hosts=r.get("max_hosts", 200),
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_cache(outdir: Path) -> None:
    from auditing_tools.cache_poisoning_finder import run_cache_audit
    source = _pick_existing(outdir, ["urls_with_params.txt", "live_urls.txt"])
    r = _module_rate("cache")
    run_cache_audit(
        source, outdir,
        rate_limit=r.get("rate_limit", 2),
        concurrency=r.get("concurrency", 3),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_auth(outdir: Path) -> None:
    from auditing_tools.auth_tester import run_auth_tester
    source = _pick_existing(outdir, ["urls_with_params.txt", "live_urls.txt"])
    r = _module_rate("auth")
    run_auth_tester(
        source, outdir,
        rate_limit=r.get("rate_limit", 2),
        concurrency=r.get("concurrency", 2),
        headers=_platform_headers() or None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_idor(outdir: Path) -> None:
    from auditing_tools.idor_finder import run_idor_audit
    source = _pick_existing(outdir, ["urls_with_params.txt", "all_urls.txt", "live_urls.txt"])
    user_a = _test_account("user_a")
    user_b = _test_account("user_b")
    headers_a = {"Cookie": user_a["cookie"]} if user_a.get("cookie") else None
    headers_b = {"Cookie": user_b["cookie"]} if user_b.get("cookie") else None
    schema_path = outdir / "graphql_schema.json"
    r = _module_rate("idor")
    run_idor_audit(
        source, outdir,
        rate_limit=r.get("rate_limit", 2),
        concurrency=r.get("concurrency", 2),
        headers=_platform_headers() or None,
        user_a_headers=headers_a,
        user_b_headers=headers_b,
        user_a_id=user_a.get("user_id") or None,
        user_b_id=user_b.get("user_id") or None,
        graphql_schema_file=schema_path if schema_path.exists() else None,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_redirect(outdir: Path) -> None:
    from auditing_tools.open_redirect_finder import run_open_redirect_audit
    source = _pick_existing(
        outdir, ["gf_redirect.txt", "urls_with_params.txt", "live_urls.txt"],
    )
    r = _module_rate("redirect")
    run_open_redirect_audit(
        source, outdir,
        headers=_platform_headers() or None,
        rate_limit=r.get("rate_limit", 3),
        concurrency=r.get("concurrency", 4),
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_race(outdir: Path) -> None:
    from auditing_tools.race_condition import run_race_audit
    source = _pick_existing(outdir, ["urls_with_params.txt", "all_urls.txt", "live_urls.txt"])
    r = _module_rate("race")
    run_race_audit(
        source, outdir,
        headers=_platform_headers() or None,
        rate_limit=r.get("rate_limit", 3),
        concurrency=r.get("concurrency", 10),
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_sqli(outdir: Path) -> None:
    from auditing_tools.sqli_finder import run_sqli_scan
    source = _pick_existing(
        outdir, ["gf_sqli.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_sqli_scan(source, outdir, headers=_platform_headers() or None)


def _run_xss(outdir: Path) -> None:
    from auditing_tools.xss_finder import run_xss_scan
    source = _pick_existing(
        outdir, ["gf_xss.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_xss_scan(
        source, outdir,
        headers=_platform_headers() or None,
        oob_domain=_oob_domain(),
    )


def _run_ssrf(outdir: Path) -> None:
    from auditing_tools.ssrf_finder import run_ssrf_scan
    source = _pick_existing(
        outdir, ["gf_ssrf.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_ssrf_scan(
        source, outdir,
        oob_domain=_oob_domain(),
        use_interactsh=_oob_interactsh(),
        headers=_platform_headers() or None,
    )


def _run_ssti(outdir: Path) -> None:
    from auditing_tools.ssti_finder import run_ssti_scan
    source = _pick_existing(
        outdir, ["gf_ssti.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_ssti_scan(source, outdir, headers=_platform_headers() or None)


def _run_xxe(outdir: Path) -> None:
    from auditing_tools.xxe_finder import run_xxe_scan
    source = _pick_existing(
        outdir, ["urls_with_params.txt", "all_urls.txt", "live_urls.txt"],
    )
    run_xxe_scan(
        source, outdir,
        oob_domain=_oob_domain(),
        use_interactsh=_oob_interactsh(),
        headers=_platform_headers() or None,
    )


def _run_mapping(outdir: Path) -> None:
    from auditing_tools.site_mapping import run_site_mapping
    source = _pick_existing(outdir, ["live_urls.txt", "live_hosts.txt"])
    run_site_mapping(
        source, outdir,
        wildcard_file=WILDCARD_FILE,
        scan_id=_CURRENT_SCAN_ID,
    )


def _run_triage(outdir: Path) -> None:
    from recon_tools.vuln_triage import run_vuln_triage
    run_vuln_triage(outdir, scan_id=_CURRENT_SCAN_ID)


RUNNERS = {
    "subs":       _run_subs,
    "dns":        _run_dns,
    "takeover":   _run_takeover,
    "live":       _run_live,
    "nmap":       _run_nmap,
    "urls":       _run_urls,
    "crawl":      _run_crawl,
    "categorize": _run_categorize,
    "js":         _run_js,
    "params":     _run_params,
    "graphql":    _run_graphql,
    "fuzz":       _run_fuzz,
    "nuclei":     _run_nuclei,
    "cors":       _run_cors,
    "smuggling":  _run_smuggling,
    "cache":      _run_cache,
    "auth":       _run_auth,
    "idor":       _run_idor,
    "redirect":   _run_redirect,
    "race":       _run_race,
    "sqli":       _run_sqli,
    "xss":        _run_xss,
    "ssrf":       _run_ssrf,
    "ssti":       _run_ssti,
    "xxe":        _run_xxe,
    "mapping":    _run_mapping,
    "triage":     _run_triage,
}


def run_one(key: str, outdir: Path, dry_run: bool) -> str:
    if dry_run:
        print(f"  {dim(S['arrow_r'])}  {dim('would run')}  {dim(STAGE_META[key][1])}")
        return "skipped"

    try:
        RUNNERS[key](outdir)
        return "ok"
    except ImportError as e:
        print(f"  {yellow(S['warn'])}  {yellow('module not yet implemented:')} {dim(str(e))}")
        return "missing"
    except FileNotFoundError as e:
        dep = STAGE_DEPS.get(key)
        hint = f"  (run `{dep}` first)" if dep else ""
        print(f"  {yellow(S['warn'])}  {yellow('missing input:')} {dim(str(e))}{dim(hint)}")
        return "failed"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"  {red(S['cross'])}  {red(str(e))}")
        logging.exception(f"Stage '{key}' failed")
        return "failed"


# ═════════════════════════════════════════════════════════════════════════════
#  DATABASE SYNC
# ═════════════════════════════════════════════════════════════════════════════
_CURRENT_SCAN_ID: Optional[int] = None
_DB_FAIL_COUNT = 0
_DB_MAX_FAILURES = 3

# Stages that own a dedicated DB table AND have no FINDINGS_JSON_MAP entry.
# These are the ONLY stages that go through the "special" path. Format:
#   stage → (json_filename, db_method_suffix)
_SPECIAL_SYNC_STAGES: dict[str, tuple[str, str]] = {
    "auth":  ("auth_findings.json",  "auth_findings"),
    "cache": ("cache_findings.json", "cache_findings"),
}

# Populated by _sync_stage_artifacts; read by _sync_summary() in the
# final briefing. Format: stage → {"ok": bool, "count": int, "note"|"error": str}
_LAST_SYNC_STATUS: dict[str, dict] = {}

def _normalize_findings(stage: str, data: dict) -> list[dict]:
    """Extract and normalize findings from a module's JSON output."""
    raw = data.get("findings")
    if raw is None:
        raw = data.get("candidates")
    if not isinstance(raw, list):
        return []

    out: list[dict] = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        vuln_type = (
            f.get("vuln_type") or f.get("technique")
            or f.get("template_id") or f.get("xss_type")
            or f.get("race_class") or f.get("variant")
            or f.get("probe") or f.get("vector")      # ← ADD THIS
            or f.get("kind")
            or stage
        )
        target = (
            f.get("target") or f.get("matched_at")
            or f.get("url") or f.get("host") or ""
        )
        severity = (f.get("severity") or "INFO").upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            severity = "INFO"

        try:
            confidence = int(f.get("confidence", 50))
        except (TypeError, ValueError):
            confidence = 50
        confidence = max(0, min(100, confidence))

        details = {
            k: v for k, v in f.items() if k not in (
                "vuln_type", "technique", "template_id", "xss_type",
                "race_class", "variant", "probe", "kind", "subtype",
                "context", "severity", "confidence", "target",
                "matched_at", "url", "host", "param", "parameter",
                "payload", "evidence", "request_curl",
                "oob_token", "oob_confirmed",
            )
        }

        out.append({
            "vuln_type":     str(vuln_type)[:128],
            "vuln_subtype":  str(f.get("subtype") or f.get("context") or "")[:128],
            "severity":      severity,
            "confidence":    confidence,
            "source_module": stage,
            "target":        str(target)[:2048],
            "parameter":     str(f.get("param") or f.get("parameter") or "")[:255],
            "payload":       str(f.get("payload") or ""),
            "evidence":      str(f.get("evidence") or ""),
            "request_curl":  str(f.get("request_curl") or ""),
            "oob_token":     str(f.get("oob_token") or "")[:128],
            "oob_confirmed": bool(f.get("oob_confirmed", False)),
            "details":       details,
        })

    return out


def _collect_oob_tokens(outdir: Path) -> list[str]:
    """Scan finder JSONs for OOB tokens."""
    tokens: set[str] = set()
    for fname in ("ssrf_findings.json", "xss_findings.json", "xxe_findings.json"):
        p = outdir / fname
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        raw = data.get("findings") or []
        if not isinstance(raw, list):
            continue
        for f in raw:
            if isinstance(f, dict):
                tok = f.get("oob_token")
                if tok:
                    tokens.add(str(tok))
    return list(tokens)

def _first_or_none(value: Any) -> Optional[str]:
    """httpx returns `a` and `aaaa` as lists; take the first element."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _to_nmap_host_payload(h: dict) -> Optional[dict]:
    ip = h.get("ip", "")
    if not ip:
        return None
    return {
        "ip":              ip,
        "hostname":        h.get("hostname", "") or None,
        "status":          h.get("status", "up"),
        "os_matches":      h.get("os_matches") or [],
        "host_scripts":    h.get("host_scripts") or [],
        "traceroute":      h.get("traceroute") or [],
        "phase":           h.get("phase"),
        "score":           int(h.get("score", 0)),
        "interesting":     bool(h.get("interesting")),
        "reasons":         h.get("reasons") or [],
        "open_port_count": len(h.get("ports", [])),
        "first_seen":      h.get("first_seen"),
    }


def _to_auth_payload(f: dict) -> Optional[dict]:
    """Convert an auth_findings.json record into the wire shape."""
    target = f.get("target") or ""
    vtype = f.get("vuln_type") or ""
    if not target or not vtype:
        return None

    # Derive category from vuln_type prefix
    category = "general"
    vtype_lower = vtype.lower()
    if vtype_lower.startswith("jwt_"):
        category = "jwt"
    elif vtype_lower.startswith("oauth_"):
        category = "oauth"
    elif vtype_lower.startswith("saml_"):
        category = "saml"
    elif vtype_lower.startswith("cookie_"):
        category = "cookie"
    elif vtype_lower.startswith("csrf_") or "csrf" in vtype_lower:
        category = "csrf"

    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""

    return {
        "target":        target,
        "target_host":   host,
        "vuln_type":     vtype,
        "category":      category,
        "severity":      (f.get("severity") or "INFO").upper(),
        "confidence":    int(f.get("confidence", 0)),
        "evidence":      f.get("evidence", ""),
        "details":       f.get("details") or {},
        "remediation":   f.get("remediation", ""),
        "auth_enabled":  bool(f.get("auth_enabled")),
        "first_seen":    _format_dt(f.get("first_seen")),
    }

def _to_url_payload(u: dict) -> Optional[dict]:
    """Convert a url_harvest.json record into the wire shape."""
    url = u.get("url") or ""
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    return {
        "url":                url,
        "host":               parsed.hostname or "",
        "path":               parsed.path or "/",
        "query_string":       parsed.query or "",
        "sources":            u.get("sources") or [],
        "source_count":       int(u.get("source_count") or 1),
        "methods":            u.get("methods") or [],
        "tags":               u.get("tags") or [],
        "attributes":         u.get("attributes") or [],
        "form_actions":       u.get("form_actions") or [],
        "is_form":            bool(u.get("is_form")),
        "has_params":         bool(u.get("has_params")),
        "is_js":              bool(u.get("is_js")),
        "is_interesting":     bool(u.get("is_interesting")),
        "interesting_reasons": u.get("interesting_reasons") or [],
        "status_code":        u.get("status"),
        "content_type":       u.get("content_type", ""),
        "content_length":     u.get("content_length"),
        "title":              u.get("title", ""),
        "webserver":          u.get("webserver", ""),
        "technologies":       u.get("technologies") or [],
        "final_url":          u.get("final_url", ""),
        "redirect_chain":     u.get("redirect_chain") or [],
        "response_time":      u.get("response_time", ""),
        "resolved_ip":        u.get("resolved_ip", ""),
        "cname":              u.get("cname", ""),
        "alive":              bool(u.get("alive")),
        "auth_enabled":       bool(u.get("auth_enabled")),
        "first_seen":         _format_dt(u.get("first_seen")),
    }

def _to_takeover_payload(f: dict) -> Optional[dict]:
    """Convert a takeover_findings.json record into the wire shape."""
    subdomain = f.get("subdomain") or ""
    if not subdomain:
        return None
    return {
        "subdomain":       subdomain,
        "cname_chain":     f.get("cname_chain") or [],
        "service":         f.get("service", ""),
        "status":          (f.get("status") or "SAFE").upper(),
        "cname_match":     bool(f.get("cname_match")),
        "http_confirmed":  bool(f.get("http_confirmed")),
        "http_status":     f.get("http_status"),
        "fingerprint":     f.get("fingerprint", ""),
        "cvss":            f.get("cvss"),
        "severity_score":  int(f.get("severity_score", 0)),
        "dangling":        bool(f.get("dangling")),
        "shared_cname":    bool(f.get("shared_cname")),
        "notes":           f.get("notes", ""),
        "error":           f.get("error", ""),
        "auth_enabled":    bool(f.get("auth_enabled")),
        "first_seen":      _format_dt(f.get("first_seen")),
    }

def _to_param_finding_payload(f: dict) -> Optional[dict]:
    """Convert a param_findings.json record into the wire shape."""
    url = f.get("url") or ""
    param = f.get("parameter") or ""
    method = (f.get("method") or "GET").upper()
    if not url or not param:
        return None

    oracles = f.get("oracles") or []
    if isinstance(oracles, str):
        oracles = [oracles]

    return {
        "url":            url,
        "method":         method,
        "parameter":      param,
        "oracles":        oracles,
        "confidence":     int(f.get("confidence", 0)),
        "vuln_classes":   f.get("vuln_classes") or [],
        "already_in_url": bool(f.get("already_in_url")),
        "evidence":       f.get("evidence") or [],
        "auth_enabled":   bool(f.get("auth_enabled")),
        "first_seen":     _format_dt(f.get("first_seen")),
    }

def _to_nuclei_finding_payload(f: dict) -> Optional[dict]:
    """Convert a nuclei_findings.json record into the wire shape."""
    tid = f.get("template_id") or ""
    matched = f.get("matched_at") or ""
    if not tid or not matched:
        return None

    return {
        "template_id":       tid,
        "template_name":     f.get("template_name", ""),
        "template_path":     f.get("template_path", ""),
        "template_author":   f.get("template_author", []),
        "severity":          (f.get("severity") or "UNKNOWN").upper(),
        "cvss_score":        f.get("cvss_score"),
        "cve_ids":           f.get("cve_ids", []),
        "cwe_ids":           f.get("cwe_ids", []),
        "matched_at":        matched,
        "host":              f.get("host", ""),
        "ip":                f.get("ip", ""),
        "port":              f.get("port"),
        "scheme":            f.get("scheme", ""),
        "path":              f.get("path", ""),
        "matcher_name":      f.get("matcher_name", ""),
        "extracted_results": f.get("extracted_results", []),
        "curl_command":      f.get("curl_command", ""),
        "request":           f.get("request", ""),
        "response":          f.get("response", ""),
        "tags":              f.get("tags", []),
        "description":       f.get("description", ""),
        "reference":         f.get("reference", []),
        "metadata":          f.get("metadata", {}),
        "auth_enabled":      bool(f.get("auth_enabled")),
        "first_seen":        _format_dt(f.get("first_seen")),
    }

def _to_nmap_port_payload(host: dict, port: dict, host_hash: str) -> Optional[dict]:
    p = port.get("port")
    if p is None:
        return None
    port_num = int(p)
    return {
        "host_hash":        host_hash,
        "port":             port_num,
        "protocol":         port.get("protocol", "tcp"),
        "state":            port.get("state", "open"),
        "reason":           port.get("reason"),
        "service":          port.get("service"),
        "product":          port.get("product"),
        "version":          port.get("version"),
        "extrainfo":        port.get("extrainfo"),
        "cpe":              port.get("cpe") or [],
        "scripts":          port.get("scripts") or [],
        "is_web":           port.get("is_web", False),
        "is_database":      port.get("is_database", False),
        "is_admin":         port.get("is_admin", False),
        "is_dangerous":     port.get("is_dangerous", False),
        "is_remote_access": port.get("is_remote_access", False),
        "first_seen":       host.get("first_seen"),
    }

def _to_live_host_payload(rec: dict) -> Optional[dict]:
    """
    Convert a live_hosts.json record into the shape live_hosts.upsert expects.
    Returns None if the record is unusable (no URL).
    """
    url = rec.get("url")
    if not url:
        return None

    return {
        "subdomain":       rec.get("subdomain") or "",
        "url":             url,
        "root":            rec.get("root"),
        "scheme":          rec.get("scheme"),
        "host":            rec.get("host"),
        "port":            str(rec["port"]) if rec.get("port") is not None else None,
        "path":            rec.get("path"),
        "status_code":     rec.get("status_code"),
        "content_type":    rec.get("content_type"),
        "content_length":  rec.get("content_length"),
        "title":           rec.get("title"),
        "web_server":      rec.get("web_server"),
        "response_time":   rec.get("response_time"),
        "final_url":       rec.get("final_url"),
        "redirect_chain":  rec.get("redirect_chain"),
        "ip":              _first_or_none(rec.get("ip")),
        "ipv6":            _first_or_none(rec.get("ipv6")),
        "cname":           rec.get("cname"),
        "cdn":             rec.get("cdn"),
        "cdn_type":        rec.get("cdn_type"),
        "technologies":    rec.get("technologies") or [],
        "favicon_hash":    str(rec["favicon_hash"]) if rec.get("favicon_hash") is not None else None,
        "jarm_hash":       rec.get("jarm_hash"),
        "tls":             rec.get("tls"),
        "sources":         rec.get("sources") or [],
        "source_count":    rec.get("source_count", 0),
        "first_seen":      _format_dt(rec.get("first_seen")),
        "geo":             rec.get("geo") or [],
        "interesting":     bool(rec.get("interesting")),
        "reasons":         rec.get("reasons") or [],
        "score":           int(rec.get("score", 0)),
    }


def _format_dt(value: Any) -> Optional[str]:
    """Convert ISO-8601 timestamps into MySQL DATETIME format."""
    if not value:
        return None
    if isinstance(value, str):
        # '2026-01-15T10:54:23.123456+00:00' → '2026-01-15 10:54:23'
        return value.replace("T", " ").split(".")[0].split("+")[0].rstrip("Z")
    return None




# ── Shared helpers ──────────────────────────────────────────────────────────

def _load_json_artifact(outdir: Path, fname: str, log) -> Optional[dict]:
    """Load a JSON artifact if present and non-empty. None on miss/parse error."""
    p = outdir / fname
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text())
    except Exception as e:
        log.debug(f"DB sync: could not parse {fname}: {e}")
        return None


def _sync_items(
    db_method,
    scan_id: int,
    items: list,
    stage: str,
    log,
    label: str = "finding(s)",
) -> Optional[int]:
    """
    Call a single DB upsert with consistent fail-count + status tracking.

    Every upsert call in this module funnels through here, so the
    ``_DB_FAIL_COUNT`` ceiling is applied uniformly and the final
    briefing can read ``_LAST_SYNC_STATUS`` for a truthful summary.

    Returns:
        count (int) on success (including 0 for empty input), None on failure.
    """
    global _DB_FAIL_COUNT

    if not items:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "empty"}
        return 0

    try:
        result = db_method(scan_id, items)
    except Exception as e:
        _DB_FAIL_COUNT += 1
        _LAST_SYNC_STATUS[stage] = {"ok": False, "count": 0, "error": str(e)}
        log.debug(f"DB sync {stage} exception: {e}")
        return None

    if result is None:
        _DB_FAIL_COUNT += 1
        _LAST_SYNC_STATUS[stage] = {"ok": False, "count": 0, "error": "None"}
        log.debug(
            f"DB sync {stage} returned None "
            f"({_DB_FAIL_COUNT}/{_DB_MAX_FAILURES})"
        )
        return None

    _DB_FAIL_COUNT = 0
    _LAST_SYNC_STATUS[stage] = {"ok": True, "count": int(result)}
    log.info(f"DB sync {stage}: {result} {label} upserted")
    return int(result)


def _sync_summary() -> str:
    """One-line summary of the last sync, for the final briefing panel."""
    if not _LAST_SYNC_STATUS:
        return "not synced"
    ok = sum(1 for s in _LAST_SYNC_STATUS.values() if s.get("ok"))
    failed = sum(1 for s in _LAST_SYNC_STATUS.values() if not s.get("ok"))
    total = sum(int(s.get("count", 0)) for s in _LAST_SYNC_STATUS.values())
    parts: list[str] = []
    if ok:
        parts.append(f"{ok} stage(s)")
    if failed:
        parts.append(f"{failed} failed")
    if not parts:
        return "not synced"
    return f"{' + '.join(parts)} · {total} row(s)"


# ── Payload builders that don't fit the simple single-call pattern ──────────

def _build_url_categorize_payloads(data: dict) -> list[dict]:
    """
    Merge url_categorize.json's two views (priority_urls + categories) into a
    single per-URL record for the DB. Extracted so it's testable on its own.
    """
    HIGH_RISK = {"sqli", "ssrf", "rce", "lfi", "ssti", "idor"}
    MED_RISK = {"redirect", "graphql", "oauth", "upload"}

    url_map: dict[str, dict] = {}

    for entry in data.get("priority_urls") or []:
        url = entry.get("url")
        if not url:
            continue
        cats = entry.get("categories") or []
        url_map[url] = {
            "url":             url,
            "categories":      list(cats),
            "category_count":  len(cats),
            "weight":          int(entry.get("weight") or 0),
            "param_names":     entry.get("param_names") or [],
            "high_risk_count": 0,
            "is_priority":     True,
        }

    for cat in data.get("categories") or []:
        cat_name = (cat.get("name") or "").lower()
        weight = 3 if cat_name in HIGH_RISK else 2 if cat_name in MED_RISK else 1
        for url in (cat.get("urls") or []):
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
            if cat_name and cat_name not in entry["categories"]:
                entry["categories"].append(cat_name)
            entry["weight"] += weight

    for url, entry in url_map.items():
        entry["high_risk_count"] = sum(
            1 for c in entry["categories"] if c in HIGH_RISK
        )
        if not entry["param_names"]:
            parsed = urllib.parse.urlparse(url)
            entry["param_names"] = list(
                urllib.parse.parse_qs(parsed.query).keys()
            )
        entry["category_count"] = len(entry["categories"])

    return list(url_map.values())


# ── Path 1: RECON_JSON_MAP dispatch ─────────────────────────────────────────

def _sync_nmap(scan_id: int, data: dict, log) -> None:
    """
    nmap writes two tables. Host ids returned by the first upsert feed the
    port payloads for the second, so this stage can't be generalized.
    """
    global _DB_FAIL_COUNT

    hosts_data = data.get("hosts") or []
    if not hosts_data:
        _LAST_SYNC_STATUS["nmap"] = {"ok": True, "count": 0, "note": "no hosts"}
        return

    host_payloads = [
        h for h in (_to_nmap_host_payload(x) for x in hosts_data)
        if h and h.get("ip")
    ]
    if not host_payloads:
        _LAST_SYNC_STATUS["nmap"] = {"ok": True, "count": 0, "note": "no valid hosts"}
        return

    try:
        host_result = DB.upsert_nmap_hosts(scan_id, host_payloads)
    except Exception as e:
        _DB_FAIL_COUNT += 1
        _LAST_SYNC_STATUS["nmap"] = {"ok": False, "count": 0, "error": str(e)}
        log.debug(f"DB sync nmap hosts exception: {e}")
        return

    if host_result is None:
        _DB_FAIL_COUNT += 1
        _LAST_SYNC_STATUS["nmap"] = {"ok": False, "count": 0, "error": "hosts None"}
        log.debug("DB sync nmap hosts returned None")
        return

    _DB_FAIL_COUNT = 0
    host_ids = host_result.get("host_ids", {}) if isinstance(host_result, dict) else {}
    host_count = host_result.get("count", 0) if isinstance(host_result, dict) else 0
    log.info(f"DB sync nmap: {host_count} host(s) upserted")

    port_payloads: list[dict] = []
    for h in hosts_data:
        ip = h.get("ip", "")
        if not ip:
            continue
        host_hash = hashlib.sha256(ip.encode()).hexdigest()
        if host_hash not in host_ids:
            continue
        for p2 in h.get("ports", []):
            pp = _to_nmap_port_payload(h, p2, host_hash)
            if pp:
                port_payloads.append(pp)

    if not port_payloads:
        _LAST_SYNC_STATUS["nmap"] = {
            "ok": True, "count": host_count, "note": "no open ports",
        }
        return

    try:
        port_count = DB.upsert_nmap_ports(scan_id, port_payloads)
    except Exception as e:
        _DB_FAIL_COUNT += 1
        _LAST_SYNC_STATUS["nmap"] = {
            "ok": True, "count": host_count, "error": f"ports: {e}",
        }
        log.debug(f"DB sync nmap ports exception: {e}")
        return

    if port_count is not None:
        log.info(f"DB sync nmap: {port_count} port(s) upserted")
        _LAST_SYNC_STATUS["nmap"] = {
            "ok": True, "count": host_count + int(port_count),
        }
    else:
        _LAST_SYNC_STATUS["nmap"] = {
            "ok": True, "count": host_count, "note": "ports None",
        }


def _sync_recon_stage(scan_id: int, stage: str, outdir: Path, log) -> None:
    """
    Handle any stage listed in RECON_JSON_MAP. Dispatches by `kind` (the
    second tuple element). Always returns — no fallthrough to the generic path.
    """
    fname, kind = RECON_JSON_MAP[stage]
    data = _load_json_artifact(outdir, fname, log)
    if data is None:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "empty"}
        return

    # ── Multi-table kinds (must return explicitly)
    if kind == "nmap":
        _sync_nmap(scan_id, data, log)
        return

    if kind == "nuclei":
        items = [
            p for p in (
                _to_nuclei_finding_payload(f)
                for f in (data.get("findings") or [])
            ) if p
        ]
        if items:
            _sync_items(
                DB.upsert_nuclei_findings, scan_id, items,
                "nuclei", log, "finding(s)",
            )
        for batch in (data.get("batches") or []):
            try:
                DB.save_nuclei_batch(scan_id, batch)
            except Exception as e:
                log.debug(f"DB save_nuclei_batch exception: {e}")
        return

    if kind == "url_categorize":
        items = _build_url_categorize_payloads(data)
        _sync_items(
            DB.upsert_url_categorize, scan_id, items,
            "url_categorize", log, "URL(s)",
        )
        return

    # ── Transform-per-item kinds (dispatch by kind, then _sync_items)
    if kind == "live_hosts":
        items = [
            p for p in (
                _to_live_host_payload(h) for h in (data.get("hosts") or [])
            ) if p and p.get("url")
        ]
        _sync_items(
            DB.upsert_live_hosts, scan_id, items,
            "live_hosts", log, "live host(s)",
        )
        return

    if kind == "takeover_findings":
        items = [
            p for p in (
                _to_takeover_payload(f) for f in (data.get("findings") or [])
            ) if p
        ]
        _sync_items(
            DB.upsert_takeover_findings, scan_id, items,
            "takeover_findings", log, "finding(s)",
        )
        return

    if kind == "param_findings":
        items = [
            p for p in (
                _to_param_finding_payload(f) for f in (data.get("findings") or [])
            ) if p
        ]
        _sync_items(
            DB.upsert_param_findings, scan_id, items,
            "param_findings", log, "parameter(s)",
        )
        return

    if kind == "urls":
        items = [
            p for p in (
                _to_url_payload(u) for u in (data.get("urls") or [])
            ) if p
        ]
        _sync_items(
            DB.upsert_urls, scan_id, items,
            "urls", log, "URL(s)",
        )
        return

    # ── Simple single-call kinds (no per-item transformation)
    simple = {
        "subdomains":   ("subdomains", DB.upsert_subdomains,   "subdomain(s)"),
        "dns_records":  ("records",    DB.upsert_dns_records,  "DNS record(s)"),
        "site_pages":   ("pages",      DB.upsert_site_pages,   "page(s)"),
        "content_fuzz": ("findings",   DB.upsert_content_fuzz, "endpoint(s)"),
        "js_findings":  ("findings",   DB.upsert_js_findings,  "JS finding(s)"),
    }
    handler = simple.get(kind)
    if handler:
        key, method, label = handler
        items = data.get(key) or []
        _sync_items(method, scan_id, items, stage, log, label)
        return

    # Unknown kind — log it, don't crash, but make it visible
    _LAST_SYNC_STATUS[stage] = {
        "ok": True, "count": 0, "note": f"no handler for kind '{kind}'",
    }
    log.debug(f"DB sync: no handler for kind '{kind}' (stage={stage})")


# ── Path 2: dedicated-table stages without FINDINGS_JSON_MAP ────────────────

def _sync_special_stage(scan_id: int, stage: str, outdir: Path, log) -> None:
    """
    Handle auth / cache (and any future stage added to _SPECIAL_SYNC_STAGES).
    These have a dedicated DB table but no normalized `findings` row.

    Per-stage transform:
      • auth  — derive `category`, `target_host`, `first_seen` from the raw
                record before it hits the bridge (see _to_auth_payload).
      • cache — records are already in wire shape; pass through.
    """
    fname, suffix = _SPECIAL_SYNC_STAGES[stage]
    data = _load_json_artifact(outdir, fname, log)
    if data is None:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "empty"}
        return

    items = data.get("findings") or []
    if not items:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "no findings"}
        return

    # Per-stage transform
    if stage == "auth":
        items = [x for x in (_to_auth_payload(f) for f in items) if x]
        if not items:
            _LAST_SYNC_STATUS[stage] = {
                "ok": True, "count": 0, "note": "no valid findings",
            }
            return

    method = getattr(DB, f"upsert_{suffix}", None)
    if method is None:
        _LAST_SYNC_STATUS[stage] = {
            "ok": False, "count": 0,
            "error": f"db.py has no upsert_{suffix}()",
        }
        log.warning(
            f"DB sync {stage}: db.py is missing upsert_{suffix}() — "
            f"add the method to enable {suffix} sync"
        )
        return

    _sync_items(method, scan_id, items, stage, log, "finding(s)")

# ── Top-level router ────────────────────────────────────────────────────────

def _sync_stage_artifacts(scan_id: Optional[int], stage: str, outdir: Path) -> None:
    """
    Route a stage's local JSON artifact(s) to the remote DB.

    Three dispatch paths, tried strictly in order — each returns, no fallthrough:

      1. RECON_JSON_MAP    — recon / harvest stages with per-kind payload builders
      2. _SPECIAL_SYNC_STAGES — auth / cache (dedicated table, no generic row)
      3. FINDINGS_JSON_MAP — everything else (generic `findings` table)

    Failure tracking is shared via the module-level ``_DB_FAIL_COUNT`` counter,
    reset to 0 on any successful sync. Per-stage outcomes are recorded in
    ``_LAST_SYNC_STATUS`` for the final briefing.
    """
    if not scan_id:
        return
    if not DB_MODULE_AVAILABLE or DB is None:
        return
    if _DB_FAIL_COUNT >= _DB_MAX_FAILURES:
        return

    log = logging.getLogger("argus")

    # ── Path 1: RECON stages with dedicated payload builders
    if stage in RECON_JSON_MAP:
        _sync_recon_stage(scan_id, stage, outdir, log)
        return

    # ── Path 2: auth / cache — dedicated table, no generic findings row
    if stage in _SPECIAL_SYNC_STAGES:
        _sync_special_stage(scan_id, stage, outdir, log)
        return

    # ── Path 3: everything else — normalized to the `findings` table
    fname = FINDINGS_JSON_MAP.get(stage)
    if not fname:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "no sync path"}
        return

    data = _load_json_artifact(outdir, fname, log)
    if data is None:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "empty"}
        return

    findings = _normalize_findings(stage, data)
    if not findings:
        _LAST_SYNC_STATUS[stage] = {"ok": True, "count": 0, "note": "no findings"}
        return

    _sync_items(
        DB.upsert_findings, scan_id, findings, stage, log, "finding(s)",
    )
    return


def _sync_oob(scan_id: Optional[int], outdir: Path) -> None:
    """Push OOB tokens and hits to the bridge."""
    if not scan_id:
        return
    if not DB_MODULE_AVAILABLE or DB is None:
        return
    if _DB_FAIL_COUNT >= _DB_MAX_FAILURES:
        return

    tokens = _collect_oob_tokens(outdir)
    if not tokens:
        return

    try:
        result = DB.sync_oob(scan_id, tokens)
        if result is not None:
            logging.getLogger("argus").info(
                f"DB OOB sync: {result} hit(s) upserted"
            )
    except Exception as e:
        logging.getLogger("argus").debug(f"OOB sync failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    level = logging.DEBUG if verbose else _cfg("LOG_LEVEL", "INFO")
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)

    if _cfg("LOG_TO_FILE", True):
        fh = logging.FileHandler(LOG_FILE, mode="a")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        root.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(ch)


# ═════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    epilog_text = f"""
{dim('Examples:')}
  {cyan('python3 main.py')}                              run all 26 stages
  {cyan('python3 main.py --stage recon')}                reconnaissance group
  {cyan('python3 main.py --stage harvest')}              URL collection
  {cyan('python3 main.py --stage discover')}             js + params + graphql + fuzz
  {cyan('python3 main.py --stage scan')}                 nuclei + cors + smuggling + cache
  {cyan('python3 main.py --stage audit')}                all 9 audit stages
  {cyan('python3 main.py --stage quick')}                fast pass: recon → urls → triage
  {cyan('python3 main.py --stage sqli,xss,ssrf')}        specific stages
  {cyan('python3 main.py --stage all --skip fuzz')}      skip the loud stages
  {cyan('python3 main.py --stage all --fail-fast')}      stop at first failure
  {cyan('python3 main.py --dry-run')}                    preview only
  {cyan('python3 main.py --stages')}                     list stage identifiers
  {cyan('python3 main.py --scan-id <uuid>')}             resume / append to a scan
  {cyan('python3 main.py --no-db')}                      force-disable DB sync

{dim('Stage groups:')}
  {dim('recon')}      subs → dns → takeover → live → nmap
  {dim('harvest')}    urls → categorize
  {dim('discover')}   js → params → graphql → fuzz
  {dim('scan')}       nuclei → cors → smuggling → cache
  {dim('audit')}      auth → idor → redirect → race → sqli → xss → ssrf → ssti → xxe
  {dim('report')}     mapping → triage
  {dim('quick')}      subs → dns → live → urls → categorize → triage

{dim('Persistence:')}
  Local artifacts always go to {dim('output/')}. DB sync requires
  {dim('config.py')} + {dim('db.py')} and {dim('BRIDGE_ENABLED=True')}.

{dim('Exit codes:')}
  {dim('0  success')}    {dim('1  stage failure')}    {dim('2  environment error')}    {dim('130  interrupted')}
"""
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Argus — the all-seeing watchman of the digital longship. "
            "A modular bug bounty reconnaissance and audit framework."
        ),
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--stage", default="all", metavar="NAME",
                        help="group name, stage name, or comma-separated list (default: all)")
    parser.add_argument("--skip", metavar="STAGES",
                        help="comma-separated stages to skip")
    parser.add_argument("--dry-run", action="store_true",
                        help="preview stages without executing anything")
    parser.add_argument("--fail-fast", action="store_true",
                        help="stop at the first failing stage")
    parser.add_argument("--stages", action="store_true",
                        help="list available stage identifiers and exit")
    parser.add_argument("--scan-id", metavar="UUID",
                        help="resume / append findings to an existing scan UUID")
    parser.add_argument("--no-db", action="store_true",
                        help="force-disable remote DB sync for this run")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="enable debug logging to stdout")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI color output")
    parser.add_argument("--version", action="version",
                        version=f"Argus v{VERSION} ({CODENAME})",
                        help="show version and exit")
    return parser


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE CATALOG
# ═════════════════════════════════════════════════════════════════════════════

def print_stages() -> None:
    gap()
    print("  " + hline("═", 71, "cyan"))
    print("  " + bold(f"{S['sword']}  AVAILABLE STAGES"))
    print("  " + hline("═", 71, "cyan"))
    gap()

    categories: dict[str, list[tuple[str, str]]] = {}
    for key, (cat, title) in STAGE_META.items():
        categories.setdefault(cat, []).append((key, title))

    for cat in GROUP_ORDER:
        entries = categories.get(cat, [])
        if not entries:
            continue
        print(f"  {magenta(cat)}")
        for key, title in entries:
            dep = STAGE_DEPS.get(key)
            dep_str = f"  {dim(f'(needs {dep})')}" if dep else ""
            print(f"    {cyan(key):<12} {title}{dep_str}")
        gap()

    print(f"  {magenta('GROUPS')}")
    for group_name in ("recon", "harvest", "discover", "scan",
                       "audit", "report", "quick", "all"):
        stages = STAGE_GROUPS[group_name]
        if len(stages) <= 5:
            preview = " → ".join(stages)
        else:
            preview = " → ".join(stages[:4]) + f" → ... (+{len(stages) - 4})"
        print(f"    {cyan(group_name):<12} {dim(preview)}")
    gap()

    print(f"  {magenta('INTEGRATIONS')}")
    cfg_state = green("loaded") if CFG_LOADED else yellow("not found")
    db_state = (
        green(f"available ({_cfg('BRIDGE_URL', '')})")
        if DB_MODULE_AVAILABLE and _cfg("BRIDGE_ENABLED", False)
        else dim("disabled")
    )
    print(f"    config.py    {cfg_state}")
    print(f"    db.py        {db_state}")
    print(f"    platform     {bold(_cfg('ACTIVE_PLATFORM', '(none)'))}")
    print(f"    oob domain   {dim(_cfg('OAST_DOMAIN', '(not set)'))}")
    gap()

    print("  " + hline("═", 71, "cyan"))
    gap()


# ═════════════════════════════════════════════════════════════════════════════
#  ENVIRONMENT VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

def load_wildcards() -> list[str]:
    if not WILDCARD_FILE.exists():
        return []
    return [
        line.strip()
        for line in WILDCARD_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def validate_environment(stages: list[str]) -> tuple[bool, str]:
    if "subs" in stages:
        if not WILDCARD_FILE.exists():
            return False, (
                f"wildcard.txt not found at {WILDCARD_FILE} — "
                "create it with one root domain per line."
            )
        if not load_wildcards():
            return False, "wildcard.txt is empty — add at least one root domain."
    OUTPUT_DIR.mkdir(exist_ok=True)
    return True, ""


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main(argv: list[str] | None = None) -> int:
    global _USE_COLOR

    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()

    if not argv or "--help" in argv or "-h" in argv:
        show_banner()
        parser.print_help()
        print()
        return 0

    args = parser.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    if args.stages:
        show_banner()
        print_stages()
        return 0

    setup_logging(args.verbose)
    log = logging.getLogger("argus")

    # ── Resolve stage list ──────────────────────────────────────────────────
    try:
        stages = resolve_stages(args.stage)
    except ValueError as e:
        show_banner()
        print(f"\n  {red(S['cross'])}  {e}")
        print(f"  {dim('Run')} {cyan('python3 main.py --stages')} {dim('to see valid identifiers.')}\n")
        return 2

    if args.skip:
        try:
            skip_list = resolve_stages(args.skip)
        except ValueError as e:
            show_banner()
            print(f"\n  {red(S['cross'])}  --skip: {e}\n")
            return 2
        skip_set = set(skip_list)
        removed = [s for s in stages if s in skip_set]
        stages = [s for s in stages if s not in skip_set]
        if removed:
            log.info(f"Skipping: {', '.join(removed)}")
        if not stages:
            show_banner()
            print(f"\n  {red(S['cross'])}  All stages were skipped — nothing to run.\n")
            return 2

    # ── Environment ─────────────────────────────────────────────────────────
    ok, err = validate_environment(stages)
    if not ok:
        show_banner()
        print(f"\n  {red(S['cross'])}  {err}\n")
        return 2

    wildcards = load_wildcards()

    # ── Database availability decision ──────────────────────────────────────
    db_available = (
        DB_MODULE_AVAILABLE
        and DB is not None
        and DB.available
        and _cfg("BRIDGE_ENABLED", False)
        and not args.no_db
    )

    # Determine final DB status string for the briefing
    if args.no_db:
        db_status = dim("disabled (--no-db)")
    elif not DB_MODULE_AVAILABLE:
        db_status = dim("disabled (db.py not found)")
    elif not _cfg("BRIDGE_ENABLED", False):
        db_status = dim("disabled (BRIDGE_ENABLED=False)")
    elif not DB.available:
        db_status = yellow("unavailable (bridge client not initialised)")
    else:
        db_status = green(f"connected to {_cfg('BRIDGE_URL', '(unknown)')}")

    # ── Scan identity ───────────────────────────────────────────────────────
    scan_uuid = args.scan_id or str(_uuid.uuid4())

    show_banner()
    show_briefing(
        wildcards, stages, OUTPUT_DIR,
        args.dry_run, args.fail_fast,
        db_status=db_status,
        platform=_cfg("ACTIVE_PLATFORM", ""),
    )

    # ── Register scan in DB ────────────────────────────────────────────────
    # Notes:
    #   • create_scan is idempotent — if scan_uuid already exists in the DB,
    #     the bridge returns the existing row's id instead of inserting a
    #     duplicate. So resuming with the same UUID "just works."
    #   • When --scan-id is passed, we log "resumed" (user intent).
    #   • When --scan-id is not passed, a fresh UUID was generated above and
    #     we log "registered" (new scan).
    #   • --dry-run and --no-db skip registration entirely.
    db_scan_id: Optional[int] = None

    if args.dry_run:
        log.debug("  Dry-run: skipping DB scan registration")
    elif not db_available:
        log.debug("  DB disabled: skipping scan registration")
    else:
        try:
            db_scan_id = DB.create_scan(
                scan_uuid=scan_uuid,
                wildcards=wildcards,
                platform=_cfg("ACTIVE_PLATFORM", ""),
                pipeline=stages,
            )
            if db_scan_id:
                intent = "resumed" if args.scan_id else "registered"
                log.info(
                    f"  Scan {intent} (db id={db_scan_id}, "
                    f"uuid={scan_uuid[:8]}…)"
                )
            else:
                log.warning(
                    "  DB create_scan returned no id — "
                    "continuing locally (self-sync will be skipped)"
                )
        except Exception as e:
            log.warning(
                f"  DB create_scan failed: {e} — "
                "continuing locally (self-sync will be skipped)"
            )

    # Expose scan_id to self-syncing modules (cors_check, content_fuzz, etc.)
    # They check this global and self-sync only when it's non-None.
    global _CURRENT_SCAN_ID
    _CURRENT_SCAN_ID = db_scan_id

    if db_scan_id:
        log.debug(f"  _CURRENT_SCAN_ID = {db_scan_id} (available to self-syncing stages)")

    # ── Execute ─────────────────────────────────────────────────────────────
    results: dict[str, str] = {}
    total = len(stages)
    interrupted = False
    scan_start = time.monotonic()

    try:
        for idx, key in enumerate(stages, start=1):
            show_stage_header(idx, total, key)

            stage_start = time.monotonic()
            result = run_one(key, OUTPUT_DIR, args.dry_run)
            stage_duration_ms = int((time.monotonic() - stage_start) * 1000)

            results[key] = result
            show_stage_result(key, result)

            # Save stage record + sync artifacts to DB
            if db_scan_id and not args.dry_run:
                try:
                    artifacts = [
                        str(OUTPUT_DIR / f)
                        for f in STAGE_ARTIFACTS.get(key, [])
                        if (OUTPUT_DIR / f).exists()
                    ]
                    DB.save_stage(
                        scan_id=db_scan_id,
                        stage=key,
                        status=result,
                        duration_ms=stage_duration_ms,
                        artifacts=artifacts,
                        stats={},
                    )
                except Exception as e:
                    log.debug(f"  DB save_stage failed for {key}: {e}")

                if result == "ok":
                    _sync_stage_artifacts(db_scan_id, key, OUTPUT_DIR)

            # Fail-fast
            if args.fail_fast and result == "failed":
                gap()
                print("  " + hline("─", 71, "red"))
                print(f"  {red(S['cross'])}  {red('Fail-fast triggered')} — "
                      f"{dim('stopping before remaining stages.')}")
                print("  " + hline("─", 71, "red"))
                break

    except KeyboardInterrupt:
        interrupted = True
        gap()
        print("  " + hline("─", 71, "yellow"))
        print(f"  {yellow(S['warn'])}  {yellow('Raid interrupted by Jarl.')} "
              f"{dim('Returning to port with what we have.')}")
        print("  " + hline("─", 71, "yellow"))

    # ── Sync OOB + finish scan ──────────────────────────────────────────────
    scan_elapsed = time.monotonic() - scan_start
    if db_scan_id and not args.dry_run:
        try:
            _sync_oob(db_scan_id, OUTPUT_DIR)
        except Exception as e:
            log.debug(f"  DB oob sync failed: {e}")

        try:
            DB.finish_scan(scan_uuid, stats={
                "stages":   results,
                "elapsed":  round(scan_elapsed, 2),
                "interrupted": interrupted,
            })
        except Exception as e:
            log.debug(f"  DB finish_scan failed: {e}")

    # ── Final panel ─────────────────────────────────────────────────────────
    show_final_briefing(
        results, OUTPUT_DIR,
        scan_uuid=scan_uuid,
        db_scan_id=db_scan_id,
        db_failures=_DB_FAIL_COUNT,
    )
    if interrupted:
        return 130
    if "failed" in results.values():
        return 1
    return 0


# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def _install_signal_handlers() -> None:
    """
    Route SIGTERM to KeyboardInterrupt so `docker stop` / `systemctl stop` /
    `kill -15` take the same graceful shutdown path as Ctrl+C — main()'s inner
    try-block catches it, runs _sync_oob() + finish_scan(), and shows the
    final briefing instead of dying mid-stage.

    SIGINT (Ctrl+C) is already handled by Python's default handler which
    raises KeyboardInterrupt — no extra wiring needed.

    SIGHUP is intentionally NOT caught: terminal-close should terminate the
    process, and `nohup` users already have SIGHUP set to ignore at the OS
    level. Overriding it here would surprise both groups.
    """
    if os.name != "posix":
        return
    try:
        import signal
        def _raise_keyboard_interrupt(signum, frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    except (ImportError, ValueError, OSError):
        # ImportError — signal module absent (unreachable on posix)
        # ValueError  — not the main thread (e.g., imported from a test)
        # OSError     — platform refused the signal (rare)
        pass


def _silence_broken_pipe() -> None:
    """
    Redirect stdout's underlying fd to /dev/null so Python's atexit flush
    doesn't raise a second BrokenPipeError during interpreter shutdown.
    Required for clean `argus | head` / `argus | less` behavior.

    Technique is the one recommended by CPython's SIGPIPE note:
    https://docs.python.org/3/library/signal.html#note-on-sigpipe
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    except (OSError, AttributeError):
        # AttributeError if sys.stdout has been replaced with None
        pass


if __name__ == "__main__":
    _install_signal_handlers()
    try:
        sys.exit(main())
    except SystemExit:
        # main() and argparse already chose an exit code (0, 1, 2, 130) —
        # pass it through without alteration.
        raise
    except KeyboardInterrupt:
        # Reached only when the interrupt lands *before* main()'s inner
        # try-block — during startup (banner, argparse, env validation,
        # DB scan registration) or as SIGTERM before the handler routes
        # it. main() itself catches the interrupt that arrives mid-stage.
        try:
            sys.stdout.flush()
            # yellow() / dim() respect _USE_COLOR; the original line used
            # the raw C['yellow'] escape and leaked ANSI under --no-color.
            print(
                f"\n{yellow('Interrupted.')} "
                f"{dim('Returning to port with what we have.')}"
            )
        except Exception:
            # flush() can raise on a broken pipe — swallow it so the
            # exit code is still 130 and not an unhandled BrokenPipe.
            pass
        sys.exit(130)
    except BrokenPipeError:
        # Consumer of stdout closed early (| head, | less, | grep -m1).
        # Exit 141 = 128 + SIGPIPE, the Unix convention that lets
        # `set -o pipefail` see the signal correctly.
        _silence_broken_pipe()
        sys.exit(141)
    except Exception as exc:
        # A genuine bug in the tool — not a user-facing error. Log a
        # one-liner so it lands in argus.log, and print the full traceback
        # to stderr (the Unix convention for every CLI tool).
        try:
            logging.getLogger("argus").error(
                f"Unhandled exception in main(): {exc}"
            )
        except Exception:
            # If logging itself is broken (setup_logging never ran),
            # nothing else to do — the traceback on stderr is enough.
            pass
        import traceback
        traceback.print_exc()
        sys.exit(3)     # distinct from stage failure (1) and env error (2)
