#!/usr/bin/env python3
"""
main.py — A R G U S  v2.0
═══════════════════════════════════════════════════════════════════════════════

The all-seeing watchman of the digital longship.

Pipeline:
    RECON     :  subs → dns → takeover → live → nmap
    HARVEST   :  urls → categorize
    DISCOVER  :  js → params → fuzz
    SCAN      :  nuclei → cors
    AUDIT     :  mapping → sqli → xss → ssrf
    REPORT    :  triage

Argus does not exploit. Argus surfaces. Every finding is a candidate — a
flag on a map that says "look here, human." Manual triage is the point.

Usage:
    python3 main.py                          run all stages
    python3 main.py --stage recon            recon group only
    python3 main.py --stage recon,live       specific stages, in order
    python3 main.py --stage discover         discovery group only
    python3 main.py --stage quick            fast pass: recon → urls → triage
    python3 main.py --stage all --skip audit skip audit stubs
    python3 main.py --fail-fast              stop at first failure
    python3 main.py --dry-run                preview, no execution
    python3 main.py --stages                 list stage identifiers
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# ═════════════════════════════════════════════════════════════════════════════
#  METADATA
# ═════════════════════════════════════════════════════════════════════════════

VERSION  = "2.0.0"
CODENAME = "Raven's Flight"
AUTHOR   = "BeardedVikingTX"
REPO     = "https://github.com/BeardedVikingTX/Argus"

# ═════════════════════════════════════════════════════════════════════════════
#  PATHS
# ═════════════════════════════════════════════════════════════════════════════

BASE_DIR      = Path(__file__).parent
OUTPUT_DIR    = BASE_DIR / "output"
WILDCARD_FILE = BASE_DIR / "wildcard.txt"
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

# ═════════════════════════════════════════════════════════════════════════════
#  SIGILS — Viking / sci-fi marks
# ═════════════════════════════════════════════════════════════════════════════

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
}

RUNES = "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃᛇᛈᛉᛊᛏᛒᛖᛗᛚᛜᛞᛟ"

# ═════════════════════════════════════════════════════════════════════════════
#  BANNER ART
# ═════════════════════════════════════════════════════════════════════════════

ARGUS_ART = r"""
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""

# ═════════════════════════════════════════════════════════════════════════════
#  COLOR HELPERS
# ═════════════════════════════════════════════════════════════════════════════

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
#  STAGE DEFINITIONS
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
    # ── Discover ────────────────────────────────────────────────────────────
    "js":         ("DISCOVER",  "JavaScript Analysis"),
    "params":     ("DISCOVER",  "Parameter Discovery"),
    "fuzz":       ("DISCOVER",  "Content Fuzzing"),
    # ── Scan ────────────────────────────────────────────────────────────────
    "nuclei":     ("SCAN",      "Vulnerability Scanning"),
    "cors":       ("SCAN",      "CORS Misconfiguration Check"),
    # ── Audit ───────────────────────────────────────────────────────────────
    "mapping":    ("AUDIT",     "Site Mapping"),
    "sqli":       ("AUDIT",     "SQLi Candidate Hunter"),
    "xss":        ("AUDIT",     "XSS Candidate Hunter"),
    "ssrf":       ("AUDIT",     "SSRF Candidate Hunter"),
    # ── Report ──────────────────────────────────────────────────────────────
    "triage":     ("REPORT",    "Finding Aggregation & Prioritization"),
}

STAGE_GROUPS = {
    "recon":    ["subs", "dns", "takeover", "live", "nmap"],
    "harvest":  ["urls", "categorize"],
    "discover": ["js", "params", "fuzz"],
    "scan":     ["nuclei", "cors"],
    "audit":    ["mapping", "sqli", "xss", "ssrf"],
    "report":   ["triage"],
    "quick":    ["subs", "dns", "live", "urls", "categorize", "triage"],
    "all":      [
        # Recon
        "subs", "dns", "takeover", "live", "nmap",
        # Harvest
        "urls", "categorize",
        # Discover
        "js", "params", "fuzz",
        # Scan
        "nuclei", "cors",
        # Audit (stubs)
        "mapping", "sqli", "xss", "ssrf",
        # Report
        "triage",
    ],
}

# Which earlier stage must run first when an input file is missing
STAGE_DEPS = {
    "dns":        "subs",
    "takeover":   "subs",
    "live":       "subs",
    "nmap":       "live",
    "urls":       "live",
    "categorize": "urls",
    "js":         "urls",
    "params":     "urls",
    "fuzz":       "live",
    "nuclei":     "live",
    "cors":       "live",
    "mapping":    "live",
    "sqli":       "urls",
    "xss":        "urls",
    "ssrf":       "urls",
    "triage":     None,
}

# Order in which groups appear in the --stages catalog
GROUP_ORDER = ["RECON", "HARVEST", "DISCOVER", "SCAN", "AUDIT", "REPORT"]


def resolve_stages(arg: str) -> list[str]:
    """Resolve a stage argument into an ordered list of stage keys."""
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
        # Preserve order but remove duplicates
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


def show_briefing(wildcards, stage_list, outdir, dry_run, fail_fast):
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
    print(f"  {cyan(S['shield'])}  Stage(s)     : {bold(str(len(stage_list)))} sub-stage(s)")
    print(f"  {cyan(S['shield'])}  Output       : {dim(str(outdir))}")
    print(f"  {cyan(S['shield'])}  Log          : {dim(str(LOG_FILE))}")
    gap()

    # Stage preview
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


# Headline artifacts shown in the final briefing, grouped by pipeline phase
ARTIFACT_GROUPS = {
    "RECON": [
        ("all_subs.txt",                "Subdomains"),
        ("subdomains.json",             "Subdomain attribution"),
        ("dns_wildcard_filtered.txt",   "DNS (clean)"),
        ("dns_takeover_candidates.txt", "Takeover candidates"),
        ("takeover_vulnerable.txt",     "Takeover CONFIRMED"),
        ("takeover_potential.txt",      "Takeover potential"),
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
        ("js_sourcemaps.txt",           "Source maps"),
        ("params_by_endpoint.txt",      "Parameters"),
        ("param_findings.json",         "Params (JSON)"),
        ("fuzzed_interesting.txt",      "Interesting paths"),
        ("fuzzed_directories.txt",      "All fuzzed paths"),
    ],
    "SCAN": [
        ("nuclei_critical.txt",         "Nuclei CRIT/HIGH"),
        ("nuclei_all.txt",              "Nuclei all"),
        ("nuclei_findings.json",        "Nuclei report"),
        ("cors_critical.txt",           "CORS CRIT/HIGH"),
        ("cors_findings.json",          "CORS report"),
    ],
    "AUDIT": [
        ("sqli_candidates.txt",         "SQLi candidates"),
        ("xss_candidates.txt",          "XSS candidates"),
        ("ssrf_candidates.txt",         "SSRF candidates"),
    ],
    "REPORT": [
        ("triage_priority.md",          "Triage markdown"),
        ("triage_report.json",          "Triage report"),
        ("triage_next_steps.txt",       "Next steps"),
        ("triage_by_category.txt",      "By category"),
    ],
}


def show_final_briefing(results: dict[str, str], outdir: Path) -> None:
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

    # Show which stages failed
    failed_keys = [k for k, v in results.items() if v == "failed"]
    if failed_keys:
        gap()
        print(f"  {red(S['cross'])}  Failed stages: {red(', '.join(failed_keys))}")

    # Artifacts, grouped by phase
    gap()
    print("  " + hline("─", 71, "dim"))
    print(f"  {cyan(S['shield'])}  Artifacts in {dim(str(outdir))}:")
    gap()

    shown_any = False
    for group in GROUP_ORDER:
        files = ARTIFACT_GROUPS.get(group, [])
        present = [
            (fname, label) for fname, label in files
            if (outdir / fname).exists()
        ]
        if not present:
            continue

        shown_any = True
        print(f"  {magenta(group)}")
        for fname, label in present:
            p = outdir / fname
            size = p.stat().st_size
            try:
                line_count = sum(1 for _ in p.open("r", errors="ignore"))
                unit = "lines"
            except OSError:
                line_count = 0
                unit = "lines"
            # For .json files, show size only (line counts are misleading)
            if fname.endswith(".json") or fname.endswith(".md"):
                print(
                    f"      {green(S['dot_full'])} {label:<24} "
                    f"{dim(fname):<34} {dim(f'{size:>9,} bytes')}"
                )
            else:
                print(
                    f"      {green(S['dot_full'])} {label:<24} "
                    f"{dim(fname):<34} {dim(f'{line_count:>6} {unit}'):<14} "
                    f"{dim(f'{size:>9,} bytes')}"
                )
        gap()

    if not shown_any:
        print(f"      {dim(S['dot_empty'])} {dim('(no artifacts produced)')}")
        gap()

    # Final recommendation
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
#  INPUT RESOLUTION HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _pick_existing(outdir: Path, candidates: list[str]) -> Path:
    """
    Return the first candidate file that exists and is non-empty.
    Raises FileNotFoundError with the full list if none match.
    """
    for name in candidates:
        p = outdir / name
        if p.exists() and p.stat().st_size > 0:
            return p
    tried = ", ".join(candidates)
    raise FileNotFoundError(f"no input file found (tried: {tried})")


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE RUNNERS — lazy imports, input fallback, honest errors
# ═════════════════════════════════════════════════════════════════════════════

def _run_subs(outdir: Path) -> None:
    from recon_tools.subs import enumerate_subdomains
    enumerate_subdomains(WILDCARD_FILE, outdir)


def _run_dns(outdir: Path) -> None:
    from recon_tools.dns_resolve import resolve_dns
    source = _pick_existing(outdir, ["all_subs.txt"])
    resolve_dns(source, outdir, wildcard_file=WILDCARD_FILE)


def _run_takeover(outdir: Path) -> None:
    from recon_tools.takeover_check import run_takeover_check
    # Prefer wildcard-filtered, then dns-resolved, then raw subdomains
    source = _pick_existing(
        outdir,
        ["dns_wildcard_filtered.txt", "dns_resolved.txt", "all_subs.txt"],
    )
    run_takeover_check(source, outdir)


def _run_live(outdir: Path) -> None:
    from recon_tools.sub_discover import discover_live
    # Prefer wildcard-filtered over raw subdomains
    source = _pick_existing(
        outdir,
        ["dns_wildcard_filtered.txt", "all_subs.txt"],
    )
    discover_live(source, outdir)


def _run_nmap(outdir: Path) -> None:
    from recon_tools.nmap import run_nmap_scan
    source = _pick_existing(outdir, ["live_urls.txt", "live_hosts.txt"])
    run_nmap_scan(source, outdir)


def _run_urls(outdir: Path) -> None:
    from recon_tools.url_harvester import run_url_harvest
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_url_harvest(source, outdir, wildcard_file=WILDCARD_FILE)


def _run_categorize(outdir: Path) -> None:
    from recon_tools.url_categorize import run_url_categorize
    source = _pick_existing(outdir, ["urls_with_params.txt", "all_urls.txt"])
    run_url_categorize(source, outdir)


def _run_js(outdir: Path) -> None:
    from recon_tools.js_analysis import run_js_analysis
    # Prefer the JS file list from url_harvester, fall back to live hosts
    source = _pick_existing(outdir, ["urls_js_files.txt", "live_urls.txt"])
    run_js_analysis(source, outdir)


def _run_params(outdir: Path) -> None:
    from recon_tools.param_discovery import run_param_discovery
    # Prefer the parameterised URL list (already filtered + deduped)
    source = _pick_existing(outdir, ["urls_with_params.txt", "live_urls.txt"])
    run_param_discovery(source, outdir, wildcard_file=WILDCARD_FILE)


def _run_fuzz(outdir: Path) -> None:
    from recon_tools.content_fuzz import run_content_fuzz
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_content_fuzz(source, outdir)


def _run_nuclei(outdir: Path) -> None:
    from recon_tools.nuclei_scan import run_nuclei_scan
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_nuclei_scan(source, outdir)


def _run_cors(outdir: Path) -> None:
    from recon_tools.cors_check import run_cors_check
    source = _pick_existing(outdir, ["live_urls.txt"])
    run_cors_check(source, outdir)


# ── Auditing tools (still stubs — will report as 'missing') ─────────────────

def _run_mapping(outdir: Path) -> None:
    from auditing_tools.site_mapping import run_site_mapping
    source = _pick_existing(outdir, ["live_urls.txt", "live_hosts.txt"])
    run_site_mapping(source, outdir)


def _run_sqli(outdir: Path) -> None:
    from auditing_tools.sqli_finder import run_sqli_scan
    # Prefer categorized, then parameterised, then all URLs
    source = _pick_existing(
        outdir,
        ["gf_sqli.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_sqli_scan(source, outdir)


def _run_xss(outdir: Path) -> None:
    from auditing_tools.xss_finder import run_xss_scan
    source = _pick_existing(
        outdir,
        ["gf_xss.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_xss_scan(source, outdir)


def _run_ssrf(outdir: Path) -> None:
    from auditing_tools.ssrf_finder import run_ssrf_scan
    source = _pick_existing(
        outdir,
        ["gf_ssrf.txt", "urls_with_params.txt", "all_urls.txt"],
    )
    run_ssrf_scan(source, outdir)


# ── Final report ────────────────────────────────────────────────────────────

def _run_triage(outdir: Path) -> None:
    from recon_tools.vuln_triage import run_vuln_triage
    run_vuln_triage(outdir)


RUNNERS = {
    "subs":       _run_subs,
    "dns":        _run_dns,
    "takeover":   _run_takeover,
    "live":       _run_live,
    "nmap":       _run_nmap,
    "urls":       _run_urls,
    "categorize": _run_categorize,
    "js":         _run_js,
    "params":     _run_params,
    "fuzz":       _run_fuzz,
    "nuclei":     _run_nuclei,
    "cors":       _run_cors,
    "mapping":    _run_mapping,
    "sqli":       _run_sqli,
    "xss":        _run_xss,
    "ssrf":       _run_ssrf,
    "triage":     _run_triage,
}


def run_one(key: str, outdir: Path, dry_run: bool) -> str:
    """
    Execute a single stage. Returns one of:
      'ok' | 'skipped' | 'missing' | 'failed'
    """
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

    except Exception as e:
        print(f"  {red(S['cross'])}  {red(str(e))}")
        logging.exception(f"Stage '{key}' failed")
        return "failed"


# ═════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)

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
  {cyan('python3 main.py')}                              run all stages
  {cyan('python3 main.py --stage recon')}                reconnaissance group
  {cyan('python3 main.py --stage harvest')}              URL collection only
  {cyan('python3 main.py --stage discover')}             js + params + fuzz
  {cyan('python3 main.py --stage scan')}                 nuclei + cors
  {cyan('python3 main.py --stage quick')}                fast pass: recon → urls → triage
  {cyan('python3 main.py --stage subs,nmap')}            specific stages
  {cyan('python3 main.py --stage all --skip audit')}     skip the audit stubs
  {cyan('python3 main.py --stage all --fail-fast')}      stop at first failure
  {cyan('python3 main.py --dry-run')}                    preview — no commands executed
  {cyan('python3 main.py --stages')}                     list stage identifiers

{dim('Stage groups:')}
  {dim('recon')}      subs → dns → takeover → live → nmap
  {dim('harvest')}    urls → categorize
  {dim('discover')}   js → params → fuzz
  {dim('scan')}       nuclei → cors
  {dim('audit')}      mapping → sqli → xss → ssrf  (stubs)
  {dim('report')}     triage
  {dim('quick')}      fast reconnaissance pass

{dim('Exit codes:')}
  {dim('0  success')}    {dim('1  stage failure')}    {dim('2  environment error')}    {dim('130  interrupted')}

{dim('Reminder:')} run {cyan('python3 tools.py --check')} first to verify dependencies.
"""
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Argus — the all-seeing watchman of the digital longship. "
            "A modular bug bounty reconnaissance framework."
        ),
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--stage", default="all", metavar="NAME",
        help="group name, stage name, or comma-separated list   (default: all)",
    )
    parser.add_argument(
        "--skip", metavar="STAGES",
        help="comma-separated stages to skip (e.g. 'audit' or 'sqli,xss,ssrf')",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="preview stages without executing anything",
    )
    parser.add_argument(
        "--fail-fast", action="store_true",
        help="stop at the first failing stage",
    )
    parser.add_argument(
        "--stages", action="store_true",
        help="list available stage identifiers and exit",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="enable debug logging to stdout",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable ANSI color output",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"Argus v{VERSION} ({CODENAME})",
        help="show version and exit",
    )
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

    # Group by category
    categories: dict[str, list[tuple[str, str]]] = {}
    for key, (cat, title) in STAGE_META.items():
        categories.setdefault(cat, []).append((key, title))

    for cat in GROUP_ORDER:
        entries = categories.get(cat, [])
        if not entries:
            continue
        print(f"  {magenta(cat)}")
        for key, title in entries:
            # Depends-on hint
            dep = STAGE_DEPS.get(key)
            dep_str = f"  {dim(f'(needs {dep})')}" if dep else ""
            print(f"    {cyan(key):<12} {title}{dep_str}")
        gap()

    print(f"  {magenta('GROUPS')}")
    for group_name in ("recon", "harvest", "discover", "scan", "audit", "report", "quick", "all"):
        stages = STAGE_GROUPS[group_name]
        if len(stages) <= 5:
            preview = " → ".join(stages)
        else:
            preview = " → ".join(stages[:4]) + " → ..."
        print(f"    {cyan(group_name):<12} {dim(preview)}")
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
    """Return (ok, error_message)."""
    # wildcard.txt is only required if the `subs` stage is in play
    if "subs" in stages:
        if not WILDCARD_FILE.exists():
            return False, (
                f"wildcard.txt not found at {WILDCARD_FILE} — "
                "create it with one root domain per line."
            )
        if not load_wildcards():
            return False, (
                "wildcard.txt is empty — add at least one root domain."
            )

    OUTPUT_DIR.mkdir(exist_ok=True)
    return True, ""


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main(argv: list[str] | None = None) -> int:
    global _USE_COLOR

    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()

    # Intercept help / no-args so we can show the banner first
    if not argv or "--help" in argv or "-h" in argv:
        show_banner()
        parser.print_help()
        print()
        return 0

    args = parser.parse_args(argv)

    # Color control must happen before any styled output
    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    # --stages catalog mode
    if args.stages:
        show_banner()
        print_stages()
        return 0

    # Setup file logging before any stage runs
    setup_logging(args.verbose)

    # Resolve stage list
    try:
        stages = resolve_stages(args.stage)
    except ValueError as e:
        show_banner()
        print(f"\n  {red(S['cross'])}  {e}")
        print(f"  {dim('Run')} {cyan('python3 main.py --stages')} {dim('to see valid identifiers.')}\n")
        return 2

    # Apply --skip
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
            logging.getLogger("argus").info(f"Skipping: {', '.join(removed)}")
        if not stages:
            show_banner()
            print(f"\n  {red(S['cross'])}  All stages were skipped — nothing to run.\n")
            return 2

    # Environment checks
    ok, err = validate_environment(stages)
    if not ok:
        show_banner()
        print(f"\n  {red(S['cross'])}  {err}\n")
        return 2

    wildcards = load_wildcards()

    # Begin
    show_banner()
    show_briefing(wildcards, stages, OUTPUT_DIR, args.dry_run, args.fail_fast)

    # Execute
    results: dict[str, str] = {}
    total = len(stages)
    interrupted = False

    try:
        for idx, key in enumerate(stages, start=1):
            show_stage_header(idx, total, key)
            result = run_one(key, OUTPUT_DIR, args.dry_run)
            results[key] = result
            show_stage_result(key, result)

            # Fail-fast handling
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

    # Final panel
    show_final_briefing(results, OUTPUT_DIR)

    if interrupted:
        return 130
    if "failed" in results.values():
        return 1
    return 0


# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C['yellow']}Interrupted.{C['reset']}")
        sys.exit(130)
