#!/usr/bin/env python3
"""
recon_tools/subs.py — Subdomain Enumeration
═══════════════════════════════════════════════════════════════════════════════

Orchestrates multiple passive subdomain sources in parallel, normalizes and
deduplicates the results, optionally validates them through DNS resolution,
writes both a plain-text inventory and a structured JSON report, and —
when a scan_id is supplied — pushes the results to the remote database.

Sources:
  • subfinder   — ProjectDiscovery, 40+ passive APIs, JSONL with source metadata
  • assetfinder — TomNomNom, lightweight, different source mix
  • amass       — OWASP, deepest passive coverage (slower, but thorough)
  • crt.sh      — Certificate Transparency fallback (via HTTP, no binary needed)

Config integration (config.py):
  • MODULE_RATE_LIMITS["subs"]["rate_limit"]   → subfinder -rl, dnsx -rl
  • MODULE_RATE_LIMITS["subs"]["concurrency"]  → ThreadPoolExecutor workers
  • SYNC_TO_DB                                 → enable/disable self-sync
  • BRIDGE_ENABLED, BRIDGE_URL, BRIDGE_KEY     → bridge connection

Headers are deliberately NOT applied in this stage. Every source here
queries third-party services (VirusTotal, Censys, Shodan, crt.sh,
public resolvers) — NOT the target. Platform headers apply from the
`live` stage onward.

Outputs (into `outdir`):
  • all_subs.txt       — sorted, deduplicated list of subdomains
  • subdomains.json    — structured report with source attribution
  • subs_resolved.txt  — only the subdomains that resolve (if dnsx available)

Remote DB (if scan_id provided and bridge reachable):
  • subdomains table   — one row per (scan_id, subdomain)

Integration:
  main.py → run_one("subs") → enumerate_subdomains(WILDCARD_FILE, outdir)
  main.py also syncs subdomains.json via _sync_stage_artifacts()
  Standalone: enumerate_subdomains(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.subs")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG — graceful fallback if config.py is missing
# ═════════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None
    CFG_LOADED = False

# DB client — optional, only used for self-sync
try:
    from db import DB, ArgusDB  # noqa: F401
    DB_AVAILABLE = True
except ImportError:
    DB = None
    DB_AVAILABLE = False


def _cfg(key: str, default=None):
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _subs_settings() -> tuple[Optional[int], int]:
    """
    Return (rate_limit, concurrency) for the 'subs' stage.

    rate_limit = None means "don't pass -rl" (tool default).
    rate_limit = 0 is treated the same as None (unlimited).
    """
    overrides = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = overrides.get("subs", {})

    rl = entry.get("rate_limit", SUBFINDER_RATE_LIMIT)
    cc = entry.get("concurrency", 3)

    if rl is not None and rl <= 0:
        rl = None
    if not isinstance(cc, int) or cc < 1:
        cc = 3

    return rl, cc


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

TIMEOUT_SUBFINDER   = 600
TIMEOUT_ASSETFINDER = 180
TIMEOUT_AMASS       = 600
TIMEOUT_CRTSH       = 30
TIMEOUT_DNSX        = 300

SUBFINDER_RATE_LIMIT: Optional[int] = 20
SUBFINDER_PROXY: Optional[str] = None

ENABLE_CRTSH_FALLBACK = True

ARGUS_UA = "argus-subs/1.0 (+https://github.com/BeardedVikingTX/Argus)"


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SourceResult:
    source: str
    domain: str
    subdomains: set[str] = field(default_factory=set)
    error: Optional[str] = None
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def count(self) -> int:
        return len(self.subdomains)


@dataclass
class SubdomainRecord:
    name: str
    sources: set[str] = field(default_factory=set)
    root: str = ""
    first_seen: str = ""


# ═════════════════════════════════════════════════════════════════════════════
#  NORMALIZATION
# ═════════════════════════════════════════════════════════════════════════════

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


def normalize_subdomain(raw: str) -> Optional[str]:
    if not raw:
        return None

    s = raw.strip().lower()

    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]

    s = s.split("/")[0].split("?")[0]

    if ":" in s:
        s = s.split(":")[0]

    s = s.lstrip("*.")
    s = s.rstrip(".")

    if not s or not _DOMAIN_RE.match(s):
        return None

    return s


def extract_apex(subdomain: str, roots: list[str]) -> Optional[str]:
    for root in roots:
        r = root.lower().strip()
        if subdomain == r or subdomain.endswith("." + r):
            return r
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  TOOL EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int, label: str) -> tuple[bool, str, str]:
    log.debug(f"[{label}] $ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.returncode == 0, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return (False, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        return (False, "", f"binary not found: {cmd[0]}")
    except Exception as e:
        return (False, "", f"unexpected error: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCES
# ═════════════════════════════════════════════════════════════════════════════

def _run_subfinder(domain: str, rate_limit: Optional[int] = None) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("subfinder", domain)

    if not _tool_available("subfinder"):
        result.error = "subfinder not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["subfinder", "-d", domain, "-all", "-recursive", "-silent", "-oJ", "-cs"]
    if rate_limit is not None and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])
    if SUBFINDER_PROXY:
        cmd.extend(["-proxy", SUBFINDER_PROXY])

    ok, stdout, stderr = _run(cmd, TIMEOUT_SUBFINDER, "subfinder")

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            sub = normalize_subdomain(line)
            if sub:
                result.subdomains.add(sub)
            continue
        host = obj.get("host") or obj.get("domain") or obj.get("subdomain")
        sub = normalize_subdomain(str(host)) if host else None
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "subfinder failed"

    result.duration = time.monotonic() - start
    return result


def _run_assetfinder(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("assetfinder", domain)

    if not _tool_available("assetfinder"):
        result.error = "assetfinder not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["assetfinder", "--subs-only", domain]
    ok, stdout, stderr = _run(cmd, TIMEOUT_ASSETFINDER, "assetfinder")

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "assetfinder failed"

    result.duration = time.monotonic() - start
    return result


def _run_amass(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("amass", domain)

    if not _tool_available("amass"):
        result.error = "amass not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "10", "-silent"]
    ok, stdout, stderr = _run(cmd, TIMEOUT_AMASS, "amass")

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "amass failed"

    result.duration = time.monotonic() - start
    return result


def _run_crtsh(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("crt.sh", domain)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(
        url, headers={"User-Agent": ARGUS_UA, "Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_CRTSH) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        result.error = f"crt.sh: {e}"
        result.duration = time.monotonic() - start
        return result

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.splitlines():
            sub = normalize_subdomain(name)
            if sub:
                result.subdomains.add(sub)

    result.duration = time.monotonic() - start
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  DNS VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

def _validate_with_dnsx(
    subdomains: list[str], rate_limit: Optional[int] = None,
) -> set[str]:
    if not subdomains:
        return set()
    if not _tool_available("dnsx"):
        log.info("    dnsx not installed — skipping resolution validation")
        return set()

    cmd = ["dnsx", "-silent"]
    if rate_limit is not None and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])

    try:
        result = subprocess.run(
            cmd, input="\n".join(subdomains),
            capture_output=True, text=True, timeout=TIMEOUT_DNSX,
        )
    except Exception as e:
        log.warning(f"    dnsx failed: {e}")
        return set()

    resolved: set[str] = set()
    for line in result.stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            resolved.add(sub)
    return resolved


# ═════════════════════════════════════════════════════════════════════════════
#  AGGREGATION
# ═════════════════════════════════════════════════════════════════════════════

def _aggregate(results: list[SourceResult], roots: list[str]) -> dict[str, SubdomainRecord]:
    now = datetime.now(timezone.utc).isoformat()
    merged: dict[str, SubdomainRecord] = {}

    for sr in results:
        if not sr.ok:
            continue
        for sub in sr.subdomains:
            if sub not in merged:
                merged[sub] = SubdomainRecord(
                    name=sub,
                    root=extract_apex(sub, roots) or "",
                    first_seen=now,
                )
            merged[sub].sources.add(sr.source)

    return merged


def _to_payloads(
    merged: dict[str, SubdomainRecord],
    resolved: set[str],
) -> list[dict]:
    """Convert merged records into the JSON schema the bridge expects."""
    payloads: list[dict] = []
    for name in sorted(merged):
        rec = merged[name]
        resolves_val: Optional[bool] = None
        if resolved:
            resolves_val = name in resolved

        payloads.append({
            "subdomain":    rec.name,
            "root":         rec.root,
            "sources":      sorted(rec.sources),
            "source_count": len(rec.sources),
            "resolves":     resolves_val,
            "first_seen":   rec.first_seen.replace("T", " ").split(".")[0],
        })
    return payloads


def _build_json_report(
    roots: list[str],
    merged: dict[str, SubdomainRecord],
    source_results: list[SourceResult],
    resolved: set[str],
    elapsed: float,
    applied_rate: Optional[int],
    applied_concurrency: int,
) -> dict:
    by_source = {}
    for sr in source_results:
        by_source[sr.source] = {
            "domain":           sr.domain,
            "ok":               sr.ok,
            "count":            sr.count,
            "duration_seconds": round(sr.duration, 2),
            "error":            sr.error,
        }

    records = []
    for name in sorted(merged):
        rec = merged[name]
        records.append({
            "subdomain":    rec.name,
            "root":         rec.root,
            "sources":      sorted(rec.sources),
            "source_count": len(rec.sources),
            "resolves":     name in resolved if resolved else None,
            "first_seen":   rec.first_seen,
        })

    return {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "wildcards":       roots,
        "config": {
            "rate_limit":      applied_rate,
            "concurrency":     applied_concurrency,
            "crtsh_fallback":  ENABLE_CRTSH_FALLBACK,
            "dnsx_validation": bool(resolved),
            "sources":         ["subfinder", "assetfinder", "amass"],
            "note":            "rate_limit applies to third-party APIs, not the "
                               "target; platform headers are not used in this stage",
        },
        "totals": {
            "unique_subdomains": len(merged),
            "resolved":          len(resolved) if resolved else None,
            "sources_run":       len(source_results),
            "sources_ok":        sum(1 for s in source_results if s.ok),
        },
        "sources":    by_source,
        "subdomains": records,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  REMOTE SYNC (self)
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, payloads: list[dict]) -> None:
    """
    Push subdomains to the bridge. Only called when scan_id is explicitly
    passed to enumerate_subdomains().

    In the pipeline, main.py handles sync via _sync_stage_artifacts(). This
    function exists for standalone / scripted use cases.
    """
    if not payloads:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not available — skipping")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB is False — skipping")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED is False — skipping")
        return
    if not DB.available:
        log.warning("  DB sync: bridge client not ready (check BRIDGE_KEY)")
        return

    try:
        result = DB.upsert_subdomains(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} subdomain(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def enumerate_subdomains(
    wildcard_file: Path,
    outdir: Path,
    resolve: bool = True,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Enumerate subdomains for every root domain in `wildcard_file`.

    Rate limit and concurrency are read from config.py unless overridden.

    If `scan_id` is provided AND db.py is available AND config allows it,
    the results are upserted to the remote database. In the pipeline,
    main.py handles sync — passing scan_id here is only for standalone use.

    Returns the path to `all_subs.txt`.
    """
    start = time.monotonic()

    cfg_rate, cfg_concurrency = _subs_settings()
    effective_rate = rate_limit if rate_limit is not None else cfg_rate
    effective_concurrency = concurrency if concurrency is not None else cfg_concurrency

    # ── Load targets ────────────────────────────────────────────────────────
    if not wildcard_file.exists():
        raise FileNotFoundError(f"wildcard file not found: {wildcard_file}")

    roots = [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not roots:
        raise ValueError(f"wildcard file is empty: {wildcard_file}")

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Targets : {len(roots)} wildcard(s)")
    for r in roots:
        log.info(f"            · {r}")
    log.info("")

    source_label = f"{effective_rate}/s" if effective_rate else "unlimited"
    log.info(f"  Config  : rate_limit={source_label}  concurrency={effective_concurrency}")
    log.info(f"            source: MODULE_RATE_LIMITS['subs']")

    if effective_rate is not None and effective_rate < 5:
        log.info("")
        log.info(f"  {chr(9888)}  rate_limit={effective_rate}/s is very slow for passive APIs.")
        log.info(f"     This stage queries third-party services, not the target.")
        log.info(f"     Consider raising MODULE_RATE_LIMITS['subs']['rate_limit']")
        log.info(f"     (default {SUBFINDER_RATE_LIMIT}/s, or 0 for unlimited).")
        log.info("")

    headers = _cfg("ACTIVE_HEADERS", {}) or {}
    if headers:
        log.info(f"  Headers : {len(headers)} configured in config.py")
        log.info(f"            NOT applied here — subs makes no target traffic.")
        log.info(f"            Platform headers apply from 'live' onward.")
        log.info("")

    # ── Run sources ─────────────────────────────────────────────────────────
    tasks: list[tuple[str, str]] = []
    for domain in roots:
        tasks.append(("subfinder", domain))
        tasks.append(("assetfinder", domain))
        tasks.append(("amass", domain))

    source_results: list[SourceResult] = []

    def _dispatch(source: str, domain: str) -> SourceResult:
        if source == "subfinder":
            return _run_subfinder(domain, rate_limit=effective_rate)
        if source == "assetfinder":
            return _run_assetfinder(domain)
        if source == "amass":
            return _run_amass(domain)
        raise ValueError(f"unknown source: {source}")

    max_workers = max(1, min(effective_concurrency * len(roots), len(tasks)))
    log.info(f"  Running {len(tasks)} source task(s) with {max_workers} worker(s)...")
    log.info("")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for source_name, domain in tasks:
            fut = pool.submit(_dispatch, source_name, domain)
            future_map[fut] = (source_name, domain)

        for fut in as_completed(future_map):
            source_name, domain = future_map[fut]
            try:
                sr = fut.result()
            except Exception as e:
                sr = SourceResult(source_name, domain, error=str(e))

            source_results.append(sr)
            status = (
                f"✓ {sr.count:>4} subdomains"
                if sr.ok
                else f"✗ {sr.error or 'failed'}"
            )
            log.info(f"    {source_name:<12} {domain:<24} {status}  ({sr.duration:.1f}s)")

    # ── Aggregate ───────────────────────────────────────────────────────────
    merged = _aggregate(source_results, roots)
    unique_subs = sorted(merged.keys())

    log.info("")
    log.info(f"  Aggregate : {len(unique_subs)} unique subdomain(s)")

    # ── crt.sh fallback ─────────────────────────────────────────────────────
    if ENABLE_CRTSH_FALLBACK and not unique_subs:
        log.info("")
        log.info("  No results from installed tools — falling back to crt.sh...")
        crtsh_results: list[SourceResult] = []
        for domain in roots:
            sr = _run_crtsh(domain)
            crtsh_results.append(sr)
            log.info(f"    crt.sh       {domain:<24} "
                     f"{'✓' if sr.ok else '✗'} {sr.count:>4} subdomains  "
                     f"({sr.duration:.1f}s)")
        source_results.extend(crtsh_results)
        merged = _aggregate(source_results, roots)
        unique_subs = sorted(merged.keys())
        log.info(f"  crt.sh aggregate: {len(unique_subs)} unique subdomain(s)")

    # ── DNS validation ──────────────────────────────────────────────────────
    resolved: set[str] = set()
    if resolve and unique_subs:
        log.info("")
        log.info("  Resolving via dnsx...")
        resolved = _validate_with_dnsx(unique_subs, rate_limit=effective_rate)
        if resolved:
            log.info(f"  Resolved  : {len(resolved)} / {len(unique_subs)} "
                     f"({len(resolved) / len(unique_subs) * 100:.0f}%)")
        else:
            log.info("  Resolved  : (dnsx unavailable or no results)")

    # ── Write outputs ───────────────────────────────────────────────────────
    txt_path = outdir / "all_subs.txt"
    txt_path.write_text("\n".join(unique_subs) + ("\n" if unique_subs else ""))
    log.info("")
    log.info(f"  Wrote     : {txt_path}  ({len(unique_subs)} lines)")

    if resolved:
        resolved_path = outdir / "subs_resolved.txt"
        resolved_path.write_text("\n".join(sorted(resolved)) + "\n")
        log.info(f"  Wrote     : {resolved_path}  ({len(resolved)} lines)")

    elapsed = time.monotonic() - start
    report = _build_json_report(
        roots, merged, source_results, resolved, elapsed,
        applied_rate=effective_rate,
        applied_concurrency=effective_concurrency,
    )
    json_path = outdir / "subdomains.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    log.info(f"  Wrote     : {json_path}")

    # ── Self-sync (standalone only) ─────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        payloads = _to_payloads(merged, resolved)
        _self_sync(scan_id, payloads)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")

    return txt_path


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
    wildcard = base / "wildcard.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus subs (standalone)")
    parser.add_argument("--scan-id", type=int, default=None,
                        help="optional: scan_id for remote DB sync")
    parser.add_argument("--rate-limit", type=int, default=None,
                        help="override MODULE_RATE_LIMITS['subs']['rate_limit']")
    parser.add_argument("--concurrency", type=int, default=None,
                        help="override MODULE_RATE_LIMITS['subs']['concurrency']")
    args = parser.parse_args()

    try:
        enumerate_subdomains(
            wildcard, out,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
