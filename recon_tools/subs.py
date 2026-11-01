#!/usr/bin/env python3
"""
recon_tools/subs.py — Subdomain Enumeration
═══════════════════════════════════════════════════════════════════════════════

Orchestrates multiple passive subdomain sources in parallel, normalizes and
deduplicates the results, optionally validates them through DNS resolution,
and writes both a plain-text inventory and a structured JSON report.

Sources:
  • subfinder   — ProjectDiscovery, 40+ passive APIs, JSONL with source metadata
  • assetfinder — TomNomNom, lightweight, different source mix
  • amass       — OWASP, deepest passive coverage (slower, but thorough)
  • crt.sh      — Certificate Transparency fallback (via HTTP, no binary needed)

Outputs (into `outdir`):
  • all_subs.txt       — sorted, deduplicated list of subdomains (one per line)
  • subdomains.json    — structured report with source attribution + statistics
  • subs_resolved.txt  — only the subdomains that resolve (if dnsx is available)

Integration:
  main.py → run_one("subs") → enumerate_subdomains(WILDCARD_FILE, outdir)
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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# Per-tool wall-clock timeouts (seconds). These are deliberately generous;
# passive sources can be slow, and killing them early loses coverage.
TIMEOUT_SUBFINDER = 600
TIMEOUT_ASSETFINDER = 180
TIMEOUT_AMASS = 600
TIMEOUT_CRTSH = 30
TIMEOUT_DNSX = 300

# Optional: if set, subfinder uses this rate limit (requests/second).
# Set to None to let subfinder use its own default.
SUBFINDER_RATE_LIMIT: Optional[int] = 20

# Optional: set to a proxy URL (e.g. "http://127.0.0.1:8080") for subfinder.
SUBFINDER_PROXY: Optional[str] = None

# crt.sh fallback — enabled if subfinder/assetfinder/amass all return nothing
ENABLE_CRTSH_FALLBACK = True


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SourceResult:
    """Outcome of one enumeration source for one domain."""
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
    """One discovered subdomain with attribution."""
    name: str
    sources: set[str] = field(default_factory=set)
    root: str = ""
    first_seen: str = ""


# ═════════════════════════════════════════════════════════════════════════════
#  NORMALIZATION & VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


def normalize_subdomain(raw: str) -> Optional[str]:
    """
    Clean a raw subdomain string into canonical form.

    - lowercase
    - strip whitespace
    - remove URL schemes (http://, https://)
    - remove wildcards (*., *., etc.)
    - remove trailing dots and ports
    - reject invalid domain syntax
    """
    if not raw:
        return None

    s = raw.strip().lower()

    # Strip URL scheme
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]

    # Strip path / query
    s = s.split("/")[0].split("?")[0]

    # Strip port
    if ":" in s:
        s = s.split(":")[0]

    # Strip leading wildcards and dots
    s = s.lstrip("*.")

    # Strip trailing dot
    s = s.rstrip(".")

    if not s or not _DOMAIN_RE.match(s):
        return None

    return s


def extract_apex(subdomain: str, roots: list[str]) -> Optional[str]:
    """Return the root domain that a subdomain belongs to, or None."""
    for root in roots:
        r = root.lower().strip()
        if subdomain == r or subdomain.endswith("." + r):
            return r
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  TOOL EXECUTION HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(
    cmd: list[str],
    timeout: int,
    label: str,
) -> tuple[bool, str, str]:
    """
    Run a command with a timeout. Returns (ok, stdout, stderr).

    stdout and stderr are captured regardless of success so callers can
    parse partial output when a tool exits non-zero after emitting results.
    """
    log.debug(f"[{label}] $ {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (result.returncode == 0, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return (False, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        return (False, "", f"binary not found: {cmd[0]}")
    except Exception as e:
        return (False, "", f"unexpected error: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE: SUBFINDER
# ═════════════════════════════════════════════════════════════════════════════

def _run_subfinder(domain: str) -> SourceResult:
    """
    Run subfinder with JSONL output and source collection.

    Flags:
      -d <domain>      single target
      -all             include all passive sources
      -recursive       use recursive-capable sources
      -silent          no banner / noise
      -oJ              JSON Lines output
      -cs              include source metadata (requires -oJ)
    """
    start = time.monotonic()
    result = SourceResult("subfinder", domain)

    if not _tool_available("subfinder"):
        result.error = "subfinder not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = [
        "subfinder",
        "-d", domain,
        "-all",
        "-recursive",
        "-silent",
        "-oJ",
        "-cs",
    ]
    if SUBFINDER_RATE_LIMIT is not None:
        cmd.extend(["-rl", str(SUBFINDER_RATE_LIMIT)])
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
            # Fallback: plain-text line (older subfinder versions)
            sub = normalize_subdomain(line)
            if sub:
                result.subdomains.add(sub)
            continue

        # JSONL shape: {"host": "...", "source": "...", "input": "..."}
        host = obj.get("host") or obj.get("domain") or obj.get("subdomain")
        sub = normalize_subdomain(str(host)) if host else None
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "subfinder failed"

    result.duration = time.monotonic() - start
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE: ASSETFINDER
# ═════════════════════════════════════════════════════════════════════════════

def _run_assetfinder(domain: str) -> SourceResult:
    """
    Run assetfinder with --subs-only. Plain-text output, one domain per line.
    Assetfinder deduplicates internally but we re-normalize anyway.
    """
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


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE: AMASS (passive)
# ═════════════════════════════════════════════════════════════════════════════

def _run_amass(domain: str) -> SourceResult:
    """
    Run amass in passive mode. Plain-text output via -o -, which writes
    discovered names to stdout.
    """
    start = time.monotonic()
    result = SourceResult("amass", domain)

    if not _tool_available("amass"):
        result.error = "amass not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = [
        "amass", "enum",
        "-passive",
        "-d", domain,
        "-timeout", "10",       # minutes
        "-silent",
    ]
    ok, stdout, stderr = _run(cmd, TIMEOUT_AMASS, "amass")

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "amass failed"

    result.duration = time.monotonic() - start
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE: CRT.SH (HTTP fallback, no binary required)
# ═════════════════════════════════════════════════════════════════════════════

def _run_crtsh(domain: str) -> SourceResult:
    """
    Query crt.sh for certificate transparency entries. This is a fallback
    source that requires no installed binary — just an HTTP request.
    """
    start = time.monotonic()
    result = SourceResult("crt.sh", domain)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "argus-subs/1.0"},
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
#  DNS VALIDATION (optional, via dnsx)
# ═════════════════════════════════════════════════════════════════════════════

def _validate_with_dnsx(subdomains: list[str]) -> set[str]:
    """
    Pass a list of subdomains through dnsx and return only the ones that
    resolve. Returns an empty set if dnsx is unavailable or fails.
    """
    if not subdomains:
        return set()

    if not _tool_available("dnsx"):
        log.info("    dnsx not installed — skipping resolution validation")
        return set()

    # Feed subdomains via stdin
    try:
        result = subprocess.run(
            ["dnsx", "-silent"],
            input="\n".join(subdomains),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_DNSX,
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

def _aggregate(
    results: list[SourceResult],
    roots: list[str],
) -> dict[str, SubdomainRecord]:
    """
    Merge per-source results into a deduplicated mapping of
    subdomain → {sources, root, first_seen}.
    """
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


def _build_json_report(
    roots: list[str],
    merged: dict[str, SubdomainRecord],
    source_results: list[SourceResult],
    resolved: set[str],
    elapsed: float,
) -> dict:
    """Build the structured JSON report."""
    by_source = {}
    for sr in source_results:
        by_source[sr.source] = {
            "domain": sr.domain,
            "ok": sr.ok,
            "count": sr.count,
            "duration_seconds": round(sr.duration, 2),
            "error": sr.error,
        }

    records = []
    for name in sorted(merged):
        rec = merged[name]
        records.append({
            "subdomain": rec.name,
            "root": rec.root,
            "sources": sorted(rec.sources),
            "source_count": len(rec.sources),
            "resolves": name in resolved if resolved else None,
            "first_seen": rec.first_seen,
        })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "wildcards": roots,
        "totals": {
            "unique_subdomains": len(merged),
            "resolved": len(resolved) if resolved else None,
            "sources_run": len(source_results),
            "sources_ok": sum(1 for s in source_results if s.ok),
        },
        "sources": by_source,
        "subdomains": records,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def enumerate_subdomains(
    wildcard_file: Path,
    outdir: Path,
    resolve: bool = True,
) -> Path:
    """
    Enumerate subdomains for every root domain in `wildcard_file`.

    Writes:
      • outdir/all_subs.txt
      • outdir/subdomains.json
      • outdir/subs_resolved.txt   (if resolve=True and dnsx is available)

    Returns the path to `all_subs.txt` (for downstream stages).
    """
    start = time.monotonic()

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

    # ── Run all sources for all domains in parallel ─────────────────────────
    tasks: list[tuple[str, str]] = []  # (source_name, domain)
    for domain in roots:
        tasks.append(("subfinder", domain))
        tasks.append(("assetfinder", domain))
        tasks.append(("amass", domain))

    source_results: list[SourceResult] = []
    runners = {
        "subfinder": _run_subfinder,
        "assetfinder": _run_assetfinder,
        "amass": _run_amass,
    }

    log.info(f"  Running {len(tasks)} source task(s) in parallel...")
    log.info("")

    with ThreadPoolExecutor(max_workers=min(len(tasks), 9)) as pool:
        future_map = {}
        for source_name, domain in tasks:
            fn = runners[source_name]
            fut = pool.submit(fn, domain)
            future_map[fut] = (source_name, domain)

        for fut in as_completed(future_map):
            source_name, domain = future_map[fut]
            try:
                sr: SourceResult = fut.result()
            except Exception as e:
                sr = SourceResult(source_name, domain, error=str(e))

            source_results.append(sr)
            status = (
                f"✓ {sr.count:>4} subdomains"
                if sr.ok
                else f"✗ {sr.error or 'failed'}"
            )
            log.info(f"    {source_name:<12} {domain:<24} {status}  ({sr.duration:.1f}s)")

    # ── Aggregate + deduplicate ─────────────────────────────────────────────
    merged = _aggregate(source_results, roots)
    unique_subs = sorted(merged.keys())

    log.info("")
    log.info(f"  Aggregate : {len(unique_subs)} unique subdomain(s)")

    # ── Optional crt.sh fallback ────────────────────────────────────────────
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

    # ── Optional DNS validation ─────────────────────────────────────────────
    resolved: set[str] = set()
    if resolve and unique_subs:
        log.info("")
        log.info("  Resolving via dnsx...")
        resolved = _validate_with_dnsx(unique_subs)
        if resolved:
            log.info(f"  Resolved  : {len(resolved)} / {len(unique_subs)} "
                     f"({len(resolved) / len(unique_subs) * 100:.0f}%)")
        else:
            log.info("  Resolved  : (dnsx unavailable or no results)")

    # ── Write plain-text inventory ──────────────────────────────────────────
    txt_path = outdir / "all_subs.txt"
    txt_path.write_text("\n".join(unique_subs) + ("\n" if unique_subs else ""))
    log.info("")
    log.info(f"  Wrote     : {txt_path}  ({len(unique_subs)} lines)")

    # ── Write resolved subset ───────────────────────────────────────────────
    if resolved:
        resolved_path = outdir / "subs_resolved.txt"
        resolved_path.write_text("\n".join(sorted(resolved)) + "\n")
        log.info(f"  Wrote     : {resolved_path}  ({len(resolved)} lines)")

    # ── Write JSON report ───────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    report = _build_json_report(roots, merged, source_results, resolved, elapsed)
    json_path = outdir / "subdomains.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    log.info(f"  Wrote     : {json_path}")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")

    return txt_path


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
    wildcard = base / "wildcard.txt"
    out = base / "output"
    try:
        enumerate_subdomains(wildcard, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
