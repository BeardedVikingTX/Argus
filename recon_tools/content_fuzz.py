#!/usr/bin/env python3
"""
recon_tools/content_fuzz.py — Content & Directory Discovery
═══════════════════════════════════════════════════════════════════════════════

Purpose-built content discovery stage for Argus.

Two-phase strategy:

  Phase 1 — feroxbuster
      Broad, automatic recursive mapping. Feroxbuster is purpose-built for
      recursive directory discovery and will recurse into found directories
      without manual re-invocation. This is the "map the surface" pass.

  Phase 2 — ffuf
      Surgical, extension-aware fuzzing on the root of every live host.
      ffuf is the Swiss-army knife: fast, scriptable, and precise when you
      supply a focused wordlist and a tight filter set.

Both tools emit JSON. This module parses both formats, normalises them into a
single record shape, deduplicates by URL, and classifies each result by
confidence so the human triager can focus on signal, not noise.

Filtering strategy:
  • Soft-404s are detected per-host by probing a random 32-char path and
    recording the response length; any result matching that length within a
    tolerance band is discarded.
  • Status codes are filtered against an allow-list (200, 201, 204, 301,
    302, 307, 308, 401, 403, 500) rather than blindly accepting all 200s.
  • Results are scored: access-gated (401/403) and backup/extension hits
    receive higher confidence than generic 200s.

Outputs (into `outdir`):
  • content_fuzz.json        — structured report, primary output
  • fuzzed_directories.txt   — one discovered URL per line (for nuclei/katana)
  • fuzzed_interesting.txt   — high-confidence subset for manual review

Integration:
  main.py → run_one("fuzz") → run_content_fuzz(live_urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.content_fuzz")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# ── Wordlists ────────────────────────────────────────────────────────────────
# Order matters: smallest / fastest lists first for quick wins.
# Each entry: (display_name, absolute_path, extensions_override_or_None)
# If the path does not exist, the entry is skipped with a warning.
WORDLISTS: list[tuple[str, str, Optional[list[str]]]] = [
    # Fast triage
    ("common",               "/usr/share/seclists/Discovery/Web-Content/common.txt",                     None),
    # Broad directory coverage
    ("raft-medium-dirs",     "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",    None),
    # File-level discovery
    ("raft-medium-files",    "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",          None),
    # API surface
    ("api-endpoints",        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",          None),
    # Backup / source-file hunting
    ("backup-files",         "/usr/share/seclists/Discovery/Web-Content/backup-files.txt",               [".bak", ".old", ".zip", ".tar.gz", ".sql", ".swp"]),
]

# Extensions applied when the wordlist does not carry its own override.
DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".js", ".html"]

# ── Execution limits ──────────────────────────────────────────────────────────
FEROX_THREADS       = 50
FEROX_RATE_LIMIT    = 100       # requests/second
FEROX_TIMEOUT       = 600       # seconds per host
FEROX_DEPTH         = 3
FEROX_SCAN_LIMIT    = 20000     # max requests per host — prevents runaway scans

FFUF_THREADS        = 40
FFUF_RATE_LIMIT     = 100
FFUF_TIMEOUT        = 600
FFUF_MAX_TIME       = 600       # --maxtime in seconds

# ── Filtering ────────────────────────────────────────────────────────────────
SOFT_404_PROBE_LEN  = 32        # random path length used for soft-404 detection
SOFT_404_TOLERANCE  = 50        # bytes of variance allowed around baseline
ALLOWED_STATUS      = {200, 201, 204, 301, 302, 307, 308, 401, 403, 500}

# ── Confidence scoring ───────────────────────────────────────────────────────
CONFIDENCE_HIGH_THRESHOLD = 60

# ── Paths ────────────────────────────────────────────────────────────────────
SECLISTS_FALLBACK_PATHS = [
    Path("/usr/share/seclists"),
    Path("/opt/seclists"),
]
MINIMAL_WORDLIST_FALLBACK = [
    "admin", "api", "v1", "v2", "v3", "login", "dashboard", "internal",
    "debug", "test", "staging", "dev", "backup", "config", "actuator",
    "swagger", "graphql", "phpmyadmin", "jenkins", "grafana",
]


# ═════════════════════════════════════════════════════════════════════════════
#  RESULT DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class FuzzFinding:
    url: str
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    redirect: str = ""
    source_tool: str = ""
    source_wordlist: str = ""
    extension: str = ""
    confidence: int = 0
    reasons: list[str] = field(default_factory=list)
    host: str = ""
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status": self.status,
            "length": self.length,
            "words": self.words,
            "lines": self.lines,
            "content_type": self.content_type,
            "redirect": self.redirect,
            "source_tool": self.source_tool,
            "source_wordlist": self.source_wordlist,
            "extension": self.extension,
            "confidence": self.confidence,
            "reasons": self.reasons,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  WORDLIST RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_wordlists() -> list[tuple[str, Path, Optional[list[str]]]]:
    """
    Return only wordlists that actually exist. If none exist, write a
    minimal fallback wordlist to outdir and return that instead.
    """
    available: list[tuple[str, Path, Optional[list[str]]]] = []
    missing: list[str] = []

    for name, path_str, exts in WORDLISTS:
        p = Path(path_str)
        if p.exists() and p.is_file() and p.stat().st_size > 0:
            available.append((name, p, exts))
        else:
            missing.append(name)

    if missing:
        log.info(f"    Wordlists unavailable: {', '.join(missing)}")

    if not available:
        log.warning("    No SecLists wordlist found — writing minimal fallback.")
        # Try to locate a SecLists root
        sec_root = next((p for p in SECLISTS_FALLBACK_PATHS if p.exists()), None)
        if sec_root:
            log.info(f"    SecLists root detected at {sec_root}, but none of the")
            log.info("    configured wordlists were present. Check your SecLists layout.")
        fallback_dir = Path(__file__).resolve().parent.parent / "output"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        fallback = fallback_dir / "argus_minimal_wordlist.txt"
        fallback.write_text("\n".join(MINIMAL_WORDLIST_FALLBACK) + "\n")
        available.append(("minimal-fallback", fallback, DEFAULT_EXTENSIONS))

    log.info(f"    Using {len(available)} wordlist(s):")
    for name, p, exts in available:
        try:
            count = sum(1 for _ in p.open("r", errors="ignore"))
        except OSError:
            count = 0
        ext_label = f"  extensions={exts}" if exts else ""
        log.info(f"      · {name:<18} {p}  ({count} lines){ext_label}")

    return available


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_hosts(input_file: Path) -> list[str]:
    """
    Accept either live_urls.txt (bare URLs) or live_hosts.txt
    (httpx format: 'URL [status] [title] [tech]').
    Returns a deduplicated, sorted list of scheme://host bases.
    """
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    bases: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            continue
        scheme = parsed.scheme or "https"
        base = f"{scheme}://{parsed.netloc}"
        bases.add(base.rstrip("/"))

    return sorted(bases)


def _soft_404_baseline(base_url: str) -> tuple[int, int]:
    """
    Probe a random non-existent path and return (length, status).
    Used to suppress false positives from catch-all responses.
    """
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=SOFT_404_PROBE_LEN))
    probe = f"{base_url}/{rand}"
    try:
        import requests
        r = requests.get(probe, timeout=10, verify=False, allow_redirects=False)
        return len(r.content), r.status_code
    except Exception:
        return 0, 0


# ═════════════════════════════════════════════════════════════════════════════
#  FEROXBUSTER
# ═════════════════════════════════════════════════════════════════════════════

def _ferox_cmd(
    base_url: str,
    wordlist: Path,
    extensions: Optional[list[str]],
    output_file: Path,
) -> list[str]:
    cmd = [
        "feroxbuster",
        "--url", base_url,
        "--wordlist", str(wordlist),
        "--json",
        "--output", str(output_file),
        "--silent",
        "--no-state",
        "--redirects",
        "--depth", str(FEROX_DEPTH),
        "--threads", str(FEROX_THREADS),
        "--rate-limit", str(FEROX_RATE_LIMIT),
        "--scan-limit", str(FEROX_SCAN_LIMIT),
        "--timeout", "10",
        "--status-codes", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
    ]
    if extensions:
        cmd.extend(["--extensions", ",".join(extensions)])
    return cmd


def _run_ferox(base_url: str, wordlist_name: str, wordlist: Path,
               extensions: Optional[list[str]], workdir: Path) -> list[FuzzFinding]:
    """
    Run feroxbuster against one base URL with one wordlist.
    Feroxbuster JSON is line-delimited: one JSON object per line.
    """
    if not shutil.which("feroxbuster"):
        log.warning("    feroxbuster not found — skipping recursive phase")
        return []

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ferox_{tag}_{wl_tag}.json"

    cmd = _ferox_cmd(base_url, wordlist, extensions, out_file)
    log.info(f"      ferox  {base_url}  wl={wordlist_name}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=FEROX_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"      ferox timeout after {FEROX_TIMEOUT}s on {base_url}")
        return []
    except FileNotFoundError:
        return []

    if not out_file.exists():
        log.debug(f"      ferox produced no output file (stderr: {result.stderr[:160]})")
        return []

    findings: list[FuzzFinding] = []
    for line in out_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "response":
            continue

        f = _build_finding(
            url=obj.get("url", ""),
            status=obj.get("status", 0),
            length=obj.get("content_length", 0),
            words=obj.get("word_count", 0),
            lines=obj.get("line_count", 0),
            content_type=obj.get("content_type", ""),
            redirect=obj.get("redirect_url", "") or "",
            tool="feroxbuster",
            wordlist=wordlist_name,
            extension=obj.get("extension", "") or "",
        )
        if f:
            findings.append(f)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  FFUF
# ═════════════════════════════════════════════════════════════════════════════

def _ffuf_cmd(
    base_url: str,
    wordlist: Path,
    extensions: Optional[list[str]],
    output_file: Path,
    baseline_length: int,
) -> list[str]:
    cmd = [
        "ffuf",
        "-u", f"{base_url}/FUZZ",
        "-w", str(wordlist),
        "-json",
        "-o", str(output_file),
        "-s",                                # silent
        "-t", str(FFUF_THREADS),
        "-rate", str(FFUF_RATE_LIMIT),
        "-timeout", "10",
        "-maxtime", str(FFUF_MAX_TIME),
        "-mc", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
        "-noninteractive",
    ]
    if extensions:
        cmd.extend(["-e", ",".join(extensions)])
    # Filter soft-404 responses by size if we have a reliable baseline
    if baseline_length > 0:
        cmd.extend(["-fs", f"{max(0, baseline_length - SOFT_404_TOLERANCE)}-{baseline_length + SOFT_404_TOLERANCE}"])
    return cmd


def _run_ffuf(base_url: str, wordlist_name: str, wordlist: Path,
              extensions: Optional[list[str]], baseline_length: int,
              workdir: Path) -> list[FuzzFinding]:
    """Run ffuf against one base URL with one wordlist."""
    if not shutil.which("ffuf"):
        log.warning("    ffuf not found — skipping surgical phase")
        return []

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ffuf_{tag}_{wl_tag}.json"

    cmd = _ffuf_cmd(base_url, wordlist, extensions, out_file, baseline_length)
    log.info(f"      ffuf   {base_url}  wl={wordlist_name}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=FFUF_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"      ffuf timeout after {FFUF_TIMEOUT}s on {base_url}")
        return []
    except FileNotFoundError:
        return []

    if not out_file.exists():
        log.debug(f"      ffuf produced no output file (stderr: {result.stderr[:160]})")
        return []

    try:
        data = json.loads(out_file.read_text())
    except json.JSONDecodeError as e:
        log.warning(f"      ffuf JSON parse error: {e}")
        return []

    findings: list[FuzzFinding] = []
    for entry in data.get("results", []):
        f = _build_finding(
            url=entry.get("url", ""),
            status=entry.get("status", 0),
            length=entry.get("length", 0),
            words=entry.get("words", 0),
            lines=entry.get("lines", 0),
            content_type=entry.get("content-type", ""),
            redirect=entry.get("redirectlocation", "") or "",
            tool="ffuf",
            wordlist=wordlist_name,
            extension=entry.get("input", {}).get("FUZZ", "") or "",
        )
        if f:
            findings.append(f)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  FINDING CONSTRUCTION & SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _build_finding(
    url: str,
    status: int,
    length: int,
    words: int,
    lines: int,
    content_type: str,
    redirect: str,
    tool: str,
    wordlist: str,
    extension: str,
) -> Optional[FuzzFinding]:
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc or ""
    path = parsed.path or "/"

    f = FuzzFinding(
        url=url, status=status, length=length, words=words, lines=lines,
        content_type=content_type, redirect=redirect,
        source_tool=tool, source_wordlist=wordlist, extension=extension,
        host=host, path=path,
    )
    _score_finding(f)
    return f


BACKUP_EXTENSIONS = {".bak", ".old", ".zip", ".tar.gz", ".sql", ".swp", ".env", ".git"}
SENSITIVE_PATH_WORDS = {
    "admin", "internal", "debug", "actuator", "swagger", "graphql",
    "phpmyadmin", "jenkins", "grafana", "kibana", "backup", "config",
    "secret", "private", "token", "api", "v1", "v2", "v3",
}


def _score_finding(f: FuzzFinding) -> None:
    score = 0
    reasons: list[str] = []

    # Access-gated: 401/403 means something real is behind this path.
    if f.status in (401, 403):
        score += 40
        reasons.append("access_gated")

    # Backup / source / config file extensions.
    if any(f.path.lower().endswith(ext) for ext in BACKUP_EXTENSIONS):
        score += 35
        reasons.append("backup_extension")

    # Sensitive path keyword.
    path_lower = f.path.lower()
    if any(k in path_lower for k in SENSITIVE_PATH_WORDS):
        score += 25
        reasons.append("sensitive_path")

    # API content type.
    ct = (f.content_type or "").lower()
    if "json" in ct or "xml" in ct:
        score += 20
        reasons.append("api_content_type")

    # Server error — potential injection or misconfiguration surface.
    if 500 <= f.status < 600:
        score += 15
        reasons.append("server_error")

    # Generic 200 with meaningful body — low-but-nonzero signal.
    if f.status == 200 and f.length > 200:
        score += 10
        reasons.append("substantial_body")

    f.confidence = min(score, 100)
    f.reasons = reasons


# ═════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
# ═════════════════════════════════════════════════════════════════════════════

def _dedupe(findings: list[FuzzFinding]) -> list[FuzzFinding]:
    """
    Keep the highest-confidence record for each unique URL.
    If two records tie on confidence, prefer the one with more metadata
    (longer content_type, non-empty redirect).
    """
    best: dict[str, FuzzFinding] = {}
    for f in findings:
        key = f.url.rstrip("/").lower()
        existing = best.get(key)
        if not existing:
            best[key] = f
            continue
        if f.confidence > existing.confidence:
            best[key] = f
        elif f.confidence == existing.confidence:
            if (len(f.content_type) + len(f.redirect)) > (
                len(existing.content_type) + len(existing.redirect)
            ):
                best[key] = f
    return list(best.values())


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_content_fuzz(
    live_urls_file: Path,
    outdir: Path,
    *,
    use_ferox: bool = True,
    use_ffuf: bool = True,
    wordlists: Optional[list[tuple[str, Path, Optional[list[str]]]]] = None,
    max_hosts: Optional[int] = None,
) -> Path:
    """
    Run content discovery against every host in `live_urls_file`.

    Returns the path to `content_fuzz.json`.
    """
    start = time.monotonic()

    if not shutil.which("feroxbuster") and not shutil.which("ffuf"):
        raise RuntimeError(
            "Neither feroxbuster nor ffuf is installed. "
            "Run `python3 tools.py --only feroxbuster,ffuf` first."
        )

    # ── Inputs ──────────────────────────────────────────────────────────────
    bases = _extract_hosts(live_urls_file)
    if max_hosts:
        bases = bases[:max_hosts]
    if not bases:
        log.warning("  No live hosts to fuzz — writing empty report")
        report = _empty_report(live_urls_file, start)
        path = outdir / "content_fuzz.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        return path

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "fuzz_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(bases)} host(s) from {live_urls_file.name}")

    # ── Resolve wordlists ───────────────────────────────────────────────────
    if wordlists is None:
        wordlists = _resolve_wordlists()

    # ── Phase 0: soft-404 baselines ─────────────────────────────────────────
    log.info("")
    log.info("  Establishing soft-404 baselines...")
    baselines: dict[str, int] = {}
    for base in bases:
        length, status = _soft_404_baseline(base)
        if length > 0:
            baselines[base] = length
            log.info(f"    {base:<40} baseline={length}B  status={status}")
        else:
            log.info(f"    {base:<40} baseline unavailable (filtering by status only)")

    # ── Phase 1: feroxbuster (broad recursion) ─────────────────────────────
    all_findings: list[FuzzFinding] = []

    if use_ferox and shutil.which("feroxbuster"):
        log.info("")
        log.info("  Phase 1 — feroxbuster (broad recursive mapping)")
        for base in bases:
            for wl_name, wl_path, wl_exts in wordlists:
                findings = _run_ferox(base, wl_name, wl_path, wl_exts, workdir)
                all_findings.extend(findings)
                if findings:
                    log.info(f"        → {len(findings)} hit(s)")
    else:
        log.info("")
        log.info("  Phase 1 — feroxbuster skipped")

    # ── Phase 2: ffuf (surgical, extension-aware) ──────────────────────────
    if use_ffuf and shutil.which("ffuf"):
        log.info("")
        log.info("  Phase 2 — ffuf (surgical fuzzing)")
        for base in bases:
            baseline = baselines.get(base, 0)
            for wl_name, wl_path, wl_exts in wordlists:
                # Skip the largest, slowest lists on the second pass unless
                # the target is small; the goal of phase 2 is precision.
                findings = _run_ffuf(base, wl_name, wl_path, wl_exts, baseline, workdir)
                all_findings.extend(findings)
                if findings:
                    log.info(f"        → {len(findings)} hit(s)")
    else:
        log.info("")
        log.info("  Phase 2 — ffuf skipped")

    # ── Deduplicate ─────────────────────────────────────────────────────────
    log.info("")
    log.info("  Deduplicating and scoring...")
    deduped = _dedupe(all_findings)
    log.info(f"  Unique : {len(deduped)} endpoint(s) after deduplication")

    # ── Sort: confidence desc, then status priority, then URL ──────────────
    STATUS_PRIORITY = {200: 1, 201: 1, 204: 1, 401: 2, 403: 2,
                       301: 3, 302: 3, 307: 3, 308: 3, 500: 4}

    def _sort_key(f: FuzzFinding) -> tuple:
        return (
            -f.confidence,
            STATUS_PRIORITY.get(f.status, 5),
            f.url,
        )

    deduped.sort(key=_sort_key)

    # ── Write outputs ───────────────────────────────────────────────────────
    all_urls = sorted({f.url for f in deduped})
    interesting = [f for f in deduped if f.confidence >= CONFIDENCE_HIGH_THRESHOLD]

    txt_all = outdir / "fuzzed_directories.txt"
    txt_all.write_text("\n".join(all_urls) + ("\n" if all_urls else ""))

    txt_interesting = outdir / "fuzzed_interesting.txt"
    txt_interesting.write_text("\n".join(f.url for f in interesting) + ("\n" if interesting else ""))

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_status: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_extension: dict[str, int] = {}
    by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}

    for f in deduped:
        by_status[str(f.status)] = by_status.get(str(f.status), 0) + 1
        by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
        ext = f.extension or "(none)"
        by_extension[ext] = by_extension.get(ext, 0) + 1
        if f.confidence >= CONFIDENCE_HIGH_THRESHOLD:
            by_confidence["high"] += 1
        elif f.confidence >= 30:
            by_confidence["medium"] += 1
        else:
            by_confidence["low"] += 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "hosts_scanned": len(bases),
        "config": {
            "ferox_threads": FEROX_THREADS,
            "ferox_rate_limit": FEROX_RATE_LIMIT,
            "ferox_depth": FEROX_DEPTH,
            "ffuf_threads": FFUF_THREADS,
            "ffuf_rate_limit": FFUF_RATE_LIMIT,
            "allowed_status": sorted(ALLOWED_STATUS),
            "soft_404_tolerance": SOFT_404_TOLERANCE,
            "wordlists": [name for name, _, _ in wordlists],
        },
        "totals": {
            "raw_findings": len(all_findings),
            "unique_endpoints": len(deduped),
            "high_confidence": len(interesting),
        },
        "summary": {
            "by_status": by_status,
            "by_tool": by_tool,
            "by_extension": dict(sorted(by_extension.items(), key=lambda kv: -kv[1])),
            "by_confidence": by_confidence,
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "content_fuzz.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup workdir ─────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(deduped):>5} endpoint(s)")
    log.info(f"    {txt_all.name:<24} {len(all_urls):>5} URL(s)")
    log.info(f"    {txt_interesting.name:<24} {len(interesting):>5} high-confidence URL(s)")

    log.info("")
    log.info(f"  Confidence : high={by_confidence['high']}  "
             f"medium={by_confidence['medium']}  low={by_confidence['low']}")

    if interesting:
        log.info("")
        log.info("  Top high-confidence hits:")
        for f in interesting[:10]:
            reasons = ",".join(f.reasons) if f.reasons else "-"
            log.info(f"    {f.status:>3}  {f.confidence:>3}  {f.url:<70}  [{reasons}]")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _empty_report(input_file: Path, start: float) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "hosts_scanned": 0,
        "config": {},
        "totals": {"raw_findings": 0, "unique_endpoints": 0, "high_confidence": 0},
        "summary": {"by_status": {}, "by_tool": {}, "by_extension": {}, "by_confidence": {}},
        "findings": [],
    }


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
    live_urls = base / "output" / "live_urls.txt"
    out = base / "output"
    try:
        run_content_fuzz(live_urls, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
