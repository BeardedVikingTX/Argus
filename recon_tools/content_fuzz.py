#!/usr/bin/env python3
"""
recon_tools/content_fuzz.py — Content & Directory Discovery
═══════════════════════════════════════════════════════════════════════════════

Two-phase content discovery: feroxbuster (broad recursion) + ffuf (surgical).

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every request. Rate limits are honored to stay within program rules.

Config integration (config.py):
  • MODULE_RATE_LIMITS["fuzz"]              → threads + rate_limit for both tools
  • ACTIVE_HEADERS + AUTH_HEADERS           → -H flags on feroxbuster and ffuf
  • AUTH_COOKIES                            → applied to soft-404 baseline probes
  • SYNC_TO_DB, BRIDGE_*                    → remote database sync

Outputs (into `outdir`):
  • content_fuzz.json        — structured report
  • fuzzed_directories.txt   — every discovered URL
  • fuzzed_interesting.txt   — high-confidence subset

Remote DB (if scan_id is provided and bridge is reachable):
  • content_fuzz table       — one row per (scan_id, url_hash)

Integration:
  main.py → run_one("fuzz") → run_content_fuzz(live_urls_file, outdir)
  main.py also syncs content_fuzz.json via _sync_stage_artifacts()
  Standalone: run_content_fuzz(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import json
import logging
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


def _fuzz_settings() -> dict:
    """Return effective (threads, rate_limit) for fuzzing tools."""
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("fuzz", {})
    threads = entry.get("concurrency", 50)
    rate = entry.get("rate_limit", 100)
    if not isinstance(threads, int) or threads < 1:
        threads = 50
    if not isinstance(rate, int) or rate < 0:
        rate = 100
    return {"threads": threads, "rate_limit": rate}


def _target_headers() -> dict[str, str]:
    """Return merged headers for target traffic (auth overrides platform)."""
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _tool_header_args() -> list[str]:
    """Return ['Name: Value', ...] for tools that accept -H."""
    return [f"{k}: {v}" for k, v in _target_headers().items()]


def _auth_cookies() -> dict[str, str]:
    """Return auth cookies (for the soft-404 baseline probes)."""
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

WORDLISTS: list[tuple[str, str, Optional[list[str]]]] = [
    ("common",            "/usr/share/seclists/Discovery/Web-Content/common.txt",                  None),
    ("raft-medium-dirs",  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", None),
    ("raft-medium-files", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",       None),
    ("api-endpoints",     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",       None),
    ("backup-files",      "/usr/share/seclists/Discovery/Web-Content/backup-files.txt",
     [".bak", ".old", ".zip", ".tar.gz", ".sql", ".swp"]),
]

DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".js", ".html"]

FEROX_THREADS         = 50
FEROX_RATE_LIMIT      = 100
FEROX_TIMEOUT         = 600
FEROX_DEPTH           = 3
FEROX_SCAN_LIMIT      = 20000

FFUF_THREADS          = 40
FFUF_RATE_LIMIT       = 100
FFUF_TIMEOUT          = 600
FFUF_MAX_TIME         = 600

SOFT_404_PROBE_LEN    = 32
SOFT_404_TOLERANCE    = 50
ALLOWED_STATUS        = {200, 201, 204, 301, 302, 307, 308, 401, 403, 500}

CONFIDENCE_HIGH_THRESHOLD = 60

SECLISTS_FALLBACK_PATHS = [Path("/usr/share/seclists"), Path("/opt/seclists")]
MINIMAL_WORDLIST_FALLBACK = [
    "admin", "api", "v1", "v2", "v3", "login", "dashboard", "internal",
    "debug", "test", "staging", "dev", "backup", "config", "actuator",
    "swagger", "graphql", "phpmyadmin", "jenkins", "grafana",
]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
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
    auth_enabled: bool = False
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "url":             self.url,
            "host":            self.host,
            "path":            self.path,
            "status":          self.status,
            "length":          self.length,
            "words":           self.words,
            "lines":           self.lines,
            "content_type":    self.content_type,
            "redirect":        self.redirect,
            "source_tool":     self.source_tool,
            "source_wordlist": self.source_wordlist,
            "extension":       self.extension,
            "confidence":      self.confidence,
            "reasons":         self.reasons,
            "auth_enabled":    self.auth_enabled,
            "first_seen":      self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  WORDLIST RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_wordlists() -> list[tuple[str, Path, Optional[list[str]]]]:
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
    """Probe a random path with headers + cookies to get a baseline."""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=SOFT_404_PROBE_LEN))
    probe = f"{base_url}/{rand}"
    try:
        import requests
        cookies = _auth_cookies()
        r = requests.get(
            probe,
            headers=_target_headers() or None,
            cookies=cookies or None,
            timeout=10,
            verify=False,
            allow_redirects=False,
        )
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
    threads: int,
    rate_limit: int,
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
        "--threads", str(threads),
        "--scan-limit", str(FEROX_SCAN_LIMIT),
        "--timeout", "10",
        "--status-codes", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["--rate-limit", str(rate_limit)])
    if extensions:
        cmd.extend(["--extensions", ",".join(extensions)])
    for hdr in _tool_header_args():
        cmd.extend(["-H", hdr])
    return cmd


def _run_ferox(
    base_url: str, wordlist_name: str, wordlist: Path,
    extensions: Optional[list[str]], workdir: Path,
    threads: int, rate_limit: int,
) -> list[FuzzFinding]:
    if not shutil.which("feroxbuster"):
        log.warning("    feroxbuster not found — skipping recursive phase")
        return []

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ferox_{tag}_{wl_tag}.json"

    cmd = _ferox_cmd(base_url, wordlist, extensions, out_file, threads, rate_limit)
    log.info(f"      ferox  {base_url}  wl={wordlist_name}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=FEROX_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning(f"      ferox timeout after {FEROX_TIMEOUT}s on {base_url}")
        return []
    except FileNotFoundError:
        return []

    if not out_file.exists():
        log.debug(f"      ferox produced no output file (stderr: {result.stderr[:160]})")
        return []

    auth_on = bool(_cfg("AUTH_ENABLED", False))
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
            auth_enabled=auth_on,
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
    threads: int,
    rate_limit: int,
) -> list[str]:
    cmd = [
        "ffuf",
        "-u", f"{base_url}/FUZZ",
        "-w", str(wordlist),
        "-json",
        "-o", str(output_file),
        "-s",
        "-t", str(threads),
        "-timeout", "10",
        "-maxtime", str(FFUF_MAX_TIME),
        "-mc", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
        "-noninteractive",
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])
    if extensions:
        cmd.extend(["-e", ",".join(extensions)])
    if baseline_length > 0:
        cmd.extend(["-fs", f"{max(0, baseline_length - SOFT_404_TOLERANCE)}-{baseline_length + SOFT_404_TOLERANCE}"])
    for hdr in _tool_header_args():
        cmd.extend(["-H", hdr])
    return cmd


def _run_ffuf(
    base_url: str, wordlist_name: str, wordlist: Path,
    extensions: Optional[list[str]], baseline_length: int,
    workdir: Path, threads: int, rate_limit: int,
) -> list[FuzzFinding]:
    if not shutil.which("ffuf"):
        log.warning("    ffuf not found — skipping surgical phase")
        return []

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ffuf_{tag}_{wl_tag}.json"

    cmd = _ffuf_cmd(base_url, wordlist, extensions, out_file, baseline_length, threads, rate_limit)
    log.info(f"      ffuf   {base_url}  wl={wordlist_name}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=FFUF_TIMEOUT)
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

    auth_on = bool(_cfg("AUTH_ENABLED", False))
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
            auth_enabled=auth_on,
        )
        if f:
            findings.append(f)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  FINDING CONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════════

def _build_finding(
    url: str, status: int, length: int, words: int, lines: int,
    content_type: str, redirect: str, tool: str, wordlist: str,
    extension: str, auth_enabled: bool = False,
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
        host=host, path=path, auth_enabled=auth_enabled,
        first_seen=datetime.now(timezone.utc).isoformat(),
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

    if f.status in (401, 403):
        score += 40
        reasons.append("access_gated")

    if any(f.path.lower().endswith(ext) for ext in BACKUP_EXTENSIONS):
        score += 35
        reasons.append("backup_extension")

    if any(k in f.path.lower() for k in SENSITIVE_PATH_WORDS):
        score += 25
        reasons.append("sensitive_path")

    ct = (f.content_type or "").lower()
    if "json" in ct or "xml" in ct:
        score += 20
        reasons.append("api_content_type")

    if 500 <= f.status < 600:
        score += 15
        reasons.append("server_error")

    if f.status == 200 and f.length > 200:
        score += 10
        reasons.append("substantial_body")

    f.confidence = min(score, 100)
    f.reasons = reasons


def _dedupe(findings: list[FuzzFinding]) -> list[FuzzFinding]:
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
            if (len(f.content_type) + len(f.redirect)) > (len(existing.content_type) + len(existing.redirect)):
                best[key] = f
    return list(best.values())


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[FuzzFinding]) -> None:
    if not findings:
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

    try:
        payloads = [f.to_dict() for f in findings]
        result = DB.upsert_content_fuzz(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} endpoint(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


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
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Run content discovery against every host in `live_urls_file`.

    Threads and rate_limit are read from MODULE_RATE_LIMITS["fuzz"] unless
    overridden. If scan_id is provided, self-syncs to the remote database.
    """
    start = time.monotonic()

    if not shutil.which("feroxbuster") and not shutil.which("ffuf"):
        raise RuntimeError(
            "Neither feroxbuster nor ffuf is installed. "
            "Run `python3 tools.py --only feroxbuster,ffuf` first."
        )

    # ── Effective settings ─────────────────────────────────────────────────
    settings = _fuzz_settings()
    eff_threads = threads if threads is not None else settings["threads"]
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]

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

    # ── Config display ──────────────────────────────────────────────────────
    rate_label = f"{eff_rate}/s" if eff_rate and eff_rate > 0 else "unlimited"
    log.info(f"  Config : threads={eff_threads}  rate_limit={rate_label}")
    log.info(f"           source: MODULE_RATE_LIMITS['fuzz']")

    if eff_rate and 0 < eff_rate < 20:
        log.info("")
        log.info(f"  {chr(9888)}  rate_limit={eff_rate}/s is EXTREMELY slow for fuzzing.")
        log.info(f"     Fuzzing sends thousands of requests per host. At {eff_rate}/s,")
        log.info(f"     a single 20,000-request scan takes ~{20000//eff_rate//60} minutes.")
        log.info(f"     If your program allows 50-100/s, raise this significantly.")
        log.info("")

    # ── Headers ─────────────────────────────────────────────────────────────
    hdrs = _target_headers()
    auth_on = bool(_cfg("AUTH_ENABLED", False))

    if hdrs:
        log.info(f"  Headers: {len(hdrs)} configured, applied to all fuzz requests")
        for k, v in list(hdrs.items())[:4]:
            v_short = v[:50] + "…" if len(v) > 50 else v
            log.info(f"           · {k}: {v_short}")
        if len(hdrs) > 4:
            log.info(f"           · ... and {len(hdrs) - 4} more")
    else:
        log.info(f"  Headers: none configured")

    if auth_on:
        log.info(f"  Auth   : ENABLED (request.txt) — fuzzing authenticated surface")
    else:
        log.info(f"  Auth   : disabled — fuzzing unauthenticated only")
    log.info("")

    # ── Wordlists ───────────────────────────────────────────────────────────
    if wordlists is None:
        wordlists = _resolve_wordlists()

    # ── Soft-404 baselines ──────────────────────────────────────────────────
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

    # ── Phase 1: feroxbuster ───────────────────────────────────────────────
    all_findings: list[FuzzFinding] = []

    if use_ferox and shutil.which("feroxbuster"):
        log.info("")
        log.info("  Phase 1 — feroxbuster (broad recursive mapping)")
        for base in bases:
            for wl_name, wl_path, wl_exts in wordlists:
                findings = _run_ferox(
                    base, wl_name, wl_path, wl_exts, workdir,
                    threads=eff_threads, rate_limit=eff_rate,
                )
                all_findings.extend(findings)
                if findings:
                    log.info(f"        → {len(findings)} hit(s)")
    else:
        log.info("")
        log.info("  Phase 1 — feroxbuster skipped")

    # ── Phase 2: ffuf ──────────────────────────────────────────────────────
    if use_ffuf and shutil.which("ffuf"):
        log.info("")
        log.info("  Phase 2 — ffuf (surgical fuzzing)")
        for base in bases:
            baseline = baselines.get(base, 0)
            for wl_name, wl_path, wl_exts in wordlists:
                findings = _run_ffuf(
                    base, wl_name, wl_path, wl_exts, baseline, workdir,
                    threads=eff_threads, rate_limit=eff_rate,
                )
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

    STATUS_PRIORITY = {200: 1, 201: 1, 204: 1, 401: 2, 403: 2,
                       301: 3, 302: 3, 307: 3, 308: 3, 500: 4}

    deduped.sort(key=lambda f: (-f.confidence, STATUS_PRIORITY.get(f.status, 5), f.url))

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
        "auth_enabled": auth_on,
        "config": {
            "threads":              eff_threads,
            "rate_limit":           eff_rate,
            "headers_count":        len(hdrs),
            "ferox_depth":          FEROX_DEPTH,
            "ferox_scan_limit":     FEROX_SCAN_LIMIT,
            "ffuf_max_time":        FFUF_MAX_TIME,
            "allowed_status":       sorted(ALLOWED_STATUS),
            "soft_404_tolerance":   SOFT_404_TOLERANCE,
            "wordlists":            [name for name, _, _ in wordlists],
        },
        "totals": {
            "raw_findings":      len(all_findings),
            "unique_endpoints":  len(deduped),
            "high_confidence":   len(interesting),
        },
        "summary": {
            "by_status":     by_status,
            "by_tool":       by_tool,
            "by_extension":  dict(sorted(by_extension.items(), key=lambda kv: -kv[1])),
            "by_confidence": by_confidence,
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "content_fuzz.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info(f"  Outputs :")
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
        "auth_enabled": False,
        "config": {},
        "totals": {"raw_findings": 0, "unique_endpoints": 0, "high_confidence": 0},
        "summary": {"by_status": {}, "by_tool": {}, "by_extension": {}, "by_confidence": {}},
        "findings": [],
    }


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
    live_urls = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus content fuzz (standalone)")
    parser.add_argument("--input", type=Path, default=live_urls)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--no-ferox", action="store_true")
    parser.add_argument("--no-ffuf", action="store_true")
    args = parser.parse_args()

    try:
        run_content_fuzz(
            args.input, args.output,
            use_ferox=not args.no_ferox,
            use_ffuf=not args.no_ffuf,
            threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
