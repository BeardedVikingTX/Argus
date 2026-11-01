#!/usr/bin/env python3
"""
recon_tools/nuclei_scan.py — Template-Driven Vulnerability Scanning
═══════════════════════════════════════════════════════════════════════════════

The vulnerability scanning stage for Argus. Wraps ProjectDiscovery's Nuclei
with bug-bounty-safe defaults, scope enforcement, and full JSONL field capture.

WHY THIS MODULE IS DIFFERENT
────────────────────────────
Nuclei is the LOUDEST stage in the pipeline. Every request is a real
vulnerability probe against the target. The defaults here are deliberately
conservative — search results consistently recommend 5-10 req/s for bug
bounty targets, 1 req/s for anything hitting an API, and bulk-size of 5-10
to prevent template-level burst concurrency.

Config integration (config.py):
  • MODULE_RATE_LIMITS["nuclei"]["rate_limit"]    → -rl (default 5)
  • MODULE_RATE_LIMITS["nuclei"]["concurrency"]   → -c  (default 10)
  • MODULE_RATE_LIMITS["nuclei"]["bulk_size"]     → -bs (default 5)
  • ACTIVE_HEADERS + AUTH_HEADERS                 → -H on every request
  • AUTH_COOKIES                                  → applied as Cookie header
  • SYNC_TO_DB, BRIDGE_*                          → remote database sync

Scan profiles:
  • recommended  — curated subset (~4,000 templates), safe defaults
  • critical     — severity critical only (fastest first pass)
  • standard     — critical + high + medium (default)
  • thorough     — all severities except info
  • full         — everything including info (noisiest)

All profiles respect the -rl / -c / -bs from config. The profile only
controls -severity and -tags; the rate limits are always honoured.

Outputs (into `outdir`):
  • nuclei_findings.json      — full structured report
  • nuclei_critical.txt       — CRITICAL + HIGH matched URLs
  • nuclei_all.txt            — every matched URL
  • nuclei_raw.jsonl          — raw Nuclei output for reprocessing

Remote DB (if scan_id is provided):
  • nuclei_findings table     — one row per unique finding
  • nuclei_scans table        — one row per batch (metadata)

Integration:
  main.py → run_one("nuclei") → run_nuclei_scan(live_urls_file, outdir)
  main.py also syncs nuclei_findings.json via _sync_stage_artifacts()
  Standalone: run_nuclei_scan(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.nuclei_scan")

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


def _nuclei_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("nuclei", {})
    return {
        "rate_limit":  entry.get("rate_limit", 5),
        "concurrency": entry.get("concurrency", 10),
        "bulk_size":   entry.get("bulk_size", 5),
        "timeout":     entry.get("timeout", 10),
        "retries":     entry.get("retries", 1),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _tool_header_args() -> list[str]:
    """Return ['Name: Value', ...] for nuclei's -H flag."""
    return [f"{k}: {v}" for k, v in _target_headers().items()]


def _auth_cookies_header() -> Optional[str]:
    """Return a Cookie header string if auth cookies are configured."""
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return None
    cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_RATE_LIMIT      = 5
DEFAULT_CONCURRENCY     = 10
DEFAULT_BULK_SIZE       = 5
DEFAULT_TIMEOUT         = 10
DEFAULT_RETRIES         = 1

MAX_TARGETS_PER_BATCH   = 100
NUCLEI_HARD_TIMEOUT     = 7200
MAX_FINDINGS_REPORT     = 10000
TEMPLATE_UPDATE_TIMEOUT = 600

# ── Scan profiles ───────────────────────────────────────────────────────────
# Each profile tunes severity + tags. Rate limits come from config, never
# from the profile — the program's rules always win.
PROFILES: dict[str, dict] = {
    "critical": {
        "severities":   ["critical"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "description":  "Critical only — fastest first pass",
    },
    "standard": {
        "severities":   ["critical", "high", "medium"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "description":  "Critical + high + medium — bug bounty default",
    },
    "thorough": {
        "severities":   ["critical", "high", "medium", "low"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce"],
        "description":  "All severities except info — deep audit",
    },
    "recommended": {
        "severities":   None,   # let nuclei decide
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "templates":    ["-as"],   # autoscan: tech-aware template selection
        "description":  "Recommended template subset with autoscan",
    },
    "full": {
        "severities":   None,
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz"],   # exclude only the most destructive
        "description":  "Everything including info — noisiest",
    },
}

DEFAULT_PROFILE = "standard"


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class NucleiFinding:
    template_id:        str
    template_name:      str = ""
    template_path:      str = ""
    template_author:    list[str] = field(default_factory=list)
    severity:           str = "UNKNOWN"
    cvss_score:         Optional[float] = None
    cve_ids:            list[str] = field(default_factory=list)
    cwe_ids:            list[str] = field(default_factory=list)
    matched_at:         str = ""
    host:               str = ""
    ip:                 str = ""
    port:               Optional[int] = None
    scheme:             str = ""
    path:               str = ""
    matcher_name:       str = ""
    extracted_results:  list[str] = field(default_factory=list)
    curl_command:       str = ""
    request:            str = ""
    response:           str = ""
    tags:               list[str] = field(default_factory=list)
    description:        str = ""
    reference:          list[str] = field(default_factory=list)
    metadata:           dict = field(default_factory=dict)
    auth_enabled:       bool = False
    first_seen:         str = ""

    def to_dict(self) -> dict:
        return {
            "template_id":       self.template_id,
            "template_name":     self.template_name,
            "template_path":     self.template_path,
            "template_author":   self.template_author,
            "severity":          self.severity,
            "cvss_score":        self.cvss_score,
            "cve_ids":           self.cve_ids,
            "cwe_ids":           self.cwe_ids,
            "matched_at":        self.matched_at,
            "host":              self.host,
            "ip":                self.ip,
            "port":              self.port,
            "scheme":            self.scheme,
            "path":              self.path,
            "matcher_name":      self.matcher_name,
            "extracted_results": self.extracted_results,
            "curl_command":      self.curl_command,
            "request":           self.request,
            "response":          self.response,
            "tags":              self.tags,
            "description":       self.description,
            "reference":         self.reference,
            "metadata":          self.metadata,
            "auth_enabled":      self.auth_enabled,
            "first_seen":        self.first_seen,
        }


@dataclass
class BatchResult:
    batch_index:    int
    input_file:     str = ""
    targets_count:  int = 0
    findings_count: int = 0
    duration_ms:    int = 0
    rate_limit:     Optional[int] = None
    concurrency:    Optional[int] = None
    bulk_size:      Optional[int] = None
    severities:     str = ""
    tags_allow:     str = ""
    tags_deny:      str = ""
    templates_used: str = ""
    headless:       bool = False
    auth_enabled:   bool = False
    error:          str = ""
    first_seen:     str = ""

    def to_dict(self) -> dict:
        return {
            "batch_index":    self.batch_index,
            "input_file":     self.input_file,
            "targets_count":  self.targets_count,
            "findings_count": self.findings_count,
            "duration_ms":    self.duration_ms,
            "rate_limit":     self.rate_limit,
            "concurrency":    self.concurrency,
            "bulk_size":      self.bulk_size,
            "severities":     self.severities,
            "tags_allow":     self.tags_allow,
            "tags_deny":      self.tags_deny,
            "templates_used": self.templates_used,
            "headless":       self.headless,
            "auth_enabled":   self.auth_enabled,
            "error":          self.error,
            "first_seen":     self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT
# ═════════════════════════════════════════════════════════════════════════════

def _load_targets(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    targets: list[str] = []
    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        if token not in seen:
            seen.add(token)
            targets.append(token)
    return targets


# ═════════════════════════════════════════════════════════════════════════════
#  TEMPLATE MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

def _update_templates() -> bool:
    if not shutil.which("nuclei"):
        log.warning("    nuclei not installed — cannot update templates")
        return False

    log.info("    Updating nuclei templates...")
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True, text=True, timeout=TEMPLATE_UPDATE_TIMEOUT,
        )
        if result.returncode == 0:
            log.info("    Templates updated")
            return True
        log.warning(f"    template update returned {result.returncode}: "
                    f"{result.stderr.strip()[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log.warning(f"    template update timed out after {TEMPLATE_UPDATE_TIMEOUT}s")
        return False
    except FileNotFoundError:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  COMMAND BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def _build_cmd(
    targets_file: Path,
    output_jsonl: Path,
    *,
    rate_limit: int,
    concurrency: int,
    bulk_size: int,
    timeout: int,
    retries: int,
    profile: str,
    custom_templates: Optional[list[str]] = None,
    custom_tags: Optional[list[str]] = None,
    cookie_header: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
) -> list[str]:
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_jsonl),
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-bs", str(bulk_size),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-silent",
        "-no-color",
        "-stats",
    ]

    # Severity filter
    if prof.get("severities"):
        cmd.extend(["-severity", ",".join(prof["severities"])])

    # Tags allow (from profile + caller)
    tags_allow: list[str] = []
    if prof.get("tags_allow"):
        tags_allow.extend(prof["tags_allow"])
    if custom_tags:
        tags_allow.extend(custom_tags)
    if tags_allow:
        cmd.extend(["-tags", ",".join(tags_allow)])

    # Tags deny
    if prof.get("tags_deny"):
        cmd.extend(["-exclude-tags", ",".join(prof["tags_deny"])])

    # Profile-specific flags (e.g. -as for autoscan)
    if "templates" in prof:
        cmd.extend(prof["templates"])

    # Custom templates (override profile defaults)
    if custom_templates:
        for t in custom_templates:
            cmd.extend(["-t", t])

    # Headers
    for hdr in _tool_header_args():
        cmd.extend(["-H", hdr])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    # Headless
    if headless:
        cmd.append("-headless")

    # Proxy
    if proxy:
        cmd.extend(["-proxy", proxy])

    return cmd


# ═════════════════════════════════════════════════════════════════════════════
#  EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_batch(
    targets: list[str],
    workdir: Path,
    batch_index: int,
    **kwargs,
) -> tuple[Optional[Path], BatchResult]:
    if not targets:
        return None, BatchResult(batch_index=batch_index)

    targets_file = workdir / f"batch_{batch_index:03d}_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")
    output_jsonl = workdir / f"batch_{batch_index:03d}_output.jsonl"

    cmd = _build_cmd(targets_file, output_jsonl, **kwargs)
    log.info(f"    batch {batch_index:02d}  {len(targets):>3} target(s)  "
             f"→ {output_jsonl.name}")

    started = time.monotonic()
    result = BatchResult(
        batch_index=batch_index,
        input_file=str(targets_file),
        targets_count=len(targets),
        rate_limit=kwargs.get("rate_limit"),
        concurrency=kwargs.get("concurrency"),
        bulk_size=kwargs.get("bulk_size"),
        severities=",".join(PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {})
                            .get("severities") or []),
        tags_allow=",".join(custom_tags) if (custom_tags := kwargs.get("custom_tags")) else "",
        tags_deny=",".join(PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {})
                          .get("tags_deny") or []),
        headless=bool(kwargs.get("headless")),
        auth_enabled=bool(kwargs.get("cookie_header") or _tool_header_args()),
        first_seen=datetime.now(timezone.utc).isoformat(),
    )

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=NUCLEI_HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result.error = f"timeout after {NUCLEI_HARD_TIMEOUT}s"
        log.warning(f"    batch {batch_index} exceeded {NUCLEI_HARD_TIMEOUT}s")
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return None, result
    except FileNotFoundError:
        result.error = "nuclei binary not found"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return None, result

    result.duration_ms = int((time.monotonic() - started) * 1000)

    if not output_jsonl.exists():
        result.error = proc.stderr.strip()[:500] or "no output file produced"
        log.debug(f"    batch {batch_index} produced no JSONL "
                  f"(stderr: {proc.stderr.strip()[:160]})")
        return None, result

    return output_jsonl, result


# ═════════════════════════════════════════════════════════════════════════════
#  JSONL PARSING (full field capture)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_jsonl(path: Path, auth_on: bool) -> list[NucleiFinding]:
    if not path.exists():
        return []

    findings: list[NucleiFinding] = []
    parse_errors = 0
    now = datetime.now(timezone.utc).isoformat()

    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        # Nuclei uses both hyphenated and underscored keys across versions
        info = obj.get("info", {}) or {}
        classification = info.get("classification", {}) or {}

        template_id = (
            obj.get("template-id")
            or obj.get("templateID")
            or obj.get("template_id")
            or ""
        )
        matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
        if not template_id or not matched_at:
            continue

        # CVSS (may be float, string, or absent)
        cvss_raw = classification.get("cvss-score") or classification.get("cvss_score")
        cvss: Optional[float] = None
        if cvss_raw not in (None, "", "null"):
            try:
                cvss = float(cvss_raw)
            except (TypeError, ValueError):
                cvss = None

        # CVE / CWE (may be str or list)
        cves = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cves, str):
            cves = [cves]
        cwes = classification.get("cwe-id") or classification.get("cwe_id") or []
        if isinstance(cwes, str):
            cwes = [cwes]

        # Tags (may be comma string or list)
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        # References (may be str or list)
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        # Author (may be str or list)
        author = info.get("author") or []
        if isinstance(author, str):
            author = [a.strip() for a in author.split(",") if a.strip()]

        # Severity
        sev = (info.get("severity") or "unknown").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "UNKNOWN"

        # Port (may be int, str, or absent)
        port: Optional[int] = None
        port_raw = obj.get("port")
        if port_raw not in (None, "", "null"):
            try:
                port = int(port_raw)
            except (TypeError, ValueError):
                port = None

        findings.append(NucleiFinding(
            template_id=template_id,
            template_name=info.get("name", ""),
            template_path=obj.get("template-path") or obj.get("template_path") or "",
            template_author=author,
            severity=sev,
            cvss_score=cvss,
            cve_ids=cves,
            cwe_ids=cwes,
            matched_at=matched_at,
            host=obj.get("host", ""),
            ip=obj.get("ip", ""),
            port=port,
            scheme=obj.get("scheme", ""),
            path=obj.get("path", ""),
            matcher_name=obj.get("matcher-name") or obj.get("matcher_name") or "",
            extracted_results=obj.get("extracted-results") or obj.get("extracted_results") or [],
            curl_command=obj.get("curl-command") or obj.get("curl_command") or "",
            request=obj.get("request", ""),
            response=obj.get("response", ""),
            tags=tags,
            description=info.get("description", ""),
            reference=refs,
            metadata=classification,
            auth_enabled=auth_on,
            first_seen=now,
        ))

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  DEDUPE + SORT
# ═════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def _dedupe(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    seen: set[tuple] = set()
    deduped: list[NucleiFinding] = []
    for f in findings:
        key = (
            f.template_id,
            f.matched_at,
            f.matcher_name,
            tuple(sorted(f.extracted_results)),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _sort_findings(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 5),
            -(f.cvss_score or 0.0),
            f.template_id,
            f.matched_at,
        ),
    )


def _build_summary(findings: list[NucleiFinding]) -> dict:
    by_severity: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0,
    }
    by_template: dict[str, int] = {}
    by_host: dict[str, int] = {}
    by_scheme: dict[str, int] = {}
    cve_count = 0

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
        host = f.host or f.matched_at.split("/")[2] if "://" in f.matched_at else f.host
        if host:
            by_host[host] = by_host.get(host, 0) + 1
        if f.scheme:
            by_scheme[f.scheme] = by_scheme.get(f.scheme, 0) + 1
        if f.cve_ids:
            cve_count += 1

    return {
        "by_severity":  by_severity,
        "by_template":  dict(sorted(by_template.items(), key=lambda kv: -kv[1])),
        "by_host":      dict(sorted(by_host.items(), key=lambda kv: -kv[1])),
        "by_scheme":    by_scheme,
        "unique_cves":  cve_count,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(
    scan_id: int,
    findings: list[NucleiFinding],
    batches: list[BatchResult],
) -> None:
    if not findings and not batches:
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

    # ── Findings ────────────────────────────────────────────────────────────
    if findings:
        try:
            payloads = [f.to_dict() for f in findings]
            result = DB.upsert_nuclei_findings(scan_id, payloads)
            if result is None:
                log.warning("  DB sync: findings upsert returned None")
            else:
                log.info(f"  DB sync: {result} finding(s) upserted")
        except Exception as e:
            log.warning(f"  DB sync findings exception: {e}")

    # ── Batches ─────────────────────────────────────────────────────────────
    if batches:
        saved = 0
        for b in batches:
            try:
                if DB.save_nuclei_batch(scan_id, b.to_dict()) is not None:
                    saved += 1
            except Exception as e:
                log.debug(f"  DB sync: batch save failed: {e}")
        log.info(f"  DB sync: {saved}/{len(batches)} batch record(s) saved")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_nuclei_scan(
    targets_file: Path,
    outdir: Path,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    bulk_size: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    profile: str = DEFAULT_PROFILE,
    severities: Optional[list[str]] = None,
    tags_allow: Optional[list[str]] = None,
    tags_deny: Optional[list[str]] = None,
    custom_templates: Optional[list[str]] = None,
    custom_tags: Optional[list[str]] = None,
    headers: Optional[dict] = None,
    cookie: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
    update_templates: bool = True,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Run nuclei against every target in `targets_file`.

    Rate limits default to MODULE_RATE_LIMITS["nuclei"] unless overridden.
    Headers come from config.py (ACTIVE_HEADERS + AUTH_HEADERS) unless overridden.
    Cookie comes from AUTH_COOKIES unless overridden.

    If scan_id is provided, self-syncs to the nuclei_findings + nuclei_scans tables.
    """
    start = time.monotonic()

    if not shutil.which("nuclei"):
        raise RuntimeError(
            "nuclei not installed. Run `python3 tools.py --only nuclei` first."
        )

    # ── Effective settings ──────────────────────────────────────────────────
    settings = _nuclei_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_bulk = bulk_size if bulk_size is not None else settings["bulk_size"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_retries = retries if retries is not None else settings["retries"]

    if profile not in PROFILES:
        log.warning(f"  Unknown profile '{profile}' — falling back to '{DEFAULT_PROFILE}'")
        profile = DEFAULT_PROFILE

    # ── Inputs ──────────────────────────────────────────────────────────────
    targets = _load_targets(targets_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "nuclei_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(targets)} target(s) from {targets_file.name}")
    if not targets:
        log.warning("  No targets to scan — writing empty report")
        return _write_empty_report(outdir, targets_file, start)

    # ── Config display ──────────────────────────────────────────────────────
    prof = PROFILES[profile]
    log.info(f"  Profile: {profile}  ({prof['description']})")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
             f"bulk_size={eff_bulk}  timeout={eff_timeout}s  retries={eff_retries}")
    log.info(f"           source: MODULE_RATE_LIMITS['nuclei']")

    if eff_rate and 0 < eff_rate < 10:
        log.info("")
        log.info(f"  {chr(9888)}  rate_limit={eff_rate}/s is conservative for nuclei.")
        log.info(f"     Bugs bounty-safe baselines are 5-10/s per target.")
        log.info(f"     If your program allows 20-50/s, consider raising this.")
        log.info("")

    # ── Headers ─────────────────────────────────────────────────────────────
    cfg_hdrs = _target_headers()
    cookie_header = _auth_cookies_header() or cookie
    auth_on = bool(cfg_hdrs or cookie_header)

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to all requests")
        for k, v in list(cfg_hdrs.items())[:4]:
            v_short = v[:50] + "…" if len(v) > 50 else v
            log.info(f"           · {k}: {v_short}")
    if cookie_header:
        log.info(f"  Auth   : ENABLED ({len(cookie_header)} char Cookie header)")
    else:
        log.info(f"  Auth   : disabled")
    log.info("")

    # ── Template update ─────────────────────────────────────────────────────
    if update_templates:
        _update_templates()
        log.info("")

    # ── Batching ────────────────────────────────────────────────────────────
    batches: list[list[str]] = [
        targets[i:i + MAX_TARGETS_PER_BATCH]
        for i in range(0, len(targets), MAX_TARGETS_PER_BATCH)
    ]
    log.info(f"  Scanning {len(targets)} target(s) in {len(batches)} batch(es)...")

    all_findings: list[NucleiFinding] = []
    batch_results: list[BatchResult] = []

    kwargs = dict(
        rate_limit=eff_rate,
        concurrency=eff_conc,
        bulk_size=eff_bulk,
        timeout=eff_timeout,
        retries=eff_retries,
        profile=profile,
        custom_templates=custom_templates,
        custom_tags=custom_tags or tags_allow,
        cookie_header=cookie_header,
        headless=headless,
        proxy=proxy,
    )

    # Apply explicit severity/tags overrides on top of profile
    if severities is not None:
        PROFILES[profile]["severities"] = severities
    if tags_deny is not None:
        PROFILES[profile]["tags_deny"] = tags_deny

    for i, batch in enumerate(batches, 1):
        output, result = _run_batch(batch, workdir, i, **kwargs)
        batch_results.append(result)
        if output:
            batch_findings = _parse_jsonl(output, auth_on)
            all_findings.extend(batch_findings)
            result.findings_count = len(batch_findings)
            log.info(f"      → {len(batch_findings)} finding(s)")

    # ── Dedupe + sort ───────────────────────────────────────────────────────
    deduped = _dedupe(all_findings)
    sorted_findings = _sort_findings(deduped)

    log.info("")
    log.info(f"  Raw findings      : {len(all_findings)}")
    log.info(f"  Unique findings   : {len(sorted_findings)}")

    # ── Write flat outputs ──────────────────────────────────────────────────
    critical_high = [f for f in sorted_findings if f.severity in ("CRITICAL", "HIGH")]
    all_urls = sorted({f.matched_at for f in sorted_findings})

    (outdir / "nuclei_critical.txt").write_text(
        "\n".join(f.matched_at for f in critical_high) + ("\n" if critical_high else "")
    )
    (outdir / "nuclei_all.txt").write_text(
        "\n".join(all_urls) + ("\n" if all_urls else "")
    )

    # Combined raw JSONL for debugging
    raw_jsonl = outdir / "nuclei_raw.jsonl"
    with raw_jsonl.open("w") as f:
        for finding in sorted_findings:
            f.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    summary = _build_summary(sorted_findings)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(targets_file),
        "profile": profile,
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "bulk_size":     eff_bulk,
            "timeout":       eff_timeout,
            "retries":       eff_retries,
            "headers_count": len(cfg_hdrs),
            "cookie_set":    bool(cookie_header),
            "headless":      headless,
            "proxy":         proxy or None,
            "profile_severities": prof.get("severities"),
            "profile_tags_deny":  prof.get("tags_deny"),
            "custom_templates":   custom_templates,
            "custom_tags":        custom_tags,
        },
        "totals": {
            "targets_input":   len(targets),
            "batches":         len(batches),
            "raw_findings":    len(all_findings),
            "unique_findings": len(sorted_findings),
            "critical":        summary["by_severity"]["CRITICAL"],
            "high":            summary["by_severity"]["HIGH"],
            "medium":          summary["by_severity"]["MEDIUM"],
            "low":             summary["by_severity"]["LOW"],
            "info":            summary["by_severity"]["INFO"],
            "unknown":         summary["by_severity"]["UNKNOWN"],
            "unique_cves":     summary["unique_cves"],
        },
        "summary":  summary,
        "batches":  [b.to_dict() for b in batch_results],
        "findings": [f.to_dict() for f in sorted_findings[:MAX_FINDINGS_REPORT]],
    }

    json_path = outdir / "nuclei_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup ─────────────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, sorted_findings, batch_results)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(sorted_findings):>5} finding(s)")
    log.info(f"    nuclei_critical.txt      {len(critical_high):>5} CRIT/HIGH URL(s)")
    log.info(f"    nuclei_all.txt           {len(all_urls):>5} matched URL(s)")
    log.info(f"    nuclei_raw.jsonl         {len(sorted_findings):>5} raw record(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={summary['by_severity']['CRITICAL']}  "
        f"HIGH={summary['by_severity']['HIGH']}  "
        f"MEDIUM={summary['by_severity']['MEDIUM']}  "
        f"LOW={summary['by_severity']['LOW']}  "
        f"INFO={summary['by_severity']['INFO']}"
    )

    if critical_high:
        log.info("")
        log.info("  Critical / high findings:")
        for f in critical_high[:15]:
            cve = f" [{','.join(f.cve_ids)}]" if f.cve_ids else ""
            log.info(f"    [{f.severity:<8}] {f.template_id:<30} "
                     f"{f.matched_at:<60}{cve}")

    if summary["by_template"]:
        log.info("")
        log.info("  Top templates:")
        for tid, count in list(summary["by_template"].items())[:8]:
            log.info(f"    {tid:<40} {count:>4}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(input_file),
        "profile":         DEFAULT_PROFILE,
        "auth_enabled":    bool(_cfg("AUTH_ENABLED", False)),
        "config":          {},
        "totals": {
            "targets_input": 0, "batches": 0,
            "raw_findings": 0, "unique_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "unknown": 0, "unique_cves": 0,
        },
        "summary":  {"by_severity": {}, "by_template": {}, "by_host": {}, "unique_cves": 0},
        "batches":  [],
        "findings": [],
    }
    path = outdir / "nuclei_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nuclei_critical.txt", "nuclei_all.txt", "nuclei_raw.jsonl"):
        (outdir / name).write_text("")
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
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus nuclei scanner (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--profile", default=DEFAULT_PROFILE,
                        choices=list(PROFILES.keys()))
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--bulk-size", type=int, default=None)
    parser.add_argument("--severities", help="comma-separated severity override")
    parser.add_argument("--tags", help="comma-separated additional tags")
    parser.add_argument("--no-update", action="store_true",
                        help="skip -update-templates")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--proxy", help="proxy URL")
    args = parser.parse_args()

    sev = None
    if args.severities:
        sev = [s.strip().lower() for s in args.severities.split(",") if s.strip()]

    tags = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    try:
        run_nuclei_scan(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            bulk_size=args.bulk_size,
            profile=args.profile,
            severities=sev,
            custom_tags=tags,
            headless=args.headless,
            proxy=args.proxy,
            update_templates=not args.no_update,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
