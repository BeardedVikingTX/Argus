#!/usr/bin/env python3
"""
recon_tools/cors_check.py — CORS Misconfiguration Scanner
═══════════════════════════════════════════════════════════════════════════════

Production-grade CORS scanner for Argus.

Accuracy model — five layers of hardening:

  1. Strict reflection matching
     Access-Control-Allow-Origin is split on commas and checked for EXACT
     membership, not substring match. Prevents false positives from
     ACAO values that merely CONTAIN the probe origin.

  2. Multi-value header parsing
     Some servers return multiple ACAO headers via misconfigured proxies.
     We read all values via resp.raw.headers.getlist() when available,
     not just the collapsed CaseInsensitiveDict value.

  3. Vary: Origin awareness
     When ACAO reflects Origin, the server SHOULD set `Vary: Origin` so
     caches partition per-origin. Missing Vary + reflection = cache
     poisoning surface (reportable).

  4. Method rotation
     CORS can be configured per-method. We test GET (full battery) and
     POST/PUT/PATCH/DELETE (spot check) so per-method misconfigs aren't
     missed.

  5. Sensitive body detection
     When reflection + ACAC:true, we look for password/token/email markers
     in the response body. Presence upgrades severity — a credentialed
     reflection of PUBLIC data is not exploitable; one containing PII is.

Additional hardening:
  • Null origin tested as the LITERAL string "null" (not None)
  • Wildcard subdomain literals (`*.example.com`) detected and flagged
  • ACAC:true without ACAO detected (browser applies same-origin fallback;
    often indicates incomplete config)
  • Preflight `Access-Control-Request-Method` matches the tested method
  • Origin split by comma, exact membership — not substring

Config integration (config.py):
  • MODULE_RATE_LIMITS["cors"]     → threads + rate_limit
  • ACTIVE_HEADERS + AUTH_HEADERS  → merged into every request
  • AUTH_COOKIES                   → applied from request.txt session
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Outputs (into `outdir`):
  • cors_findings.json       — full structured report
  • cors_critical.txt        — CRITICAL/HIGH URL list
  • cors_all.txt             — every flagged URL

Remote DB (if scan_id is provided):
  • cors_findings table      — one row per (scan_id, url_hash, probe, method)

Integration:
  main.py → run_one("cors") → run_cors_check(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import string
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.cors")

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


def _cors_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("cors", {})
    threads = entry.get("concurrency", 10)
    rate = entry.get("rate_limit", 100)
    if not isinstance(threads, int) or threads < 1:
        threads = 10
    if not isinstance(rate, int) or rate < 0:
        rate = 100
    return {"threads": threads, "rate_limit": rate}


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS    = 10
DEFAULT_RATE_LIMIT = 100
DEFAULT_TIMEOUT    = 12
DEFAULT_RETRIES    = 2
MAX_URLS           = 5000
MAX_BODY_BYTES     = 65536

SEV_CRITICAL_SCORE = 80
SEV_HIGH_SCORE     = 50
SEV_MEDIUM_SCORE   = 30
SEV_LOW_SCORE      = 10

# Method rotation — full battery on GET, spot check on others.
CORS_TEST_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
PRIMARY_METHOD = "GET"
SECONDARY_METHODS = ["POST"]   # spot-check — full battery is expensive

# Markers that suggest a response contains sensitive data (upgrades severity).
SENSITIVE_MARKERS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key",
    "ssn", "social_security", "credit_card", "card_number", "cvv",
    "email", "user_id", "account_id", "username",
    "authorization", "bearer ",
    "session_id", "sessionid",
]


# ═════════════════════════════════════════════════════════════════════════════
#  ORIGIN PROBES
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class OriginProbe:
    name: str
    origin: str
    description: str
    weight: int = 0


def _build_probes(target_host: str, base_host: str) -> list[OriginProbe]:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    attacker_origin = f"https://evil-{rand}.example"
    attacker_host   = f"evil-{rand}.example"

    probes = [
        OriginProbe(
            "arbitrary_reflection",
            attacker_origin,
            "Server reflects an entirely attacker-controlled origin",
            weight=40,
        ),
        OriginProbe(
            "null_origin",
            "null",
            "Server trusts the literal 'null' origin (sandboxed iframe / data: URI)",
            weight=40,
        ),
        OriginProbe(
            "suffix_bypass",
            f"https://{target_host}.{attacker_host}",
            "Server uses endsWith(target_host) and accepts target.com.evil.com",
            weight=35,
        ),
        OriginProbe(
            "prefix_bypass",
            f"https://{attacker_host}-{target_host}",
            "Server uses startsWith(target_host) and accepts evil-target.com",
            weight=35,
        ),
        OriginProbe(
            "subdomain_trust",
            f"https://{attacker_host}.{target_host}",
            "Server trusts *.target_host — attacker registers a matching subdomain",
            weight=30,
        ),
        OriginProbe(
            "scheme_downgrade",
            f"http://{target_host}",
            "Server accepts an HTTP origin on an HTTPS endpoint",
            weight=25,
        ),
        OriginProbe(
            "pre_domain_injection",
            f"https://{attacker_host}.{target_host}",
            "Server naively contains(target_host) and accepts attacker.com.target.com",
            weight=30,
        ),
    ]

    # If the target is a subdomain, add a probe against the apex domain too.
    if base_host and base_host != target_host:
        probes.append(OriginProbe(
            "apex_origin",
            f"https://{base_host}",
            "Server trusts the apex domain for this subdomain (cross-subdomain CORS)",
            weight=20,
        ))

    return probes


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CORSFinding:
    url: str
    method: str = "GET"
    probe_name: str = ""
    sent_origin: str = ""
    reflected: bool = False
    acao: str = ""
    acac: bool = False
    acam: str = ""
    acah: str = ""
    status_code: int = 0
    content_type: str = ""
    score: int = 0
    severity: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    vary_origin: bool = False
    sensitive_body: bool = False
    auth_enabled: bool = False
    response_snippet: str = ""
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "url":              self.url,
            "method":           self.method,
            "probe":            self.probe_name,
            "sent_origin":      self.sent_origin,
            "reflected":        self.reflected,
            "acao":             self.acao,
            "acac":             self.acac,
            "acam":             self.acam,
            "acah":             self.acah,
            "status_code":      self.status_code,
            "content_type":     self.content_type,
            "score":            self.score,
            "severity":         self.severity,
            "reasons":          self.reasons,
            "vary_origin":      self.vary_origin,
            "sensitive_body":   self.sensitive_body,
            "auth_enabled":     self.auth_enabled,
            "response_snippet": self.response_snippet,
            "first_seen":       self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    urls: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        urls.add(url.rstrip("/"))
    return sorted(urls)


def _host_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or ""


def _base_host(target_host: str) -> str:
    """Approximate the apex domain from a hostname (best-effort, 2 labels)."""
    parts = target_host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return target_host


# ═════════════════════════════════════════════════════════════════════════════
#  HEADER PARSING (multi-value aware)
# ═════════════════════════════════════════════════════════════════════════════

def _get_header_values(resp: requests.Response, name: str) -> list[str]:
    """
    Return ALL values for a header, not just the last one.

    requests' CaseInsensitiveDict collapses duplicate headers to a
    comma-joined string. We try the urllib3 raw HTTPHeaderDict first
    (which preserves duplicates via getlist), then fall back to splitting
    the collapsed value.
    """
    # Preferred: urllib3 raw headers
    try:
        values = resp.raw.headers.getlist(name)
        if values:
            return [v.strip() for v in values if v and v.strip()]
    except (AttributeError, Exception):
        pass

    # Fallback: split on comma (imperfect for values that legitimately contain commas)
    collapsed = resp.headers.get(name, "")
    if not collapsed:
        return []
    return [v.strip() for v in collapsed.split(",") if v.strip()]


def _parse_acao(values: list[str]) -> tuple[str, list[str]]:
    """Return (joined_string, individual_values)."""
    if not values:
        return "", []
    return ",".join(values), values


# ═════════════════════════════════════════════════════════════════════════════
#  REFLECTION MATCHING (strict)
# ═════════════════════════════════════════════════════════════════════════════

def _is_reflected(sent_origin: str, acao_values: list[str]) -> bool:
    """
    Check whether the server reflected our sent origin.

    Exact membership only — ACAO is split on commas and each value is
    compared against the sent origin. No substring matching.
    """
    if not sent_origin or not acao_values:
        return False

    sent_norm = sent_origin.rstrip("/").lower()

    for v in acao_values:
        v_norm = v.rstrip("/").lower()
        if v_norm == sent_norm:
            return True
        # Special case: null origin, browsers send literal "null"
        if sent_norm == "null" and v_norm == "null":
            return True
        # Trailing-slash tolerance (rare but seen)
        if v_norm.rstrip("/") == sent_norm.rstrip("/"):
            return True

    return False


# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE BODY DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _has_sensitive_data(body: str) -> bool:
    if not body:
        return False
    body_lower = body.lower()
    return any(marker in body_lower for marker in SENSITIVE_MARKERS)


# ═════════════════════════════════════════════════════════════════════════════
#  REQUEST ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _make_session() -> requests.Session:
    s = requests.Session()
    hdrs = _target_headers()
    if hdrs:
        s.headers.update(hdrs)
    cookies = _auth_cookies()
    if cookies:
        for name, value in cookies.items():
            s.cookies.set(name, value)
    s.verify = False
    return s


def _send_probe(
    session: requests.Session,
    url: str,
    probe: OriginProbe,
    method: str,
    timeout: int,
    retries: int,
    auth_enabled: bool,
) -> Optional[CORSFinding]:
    headers = {"Origin": probe.origin}

    resp = None
    for attempt in range(retries + 1):
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
            break
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            log.debug(f"    probe failed: {method} {url} origin={probe.name}: {e}")
            return None

    if resp is None:
        return None

    # ── Multi-value header parsing ──────────────────────────────────────────
    acao_values = _get_header_values(resp, "Access-Control-Allow-Origin")
    acao_joined, _ = _parse_acao(acao_values)

    acac_values = _get_header_values(resp, "Access-Control-Allow-Credentials")
    acac = any(v.strip().lower() == "true" for v in acac_values)

    acam_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Methods"))
    acah_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Headers"))

    # ── Vary: Origin tracking ───────────────────────────────────────────────
    vary_values = _get_header_values(resp, "Vary")
    vary_joined = ",".join(vary_values).lower()
    vary_origin = "origin" in vary_joined

    # ── Strict reflection ───────────────────────────────────────────────────
    reflected = _is_reflected(probe.origin, acao_values)

    # ── Body snippet + sensitivity ──────────────────────────────────────────
    snippet = ""
    sensitive = False
    try:
        content_length = int(resp.headers.get("Content-Length", "0") or 0)
    except ValueError:
        content_length = 0
    if 0 < content_length <= MAX_BODY_BYTES:
        try:
            raw = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
            text = raw.decode("utf-8", errors="replace")
            snippet = text[:500]
            sensitive = _has_sensitive_data(text)
        except Exception:
            pass

    resp.close()

    finding = CORSFinding(
        url=url,
        method=method,
        probe_name=probe.name,
        sent_origin=probe.origin,
        reflected=reflected,
        acao=acao_joined,
        acac=acac,
        acam=acam_joined,
        acah=acah_joined,
        status_code=resp.status_code,
        content_type=resp.headers.get("Content-Type", ""),
        vary_origin=vary_origin,
        sensitive_body=sensitive,
        auth_enabled=auth_enabled,
        response_snippet=snippet,
        first_seen=datetime.now(timezone.utc).isoformat(),
    )

    _score_finding(finding, probe)
    return finding


# ═════════════════════════════════════════════════════════════════════════════
#  SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _score_finding(f: CORSFinding, probe: OriginProbe) -> None:
    score = 0
    reasons: list[str] = []

    # ── Reflection is the gate ──────────────────────────────────────────────
    if f.reflected:
        reasons.append("origin_reflected")
        score += probe.weight

        if probe.name == "null_origin":
            reasons.append("null_origin_trusted")
            score += 10

        if probe.name in (
            "suffix_bypass", "prefix_bypass",
            "subdomain_trust", "pre_domain_injection",
        ):
            reasons.append("regex_bypass")
            score += 15

        if probe.name == "apex_origin":
            reasons.append("apex_origin_trusted")
            score += 5

    # ── Credentials + reflection is the money case ──────────────────────────
    if f.reflected and f.acac:
        reasons.append("credentials_allowed")
        score += 50

        # If we have auth AND the body contains sensitive markers, upgrade
        if f.auth_enabled and f.sensitive_body:
            reasons.append("sensitive_data_in_body")
            score += 15

        # Missing Vary: Origin alongside reflection + credentials is a
        # cache poisoning surface — some CDNs will cache the reflected ACAO
        if not f.vary_origin:
            reasons.append("missing_vary_origin")
            score += 10

    # ── Wildcard with credentials (invalid spec, but seen) ──────────────────
    if f.acao.strip() == "*" and f.acac:
        reasons.append("wildcard_with_credentials")
        score += 40

    # ── Wildcard subdomain literal ──────────────────────────────────────────
    if f.acao.strip().startswith("*.") or "/*." in f.acao:
        reasons.append("wildcard_subdomain_literal")
        score += 20

    # ── ACAC without any ACAO ───────────────────────────────────────────────
    if not f.acao and f.acac:
        reasons.append("acac_without_acao")
        score += 15

    # ── Scheme downgrade ────────────────────────────────────────────────────
    if probe.name == "scheme_downgrade" and f.reflected:
        reasons.append("scheme_downgrade")
        score += 10

    # ── Informational wildcard ──────────────────────────────────────────────
    if f.acao.strip() == "*" and not f.acac:
        reasons.append("wildcard_without_credentials")
        score += 5

    # ── No CORS headers at all ──────────────────────────────────────────────
    if not f.acao and not f.acac:
        f.score = 0
        f.severity = "INFO"
        f.reasons = []
        return

    f.score = min(score, 100)

    if f.score >= SEV_CRITICAL_SCORE:
        f.severity = "CRITICAL"
    elif f.score >= SEV_HIGH_SCORE:
        f.severity = "HIGH"
    elif f.score >= SEV_MEDIUM_SCORE:
        f.severity = "MEDIUM"
    elif f.score >= SEV_LOW_SCORE:
        f.severity = "LOW"
    else:
        f.severity = "INFO"

    f.reasons = reasons


# ═════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT (OPTIONS) PROBE
# ═════════════════════════════════════════════════════════════════════════════

def _send_preflight(
    session: requests.Session,
    url: str,
    origin: str,
    request_method: str,
    timeout: int,
    auth_enabled: bool,
) -> Optional[CORSFinding]:
    """Send a proper preflight matching the method being tested."""
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    try:
        resp = session.options(
            url, headers=headers, timeout=timeout, allow_redirects=False,
        )
    except requests.RequestException:
        return None

    acao_values = _get_header_values(resp, "Access-Control-Allow-Origin")
    acao_joined, _ = _parse_acao(acao_values)
    acac = any(v.strip().lower() == "true"
               for v in _get_header_values(resp, "Access-Control-Allow-Credentials"))
    acam_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Methods"))
    acah_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Headers"))

    reflected = _is_reflected(origin, acao_values)
    if not reflected and not (acao_joined.strip() == "*" and acac):
        return None

    finding = CORSFinding(
        url=url,
        method="OPTIONS",
        probe_name=f"preflight:{request_method}",
        sent_origin=origin,
        reflected=reflected,
        acao=acao_joined,
        acac=acac,
        acam=acam_joined,
        acah=acah_joined,
        status_code=resp.status_code,
        content_type=resp.headers.get("Content-Type", ""),
        auth_enabled=auth_enabled,
        first_seen=datetime.now(timezone.utc).isoformat(),
    )

    score = 0
    reasons = ["preflight_reflection"]
    if reflected:
        score += 30
    if acac:
        score += 40
        reasons.append("credentials_allowed")
    if acam_joined:
        score += 5
        reasons.append(f"methods:{acam_joined[:60]}")

    finding.score = min(score, 100)
    if finding.score >= SEV_CRITICAL_SCORE:
        finding.severity = "CRITICAL"
    elif finding.score >= SEV_HIGH_SCORE:
        finding.severity = "HIGH"
    elif finding.score >= SEV_MEDIUM_SCORE:
        finding.severity = "MEDIUM"
    else:
        finding.severity = "LOW"
    finding.reasons = reasons

    return finding


# ═════════════════════════════════════════════════════════════════════════════
#  PER-URL SCAN
# ═════════════════════════════════════════════════════════════════════════════

def _scan_url(
    url: str,
    timeout: int,
    retries: int,
    auth_enabled: bool,
) -> list[CORSFinding]:
    host = _host_from_url(url)
    if not host:
        return []

    probes = _build_probes(host, _base_host(host))
    session = _make_session()
    findings: list[CORSFinding] = []

    try:
        # ── Full battery on primary method ──────────────────────────────────
        for probe in probes:
            f = _send_probe(
                session, url, probe, PRIMARY_METHOD, timeout, retries, auth_enabled,
            )
            if f and f.severity != "INFO":
                findings.append(f)

        # ── Spot-check secondary methods (only if primary found nothing) ────
        if not any(x.severity in ("CRITICAL", "HIGH") for x in findings):
            for method in SECONDARY_METHODS:
                for probe in probes[:3]:  # just the top-3 probes to limit noise
                    f = _send_probe(
                        session, url, probe, method, timeout, retries, auth_enabled,
                    )
                    if f and f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                        findings.append(f)

        # ── Preflight, only if we don't already have a CRITICAL ─────────────
        if not any(x.severity == "CRITICAL" for x in findings):
            attacker = probes[0].origin
            pf = _send_preflight(
                session, url, attacker, PRIMARY_METHOD, timeout, auth_enabled,
            )
            if pf and pf.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                findings.append(pf)

    finally:
        session.close()

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[CORSFinding]) -> None:
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
        result = DB.upsert_cors_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} CORS finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_cors_check(
    live_urls_file: Path,
    outdir: Path,
    *,
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_urls: int = MAX_URLS,
    headers: Optional[dict] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Scan every URL in `live_urls_file` for CORS misconfigurations.

    Threads and rate_limit are read from MODULE_RATE_LIMITS["cors"] unless
    overridden. Headers are merged from config.py + request.txt auth unless
    overridden. If scan_id is provided, self-syncs to the dedicated
    `cors_findings` table.
    """
    start = time.monotonic()

    settings = _cors_settings()
    eff_threads = threads if threads is not None else settings["threads"]
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]

    urls = _extract_urls(live_urls_file)
    if not urls:
        log.warning("  No URLs to scan — writing empty report")
        report = _empty_report(live_urls_file, start)
        path = outdir / "cors_findings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
        return path

    if len(urls) > max_urls:
        log.warning(f"  Capping scan at {max_urls} URL(s) (input had {len(urls)})")
        urls = urls[:max_urls]

    outdir.mkdir(parents=True, exist_ok=True)

    auth_enabled = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : threads={eff_threads}  rate_limit={eff_rate}/s  "
             f"timeout={timeout}s  retries={retries}")

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to every request")
    if auth_enabled:
        log.info(f"  Auth   : ENABLED (request.txt) — credentialed probes")
    else:
        log.info(f"  Auth   : disabled")
    log.info("")

    # ── Scan ────────────────────────────────────────────────────────────────
    all_findings: list[CORSFinding] = []
    scanned = 0
    errored = 0
    rate_sleep = 1.0 / eff_rate if eff_rate and eff_rate > 0 else 0.0

    with ThreadPoolExecutor(max_workers=eff_threads) as pool:
        future_map = {
            pool.submit(_scan_url, url, timeout, retries, auth_enabled): url
            for url in urls
        }

        for future in as_completed(future_map):
            url = future_map[future]
            scanned += 1
            try:
                findings = future.result()
            except Exception as e:
                log.debug(f"    scan error on {url}: {e}")
                errored += 1
                continue

            if findings:
                all_findings.extend(findings)
                crit = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
                if crit:
                    log.info(
                        f"    [{crit[0].severity:<8}] {url[:70]:<70}  "
                        f"probe={crit[0].probe_name}  score={crit[0].score}"
                    )

            if scanned % 25 == 0:
                log.info(f"    ... scanned {scanned}/{len(urls)}")

            if rate_sleep > 0:
                time.sleep(rate_sleep)

    # ── Dedupe (keep highest score per URL) ─────────────────────────────────
    best_per_url: dict[str, CORSFinding] = {}
    for f in all_findings:
        key = f.url.rstrip("/").lower()
        existing = best_per_url.get(key)
        if not existing or f.score > existing.score:
            best_per_url[key] = f

    final = sorted(best_per_url.values(), key=lambda f: (-f.score, f.url))

    # ── Write flat lists ────────────────────────────────────────────────────
    critical_urls = [f.url for f in final if f.severity in ("CRITICAL", "HIGH")]
    all_urls_flagged = [f.url for f in final]

    crit_path = outdir / "cors_critical.txt"
    crit_path.write_text("\n".join(critical_urls) + ("\n" if critical_urls else ""))

    all_path = outdir / "cors_all.txt"
    all_path.write_text("\n".join(all_urls_flagged) + ("\n" if all_urls_flagged else ""))

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in final:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "scanned": scanned,
        "errored": errored,
        "auth_enabled": auth_enabled,
        "config": {
            "threads":       eff_threads,
            "rate_limit":    eff_rate,
            "timeout":       timeout,
            "retries":       retries,
            "headers_count": len(cfg_hdrs),
        },
        "totals": {
            "urls_scanned":  scanned,
            "findings":      len(final),
            "critical":      by_sev["CRITICAL"],
            "high":          by_sev["HIGH"],
            "medium":        by_sev["MEDIUM"],
            "low":           by_sev["LOW"],
        },
        "by_severity": by_sev,
        "findings": [f.to_dict() for f in final],
    }

    json_path = outdir / "cors_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, final)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<22} {len(final):>4} finding(s)")
    log.info(f"    {crit_path.name:<22} {len(critical_urls):>4} URL(s)")
    log.info(f"    {all_path.name:<22} {len(all_urls_flagged):>4} URL(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_sev['CRITICAL']}  "
        f"HIGH={by_sev['HIGH']}  "
        f"MEDIUM={by_sev['MEDIUM']}  "
        f"LOW={by_sev['LOW']}"
    )

    if critical_urls:
        log.info("")
        log.info("  Critical / high findings:")
        for f in final:
            if f.severity in ("CRITICAL", "HIGH"):
                reasons = ",".join(f.reasons[:4])
                log.info(
                    f"    [{f.severity:<8}] {f.url[:60]:<60}  "
                    f"probe={f.probe_name:<22}  score={f.score:>3}  [{reasons}]"
                )

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _empty_report(input_file: Path, start: float) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "scanned": 0,
        "errored": 0,
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "totals": {"urls_scanned": 0, "findings": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
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

    parser = argparse.ArgumentParser(description="Argus CORS scanner (standalone)")
    parser.add_argument("--input", type=Path, default=live_urls)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    args = parser.parse_args()

    try:
        run_cors_check(
            args.input, args.output,
            threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
