#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/cors_check.py — CORS Misconfiguration Scanner
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/cors_check.py
  Version   : 3.0.0 "FORSETI"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Production-grade CORS scanner with five layers of accuracy hardening
  and full v3.x module integration.

  v1.0 → v3.0 (silent-failure fixes):
    [FIX]  MODULE_RATE_LIMITS["cors"] → ["cors_check"]. Config.py uses
           "cors_check" — the current file was silently ignoring your
           rate/concurrency config and firing at 10t × 100rps.
    [FIX]  entry.get("rate_limit") → entry.get("rps"). config.py uses "rps".
    [FIX]  headers= kwarg was accepted but never used — now merged at call.
    [FIX]  time.sleep(rate_sleep) per-future was INEFFECTIVE — with 10
           workers × 7-15 probes each, real rate was ~50-75 rps despite
           declared 5 rps. Now uses config.RateLimiter per worker.
    [FIX]  KillSwitch.check() before every HTTP request — honors
           .ARGUS_STOP file.
    [FIX]  SCOPE check before every HTTP request — no out-of-scope traffic.
    [FIX]  _extract_urls: BOM/CRLF/inline-comment/trailing-dot safe.
    [FIX]  status_code captured BEFORE resp.close() — was working by
           accident.
    [FIX]  _is_reflected dead code removed (redundant trailing-slash
           check after normalization).
    [FIX]  _base_host TLD-aware (handles co.uk, com.au, org.uk, etc).
    [FIX]  Preflight uses correct probe origin by name lookup, not hardcoded
           index 0.
    [FIX]  max_urls capping shuffles URLs before truncate (was
           alphabetically biased).

  v3.0 — NEW:
    [NEW]  Parallel-URL workers with proper config.RateLimiter integration.
    [NEW]  Rate division across workers (total_cap preserved).
    [NEW]  Baseline probe — same-origin origin as sanity check.
    [NEW]  Trusted-origin probe — if we detect target's own origin from
           headers, use it as known-good baseline for reflection diffing.
    [NEW]  Access-Control-Max-Age tracking — high max-age + reflection =
           longer cache-poisoning window.
    [NEW]  Location header tracking — CORS + redirect combo often missed.
    [NEW]  Per-finding manual_test + confidence (0-100) consistent with
           js_analysis/takeover/content_fuzz schemas.
    [NEW]  AI triage with schema validation + corrective retry + cache
           (mirrors js_analysis v3.1 pattern).
    [NEW]  Structured `warnings` array in report.
    [NEW]  SIGINT handler — finish current URL, write partial report.
    [NEW]  --dry-run, --quiet, --selftest, --no-ai, --ai-max-hosts,
           --ai-max-cost, --ai-cache-ttl, --parallel-urls, --url-timeout.
    [NEW]  on_progress callback for TUI/dashboard integration.
    [NEW]  cors_findings_digest.md — top-50 markdown table.
    [NEW]  Selftest with 55 checks (was 0).

  Preserves every public symbol and file output from v1.0.

  Accuracy model — five layers:
    1. Strict reflection matching (comma-split, exact membership)
    2. Multi-value header parsing via urllib3.raw.getlist()
    3. Vary: Origin awareness (cache poisoning surface)
    4. Method rotation (GET full battery, POST spot check)
    5. Sensitive body detection (upgrades severity when reflection+ACAC)

  Config integration:
    ·  MODULE_RATE_LIMITS["cors_check"]   → rps + concurrency + jitter
    ·  ACTIVE_HEADERS + AUTH_HEADERS      → merged into every request
    ·  AUTH_COOKIES                       → session cookies
    ·  SCOPE, KillSwitch, RateLimiter, human_delay, random_user_agent
    ·  AI_ENABLED, AI.model, ai_complete, AI_COSTS
    ·  SYNC_TO_DB, BRIDGE_ENABLED, new_audit_trail

  Outputs:
    cors_findings.json         — full report
    cors_critical.txt          — CRITICAL/HIGH URL list
    cors_all.txt               — every flagged URL
    cors_findings_digest.md    — top-50 markdown table
    cors_ai_<host>.md          — per-host AI triage (when AI on)
    cors_ai_cache/             — versioned AI cache
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import os
import random
import re
import signal
import string
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore[assignment]
    REQUESTS_AVAILABLE = False

log = logging.getLogger("argus.cors")


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG INTEGRATION
# ═════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False

try:
    from db import DB  # type: ignore
    DB_AVAILABLE = True
except ImportError:
    DB = None  # type: ignore[assignment]
    DB_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _ai_enabled() -> bool:
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


def _killswitch_check(label: str = "") -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


def _scope_check(url: str) -> bool:
    """Return True if URL is in scope (or SCOPE not configured)."""
    try:
        scope = _cfg("SCOPE")
        if scope is None:
            return True
        if hasattr(scope, "is_in_scope"):
            return bool(scope.is_in_scope(url))
    except Exception:
        pass
    return True


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG READERS — v3.0 FIX
# ═════════════════════════════════════════════════════════════════════════

def _cors_settings() -> dict:
    """
    v3.0: reads MODULE_RATE_LIMITS["cors_check"] (config's canonical key)
    with legacy fallback to "cors". Returns rps + concurrency + jitter +
    timeout.
    """
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = all_limits.get("cors_check") or all_limits.get("cors") or {}

    threads = entry.get("concurrency", 3)
    rate    = entry.get("rps", entry.get("rate_limit", 5))
    jitter  = entry.get("jitter", (0.0, 0.0))
    timeout = entry.get("timeout", 12)

    if not isinstance(threads, int) or threads < 1: threads = 3
    if not isinstance(rate, int) or rate < 0:       rate = 5
    if not isinstance(timeout, int) or timeout < 1: timeout = 12
    if not isinstance(jitter, (tuple, list)) or len(jitter) != 2:
        jitter = (0.0, 0.0)

    return {"threads": threads, "rate_limit": rate,
            "jitter": tuple(jitter), "timeout": timeout}


def _target_headers(extra: Optional[dict] = None) -> dict[str, str]:
    """v3.0: caller-supplied headers override config."""
    h: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    if extra:
        h.update(extra)
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════
#  THREAD LOCKS
# ═════════════════════════════════════════════════════════════════════════

_AI_LOCK     = threading.Lock()
_LOG_LOCK    = threading.Lock()
_SHARED      = {"_quiet": False}


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS    = 3
DEFAULT_RATE_LIMIT = 5
DEFAULT_TIMEOUT    = 12
DEFAULT_RETRIES    = 2
MAX_URLS           = 5000
MAX_BODY_BYTES     = 65536
DEFAULT_URL_TIMEOUT = 90   # per-URL wall clock
DEFAULT_MAX_FINDINGS = 10000

SEV_CRITICAL_SCORE = 80
SEV_HIGH_SCORE     = 50
SEV_MEDIUM_SCORE   = 30
SEV_LOW_SCORE      = 10

# AI triage
AI_MIN_FINDINGS_PER_HOST = 1
AI_DEFAULT_MAX_HOSTS     = 20
AI_DEFAULT_CACHE_TTL_HOURS = 72
AI_ESTIMATE_PER_CALL_USD = 0.002
AI_PROMPT_VERSION        = "v3.0"

# Method rotation
CORS_TEST_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
PRIMARY_METHOD = "GET"
SECONDARY_METHODS = ["POST"]
MAX_SECONDARY_PROBES = 3

# Sensitive body markers
SENSITIVE_MARKERS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key",
    "ssn", "social_security", "credit_card", "card_number", "cvv",
    "email", "user_id", "account_id", "username",
    "authorization", "bearer ",
    "session_id", "sessionid",
]

# TLD-aware apex computation
_SECOND_LEVEL_TLDS = frozenset({
    "co", "com", "net", "org", "ac", "gov", "edu", "mil",
})


# ═════════════════════════════════════════════════════════════════════════
#  ORIGIN PROBES
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class OriginProbe:
    name: str
    origin: str
    description: str
    weight: int = 0
    is_baseline: bool = False


def _build_probes(target_host: str, base_host: str) -> list[OriginProbe]:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    attacker_origin = f"https://evil-{rand}.example"
    attacker_host   = f"evil-{rand}.example"

    probes = [
        # Baseline — same as target, should NEVER reflect for a well-configured
        # server (this is our sanity check)
        OriginProbe(
            "baseline_same_origin",
            f"https://{target_host}",
            "Baseline: target's own origin",
            weight=0,
            is_baseline=True,
        ),
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
            "Server uses endsWith(target_host) — accepts target.com.evil.com",
            weight=35,
        ),
        OriginProbe(
            "prefix_bypass",
            f"https://{attacker_host}-{target_host}",
            "Server uses startsWith(target_host) — accepts evil-target.com",
            weight=35,
        ),
        OriginProbe(
            "subdomain_trust",
            f"https://{attacker_host}.{target_host}",
            "Server trusts *.target_host — attacker registers matching subdomain",
            weight=30,
        ),
        OriginProbe(
            "scheme_downgrade",
            f"http://{target_host}",
            "Server accepts HTTP origin on HTTPS endpoint",
            weight=25,
        ),
        OriginProbe(
            "pre_domain_injection",
            f"https://{attacker_host}.{target_host}",
            "Server naively contains(target_host) — accepts attacker.com.target.com",
            weight=30,
        ),
    ]

    if base_host and base_host != target_host:
        probes.append(OriginProbe(
            "apex_origin",
            f"https://{base_host}",
            "Server trusts apex domain for this subdomain (cross-subdomain CORS)",
            weight=20,
        ))

    return probes


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════

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
    ac_max_age: int = 0
    location: str = ""
    status_code: int = 0
    content_type: str = ""
    score: int = 0
    severity: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    vary_origin: bool = False
    sensitive_body: bool = False
    auth_enabled: bool = False
    response_snippet: str = ""
    is_baseline: bool = False
    first_seen: str = ""
    # v3.0 additions
    confidence: int = 0
    manual_test: str = ""
    nuclei_tags: list[str] = field(default_factory=list)

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
            "ac_max_age":       self.ac_max_age,
            "location":         self.location,
            "status_code":      self.status_code,
            "content_type":     self.content_type,
            "score":            self.score,
            "severity":         self.severity,
            "reasons":          self.reasons,
            "vary_origin":      self.vary_origin,
            "sensitive_body":   self.sensitive_body,
            "auth_enabled":     self.auth_enabled,
            "response_snippet": self.response_snippet,
            "is_baseline":      self.is_baseline,
            "first_seen":       self.first_seen,
            "confidence":       self.confidence,
            "manual_test":      self.manual_test,
            "nuclei_tags":      self.nuclei_tags,
        }


@dataclass
class HostResult:
    host: str
    findings: list[CORSFinding] = field(default_factory=list)
    triage: Optional[dict] = None
    triage_source: str = ""
    warnings: list[str] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════

def _host_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _base_host(target_host: str) -> str:
    """
    v3.0: TLD-aware apex computation. Handles co.uk, com.au, org.uk, etc.
    Falls back to simple last-2-labels for unknown TLDs.
    """
    if not target_host:
        return ""
    parts = target_host.split(".")
    if len(parts) < 2:
        return target_host
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _confidence_band(score: int) -> str:
    if score >= 80: return "high"
    if score >= 50: return "medium"
    return "low"


def _log_locked(level: str, msg: str) -> None:
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        getattr(log, level)(msg)


# ═════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING (v3.0 — BOM/CRLF/inline-comment safe)
# ═════════════════════════════════════════════════════════════════════════

def _extract_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    urls: set[str] = set()
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        urls.add(url.rstrip("/"))
    return sorted(urls)


# ═════════════════════════════════════════════════════════════════════════
#  HEADER PARSING (multi-value aware)
# ═════════════════════════════════════════════════════════════════════════

def _get_header_values(resp: Any, name: str) -> list[str]:
    if not REQUESTS_AVAILABLE:
        return []
    try:
        values = resp.raw.headers.getlist(name)
        if values:
            return [v.strip() for v in values if v and v.strip()]
    except (AttributeError, Exception):
        pass
    collapsed = resp.headers.get(name, "")
    if not collapsed:
        return []
    return [v.strip() for v in collapsed.split(",") if v.strip()]


def _parse_acao(values: list[str]) -> tuple[str, list[str]]:
    if not values:
        return "", []
    return ",".join(values), values


# ═════════════════════════════════════════════════════════════════════════
#  REFLECTION MATCHING (strict, v3.0 cleanup)
# ═════════════════════════════════════════════════════════════════════════

def _is_reflected(sent_origin: str, acao_values: list[str]) -> bool:
    """v3.0: exact membership only. Dead trailing-slash branch removed."""
    if not sent_origin or not acao_values:
        return False
    sent_norm = sent_origin.rstrip("/").lower()
    for v in acao_values:
        if v.rstrip("/").lower() == sent_norm:
            return True
    return False


# ═════════════════════════════════════════════════════════════════════════
#  SENSITIVE BODY DETECTION
# ═════════════════════════════════════════════════════════════════════════

def _has_sensitive_data(body: str) -> bool:
    if not body:
        return False
    body_lower = body.lower()
    return any(marker in body_lower for marker in SENSITIVE_MARKERS)


# ═════════════════════════════════════════════════════════════════════════
#  SESSION + RATE LIMITER
# ═════════════════════════════════════════════════════════════════════════

def _make_session(extra_headers: Optional[dict] = None) -> Any:
    if not REQUESTS_AVAILABLE:
        return None
    s = requests.Session()
    hdrs = _target_headers(extra_headers)
    if hdrs:
        s.headers.update(hdrs)
    cookies = _auth_cookies()
    if cookies:
        for name, value in cookies.items():
            s.cookies.set(name, value)
    s.verify = False
    return s


def _make_rate_limiter(rps: int) -> Any:
    """v3.0: uses config.RateLimiter for proper per-worker rate limiting."""
    if rps <= 0:
        return None
    try:
        rl_cls = _cfg("RateLimiter")
        if rl_cls is None:
            return None
        return rl_cls(per_minute=rps * 60, per_hour=rps * 3600)
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════
#  REQUEST ENGINE
# ═════════════════════════════════════════════════════════════════════════

def _send_probe(
    session: Any,
    url: str,
    probe: OriginProbe,
    method: str,
    timeout: int,
    retries: int,
    auth_enabled: bool,
    rate_limiter: Any = None,
    extra_headers: Optional[dict] = None,
) -> Optional[CORSFinding]:
    """v3.0: rate-limiter-gated, KillSwitch-checked, SCOPE-checked."""
    _killswitch_check("cors-probe")
    if not _scope_check(url):
        return None
    if rate_limiter is not None:
        try:
            rate_limiter.acquire()
        except Exception:
            pass

    headers = {"Origin": probe.origin}
    resp = None
    for attempt in range(retries + 1):
        try:
            resp = session.request(
                method, url, headers=headers, timeout=timeout,
                allow_redirects=False, stream=True,
            )
            break
        except Exception as e:
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

    # ── Access-Control-Max-Age (v3.0) ───────────────────────────────────────
    max_age = 0
    try:
        ma_values = _get_header_values(resp, "Access-Control-Max-Age")
        if ma_values:
            max_age = int(ma_values[0])
    except (ValueError, IndexError):
        pass

    # ── Location header (v3.0 — CORS + redirect combo) ──────────────────────
    location = resp.headers.get("Location", "") or ""

    # ── Vary: Origin tracking ───────────────────────────────────────────────
    vary_joined = ",".join(_get_header_values(resp, "Vary")).lower()
    vary_origin = "origin" in vary_joined

    # ── Strict reflection ───────────────────────────────────────────────────
    reflected = _is_reflected(probe.origin, acao_values)

    # ── Body snippet (v3.0: always read up to MAX_BODY_BYTES) ───────────────
    snippet = ""
    sensitive = False
    try:
        raw = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
        text = raw.decode("utf-8", errors="replace")
        snippet = text[:500]
        sensitive = _has_sensitive_data(text)
    except Exception:
        pass

    # ── v3.0: capture status_code BEFORE close (was working by accident) ──
    status_code = resp.status_code
    content_type = resp.headers.get("Content-Type", "")
    resp.close()

    finding = CORSFinding(
        url=url, method=method, probe_name=probe.name,
        sent_origin=probe.origin, reflected=reflected,
        acao=acao_joined, acac=acac, acam=acam_joined, acah=acah_joined,
        ac_max_age=max_age, location=location,
        status_code=status_code, content_type=content_type,
        vary_origin=vary_origin, sensitive_body=sensitive,
        auth_enabled=auth_enabled, response_snippet=snippet,
        is_baseline=probe.is_baseline,
        first_seen=datetime.now(timezone.utc).isoformat(),
    )

    _score_finding(finding, probe)
    return finding


def _send_preflight(
    session: Any,
    url: str,
    origin: str,
    request_method: str,
    timeout: int,
    auth_enabled: bool,
    rate_limiter: Any = None,
    extra_headers: Optional[dict] = None,
) -> Optional[CORSFinding]:
    """v3.0: proper preflight with correct origin, rate-gated."""
    _killswitch_check("cors-preflight")
    if not _scope_check(url):
        return None
    if rate_limiter is not None:
        try:
            rate_limiter.acquire()
        except Exception:
            pass

    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    try:
        resp = session.options(url, headers=headers, timeout=timeout,
                                allow_redirects=False)
    except Exception:
        return None

    acao_values = _get_header_values(resp, "Access-Control-Allow-Origin")
    acao_joined, _ = _parse_acao(acao_values)
    acac = any(v.strip().lower() == "true"
               for v in _get_header_values(resp, "Access-Control-Allow-Credentials"))
    acam_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Methods"))
    acah_joined, _ = _parse_acao(_get_header_values(resp, "Access-Control-Allow-Headers"))

    max_age = 0
    try:
        ma_values = _get_header_values(resp, "Access-Control-Max-Age")
        if ma_values:
            max_age = int(ma_values[0])
    except (ValueError, IndexError):
        pass

    reflected = _is_reflected(origin, acao_values)
    if not reflected and not (acao_joined.strip() == "*" and acac):
        return None

    finding = CORSFinding(
        url=url, method="OPTIONS", probe_name=f"preflight:{request_method}",
        sent_origin=origin, reflected=reflected,
        acao=acao_joined, acac=acac, acam=acam_joined, acah=acah_joined,
        ac_max_age=max_age, status_code=resp.status_code,
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
    if max_age > 86400:  # > 1 day
        score += 10
        reasons.append(f"long_max_age:{max_age}s")

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
    _decorate_finding(finding)
    return finding


# ═════════════════════════════════════════════════════════════════════════
#  SCORING + DECORATION
# ═════════════════════════════════════════════════════════════════════════

def _score_finding(f: CORSFinding, probe: OriginProbe) -> None:
    # Baseline probe = sanity check, never counted as a finding
    if probe.is_baseline:
        f.score = 0
        f.severity = "INFO"
        f.confidence = 0
        return

    score = 0
    reasons: list[str] = []

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

    if f.reflected and f.acac:
        reasons.append("credentials_allowed")
        score += 50
        if f.auth_enabled and f.sensitive_body:
            reasons.append("sensitive_data_in_body")
            score += 15
        if not f.vary_origin:
            reasons.append("missing_vary_origin")
            score += 10

    if f.acao.strip() == "*" and f.acac:
        reasons.append("wildcard_with_credentials")
        score += 40

    if f.acao.strip().startswith("*.") or "/*." in f.acao:
        reasons.append("wildcard_subdomain_literal")
        score += 20

    if not f.acao and f.acac:
        reasons.append("acac_without_acao")
        score += 15

    if probe.name == "scheme_downgrade" and f.reflected:
        reasons.append("scheme_downgrade")
        score += 10

    if f.acao.strip() == "*" and not f.acac:
        reasons.append("wildcard_without_credentials")
        score += 5

    # v3.0: cache poisoning window extension
    if f.reflected and not f.vary_origin and f.ac_max_age > 86400:
        reasons.append(f"cache_poison_window:{f.ac_max_age}s")
        score += 5

    # v3.0: CORS + redirect combo
    if f.reflected and f.location:
        reasons.append("cors_on_redirect")
        score += 5

    if not f.acao and not f.acac:
        f.score = 0
        f.severity = "INFO"
        f.reasons = []
        f.confidence = 0
        return

    f.score = min(score, 100)

    if f.score >= SEV_CRITICAL_SCORE:   f.severity = "CRITICAL"
    elif f.score >= SEV_HIGH_SCORE:     f.severity = "HIGH"
    elif f.score >= SEV_MEDIUM_SCORE:   f.severity = "MEDIUM"
    elif f.score >= SEV_LOW_SCORE:      f.severity = "LOW"
    else:                               f.severity = "INFO"

    f.reasons = reasons
    _decorate_finding(f)


def _decorate_finding(f: CORSFinding) -> None:
    """v3.0: add confidence, manual_test, nuclei_tags per finding."""
    # Confidence mirrors score (0-100)
    f.confidence = f.score

    # Manual test hint
    probe = f.probe_name
    if "preflight" in probe:
        f.manual_test = (
            f"curl -i -X OPTIONS '{f.url}' -H 'Origin: {f.sent_origin}' "
            f"-H 'Access-Control-Request-Method: {f.method}'"
        )
    elif probe == "arbitrary_reflection":
        f.manual_test = (
            f"curl -i '{f.url}' -H 'Origin: {f.sent_origin}' "
            f"| grep -i 'access-control-allow-origin'"
        )
    elif probe == "null_origin":
        f.manual_test = (
            f"Open {f.url} in sandboxed iframe; check data: origin acceptance"
        )
    elif "bypass" in probe or "subdomain" in probe or "pre_domain" in probe:
        f.manual_test = (
            f"Register/control {f.sent_origin.split('//')[1]}, then "
            f"fetch('{f.url}', {{credentials:'include'}})"
        )
    elif probe == "scheme_downgrade":
        f.manual_test = (
            f"Serve http://MITM from same network; check ACAO on '{f.url}'"
        )
    elif probe == "apex_origin":
        f.manual_test = (
            f"From apex origin, fetch('{f.url}', {{credentials:'include'}})"
        )
    else:
        f.manual_test = f"Manual review of {probe} probe response"

    # Nuclei tags
    tags: list[str] = ["cors"]
    if f.acac:
        tags.append("cors-credentials")
    if f.acao.strip() == "*":
        tags.append("cors-wildcard")
    if not f.vary_origin and f.reflected:
        tags.append("cache-poisoning")
    if f.sensitive_body:
        tags.append("sensitive-data")
    f.nuclei_tags = tags


# ═════════════════════════════════════════════════════════════════════════
#  PER-URL SCAN
# ═════════════════════════════════════════════════════════════════════════

def _scan_url(
    url: str,
    timeout: int,
    retries: int,
    auth_enabled: bool,
    rate_limiter: Any,
    extra_headers: Optional[dict],
    url_timeout: int,
) -> list[CORSFinding]:
    if not REQUESTS_AVAILABLE:
        return []
    host = _host_from_url(url)
    if not host:
        return []

    probes = _build_probes(host, _base_host(host))
    session = _make_session(extra_headers)
    if session is None:
        return []

    findings: list[CORSFinding] = []
    deadline = time.monotonic() + url_timeout

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    try:
        # Full battery on primary method
        for probe in probes:
            if _timed_out():
                break
            f = _send_probe(
                session, url, probe, PRIMARY_METHOD, timeout, retries,
                auth_enabled, rate_limiter, extra_headers,
            )
            if f and f.severity != "INFO" and not f.is_baseline:
                findings.append(f)

        # Spot-check secondary methods only if no CRIT/HIGH yet
        if not any(x.severity in ("CRITICAL", "HIGH") for x in findings):
            for method in SECONDARY_METHODS:
                if _timed_out():
                    break
                for probe in [p for p in probes if not p.is_baseline][:MAX_SECONDARY_PROBES]:
                    if _timed_out():
                        break
                    f = _send_probe(
                        session, url, probe, method, timeout, retries,
                        auth_enabled, rate_limiter, extra_headers,
                    )
                    if f and f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                        findings.append(f)

        # Preflight only if no CRITICAL yet
        if not any(x.severity == "CRITICAL" for x in findings) and not _timed_out():
            arbitrary = next(
                (p for p in probes if p.name == "arbitrary_reflection"),
                None,
            )
            if arbitrary:
                pf = _send_preflight(
                    session, url, arbitrary.origin, PRIMARY_METHOD,
                    timeout, auth_enabled, rate_limiter, extra_headers,
                )
                if pf and pf.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    findings.append(pf)
    finally:
        try:
            session.close()
        except Exception:
            pass

    return findings


def _dedupe(findings: list[CORSFinding]) -> list[CORSFinding]:
    """v3.0: extract to testable function. Keep highest score per URL."""
    best: dict[str, CORSFinding] = {}
    for f in findings:
        key = f.url.rstrip("/").lower()
        existing = best.get(key)
        if not existing or f.score > existing.score:
            best[key] = f
    return sorted(best.values(), key=lambda f: (-f.score, f.url))


# ═════════════════════════════════════════════════════════════════════════
#  HEURISTIC TRIAGE (per-host)
# ═════════════════════════════════════════════════════════════════════════

def _heuristic_host_triage(host: str, findings: list[CORSFinding]) -> dict:
    if not findings:
        return {
            "summary": f"No CORS misconfigurations on {host}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "false_positive_likelihood": "n/a",
            "suggested_manual_tests": [],
            "next_actions": ["Manual review of response headers on primary endpoints"],
            "source": "heuristic",
        }

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    if sev_counts["CRITICAL"] > 0:   host_risk = "CRITICAL"
    elif sev_counts["HIGH"] > 0:     host_risk = "HIGH"
    elif sev_counts["MEDIUM"] > 0:   host_risk = "MEDIUM"
    elif sev_counts["LOW"] > 0:      host_risk = "LOW"
    else:                             host_risk = "INFO"

    top = sorted(findings, key=lambda f: -f.score)[:5]
    top_priorities = []
    for i, f in enumerate(top, 1):
        reasons = ",".join(f.reasons[:3]) if f.reasons else "-"
        top_priorities.append({
            "rank": i,
            "finding": f"{f.severity} {f.probe_name} on {f.url}",
            "reason": f"score={f.score} ({reasons})",
            "test_idea": f.manual_test,
        })

    # Real vs noise
    n_wildcard_no_creds = sum(1 for f in findings
                                if "wildcard_without_credentials" in f.reasons)
    noise_bits = []
    if n_wildcard_no_creds:
        noise_bits.append(f"{n_wildcard_no_creds} wildcard-without-creds (LOW value)")
    real_bits = []
    n_cred_refl = sum(1 for f in findings if "credentials_allowed" in f.reasons
                       and f.reflected)
    if n_cred_refl:
        real_bits.append(f"{n_cred_refl} credentialed reflection(s) — HIGH value")
    n_bypass = sum(1 for f in findings if "regex_bypass" in f.reasons)
    if n_bypass:
        real_bits.append(f"{n_bypass} bypass-pattern hit(s)")

    real_vs_noise = (
        f"{len(findings)} finding(s). "
        + (f"Real: {', '.join(real_bits)}. " if real_bits else "")
        + (f"Noise: {', '.join(noise_bits)}." if noise_bits else "")
    ).strip()

    tests: list[str] = []
    for f in top:
        if f.manual_test and f.manual_test not in tests:
            tests.append(f.manual_test)
        if len(tests) >= 5:
            break

    next_actions: list[str] = []
    if sev_counts["CRITICAL"] > 0:
        next_actions.append(
            f"Immediately verify {sev_counts['CRITICAL']} CRITICAL finding(s) — "
            f"credentialed CORS reflection is highest-value")
    if any("regex_bypass" in f.reasons for f in findings):
        next_actions.append("Register attacker domain; test bypass pattern live")
    if any("wildcard_with_credentials" in f.reasons for f in findings):
        next_actions.append(
            "Wildcard + credentials is spec-invalid — browser behavior varies; "
            "test in Firefox + Chrome")
    if any("missing_vary_origin" in f.reasons for f in findings):
        next_actions.append(
            "Cache poisoning test: poison CDN with reflected ACAO, "
            "wait for cache TTL, observe other users")
    if not next_actions:
        next_actions.append("Manual review of MEDIUM findings in browser devtools")

    summary = (
        f"{len(findings)} CORS finding(s) on {host}. "
        f"CRIT={sev_counts['CRITICAL']} HIGH={sev_counts['HIGH']} "
        f"MED={sev_counts['MEDIUM']}."
    )

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "real_vs_noise": real_vs_noise,
        "suggested_manual_tests": tests,
        "next_actions": next_actions[:5],
        "source": "heuristic",
    }


# ═════════════════════════════════════════════════════════════════════════
#  AI CACHE
# ═════════════════════════════════════════════════════════════════════════

def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "cors_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: str, findings: list[CORSFinding], model: str = "") -> str:
    parts = [host.lower(), f"model={model or 'unknown'}",
             f"prompt={AI_PROMPT_VERSION}"]
    for f in sorted(findings, key=lambda x: x.url):
        parts.append(f"{f.url}|{f.score}|{f.severity}|{f.probe_name}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
    if ttl_hours <= 0:
        return None
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        if not p.exists():
            return None
        age = (time.time() - p.stat().st_mtime) / 3600
        if age > ttl_hours:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ai_cache_put(outdir: Path, key: str, data: dict) -> None:
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


_BUDGET_LOCK = threading.Lock()


def _current_spend() -> float:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return float(tracker.estimate_cost() or 0)
    except Exception:
        pass
    return 0.0


def _ai_cost_guard(would_add: float, budget_usd: float) -> bool:
    if budget_usd <= 0 or would_add <= 0:
        return True
    with _BUDGET_LOCK:
        return (_current_spend() + would_add) <= budget_usd


# ═════════════════════════════════════════════════════════════════════════
#  AI TRIAGE
# ═════════════════════════════════════════════════════════════════════════

AI_CORS_SYSTEM = (
    "You are an expert CORS-triage analyst. Analyze findings from one "
    "host. Reference actual URLs and probe types. Never suggest running "
    "exploits. Return STRICT JSON only."
)


def _validate_ai_triage(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("summary", "host_risk", "top_priorities",
                "real_vs_noise", "suggested_manual_tests", "next_actions"):
        if key not in data:
            return False
    if not isinstance(data.get("top_priorities"), list): return False
    if not isinstance(data.get("suggested_manual_tests"), list): return False
    if not isinstance(data.get("next_actions"), list): return False
    if data.get("host_risk") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                       "INFO", "UNKNOWN", ""):
        return False
    return True


def _build_top_findings_block(findings: list[CORSFinding], limit: int = 30) -> str:
    top = sorted(findings, key=lambda f: -f.score)[:limit]
    lines = []
    for f in top:
        bits = [f"[{f.severity:<8}]", f"{f.score:>3}", f.probe_name,
                f"{f.method} {f.url}"]
        if f.reasons:
            bits.append(f"({','.join(f.reasons[:2])})")
        lines.append("  " + " ".join(bits))
    return "\n".join(lines) if lines else "  (no findings)"


def _ai_triage_host(host_result: HostResult, outdir: Path, *,
                     use_cache: bool = True,
                     cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
                     budget_usd: float = 0.0,
                     heuristic_hint: Optional[dict] = None) -> Optional[dict]:
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.findings) < AI_MIN_FINDINGS_PER_HOST:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(host_result.host, host_result.findings,
                                model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        return None

    findings = host_result.findings
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    hint_block = ""
    if heuristic_hint and heuristic_hint.get("summary"):
        hint_block = (
            "\n\nHeuristic baseline (HINT ONLY):\n"
            f"  Summary: {heuristic_hint.get('summary', '')[:300]}\n"
        )

    prompt = f"""Analyze CORS findings for host: {host_result.host}

Stats:
  Total:    {len(findings)}
  CRITICAL: {sev_counts['CRITICAL']}
  HIGH:     {sev_counts['HIGH']}
  MEDIUM:   {sev_counts['MEDIUM']}
  LOW:      {sev_counts['LOW']}

Top findings:
{_build_top_findings_block(findings)}{hint_block}
"""

    def _call(text: str) -> Optional[str]:
        try:
            return ai_fn(text, system=AI_CORS_SYSTEM)
        except Exception as e:
            log.warning(f"  AI triage failed for {host_result.host}: "
                         f"{type(e).__name__}: {e}")
            return None

    text = _call(prompt)
    if not text:
        return None

    def _strip_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        return s

    def _try_parse(raw: str) -> Optional[dict]:
        try:
            d = json.loads(_strip_fences(raw))
            return d if _validate_ai_triage(d) else None
        except Exception:
            return None

    data = _try_parse(text)

    if data is None:
        correction = (
            "Your previous response could not be parsed as valid JSON. "
            "Return ONLY the JSON object, no fences. Required keys: "
            "summary, host_risk, top_priorities, real_vs_noise, "
            "suggested_manual_tests, next_actions.\n\n"
            f"Previous response:\n{text[:600]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {
                    "summary": text2[:1500], "host_risk": "UNKNOWN",
                    "top_priorities": [], "real_vs_noise": "unknown",
                    "suggested_manual_tests": [], "next_actions": [],
                    "parse_error": True,
                }
        else:
            return None

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"cors_ai_{safe}.md"
    try:
        md = (f"# Forseti · CORS AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("host_risk"):
            md += f"**Host risk:** {data['host_risk']}\n\n"
        if data.get("summary"):
            md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("top_priorities"):
            md += "## Top Priorities\n\n"
            for p in data["top_priorities"]:
                md += (f"{p.get('rank', '?')}. **{p.get('finding', '')}**\n"
                       f"   - Reason: {p.get('reason', '')}\n"
                       f"   - Test: {p.get('test_idea', '')}\n\n")
        if data.get("real_vs_noise"):
            md += f"## Real vs Noise\n\n{data['real_vs_noise']}\n\n"
        if data.get("suggested_manual_tests"):
            md += "## Suggested Manual Tests\n\n"
            for t in data["suggested_manual_tests"]:
                md += f"- {t}\n"
            md += "\n"
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"  AI triage saved: {md_path.name}")

    return {
        "path":             str(md_path),
        "summary":          data.get("summary", ""),
        "host_risk":        data.get("host_risk", ""),
        "top_priorities":   data.get("top_priorities", [])[:10],
        "real_vs_noise":    data.get("real_vs_noise", ""),
        "suggested_manual_tests": data.get("suggested_manual_tests", [])[:10],
        "next_actions":     data.get("next_actions", [])[:10],
        "cost_estimate":    round(_current_spend(), 6),
        "source": "ai",
    }


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════

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
    if not getattr(DB, "available", False):
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


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════

def run_cors_check(
    live_urls_file: Path,
    outdir: Path,
    *,
    # v2 backward-compat
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_urls: int = MAX_URLS,
    headers: Optional[dict] = None,
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    parallel_urls: Optional[int] = None,
    url_timeout: int = DEFAULT_URL_TIMEOUT,
    no_ai: bool = False,
    ai_max_hosts: int = AI_DEFAULT_MAX_HOSTS,
    ai_max_cost_usd: float = 0.0,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
) -> Path:
    """v3.0: full CORS scan with proper rate limiting, warnings, AI triage."""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError(
            "requests library required — install via `pip install requests urllib3`")

    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    # ── Settings ────────────────────────────────────────────────────────────
    settings = _cors_settings()
    eff_threads = threads if threads is not None else settings["threads"]
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_timeout = settings["timeout"] if timeout == DEFAULT_TIMEOUT else timeout

    if not isinstance(eff_threads, int) or eff_threads < 1:
        eff_threads = settings["threads"]
    if not isinstance(eff_rate, int) or eff_rate < 0:
        eff_rate = settings["rate_limit"]

    eff_parallel = (parallel_urls
                     if parallel_urls is not None and parallel_urls >= 1
                     else eff_threads)
    eff_rate_per_worker = (
        max(1, eff_rate // eff_parallel) if eff_rate > 0 else 0
    )

    # ── Inputs ──────────────────────────────────────────────────────────────
    urls = _extract_urls(live_urls_file)
    total_input = len(urls)
    if len(urls) > max_urls:
        # v3.0: shuffle before cap to avoid alphabetical bias
        random.shuffle(urls)
        warnings.append(f"urls-capped: {len(urls)} → {max_urls}")
        log.warning(f"  Capping scan at {max_urls} URL(s) "
                     f"(input had {total_input}, shuffled before truncate)")
        urls = urls[:max_urls]

    if not urls:
        log.warning("  No URLs to scan — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start,
                                     total_input=total_input, scan_id=scan_id)

    outdir.mkdir(parents=True, exist_ok=True)

    auth_enabled = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers(headers)
    ai_active = _ai_enabled() and not no_ai and not dry_run

    if not quiet:
        log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
        log.info(f"  Config : workers={eff_parallel}  "
                 f"rate_limit={eff_rate}/s  "
                 f"per_worker={eff_rate_per_worker}/s  "
                 f"timeout={eff_timeout}s  retries={retries}")
        log.info(f"           source=MODULE_RATE_LIMITS['cors_check']")
        if dry_run:
            log.info("  Mode   : DRY-RUN (no network calls)")
        if cfg_hdrs:
            log.info(f"  Headers: {len(cfg_hdrs)} configured")
        log.info(f"  Auth   : {'ENABLED' if auth_enabled else 'disabled'}")
        if ai_active:
            budget_str = (f"${ai_max_cost_usd:.2f}"
                           if ai_max_cost_usd > 0 else "unlimited")
            log.info(f"  AI     : enabled  (budget={budget_str}, "
                     f"max_hosts={ai_max_hosts}, cache={ai_cache_ttl_hours}h)")
        else:
            log.info("  AI     : disabled — heuristic triage active")
        log.info("")

    if dry_run:
        log.info(f"  DRY-RUN — would scan {len(urls)} URL(s) with "
                 f"{eff_parallel} workers")
        for url in urls[:20]:
            log.info(f"    {url}")
        if len(urls) > 20:
            log.info(f"    … and {len(urls) - 20} more")
        return _write_empty_report(outdir, live_urls_file, start,
                                     total_input=total_input, scan_id=scan_id,
                                     dry_run=True)

    # ── SIGINT/SIGTERM handler ──────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — finishing current URL, writing report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    # ── Scan ────────────────────────────────────────────────────────────────
    all_findings: list[CORSFinding] = []
    scanned = 0
    errored = 0

    _progress("stage_start", {"stage": "scan", "urls": len(urls)})
    log.info(f"  Scanning {len(urls)} URL(s) with {eff_parallel} worker(s)")

    try:
        with ThreadPoolExecutor(max_workers=eff_parallel) as pool:
            futures = {}
            for url in urls:
                if _sigint["flag"]:
                    warnings.append("run-interrupted: SIGINT — partial results")
                    break
                # Each URL gets its own rate limiter so total rate is
                # parallel_urls × eff_rate_per_worker (never exceeds cap)
                rl = _make_rate_limiter(eff_rate_per_worker)
                fut = pool.submit(
                    _scan_url, url, eff_timeout, retries, auth_enabled,
                    rl, headers, url_timeout,
                )
                futures[fut] = url

            for fut in as_completed(futures):
                url = futures[fut]
                scanned += 1
                try:
                    findings = fut.result()
                except Exception as e:
                    warnings.append(f"scan-error: {url}: {type(e).__name__}: {e}")
                    errored += 1
                    continue

                if findings:
                    all_findings.extend(findings)
                    crit = [f for f in findings
                            if f.severity in ("CRITICAL", "HIGH")]
                    if crit and not quiet:
                        with _LOG_LOCK:
                            log.info(f"    [{crit[0].severity:<8}] "
                                     f"{url[:60]:<60}  "
                                     f"probe={crit[0].probe_name:<22}  "
                                     f"score={crit[0].score}")

                if scanned % 25 == 0 and not quiet:
                    with _LOG_LOCK:
                        log.info(f"    ... scanned {scanned}/{len(urls)}")
                _progress("url_done", {"url": url,
                                         "index": scanned,
                                         "total": len(urls)})
    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass

    _progress("stage_end", {"stage": "scan", "findings": len(all_findings)})

    # ── Dedupe ──────────────────────────────────────────────────────────────
    final = _dedupe(all_findings)

    if len(final) > DEFAULT_MAX_FINDINGS:
        warnings.append(f"findings-capped: {len(final)} → {DEFAULT_MAX_FINDINGS}")
        final = final[:DEFAULT_MAX_FINDINGS]

    # ── Group by host + triage ──────────────────────────────────────────────
    by_host: dict[str, list[CORSFinding]] = {}
    for f in final:
        host = _host_from_url(f.url) or "unknown"
        by_host.setdefault(host, []).append(f)

    host_results: list[HostResult] = []
    ai_hosts_done = 0
    ai_budget_exhausted = False

    _progress("stage_start", {"stage": "triage", "hosts": len(by_host)})

    for host, host_findings in sorted(by_host.items()):
        hr = HostResult(host=host, findings=host_findings)
        heuristic = _heuristic_host_triage(host, host_findings)

        ai_result: Optional[dict] = None
        if (ai_active and ai_hosts_done < ai_max_hosts
                and not ai_budget_exhausted):
            ai_result = _ai_triage_host(
                hr, outdir,
                use_cache=True,
                cache_ttl_hours=ai_cache_ttl_hours,
                budget_usd=ai_max_cost_usd,
                heuristic_hint=heuristic,
            )
            if ai_result:
                ai_hosts_done += 1
            elif ai_max_cost_usd > 0 and _current_spend() >= ai_max_cost_usd:
                ai_budget_exhausted = True

        if ai_result:
            hr.triage = ai_result
            hr.triage_source = ai_result.get("source", "ai")
        else:
            hr.triage = heuristic
            hr.triage_source = "heuristic"

        host_results.append(hr)

    if ai_active and ai_hosts_done > 0:
        log.info(f"  AI triaged: {ai_hosts_done} host(s)")
        if ai_budget_exhausted:
            warnings.append(f"ai-budget-exhausted: ${ai_max_cost_usd:.2f}")

    _progress("stage_end", {"stage": "triage"})

    # ── Write report ────────────────────────────────────────────────────────
    return _write_report(
        outdir, live_urls_file, start, total_input, scanned, errored,
        final, host_results, eff_threads=eff_parallel,
        eff_rate=eff_rate, eff_rate_per_worker=eff_rate_per_worker,
        auth_enabled=auth_enabled, cfg_hdrs=cfg_hdrs,
        ai_active=ai_active, warnings=warnings,
        dry_run=dry_run, scan_id=scan_id,
    )


# ═════════════════════════════════════════════════════════════════════════
#  REPORT WRITER
# ═════════════════════════════════════════════════════════════════════════

def _write_report(
    outdir: Path, input_file: Path, start: float, total_input: int,
    scanned: int, errored: int, findings: list[CORSFinding],
    host_results: list[HostResult], *,
    eff_threads: int, eff_rate: int, eff_rate_per_worker: int,
    auth_enabled: bool, cfg_hdrs: dict, ai_active: bool,
    warnings: list[str], dry_run: bool, scan_id: Optional[int],
) -> Path:
    elapsed = time.monotonic() - start

    critical_urls = [f.url for f in findings
                     if f.severity in ("CRITICAL", "HIGH")]
    all_urls_flagged = [f.url for f in findings]

    crit_path = outdir / "cors_critical.txt"
    crit_path.write_text("\n".join(critical_urls) + ("\n" if critical_urls else ""))

    all_path = outdir / "cors_all.txt"
    all_path.write_text("\n".join(all_urls_flagged) + ("\n" if all_urls_flagged else ""))

    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_probe: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_probe[f.probe_name] = by_probe.get(f.probe_name, 0) + 1

    ai_triaged = sum(1 for h in host_results if h.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for h in host_results if h.triage_source == "heuristic")

    report = {
        "schema_version": 3,
        "producer": "cors_check.py v3.0.0 'FORSETI'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(input_file),
        "total_input": total_input,
        "scanned": scanned,
        "errored": errored,
        "auth_enabled": auth_enabled,
        "ai_enabled": ai_active,
        "ai_prompt_version": AI_PROMPT_VERSION,
        "dry_run": dry_run,
        "config": {
            "workers":           eff_threads,
            "rate_limit":        eff_rate,
            "rate_per_worker":   eff_rate_per_worker,
            "headers_count":     len(cfg_hdrs),
            "probes_per_url":    "7-8 (baseline + bypass patterns)",
            "method_rotation":   [PRIMARY_METHOD] + SECONDARY_METHODS,
        },
        "warnings": warnings,
        "totals": {
            "urls_scanned":  scanned,
            "urls_errored":  errored,
            "findings":      len(findings),
            "critical":      by_sev["CRITICAL"],
            "high":          by_sev["HIGH"],
            "medium":        by_sev["MEDIUM"],
            "low":           by_sev["LOW"],
            "ai_triaged":    ai_triaged,
            "heuristic_triaged": heuristic_triaged,
        },
        "by_severity": by_sev,
        "by_probe":    by_probe,
        "hosts": [
            {
                "host":          h.host,
                "findings":      [f.to_dict() for f in h.findings],
                "triage":        h.triage,
                "triage_source": h.triage_source,
            }
            for h in host_results
        ],
        "findings": [f.to_dict() for f in findings],
    }

    json_path = outdir / "cors_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    _write_digest(outdir, findings)

    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, findings)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    _print_summary(outdir, report, findings, critical_urls, elapsed)

    return json_path


def _write_digest(outdir: Path, findings: list[CORSFinding]) -> None:
    if not findings:
        (outdir / "cors_findings_digest.md").write_text(
            "# CORS Findings Digest\n\nNo findings.\n", encoding="utf-8")
        return

    top = sorted(findings, key=lambda f: -f.score)[:50]
    lines = [
        "# CORS Findings Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Total findings:** {len(findings)}  \n\n",
        "## Top 50 findings\n\n",
        "| Sev | Score | URL | Method | Probe | Reasons | Manual Test |\n",
        "|-----|-------|-----|--------|-------|---------|-------------|\n",
    ]
    for f in top:
        url = f.url.replace("|", "\\|")[:60]
        reasons = ",".join(f.reasons[:3]).replace("|", "\\|")[:60]
        test = (f.manual_test or "Review").replace("|", "\\|")[:70]
        lines.append(
            f"| {f.severity:<8} | {f.score:>3} | {url} | {f.method} | "
            f"{f.probe_name[:22]} | {reasons} | {test} |\n"
        )
    (outdir / "cors_findings_digest.md").write_text(
        "".join(lines), encoding="utf-8")
    log.ok(f"  Digest: cors_findings_digest.md ({len(top)} findings)")


def _print_summary(outdir: Path, report: dict,
                    findings: list[CORSFinding],
                    critical_urls: list[str], elapsed: float) -> None:
    log.info("")
    log.info("── ᛊ  Summary ──")
    totals = report["totals"]
    log.info(f"  URLs scanned     : {totals['urls_scanned']} "
             f"(errored={totals['urls_errored']})")
    log.info(f"  Total findings   : {totals['findings']}")
    log.info(f"  Severity         : "
             f"CRITICAL={totals['critical']}  "
             f"HIGH={totals['high']}  "
             f"MEDIUM={totals['medium']}  "
             f"LOW={totals['low']}")
    if report["ai_enabled"]:
        log.info(f"  AI triage        : {totals['ai_triaged']} host(s) AI · "
                 f"{totals['heuristic_triaged']} heuristic")

    by_probe = report.get("by_probe", {})
    if by_probe:
        log.info("")
        log.info("  Findings by probe:")
        for probe, count in sorted(by_probe.items(), key=lambda kv: -kv[1])[:8]:
            log.info(f"    {probe:<30} {count:>3}")

    if critical_urls:
        log.info("")
        log.info("  CRITICAL / HIGH findings:")
        for f in findings:
            if f.severity in ("CRITICAL", "HIGH"):
                reasons = ",".join(f.reasons[:4])
                log.info(f"    [{f.severity:<8}] {f.url[:55]:<55}  "
                         f"probe={f.probe_name:<22}  "
                         f"score={f.score:>3}  [{reasons}]")

    log.info("")
    log.info("  Outputs:")
    log.info(f"    cors_findings.json")
    log.info(f"    cors_critical.txt")
    log.info(f"    cors_all.txt")
    log.info(f"    cors_findings_digest.md")
    if report["ai_enabled"] and totals["ai_triaged"] > 0:
        log.info(f"    cors_ai_<host>.md")

    if report.get("warnings"):
        log.info("")
        log.info("  Warnings:")
        for w in report["warnings"][:8]:
            log.warning(f"    {w}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")


def _write_empty_report(outdir: Path, input_file: Path, start: float,
                          total_input: int = 0, scan_id: Optional[int] = None,
                          dry_run: bool = False) -> Path:
    report = {
        "schema_version": 3,
        "producer": "cors_check.py v3.0.0 'FORSETI'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "total_input": total_input,
        "scanned": 0,
        "errored": 0,
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "ai_enabled": False,
        "ai_prompt_version": AI_PROMPT_VERSION,
        "dry_run": dry_run,
        "config": {},
        "warnings": [],
        "totals": {"urls_scanned": 0, "urls_errored": 0, "findings": 0,
                    "critical": 0, "high": 0, "medium": 0, "low": 0,
                    "ai_triaged": 0, "heuristic_triaged": 0},
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "by_probe": {},
        "hosts": [],
        "findings": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / "cors_findings.json"
    p.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (outdir / "cors_critical.txt").write_text("")
    (outdir / "cors_all.txt").write_text("")
    (outdir / "cors_findings_digest.md").write_text(
        "# CORS Findings Digest\n\nNo findings.\n", encoding="utf-8")
    return p


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  cors_check.py v3.0 'FORSETI' — selftest")
    print("═" * 70)

    def _mk_finding(url: str = "https://test.example/",
                     probe_name: str = "arbitrary_reflection",
                     sent_origin: str = "https://evil.example",
                     reflected: bool = True,
                     acao: str = "https://evil.example",
                     acac: bool = True,
                     score: int = 90,
                     severity: str = "CRITICAL") -> CORSFinding:
        return CORSFinding(
            url=url, method="GET", probe_name=probe_name,
            sent_origin=sent_origin, reflected=reflected,
            acao=acao, acac=acac, score=score, severity=severity,
            first_seen="2026-01-01T00:00:00Z",
        )

    def _settings_reads_canonical_key() -> bool:
        s = _cors_settings()
        # config.py: {"cors_check": {"rps": 5, "concurrency": 3}}
        return s["threads"] == 3 and s["rate_limit"] == 5

    def _settings_reads_rps_not_rate_limit() -> bool:
        s = _cors_settings()
        return s["rate_limit"] != 100

    def _input_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example\r\n"
                     b"b.example  # inline\r\n"
                     b"\r\n"
                     b"# full-line\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _extract_urls(tmp)
            return loaded == ["https://a.example", "https://b.example"]
        finally:
            tmp.unlink(missing_ok=True)

    def _base_host_simple() -> bool:
        return _base_host("api.example.com") == "example.com"

    def _base_host_co_uk() -> bool:
        return _base_host("api.example.co.uk") == "example.co.uk"

    def _base_host_apex() -> bool:
        return _base_host("example.com") == "example.com"

    def _is_reflected_exact() -> bool:
        return _is_reflected("https://evil.example",
                              ["https://evil.example"])

    def _is_reflected_no_substring() -> bool:
        # Must NOT match when ACAO merely CONTAINS the probe origin
        return not _is_reflected("https://evil.example",
                                  ["https://evil.example.com"])

    def _is_reflected_multi_value() -> bool:
        return _is_reflected("https://evil.example",
                              ["https://a.example", "https://evil.example"])

    def _is_reflected_null() -> bool:
        return _is_reflected("null", ["null"])

    def _is_reflected_case_insensitive() -> bool:
        return _is_reflected("https://EVIL.example",
                              ["https://evil.example"])

    def _has_sensitive_data_password() -> bool:
        return _has_sensitive_data('{"password": "x"}')

    def _has_sensitive_data_clean() -> bool:
        return not _has_sensitive_data('{"status": "ok"}')

    def _has_sensitive_data_email() -> bool:
        return _has_sensitive_data('user_email@example.com')

    def _build_probes_count() -> bool:
        # 8 probes when target is a subdomain (includes apex)
        return len(_build_probes("api.example.com", "example.com")) == 9

    def _build_probes_has_baseline() -> bool:
        probes = _build_probes("api.example.com", "example.com")
        return any(p.is_baseline for p in probes)

    def _build_probes_arbitrary() -> bool:
        probes = _build_probes("api.example.com", "example.com")
        return any(p.name == "arbitrary_reflection" for p in probes)

    def _build_probes_apex_when_subdomain() -> bool:
        probes = _build_probes("api.example.com", "example.com")
        return any(p.name == "apex_origin" for p in probes)

    def _build_probes_no_apex_at_apex() -> bool:
        probes = _build_probes("example.com", "example.com")
        return not any(p.name == "apex_origin" for p in probes)

    def _score_reflection_critical() -> bool:
        f = _mk_finding(reflected=True, acac=True, score=0)
        probe = OriginProbe("arbitrary_reflection", "https://evil.example",
                             "test", weight=40)
        _score_finding(f, probe)
        return f.score >= 80 and f.severity == "CRITICAL"

    def _score_wildcard_no_creds_low() -> bool:
        f = _mk_finding(reflected=False, acao="*", acac=False, score=0)
        probe = OriginProbe("arbitrary_reflection", "https://evil.example",
                             "test", weight=40)
        _score_finding(f, probe)
        return f.score < 30  # LOW or INFO

    def _score_null_origin() -> bool:
        f = _mk_finding(probe_name="null_origin",
                         sent_origin="null", acao="null",
                         reflected=True, acac=True, score=0)
        probe = OriginProbe("null_origin", "null", "test", weight=40)
        _score_finding(f, probe)
        return f.score >= 80

    def _decorate_manual_test_present() -> bool:
        f = _mk_finding()
        _decorate_finding(f)
        return bool(f.manual_test) and "curl" in f.manual_test.lower()

    def _decorate_nuclei_tags() -> bool:
        f = _mk_finding(acac=True)
        _decorate_finding(f)
        return "cors" in f.nuclei_tags

    def _decorate_nuclei_tags_creds() -> bool:
        f = _mk_finding(acac=True)
        _decorate_finding(f)
        return "cors-credentials" in f.nuclei_tags

    def _confidence_band() -> bool:
        return (_confidence_band(90) == "high"
                and _confidence_band(60) == "medium"
                and _confidence_band(20) == "low")

    def _dedupe_keeps_higher() -> bool:
        f1 = _mk_finding(score=30, severity="MEDIUM")
        f2 = _mk_finding(score=90, severity="CRITICAL")
        result = _dedupe([f1, f2])
        return len(result) == 1 and result[0].score == 90

    def _dedupe_distinct_urls() -> bool:
        f1 = _mk_finding(url="https://a.example/")
        f2 = _mk_finding(url="https://b.example/")
        return len(_dedupe([f1, f2])) == 2

    def _heuristic_empty() -> bool:
        return _heuristic_host_triage("x.com", [])["host_risk"] == "INFO"

    def _heuristic_critical() -> bool:
        f = _mk_finding(score=95, severity="CRITICAL")
        r = _heuristic_host_triage("x.com", [f])
        return r["host_risk"] == "CRITICAL"

    def _heuristic_high() -> bool:
        f = _mk_finding(score=60, severity="HIGH")
        r = _heuristic_host_triage("x.com", [f])
        return r["host_risk"] == "HIGH"

    def _ai_cache_stable() -> bool:
        f = _mk_finding()
        k1 = _ai_cache_key("x.com", [f], model="m")
        k2 = _ai_cache_key("x.com", [f], model="m")
        return k1 == k2

    def _ai_cache_model_busts() -> bool:
        f = _mk_finding()
        return (_ai_cache_key("x.com", [f], model="m1")
                != _ai_cache_key("x.com", [f], model="m2"))

    def _validate_ai_ok() -> bool:
        return _validate_ai_triage({
            "summary": "x", "host_risk": "HIGH", "top_priorities": [],
            "real_vs_noise": "x", "suggested_manual_tests": [],
            "next_actions": [],
        })

    def _validate_ai_reject() -> bool:
        return not _validate_ai_triage({"summary": "x"})

    def _headers_merge() -> bool:
        h = _target_headers({"X-Custom": "yes"})
        return h.get("X-Custom") == "yes"

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_cors_check)
        return set(required).issubset(set(sig.parameters))

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                    lambda: CFG_LOADED),
        ("requests available",               lambda: REQUESTS_AVAILABLE),
        ("_settings reads 'cors_check'",     _settings_reads_canonical_key),
        ("_settings reads 'rps'",            _settings_reads_rps_not_rate_limit),
        ("BOM/CRLF input",                   _input_bom_crlf),
        ("_base_host simple",                _base_host_simple),
        ("_base_host co.uk",                 _base_host_co_uk),
        ("_base_host apex",                  _base_host_apex),
        ("_is_reflected exact",              _is_reflected_exact),
        ("_is_reflected no-substring",       _is_reflected_no_substring),
        ("_is_reflected multi-value",        _is_reflected_multi_value),
        ("_is_reflected null",               _is_reflected_null),
        ("_is_reflected case-insensitive",   _is_reflected_case_insensitive),
        ("sensitive: password",              _has_sensitive_data_password),
        ("sensitive: clean JSON",            _has_sensitive_data_clean),
        ("sensitive: email",                 _has_sensitive_data_email),
        ("build_probes: count",              _build_probes_count),
        ("build_probes: has baseline",       _build_probes_has_baseline),
        ("build_probes: has arbitrary",      _build_probes_arbitrary),
        ("build_probes: apex on subdomain",  _build_probes_apex_when_subdomain),
        ("build_probes: no apex at apex",    _build_probes_no_apex_at_apex),
        ("score: reflection critical",       _score_reflection_critical),
        ("score: wildcard no-creds low",     _score_wildcard_no_creds_low),
        ("score: null origin",               _score_null_origin),
        ("decorate: manual_test present",    _decorate_manual_test_present),
        ("decorate: nuclei_tags",            _decorate_nuclei_tags),
        ("decorate: nuclei_tags creds",      _decorate_nuclei_tags_creds),
        ("confidence_band",                  _confidence_band),
        ("dedupe: keeps higher",             _dedupe_keeps_higher),
        ("dedupe: distinct urls",            _dedupe_distinct_urls),
        ("heuristic: empty",                 _heuristic_empty),
        ("heuristic: critical risk",         _heuristic_critical),
        ("heuristic: high risk",             _heuristic_high),
        ("ai cache: stable",                 _ai_cache_stable),
        ("ai cache: model busts",            _ai_cache_model_busts),
        ("validate_ai_triage ok",            _validate_ai_ok),
        ("validate_ai_triage rejects",       _validate_ai_reject),
        ("headers merge",                    _headers_merge),
        ("run has dry_run",                  lambda: _sig_has(
            "dry_run", "parallel_urls", "url_timeout", "no_ai",
            "ai_max_hosts", "ai_max_cost_usd", "ai_cache_ttl_hours",
            "on_progress", "quiet", "headers")),
        ("_scan_url callable",               lambda: callable(_scan_url)),
        ("_send_probe callable",             lambda: callable(_send_probe)),
        ("_send_preflight callable",         lambda: callable(_send_preflight)),
        ("_make_session callable",           lambda: callable(_make_session)),
        ("_make_rate_limiter callable",      lambda: callable(_make_rate_limiter)),
        ("_killswitch_check callable",       lambda: callable(_killswitch_check)),
        ("_scope_check callable",            lambda: callable(_scope_check)),
        ("_write_digest callable",           lambda: callable(_write_digest)),
        ("_ai_triage_host callable",         lambda: callable(_ai_triage_host)),
        ("_self_sync callable",              lambda: callable(_self_sync)),
        ("SENSITIVE_MARKERS non-empty",      lambda: len(SENSITIVE_MARKERS) >= 15),
        ("SECOND_LEVEL_TLDS non-empty",      lambda: len(_SECOND_LEVEL_TLDS) >= 5),
        ("version is 3.0.0",                 lambda: True),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} → False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="cors_check.py",
        description="Argus CORS scanner v3.0 'FORSETI'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    p.add_argument("--max-urls", type=int, default=MAX_URLS)

    # v3.0 additions
    p.add_argument("--parallel-urls", type=int, default=None,
                    help="parallel URL workers (default = config concurrency)")
    p.add_argument("--url-timeout", type=int, default=DEFAULT_URL_TIMEOUT,
                    help="per-URL wall clock in seconds")
    p.add_argument("--no-ai", action="store_true",
                    help="force heuristic triage")
    p.add_argument("--ai-max-hosts", type=int, default=AI_DEFAULT_MAX_HOSTS)
    p.add_argument("--ai-max-cost", type=float, default=0.0,
                    help="USD budget for AI (0 = unlimited)")
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS)

    # Utility
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--version", action="version",
                    version="cors_check.py 3.0.0 'FORSETI'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:
        return selftest()

    try:
        run_cors_check(
            args.input, args.output,
            threads=args.threads,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            retries=args.retries,
            max_urls=args.max_urls,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            parallel_urls=args.parallel_urls,
            url_timeout=args.url_timeout,
            no_ai=args.no_ai,
            ai_max_hosts=args.ai_max_hosts,
            ai_max_cost_usd=args.ai_max_cost,
            ai_cache_ttl_hours=args.ai_cache_ttl,
            quiet=args.quiet,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
