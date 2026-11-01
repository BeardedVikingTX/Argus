#!/usr/bin/env python3
"""
auditing_tools/cache_poisoning_finder.py — Web Cache Poisoning & Deception Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive cache attack detection module for Argus.

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every request. Rate limits are honored — cache-buster probes multiply
request volume, so throttling is critical.

Seven attack classes:

  1. Unkeyed-header poisoning
     17 headers that CDNs commonly leave unkeyed. Confirm via cache-buster
     reflection + headerless re-request.

  2. Unkeyed-parameter poisoning
     utm_*, fbclid, gclid, callback, and similar "analytics" params that
     origin reflects but cache ignores.

  3. Parameter cloaking
     Duplicate params (?a=1&a=payload), where cache normalizes what the
     origin doesn't.

  4. Fat GET
     GET request with a body. Origin parses body, cache keys only the URL.

  5. HTTP method override
     X-HTTP-Method-Override, X-Method-Override — cache may key on the
     original method while origin honors the override.

  6. Cache deception (path confusion)
     15 extensions × 8 delimiters = 120 variants. With victim cookie:
     request with auth, then without → check for auth-response leak.

  7. Cache-key normalization gaps
     Case, trailing slash, path params (;jsessionid), encoded traversal,
     and parameter order variants — cache and origin disagree.

Confirmation tiers:
  • CRITICAL   — poisoning confirmed with cache-buster + headerless re-request
                showing Age > 0 or X-Cache: HIT; OR deception confirmed with
                matching authenticated response served anonymously
  • HIGH       — reflection confirmed, cache hit not conclusively proven
  • MEDIUM     — surface mapped, manual verification required
  • LOW        — pattern detected, no confirmation attempted

Config integration (config.py):
  • MODULE_RATE_LIMITS["cache"]    → request rate + concurrency
  • ACTIVE_HEADERS + AUTH_HEADERS  → merged into every request
  • AUTH_COOKIES                   → session cookies
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Outputs (into `outdir`):
  • cache_findings.json        — full structured report
  • cache_candidates.txt       — flat list for triage
  • cache_poisoning.txt        — poisoning-specific findings
  • cache_deception.txt        — deception-specific findings

Remote DB (if scan_id is provided):
  • cache_findings table       — one row per (scan_id, finding_hash)

Integration:
  main.py → run_one("cache") → run_cache_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
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

log = logging.getLogger("argus.cache_poisoning")

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


def _cache_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("cache", {})
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 3),
        "timeout":     entry.get("timeout", 12),
    }


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

DEFAULT_THREADS      = 3
DEFAULT_RATE_LIMIT   = 2
DEFAULT_TIMEOUT      = 12

CACHE_BUSTER_LEN     = 16
CONFIRM_DELAY        = 0.4

# ── Cache-status headers (exhaustive) ──────────────────────────────────────
CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Varnish",
    "Age", "Cache-Control", "Via",
    "X-Served-By", "X-Cache-Hits", "X-Vercel-Cache",
    "Akamai-Cache-Status", "X-Drupal-Cache", "X-Magento-Cache-Debug",
    "x-nextjs-cache", "Server-Timing", "CDN-Cache-Control",
    "Surrogate-Control", "Fastly-Cache-Status", "X-Proxy-Cache",
    "X-Cache-Info", "X-CI-Cache", "X-Akamai-Transformed",
]

# ── Unkeyed header probes (expanded 17) ────────────────────────────────────
UNKEYED_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host", "evil-cache.example"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Forwarded-Port", "1"),
    ("X-Forwarded-For", "evil-cache.example"),
    ("X-Host", "evil-cache.example"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Server", "evil-cache.example"),
    ("Forwarded", "host=evil-cache.example"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Method-Override", "POST"),
    ("X-Forwarded-Prefix", "/admin"),
    ("X-Original-Host", "evil-cache.example"),
    ("X-Proxy-Host", "evil-cache.example"),
    ("X-Forwarded-Protocol", "http"),
    ("X-Forwarded-Path", "/admin"),
]

# ── Unkeyed parameter probes (expanded 9) ──────────────────────────────────
UNKEYED_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "callback", "cb",
]

# ── Deception extensions (15) ──────────────────────────────────────────────
DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".json", ".xml", ".txt",
]

# ── Deception delimiters (8) ───────────────────────────────────────────────
DECEPTION_DELIMITERS = [
    "",           # plain append: /account.css
    ";",          # path parameter: /account;.css
    "%2f",        # encoded slash:  /account%2f.css
    "%23",        # fragment:       /account%23.css
    "%00",        # null byte:      /account%00.css
    "/..%2f",     # traversal:      /account/..%2f.css
    "/.",         # dot path:       /account/..css
    "\\",         # backslash:      /account\.css
]

# ── Response headers that indicate dynamic content (potential PII) ────────
SENSITIVE_CONTENT_HEADERS = [
    "Set-Cookie", "Authorization", "X-User", "X-Account",
]

# ── Sensitive-content markers (for deception confirmation) ─────────────────
SENSITIVE_MARKERS = [
    "email", "user", "account", "profile", "dashboard", "session",
    "token", "api_key", "password", "billing", "invoice", "settings",
    "private", "personal", "logout", "sign out", "my account",
]

# ── Framework-specific headers (2025) ──────────────────────────────────────
FRAMEWORK_HEADERS: list[tuple[str, str]] = [
    ("RSC", "1"),                     # Next.js React Server Component
    ("Next-Router-State-Tree", "%5B%22%22%5D"),
    ("X-Nextjs-Data", "1"),
    ("Accept", "application/json"),
]

# ── Severity thresholds ────────────────────────────────────────────────────
SEV_CRITICAL = 90
SEV_HIGH     = 70
SEV_MEDIUM   = 45


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    def __init__(self, rate_limit: int = DEFAULT_RATE_LIMIT, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.verify = False
        hdrs = _target_headers()
        if hdrs:
            self.session.headers.update(hdrs)
        if "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = "Argus-Cache-Auditor/2.0"
        cookies = _auth_cookies()
        for k, v in cookies.items():
            self.session.cookies.set(k, v)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.min_interval > 0:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
        self._last = time.monotonic()
        try:
            return self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CacheFinding:
    target: str
    vuln_type: str
    category: str = "poisoning"
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    evidence: str = ""
    payload: str = ""
    cache_headers: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.target}|{self.vuln_type}".encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":        self.target,
            "target_host":   urllib.parse.urlparse(self.target).hostname or "",
            "vuln_type":     self.vuln_type,
            "category":      self.category,
            "severity":      self.severity,
            "confidence":    self.confidence,
            "confirmed":     self.confirmed,
            "evidence":      self.evidence[:500],
            "payload":       self.payload[:500],
            "cache_headers": self.cache_headers,
            "details":       self.details,
            "auth_enabled":  self.auth_enabled,
            "finding_hash":  self.finding_hash,
            "first_seen":    self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _buster() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=CACHE_BUSTER_LEN))


def _with_buster(url: str, extra: Optional[dict] = None) -> str:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params["argus_cb"] = _buster()
    if extra:
        params.update(extra)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))


def _load_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    urls, seen = [], set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0]
        if not tok.startswith(("http://", "https://")):
            tok = "https://" + tok
        if tok not in seen:
            seen.add(tok)
            urls.append(tok)
    return urls


def _body_snippet(resp: requests.Response, n: int = 400) -> str:
    try:
        return resp.text[:n].replace("\n", " ").strip()
    except Exception:
        return ""


def _reflects(resp: requests.Response, needle: str) -> bool:
    if not needle:
        return False
    try:
        if needle in resp.text[:100000]:
            return True
    except Exception:
        pass
    return needle in resp.headers.get("Location", "")


def _extract_cache_headers(resp: requests.Response) -> dict:
    out = {}
    for hdr in CACHE_STATUS_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            out[hdr] = val
    return out


def _is_cache_hit(resp: requests.Response) -> bool:
    """True if response shows evidence of having been cached."""
    # Age > 0 always means cached
    age = resp.headers.get("Age")
    if age:
        try:
            if int(age) > 0:
                return True
        except ValueError:
            pass
    # X-Cache-family headers containing HIT
    for hdr in ("X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Vercel-Cache",
                "Akamai-Cache-Status", "X-Drupal-Cache", "X-Proxy-Cache",
                "X-Cache-Info", "Fastly-Cache-Status"):
        val = (resp.headers.get(hdr) or "").lower()
        if "hit" in val:
            return True
    # Varnish X-Cache-Hits count
    hits = resp.headers.get("X-Cache-Hits")
    if hits:
        try:
            if int(hits.split(",")[0]) > 0:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _has_sensitive_content(resp: requests.Response) -> bool:
    try:
        body = resp.text[:100000].lower()
    except Exception:
        return False
    hits = sum(1 for m in SENSITIVE_MARKERS if m in body)
    return hits >= 2


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — CACHE DETECTION (with Age evolution)
# ═════════════════════════════════════════════════════════════════════════════

def detect_cache(session: RateLimitedSession, url: str) -> tuple[bool, dict]:
    """
    Determine whether a cache is present. Returns (has_cache, headers).

    Uses Age evolution: fire the same cache-buster URL 3× spaced 1s apart
    and watch whether Age increments. This is the highest-confidence
    cache-presence signal available without knowing the CDN.
    """
    test_url = _with_buster(url)
    ages: list[int] = []
    headers_seen: dict = {}

    for i in range(3):
        resp = session.get(test_url)
        if not resp:
            return False, headers_seen
        if i == 0:
            headers_seen = _extract_cache_headers(resp)
        age_hdr = resp.headers.get("Age")
        if age_hdr:
            try:
                ages.append(int(age_hdr))
            except ValueError:
                ages.append(0)
        if i < 2:
            time.sleep(1.0)

    has_cache = False
    # Age evolution: monotonic increase = definitely cached
    if len(ages) >= 2 and ages[-1] > ages[0]:
        has_cache = True
    # Any single hit-indicator header
    if not has_cache and any(
        "hit" in (headers_seen.get(h, "") or "").lower()
        for h in ("X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Vercel-Cache")
    ):
        has_cache = True
    # Any cache-status header at all = cache present (may be MISS)
    if not has_cache and headers_seen:
        has_cache = True

    return has_cache, headers_seen


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — UNKEYED HEADER POISONING
# ═════════════════════════════════════════════════════════════════════════════

def test_header_poisoning(
    session: RateLimitedSession, url: str, auth_on: bool,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for header_name, header_value in UNKEYED_HEADERS:
        test_url = _with_buster(url)

        resp_with = session.get(test_url, headers={header_name: header_value})
        if not resp_with:
            continue
        if not _reflects(resp_with, header_value):
            continue

        # Reflected — check if cached
        time.sleep(CONFIRM_DELAY)
        resp_without = session.get(test_url)
        if not resp_without:
            continue

        still_reflected = _reflects(resp_without, header_value)
        cache_hit = _is_cache_hit(resp_without)
        confirmed = still_reflected and cache_hit

        if confirmed:
            severity = "CRITICAL"
            confidence = 95
        elif still_reflected:
            severity = "HIGH"
            confidence = 70
        else:
            severity = "MEDIUM"
            confidence = 55

        findings.append(CacheFinding(
            target=url,
            vuln_type=f"header_poisoning_{header_name.lower().replace('-', '_')}",
            category="poisoning",
            severity=severity,
            confidence=confidence,
            confirmed=confirmed,
            evidence=(
                f"{header_name}={header_value!r} reflected"
                + (" and cached (CONFIRMED)" if confirmed
                   else " (cache-hit not proven)" if still_reflected
                   else " but not persisted on re-request")
            ),
            payload=f"{header_name}: {header_value}",
            cache_headers=_extract_cache_headers(resp_with),
            details={
                "header": header_name,
                "payload": header_value,
                "cache_hit_on_replay": cache_hit,
                "still_reflected": still_reflected,
                "body_snippet": _body_snippet(resp_with),
            },
            auth_enabled=auth_on,
            first_seen=now,
        ))

        if confirmed:
            break  # one confirmed poisoning per URL is sufficient

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CACHE DECEPTION
# ═════════════════════════════════════════════════════════════════════════════

def test_cache_deception(
    session: RateLimitedSession, url: str,
    victim_cookie: Optional[str], auth_on: bool,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    max_variants = 25  # cap to keep request volume sane
    tested = 0

    for ext in DECEPTION_EXTENSIONS:
        for delim in DECEPTION_DELIMITERS:
            if tested >= max_variants:
                break
            tested += 1

            test_path = f"{url.rstrip('/')}{delim}{_buster()[:6]}{ext}"
            test_url = _with_buster(test_path)

            # With victim cookie (if supplied)
            headers_victim = {}
            if victim_cookie:
                headers_victim["Cookie"] = victim_cookie

            resp_victim = session.get(test_url, headers=headers_victim)
            if not resp_victim:
                continue

            # Only investigate if the static-extension path returns 200
            if resp_victim.status_code != 200:
                continue

            # No victim cookie → surface candidate only
            if not victim_cookie:
                time.sleep(CONFIRM_DELAY)
                resp_recheck = session.get(test_url)
                if resp_recheck and _is_cache_hit(resp_recheck):
                    findings.append(CacheFinding(
                        target=test_url,
                        vuln_type="cache_deception_surface",
                        category="deception",
                        severity="MEDIUM",
                        confidence=50,
                        confirmed=False,
                        evidence="Static-extension variant returned 200 and was cached",
                        payload=test_url,
                        details={
                            "extension": ext,
                            "delimiter": delim,
                            "has_victim_cookie": False,
                        },
                        auth_enabled=auth_on,
                        first_seen=now,
                    ))
                continue

            # Victim cookie → try anonymous re-request
            time.sleep(CONFIRM_DELAY)
            resp_anon = session.get(test_url)
            if not resp_anon:
                continue

            # Deception confirmed if:
            #  • Anonymous response matches victim response (body equality)
            #  • Victim response contained sensitive markers
            #  • Anonymous response is a cache hit
            victim_snippet = _body_snippet(resp_victim, 500)
            anon_snippet = _body_snippet(resp_anon, 500)
            sensitive = _has_sensitive_content(resp_victim)
            cache_hit = _is_cache_hit(resp_anon)

            if (victim_snippet
                and victim_snippet == anon_snippet
                and len(victim_snippet) > 100
                and sensitive
                and cache_hit):
                findings.append(CacheFinding(
                    target=test_url,
                    vuln_type="cache_deception_confirmed",
                    category="deception",
                    severity="CRITICAL",
                    confidence=95,
                    confirmed=True,
                    evidence="Authenticated PII response served anonymously via static extension",
                    payload=test_url,
                    details={
                        "extension": ext,
                        "delimiter": delim,
                        "victim_snippet": victim_snippet[:200],
                        "anon_snippet": anon_snippet[:200],
                        "sensitive_detected": sensitive,
                    },
                    auth_enabled=auth_on,
                    first_seen=now,
                ))
                return findings  # one confirmed deception per URL

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — PARAMETER CLOAKING + POLLUTION
# ═════════════════════════════════════════════════════════════════════════════

def test_parameter_cloaking(
    session: RateLimitedSession, url: str, auth_on: bool,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    parsed = urllib.parse.urlparse(url)
    existing = urllib.parse.parse_qsl(parsed.query)

    # ── Duplicate parameter cloaking ────────────────────────────────────────
    if existing:
        key, orig_val = existing[0]
        payload = f"argus_{_buster()[:8]}"

        # Build: ?key=original&key=payload
        dup_query = f"{key}={urllib.parse.quote(orig_val)}&{key}={urllib.parse.quote(payload)}"
        test_url = urllib.parse.urlunparse(parsed._replace(query=dup_query + f"&argus_cb={_buster()}"))

        resp = session.get(test_url)
        if resp and _reflects(resp, payload):
            time.sleep(CONFIRM_DELAY)
            resp2 = session.get(test_url)
            cache_hit = _is_cache_hit(resp2) if resp2 else False
            findings.append(CacheFinding(
                target=url,
                vuln_type="parameter_cloaking_duplicate",
                category="cloaking",
                severity="HIGH" if cache_hit else "MEDIUM",
                confidence=75 if cache_hit else 60,
                confirmed=cache_hit,
                evidence=f"Duplicate param '{key}' reflected with payload — cache may parse differently",
                payload=test_url,
                details={"param": key, "payload": payload, "cache_hit": cache_hit},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Unkeyed parameter reflection ────────────────────────────────────────
    for param in UNKEYED_PARAMS:
        payload = f"argus_{_buster()[:8]}"
        test_url = _with_buster(url, {param: payload})
        resp = session.get(test_url)
        if resp and _reflects(resp, payload):
            findings.append(CacheFinding(
                target=url,
                vuln_type=f"unkeyed_param_{param}",
                category="poisoning",
                severity="MEDIUM",
                confidence=55,
                confirmed=False,
                evidence=f"Unkeyed parameter '{param}' reflected into response",
                payload=f"{param}={payload}",
                details={"param": param},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Fat GET ────────────────────────────────────────────────────────────
    fat_payload = f"argus_fat_{_buster()[:8]}=reflected"
    try:
        resp = session.request(
            "GET", _with_buster(url),
            data=fat_payload,
        )
        if resp and (fat_payload.split("=")[1] in resp.text or "reflected" in resp.text):
            time.sleep(CONFIRM_DELAY)
            resp2 = session.get(_with_buster(url))
            cache_hit = _is_cache_hit(resp2) if resp2 else False
            findings.append(CacheFinding(
                target=url,
                vuln_type="fat_get_reflection",
                category="fat_get",
                severity="HIGH" if cache_hit else "MEDIUM",
                confidence=70 if cache_hit else 55,
                confirmed=cache_hit,
                evidence="GET request body reflected — origin parses body, cache may ignore it",
                payload=fat_payload,
                details={"cache_hit": cache_hit},
                auth_enabled=auth_on,
                first_seen=now,
            ))
    except Exception:
        pass

    # ── HTTP method override ───────────────────────────────────────────────
    for hdr_name, hdr_value in (
        ("X-HTTP-Method-Override", "POST"),
        ("X-Method-Override", "POST"),
    ):
        resp = session.get(
            _with_buster(url),
            headers={hdr_name: hdr_val if (hdr_val := hdr_value) else ""},
        )
        if resp and resp.status_code in (200, 201, 202):
            findings.append(CacheFinding(
                target=url,
                vuln_type=f"method_override_{hdr_name.lower().replace('-', '_')}",
                category="method_override",
                severity="MEDIUM",
                confidence=45,
                confirmed=False,
                evidence=f"{hdr_name}: {hdr_value} accepted by origin",
                payload=f"{hdr_name}: {hdr_value}",
                details={"status": resp.status_code},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Parameter pollution (HPP) ──────────────────────────────────────────
    if existing:
        key = existing[0][0]
        pollution_payload = f"argus_hpp_{_buster()[:8]}"
        # Send param twice with different values
        hpp_query = f"{key}=1&{key}={urllib.parse.quote(pollution_payload)}"
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=hpp_query + f"&argus_cb={_buster()}")
        )
        resp = session.get(test_url)
        if resp and _reflects(resp, pollution_payload):
            findings.append(CacheFinding(
                target=url,
                vuln_type="parameter_pollution_reflected",
                category="pollution",
                severity="MEDIUM",
                confidence=50,
                confirmed=False,
                evidence=f"HTTP parameter pollution reflected for '{key}'",
                payload=hpp_query,
                details={"param": key},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — CACHE-KEY NORMALIZATION GAPS
# ═════════════════════════════════════════════════════════════════════════════

def test_normalization_gaps(
    session: RateLimitedSession, url: str, auth_on: bool,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    parsed = urllib.parse.urlparse(url)
    if not parsed.path or parsed.path == "/":
        return findings

    # ── Trailing slash ────────────────────────────────────────────────────
    if not parsed.path.endswith("/"):
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=parsed.path + "/", query=f"argus_cb={_buster()}")
        )
        resp = session.get(test_url)
        if resp and resp.status_code in (200, 301, 302):
            findings.append(CacheFinding(
                target=url,
                vuln_type="normalization_trailing_slash",
                category="normalization",
                severity="LOW",
                confidence=40,
                confirmed=False,
                evidence="Trailing-slash variant resolves differently",
                payload=test_url,
                details={"variant": parsed.path + "/", "status": resp.status_code},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Path parameter (;jsessionid) ──────────────────────────────────────
    if not parsed.path.endswith("/"):
        test_path = f"{parsed.path};argus={_buster()[:6]}"
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=test_path, query=f"argus_cb={_buster()}")
        )
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            findings.append(CacheFinding(
                target=url,
                vuln_type="normalization_path_param",
                category="normalization",
                severity="MEDIUM",
                confidence=50,
                confirmed=False,
                evidence="Path parameter accepted — cache may strip it, origin may not",
                payload=test_url,
                details={"variant": test_path},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Case variation ────────────────────────────────────────────────────
    if parsed.path != parsed.path.lower():
        # Only test if path has uppercase (rare)
        pass
    # Test lowercase variant
    test_path = parsed.path.lower()
    if test_path != parsed.path:
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=test_path, query=f"argus_cb={_buster()}")
        )
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            findings.append(CacheFinding(
                target=url,
                vuln_type="normalization_case",
                category="normalization",
                severity="LOW",
                confidence=35,
                confirmed=False,
                evidence="Case-lowercase path variant resolves",
                payload=test_url,
                details={"variant": test_path},
                auth_enabled=auth_on,
                first_seen=now,
            ))

    # ── Encoded traversal ─────────────────────────────────────────────────
    test_path = f"{parsed.path.rstrip('/')}/..%2f{parsed.path.strip('/').split('/')[-1]}"
    test_url = urllib.parse.urlunparse(
        parsed._replace(path=test_path, query=f"argus_cb={_buster()}")
    )
    resp = session.get(test_url)
    if resp and resp.status_code == 200:
        findings.append(CacheFinding(
            target=url,
            vuln_type="normalization_encoded_traversal",
            category="normalization",
            severity="MEDIUM",
            confidence=45,
            confirmed=False,
            evidence="Encoded traversal path resolves — cache/origin may disagree",
            payload=test_url,
            details={"variant": test_path},
            auth_enabled=auth_on,
            first_seen=now,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[CacheFinding]) -> None:
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
        result = DB.upsert_cache_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} cache finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_cache_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    victim_cookie: Optional[str] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    headers: Optional[dict] = None,
    test_poisoning: bool = True,
    test_deception: bool = True,
    test_cloaking: bool = True,
    test_normalization: bool = True,
    max_urls: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Run the full cache audit against every URL in `live_urls_file`.
    """
    start = time.monotonic()

    settings = _cache_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]

    urls = _load_urls(live_urls_file)
    if max_urls:
        urls = urls[:max_urls]
    outdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
             f"timeout={eff_timeout}s")
    log.info(f"           source: MODULE_RATE_LIMITS['cache']")

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to every request")
        for k, v in list(cfg_hdrs.items())[:4]:
            v_short = v[:40] + "…" if len(v) > 40 else v
            log.info(f"           · {k}: {v_short}")
    if victim_cookie:
        log.info(f"  Auth   : victim cookie supplied (deception confirmation enabled)")
    elif auth_on:
        log.info(f"  Auth   : request.txt session (deception confirmation may be limited)")
    else:
        log.info(f"  Auth   : disabled")
    log.info("")

    if not urls:
        log.warning("  No URLs to audit — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)

    # ── Phase 1: Cache detection ────────────────────────────────────────────
    log.info("  Phase 1 — Cache detection (Age evolution test)")
    profiles: list[dict] = []
    seen_hosts: set[str] = set()
    cached_count = 0

    for url in urls:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        has_cache, headers_seen = detect_cache(session, url)
        profiles.append({
            "host": host,
            "sample_url": url,
            "has_cache": has_cache,
            "cache_headers": headers_seen,
        })
        if has_cache:
            cached_count += 1
            log.info(f"    {host:<40} CACHED  ({len(headers_seen)} cache header(s))")
        else:
            log.info(f"    {host:<40} no cache")

    if cached_count == 0:
        log.warning("  No cache detected on any host — proceeding with surface mapping only")

    # ── Phases 2–5: Per-URL testing ────────────────────────────────────────
    all_findings: list[CacheFinding] = []

    def _process(url: str) -> list[CacheFinding]:
        local: list[CacheFinding] = []
        if test_poisoning:
            local.extend(test_header_poisoning(session, url, auth_on))
        if test_deception:
            local.extend(test_cache_deception(session, url, victim_cookie, auth_on))
        if test_cloaking:
            local.extend(test_parameter_cloaking(session, url, auth_on))
        if test_normalization:
            local.extend(test_normalization_gaps(session, url, auth_on))
        return local

    log.info("")
    log.info(f"  Phases 2–5 — Testing {len(urls)} URL(s) for cache attacks...")

    with ThreadPoolExecutor(max_workers=eff_conc) as pool:
        futures = {pool.submit(_process, u): u for u in urls}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                results = fut.result()
                if results:
                    all_findings.extend(results)
                    confirmed = sum(1 for r in results if r.confirmed)
                    tag = f" ({confirmed} confirmed)" if confirmed else ""
                    log.info(f"    {url[:60]:<60} {len(results)} finding(s){tag}")
            except Exception as e:
                log.debug(f"    error on {url}: {e}")

    # ── Dedupe ──────────────────────────────────────────────────────────────
    seen_keys: set[tuple] = set()
    deduped: list[CacheFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}
    by_type: dict[str, int] = {}
    confirmed_count = 0

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        if f.confirmed:
            confirmed_count += 1

    # Flat outputs
    (outdir / "cache_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.category}\t{f.severity}\t{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "cache_poisoning.txt").write_text(
        "\n".join(f"{f.target}\t{f.vuln_type}\t{f.evidence[:160]}"
                  for f in deduped if f.category == "poisoning") + "\n"
    )
    (outdir / "cache_deception.txt").write_text(
        "\n".join(f"{f.target}\t{f.vuln_type}\t{f.evidence[:160]}"
                  for f in deduped if f.category == "deception") + "\n"
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "victim_cookie_supplied": victim_cookie is not None,
        "config": {
            "rate_limit":         eff_rate,
            "concurrency":        eff_conc,
            "timeout":            eff_timeout,
            "headers_count":      len(cfg_hdrs),
            "test_poisoning":     test_poisoning,
            "test_deception":     test_deception,
            "test_cloaking":      test_cloaking,
            "test_normalization": test_normalization,
        },
        "cache_profiles": profiles,
        "totals": {
            "urls_scanned":       len(urls),
            "hosts_with_cache":   cached_count,
            "total_findings":     len(deduped),
            "confirmed":          confirmed_count,
            "critical":           by_severity["CRITICAL"],
            "high":               by_severity["HIGH"],
            "medium":             by_severity["MEDIUM"],
            "low":                by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_category":  dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "by_type":      dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "cache_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

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
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    cache_candidates.txt         {len(deduped):>5} candidate(s)")
    log.info(f"    cache_poisoning.txt          {sum(1 for f in deduped if f.category=='poisoning'):>5} poisoning finding(s)")
    log.info(f"    cache_deception.txt          {sum(1 for f in deduped if f.category=='deception'):>5} deception finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    log.info(f"  Confirmed : {confirmed_count} / {len(deduped)}")

    if deduped:
        log.info("")
        log.info("  Top findings:")
        for f in deduped[:12]:
            tag = "✓" if f.confirmed else " "
            log.info(f"    {tag} [{f.severity:<8}] {f.category:<14} {f.vuln_type:<40} {f.target[:50]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "cache_profiles": [],
        "totals": {
            "urls_scanned": 0, "hosts_with_cache": 0, "total_findings": 0,
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_category": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "cache_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for n in ("cache_candidates.txt", "cache_poisoning.txt", "cache_deception.txt"):
        (outdir / n).write_text("")
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus Cache Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--cookie", help="Victim session cookie for deception confirmation")
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--max-urls", type=int, default=None)
    parser.add_argument("--no-poisoning", action="store_true")
    parser.add_argument("--no-deception", action="store_true")
    parser.add_argument("--no-cloaking", action="store_true")
    parser.add_argument("--no-normalization", action="store_true")
    args = parser.parse_args()

    try:
        run_cache_audit(
            args.input, args.output,
            victim_cookie=args.cookie,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            max_urls=args.max_urls,
            test_poisoning=not args.no_poisoning,
            test_deception=not args.no_deception,
            test_cloaking=not args.no_cloaking,
            test_normalization=not args.no_normalization,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
