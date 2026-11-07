#!/usr/bin/env python3
"""
auditing_tools/cache_poisoning_finder.py — Web Cache Poisoning & Deception
Auditor (v3.0, military-grade)
═══════════════════════════════════════════════════════════════════════════════

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing (defeats fixed-interval rate-limit fingerprints)
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page
  • Hostname payloads randomized (`cache-{rhex}.example`) so WAF signatures
    cannot match a fixed evil domain

CONFIRMATION PHILOSOPHY (no false positives)
────────────────────────────────────────────
A poisoning finding is CONFIRMED only when ALL THREE are true:

  1. Reflection   — the random payload appears in the response to Request A.
  2. Persistence  — a follow-up Request B to the SAME cache-buster URL
                    (WITHOUT the payload header/param) STILL contains the
                    same random payload.
  3. Cache-hit    — Request B shows at least one cache-hit signal:
                       • Age > 0
                       • X-Cache / CF-Cache-Status / X-Vercel-Cache = HIT
                       • MISS→HIT transition vs Request A
                       • Response time drops ≥ 30 % vs Request A
                    AND the response does NOT contain `Vary` for the
                    injected header (keyed = not exploitable).

Deception is CONFIRMED only when:
  • Request A (authenticated) returns 200 with sensitive markers, AND
  • Request B (anonymous, same URL) returns identical content, AND
  • Request B shows cache-hit evidence.

SEVERITY (impact-driven, not technique-driven)
──────────────────────────────────────────────
  CRITICAL   Confirmed poisoning AND payload is HTML-unescaped
             (XSS-capable), OR redirect_location (open-redirect-capable),
             OR confirmed deception with PII.
  HIGH       Confirmed poisoning with non-XSS/redirect context, OR
             Host-header poisoning confirmed, OR
             confirmed deception without PII.
  MEDIUM     Persistence proven but cache-hit not conclusively shown, OR
             Fat-GET/cloaking/normalization with cache-hit evidence.
  LOW        Surface mapped (cacheable endpoint, or reflection in
             non-sensitive context). No persistence proof.
  INFO       Cache detected; no injection surface.

CHAINS (aggregated into cache_chains.json)
──────────────────────────────────────────
  cache-poison-xss         confirmed poisoning + unescaped HTML reflection
  cache-poison-redirect    confirmed poisoning + Location header reflection
  cache-poison-host        Host-header poisoning confirmed
  cache-deception-pii      authenticated PII served anonymously
  cache-deception-bypass   deception lets attacker read protected page

OUTPUTS
───────
  cache_findings.json      — every finding (full report)
  cache_confirmed.json     — HIGH / CRITICAL / chain-confirmed ONLY
  cache_chains.json        — structured chain records
  cache_candidates.txt     — flat triage
  cache_poisoning.txt      — category-specific
  cache_deception.txt      — category-specific
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import string
import statistics
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

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
    return getattr(CFG, key, default) if CFG_LOADED else default


def _cache_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("cache", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 2),
        "timeout":     entry.get("timeout", 12),
        "jitter":      entry.get("jitter", 0.5),
        "proxies":     entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY
# ═════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# ═════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare":  {"headers": ["cf-ray", "__cf_bm", "cf-cache-status"],
                    "body":    ["Attention Required! | Cloudflare"]},
    "Akamai":      {"headers": ["akamai-grn", "x-akamai-transformed", "_abck"],
                    "body":    ["Access Denied", "Reference&#32;&#35;"]},
    "Imperva":     {"headers": ["x-iinfo", "incap_ses", "_Incapsula_Resource"],
                    "body":    ["Pardon Our Interruption"]},
    "AWS WAF":     {"headers": ["x-amzn-requestid", "x-amzn-errortype"],
                    "body":    ["Request blocked", "AWS WAF"]},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "bigipserver"],
                    "body":    ["The requested URL was rejected"]},
    "Sucuri":      {"headers": ["x-sucuri-id", "x-sucuri-cache"],
                    "body":    ["Sucuri WebSite Firewall"]},
    "DataDome":    {"headers": ["x-datadome", "datadome"],
                    "body":    ["captcha-delivery"]},
    "ModSecurity": {"headers": ["x-mod-security"], "body": ["ModSecurity"]},
}


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


def detect_waf(session: "EvasionSession", url: str) -> WAFReport:
    report = WAFReport()
    try:
        resp = session.benign_get(url)
    except Exception:
        return report
    if resp is None:
        return report

    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:4000].lower()

    for vendor, sig in WAF_SIGNATURES.items():
        hits = [f"header:{h}" for h in sig["headers"] if h.lower() in header_blob]
        hits += [f"body:{b[:40]}" for b in sig["body"] if b.lower() in body_blob]
        if hits:
            report.vendor = vendor
            report.signals = hits
            report.confidence = min(100, 50 + 15 * len(hits))
            break

    if resp.status_code in (403, 406, 429, 503):
        low = (resp.text or "")[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40
    return report


# ═════════════════════════════════════════════════════════════════════════════
#  EVASION SESSION
# ═════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


@dataclass
class EvasionProfile:
    rate_limit: float = 2.0
    jitter: float = 0.5
    rotate_ua: bool = True
    rotate_xff: bool = True
    proxies: list[str] = field(default_factory=list)
    backoff_codes: tuple[int, ...] = (403, 406, 429, 503)
    max_backoff: float = 30.0
    cooldown_after_block: float = 60.0


class EvasionSession:
    def __init__(self, profile: EvasionProfile, timeout: int = 12):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())
        for k, v in _auth_cookies().items():
            self.session.cookies.set(k, v)

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0

    def __enter__(self): return self
    def __exit__(self, *exc):
        try: self.session.close()
        except Exception: pass

    def _pace(self):
        now = time.monotonic()
        if now < self._cooldown_until:
            time.sleep(self._cooldown_until - now)
        interval = self._min_interval + random.uniform(0, self.profile.jitter)
        elapsed = time.monotonic() - self._last
        if elapsed < interval:
            time.sleep(interval - elapsed)
        if self._backoff > 0:
            time.sleep(self._backoff)
        self._last = time.monotonic()

    def _rotate(self):
        if self.profile.rotate_ua:
            self.session.headers["User-Agent"] = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
            self._ua_idx += 1
        if self.profile.rotate_xff:
            self._xff_counter += 1
            o = self._xff_counter % 254 + 1
            self.session.headers["X-Forwarded-For"] = f"10.0.{o}.{o}"
            self.session.headers["X-Real-IP"] = f"10.0.{o}.{o}"

    def _proxy(self) -> Optional[dict]:
        if not self.profile.proxies:
            return None
        p = self.profile.proxies[self._proxy_idx % len(self.profile.proxies)]
        self._proxy_idx += 1
        return {"http": p, "https": p}

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False, proxies=proxy, **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

        if resp.status_code in self.profile.backoff_codes:
            self._backoff = min(self.profile.max_backoff,
                                max(1.0, self._backoff * 2 or 1.0))
            low = (resp.text or "")[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + self.profile.cooldown_after_block
                log.warning("  WAF block — cooling down %.0fs",
                            self.profile.cooldown_after_block)
        elif resp.status_code < 400:
            self._backoff = 0.0
        return resp

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def benign_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

CACHE_BUSTER_LEN  = 16
CONFIRM_DELAY     = 0.6   # seconds — better for typical CDN TTLs
CONFIRM_DELAY_MAX = 3.0   # adaptive retry ceiling
RESPONSE_TIME_HIT_RATIO = 0.7  # request B < 70 % of request A = likely hit

# ── Cache-status header families ─────────────────────────────────────────
CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Varnish",
    "Age", "Cache-Control", "Via", "X-Served-By", "X-Cache-Hits",
    "X-Vercel-Cache", "Akamai-Cache-Status", "X-Drupal-Cache",
    "X-Magento-Cache-Debug", "x-nextjs-cache", "Server-Timing",
    "CDN-Cache-Control", "Surrogate-Control", "Fastly-Cache-Status",
    "X-Proxy-Cache", "X-Cache-Info", "X-CI-Cache", "X-Akamai-Transformed",
]
HIT_INDICATOR_HEADERS = [
    "X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Vercel-Cache",
    "Akamai-Cache-Status", "X-Drupal-Cache", "X-Proxy-Cache",
    "X-Cache-Info", "Fastly-Cache-Status",
]

# ── Unkeyed header probes (17) — payloads randomized per call ───────────
UNKEYED_HEADER_NAMES: list[str] = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-For", "X-Host", "X-Original-URL",
    "X-Rewrite-URL", "X-Forwarded-Server", "Forwarded",
    "X-HTTP-Method-Override", "X-Method-Override", "X-Forwarded-Prefix",
    "X-Original-Host", "X-Proxy-Host", "X-Forwarded-Protocol",
    "X-Forwarded-Path",
]

UNKEYED_PARAM_NAMES = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "callback", "cb",
]

DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".json", ".xml", ".txt",
]

DECEPTION_DELIMITERS = [
    "", ";", "%2f", "%23", "%00", "/..%2f", "/.", "\\",
]

SENSITIVE_MARKERS = [
    "email", "user", "account", "profile", "dashboard", "session",
    "token", "api_key", "password", "billing", "invoice", "settings",
    "private", "personal", "logout", "sign out", "my account",
]

# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CacheFinding:
    target: str
    vuln_type: str
    category: str = "poisoning"
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    evidence: str = ""
    payload: str = ""
    reflection_context: str = ""
    cache_headers: dict = field(default_factory=dict)
    cache_hit_evidence: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.target}|{self.vuln_type}".encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":              self.target,
            "target_host":         urllib.parse.urlparse(self.target).hostname or "",
            "vuln_type":           self.vuln_type,
            "category":            self.category,
            "severity":            self.severity.value,
            "confidence":          self.confidence,
            "confirmed":           self.confirmed,
            "evidence":            self.evidence[:600],
            "payload":             self.payload[:500],
            "reflection_context":  self.reflection_context,
            "cache_headers":       self.cache_headers,
            "cache_hit_evidence":  self.cache_hit_evidence,
            "details":             self.details,
            "chain_ids":           self.chain_ids,
            "waf_vendor":          self.waf_vendor,
            "auth_enabled":        self.auth_enabled,
            "finding_hash":        self.finding_hash,
            "first_seen":          self.first_seen,
        }


@dataclass
class CacheChain:
    chain_id: str
    name: str
    severity: Severity
    steps: list[str]
    finding_hashes: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_id":       self.chain_id,
            "name":           self.name,
            "severity":       self.severity.value,
            "steps":          self.steps,
            "finding_hashes": self.finding_hashes,
            "evidence":       self.evidence[:600],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _buster() -> str:
    return _rand_token(CACHE_BUSTER_LEN)


def _with_buster(url: str, extra: Optional[dict] = None) -> str:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params["argus_cb"] = _buster()
    if extra:
        params.update(extra)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))


def _add_buster_to(url: str, buster: str) -> str:
    """Add a SPECIFIC buster to a URL — used when we must reuse the same cache key."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params["argus_cb"] = buster
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


def _body_snippet(resp: Optional[requests.Response], n: int = 400) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:n].replace("\n", " ").strip()
    except Exception:
        return ""


def _body_text(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text or ""
    except Exception:
        return ""


def _body_fingerprint(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return hashlib.sha256(resp.content).hexdigest()[:16]
    except Exception:
        return ""


def _extract_cache_headers(resp: Optional[requests.Response]) -> dict:
    if resp is None:
        return {}
    out = {}
    for hdr in CACHE_STATUS_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            out[hdr] = val
    return out


def _get_age(resp: Optional[requests.Response]) -> Optional[int]:
    if resp is None:
        return None
    age = resp.headers.get("Age")
    if age is None:
        return None
    try:
        return int(age)
    except ValueError:
        return None


def _get_cache_status(resp: Optional[requests.Response]) -> str:
    """Return a canonicalized cache status: 'hit' / 'miss' / '' """
    if resp is None:
        return ""
    for h in HIT_INDICATOR_HEADERS:
        val = (resp.headers.get(h) or "").lower()
        if "hit" in val:
            return "hit"
        if "miss" in val:
            return "miss"
        if "bypass" in val or "dynamic" in val:
            return "bypass"
    return ""


def _cache_hit_evidence(resp_a: Optional[requests.Response],
                        resp_b: Optional[requests.Response],
                        time_a_ms: float = 0.0,
                        time_b_ms: float = 0.0) -> dict:
    """
    Multi-signal cache-hit determination for Request B (verify request).

    Returns dict with:
      hit:        bool (True if at least one strong signal confirms a hit)
      signals:    list of signal names that fired
      evidence:   dict of raw evidence
    """
    if resp_b is None:
        return {"hit": False, "signals": [], "evidence": {}}

    signals: list[str] = []
    evidence: dict = {}

    # Signal 1 — Age > 0
    age_b = _get_age(resp_b)
    if age_b is not None and age_b > 0:
        signals.append("age_positive")
        evidence["age_b"] = age_b

    # Signal 2 — HIT indicator header on request B
    status_b = _get_cache_status(resp_b)
    if status_b == "hit":
        signals.append("status_hit")
        evidence["status_b"] = "hit"

    # Signal 3 — MISS → HIT transition
    status_a = _get_cache_status(resp_a)
    if status_a == "miss" and status_b == "hit":
        signals.append("miss_to_hit_transition")
        evidence["transition"] = "miss→hit"

    # Signal 4 — Response-time drop ≥ 30 %
    if time_a_ms > 0 and time_b_ms > 0 and time_b_ms < time_a_ms * RESPONSE_TIME_HIT_RATIO:
        signals.append("faster_response")
        evidence["time_a_ms"] = round(time_a_ms, 1)
        evidence["time_b_ms"] = round(time_b_ms, 1)

    # Signal 5 — X-Cache-Hits counter
    hits_hdr = resp_b.headers.get("X-Cache-Hits")
    if hits_hdr:
        try:
            if int(hits_hdr.split(",")[0]) > 0:
                signals.append("cache_hits_counter")
                evidence["x_cache_hits"] = hits_hdr
        except (ValueError, IndexError):
            pass

    return {
        "hit": len(signals) >= 1,
        "signals": signals,
        "evidence": evidence,
    }


def _vary_includes(resp: Optional[requests.Response], header_name: str) -> bool:
    """Check whether `Vary` explicitly includes the given header."""
    if resp is None:
        return False
    vary = (resp.headers.get("Vary") or "").lower()
    if not vary:
        return False
    if vary.strip() == "*":
        return True
    return header_name.lower() in [v.strip() for v in vary.split(",")]


def _classify_reflection(resp: Optional[requests.Response], needle: str) -> str:
    """
    Where does the needle appear in the response?

    Values:
      html_unescaped    — inside HTML, dangerous chars around needle
      html_attribute    — inside an HTML attribute value
      html_event        — inside an on* handler
      script_src        — inside a <script src="...">
      href_reflection   — inside an <a href="...">
      redirect_location — in the Location response header
      header_value      — in another response header
      json_or_text      — in body but not obviously HTML
      unknown
    """
    if resp is None or not needle:
        return "unknown"

    # Location header
    loc = resp.headers.get("Location", "")
    if needle in loc:
        return "redirect_location"

    # Other headers
    for hname, hval in resp.headers.items():
        if needle in hval and hname.lower() not in ("set-cookie",):
            return "header_value"

    try:
        body = resp.text or ""
    except Exception:
        return "unknown"

    if needle not in body:
        return "unknown"

    # Find the needle position
    idx = body.find(needle)
    window_start = max(0, idx - 60)
    window_end = min(len(body), idx + len(needle) + 60)
    window = body[window_start:window_end]

    # Event handler (onerror=... onload=...)
    if re.search(rf'(?:on[a-z]+)\s*=\s*["\'][^"\']*{re.escape(needle)}', body, re.I):
        return "html_event"

    # Script src
    if re.search(rf'<script[^>]*src\s*=\s*["\'][^"\']*{re.escape(needle)}', body, re.I):
        return "script_src"

    # Anchor href
    if re.search(rf'<a[^>]*href\s*=\s*["\'][^"\']*{re.escape(needle)}', body, re.I):
        return "href_reflection"

    # Inside an attribute value generally
    if re.search(rf'\w+\s*=\s*["\'][^"\']*{re.escape(needle)}', body, re.I):
        return "html_attribute"

    # Unescaped HTML body — presence of raw angle brackets / quotes around it
    if re.search(r'[<>]', window):
        return "html_unescaped"

    # JSON or plain text
    if re.search(r'^\s*[\{\[]', body.lstrip()[:5]):
        return "json_or_text"

    return "json_or_text"


def _reflection_is_exploitable(context: str) -> bool:
    """Return True if the reflection context can lead to XSS or redirect."""
    return context in (
        "html_unescaped", "html_event", "script_src",
        "href_reflection", "redirect_location",
    )


def _has_sensitive_content(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return False
    try:
        body = (resp.text or "")[:100000].lower()
    except Exception:
        return False
    hits = sum(1 for m in SENSITIVE_MARKERS if m in body)
    return hits >= 2


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — CACHE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def detect_cache(
    session: EvasionSession, url: str,
) -> tuple[bool, dict, dict]:
    """
    Determine whether a cache is present and whether it is active.

    Returns (has_cache, headers_seen, evidence).

    Uses three signals:
      • Age progression across 3 requests (1s apart) to the SAME cache-buster
      • MISS→HIT transition on status headers
      • Response-time improvement
    """
    test_url = _with_buster(url)
    ages: list[Optional[int]] = []
    statuses: list[str] = []
    times: list[float] = []
    headers_seen: dict = {}

    for i in range(3):
        t0 = time.monotonic()
        resp = session.get(test_url)
        elapsed = (time.monotonic() - t0) * 1000.0
        if resp is None:
            return False, headers_seen, {}
        if i == 0:
            headers_seen = _extract_cache_headers(resp)
        ages.append(_get_age(resp))
        statuses.append(_get_cache_status(resp))
        times.append(elapsed)
        if i < 2:
            time.sleep(1.0)

    evidence: dict = {
        "ages": ages,
        "statuses": statuses,
        "times_ms": [round(t, 1) for t in times],
    }
    has_cache = False

    # Age progression
    valid_ages = [a for a in ages if a is not None]
    if len(valid_ages) >= 2 and valid_ages[-1] > valid_ages[0]:
        has_cache = True
        evidence["signal"] = "age_progression"

    # Status transition
    if not has_cache and "miss" in statuses and "hit" in statuses:
        if statuses.index("miss") < statuses.index("hit"):
            has_cache = True
            evidence["signal"] = "miss_to_hit"

    # Hit indicator alone
    if not has_cache and any(s == "hit" for s in statuses):
        has_cache = True
        evidence["signal"] = "hit_indicator"

    # Any cache-status header at all — suggests cache present (may MISS)
    if not has_cache and headers_seen:
        has_cache = True
        evidence["signal"] = "cache_headers_present"

    return has_cache, headers_seen, evidence


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — UNKEYED HEADER POISONING
# ═════════════════════════════════════════════════════════════════════════════

def _build_header_payload(header_name: str, marker: str) -> str:
    """Craft a plausible-looking but unique marker for the given header."""
    host_like = ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
                 "X-Original-Host", "X-Proxy-Host")
    path_like = ("X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix",
                 "X-Forwarded-Path")
    if header_name in host_like or header_name == "Forwarded":
        return f"cache-{marker}.example"
    if header_name in path_like:
        return f"/argus-{marker}"
    if header_name == "Forwarded":
        return f"host=cache-{marker}.example"
    if header_name == "X-Forwarded-Scheme":
        return "http"
    if header_name == "X-Forwarded-Proto" or header_name == "X-Forwarded-Protocol":
        return "http"
    if header_name == "X-Forwarded-Port":
        return "8080"
    return f"argus-{marker}"


def test_header_poisoning(
    session: EvasionSession, url: str, auth_on: bool, waf: WAFReport,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for header_name in UNKEYED_HEADER_NAMES:
        marker = _rand_token(10)
        payload = _build_header_payload(header_name, marker)
        test_url = _with_buster(url)

        # Request A — inject header
        t0 = time.monotonic()
        resp_a = session.get(test_url, headers={header_name: payload})
        time_a_ms = (time.monotonic() - t0) * 1000.0
        if resp_a is None:
            continue

        # Must reflect
        if payload not in _body_text(resp_a) and payload not in resp_a.headers.get("Location", ""):
            continue

        # Keyed via Vary? Then not exploitable
        if _vary_includes(resp_a, header_name):
            log.debug("      %s: reflected but keyed (Vary) — skipped", header_name)
            continue

        # Request B — same URL, WITHOUT the header
        time.sleep(CONFIRM_DELAY)
        t0 = time.monotonic()
        resp_b = session.get(test_url)
        time_b_ms = (time.monotonic() - t0) * 1000.0
        if resp_b is None:
            continue

        still_reflected = (
            payload in _body_text(resp_b)
            or payload in resp_b.headers.get("Location", "")
        )
        hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
        context = _classify_reflection(resp_b if still_reflected else resp_a, payload)
        confirmed = still_reflected and hit["hit"]

        if confirmed:
            if _reflection_is_exploitable(context):
                severity = Severity.CRITICAL
                confidence = 95
            else:
                severity = Severity.HIGH
                confidence = 88
        elif still_reflected:
            severity = Severity.MEDIUM
            confidence = 65
        else:
            severity = Severity.MEDIUM
            confidence = 50

        finding = CacheFinding(
            target=url,
            vuln_type=f"header_poisoning_{header_name.lower().replace('-', '_')}",
            category="poisoning",
            severity=severity, confidence=confidence, confirmed=confirmed,
            evidence=(
                f"{header_name}={payload!r} reflected in {context}"
                + (" and persisted across cache-hit request (CONFIRMED)"
                   if confirmed
                   else " (cache-hit not proven)" if still_reflected
                   else " but did not persist")
            ),
            payload=f"{header_name}: {payload}",
            reflection_context=context,
            cache_headers=_extract_cache_headers(resp_b),
            cache_hit_evidence=hit,
            details={
                "header":       header_name,
                "payload":      payload,
                "cache_buster": test_url,
                "still_reflected": still_reflected,
                "body_snippet_a":  _body_snippet(resp_a, 200),
                "body_snippet_b":  _body_snippet(resp_b, 200),
            },
            waf_vendor=waf.vendor,
            auth_enabled=auth_on,
            first_seen=now,
        )
        findings.append(finding)

        # One confirmed poison per URL is enough
        if confirmed:
            break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — HOST HEADER POISONING
# ═════════════════════════════════════════════════════════════════════════════

def test_host_header_poisoning(
    session: EvasionSession, url: str, auth_on: bool, waf: WAFReport,
) -> list[CacheFinding]:
    """
    Classic Host-header cache poisoning — the single most-impactful cache
    attack. Sends a payload Host that the origin echoes back (into absolute
    URLs, redirects, or canonical links) and the cache ignores.
    """
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    parsed = urllib.parse.urlparse(url)
    real_host = parsed.netloc
    marker = _rand_token(10)
    payload_host = f"cache-{marker}.example"

    test_url = _with_buster(url)

    # Request A — malicious Host
    t0 = time.monotonic()
    resp_a = session.get(test_url, headers={"Host": payload_host})
    time_a_ms = (time.monotonic() - t0) * 1000.0
    if resp_a is None:
        return findings

    if payload_host not in _body_text(resp_a) and payload_host not in resp_a.headers.get("Location", ""):
        return findings

    if _vary_includes(resp_a, "Host"):
        return findings

    # Request B — real Host (default)
    time.sleep(CONFIRM_DELAY)
    t0 = time.monotonic()
    resp_b = session.get(test_url)
    time_b_ms = (time.monotonic() - t0) * 1000.0
    if resp_b is None:
        return findings

    still_reflected = (
        payload_host in _body_text(resp_b)
        or payload_host in resp_b.headers.get("Location", "")
    )
    hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
    context = _classify_reflection(resp_b if still_reflected else resp_a, payload_host)
    confirmed = still_reflected and hit["hit"]

    if confirmed:
        severity = Severity.CRITICAL
        confidence = 95
    elif still_reflected:
        severity = Severity.HIGH
        confidence = 75
    else:
        severity = Severity.MEDIUM
        confidence = 55

    findings.append(CacheFinding(
        target=url,
        vuln_type="host_header_poisoning",
        category="poisoning",
        severity=severity, confidence=confidence, confirmed=confirmed,
        evidence=(
            f"Host: {payload_host} reflected in {context}"
            + (" and persisted across cache-hit request (CONFIRMED)"
               if confirmed
               else " (cache-hit not proven)" if still_reflected
               else " but did not persist")
        ),
        payload=f"Host: {payload_host} (real host: {real_host})",
        reflection_context=context,
        cache_headers=_extract_cache_headers(resp_b),
        cache_hit_evidence=hit,
        details={
            "payload_host":     payload_host,
            "real_host":        real_host,
            "cache_buster":     test_url,
            "still_reflected":  still_reflected,
        },
        waf_vendor=waf.vendor,
        auth_enabled=auth_on,
        first_seen=now,
    ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — UNKEYED PARAMETER POISONING
# ═════════════════════════════════════════════════════════════════════════════

def test_unkeyed_param_poisoning(
    session: EvasionSession, url: str, auth_on: bool, waf: WAFReport,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for param in UNKEYED_PARAM_NAMES:
        marker = _rand_token(10)
        payload = f"argus-{marker}"
        buster = _buster()
        test_url = _add_buster_to(
            url, buster,
        )
        # Add param without disturbing buster
        parsed = urllib.parse.urlparse(test_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        test_url_with_param = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(params))
        )

        t0 = time.monotonic()
        resp_a = session.get(test_url_with_param)
        time_a_ms = (time.monotonic() - t0) * 1000.0
        if resp_a is None:
            continue
        if payload not in _body_text(resp_a) and payload not in resp_a.headers.get("Location", ""):
            continue

        # Request B — SAME URL without the param, SAME buster
        time.sleep(CONFIRM_DELAY)
        t0 = time.monotonic()
        resp_b = session.get(test_url)
        time_b_ms = (time.monotonic() - t0) * 1000.0
        if resp_b is None:
            continue

        still_reflected = (
            payload in _body_text(resp_b)
            or payload in resp_b.headers.get("Location", "")
        )
        hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
        context = _classify_reflection(resp_b if still_reflected else resp_a, payload)
        confirmed = still_reflected and hit["hit"]

        if confirmed:
            severity = Severity.CRITICAL if _reflection_is_exploitable(context) else Severity.HIGH
            confidence = 92
        elif still_reflected:
            severity = Severity.MEDIUM
            confidence = 65
        else:
            severity = Severity.MEDIUM
            confidence = 50

        findings.append(CacheFinding(
            target=url,
            vuln_type=f"unkeyed_param_{param}",
            category="poisoning",
            severity=severity, confidence=confidence, confirmed=confirmed,
            evidence=(
                f"unkeyed param {param}={payload!r} reflected in {context}"
                + (" and persisted across cache-hit request (CONFIRMED)"
                   if confirmed else " (cache-hit not proven)")
            ),
            payload=f"{param}={payload}",
            reflection_context=context,
            cache_headers=_extract_cache_headers(resp_b),
            cache_hit_evidence=hit,
            details={"param": param, "payload": payload,
                     "buster": buster, "still_reflected": still_reflected},
            waf_vendor=waf.vendor,
            auth_enabled=auth_on,
            first_seen=now,
        ))
        if confirmed:
            break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — CACHE DECEPTION
# ═════════════════════════════════════════════════════════════════════════════

def test_cache_deception(
    session: EvasionSession, url: str,
    victim_cookie: Optional[str], auth_on: bool, waf: WAFReport,
    aggressive: bool = False,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    max_variants = 40 if aggressive else 20
    tested = 0

    for ext in DECEPTION_EXTENSIONS:
        for delim in DECEPTION_DELIMITERS:
            if tested >= max_variants:
                break
            tested += 1

            buster = _buster()
            test_path = f"{url.rstrip('/')}{delim}{buster[:6]}{ext}"
            parsed = urllib.parse.urlparse(test_path)
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode({"argus_cb": buster}),
            ))

            headers_victim = {"Cookie": victim_cookie} if victim_cookie else {}

            # Request A — with cookie if supplied
            t0 = time.monotonic()
            resp_a = session.get(test_url, headers=headers_victim)
            time_a_ms = (time.monotonic() - t0) * 1000.0
            if resp_a is None or resp_a.status_code != 200:
                continue

            # Request B — anonymous
            time.sleep(CONFIRM_DELAY)
            t0 = time.monotonic()
            resp_b = session.get(test_url)
            time_b_ms = (time.monotonic() - t0) * 1000.0
            if resp_b is None or resp_b.status_code != 200:
                continue

            hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
            sensitive = _has_sensitive_content(resp_a)
            fp_a = _body_fingerprint(resp_a)
            fp_b = _body_fingerprint(resp_b)
            body_match = fp_a and fp_a == fp_b

            # Confirmed deception:
            #  • victim_cookie was supplied (auth vs anon comparison)
            #  • bodies match
            #  • victim response had sensitive markers
            #  • anon response is a cache hit
            if victim_cookie and body_match and sensitive and hit["hit"]:
                findings.append(CacheFinding(
                    target=test_url,
                    vuln_type="cache_deception_confirmed",
                    category="deception",
                    severity=Severity.CRITICAL, confidence=95, confirmed=True,
                    evidence=(
                        f"Authenticated PII served anonymously via '{delim}'+'{ext}' "
                        f"(fingerprint {fp_b}, cache signals: {hit['signals']})"
                    ),
                    payload=test_url,
                    cache_headers=_extract_cache_headers(resp_b),
                    cache_hit_evidence=hit,
                    details={
                        "extension": ext, "delimiter": delim,
                        "victim_snippet": _body_snippet(resp_a, 200),
                        "anon_snippet":   _body_snippet(resp_b, 200),
                        "body_fingerprint": fp_b,
                        "sensitive_detected": True,
                    },
                    chain_ids=["cache-deception-pii"],
                    waf_vendor=waf.vendor,
                    auth_enabled=auth_on,
                    first_seen=now,
                ))
                return findings

            # Victim cookie + body match but no sensitive markers → HIGH
            if victim_cookie and body_match and hit["hit"]:
                findings.append(CacheFinding(
                    target=test_url,
                    vuln_type="cache_deception_confirmed",
                    category="deception",
                    severity=Severity.HIGH, confidence=80, confirmed=True,
                    evidence=f"Auth body served anonymously via '{delim}'+'{ext}'",
                    payload=test_url,
                    cache_headers=_extract_cache_headers(resp_b),
                    cache_hit_evidence=hit,
                    details={"extension": ext, "delimiter": delim,
                             "body_fingerprint": fp_b},
                    chain_ids=["cache-deception-bypass"],
                    waf_vendor=waf.vendor,
                    auth_enabled=auth_on,
                    first_seen=now,
                ))
                return findings

            # No victim cookie → surface candidate only
            if not victim_cookie and hit["hit"]:
                findings.append(CacheFinding(
                    target=test_url,
                    vuln_type="cache_deception_surface",
                    category="deception",
                    severity=Severity.MEDIUM, confidence=50, confirmed=False,
                    evidence=f"Static-extension variant '{delim}'+'{ext}' cached",
                    payload=test_url,
                    cache_headers=_extract_cache_headers(resp_b),
                    cache_hit_evidence=hit,
                    details={"extension": ext, "delimiter": delim,
                             "has_victim_cookie": False},
                    waf_vendor=waf.vendor,
                    auth_enabled=auth_on,
                    first_seen=now,
                ))
                # Keep scanning — one confirmed would be better
                continue

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — PARAMETER CLOAKING + FAT GET (bug-fixed)
# ═════════════════════════════════════════════════════════════════════════════

def test_parameter_cloaking(
    session: EvasionSession, url: str, auth_on: bool, waf: WAFReport,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    parsed = urllib.parse.urlparse(url)
    existing = urllib.parse.parse_qsl(parsed.query)

    # ── Duplicate parameter cloaking ────────────────────────────────────────
    if existing:
        key, orig_val = existing[0]
        marker = _rand_token(10)
        payload = f"argus-{marker}"
        buster = _buster()

        dup_query = (
            f"{key}={urllib.parse.quote(orig_val)}&{key}={urllib.parse.quote(payload)}"
            f"&argus_cb={buster}"
        )
        test_url = urllib.parse.urlunparse(parsed._replace(query=dup_query))

        t0 = time.monotonic()
        resp_a = session.get(test_url)
        time_a_ms = (time.monotonic() - t0) * 1000.0
        if resp_a is not None and (payload in _body_text(resp_a)
                                   or payload in resp_a.headers.get("Location", "")):
            time.sleep(CONFIRM_DELAY)
            t0 = time.monotonic()
            resp_b = session.get(test_url)
            time_b_ms = (time.monotonic() - t0) * 1000.0
            hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
            context = _classify_reflection(resp_a, payload)
            confirmed = hit["hit"]

            sev = Severity.MEDIUM
            if confirmed:
                sev = Severity.HIGH if _reflection_is_exploitable(context) else Severity.MEDIUM

            findings.append(CacheFinding(
                target=url, vuln_type="parameter_cloaking_duplicate",
                category="cloaking", severity=sev,
                confidence=75 if confirmed else 55, confirmed=confirmed,
                evidence=(
                    f"Duplicate param '{key}' payload reflected in {context}"
                    + (" + cache-hit confirmed" if confirmed else "")
                ),
                payload=test_url, reflection_context=context,
                cache_headers=_extract_cache_headers(resp_b),
                cache_hit_evidence=hit,
                details={"param": key, "payload": payload},
                waf_vendor=waf.vendor, auth_enabled=auth_on, first_seen=now,
            ))

    # ── Fat GET (FIXED: reuse same buster) ─────────────────────────────────
    marker = _rand_token(10)
    fat_payload = f"argus_fat_{marker}=reflected_{marker}"
    fat_url = _with_buster(url)

    t0 = time.monotonic()
    resp_a = session.request("GET", fat_url, data=fat_payload)
    time_a_ms = (time.monotonic() - t0) * 1000.0

    if resp_a is not None:
        needle = f"reflected_{marker}"
        if needle in _body_text(resp_a):
            time.sleep(CONFIRM_DELAY)
            t0 = time.monotonic()
            resp_b = session.get(fat_url)  # SAME URL — this is the v2 bug fix
            time_b_ms = (time.monotonic() - t0) * 1000.0

            if resp_b is not None:
                still_reflected = needle in _body_text(resp_b)
                hit = _cache_hit_evidence(resp_a, resp_b, time_a_ms, time_b_ms)
                context = _classify_reflection(resp_a, needle)
                confirmed = still_reflected and hit["hit"]

                if confirmed:
                    sev = Severity.HIGH if _reflection_is_exploitable(context) else Severity.MEDIUM
                elif still_reflected:
                    sev = Severity.MEDIUM
                else:
                    sev = Severity.LOW

                findings.append(CacheFinding(
                    target=url, vuln_type="fat_get_reflection",
                    category="fat_get", severity=sev,
                    confidence=80 if confirmed else 55, confirmed=confirmed,
                    evidence=(
                        "GET-with-body parsed by origin; "
                        + ("cache-hit confirmed" if confirmed
                           else "persistence unconfirmed")
                    ),
                    payload=fat_payload, reflection_context=context,
                    cache_headers=_extract_cache_headers(resp_b),
                    cache_hit_evidence=hit,
                    details={"still_reflected": still_reflected,
                             "cache_buster": fat_url},
                    waf_vendor=waf.vendor, auth_enabled=auth_on, first_seen=now,
                ))

    # ── HTTP method override ───────────────────────────────────────────────
    for hdr_name, hdr_value in (
        ("X-HTTP-Method-Override", "POST"),
        ("X-Method-Override", "POST"),
    ):
        resp = session.get(_with_buster(url), headers={hdr_name: hdr_value})
        if resp and resp.status_code in (200, 201, 202):
            findings.append(CacheFinding(
                target=url,
                vuln_type=f"method_override_{hdr_name.lower().replace('-', '_')}",
                category="method_override",
                severity=Severity.LOW, confidence=40, confirmed=False,
                evidence=f"{hdr_name}: {hdr_value} accepted by origin",
                payload=f"{hdr_name}: {hdr_value}",
                details={"status": resp.status_code},
                waf_vendor=waf.vendor, auth_enabled=auth_on, first_seen=now,
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — CACHE-KEY NORMALIZATION GAPS
# ═════════════════════════════════════════════════════════════════════════════

def test_normalization_gaps(
    session: EvasionSession, url: str, auth_on: bool, waf: WAFReport,
) -> list[CacheFinding]:
    findings: list[CacheFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    parsed = urllib.parse.urlparse(url)
    if not parsed.path or parsed.path == "/":
        return findings

    def _check_variant(test_path: str, label: str, sev: Severity) -> None:
        buster = _buster()
        test_url = urllib.parse.urlunparse(parsed._replace(
            path=test_path,
            query=urllib.parse.urlencode({"argus_cb": buster}),
        ))
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            findings.append(CacheFinding(
                target=url, vuln_type=f"normalization_{label}",
                category="normalization", severity=sev,
                confidence=45, confirmed=False,
                evidence=f"Variant '{label}' resolves (HTTP 200)",
                payload=test_url,
                details={"variant": test_path},
                waf_vendor=waf.vendor, auth_enabled=auth_on, first_seen=now,
            ))

    if not parsed.path.endswith("/"):
        _check_variant(parsed.path + "/", "trailing_slash", Severity.LOW)

    if not parsed.path.endswith("/"):
        _check_variant(f"{parsed.path};argus={_rand_token(6)}",
                       "path_param", Severity.MEDIUM)

    lower = parsed.path.lower()
    if lower != parsed.path:
        _check_variant(lower, "case", Severity.LOW)

    encoded = (
        f"{parsed.path.rstrip('/')}/..%2f"
        f"{parsed.path.strip('/').split('/')[-1]}"
    )
    _check_variant(encoded, "encoded_traversal", Severity.MEDIUM)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def _chain_id_for(f: CacheFinding) -> list[str]:
    if not f.confirmed:
        return []
    ids: list[str] = []
    if f.category == "poisoning":
        if f.reflection_context in ("html_unescaped", "html_event",
                                    "script_src", "html_attribute"):
            ids.append("cache-poison-xss")
        if f.reflection_context in ("redirect_location", "href_reflection"):
            ids.append("cache-poison-redirect")
        if f.vuln_type == "host_header_poisoning":
            ids.append("cache-poison-host")
    if f.category == "deception":
        if "pii" in f.vuln_type or any(
            m in (f.details.get("victim_snippet", "") or "").lower()
            for m in SENSITIVE_MARKERS
        ):
            ids.append("cache-deception-pii")
        else:
            ids.append("cache-deception-bypass")
    return ids


def build_chains(findings: list[CacheFinding]) -> list[CacheChain]:
    chains: dict[str, list[CacheFinding]] = {}
    NAMES = {
        "cache-poison-xss":      "Cache poisoning → stored XSS",
        "cache-poison-redirect": "Cache poisoning → open redirect",
        "cache-poison-host":     "Host-header cache poisoning",
        "cache-deception-pii":   "Cache deception → PII exposure",
        "cache-deception-bypass":"Cache deception → auth bypass",
    }
    for f in findings:
        for cid in f.chain_ids or _chain_id_for(f):
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
            chains.setdefault(cid, []).append(f)

    out: list[CacheChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(CacheChain(
            chain_id=cid,
            name=NAMES.get(cid, cid),
            severity=max_sev,
            steps=[f.evidence for f in fs],
            finding_hashes=[f.finding_hash for f in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[CacheFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    try:
        result = DB.upsert_cache_findings(scan_id, [f.to_dict() for f in findings])
        if result is not None:
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
    test_host_poisoning: bool = True,
    test_param_poisoning: bool = True,
    test_deception: bool = True,
    test_cloaking: bool = True,
    test_normalization: bool = True,
    aggressive: bool = False,
    proxies: Optional[list[str]] = None,
    max_urls: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _cache_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
    eff_jitter = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

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
    log.info(f"  Config : rate_limit={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    if victim_cookie:
        log.info("  Auth   : victim cookie supplied (deception confirmation enabled)")
    elif auth_on:
        log.info("  Auth   : request.txt session")
    else:
        log.info("  Auth   : disabled")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, live_urls_file, start)

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )

    all_findings: list[CacheFinding] = []
    waf_by_host: dict[str, WAFReport] = {}
    cache_profiles: list[dict] = []

    with EvasionSession(profile=profile, timeout=eff_timeout) as session:
        # ── WAF + cache detection ───────────────────────────────────────────
        log.info("  Phase 1 — WAF + cache detection")
        seen_hosts: set[str] = set()
        for url in urls:
            host = urllib.parse.urlparse(url).hostname or ""
            if host in seen_hosts:
                continue
            seen_hosts.add(host)

            waf = detect_waf(session, url)
            waf_by_host[host] = waf
            if waf.vendor != "unknown":
                log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

            has_cache, headers_seen, evidence = detect_cache(session, url)
            cache_profiles.append({
                "host": host, "sample_url": url,
                "has_cache": has_cache,
                "cache_headers": headers_seen,
                "evidence": evidence,
            })
            status = "CACHED" if has_cache else "no cache"
            log.info(f"    {host:<40} {status} ({len(headers_seen)} cache header(s))")

        # Adapt pacing if WAF seen
        if any(w.vendor != "unknown" for w in waf_by_host.values()):
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 1.0)

        # ── Per-URL testing ─────────────────────────────────────────────────
        log.info("")
        log.info(f"  Phases 2–7 — Testing {len(urls)} URL(s) for cache attacks...")

        def _process(url: str) -> list[CacheFinding]:
            host = urllib.parse.urlparse(url).hostname or ""
            waf = waf_by_host.get(host, WAFReport())
            local: list[CacheFinding] = []
            try:
                if test_poisoning:
                    local.extend(test_header_poisoning(session, url, auth_on, waf))
                if test_host_poisoning:
                    local.extend(test_host_header_poisoning(session, url, auth_on, waf))
                if test_param_poisoning:
                    local.extend(test_unkeyed_param_poisoning(session, url, auth_on, waf))
                if test_deception:
                    local.extend(test_cache_deception(
                        session, url, victim_cookie, auth_on, waf, aggressive,
                    ))
                if test_cloaking:
                    local.extend(test_parameter_cloaking(session, url, auth_on, waf))
                if test_normalization:
                    local.extend(test_normalization_gaps(session, url, auth_on, waf))
            except Exception as e:
                log.debug(f"  error on {url}: {e}")
            return local

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

    # ── Chains ─────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Phase 8 — Chain aggregation")
    chains = build_chains(all_findings)
    log.info(f"    {len(chains)} chain(s) confirmed")

    # ── Dedupe ─────────────────────────────────────────────────────────────
    seen_keys: set[tuple] = set()
    deduped: list[CacheFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.target))

    # ── Reports ────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_cat: dict[str, int] = {}
    by_type: dict[str, int] = {}
    confirmed_count = 0
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        if f.confirmed:
            confirmed_count += 1

    json_path = outdir / "cache_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "victim_cookie_supplied": victim_cookie is not None,
        "aggressive": aggressive,
        "config": {
            "rate_limit":  eff_rate,
            "jitter":      eff_jitter,
            "concurrency": eff_conc,
            "timeout":     eff_timeout,
            "proxies":     len(eff_proxies),
        },
        "cache_profiles": cache_profiles,
        "totals": {
            "urls_scanned":   len(urls),
            "hosts_with_cache": sum(1 for p in cache_profiles if p["has_cache"]),
            "total_findings": len(deduped),
            "confirmed":      confirmed_count,
            "critical":       by_sev["CRITICAL"],
            "high":           by_sev["HIGH"],
            "medium":         by_sev["MEDIUM"],
            "low":            by_sev["LOW"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── cache_confirmed.json — HIGH+ only ──────────────────────────────────
    confirmed_findings = [
        f for f in deduped
        if f.severity.rank >= Severity.HIGH.rank
    ]
    (outdir / "cache_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(live_urls_file),
            "totals": {
                "confirmed": len(confirmed_findings),
                "critical":  sum(1 for f in confirmed_findings if f.severity == Severity.CRITICAL),
                "high":      sum(1 for f in confirmed_findings if f.severity == Severity.HIGH),
                "by_category": {
                    c: sum(1 for f in confirmed_findings if f.category == c)
                    for c in {f.category for f in confirmed_findings}
                },
                "by_chain": {
                    c: sum(1 for f in confirmed_findings if c in f.chain_ids)
                    for c in {cid for f in confirmed_findings for cid in f.chain_ids}
                },
            },
            "findings": [f.to_dict() for f in confirmed_findings],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # ── cache_chains.json ──────────────────────────────────────────────────
    (outdir / "cache_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # ── Flat files ─────────────────────────────────────────────────────────
    (outdir / "cache_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.category}\t{f.severity.value}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t"
            f"{f.evidence[:160]}"
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

    # ── DB sync ────────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    cache_findings.json          {len(deduped):>5} finding(s)")
    log.info(f"    cache_confirmed.json         {len(confirmed_findings):>5} confirmed (HIGH+)")
    log.info(f"    cache_chains.json            {len(chains):>5} chain(s)")
    log.info(f"    cache_candidates.txt         {len(deduped):>5} candidate(s)")
    log.info(f"    cache_poisoning.txt          "
             f"{sum(1 for f in deduped if f.category == 'poisoning'):>5} poisoning")
    log.info(f"    cache_deception.txt          "
             f"{sum(1 for f in deduped if f.category == 'deception'):>5} deception")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}")
    log.info(f"  Confirmed: {confirmed_count} / {len(deduped)}")
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains
        ))
    if confirmed_findings:
        log.info("")
        log.info("  Confirmed findings (HIGH+):")
        for f in confirmed_findings[:12]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.vuln_type:<36} "
                     f"{f.target[:55]}{tag}")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "cache_profiles": [],
        "totals": {"urls_scanned": 0, "hosts_with_cache": 0,
                   "total_findings": 0, "confirmed": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0},
        "summary": {"by_severity": {}, "by_category": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "cache_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "cache_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0,
                   "by_category": {}, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "cache_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chains": [],
    }, indent=2) + "\n")
    for name in ("cache_candidates.txt", "cache_poisoning.txt", "cache_deception.txt"):
        (outdir / name).write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
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

    parser = argparse.ArgumentParser(description="Argus Cache Auditor v3")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--cookie", help="Victim session cookie for deception confirmation")
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--proxies", default=None, help="Comma-separated proxy URLs")
    parser.add_argument("--max-urls", type=int, default=None)
    parser.add_argument("--aggressive", action="store_true",
                        help="Enable extended deception tests")
    parser.add_argument("--no-poisoning", action="store_true")
    parser.add_argument("--no-host-poisoning", action="store_true")
    parser.add_argument("--no-param-poisoning", action="store_true")
    parser.add_argument("--no-deception", action="store_true")
    parser.add_argument("--no-cloaking", action="store_true")
    parser.add_argument("--no-normalization", action="store_true")
    args = parser.parse_args()

    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_cache_audit(
            args.input, args.output,
            victim_cookie=args.cookie,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            proxies=proxies,
            max_urls=args.max_urls,
            test_poisoning=not args.no_poisoning,
            test_host_poisoning=not args.no_host_poisoning,
            test_param_poisoning=not args.no_param_poisoning,
            test_deception=not args.no_deception,
            test_cloaking=not args.no_cloaking,
            test_normalization=not args.no_normalization,
            aggressive=args.aggressive,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback
        log.debug(traceback.format_exc())
        sys.exit(1)
