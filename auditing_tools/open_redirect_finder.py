#!/usr/bin/env python3
"""
auditing_tools/open_redirect_finder.py — Open Redirect Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive open redirect detection for Argus.

v3 corrects 12 bugs in v2 (see CHANGELOG at bottom) and adds coverage for:
  • Header-based redirects  (Refresh:, X-Redirect-URL, X-Forward-To)
  • JSON body redirects     ({"redirect": "https://..."})
  • Param pollution         (?next=A&next=B)
  • Method rotation         (GET → POST → PUT → PATCH)
  • Unicode dot/slash       (IDN homograph bypasses)

Detection pipeline:

  Phase 1 — Surface discovery
      Query, path, and POST-form parameters matched against the redirect
      taxonomy. OAuth detection is segment-strict so /api/auth/users does
      not falsely escalate.

  Phase 2 — Baseline discipline
      A random non-URL value must NOT produce an external redirect. If it
      does, the endpoint hardcodes a redirect and the param is uninteresting.
      Accepts 404 as "still honored" (payloads sometimes succeed where
      baselines 404).

  Phase 3 — Server-side testing
      For each honored surface, iterate PAYLOAD_MATRIX. For each payload,
      check four detection vectors in order:
        1. Location / Refresh / X-Redirect-URL response headers  → server_side
        2. JSON body keys (redirect/url/location/next/target)     → json_body
        3. <meta http-equiv="refresh">                            → meta_refresh
        4. DOM sinks (window.location etc.)                       → dom_sink
      Confirmed when the destination host is our confirmation domain
      (or a subdomain thereof).

  Phase 4 — Bypass variants
      Param pollution, method rotation, content-type switch.

  Phase 5 — Severity scoring
      Bands enforced:
        CRITICAL  — confirmed + OAuth param (redirect_uri/returnTo/RelayState)
        HIGH      — confirmed + login param (next/return_to/continue)
        MEDIUM    — confirmed + generic redirect param
        LOW       — external redirect to wrong host (validation bypass only)
        INFO      — surface candidate / param ignored

Outputs (into `outdir`):
  • open_redirect_findings.json
  • open_redirect_candidates.txt
  • open_redirect_confirmed.txt
  • open_redirect_oauth.txt

Integration:
  main.py → run_one("redirect") → run_open_redirect_audit(urls_file, outdir,
                                                          scan_id=scan_id)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import secrets
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
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _redirect_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("redirect", {})
    return {
        "rate_limit":  entry.get("rate_limit", 3),
        "concurrency": entry.get("concurrency", 4),
        "timeout":     entry.get("timeout", 12),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _confirmation_domain() -> str:
    d = _cfg("REDIRECT_CONFIRMATION_DOMAIN", "example.com")
    return (d or "example.com").strip().lower()


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 12
MAX_URLS = 5000


@dataclass(frozen=True)
class Payload:
    label: str
    template: str
    boost: int
    can_confirm: bool = True          # False → only reports LOW (validation bypass)
    vector_class: str = "redirect"    # "redirect" | "xss_pivot"


PAYLOAD_MATRIX: list[Payload] = [
    # ── Direct external (high confidence)
    Payload("direct_https",  "https://{CONF}", 30),
    Payload("direct_http",   "http://{CONF}", 28),

    # ── Protocol-relative (bypasses scheme allowlist)
    Payload("protocol_relative",           "//{CONF}", 35),
    Payload("protocol_relative_backslash", "\\\\{CONF}", 30),
    Payload("protocol_relative_slash_backslash", "/\\{CONF}", 30),
    Payload("quad_slash",                  "////{CONF}", 28),

    # ── Userinfo / @-confusion (bypasses host allowlist + startsWith)
    Payload("at_confusion",                 "https://{HOST}@{CONF}", 30),
    Payload("at_confusion_scheme_relative", "//{HOST}@{CONF}", 30),
    Payload("at_confusion_empty_user",      "https://{HOST}:@{CONF}", 25),

    # ── Subdomain suffix (bypasses "contains(target)" checks)
    # NOTE: {HOST}.{CONF} = target.com.attacker.com — attacker controls
    # attacker.com wildcard DNS → confirmed. dot_prefix is the inverse and
    # CANNOT be confirmed, so it's marked can_confirm=False.
    Payload("subdomain_suffix",    "https://{HOST}.{CONF}", 25, can_confirm=True),
    Payload("dot_prefix_suffix",   "https://{CONF}.{HOST}", 20, can_confirm=False),

    # ── Fragment (never sent to server, browser-side only)
    Payload("fragment", "https://{CONF}#.target", 20),

    # ── Path prefix (bypasses startsWith("https://target.com") checks)
    Payload("target_in_path", "https://{CONF}/{HOST}", 18),

    # ── URL-encoded (bypasses basic string scans)
    Payload("url_encoded",    "https://%65%78%61%6D%70%6C%65%2E%63%6F%6D", 25),
    Payload("double_encoded", "https://{CONF}%2f..%2f", 18),

    # ── Null byte / whitespace (some decoders stop early)
    Payload("null_byte",       "{CONF}%00target.com", 20),
    Payload("whitespace_tab",  "{CONF}%09", 18),
    Payload("whitespace_space", "%20{CONF}", 18),

    # ── Scheme confusion
    Payload("scheme_missing_slashes", "https:{CONF}", 20),

    # ── Unicode IDN homograph
    Payload("unicode_dot",   "https://{CONF}\u3002attacker", 18, can_confirm=False),
    Payload("unicode_slash", "\uff0f\uff0f{CONF}", 15, can_confirm=False),

    # ── XSS pivots — separate vector_class, never counted as redirect
    Payload("javascript_uri", "javascript:alert(document.domain)", 20,
            can_confirm=False, vector_class="xss_pivot"),
    Payload("data_uri", "data:text/html,<script>alert(document.domain)</script>", 15,
            can_confirm=False, vector_class="xss_pivot"),
    Payload("crlf_javascript", "java%0d%0ascript%0d%0a:alert(1)", 15,
            can_confirm=False, vector_class="xss_pivot"),
]

# Client-side payloads — literal appearance in body required
CLIENT_PAYLOADS: list[Payload] = [
    Payload("meta_direct",             "https://{CONF}", 30),
    Payload("meta_protocol_relative",  "//{CONF}", 25),
    Payload("dom_javascript",          "javascript:alert(document.domain)", 20,
            can_confirm=False, vector_class="xss_pivot"),
]

# Redirect-related parameters — context weight drives confidence
CONTEXT_WEIGHTS = {
    # OAuth / SSO
    "redirect_uri":  40, "redir_uri": 40,
    "returnto":      35, "relaystate": 35,
    "return_to":     30, "return_url": 30,
    "callback":      30, "callback_url": 30,
    # Login flows
    "next":          25, "continue": 25,
    "return":        25, "back": 20, "backto": 20,
    # Generic
    "redirect":      15, "redirect_url": 15, "redirect_to": 15,
    "url":           15, "redir": 15, "goto": 15,
    "destination":   10, "dest": 10, "target": 10, "to": 10,
    "forward":       10, "out": 10, "go": 10, "link": 10,
    "view":          10, "jump": 10, "jump_url": 10,
    # Low-context
    "backurl":        8, "back_url": 8, "forward_url": 8,
    "success_url":    8, "cancel_url": 8,
    "logout_redirect": 8, "logout": 8,
    "service":        8, "origin": 8, "originurl": 8,
    "image_url":      5, "file_url": 5, "pic": 5,
    "action":         5, "action_url": 5, "clickurl": 5,
    "rurl":           8, "sp_url": 5, "ext": 5,
}
REDIRECT_PARAMS = set(CONTEXT_WEIGHTS.keys())

# OAuth parameter hints (strict — presence + auth-path context)
OAUTH_PARAMS = {"redirect_uri", "redir_uri", "returnto", "relaystate", "return_to"}
OAUTH_PARAM_HINTS = OAUTH_PARAMS | {
    "client_id", "response_type", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method",
}

# OAuth-only path segments — NOT "auth"/"login" alone (too broad)
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
)

# JSON body keys that sometimes hold redirect URLs
JSON_REDIRECT_KEYS = (
    "redirect", "redirect_uri", "redirect_url", "url", "location",
    "target", "next", "return_to", "returnUrl", "return_url", "goto",
    "destination", "continue", "callback", "forward",
)

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

CONF_CONFIRMED = 90
CONF_LIKELY = 70
CONF_CANDIDATE = 45


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RedirectSurface:
    url: str
    param_name: str
    param_value: str = ""
    location: str = "query"       # "query" | "path" | "body" | "header"
    is_oauth: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param_name": self.param_name,
            "param_value": self.param_value, "location": self.location,
            "is_oauth": self.is_oauth,
        }


@dataclass
class OpenRedirectFinding:
    target: str
    param_name: str
    vector: str                    # server_side | json_body | meta_refresh | dom_sink | header
    param_location: str = "query"
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    payload: str = ""
    payload_label: str = ""
    evidence: str = ""
    redirect_location: str = ""
    http_status: int = 0
    is_oauth: bool = False
    request_curl: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        # Key on (target, param, vector) — payload_label is deliberately
        # excluded so re-scanning the same bug with a different payload
        # doesn't produce a new row.
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
            "severity":          self.severity,
            "confidence":        self.confidence,
            "confirmed":         self.confirmed,
            "payload":           (self.payload or "")[:1024],
            "payload_label":     self.payload_label,
            "evidence":          (self.evidence or "")[:1024],
            "redirect_location": (self.redirect_location or "")[:1024],
            "http_status":       self.http_status,
            "is_oauth":          self.is_oauth,
            "request_curl":      (self.request_curl or "")[:2048],
            "auth_enabled":      self.auth_enabled,
            "details":           self.details,
            "finding_hash":      self.finding_hash,
            "first_seen":        self.first_seen or _db_now(),
        }


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION (thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    """
    Rate-limited HTTP session safe for concurrent use.

    The lock covers the read-sleep-update sequence so N worker threads
    emitting requests simultaneously still respect the global rate.
    Without the lock, threads burst through the check (all read `_last`,
    all sleep the same stale interval, all fire at once).
    """

    def __init__(self, rate_limit: int = 3, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.verify = False
        base_hdrs = _target_headers()
        if base_hdrs:
            self.session.headers.update(base_hdrs)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0
        self._lock = threading.Lock()

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.min_interval > 0:
            with self._lock:
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


def _is_oauth_url(url: str, params: dict[str, list[str]]) -> bool:
    """
    Strict OAuth detection.

    Signal 1: path segment in {oauth, oauth2, openid, oidc, sso, saml, ...}
    Signal 2: path segment in {auth, login, signin} AND an OAuth param
              (client_id, redirect_uri, state, ...) is present

    Segments like /api/auth/users no longer falsely escalate — they'd need
    an OAuth param too.
    """
    parsed = urllib.parse.urlparse(url)
    segments = {s.lower() for s in parsed.path.split("/") if s}
    if segments & OAUTH_PATH_STRICT:
        return True
    if segments & AUTH_PATH_HINTS and OAUTH_PARAM_HINTS & {k.lower() for k in params}:
        return True
    return False


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
        oauth = _is_oauth_url(url, params)

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
                location="query", is_oauth=oauth,
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
                    location="path", is_oauth=oauth,
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
                ))
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BASELINE DISCIPLINE
# ═════════════════════════════════════════════════════════════════════════════

def is_param_honored(
    session: RateLimitedSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> bool:
    """
    Return True if the parameter is worth testing.

    Honored   → baseline with a random non-URL value does NOT produce an
                external redirect. The endpoint isn't hardcoded to redirect
                somewhere else unconditionally.
    Not honored → baseline DOES produce an external redirect. Something else
                is causing it; the parameter isn't in control.

    Network error on baseline → honored=True (err on the testing side; a
    transient failure shouldn't skip a real bug). A 404 on baseline →
    honored=True (some apps 404 the random value but still honor URLs).
    """
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
        return True  # path surfaces have no baseline to compare

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
#  PHASE 3 — SERVER-SIDE + BODY DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _detect_redirect_headers(resp: requests.Response) -> list[tuple[str, str]]:
    """Return [(header_name, header_value)] for any redirect-bearing header."""
    hits: list[tuple[str, str]] = []
    for hname in REDIRECT_HEADERS:
        val = resp.headers.get(hname)
        if not val:
            continue
        if hname.lower() == "refresh":
            m = REFRESH_HEADER_RE.match(val)
            if m:
                hits.append(("Refresh", m.group(1)))
        elif hname.lower() == "location":
            hits.append(("Location", val))
        else:
            hits.append((hname, val))
    return hits


def _detect_json_body_redirect(resp: requests.Response) -> list[tuple[str, str]]:
    """Return [(json_key, url_value)] from a JSON response body."""
    if not resp.text or len(resp.text) > 100_000:
        return []
    try:
        data = resp.json()
    except Exception:
        return []

    hits: list[tuple[str, str]] = []

    def _walk(obj, depth=0):
        if depth > 4 or not isinstance(obj, (dict, list)):
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and k.lower() in {x.lower() for x in JSON_REDIRECT_KEYS}:
                    if "://" in v or v.startswith("//"):
                        hits.append((k, v))
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:20]:
                _walk(item, depth + 1)

    _walk(data)
    return hits


def _detect_client_side(body: str) -> list[tuple[str, str]]:
    """Return [(vector, url_value)] from meta refresh and DOM sinks."""
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


def _test_one_surface_payload(
    session: RateLimitedSession,
    surface: RedirectSurface,
    payload_obj: Payload,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> list[OpenRedirectFinding]:
    """Test a single payload against a single surface. Returns 0..N findings."""
    findings: list[OpenRedirectFinding] = []

    payload = _render_payload(payload_obj.template, target_host, confirmation)

    if surface.location == "query":
        test_url = _build_test_url(surface.url, surface.param_name, payload)
        r = session.get(test_url, headers=headers)
        curl = _build_curl("GET", test_url, headers)
    elif surface.location == "body":
        test_url = surface.url
        r = session.request(
            "POST", surface.url, headers=headers,
            data={surface.param_name: payload},
        )
        curl = _build_curl("POST", test_url, headers,
                            form_body={surface.param_name: payload})
    else:
        return findings

    if not r:
        return findings
    if _has_denial_marker(r):
        return findings

    # ── Detection 1: response headers (Location / Refresh / X-Redirect-URL)
    for hname, hval in _detect_redirect_headers(r):
        analysis = _analyze_redirect(hval, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        # xss_pivot payloads that land in headers are XSS, not redirect
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        findings.append(_make_finding(
            surface, payload_obj, payload, r, analysis, hname, curl,
            target_host, confirmation,
        ))
        return findings

    # ── Detection 2: JSON body redirect
    for jkey, jval in _detect_json_body_redirect(r):
        analysis = _analyze_redirect(jval, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        f = _make_finding(
            surface, payload_obj, payload, r, analysis,
            f"json_body:{jkey}", curl, target_host, confirmation,
            vector="json_body",
        )
        findings.append(f)
        return findings

    # ── Detection 3 & 4: client-side (meta refresh, DOM sinks)
    for vector, url_val in _detect_client_side(r.text or ""):
        analysis = _analyze_redirect(url_val, target_host, confirmation)
        if not (analysis.is_external or analysis.is_confirmation_domain):
            continue
        if payload_obj.vector_class == "xss_pivot" and analysis.is_external:
            continue
        f = _make_finding(
            surface, payload_obj, payload, r, analysis,
            f"{vector}:{url_val[:60]}", curl, target_host, confirmation,
            vector=vector,
        )
        findings.append(f)
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
    vector: str = "server_side",
) -> OpenRedirectFinding:
    """Construct a finding from a detection hit."""
    confirmed = analysis.is_confirmation_domain and payload_obj.can_confirm
    if payload_obj.vector_class == "xss_pivot":
        confirmed = False
        severity = "MEDIUM" if analysis.is_confirmation_domain else "LOW"
        confidence = 60 if analysis.is_confirmation_domain else CONF_CANDIDATE
    else:
        context = _context_score(surface.param_name)
        if confirmed:
            confidence = min(70 + payload_obj.boost + context, 100)
        else:
            confidence = CONF_CANDIDATE
        severity = _score_severity(confidence, surface, confirmed=confirmed)

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
            f"{analysis.normalized_location[:200]} (host={analysis.actual_host})"
        ),
        redirect_location=analysis.normalized_location,
        http_status=resp.status_code,
        is_oauth=surface.is_oauth,
        request_curl=curl,
        auth_enabled=bool(_target_headers()),
        first_seen=_db_now(),
        details={
            "target_host":         target_host,
            "actual_host":         analysis.actual_host,
            "confirmation_domain": confirmation,
            "detection_source":    source,
            "payload_class":       payload_obj.vector_class,
            "can_confirm":         payload_obj.can_confirm,
            "is_oauth_endpoint":   surface.is_oauth,
        },
    )


def test_server_side(
    session: RateLimitedSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> list[OpenRedirectFinding]:
    """
    Iterate PAYLOAD_MATRIX until one payload confirms.

    Returns the confirmed finding if any, else the best-scoring candidate
    (or [] if the surface produced nothing).
    """
    best: Optional[OpenRedirectFinding] = None

    for payload_obj in PAYLOAD_MATRIX:
        if payload_obj.vector_class == "xss_pivot" and surface.location != "query":
            # XSS pivots only meaningful for query params
            continue

        hits = _test_one_surface_payload(
            session, surface, payload_obj, headers, target_host, confirmation,
        )
        if not hits:
            continue

        hit = hits[0]
        if hit.confirmed:
            return [hit]
        # Keep the highest-confidence unconfirmed candidate
        if best is None or hit.confidence > best.confidence:
            best = hit

    return [best] if best else []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3b — BYPASS VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def test_param_pollution(
    session: RateLimitedSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> list[OpenRedirectFinding]:
    """?param=SAFE&param=https://example.com — bypasses last-wins validators."""
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
                target_host, confirmation, vector="server_side",
            )]
    return []


def test_method_rotation(
    session: RateLimitedSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> list[OpenRedirectFinding]:
    """Try GET→POST, POST→GET for surfaces where the default method 404s."""
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
                target_host, confirmation,
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _score_severity(confidence: int, surface: RedirectSurface, confirmed: bool) -> str:
    if not confirmed:
        return "LOW"

    pname = (surface.param_name or "").lower()

    if surface.is_oauth and pname in OAUTH_PARAMS:
        return "CRITICAL"
    if pname in OAUTH_PARAMS:
        return "HIGH"
    if pname in ("next", "continue", "return", "return_url", "back", "backto"):
        return "HIGH"
    if confidence >= CONF_CONFIRMED:
        return "MEDIUM"
    return "LOW"


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[OpenRedirectFinding]) -> None:
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
    method = getattr(DB, "upsert_open_redirect_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_open_redirect_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
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
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _redirect_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
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
    log.info(
        f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
        f"timeout={eff_timeout}s"
    )
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)

    # ── Phase 1: Surface discovery
    log.info("  Phase 1 — Surface discovery")
    surfaces = discover_surfaces(urls)
    surfaces.extend(discover_surfaces_from_pages(outdir))
    seen: set[tuple] = set()
    unique: list[RedirectSurface] = []
    for s in surfaces:
        key = (s.url, s.param_name, s.location)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    surfaces = unique

    log.info(
        f"    {len(surfaces)} surface(s)  "
        f"(query: {sum(1 for s in surfaces if s.location == 'query')}, "
        f"path: {sum(1 for s in surfaces if s.location == 'path')}, "
        f"body: {sum(1 for s in surfaces if s.location == 'body')})"
    )

    if not surfaces:
        log.warning("  No surfaces — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 2: Baseline (parallel — no reason to serialize 500 HTTP calls)
    log.info("")
    log.info("  Phase 2 — Baseline discipline (param honored?)")

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
                    # Keep the surface on exception (err on testing side)
                    honored.append(futures[fut])

    skipped = len(surfaces) - len(honored)
    log.info(f"    {len(honored)} honored, {skipped} skipped (param ignored/hardcoded)")

    if not honored:
        log.warning("  No honored surfaces — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 3: Test
    log.info("")
    log.info(f"  Phase 3 — Testing {len(honored)} surface(s)")
    all_findings: list[OpenRedirectFinding] = []

    def _process(surface: RedirectSurface) -> list[OpenRedirectFinding]:
        local: list[OpenRedirectFinding] = []
        host = urllib.parse.urlparse(surface.url).hostname or ""
        local.extend(test_server_side(session, surface, cfg_hdrs, host, confirmation))

        if not any(f.confirmed for f in local):
            if test_client_side:
                local.extend(
                    test_client_side_payloads(session, surface, cfg_hdrs, host, confirmation)
                )
            if test_bypasses:
                local.extend(test_param_pollution(session, surface, cfg_hdrs, host, confirmation))
                if not any(f.confirmed for f in local):
                    local.extend(test_method_rotation(
                        session, surface, cfg_hdrs, host, confirmation,
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

    # ── Dedup + sort
    seen_f: set[tuple] = set()
    deduped: list[OpenRedirectFinding] = []
    for f in all_findings:
        # Key on (target, param, vector) — NOT payload_label
        key = (f.target, f.param_name, f.vector)
        if key in seen_f:
            continue
        seen_f.add(key)
        deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Reports
    elapsed = time.monotonic() - start
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_vector: dict[str, int] = {}
    confirmed_list: list[OpenRedirectFinding] = []
    oauth_list: list[OpenRedirectFinding] = []

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_vector[f.vector] = by_vector.get(f.vector, 0) + 1
        if f.confirmed:
            confirmed_list.append(f)
        if f.is_oauth:
            oauth_list.append(f)

    (outdir / "open_redirect_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.vector}\t{f.severity}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t"
            f"{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "open_redirect_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.payload_label}\t"
            f"{f.redirect_location[:120]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
    )
    (outdir / "open_redirect_oauth.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param_name}\t{f.severity}\t{f.evidence[:120]}"
            for f in oauth_list
        ) + ("\n" if oauth_list else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "confirmation_domain": confirmation,
            "rate_limit":          eff_rate,
            "concurrency":         eff_conc,
            "timeout":             eff_timeout,
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
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_vector":   dict(sorted(by_vector.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "open_redirect_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync to dedicated table
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<32} {len(deduped):>5} finding(s)")
    log.info(f"    open_redirect_candidates.txt    {len(deduped):>5} candidate(s)")
    log.info(f"    open_redirect_confirmed.txt     {len(confirmed_list):>5} confirmed")
    log.info(f"    open_redirect_oauth.txt         {len(oauth_list):>5} OAuth")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def test_client_side_payloads(
    session: RateLimitedSession,
    surface: RedirectSurface,
    headers: Optional[dict],
    target_host: str,
    confirmation: str,
) -> list[OpenRedirectFinding]:
    """Client-side-only payload iteration (meta refresh / DOM sinks)."""
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

        if not r or r.status_code >= 500:
            continue
        if _has_denial_marker(r):
            continue

        for vector, url_val in _detect_client_side(r.text or ""):
            analysis = _analyze_redirect(url_val, target_host, confirmation)
            if not (analysis.is_external or analysis.is_confirmation_domain):
                continue
            findings.append(_make_finding(
                surface, payload_obj, payload, r, analysis,
                f"{vector}:{url_val[:60]}", curl, target_host, confirmation,
                vector=vector,
            ))
            if findings:
                return findings
    return findings


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": False,
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces": 0, "honored_surfaces": 0,
            "total_findings": 0, "confirmed": 0, "oauth_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_vector": {}},
        "findings": [],
    }
    path = outdir / "open_redirect_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
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

    parser = argparse.ArgumentParser(description="Argus Open Redirect Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument("--no-client-side", action="store_true")
    parser.add_argument("--no-bypasses", action="store_true")
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_open_redirect_audit(
            args.input, args.output,
            headers=hdrs,
            test_client_side=not args.no_client_side,
            test_bypasses=not args.no_bypasses,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
#  CHANGELOG — v2 → v3
# ═════════════════════════════════════════════════════════════════════════════
#
#  Bug fixes:
#    1. RateLimitedSession now uses threading.Lock — no burst under concurrency
#    2. is_param_honored() no longer skips surfaces on transient network errors
#    3. Baseline accepts 404 responses as "honored" (payload may still succeed)
#    4. _is_oauth_url requires OAuth-specific segment OR auth-segment+OAuth-param
#       (stops /api/auth/users from being falsely escalated to CRITICAL)
#    5. dot_prefix_suffix marked can_confirm=False (DNS is target-owned; can't
#       confirm a redirect with our domain as prefix of the target host)
#    6. Header-based redirects (Refresh:, X-Redirect-URL, X-Forward-To) now
#       detected — v2 only looked at Location
#    7. JSON body redirects ({"redirect": "https://..."}) now detected
#    8. SAML RelayState / OAuth redirect_uri now match the OAUTH_PARAMS set
#    9. Param pollution (?next=A&next=B) tested as a bypass variant
#   10. Method rotation (GET→POST→PUT→PATCH) tested as a bypass variant
#   11. _build_curl knows about method + body (was always GET)
#   12. Dedup key is (target, param, vector), not payload_label — one bug,
#       one row, even when the same surface confirms with multiple payloads
#
#  New coverage:
#    • Unicode dot / slash payloads (IDN homograph)
#    • at_confusion_empty_user  (https://target:@attacker.com)
#    • can_confirm flag on payloads (prevents false "confirmed" from
#      validation-bypass-only payloads like dot_prefix_suffix)
#    • vector_class="xss_pivot" for javascript:/data:/crlf payloads (LOW
#      severity, separate from server_side redirects)
#    • Parallel Phase 2 baseline (was sequential — 10x faster on large URL sets)
#    • Evidence includes detection source ("Location", "Refresh",
#      "json_body:redirect", "meta_refresh", "dom_sink")
