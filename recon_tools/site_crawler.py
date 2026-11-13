#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
site_crawler.py v9.0 "FJÖLNIR"
Multi-factor auth · cookie persistence · post-auth BFS · WAF origin fallback.
AI-first page triage (config.ai_complete) with full static fallback when
AI_ENABLED is False or unavailable.

Reads config.py: SCOPE, EMAIL, OUTPUT_DIR, AI_ENABLED, BBP_PROGRAM, etc.

v9.0 "FJÖLNIR" changelog:
  · PERF  parallel-host crawl (--parallel-hosts N, default 4) with proper
          thread-safety for shared AI cache, credential store, and streams.
          Rate limit is divided across workers so program caps are honored.
  · FIX   skip empty verification-inbox poll when register response has no
          verify hint AND no session cookie set (was 30s × 7 = 3.5 min in
          the last run against sites that never send verification email).
  · FIX   query-string tracking-param dedupe (`?ND`, `?MA`, `?SA`, `utm_*`,
          `fbclid`, etc.) — 22 junk URLs/run eliminated.
  · FIX   BOM + inline-comment + trailing-dot normalization in _load_targets.
  · NEW   --parallel-hosts, --host-timeout, --quiet.
  · NEW   structured `warnings` array in the report JSON.
  · NEW   SIGINT handler — finish current host batch, write partial report.
  · NEW   on_progress(stage, payload) callback for dashboard integration.
  · NEW   KillSwitch checked per-host and per-page.
  · NEW   per-host wall-clock timeout (--host-timeout, default 1800s).
  · NEW   thread-safe AI cache + AI summary counter (_AI_LOCK).
  · NEW   thread-safe CredentialStore._save() and stream writes (_CREDS_LOCK,
          _STREAM_LOCK).
  · NEW   selftest +6 checks (parallel locks, query strip, BOM, skip-poll).
"""
from __future__ import annotations
import argparse, hashlib, html as html_lib, http.cookiejar, json, logging
import os, random, re, signal, socket, ssl, string, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.cookiejar import Cookie
from pathlib import Path
from typing import Any, Callable, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None
    CFG_LOADED = False

_RUNTIME_CFG_OVERRIDES: dict = {}   # set by CLI flags (--no-ai, --ai-max-pages); overrides config.py

def _cfg(key, default=None):
    if key in _RUNTIME_CFG_OVERRIDES:
        return _RUNTIME_CFG_OVERRIDES[key]
    return getattr(CFG, key, default) if CFG_LOADED else default

class _FallbackPalette:
    _enabled = sys.stdout.isatty()
    _R = {"reset": "\033[0m", "dim": "\033[2m", "gold": "\033[38;5;220m",
          "amber": "\033[38;5;214m", "purple": "\033[38;5;135m",
          "violet": "\033[38;5;93m", "crimson": "\033[38;5;160m",
          "green": "\033[38;5;46m", "cyan": "\033[38;5;51m", "grey": "\033[38;5;242m"}
    @classmethod
    def c(cls, name):
        return cls._R.get(name, "") if cls._enabled else ""

def _c(name):
    if CFG_LOADED and hasattr(CFG, "_c"): return CFG._c(name)
    return _FallbackPalette.c(name)

class _FallbackLogger:
    _L = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}
    def __init__(self): self.min_level = "info"
    def _emit(self, level, msg, color, prefix):
        if self._L.get(level, 20) >= self._L.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")
    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info(self, m):  self._emit("info", m, "cyan", "·")
    def warn(self, m):  self._emit("warn", m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def ok(self, m):    self._emit("info", m, "green", "✓")
    def rune(self, rune, msg):
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")

log = _cfg("log") or _FallbackLogger()

# ── Shared thread-safety primitives (v9.0) ────────────────────────────────
_AI_LOCK     = threading.Lock()   # guards _AI_SUMMARIES and _AI_CACHE
_CREDS_LOCK  = threading.Lock()   # guards CredentialStore._save()
_STREAM_LOCK = threading.Lock()   # guards site_pages_pages/hosts .jsonl appends
_LOG_LOCK    = threading.Lock()   # guards print interleaving across workers
_SHARED = {"_quiet": False}

class Sym:
    WARN = "⚠"; LOCK = "🔒"; WOLF = "🐺"; GEAR = "⚙"; SHAMROCK = "☘"
    LINK = "🔗"; KEY = "🔑"; MAIL = "📧"; FIRE = "🔥"; TROPHY = "🏆"

class Rune:
    RAIDO = "ᚱ"; SOWILO = "ᛊ"; KANO = "ᚲ"

__version__ = "9.0.0"
__codename__ = "FJÖLNIR"

def print_banner():
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"\n    {G}ᛊ ᚲ ᛟ ᛚ ᛚ{R}\n    {P}{rule}{R}")
    print(f"    {V}      S I T E   C R A W L E R   ·   T H E   P U R S U E R{R}")
    print(f"    {V}         F J Ö L N I R   ·   v{__version__}{R}")
    print(f"    {D}{rule}{R}")
    print(f"    {G}        {Sym.WOLF}  \"{__codename__}\"  ·  auth-native · WAF-aware · parallel{R}")
    print(f"    {G}        {Sym.GEAR}  config v{_cfg('__version__', 'missing')} {R}\n")

class Severity(str, Enum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    @property
    def rank(self):
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

# ─── CONSTANTS ────────────────────────────────────────────────────────────
DEFAULT_MAX_PAGES_PER_HOST = 200
DEFAULT_MAX_DEPTH          = 3
DEFAULT_TIMEOUT            = 15.0
DEFAULT_MAX_BODY_BYTES     = 2_000_000
REGISTRATION_TIMEOUT       = 180.0
CIRCUIT_BREAK_THRESHOLD    = 3
CREDS_FILE_NAME            = ".argus_creds.json"
AI_PAGE_SUMMARY_LIMIT      = 15
JS_FETCH_LIMIT             = 10
ENDPOINT_PROBE_LIMIT       = 30
POST_AUTH_CRAWL_LIMIT      = 100
HUMAN_PAUSE_CHANCE         = 0.10
HUMAN_PAUSE_RANGE          = (5.0, 15.0)
PAGE_SKIP_CHANCE           = 0.05
PROTOCOL_PATHS             = ("/robots.txt", "/sitemap.xml")
# v9.0 additions
DEFAULT_PARALLEL_HOSTS     = 4
DEFAULT_HOST_TIMEOUT       = 1800    # 30 min per host
SHORT_POLL_TIMEOUT         = 15.0    # for ambiguous register (was 30)
# Query-string tracking params — stripped before normalize so ?ND, ?MA, ?SA
# from analytics injections don't each become a separate crawled URL.
QUERY_TRACKING_PARAMS = frozenset({
    "nd","ma","sa","na","md","sd",  # your observed noise
    "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
    "fbclid","gclid","msclkid","yclid","dclid","wbraid",
    "mc_cid","mc_eid","_ga","_gl","_hsenc","_hsmi","ref","ref_src","ref_url",
    "spm","scm","share_source","share_medium","share_plat","share_session_id",
})

AUTH_SUCCESS_PATHS = ("dashboard","account","profile","home","me","user",
                      "welcome","my-account","settings","members","admin/","console")
AUTH_LOGIN_PATHS = ("login","signin","sign-in","log-in","auth")
AUTH_VERIFY_PATHS = ("verify","confirm","activate","check-email",
                     "verify-email","confirm-email","email-verification")
AUTH_SUCCESS_BODY = ("welcome, ","welcome back","dashboard","logged in","signed in",
                     "you're in","sign out","log out","logout","my account",
                     "your profile","account settings")
AUTH_VERIFY_BODY = ("check your email","verify your email","verification email",
                    "confirmation email","email sent","verification sent",
                    "check your inbox","click the link","we've sent","we have sent",
                    "confirmation link","verify your account")
AUTH_FAILURE_BODY = ("wrong password","bad credentials","invalid credentials",
                     "invalid password","incorrect password","login failed",
                     "authentication failed","invalid username")
AUTH_EXISTS_BODY = ("already exists","already registered","already taken",
                    "email already","username already","account already")
AUTH_COOKIE_NAMES = (
    "session","sessid","phpsessid","jsessionid","auth","token","jwt",
    "logged_in","loggedin","user_id","userid","authenticated","remember",
    "access_token","refresh_token","connect.sid","laravel_session",
    "django_session","csrftoken","accesstoken","refreshtoken","sessionid",
    "jwttoken","auth_token","authtoken","remember_me","rememberme","signedin","signed_in",
)
PROTECTED_PROBE_PATHS = (
    "/dashboard","/account","/profile","/settings","/me","/user","/admin","/home",
    "/my-account","/orders","/wallet","/messages","/portal","/member","/members",
    "/secure","/private","/console","/user/profile","/user/settings",
    "/account/settings","/settings/profile","/api/me","/api/user","/api/v1/me","/dashboard/home",
)
POST_AUTH_PROBE_PATHS = (
    "/","/dashboard","/account","/profile","/settings","/me","/user","/user/profile",
    "/members","/member","/admin","/home","/my-account","/orders","/wallet","/messages",
    "/portal","/secure","/private","/console","/logout","/signout","/account/settings",
    "/settings/profile","/api/me","/api/user","/api/v1/me","/dashboard/home","/user/settings",
)

WAF_BLOCK_STATUSES = {403,429,503,520,521,522,523,524,525,526,530}
WAF_HEADER_MARKERS = ("cf-mitigated","cf-ray","cf-chl-bypass","cf-cache-status",
                     "x-akamai-bot-manager","x-akamai-transformed","x-iinfo",
                     "x-sucuri-block","x-datadome","x-wa-info","bigipserver")
WAF_BODY_MARKERS = ("attention required! | cloudflare","just a moment...",
                    "checking your browser","please wait while we verify",
                    "ddos-guard","enable javascript and cookies to continue")

LOGIN_PATTERNS = re.compile(r"/(login|signin|sign-in|log-in|authenticate|auth|session|sso|signon)(\.\w+)?(/|$|\?)", re.I)
REGISTER_PATTERNS = re.compile(r"/(register|signup|sign-up|create[-_]?account|join|onboard|registration)(\.\w+)?(/|$|\?)", re.I)
ADMIN_PATTERNS = re.compile(r"/(admin|dashboard|console|management|internal|cp|panel|backoffice)(\.\w+)?(/|$|\?)", re.I)
API_PATTERNS = re.compile(r"/(api|graphql|rest|gql|v\d+)(\.\w+)?(/|$|\?)", re.I)
DEBUG_PATTERNS = re.compile(r"/(debug|actuator|phpinfo|trace|swagger|api-docs|\.env)(\.\w+)?(/|$|\?)", re.I)
STATIC_EXTENSIONS = (".png",".jpg",".jpeg",".gif",".svg",".ico",".webp",
                     ".woff",".woff2",".ttf",".eot",".otf",".mp4",".webm",
                     ".mp3",".wav",".ogg",".pdf",".zip",".tar",".gz",".bz2",
                     ".7z",".rar",".doc",".docx",".xls",".xlsx",".ppt",".pptx",
                     ".exe",".dll",".so",".dylib")
JS_ENDPOINT_RE = re.compile(r"""['"]((?:https?://|//)[A-Za-z0-9_\-./?=&%:{}]+|/[A-Za-z0-9_\-./?=&%:{}]{2,120})['"]""")
JS_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]""")
JS_AJAX_RE  = re.compile(r"""\$\.[a-z]+\s*\(\s*['"]([^'"]+)['"]""")
JS_AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""")
PASSWORD_FIELD_RE = re.compile(r"(password|passwd|pwd|pass)", re.I)
CONFIRM_FIELD_RE  = re.compile(r"(confirm|repeat|verify|retype)", re.I)
EMAIL_FIELD_RE    = re.compile(r"(email|e-mail|mail)", re.I)
USERNAME_FIELD_RE = re.compile(r"(user|login|account|name)", re.I)
CSRF_FIELD_RE     = re.compile(r"(csrf|_token|authenticity|__request|nonce|csrfmiddlewaretoken)", re.I)
CODE_FIELD_RE     = re.compile(r"(code|otp|token|pin|verification)", re.I)
VERIFY_SUBJECTS = ("verify","confirm","activate","welcome","validate",
                   "complete your","finish","account")

SECRET_PATTERNS = {
    "aws_access_key":    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key":    re.compile(r"(?i)aws(.{0,20})?(secret|access)[_-]?key(.{0,3})?[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    "generic_api_key":   re.compile(r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,80}['\"]"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    "jwt":               re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "slack_token":       re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
    "stripe_key":        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    "google_api_key":    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "connection_string": re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s'\"<>]{8,}"),
    "deepseek_key":      re.compile(r"\bsk-[a-f0-9]{32}\b"),
}
SECRET_FALSE_POSITIVE_HINTS = ("your_","example","xxxxxxxx","<","00000000",
                               "changeme","placeholder","sk_test_123")

SQL_ERROR_PATTERNS = re.compile(
    r"(?i)(sql syntax.{0,40}mysql|warning.{0,40}mysqli?_|unclosed quotation mark|"
    r"quoted string not properly terminated|pg_query\(\)|postgresql.{0,30}error|"
    r"sqlite3?\.(?:operationalerror|error)|ora-\d{5}|microsoft ole db provider|"
    r"odbc (?:sql server |)driver|sqlstate\[|you have an error in your sql syntax|"
    r"supplied argument is not a valid mysql)")

STACK_TRACE_PATTERNS = re.compile(
    r"(?i)(traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)\s*\n|"
    r"stack trace:|fatal error:.{0,60}on line \d+|"
    r"exception in thread|\.(?:php|py|rb|java):\d+ in |"
    r"whoops\\|django\.(?:core|db)\.|werkzeug\.exceptions|"
    r"system\.web\.httpexception|unhandled exception)")

DIR_LISTING_PATTERNS = re.compile(r"(?i)(index of /|<title>index of|directory listing for /|parent directory</a>)")
DEBUG_BANNER_PATTERNS = re.compile(
    r"(?i)(debug\s*=\s*true|werkzeug debugger|whoops.{0,10}(?:error|exception)|"
    r"this page is showing an error|django debug|laravel.{0,10}whoops|phpinfo\(\)|xdebug)")
SECURE_COOKIE_NAME_HINTS = ("session","sess","auth","token","jwt","sid","login")

FRAMEWORK_SIGNATURES = {
    "wordpress": (["wp-","x-pingback","wp-json"],["wordpress"],["/wp-content/","/wp-includes/"]),
    "drupal":    (["x-generator: drupal","x-drupal-"],["drupal"],["/sites/default/","drupal.js"]),
    "joomla":    (["x-content-encoded-by: joomla"],["joomla"],["/media/system/js/"]),
    "django":    (["csrftoken","x-django"],[],["csrftoken","csrfmiddlewaretoken"]),
    "rails":     (["x-runtime","x-request-id"],[],["rails","turbolinks","csrf-token"]),
    "laravel":   (["x-powered-by: laravel","laravel_session"],[],["laravel","csrf-token"]),
    "spring":    (["x-application-context","jsessionid"],[],["spring","j_spring"]),
    "express":   (["x-powered-by: express"],[],["express"]),
    "nextjs":    (["x-nextjs"],[],["/_next/","__next_data__"]),
    "nuxt":      (["x-nuxt"],[],["/_nuxt/","__nuxt__"]),
    "react":     ([],["react"],["react-dom","__react"]),
    "vue":       ([],["vue"],["vue.js","__vue__"]),
    "angular":   (["ng-"],["angular"],["angular.min.js","ng-app"]),
    "jquery":    ([],[],["jquery","jquery.min.js"]),
    "bootstrap": ([],[],["bootstrap.css","bootstrap.min.css"]),
    "tailwind":  ([],[],["tailwind"]),
    "graphql":   ([],[],["graphql","/graphiql","__schema","apollo"]),
    "swagger":   ([],[],["swagger-ui","swagger.json"]),
    "cloudflare":(["cf-ray","cloudflare"],[],["cdn-cgi/"]),
}

CHAIN_SEVERITY = {
    "crawl-admin-surface":Severity.HIGH, "crawl-auth-gated":Severity.HIGH,
    "crawl-debug-exposed":Severity.HIGH, "crawl-register-exposed":Severity.MEDIUM,
    "crawl-api-surface":Severity.MEDIUM, "crawl-parameterized-urls":Severity.MEDIUM,
    "crawl-js-endpoints":Severity.MEDIUM, "crawl-upload-form":Severity.HIGH,
    "crawl-external-redirect":Severity.MEDIUM, "crawl-cors-permissive":Severity.MEDIUM,
    "crawl-mass-surface":Severity.LOW, "crawl-authenticated":Severity.HIGH,
    "crawl-waf-fallback":Severity.MEDIUM, "crawl-post-auth-discovery":Severity.HIGH,
    "crawl-secret-exposure":Severity.CRITICAL, "crawl-sql-error":Severity.HIGH,
    "crawl-stack-trace":Severity.MEDIUM, "crawl-dir-listing":Severity.MEDIUM,
    "crawl-debug-banner":Severity.MEDIUM, "crawl-reflected-param":Severity.MEDIUM,
    "crawl-insecure-cookie":Severity.LOW, "crawl-mixed-content":Severity.LOW,
}
CHAIN_NAMES = {
    "crawl-admin-surface":"Admin panel pages", "crawl-auth-gated":"Auth-required pages",
    "crawl-debug-exposed":"Debug/actuator pages", "crawl-register-exposed":"Public registration forms",
    "crawl-api-surface":"API endpoints", "crawl-parameterized-urls":"Pages with query params",
    "crawl-js-endpoints":"Endpoints discovered in JS", "crawl-upload-form":"Forms with file upload",
    "crawl-external-redirect":"Pages redirecting off-host", "crawl-cors-permissive":"Permissive CORS",
    "crawl-mass-surface":"Large surface (>50 pages)", "crawl-authenticated":"Pages accessible after login",
    "crawl-waf-fallback":"Pages fetched via origin", "crawl-post-auth-discovery":"Auth-discovered pages",
    "crawl-secret-exposure":"Secret/credential-shaped strings in response",
    "crawl-sql-error":"SQL error signatures in response",
    "crawl-stack-trace":"Stack trace / unhandled exception disclosed",
    "crawl-dir-listing":"Directory listing exposed",
    "crawl-debug-banner":"Debug mode / debugger banner exposed",
    "crawl-reflected-param":"Query param value reflected in response body",
    "crawl-insecure-cookie":"Auth cookie missing Secure/HttpOnly/SameSite",
    "crawl-mixed-content":"HTTPS page loading HTTP sub-resources",
}

def _measure_host():
    cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024
                        break
    except Exception: pass
    reasons = []
    if cores <= 2: reasons.append(f"{cores} cores")
    if ram_mb and ram_mb < 2048: reasons.append(f"{ram_mb} MB RAM")
    return cores, ram_mb, ", ".join(reasons) if reasons else ""

HOST_CORES, HOST_RAM_MB, LIGHTWEIGHT_REASON = _measure_host()
LIGHTWEIGHT_MODE = bool(LIGHTWEIGHT_REASON) or os.getenv("ARGUS_LIGHTWEIGHT") == "1"

def _effective_limits(max_pages, max_depth):
    if not LIGHTWEIGHT_MODE: return max_pages, max_depth
    return min(max_pages, 75), min(max_depth, 2)

# ─── HELPERS ──────────────────────────────────────────────────────────────
def _safe_filename(s, max_len=80):
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)[:max_len].strip("_") or "root"

def _host_of(url):
    try: return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception: return ""

def _normalize_url(url, base_host):
    """v9.0: strips known tracking params so ?ND, ?MA, ?SA, utm_*, fbclid
    don't each become separate crawled URLs. If the query becomes empty
    after stripping, treats it as no-query so /?ND normalizes to /."""
    if not url: return None
    try: parsed = urllib.parse.urlparse(url)
    except Exception: return None
    if parsed.scheme not in ("http","https"): return None
    if parsed.hostname != base_host: return None
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS): return None
    # Strip tracking params
    clean_query = ""
    if parsed.query:
        try:
            params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            filtered = [(k, v) for k, v in params if k.lower() not in QUERY_TRACKING_PARAMS]
            if filtered:
                clean_query = urllib.parse.urlencode(filtered)
        except Exception:
            clean_query = parsed.query
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(),
                                    parsed.path or "/", "", clean_query, ""))

def _extract_params(url):
    try:
        qs = urllib.parse.urlparse(url).query
        return list(urllib.parse.parse_qs(qs).keys()) if qs else []
    except Exception: return []

def _categorize_error(exc):
    if isinstance(exc, (socket.timeout, TimeoutError)): return "timeout"
    if isinstance(exc, ssl.SSLError): return "ssl"
    if isinstance(exc, socket.gaierror): return "dns"
    if isinstance(exc, ConnectionRefusedError): return "refused"
    if isinstance(exc, ConnectionResetError): return "reset"
    if isinstance(exc, urllib.error.HTTPError): return f"http{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        r = str(exc.reason).lower()
        if "proxy" in r: return "proxy"
        if "dns" in r or "name" in r: return "dns"
        if "refused" in r: return "refused"
        if "timeout" in r: return "timeout"
        if "ssl" in r or "certificate" in r: return "ssl"
        return "url"
    if "proxy" in str(exc).lower(): return "proxy"
    return type(exc).__name__.lower()[:20]

def _text_preview(html, limit=500):
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html or "", flags=re.I|re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I|re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;|&#\d+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]

# ─── STATIC DETECTORS ─────────────────────────────────────────────────────
def _detect_secrets(body):
    if not body: return []
    found = []
    for kind, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(body):
            raw = m.group(0); low = raw.lower()
            if any(h in low for h in SECRET_FALSE_POSITIVE_HINTS): continue
            redacted = raw[:6] + "…" + raw[-4:] if len(raw) > 14 else "…"
            found.append({"kind": kind, "sample": redacted})
            if len(found) >= 10: return found
    return found

def _detect_sql_error(body):
    if not body: return False
    return bool(SQL_ERROR_PATTERNS.search(body[:20000]))

def _detect_stack_trace(body):
    if not body: return False
    return bool(STACK_TRACE_PATTERNS.search(body[:20000]))

def _detect_dir_listing(body, title):
    hay = f"{title or ''} {body[:2000] if body else ''}"
    return bool(DIR_LISTING_PATTERNS.search(hay))

def _detect_debug_banner(body):
    if not body: return False
    return bool(DEBUG_BANNER_PATTERNS.search(body[:20000]))

def _detect_reflected_params(url, body):
    if not body: return []
    try:
        qs = urllib.parse.urlparse(url).query
        params = urllib.parse.parse_qs(qs)
    except Exception: return []
    hits = []
    body_low = body[:200000].lower()
    for name, values in params.items():
        for v in values:
            v = v.strip()
            if len(v) < 4 or v.lower() in ("true","false","null"): continue
            if v.lower() in body_low:
                hits.append(name); break
    return hits

def _audit_cookie_flags(set_cookie_headers):
    issues = []
    for line in set_cookie_headers or []:
        try: name = line.split("=", 1)[0].strip().lower()
        except Exception: continue
        if not any(h in name for h in SECURE_COOKIE_NAME_HINTS): continue
        ll = line.lower(); missing = []
        if "secure" not in ll: missing.append("Secure")
        if "httponly" not in ll: missing.append("HttpOnly")
        if "samesite" not in ll: missing.append("SameSite")
        if missing: issues.append({"cookie": name, "missing": missing})
    return issues

def _detect_mixed_content(final_url, scripts, stylesheets, links):
    if not (final_url or "").lower().startswith("https://"): return False
    for u in (scripts or []) + (stylesheets or []):
        if (u or "").lower().startswith("http://"): return True
    return False

# ─── CREDENTIAL STORE ─────────────────────────────────────────────────────
def _serialize_cookies(cookiejar):
    return [{"name":c.name,"value":c.value,"domain":c.domain,
             "path":c.path,"secure":c.secure,"expires":c.expires}
            for c in cookiejar]

def _load_cookies_into_session(cookiejar, cookies, host):
    loaded = 0
    for c in cookies:
        try:
            cookie = Cookie(version=0, name=c.get("name",""), value=c.get("value",""),
                            port=None, port_specified=False,
                            domain=c.get("domain") or host, domain_specified=True,
                            domain_initial_dot=False, path=c.get("path","/"),
                            path_specified=True, secure=c.get("secure",False),
                            expires=c.get("expires"), discard=False, comment=None,
                            comment_url=None, rest={}, rfc2109=False)
            cookiejar.set_cookie(cookie); loaded += 1
        except Exception: continue
    return loaded

def _cookie_signature(cookiejar):
    return frozenset((c.name, c.value) for c in cookiejar)

def _detect_new_auth_cookies(before, after):
    return [name for name, _ in (after - before)
            if any(a in name.lower() for a in AUTH_COOKIE_NAMES)]

class CredentialStore:
    def __init__(self, path):
        self.path = path
        self._data = {"version": 3, "accounts": {}}
        self._load()
    def _load(self):
        if not self.path.exists(): return
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(d, dict) and "accounts" in d: self._data = d
        except Exception as e:
            log.warn(f"    creds unreadable ({e}) — starting fresh")
    def _save(self):
        # v9.0: lock prevents concurrent writes from parallel hosts
        try:
            with _CREDS_LOCK:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False)+"\n",
                                     encoding="utf-8")
                try: os.chmod(self.path, 0o600)
                except Exception: pass
        except Exception as e: log.warn(f"    creds save failed: {e}")
    def get(self, host): return self._data.get("accounts", {}).get(host)
    def set(self, host, entry):
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._data.setdefault("accounts", {})[host] = entry
        self._save()
    def mark_invalid(self, host):
        acc = self._data.get("accounts", {}).get(host)
        if acc: acc["valid"] = False; self._save()
    def mark_session_stale(self, host):
        acc = self._data.get("accounts", {}).get(host)
        if acc: acc["session_valid"] = False; self._save()
    def mark_session_valid(self, host):
        acc = self._data.get("accounts", {}).get(host)
        if acc:
            acc["session_valid"] = True
            acc["last_verified"] = datetime.now(timezone.utc).isoformat()
            self._save()
    def count(self): return len(self._data.get("accounts", {}))

def _creds_path(outdir): return _REPO_ROOT / CREDS_FILE_NAME

# ─── ORIGIN LOADER ────────────────────────────────────────────────────────
class OriginLoader:
    def __init__(self, path=None):
        self.path = path or ((_cfg("OUTPUT_DIR") or Path("output")) / "origin_hunt.json")
        self._data = {}
        self._load()
    def _load(self):
        if not self.path.exists(): return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for h in data.get("hosts", []):
                host = (h.get("host") or "").lower()
                if host: self._data[host] = h
            if self._data:
                log.info(f"  origin_hunt.json: {len(self._data)} host(s) loaded")
        except Exception as e:
            log.warn(f"  origin_hunt.json unreadable: {e}")
    def get_usable_origins(self, host):
        h = self._data.get(host.lower())
        if not h: return []
        out = []
        for cand in h.get("confirmed_origins", []):
            cids = cand.get("chain_ids") or []
            if "origin-paas-edge" in cids: continue
            if cand.get("confidence") not in ("CONFIRMED","HIGH"): continue
            if cand.get("severity") not in ("HIGH","CRITICAL","MEDIUM"): continue
            if not cand.get("ip"): continue
            out.append(cand)
        return out

# ─── WAF DETECTION ────────────────────────────────────────────────────────
def _detect_waf_block(res):
    hl = {k.lower(): str(v) for k, v in (res.headers or {}).items()}
    bl = (res.body or "")[:5000].lower()
    for m in WAF_HEADER_MARKERS:
        if m in hl:
            v = _waf_vendor(m)
            if res.status in WAF_BLOCK_STATUSES: return True, v
            if v == "cloudflare" and res.status == 200:
                if "just a moment" in bl or "checking your browser" in bl:
                    return True, "cloudflare-challenge"
    for m in WAF_BODY_MARKERS:
        if m in bl: return True, _waf_from_body(m)
    return False, ""

def _waf_vendor(m):
    if "cf-" in m: return "cloudflare"
    if "akamai" in m: return "akamai"
    if "sucuri" in m: return "sucuri"
    if "datadome" in m: return "datadome"
    if "iinfo" in m or "incapsula" in m: return "imperva"
    if "bigip" in m: return "f5"
    return "waf"

def _waf_from_body(m):
    if "cloudflare" in m or "just a moment" in m or "checking your browser" in m: return "cloudflare"
    if "ddos-guard" in m: return "ddos-guard"
    return "waf"

# ─── HTTP CLIENT ──────────────────────────────────────────────────────────
@dataclass
class HttpResult:
    status: int
    headers: dict
    body: str
    url: str
    final_url: str
    latency_ms: float
    error: Optional[str] = None
    error_category: Optional[str] = None
    via_origin: Optional[str] = None
    set_cookie_headers: list = field(default_factory=list)
    @property
    def ok(self): return self.error is None and self.status > 0

def _all_set_cookie_headers(headers_obj):
    try:
        if hasattr(headers_obj, "get_all"):
            return headers_obj.get_all("Set-Cookie") or []
    except Exception: pass
    return []

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

_BUILTIN_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
)

class HostSession:
    def __init__(self, host, bbp_program=None, proxy_pool=None, audit_trail=None,
                 extra_headers=None, use_proxy=True, respect_robots=False,
                 origin_loader=None, origin_fallback=True, effective_rps=None):
        self.host = host
        self.base_url = f"https://{host}"
        self.bbp_program = bbp_program
        self.audit = audit_trail
        self.proxy_pool = proxy_pool if use_proxy else None
        self.use_proxy = use_proxy
        self.cookiejar = http.cookiejar.CookieJar()
        self.effective_rps = effective_rps
        self.rate_limiter = self._build_rate_limiter()
        self.static_headers = self._build_headers(bbp_program, extra_headers)
        self.respect_robots = respect_robots
        self.origin_loader = origin_loader
        self.origin_fallback = origin_fallback
        self.robots = {"disallow": [], "allow": [], "sitemaps": []}
        self.stats = {"requests":0,"errors":0,"bytes":0,"failures":0,
                      "origin_fallbacks":0,"proxies_used":set()}
        self.consecutive_failures = 0
        self.dead = False
        self.dead_reason = ""

    def _build_rate_limiter(self):
        try:
            rl = _cfg("RateLimiter")
            if self.effective_rps is not None:
                rps = self.effective_rps
            else:
                limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("crawl", {})
                rps = limits.get("rps", 4)
            return rl(per_minute=rps*60, per_hour=rps*3600) if rl else None
        except Exception: return None

    def _build_headers(self, bbp_program, extra):
        headers = {"Accept":"text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                   "Accept-Language":"en-US,en;q=0.5"}
        try:
            if bbp_program:
                b = _cfg("build_headers")
                if callable(b): headers.update(b(bbp_program, dynamic_ua=False))
        except Exception: pass
        if extra: headers.update(extra)
        return headers

    def _next_proxy(self):
        if self.proxy_pool is None: return None
        try:
            p = self.proxy_pool.pick()
            if p is not None:
                try: self.stats["proxies_used"].add(p.url())
                except Exception: pass
            return p
        except Exception: return None

    def _ua(self):
        try:
            fn = _cfg("random_user_agent")
            if callable(fn): return fn()
        except Exception: pass
        return random.choice(_BUILTIN_UAS)

    def _guard(self):
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"): ks.check()
        except Exception: pass

    def _pace(self):
        try:
            if self.rate_limiter is not None: self.rate_limiter.acquire()
            dfn = _cfg("human_delay")
            d = dfn() if callable(dfn) else random.uniform(0.4, 2.5)
            time.sleep(d)
            if random.random() < HUMAN_PAUSE_CHANCE:
                time.sleep(random.uniform(*HUMAN_PAUSE_RANGE))
        except Exception: pass

    def _enforce_scope(self, url):
        try:
            scope = _cfg("SCOPE")
            if scope is None: return True
            if scope.is_in_scope(url): return True
            host = _host_of(url)
            if not host: return False
            for rule in getattr(scope, "_rules", []):
                if not getattr(rule, "include", True): continue
                if getattr(rule, "regex", False): continue
                pat = (rule.pattern or "").lower().strip().lstrip("*.")
                if pat and (host == pat or host.endswith("." + pat)): return True
            return False
        except Exception: return True

    def _record_result(self, res):
        if res.ok or (0 < res.status < 500):
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
            self.stats["failures"] += 1
            if self.consecutive_failures >= CIRCUIT_BREAK_THRESHOLD and not self.dead:
                self.dead = True
                self.dead_reason = res.error_category or res.error or "unknown"
                log.warn(f"    circuit breaker tripped ({self.dead_reason})")

    def _build_opener(self, proxy, follow_redirects=True):
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar)]
        if not follow_redirects: handlers.append(_NoRedirectHandler())
        if proxy is not None:
            try:
                handlers.append(urllib.request.ProxyHandler(
                    {"http": proxy.url(), "https": proxy.url()}))
            except Exception: pass
        return urllib.request.build_opener(*handlers)

    def _report_proxy_result(self, proxy, success, latency=0.0):
        if proxy is None or self.proxy_pool is None: return
        try:
            if success: self.proxy_pool.report_success(proxy, latency)
            else: self.proxy_pool.report_failure(proxy)
        except Exception: pass

    def get(self, url, allow_redirects=True, referer=None):
        if self.dead:
            return HttpResult(0, {}, "", url, url, 0, error="host dead", error_category="circuit")
        if not self._enforce_scope(url):
            return HttpResult(0, {}, "", url, url, 0, error="out of scope", error_category="scope")
        last_err = None
        for attempt in range(3):
            self._guard(); self._pace()
            headers = dict(self.static_headers)
            headers["User-Agent"] = self._ua()
            if referer: headers["Referer"] = referer
            proxy = self._next_proxy()
            req = urllib.request.Request(url, headers=headers, method="GET")
            opener = self._build_opener(proxy, follow_redirects=allow_redirects)
            start = time.monotonic()
            try:
                with opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                    final = resp.geturl() if allow_redirects else url
                    body_b = resp.read(DEFAULT_MAX_BODY_BYTES)
                    lat = (time.monotonic() - start) * 1000
                    body = body_b.decode("utf-8", errors="replace")
                    hd = {k: v for k, v in resp.headers.items()}
                    self.stats["requests"] += 1
                    self.stats["bytes"] += len(body_b)
                    self._audit("GET", final, resp.getcode(), lat, None, proxy)
                    self._report_proxy_result(proxy, True, lat/1000)
                    r = HttpResult(resp.getcode(), hd, body, url, final, lat,
                                   set_cookie_headers=_all_set_cookie_headers(resp.headers))
                    self._record_result(r); return r
            except urllib.error.HTTPError as e:
                lat = (time.monotonic() - start) * 1000
                self.stats["requests"] += 1
                try:
                    body = e.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                    hd = dict(e.headers.items()) if e.headers else {}
                except Exception: body, hd = "", {}
                self._audit("GET", url, e.code, lat, f"HTTP {e.code}", proxy)
                self._report_proxy_result(proxy, e.code < 500)
                r = HttpResult(e.code, hd, body, url, url, lat,
                               error=f"HTTP {e.code}", error_category=f"http{e.code}")
                self.consecutive_failures = 0; return r
            except Exception as e:
                lat = (time.monotonic() - start) * 1000
                self.stats["errors"] += 1
                cat = _categorize_error(e)
                self._audit("GET", url, 0, lat, str(e)[:200], proxy)
                self._report_proxy_result(proxy, False)
                last_err = HttpResult(0, {}, "", url, url, lat,
                                      error=f"{cat}: {type(e).__name__}",
                                      error_category=cat)
                if cat in ("proxy","timeout","reset","refused") and attempt < 2:
                    log.debug(f"    retry {attempt+1}/3 ({cat})")
                    time.sleep(0.5 + attempt * 0.5)
                    continue
                self._record_result(last_err); return last_err
        if last_err:
            self._record_result(last_err); return last_err
        return HttpResult(0, {}, "", url, url, 0, error="unknown", error_category="unknown")

    def get_with_origin_fallback(self, url, referer=None):
        res = self.get(url, allow_redirects=True, referer=referer)
        if not self.origin_fallback or self.origin_loader is None: return res
        blocked, waf = _detect_waf_block(res)
        if not blocked: return res
        origins = self.origin_loader.get_usable_origins(self.host)
        if not origins: return res
        for o in origins[:3]:
            ip = o.get("ip")
            if not ip: continue
            log.info(f"    {Sym.FIRE} origin fallback {url[:60]} → {ip}")
            r = self._fetch_via_origin(url, ip)
            if r.status == 200 and not r.error:
                self.stats["origin_fallbacks"] += 1
                return r
        return res

    def _fetch_via_origin(self, url, ip):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "https"
        path = parsed.path or "/"
        qs = f"?{parsed.query}" if parsed.query else ""
        port = 443 if scheme == "https" else 80
        ua = self._ua()
        start = time.monotonic()
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((ip, port), timeout=DEFAULT_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=self.host) as ss:
                    req = (f"GET {path}{qs} HTTP/1.1\r\nHost: {self.host}\r\n"
                           f"User-Agent: {ua}\r\nConnection: close\r\n\r\n")
                    ss.sendall(req.encode()); data = b""
                    while len(data) < DEFAULT_MAX_BODY_BYTES:
                        chunk = ss.recv(65536)
                        if not chunk: break
                        data += chunk
            else:
                sock = socket.create_connection((ip, port), timeout=DEFAULT_TIMEOUT)
                with sock:
                    req = (f"GET {path}{qs} HTTP/1.1\r\nHost: {self.host}\r\n"
                           f"User-Agent: {ua}\r\nConnection: close\r\n\r\n")
                    sock.sendall(req.encode()); data = b""
                    while len(data) < DEFAULT_MAX_BODY_BYTES:
                        chunk = sock.recv(65536)
                        if not chunk: break
                        data += chunk
            lat = (time.monotonic() - start) * 1000
            text = data.decode("utf-8", errors="replace")
            parts = text.split("\r\n\r\n", 1)
            hb, body = (parts[0], parts[1]) if len(parts) > 1 else (parts[0] if parts else "", "")
            lines = hb.split("\r\n")
            m = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0] if lines else "")
            status = int(m.group(1)) if m else 0
            hd = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":"); hd[k.strip()] = v.strip()
            return HttpResult(status, hd, body, url, url, lat, via_origin=ip)
        except Exception as e:
            return HttpResult(0, {}, "", url, url, 0,
                              error=f"origin: {type(e).__name__}",
                              error_category="origin", via_origin=ip)

    def post(self, url, data, referer=None, allow_redirects=True):
        if self.dead:
            return HttpResult(0, {}, "", url, url, 0, error="host dead", error_category="circuit")
        if not self._enforce_scope(url):
            return HttpResult(0, {}, "", url, url, 0, error="out of scope", error_category="scope")
        body_b = urllib.parse.urlencode(data).encode("utf-8")
        last_err = None
        for attempt in range(3):
            self._guard(); self._pace()
            headers = dict(self.static_headers)
            headers["User-Agent"] = self._ua()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            if referer: headers["Referer"] = referer
            proxy = self._next_proxy()
            req = urllib.request.Request(url, data=body_b, headers=headers, method="POST")
            opener = self._build_opener(proxy, follow_redirects=allow_redirects)
            start = time.monotonic()
            try:
                with opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                    body = resp.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                    lat = (time.monotonic() - start) * 1000
                    hd = {k: v for k, v in resp.headers.items()}
                    self.stats["requests"] += 1
                    self._audit("POST", resp.geturl(), resp.getcode(), lat, None, proxy)
                    self._report_proxy_result(proxy, True, lat/1000)
                    r = HttpResult(resp.getcode(), hd, body, url, resp.geturl(), lat,
                                   set_cookie_headers=_all_set_cookie_headers(resp.headers))
                    self._record_result(r); return r
            except urllib.error.HTTPError as e:
                lat = (time.monotonic() - start) * 1000
                self.stats["requests"] += 1
                try:
                    body = e.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                    hd = dict(e.headers.items()) if e.headers else {}
                except Exception: body, hd = "", {}
                self._audit("POST", url, e.code, lat, f"HTTP {e.code}", proxy)
                self._report_proxy_result(proxy, e.code < 500)
                if e.code >= 400:
                    return HttpResult(e.code, hd, body, url, url, lat,
                                      error=f"HTTP {e.code}",
                                      error_category=f"http{e.code}")
                return HttpResult(e.code, hd, body, url, url, lat)
            except Exception as e:
                lat = (time.monotonic() - start) * 1000
                self.stats["errors"] += 1
                cat = _categorize_error(e)
                self._audit("POST", url, 0, lat, str(e)[:200], proxy)
                self._report_proxy_result(proxy, False)
                last_err = HttpResult(0, {}, "", url, url, lat,
                                      error=f"{cat}: {type(e).__name__}",
                                      error_category=cat)
                if cat in ("proxy","timeout","reset","refused") and attempt < 2:
                    log.debug(f"    retry {attempt+1}/3 ({cat})")
                    time.sleep(0.5 + attempt * 0.5)
                    continue
                self._record_result(last_err); return last_err
        if last_err:
            self._record_result(last_err); return last_err
        return HttpResult(0, {}, "", url, url, 0, error="unknown", error_category="unknown")

    def _audit(self, method, url, status, lat, error, proxy):
        if self.audit is None: return
        try:
            self.audit.record(method=method, url=url, status=status,
                              latency_ms=lat, proxy=proxy.url() if proxy else None,
                              user_agent="(rotating)", error=error)
        except Exception: pass

# ─── HTML PARSING ─────────────────────────────────────────────────────────
def _parse_html(html, base_url):
    out = {"title":"","links":[],"forms":[],"scripts":[],"stylesheets":[],
           "meta":{},"endpoints":[],"base_href":None}
    m = re.search(r'<base\s+[^>]*href=["\']([^"\']+)["\']', html, re.I)
    if m:
        try:
            out["base_href"] = urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1)))
            base_url = out["base_href"]
        except Exception: pass
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m: out["title"] = html_lib.unescape(m.group(1).strip())[:200]
    for m in re.finditer(r'<meta\s+([^>]+?)/?>', html, re.I):
        attrs = m.group(1)
        nm = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
        cm = re.search(r'content=["\']([^"\']*)["\']', attrs, re.I)
        if nm and cm:
            k = nm.group(1).lower()
            if k in ("generator","description","author","csrf-token",
                     "csrf-param","viewport","x-csrf-token"):
                out["meta"][k] = html_lib.unescape(cm.group(1))[:300]
    for m in re.finditer(r'<a\s+[^>]*?href=["\']([^"\']+)["\']', html, re.I):
        try: out["links"].append(urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1))))
        except Exception: pass
    for m in re.finditer(r'<script\s+[^>]*?src=["\']([^"\']+)["\']', html, re.I):
        try: out["scripts"].append(urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1))))
        except Exception: pass
    for m in re.finditer(r'<link\s+[^>]*?rel=["\'][^"\']*stylesheet[^"\']*["\'][^>]*?href=["\']([^"\']+)["\']', html, re.I):
        try: out["stylesheets"].append(urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1))))
        except Exception: pass
    for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        am = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        mm = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        em = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)
        try: action = urllib.parse.urljoin(base_url, html_lib.unescape(am.group(1) if am else ""))
        except Exception: action = base_url
        method = (mm.group(1) if mm else "get").upper()
        enctype = (em.group(1) if em else "").lower()
        fields = []
        for im in re.finditer(r'<input\b([^>]*?)/?>', inner, re.I):
            ia = im.group(1)
            nm = re.search(r'name=["\']([^"\']+)["\']', ia, re.I)
            ty = re.search(r'type=["\']([^"\']+)["\']', ia, re.I)
            vl = re.search(r'value=["\']([^"\']*)["\']', ia, re.I)
            if not nm: continue
            fields.append({"name": nm.group(1),
                           "type": (ty.group(1) if ty else "text").lower(),
                           "value": html_lib.unescape(vl.group(1)) if vl else "",
                           "csrf": bool(CSRF_FIELD_RE.search(nm.group(1))),
                           "code": bool(CODE_FIELD_RE.search(nm.group(1)))})
        for tm in re.finditer(r'<textarea\b([^>]*)>', inner, re.I):
            nm = re.search(r'name=["\']([^"\']+)["\']', tm.group(1), re.I)
            if nm: fields.append({"name": nm.group(1), "type": "textarea",
                                  "value": "", "csrf": False, "code": False})
        for sm in re.finditer(r'<select\b([^>]*)>', inner, re.I):
            nm = re.search(r'name=["\']([^"\']+)["\']', sm.group(1), re.I)
            if nm: fields.append({"name": nm.group(1), "type": "select",
                                  "value": "", "csrf": False, "code": False})
        out["forms"].append({
            "action": action, "method": method, "enctype": enctype, "fields": fields,
            "has_password": any((f["type"] == "password") or PASSWORD_FIELD_RE.search(f["name"]) for f in fields),
            "has_file_upload": enctype == "multipart/form-data" or any(f["type"] == "file" for f in fields),
            "has_code_field": any(f.get("code") for f in fields),
        })
    endpoints = set()
    for m in re.finditer(r'<script\b[^>]*>(.*?)</script>', html, re.I | re.S):
        js = m.group(1)
        if not js.strip(): continue
        for regex in (JS_FETCH_RE, JS_AJAX_RE, JS_AXIOS_RE):
            for jm in regex.finditer(js):
                try: endpoints.add(urllib.parse.urljoin(base_url, jm.group(1)))
                except Exception: pass
        for jm in JS_ENDPOINT_RE.finditer(js):
            try: endpoints.add(urllib.parse.urljoin(base_url, jm.group(1)))
            except Exception: pass
    out["endpoints"] = sorted(endpoints)[:200]
    return out

def _parse_robots(body, base_url):
    out = {"sitemaps": [], "disallow": [], "allow": []}
    for line in body.splitlines():
        line = line.split("#")[0].strip()
        if not line or ":" not in line: continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "sitemap":
            try: out["sitemaps"].append(urllib.parse.urljoin(base_url, v))
            except Exception: pass
        elif k == "disallow" and v: out["disallow"].append(v)
        elif k == "allow" and v: out["allow"].append(v)
    return out

def _parse_sitemap(body, base_url):
    urls = []
    for m in re.finditer(r"<loc>\s*([^<]+?)\s*</loc>", body, re.I):
        try: urls.append(urllib.parse.urljoin(base_url, m.group(1).strip()))
        except Exception: pass
    return urls

def _is_disallowed(url, robots):
    try: path = urllib.parse.urlparse(url).path or "/"
    except Exception: return False
    for pat in robots.get("allow", []):
        if path.startswith(pat): return False
    for pat in robots.get("disallow", []):
        if path.startswith(pat): return True
    return False

def _detect_frameworks(html, headers, scripts, stylesheets, meta):
    detected = set()
    hf = " ".join(f"{k.lower()}:{v.lower()}" for k, v in (headers or {}).items())
    mf = " ".join(f"{k}={v}".lower() for k, v in (meta or {}).items())
    rf = " ".join((scripts or []) + (stylesheets or [])).lower()
    hl = (html or "")[:50000].lower()
    for name, (hp, mp, rp) in FRAMEWORK_SIGNATURES.items():
        if any(p.lower() in hf for p in hp): detected.add(name); continue
        if any(p.lower() in mf for p in mp): detected.add(name); continue
        if any(p.lower() in rf or p.lower() in hl for p in rp): detected.add(name)
    return sorted(detected)

# ─── PAGE CLASSIFICATION ──────────────────────────────────────────────────
def _classify_page(url, title, forms, meta):
    path = (urllib.parse.urlparse(url).path or "/").lower()
    tl = (title or "").lower()
    chains = []
    if DEBUG_PATTERNS.search(path): return "debug", ["crawl-debug-exposed"]
    if ADMIN_PATTERNS.search(path): return "admin", ["crawl-admin-surface"]
    if API_PATTERNS.search(path):   return "api", ["crawl-api-surface"]
    if REGISTER_PATTERNS.search(path): return "register", ["crawl-register-exposed"]
    if LOGIN_PATTERNS.search(path): return "login", ["crawl-auth-gated"]
    if any(t in tl for t in ("sign up","register","create account","registration","join us")):
        return "register", ["crawl-register-exposed"]
    if any(t in tl for t in ("sign in","login","log in","signin")):
        return "login", ["crawl-auth-gated"]
    has_pw = has_cf = has_em = has_un = has_up = False
    text_ct = 0
    for f in forms or []:
        for fld in f.get("fields", []):
            n = fld.get("name") or ""
            t = (fld.get("type") or "").lower()
            if t == "password" or PASSWORD_FIELD_RE.search(n):
                has_pw = True
                if CONFIRM_FIELD_RE.search(n): has_cf = True
            if EMAIL_FIELD_RE.search(n) or t == "email": has_em = True
            if USERNAME_FIELD_RE.search(n): has_un = True
            if t == "file": has_up = True
            if t in ("text","email","tel") and not CSRF_FIELD_RE.search(n):
                text_ct += 1
        if f.get("has_file_upload"): has_up = True
    if has_up: chains.append("crawl-upload-form")
    if has_pw:
        if has_cf or (has_em and has_un) or text_ct >= 3:
            return "register", chains + ["crawl-register-exposed"]
        if has_em and any(t in tl for t in ("create","new","sign up","join")):
            return "register", chains + ["crawl-register-exposed"]
        return "login", chains + ["crawl-auth-gated"]
    return "public", chains

def _heuristic_score(page):
    score = 0
    k = page.get("kind", "public")
    score += {"debug":45,"admin":40,"login":30,"register":25,"api":20}.get(k, 0)
    if page.get("params"): score += 5 * min(len(page["params"]), 5)
    if page.get("forms"):
        score += 10
        if "crawl-upload-form" in (page.get("chain_ids") or []): score += 20
    if page.get("headers_security", {}).get("cors_acao") == "*": score += 10
    if page.get("external_redirect"): score += 5
    if page.get("status_code") in (401, 403): score += 15
    if page.get("authenticated"): score += 20
    if page.get("secrets_found"): score += 60 + 10 * min(len(page["secrets_found"]), 4)
    if page.get("sql_error"): score += 35
    if page.get("stack_trace"): score += 15
    if page.get("dir_listing"): score += 15
    if page.get("debug_banner"): score += 15
    if page.get("reflected_params"): score += 10 * min(len(page["reflected_params"]), 3)
    if page.get("insecure_cookies"): score += 8
    if page.get("mixed_content"): score += 5
    if score >= 70:   sev = Severity.CRITICAL
    elif score >= 45: sev = Severity.HIGH
    elif score >= 25: sev = Severity.MEDIUM
    elif score >= 10: sev = Severity.LOW
    else:             sev = Severity.INFO
    return score, sev

def _heuristic_summary(page):
    kind = page.get("kind", "public")
    params = page.get("params") or []
    forms = page.get("forms") or []
    fws = page.get("framework") or []
    inj_p = [p for p in params if p.lower() in ("id","user","uid","pid","page","cat","category",
            "product","item","order","invoice","search","q","query","filter","sort","doc",
            "num","view","account","profile")]
    inj_f = []
    for f in forms:
        for fld in f.get("fields", []):
            n = fld.get("name") or ""
            t = (fld.get("type") or "").lower()
            if t not in ("hidden","submit","button","reset","file") and n:
                inj_f.append(n)
    secrets = page.get("secrets_found") or []
    reflected = page.get("reflected_params") or []
    notes = []
    risk = "INFO"
    if secrets:
        risk = "CRITICAL"
        notes.append(f"{len(secrets)} secret-shaped string(s): " +
                     ", ".join(sorted({s['kind'] for s in secrets}))[:120])
    elif page.get("sql_error"):
        risk = "HIGH"; notes.append("SQL error signature in response body")
    elif page.get("authenticated") or kind in ("debug","admin") or page.get("status_code") in (401, 403):
        risk = "HIGH"
    elif kind in ("login","register","api") or reflected:
        risk = "MEDIUM"
    elif inj_p or forms: risk = "MEDIUM"
    elif params: risk = "LOW"
    if page.get("stack_trace"): notes.append("stack trace / unhandled exception disclosed")
    if page.get("dir_listing"): notes.append("directory listing exposed")
    if page.get("debug_banner"): notes.append("debug banner/mode detected")
    if reflected: notes.append(f"param(s) reflected verbatim: {', '.join(reflected[:5])}")
    if page.get("insecure_cookies"):
        bad = ", ".join(c["cookie"] for c in page["insecure_cookies"][:3])
        notes.append(f"auth cookie(s) missing flags: {bad}")
    if page.get("mixed_content"): notes.append("HTTPS page loads HTTP sub-resources")
    summary = f"{kind} page"
    if page.get("authenticated"): summary = f"AUTHENTICATED {summary}"
    if secrets: summary += f" · {Sym.KEY} {len(secrets)} secret-shaped string(s)"
    if inj_p: summary += f" · {len(inj_p)} injectable-look param(s)"
    if inj_f: summary += f" · {len(inj_f)} input field(s)"
    if fws:   summary += f" · {', '.join(fws[:3])}"
    return {"summary": summary, "risk_level": risk,
            "injectable_params": inj_p, "injectable_fields": inj_f,
            "notes": "; ".join(notes), "source": "heuristic"}

_AI_SUMMARIES: dict[str, int] = {}
_AI_CACHE: dict[str, dict] = {}
AI_HIGH_PRIORITY_SCORE = 60
AI_RESPONSE_MAX_CHARS  = 4000

def _ai_content_signature(page):
    sig_src = json.dumps({
        "kind": page.get("kind"), "status": page.get("status_code"),
        "title": (page.get("title") or "")[:80],
        "param_names": sorted(page.get("params") or []),
        "form_field_sets": sorted(
            tuple(sorted(fld.get("name","") for fld in f.get("fields", [])))
            for f in (page.get("forms") or [])
        ),
        "secrets": sorted({s["kind"] for s in (page.get("secrets_found") or [])}),
        "sql_error": bool(page.get("sql_error")),
        "stack_trace": bool(page.get("stack_trace")),
        "framework": sorted(page.get("framework") or []),
    }, sort_keys=True, default=str)
    return hashlib.sha1(sig_src.encode("utf-8", "replace")).hexdigest()

def _ai_worth_spending(page, host, max_pages):
    score = page.get("heuristic_score", 0)
    hard_finding = bool(page.get("secrets_found") or page.get("sql_error")
                        or page.get("stack_trace") or page.get("dir_listing"))
    with _AI_LOCK:
        used = _AI_SUMMARIES.get(host, 0)
    if hard_finding: return True
    if used < max_pages // 2: return bool(page.get("interesting") or page.get("forms") or page.get("params"))
    return score >= AI_HIGH_PRIORITY_SCORE

def _ai_summarize_page(page, host):
    if not bool(_cfg("AI_ENABLED", False)):
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    max_pages = int(_cfg("AI_MAX_PAGES", AI_PAGE_SUMMARY_LIMIT))
    with _AI_LOCK:
        if _AI_SUMMARIES.get(host, 0) >= max_pages: return None
    if not _ai_worth_spending(page, host, max_pages):
        return None

    sig = _ai_content_signature(page)
    with _AI_LOCK:
        cached = _AI_CACHE.get(sig)
    if cached is not None:
        out = dict(cached); out["source"] = "ai-cached"
        with _AI_LOCK:
            _AI_SUMMARIES[host] = _AI_SUMMARIES.get(host, 0) + 1
        return out

    forms_brief = []
    for f in (page.get("forms") or [])[:3]:
        fields = [fld.get("name") for fld in (f.get("fields") or [])[:10] if fld.get("name")]
        forms_brief.append({
            "action": f.get("action", "")[:200], "method": f.get("method", "GET"),
            "fields": fields, "has_password": f.get("has_password", False),
            "has_file_upload": f.get("has_file_upload", False),
        })

    static_findings = {
        "secrets_found": [s["kind"] for s in (page.get("secrets_found") or [])],
        "sql_error_signature": bool(page.get("sql_error")),
        "stack_trace_disclosed": bool(page.get("stack_trace")),
        "directory_listing": bool(page.get("dir_listing")),
        "debug_banner": bool(page.get("debug_banner")),
        "reflected_params": page.get("reflected_params") or [],
        "insecure_cookie_flags": [c["cookie"] for c in (page.get("insecure_cookies") or [])],
        "mixed_content": bool(page.get("mixed_content")),
        "heuristic_risk_level": (page.get("page_summary") or {}).get("risk_level", "INFO"),
        "heuristic_score": page.get("heuristic_score", 0),
    }

    system = (
        "You are an expert bug bounty web analyst performing triage on a "
        "crawled page for an AUTHORIZED security assessment. You are given "
        "static-analysis findings already computed by the crawler — confirm, "
        "escalate, or downgrade them with your own judgment; do not just "
        "repeat them. Return STRICT JSON only. No markdown, no prose, no code fences."
    )
    prompt = f"""Analyze this crawled page for bug bounty value.

URL: {page.get('url')}
Host: {host}
Status: {page.get('status_code')}
Authenticated: {page.get('authenticated', False)}
Title: {page.get('title','')}
Kind: {page.get('kind','public')}
Params: {page.get('params', [])}
Forms: {forms_brief}
Framework: {page.get('framework', [])}
Headers: {page.get('headers_security', {})}
Static findings (crawler-computed, verify/escalate/dismiss): {json.dumps(static_findings)}
Body preview: {(page.get('body_preview') or '')[:800]}

Return STRICT JSON:
{{
  "summary": "1-sentence description",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "injectable_params": ["param names that look injectable"],
  "injectable_fields": ["form field names worth testing"],
  "confirmed_findings": ["which static findings above you'd actually escalate for manual testing"],
  "false_positive_findings": ["which static findings above look like false positives"],
  "notes": "notable observations the static findings miss"
}}"""

    try:
        response = ai_fn(prompt, system=system)
        if not response: return None
        text = response.strip()[:AI_RESPONSE_MAX_CHARS]
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        data = json.loads(text)
        if not isinstance(data, dict): return None
        data["source"] = "ai"
        data.setdefault("heuristic_risk_level", static_findings["heuristic_risk_level"])
        data["cross_validated"] = (data.get("risk_level") == static_findings["heuristic_risk_level"])
        with _AI_LOCK:
            _AI_SUMMARIES[host] = _AI_SUMMARIES.get(host, 0) + 1
            if len(_AI_CACHE) < 5000:
                _AI_CACHE[sig] = data
        return data
    except Exception as e:
        log.debug(f"    AI summary failed: {type(e).__name__}: {e}")
        return None

def _build_page_record(res, host, depth, parsed=None, referer=None, authenticated=False):
    final_url = res.final_url or res.url
    final_host = _host_of(final_url)
    redirect_off = (final_host != host and final_host != "")
    page = {"url": final_url, "requested_url": res.url, "host": host,
            "path": urllib.parse.urlparse(final_url).path or "/",
            "status_code": res.status,
            "content_type": res.headers.get("Content-Type", ""),
            "content_length": len(res.body),
            "title": "", "kind": "public", "chain_ids": [],
            "params": _extract_params(final_url), "links": [], "forms": [],
            "scripts": [], "stylesheets": [], "meta": {}, "endpoints": [],
            "response_time_ms": round(res.latency_ms, 1), "depth": depth,
            "referer": referer,
            "redirected_to": final_url if final_url != res.url else None,
            "external_redirect": redirect_off,
            "headers_security": {}, "framework": [],
            "body_preview": _text_preview(res.body or ""),
            "page_summary": {}, "error": res.error,
            "error_category": res.error_category,
            "origin_fallback_used": bool(res.via_origin),
            "origin_ip_used": res.via_origin,
            "authenticated": authenticated, "interesting": False,
            "reasons": [], "heuristic_score": 0,
            "severity": Severity.INFO.value}
    h = res.headers
    page["headers_security"] = {
        "hsts": bool(h.get("Strict-Transport-Security")),
        "csp": bool(h.get("Content-Security-Policy")),
        "xfo": bool(h.get("X-Frame-Options")),
        "cors_acao": h.get("Access-Control-Allow-Origin", ""),
        "server": h.get("Server", ""),
        "powered_by": h.get("X-Powered-By", ""),
    }
    if parsed is not None:
        page["title"] = parsed["title"]
        page["meta"] = parsed["meta"]
        page["forms"] = parsed["forms"]
        page["scripts"] = parsed["scripts"][:50]
        page["stylesheets"] = parsed["stylesheets"][:50]
        page["endpoints"] = parsed["endpoints"]
        page["links"] = list(dict.fromkeys(parsed["links"]))[:200]
        kind, chains = _classify_page(final_url, parsed["title"], parsed["forms"], parsed["meta"])
        page["kind"] = kind
        page["chain_ids"] = chains
    page["framework"] = _detect_frameworks(res.body or "", res.headers or {},
                                           page["scripts"], page["stylesheets"], page["meta"])
    page["secrets_found"] = _detect_secrets(res.body or "")
    page["sql_error"] = _detect_sql_error(res.body or "")
    page["stack_trace"] = _detect_stack_trace(res.body or "")
    page["dir_listing"] = _detect_dir_listing(res.body or "", page["title"])
    page["debug_banner"] = _detect_debug_banner(res.body or "")
    page["reflected_params"] = _detect_reflected_params(final_url, res.body or "")
    page["insecure_cookies"] = _audit_cookie_flags(getattr(res, "set_cookie_headers", None))
    page["mixed_content"] = _detect_mixed_content(final_url, page["scripts"],
                                                  page["stylesheets"], page["links"])
    if page["secrets_found"]:
        page["reasons"].append(f"secrets:{len(page['secrets_found'])}")
        page["chain_ids"].append("crawl-secret-exposure")
    if page["sql_error"]:
        page["reasons"].append("sql_error_signature")
        page["chain_ids"].append("crawl-sql-error")
    if page["stack_trace"]:
        page["reasons"].append("stack_trace_disclosed")
        page["chain_ids"].append("crawl-stack-trace")
    if page["dir_listing"]:
        page["reasons"].append("directory_listing")
        page["chain_ids"].append("crawl-dir-listing")
    if page["debug_banner"]:
        page["reasons"].append("debug_banner")
        page["chain_ids"].append("crawl-debug-banner")
    if page["reflected_params"]:
        page["reasons"].append(f"reflected_params:{','.join(page['reflected_params'][:3])}")
        page["chain_ids"].append("crawl-reflected-param")
    if page["insecure_cookies"]:
        page["reasons"].append("insecure_cookie_flags")
        page["chain_ids"].append("crawl-insecure-cookie")
    if page["mixed_content"]:
        page["reasons"].append("mixed_content")
        page["chain_ids"].append("crawl-mixed-content")
    if page["kind"] in ("admin","login","register","debug","api"):
        page["interesting"] = True
        page["reasons"].append(f"kind:{page['kind']}")
    if page["authenticated"]:
        page["interesting"] = True
        page["reasons"].append("authenticated_access")
        if "crawl-authenticated" not in page["chain_ids"]:
            page["chain_ids"].append("crawl-authenticated")
    if page["params"]:
        page["reasons"].append(f"params:{len(page['params'])}")
        page["chain_ids"].append("crawl-parameterized-urls")
    if page["headers_security"]["cors_acao"] == "*":
        page["reasons"].append("cors_wildcard")
        page["chain_ids"].append("crawl-cors-permissive")
    if page["external_redirect"]:
        page["reasons"].append("external_redirect")
        page["chain_ids"].append("crawl-external-redirect")
    if page["origin_fallback_used"]:
        page["reasons"].append(f"origin_fallback:{page['origin_ip_used']}")
        page["chain_ids"].append("crawl-waf-fallback")
    score, sev = _heuristic_score(page)
    page["heuristic_score"] = score
    page["severity"] = sev.value
    if score >= 45: page["interesting"] = True
    heuristic = _heuristic_summary(page)
    page["page_summary"] = heuristic
    ai = _ai_summarize_page(page, host)
    if ai:
        merged = dict(heuristic)
        merged.update({k: v for k, v in ai.items() if v not in (None, "", [])})
        merged["heuristic_risk_level"] = heuristic.get("risk_level")
        page["page_summary"] = merged
        try:
            ai_sev = Severity(merged.get("risk_level", "INFO"))
            cur_sev = Severity(page["severity"])
            if ai_sev.rank > cur_sev.rank:
                page["severity"] = ai_sev.value
                page["interesting"] = True
        except Exception: pass
    return page

# ─── JS ANALYSIS ──────────────────────────────────────────────────────────
def _analyze_js_file(url, session):
    res = session.get_with_origin_fallback(url)
    if not res.ok or res.status != 200 or not res.body: return [], None
    eps = set()
    for regex in (JS_FETCH_RE, JS_AJAX_RE, JS_AXIOS_RE):
        for m in regex.finditer(res.body):
            try: eps.add(urllib.parse.urljoin(url, m.group(1)))
            except Exception: pass
    for m in JS_ENDPOINT_RE.finditer(res.body):
        try: eps.add(urllib.parse.urljoin(url, m.group(1)))
        except Exception: pass
    return sorted(eps)[:100], res.body[:50000]

def _analyze_css_file(url, session): return [], None

# ─── CRAWL ENGINE ─────────────────────────────────────────────────────────
def _crawl_host(host, session, *, max_pages, max_depth, aggressive,
                page_stream_path=None, host_timeout=None):
    base_url = session.base_url
    pages = []
    visited = set()
    queue = []
    assets_js, assets_css = set(), set()
    endpoints_found = set()
    js_done, css_done = set(), set()
    deadline = (time.monotonic() + host_timeout) if host_timeout else None

    def _timed_out():
        return deadline is not None and time.monotonic() > deadline

    def stream(p):
        if page_stream_path is None: return
        try:
            with _STREAM_LOCK:
                with page_stream_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(p, ensure_ascii=False) + "\n")
        except Exception: pass

    front = session.get_with_origin_fallback(base_url + "/")
    blocked, waf = _detect_waf_block(front)
    if not blocked and (front.error or front.status == 0) and \
       session.consecutive_failures < CIRCUIT_BREAK_THRESHOLD:
        front = session.get_with_origin_fallback(f"http://{host}/")
        blocked, waf = _detect_waf_block(front)
    if blocked:
        log.warn(f"    WAF-blocked ({waf}) — returned {front.status}")
        return {"host": host, "base_url": base_url, "pages": [],
                "assets_js": [], "assets_css": [], "endpoints": [], "chains": {},
                "session_stats": _stats(session.stats), "dead": False,
                "waf_blocked": True, "waf_vendor": waf,
                "waf_status": front.status, "ai_summaries": 0,
                "unvisited_queue": [], "timed_out": False}
    if front.error or front.status == 0:
        return {"host": host, "base_url": base_url, "pages": [],
                "assets_js": [], "assets_css": [], "endpoints": [], "chains": {},
                "session_stats": _stats(session.stats), "dead": True,
                "dead_reason": front.error or "no response", "ai_summaries": 0,
                "unvisited_queue": [], "timed_out": False}

    visited.add(front.final_url or front.url)
    last = front.final_url or front.url
    fp = _parse_html(front.body, last)
    fpage = _build_page_record(front, host, 0, fp)
    pages.append(fpage); stream(fpage)
    if not _SHARED["_quiet"]:
        log.info(f"    [{fpage['kind']:<8}] {front.status:>3} {fpage['url'][:70]}")

    fh = _host_of(last)
    for s in fp["scripts"]:
        if s and _host_of(s) == host: assets_js.add(s)
    for s in fp["stylesheets"]:
        if s and _host_of(s) == host: assets_css.add(s)
    for ep in fp["endpoints"]:
        if ep and _host_of(ep) == host: endpoints_found.add(ep)
    for link in fp["links"]:
        n = _normalize_url(link, fh)
        if n and n not in visited: queue.append((n, 1, last))

    for pp in PROTOCOL_PATHS:
        if len(pages) >= max_pages or _timed_out(): break
        pu = base_url + pp
        if pu in visited: continue
        visited.add(pu)
        pr = session.get_with_origin_fallback(pu)
        if pr.error or pr.status not in (200, 203): continue
        if pp == "/robots.txt":
            session.robots = _parse_robots(pr.body, base_url)
            if not _SHARED["_quiet"]: log.info(f"    [robots  ] {pr.status:>3} {pu[:70]}")
            for sm in session.robots.get("sitemaps", []):
                if _host_of(sm) == host and sm not in visited:
                    queue.append((sm, 1, pu))
        elif pp == "/sitemap.xml":
            sm_urls = _parse_sitemap(pr.body, base_url)
            if not _SHARED["_quiet"]: log.info(f"    [sitemap ] {pr.status:>3} {pu[:70]}")
            for sm in sm_urls:
                n = _normalize_url(sm, fh)
                if n and n not in visited: queue.append((n, 1, pu))

    while queue and len(pages) < max_pages and not session.dead and not _timed_out():
        url, depth, ref = queue.pop(0)
        if url in visited or depth > max_depth: continue
        visited.add(url)
        if session.respect_robots and _is_disallowed(url, session.robots): continue
        if random.random() < PAGE_SKIP_CHANCE and len(queue) > 3: continue
        res = session.get_with_origin_fallback(url, referer=ref)
        if res.error or res.status == 0: continue
        fhost = _host_of(res.final_url or res.url)
        if fhost and fhost != host:
            page = _build_page_record(res, host, depth, None, referer=ref)
            pages.append(page); stream(page); continue
        parsed = _parse_html(res.body, res.final_url or res.url)
        page = _build_page_record(res, host, depth, parsed, referer=ref)
        pages.append(page); stream(page)
        last = page["url"]
        if not _SHARED["_quiet"]:
            log.info(f"    [{page['kind']:<8}] {res.status:>3} {page['url'][:70]}")
        for s in parsed["scripts"]:
            if s and _host_of(s) == host: assets_js.add(s)
        for s in parsed["stylesheets"]:
            if s and _host_of(s) == host: assets_css.add(s)
        for ep in parsed["endpoints"]:
            if ep and _host_of(ep) == host: endpoints_found.add(ep)
        for link in parsed["links"]:
            n = _normalize_url(link, host)
            if n and n not in visited and depth + 1 <= max_depth:
                queue.append((n, depth + 1, page["url"]))

    if aggressive and not _timed_out():
        for ju in list(assets_js)[:JS_FETCH_LIMIT]:
            if ju in js_done: continue
            eps, _ = _analyze_js_file(ju, session)
            js_done.add(ju)
            for ep in eps:
                if _host_of(ep) == host: endpoints_found.add(ep)
        for cu in list(assets_css)[:5]:
            if cu in css_done: continue
            _analyze_css_file(cu, session); css_done.add(cu)

    if aggressive and endpoints_found and not _timed_out():
        for ep in list(endpoints_found)[:ENDPOINT_PROBE_LIMIT]:
            if len(pages) >= max_pages or session.dead or _timed_out(): break
            if ep in visited: continue
            visited.add(ep)
            res = session.get_with_origin_fallback(ep, referer=last)
            if res.status in (200, 201, 401, 403, 500):
                page = {"url": ep, "requested_url": ep, "host": host,
                        "path": urllib.parse.urlparse(ep).path or "/",
                        "status_code": res.status,
                        "content_type": res.headers.get("Content-Type", ""),
                        "content_length": len(res.body), "title": "",
                        "kind": "api", "chain_ids": ["crawl-api-surface","crawl-js-endpoints"],
                        "params": _extract_params(ep), "links": [], "forms": [],
                        "scripts": [], "stylesheets": [], "meta": {}, "endpoints": [],
                        "framework": [], "body_preview": _text_preview(res.body or "", 300),
                        "response_time_ms": round(res.latency_ms, 1),
                        "depth": 99, "referer": last, "redirected_to": None,
                        "external_redirect": False, "headers_security": {},
                        "origin_fallback_used": bool(res.via_origin),
                        "origin_ip_used": res.via_origin, "authenticated": False,
                        "error": res.error, "error_category": res.error_category,
                        "interesting": True, "reasons": ["js_endpoint"],
                        "heuristic_score": 25, "severity": Severity.MEDIUM.value,
                        "page_summary": {}}
                page["page_summary"] = _heuristic_summary(page)
                pages.append(page); stream(page)

    chains_by_id = {}
    for p in pages:
        for cid in p.get("chain_ids", []):
            chains_by_id.setdefault(cid, []).append(p["url"])
    if len(pages) > 50:
        chains_by_id.setdefault("crawl-mass-surface", []).append(f"total_pages={len(pages)}")

    with _AI_LOCK:
        ai_ct = _AI_SUMMARIES.get(host, 0)
    return {"host": host, "base_url": base_url, "pages": pages,
            "assets_js": sorted(assets_js), "assets_css": sorted(assets_css),
            "endpoints": sorted(endpoints_found), "chains": chains_by_id,
            "session_stats": _stats(session.stats), "dead": session.dead,
            "dead_reason": session.dead_reason, "ai_summaries": ai_ct,
            "unvisited_queue": [(u, d, r) for u, d, r in queue],
            "timed_out": _timed_out()}

def _stats(stats):
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in stats.items()}

# ─── AUTH DETECTION ───────────────────────────────────────────────────────
@dataclass
class AuthResult:
    status: str
    method: str = ""
    redirect_url: str = ""
    email: str = ""
    username: str = ""
    password: str = ""
    register_url: str = ""
    login_url: str = ""
    verify_url: Optional[str] = None
    verify_code: Optional[str] = None
    cookies_count: int = 0
    body_markers: list[str] = field(default_factory=list)
    protected_urls_hit: list[str] = field(default_factory=list)
    session_valid: bool = False
    error: str = ""

def _try_protected_probe(session, host):
    base = session.base_url.rstrip("/")
    for probe in PROTECTED_PROBE_PATHS:
        res = session.get_with_origin_fallback(base + probe, referer=base + "/")
        if res.error or res.status != 200: continue
        final = (res.final_url or res.url).lower()
        if any(p in final for p in AUTH_LOGIN_PATHS): continue
        body_low = (res.body or "")[:3000].lower()
        if 'type="password"' in body_low and "login" in final: continue
        return base + probe
    return None

def _detect_auth_state(res, before_cookies, after_cookies, *, session=None,
                       host="", is_post_register=False):
    status = res.status
    headers = res.headers or {}
    body = (res.body or "").lower()
    loc = (headers.get("Location", "") or headers.get("location", "")).lower()
    bp = body[:5000]
    signals = []
    new_auth = _detect_new_auth_cookies(before_cookies, after_cookies)
    if new_auth: signals.append(f"cookie:{','.join(new_auth[:3])}")
    if status in (301,302,303,307,308) and loc:
        if any(p in loc for p in AUTH_SUCCESS_PATHS):
            signals.append(f"redirect_to:{loc[:80]}")
        elif any(p in loc for p in AUTH_VERIFY_PATHS):
            return "verify_needed", [f"redirect_to_verify:{loc[:80]}"]
        elif any(p in loc for p in AUTH_LOGIN_PATHS):
            if is_post_register: return "already_exists", ["redirect_to_login_after_register"]
            return "failed", ["redirect_back_to_login"]
    for m in AUTH_VERIFY_BODY:
        if m in bp: return "verify_needed", [f"body:{m}"]
    for m in AUTH_EXISTS_BODY:
        if m in bp: return "already_exists", [f"body:{m}"]
    for m in AUTH_FAILURE_BODY:
        if m in bp: return "failed", [f"body:{m}"]
    for m in AUTH_SUCCESS_BODY:
        if m in bp: signals.append(f"body:{m}"); break
    if session is not None and host:
        ph = _try_protected_probe(session, host)
        if ph: signals.append(f"protected:{ph}")
    n = len(signals)
    if n >= 2: return "logged_in", signals
    if n == 1: return "ambiguous", signals
    if status >= 500: return "failed", [f"server_error:{status}"]
    if status == 200 and is_post_register: return "ambiguous", ["200_after_register"]
    return "ambiguous", [f"status:{status}"]

# ─── FORM + PAYLOAD HELPERS ───────────────────────────────────────────────
def _build_form_payload(form, values):
    payload = {}
    for fld in form.get("fields", []):
        n = fld.get("name", "")
        t = (fld.get("type") or "").lower()
        if not n: continue
        if t in ("submit","button","reset","image","file"): continue
        if fld.get("csrf") and fld.get("value"):
            payload[n] = fld["value"]; continue
        if fld.get("value") and t == "hidden":
            payload[n] = fld["value"]; continue
        if PASSWORD_FIELD_RE.search(n) and "confirm" not in n.lower():
            payload[n] = values.get("password", ""); continue
        if CONFIRM_FIELD_RE.search(n):
            payload[n] = values.get("password_confirm", values.get("password", "")); continue
        if EMAIL_FIELD_RE.search(n) or t == "email":
            payload[n] = values.get("email", ""); continue
        if USERNAME_FIELD_RE.search(n):
            payload[n] = values.get("username", values.get("email", "")); continue
        if t in ("text","tel","url","number"):
            payload[n] = values.get("username", values.get("email", ""))
        elif fld.get("value"):
            payload[n] = fld["value"]
    for k, v in values.items():
        if k not in payload and v:
            for fld in form.get("fields", []):
                if fld.get("name") == k:
                    payload[k] = v; break
    return payload

def _find_login_form(pages):
    cands = [p for p in pages if p.get("kind") == "login" and p.get("forms")]
    if not cands:
        cands = [p for p in pages if p.get("forms") and
                 any(f.get("has_password") for f in p["forms"])]
    if not cands: return None
    def sc(p):
        s = 0
        for f in p["forms"]:
            names = " ".join(fld.get("name","") for fld in f.get("fields",[]))
            if PASSWORD_FIELD_RE.search(names): s += 2
            if EMAIL_FIELD_RE.search(names): s += 2
            if USERNAME_FIELD_RE.search(names): s += 1
        return s
    return max(cands, key=sc)

def _find_register_form(pages):
    cands = [p for p in pages if p.get("kind") == "register" and p.get("forms")]
    if cands:
        def sc(p):
            s = 0
            for f in p["forms"]:
                names = " ".join(fld.get("name","") for fld in f.get("fields",[]))
                if PASSWORD_FIELD_RE.search(names): s += 2
                if EMAIL_FIELD_RE.search(names): s += 2
                if CONFIRM_FIELD_RE.search(names): s += 1
            return s
        return max(cands, key=sc)
    for p in pages:
        if not p.get("forms"): continue
        for form in p["forms"]:
            if not form.get("has_password"): continue
            fields = form.get("fields", [])
            names = " ".join((f.get("name") or "").lower() for f in fields)
            em = bool(EMAIL_FIELD_RE.search(names))
            un = bool(USERNAME_FIELD_RE.search(names))
            cf = bool(CONFIRM_FIELD_RE.search(names))
            ct = sum(1 for f in fields if (f.get("type") or "").lower() in ("text","email"))
            if cf or (em and un) or ct >= 3: return p
    return None

def _find_code_verification_form(pages):
    for p in pages:
        for form in p.get("forms", []):
            if form.get("has_code_field"):
                return {"page": p, "form": form}
    return None

def _generate_password(length=20):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))

def _extract_verification(msg, host):
    if isinstance(msg, dict):
        subject = (msg.get("subject") or "")[:200]
        sender = (msg.get("from") or msg.get("sender") or "")[:200]
        body = (msg.get("body") or msg.get("text") or msg.get("html") or "")
        pre_links = msg.get("links") or []
    else:
        subject = (getattr(msg, "subject", "") or "")[:200]
        sender = (getattr(msg, "sender", "") or "")[:200]
        body = (getattr(msg, "text", "") or getattr(msg, "html", "") or "")
        pre_links = []
    urls = list(pre_links) + re.findall(r"https?://[^\s<>\"']+", body)
    host_urls = [u for u in urls if host in u.lower()]
    if host_urls:
        return {"method": "link", "url": host_urls[0], "code": None,
                "subject": subject, "sender": sender}
    for pat in (re.compile(r"(?:code|pin)[\s:#]*(\d{4,8})", re.I),
                re.compile(r"(\d{4,8})[\s-]*(?:is|as)\s+your", re.I),
                re.compile(r"verification[^0-9]{0,20}(\d{4,8})", re.I),
                re.compile(r"token[\s:]*([A-Za-z0-9_\-]{6,32})", re.I)):
        m = pat.search(body)
        if m:
            return {"method": "code", "url": None, "code": m.group(1),
                    "subject": subject, "sender": sender}
    return {"method": "none", "url": None, "code": None,
            "subject": subject, "sender": sender}

# ─── LOGIN ────────────────────────────────────────────────────────────────
def _attempt_login_v2(host, session, pages, creds):
    login_page = _find_login_form(pages)
    if not login_page: return "failed", ["no_login_form"]
    form = login_page["forms"][0]
    action = form.get("action") or login_page["url"]
    fresh = session.get_with_origin_fallback(login_page["url"])
    if fresh.ok and fresh.status == 200:
        fp = _parse_html(fresh.body, fresh.final_url or fresh.url)
        for f in fp.get("forms", []):
            if f.get("has_password"):
                for fld in f.get("fields", []):
                    if fld.get("csrf"):
                        form.setdefault("fields", []).append(fld)
                break
    payload = _build_form_payload(form, {
        "email": creds.get("email", ""),
        "password": creds.get("password", ""),
        "username": creds.get("username", creds.get("email","").split("@")[0]),
    })
    log.info(f"    login: POST {action[:70]} ({len(payload)} fields)")
    pre = _cookie_signature(session.cookiejar)
    lr = session.post(action, payload, referer=login_page["url"], allow_redirects=False)
    post = _cookie_signature(session.cookiejar)
    final = lr; loc_final = ""
    if lr.status in (301,302,303,307,308):
        loc = (lr.headers or {}).get("Location", "") or (lr.headers or {}).get("location","")
        if loc:
            if loc.startswith("/"): loc = urllib.parse.urljoin(login_page["url"], loc)
            loc_final = loc
            final = session.get_with_origin_fallback(loc)
            post = _cookie_signature(session.cookiejar)
    setattr(session, "last_auth_redirect", loc_final)
    state, markers = _detect_auth_state(final, pre, post, session=session, host=host)
    if state == "ambiguous":
        ph = _try_protected_probe(session, host)
        if ph: return "logged_in", markers + [f"protected_retry:{ph}"]
    return state, markers

# ─── REGISTER ─────────────────────────────────────────────────────────────
def _attempt_register_flow(host, session, pages, outdir, creds_store):
    result = AuthResult(status="not_attempted")
    email_cfg = _cfg("EMAIL")
    if email_cfg is None:
        result.status = "failed"; result.error = "config.EMAIL not available"
        return result
    reg_page = _find_register_form(pages)
    if not reg_page:
        result.status = "failed"; result.error = "no register form found"
        return result
    log.warn(f"    {Sym.WARN}  AUTO-REGISTER on {host}")
    log.warn(f"       Form : {reg_page['url']}")
    log.warn(f"       Email: {email_cfg.address}")
    password = _generate_password()
    username = f"argus_{int(time.time())}"
    form = reg_page["forms"][0]
    action = form.get("action") or reg_page["url"]
    fresh = session.get_with_origin_fallback(reg_page["url"])
    if fresh.ok and fresh.status == 200:
        fp = _parse_html(fresh.body, fresh.final_url or fresh.url)
        for f in fp.get("forms", []):
            if f.get("has_password"):
                for fld in f.get("fields", []):
                    if fld.get("csrf"):
                        form.setdefault("fields", []).append(fld)
                break
    payload = _build_form_payload(form, {
        "email": email_cfg.address, "password": password,
        "password_confirm": password, "username": username,
    })
    pre = _cookie_signature(session.cookiejar)
    log.info(f"    POST register: {action[:60]} ({len(payload)} fields)")
    rr = session.post(action, payload, referer=reg_page["url"], allow_redirects=False)
    post = _cookie_signature(session.cookiejar)
    final = rr; loc_final = ""
    if rr.status in (301,302,303,307,308):
        loc = (rr.headers or {}).get("Location","") or (rr.headers or {}).get("location","")
        if loc:
            if loc.startswith("/"): loc = urllib.parse.urljoin(reg_page["url"], loc)
            loc_final = loc
            final = session.get_with_origin_fallback(loc)
            post = _cookie_signature(session.cookiejar)
    setattr(session, "last_auth_redirect", loc_final)
    entry = {"email": email_cfg.address, "password": password,
             "username": username,
             "registered_at": datetime.now(timezone.utc).isoformat(),
             "register_url": action, "register_status": rr.status,
             "register_final_status": final.status,
             "verified": False, "valid": True, "account_confirmed": False,
             "session_valid": False, "cookies": []}
    state, markers = _detect_auth_state(final, pre, post,
                                        session=session, host=host,
                                        is_post_register=True)
    log.info(f"    register outcome: {state} ({', '.join(markers)})")
    if state == "logged_in":
        log.ok(f"    {Sym.TROPHY} Registered + authenticated (cookies={len(list(session.cookiejar))})")
        entry["verified"] = True; entry["session_valid"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        entry["login_status"] = "immediate_after_register"
        creds_store.set(host, entry)
        return AuthResult(status="logged_in", method="register_immediate_login",
                          email=email_cfg.address, username=username,
                          password=password, register_url=action,
                          cookies_count=len(list(session.cookiejar)),
                          body_markers=markers, session_valid=True)
    if state == "already_exists":
        log.warn("    Account exists — attempting login")
        s2, m2 = _attempt_login_v2(host, session, pages, entry)
        if s2 == "logged_in":
            entry["cookies"] = _serialize_cookies(session.cookiejar)
            entry["verified"] = True; entry["session_valid"] = True
            entry["account_confirmed"] = True
            creds_store.set(host, entry)
            return AuthResult(status="logged_in", method="login_after_exists",
                              email=email_cfg.address, username=username,
                              password=password,
                              cookies_count=len(list(session.cookiejar)),
                              body_markers=markers+m2, session_valid=True)
        creds_store.set(host, entry)
        return AuthResult(status="already_exists", error=s2,
                          email=email_cfg.address, password=password)
    if state == "failed":
        log.error(f"    Registration failed: {markers}")
        creds_store.set(host, entry)
        return AuthResult(status="failed", error="; ".join(markers[:2]),
                          email=email_cfg.address, username=username,
                          password=password)
    if state == "verify_needed":
        log.info(f"    {Sym.MAIL} Verification required — polling inbox")
        return _handle_verification(host, session, pages, outdir,
                                    creds_store, entry, email_cfg)
    # ── v9.0: ambiguous register — check for ANY poll signal before burning 15s
    body_low = (final.body or "")[:5000].lower()
    has_verify_hint = any(h in body_low for h in AUTH_VERIFY_BODY)
    has_session_cookie = len(list(session.cookiejar)) > 0
    if not has_verify_hint and not has_session_cookie:
        log.info("    Register ambiguous — no verify hint, no session cookie — "
                 "skipping inbox poll")
        creds_store.set(host, entry)
        return AuthResult(status="ambiguous_no_signal",
                          email=email_cfg.address, username=username,
                          password=password,
                          error="no verify signal in body, no session cookie — poll skipped")
    log.info(f"    Register ambiguous — short inbox poll ({SHORT_POLL_TIMEOUT:.0f}s)")
    return _handle_verification(host, session, pages, outdir,
                                creds_store, entry, email_cfg,
                                timeout_seconds=SHORT_POLL_TIMEOUT)

# ─── VERIFICATION ─────────────────────────────────────────────────────────
def _handle_verification(host, session, pages, outdir, creds_store, entry, email_cfg,
                         timeout_seconds=None):
    if timeout_seconds is None:
        timeout_seconds = REGISTRATION_TIMEOUT
    fn = _cfg("find_verification_email")
    if not callable(fn):
        log.warn("    find_verification_email unavailable — skipping")
        creds_store.set(host, entry)
        return AuthResult(status="verify_needed", email=email_cfg.address,
                          password=entry["password"],
                          error="no find_verification_email")
    log.info(f"    polling inbox (up to {timeout_seconds:.0f}s)...")
    per = timeout_seconds / len(VERIFY_SUBJECTS)
    msg = None
    for subj in VERIFY_SUBJECTS:
        try: msg = fn(subject_contains=subj, timeout_seconds=per, poll_interval=4.0)
        except Exception: msg = None
        if msg: break
    if not msg:
        log.warn("    no verification email received")
        creds_store.set(host, entry)
        return AuthResult(status="verify_needed", email=email_cfg.address,
                          password=entry["password"],
                          error="no verification email after timeout")
    vi = _extract_verification(msg, host)
    entry["verification_method"] = vi["method"]
    entry["verification_url"] = vi["url"]
    log.info(f"    email: method={vi['method']}")
    if vi["method"] == "link":
        log.ok(f"    {Sym.LINK} Verification link: {vi['url'][:80]}")
        session.get_with_origin_fallback(vi["url"])
        ph = _try_protected_probe(session, host)
        if ph:
            log.ok(f"    {Sym.TROPHY} Magic link logged us in ({ph})")
            entry["cookies"] = _serialize_cookies(session.cookiejar)
            entry["verified"] = True; entry["session_valid"] = True
            entry["login_status"] = "magic_link"
            creds_store.set(host, entry)
            return AuthResult(status="logged_in", method="magic_link",
                              email=email_cfg.address,
                              username=entry.get("username",""),
                              password=entry["password"], verify_url=vi["url"],
                              cookies_count=len(list(session.cookiejar)),
                              protected_urls_hit=[ph], session_valid=True)
        s, m = _attempt_login_v2(host, session, pages, entry)
        if s == "logged_in":
            log.ok(f"    {Sym.TROPHY} Logged in after verification")
            entry["cookies"] = _serialize_cookies(session.cookiejar)
            entry["verified"] = True; entry["session_valid"] = True
            entry["login_status"] = "ok_after_verify_link"
            creds_store.set(host, entry)
            return AuthResult(status="logged_in", method="verify_link_then_login",
                              email=email_cfg.address,
                              username=entry.get("username",""),
                              password=entry["password"], verify_url=vi["url"],
                              cookies_count=len(list(session.cookiejar)),
                              body_markers=m, session_valid=True)
        creds_store.set(host, entry)
        return AuthResult(status="verify_needed", verify_url=vi["url"],
                          email=email_cfg.address, password=entry["password"],
                          error=f"login after verify: {s}")
    if vi["method"] == "code":
        log.ok(f"    {Sym.KEY} Verification code: {vi['code']}")
        ok, det = _attempt_code_verification(vi["code"], host, session, pages)
        entry["code_submit_status"] = "ok" if ok else det
        if ok:
            s, m = _attempt_login_v2(host, session, pages, entry)
            if s == "logged_in":
                log.ok(f"    {Sym.TROPHY} Logged in after code verification")
                entry["cookies"] = _serialize_cookies(session.cookiejar)
                entry["verified"] = True; entry["session_valid"] = True
                entry["login_status"] = "ok_after_verify_code"
                creds_store.set(host, entry)
                return AuthResult(status="logged_in", method="verify_code_then_login",
                                  email=email_cfg.address,
                                  username=entry.get("username",""),
                                  password=entry["password"], verify_code=vi["code"],
                                  cookies_count=len(list(session.cookiejar)),
                                  session_valid=True)
        log.warn(f"    Code submission failed: {det}")
        creds_store.set(host, entry)
        return AuthResult(status="verify_needed", verify_code=vi["code"],
                          email=email_cfg.address, password=entry["password"],
                          error=det)
    log.warn("    no verification method in email")
    creds_store.set(host, entry)
    return AuthResult(status="verify_needed", email=email_cfg.address,
                      password=entry["password"],
                      error="no verification method in email")

def _attempt_code_verification(code, host, session, pages):
    vf = _find_code_verification_form(pages)
    if not vf: return False, "no code form found"
    page, form = vf["page"], vf["form"]
    action = form.get("action") or page["url"]
    method = (form.get("method","POST") or "POST").upper()
    payload = _build_form_payload(form, {
        "code": code,
        "email": (_cfg("EMAIL").address if _cfg("EMAIL") else ""),
    })
    log.info(f"    submit code: {method} {action[:70]} ({len(payload)} fields)")
    pre = _cookie_signature(session.cookiejar)
    if method == "POST":
        res = session.post(action, payload, referer=page["url"])
    else:
        qs = urllib.parse.urlencode(payload)
        sep = "&" if "?" in action else "?"
        res = session.get(f"{action}{sep}{qs}", referer=page["url"])
    post = _cookie_signature(session.cookiejar)
    if res.error and res.status == 0:
        return False, f"submission failed: {res.error}"
    state, markers = _detect_auth_state(res, pre, post, session=session, host=host)
    if state == "logged_in": return True, "code accepted + logged in"
    if state == "failed": return False, "code rejected"
    if res.status in (200, 301, 302, 303):
        return True, f"code accepted (status={res.status}, state={state})"
    return False, f"ambiguous (status={res.status})"

# ─── AUTH FLOW ORCHESTRATOR ───────────────────────────────────────────────
def _do_auth_flow(host, pages, session, outdir, creds_store, attempt_email_verify=True):
    existing = creds_store.get(host)
    if existing and existing.get("valid", True) and existing.get("cookies"):
        loaded = _load_cookies_into_session(session.cookiejar, existing["cookies"], host)
        if loaded > 0:
            ph = _try_protected_probe(session, host)
            if ph:
                log.ok(f"    {Sym.TROPHY} Reused cookies work — {ph}")
                creds_store.mark_session_valid(host)
                return AuthResult(status="logged_in", method="reused_cookies",
                                  email=existing.get("email",""),
                                  username=existing.get("username",""),
                                  password=existing.get("password",""),
                                  cookies_count=len(list(session.cookiejar)),
                                  protected_urls_hit=[ph], session_valid=True)
            log.info("    stored cookies expired")
            session.cookiejar.clear()
            creds_store.mark_session_stale(host)
    if existing and existing.get("valid", True) and existing.get("password"):
        log.info("    attempting login with stored credentials")
        state, markers = _attempt_login_v2(host, session, pages, existing)
        if state == "logged_in":
            existing["cookies"] = _serialize_cookies(session.cookiejar)
            existing["last_login"] = datetime.now(timezone.utc).isoformat()
            existing["session_valid"] = True
            creds_store.set(host, existing)
            return AuthResult(status="logged_in", method="stored_credentials",
                              email=existing.get("email",""),
                              username=existing.get("username",""),
                              password=existing.get("password",""),
                              cookies_count=len(list(session.cookiejar)),
                              body_markers=markers, session_valid=True)
        log.warn(f"    stored creds failed ({state}), attempting register")
        creds_store.mark_invalid(host)
    email_cfg = _cfg("EMAIL")
    if email_cfg is None:
        log.warn("    auto-register: config.EMAIL not available")
        return AuthResult(status="failed", error="no EMAIL configured")
    if not _find_register_form(pages):
        log.info("    auto-register: no register form found")
        return None
    return _attempt_register_flow(host, session, pages, outdir, creds_store)

# ─── POST-AUTH CRAWL ──────────────────────────────────────────────────────
def _post_auth_crawl(host, session, first_result, auth_result=None,
                     max_pages=POST_AUTH_CRAWL_LIMIT):
    new_pages = []; visited = set(); queue = []
    base = session.base_url
    unauth_hashes: dict[str, str] = {}
    unauth_protected: set[str] = set()
    for p in first_result.get("pages", []):
        if p.get("body_preview"):
            unauth_hashes[p["url"]] = hashlib.sha1(
                p["body_preview"].encode("utf-8", "replace")).hexdigest()
        if p.get("status_code") in (401, 403):
            unauth_protected.add(p["url"])
    if auth_result is not None and getattr(auth_result, "redirect_url", ""):
        queue.append((auth_result.redirect_url, 0, None))
        log.info(f"    seed from auth redirect: {auth_result.redirect_url}")
    orig_q = first_result.get("unvisited_queue", [])
    for item in orig_q:
        if len(item) == 3: queue.append(item)
        elif len(item) == 2: queue.append((item[0], item[1], None))
    if orig_q: log.info(f"    carrying forward {len(orig_q)} unvisited URL(s)")
    for path in POST_AUTH_PROBE_PATHS:
        queue.append((base.rstrip("/") + path, 0, None))
    for u in unauth_protected:
        queue.append((u, 0, None))
    while queue and len(new_pages) < max_pages and not session.dead:
        url, depth, ref = queue.pop(0)
        if url in visited: continue
        visited.add(url)
        res = session.get_with_origin_fallback(url, referer=ref)
        if res.error or res.status == 0 or res.status == 404: continue
        final = (res.final_url or res.url).lower()
        if any(p in final for p in AUTH_LOGIN_PATHS) and res.status == 200: continue
        post_hash = hashlib.sha1(
            (_text_preview(res.body or "") or "").encode("utf-8", "replace")).hexdigest()
        was_protected = url in unauth_protected
        seen_preauth = url in unauth_hashes
        if was_protected: is_auth_only = True
        elif seen_preauth: is_auth_only = unauth_hashes[url] != post_hash
        else: is_auth_only = True
        parsed = _parse_html(res.body or "", res.final_url or url)
        page = _build_page_record(res, host, depth, parsed, referer=ref,
                                  authenticated=is_auth_only)
        if is_auth_only:
            page["authenticated"] = True
            page["interesting"] = True
            page["reasons"].append("authenticated_access")
        new_pages.append(page)
        marker = f"{Sym.LOCK}" if is_auth_only else "  "
        if not _SHARED["_quiet"]:
            log.info(f"    {marker} post-auth: [{page['kind']:<8}] "
                     f"{res.status:>3} {page['url'][:60]}"
                     + ("" if is_auth_only else "  (public — unchanged)"))
        for link in parsed.get("links", []):
            n = _normalize_url(link, host)
            if n and n not in visited and depth < 2:
                queue.append((n, depth + 1, page["url"]))
    return new_pages

def _merge_auth_pages(unauth, auth):
    auth_urls = {p["url"] for p in auth}
    merged = [p for p in unauth if p["url"] not in auth_urls]
    merged.extend(auth)
    return merged

# ─── PARALLEL ORCHESTRATOR ────────────────────────────────────────────────
def _process_one_host(args):
    """v9.0 worker — runs in a ThreadPoolExecutor. Must not raise."""
    index, total, host, opts = args
    max_pages = opts["max_pages"]
    max_depth = opts["max_depth"]
    aggressive = opts["aggressive"]
    auto_register = opts["auto_register"]
    respect_robots = opts["respect_robots"]
    bbp_program = opts["bbp_program"]
    use_proxy = opts["use_proxy"]
    origin_fallback = opts["origin_fallback"]
    extra_headers = opts["extra_headers"]
    audit_trail = opts["audit_trail"]
    proxy_pool = opts["proxy_pool"]
    origin_loader = opts["origin_loader"]
    creds_store = opts["creds_store"]
    page_stream_path = opts["page_stream_path"]
    hosts_stream_path = opts["hosts_stream_path"]
    effective_rps = opts["effective_rps"]
    host_timeout = opts["host_timeout"]

    warnings_local: list[str] = []
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"): ks.check()
    except Exception:
        warnings_local.append(f"killswitch: tripped — skipping {host}")
        return {"host": host, "base_url": f"https://{host}", "pages": [],
                "assets_js": [], "assets_css": [], "endpoints": [], "chains": {},
                "session_stats": {}, "dead": True, "dead_reason": "killswitch",
                "ai_summaries": 0, "unvisited_queue": [], "timed_out": False,
                "_warnings": warnings_local}

    if not _SHARED["_quiet"]:
        with _LOG_LOCK:
            log.rune(Rune.RAIDO, f"[{index}/{total}] {host} ──")
    session = HostSession(host, bbp_program=bbp_program,
                          proxy_pool=proxy_pool if use_proxy else None,
                          audit_trail=audit_trail, extra_headers=extra_headers,
                          use_proxy=use_proxy, respect_robots=respect_robots,
                          origin_loader=origin_loader,
                          origin_fallback=origin_fallback,
                          effective_rps=effective_rps)
    if not _SHARED["_quiet"]:
        with _LOG_LOCK:
            log.info(f"    proxy    : {'rotating' if use_proxy else 'direct'}")

    try:
        hr = _crawl_host(host, session, max_pages=max_pages, max_depth=max_depth,
                         aggressive=aggressive, page_stream_path=page_stream_path,
                         host_timeout=host_timeout)
    except Exception as e:
        warnings_local.append(f"host-crawl-exception: {host}: {type(e).__name__}: {e}")
        hr = {"host": host, "base_url": session.base_url, "pages": [],
              "assets_js": [], "assets_css": [], "endpoints": [], "chains": {},
              "session_stats": _stats(session.stats), "dead": True,
              "dead_reason": str(e), "ai_summaries": 0,
              "unvisited_queue": [], "timed_out": False}

    if hr.get("timed_out"):
        warnings_local.append(f"host-timeout: {host} after {host_timeout}s")
    if hr.get("dead"):
        warnings_local.append(f"host-dead: {host}: {hr.get('dead_reason', 'unknown')}")

    auth_pages = [p for p in hr["pages"] if p.get("kind") in ("login","register")]
    if auth_pages and not auto_register and not _SHARED["_quiet"]:
        with _LOG_LOCK:
            log.warn(f"  {Sym.WARN} AUTH SURFACE DETECTED on {host}")
            for ap in auth_pages[:3]:
                log.warn(f"       [{ap['kind']}] {ap['url']}")
            log.warn("       Re-run with --auto-register to crawl auth pages")

    should_try = auto_register or creds_store.get(host) is not None
    if should_try and hr["pages"]:
        try:
            ar = _do_auth_flow(host, hr["pages"], session, page_stream_path.parent, creds_store)
        except Exception as e:
            warnings_local.append(f"auth-exception: {host}: {type(e).__name__}: {e}")
            ar = None
        if ar:
            hr["auth_result"] = {"status": ar.status, "method": ar.method,
                                 "email": ar.email, "detail": ar.error,
                                 "protected_urls_hit": ar.protected_urls_hit,
                                 "session_valid": ar.session_valid}
            if ar.status == "logged_in":
                try:
                    ac = _post_auth_crawl(host, session, hr, auth_result=ar,
                                          max_pages=POST_AUTH_CRAWL_LIMIT)
                except Exception as e:
                    warnings_local.append(f"post-auth-exception: {host}: {e}")
                    ac = []
                if ac:
                    if not _SHARED["_quiet"]:
                        with _LOG_LOCK:
                            log.ok(f"    +{len(ac)} authenticated page(s) discovered")
                    hr["pages"] = _merge_auth_pages(hr["pages"], ac)
                    for p in ac:
                        for cid in p.get("chain_ids", []):
                            hr["chains"].setdefault(cid, []).append(p["url"])

    pages = hr["pages"]
    interesting = sum(1 for p in pages if p.get("interesting"))
    js_ct = sum(1 for p in pages if p.get("scripts"))
    ep_ct = len(hr.get("endpoints", []))
    fw_ct = len({f for p in pages for f in p.get("framework", [])})
    if not _SHARED["_quiet"]:
        with _LOG_LOCK:
            log.ok(f"    ✓ {len(pages)} page(s), {interesting} interesting, "
                   f"{js_ct} JS, {ep_ct} endpoints, {fw_ct} fw")

    hr["_warnings"] = warnings_local
    # Stream host summary (page-level stream already handled in _crawl_host)
    try:
        with _STREAM_LOCK:
            with Path(hosts_stream_path).open("a", encoding="utf-8") as f:
                f.write(json.dumps({k: v for k, v in hr.items() if k != "pages"},
                                   ensure_ascii=False, default=str) + "\n")
    except Exception as e:
        warnings_local.append(f"host-stream-write: {host}: {e}")
    return hr

def run_site_crawl(targets, *, outdir, creds_path=None,
                   max_pages=DEFAULT_MAX_PAGES_PER_HOST,
                   max_depth=DEFAULT_MAX_DEPTH, aggressive=True,
                   auto_register=False, respect_robots=False,
                   bbp_program=None, use_proxy=True, origin_fallback=True,
                   extra_headers=None, resume=False, audit_trail=None,
                   proxy_pool=None, scope_file=None,
                   parallel_hosts=DEFAULT_PARALLEL_HOSTS,
                   host_timeout=DEFAULT_HOST_TIMEOUT,
                   on_progress=None, quiet=False, **kwargs):
    print_banner()
    start = time.monotonic()
    _SHARED["_quiet"] = quiet
    origin_loader = OriginLoader((_cfg("OUTPUT_DIR") or Path("output")) / "origin_hunt.json")
    creds_store = CredentialStore(creds_path or _creds_path(outdir))
    log.info(f"  Creds  : {creds_store.count()} existing account(s)")

    outdir.mkdir(parents=True, exist_ok=True)
    pages_stream = outdir / "site_pages_pages.jsonl"
    pages_stream.write_text("")
    hosts_stream = outdir / "site_pages_hosts.jsonl"
    hosts_stream.write_text("")

    warnings: list[str] = []

    max_pages, max_depth = _effective_limits(max_pages, max_depth)

    if auto_register:
        ec = _cfg("EMAIL")
        if ec is None:
            log.error("  --auto-register requested but config.EMAIL not set")
            auto_register = False
        else:
            log.warn(""); log.warn("  ⚠  AUTO-REGISTER IS ENABLED")
            log.warn(f"  ⚠     Will register accounts using {ec.address}")
            log.warn("  ⚠     Only proceed on AUTHORIZED targets."); log.warn("")

    # ── v9.0: rate division across parallel workers ─────────────────────
    base_rps = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("crawl", {}).get("rps", 4)
    eff_parallel = max(1, parallel_hosts)
    effective_rps = max(1, base_rps // eff_parallel) if eff_parallel > 1 else base_rps

    log.info(f"  Config : parallel_hosts={eff_parallel}  "
             f"rate_per_host={effective_rps}/s (total_cap={base_rps}/s)  "
             f"host_timeout={host_timeout}s")
    if quiet:
        log.info("  Mode   : QUIET (per-page logging suppressed)")

    # ── SIGINT handler ──────────────────────────────────────────────────
    _sigint = {"flag": False}
    def _on_sigint(signum, frame):  # noqa
        if not _sigint["flag"]:
            log.warn("SIGINT — finishing current host batch, writing partial report")
            _sigint["flag"] = True
    prev_sigint = signal.signal(signal.SIGINT, _on_sigint)

    def _progress(stage, payload):
        if on_progress:
            try: on_progress(stage, payload)
            except Exception: pass

    host_results: list = []
    try:
        worker_args = [
            (i, len(targets), host,
             dict(max_pages=max_pages, max_depth=max_depth, aggressive=aggressive,
                  auto_register=auto_register, respect_robots=respect_robots,
                  bbp_program=bbp_program, use_proxy=use_proxy,
                  origin_fallback=origin_fallback, extra_headers=extra_headers,
                  audit_trail=audit_trail, proxy_pool=proxy_pool,
                  origin_loader=origin_loader, creds_store=creds_store,
                  page_stream_path=pages_stream, hosts_stream_path=hosts_stream,
                  effective_rps=effective_rps, host_timeout=host_timeout))
            for i, host in enumerate(targets, 1)
        ]

        if eff_parallel > 1:
            log.info(f"  Crawling {len(targets)} host(s) with {eff_parallel} parallel workers")
            _progress("stage_start", {"stage": "crawl", "hosts": len(targets),
                                       "parallel": eff_parallel})
            with ThreadPoolExecutor(max_workers=eff_parallel) as pool:
                futures = {}
                for wa in worker_args:
                    if _sigint["flag"]:
                        warnings.append(f"sigint-aborted: skipped remaining hosts")
                        break
                    futures[pool.submit(_process_one_host, wa)] = wa[2]
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        hr = future.result()
                        host_results.append(hr)
                        for w in hr.pop("_warnings", []):
                            warnings.append(w)
                        _progress("host_end", {"host": host,
                                                "pages": len(hr.get("pages", [])),
                                                "dead": hr.get("dead", False)})
                    except Exception as e:
                        warnings.append(f"host-worker: {host}: {type(e).__name__}: {e}")
                        _progress("host_error", {"host": host, "error": str(e)})
        else:
            for wa in worker_args:
                if _sigint["flag"]:
                    warnings.append("sigint-aborted: skipped remaining hosts")
                    break
                _progress("host_start", {"host": wa[2], "index": wa[0],
                                          "total": wa[1]})
                hr = _process_one_host(wa)
                host_results.append(hr)
                for w in hr.pop("_warnings", []):
                    warnings.append(w)
                _progress("host_end", {"host": wa[2],
                                        "pages": len(hr.get("pages", [])),
                                        "dead": hr.get("dead", False)})
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        _progress("stage_end", {"stage": "crawl", "completed": len(host_results)})

    # ── Aggregate ───────────────────────────────────────────────────────
    all_pages, all_chains = [], {}
    ai_summaries = 0
    for hr in host_results:
        all_pages.extend(hr.get("pages", []))
        ai_summaries += hr.get("ai_summaries", 0)
        for cid, mem in hr.get("chains", {}).items():
            all_chains.setdefault(cid, []).extend(mem)

    (outdir / "site_pages.json").write_text(
        json.dumps({"hosts": host_results, "total_pages": len(all_pages),
                    "warnings": warnings},
                   indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8")
    (outdir / "site_pages.txt").write_text(
        "\n".join(sorted({p["url"] for p in all_pages})) + "\n", encoding="utf-8")
    (outdir / "auth_pages.txt").write_text(
        "\n".join(sorted({p["url"] for p in all_pages
                          if p.get("kind") in ("login","register")
                          or p.get("authenticated")})) + "\n", encoding="utf-8")

    elapsed = time.monotonic() - start
    _print_summary(host_results, all_pages, all_chains, elapsed, ai_summaries, warnings)
    return {"hosts": host_results, "total_pages": len(all_pages),
            "chains": all_chains, "elapsed_sec": elapsed,
            "warnings": warnings, "parallel_hosts": eff_parallel,
            "rate_per_host": effective_rps}

def _print_summary(host_results, all_pages, chains, elapsed, ai_summaries, warnings=None):
    log.rune(Rune.SOWILO, "Summary")
    dead = [h for h in host_results if h.get("dead")]
    log.info(f"  Hosts crawled    : {len(host_results)}")
    log.info(f"  Dead (unreach.)  : {len(dead)}")
    log.info(f"  Total pages      : {len(all_pages)}")
    auth_h = [h for h in host_results if (h.get("auth_result") or {}).get("status") == "logged_in"]
    pend_h = [h for h in host_results if (h.get("auth_result") or {}).get("status") == "verify_needed"]
    fail_h = [h for h in host_results if (h.get("auth_result") or {}).get("status") == "failed"]
    skip_h = [h for h in host_results if (h.get("auth_result") or {}).get("status") == "ambiguous_no_signal"]
    auth_ct = sum(1 for p in all_pages if p.get("authenticated"))
    if auth_h:
        log.info(f"  Authenticated    : {len(auth_h)} host(s)")
        for h in auth_h:
            log.ok(f"    ✓ {h['host']:44s} ({h['auth_result'].get('method','?')})")
    if pend_h:
        log.info(f"  Auth pending     : {len(pend_h)} host(s)")
        for h in pend_h:
            log.warn(f"    ⚠ {h['host']:44s}")
    if fail_h:
        log.info(f"  Auth failed      : {len(fail_h)} host(s)")
        for h in fail_h:
            log.error(f"    ✗ {h['host']:44s}")
    if skip_h:
        log.info(f"  Auth skipped     : {len(skip_h)} host(s) (no verify signal — poll skipped)")
    if auth_ct: log.info(f"  Auth-gated pages : {auth_ct}")
    kinds = {}
    for p in all_pages:
        k = p.get("kind","public"); kinds[k] = kinds.get(k,0) + 1
    if kinds:
        log.info("  By kind          : " +
                 " · ".join(f"{k}({v})" for k, v in sorted(kinds.items())))
    fws = {}
    for p in all_pages:
        for f in p.get("framework", []): fws[f] = fws.get(f,0) + 1
    if fws:
        log.info("  By framework     : " +
                 " · ".join(f"{k}({v})" for k, v in sorted(fws.items(), key=lambda x: -x[1])[:5]))
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for p in all_pages:
        s = p.get("severity","INFO")
        if s in sev: sev[s] += 1
    log.info(f"  Severity         : CRITICAL={sev['CRITICAL']} "
             f"HIGH={sev['HIGH']} MEDIUM={sev['MEDIUM']} LOW={sev['LOW']}")
    if ai_summaries: log.info(f"  AI summaries     : {ai_summaries}")
    if warnings:
        log.info(""); log.info("  Warnings:")
        for w in warnings[:10]:
            log.warn(f"    {w}")
        if len(warnings) > 10:
            log.info(f"    … and {len(warnings) - 10} more (see site_pages.json)")
    if chains:
        log.info(""); log.info("  Chains:")
        ordered = sorted(chains.keys(), key=lambda c: -CHAIN_SEVERITY.get(c, Severity.LOW).rank)
        for cid in ordered:
            sv = CHAIN_SEVERITY.get(cid, Severity.LOW)
            log.info(f"    ➤ {cid:32s} [{sv.value:<6s}] {len(chains[cid]):>3} — {CHAIN_NAMES.get(cid,cid)}")
    log.info(""); log.info("  Outputs:")
    for fn in ("site_pages.json","site_pages_hosts.jsonl","site_pages_pages.jsonl",
               "site_pages.txt","auth_pages.txt"):
        log.info(f"    ➤ {fn}")
    log.info(""); log.ok(f"  Completed in {elapsed:.1f}s")

# ─── SELFTEST ─────────────────────────────────────────────────────────────
def selftest():
    print_banner(); log.rune(Rune.KANO, "Selftest")
    fails, total = 0, 0
    def _ck(name, cond, detail=""):
        nonlocal fails, total
        total += 1
        if cond: log.ok(f"  ✓ {name}")
        else: fails += 1; log.error(f"  ✗ {name}  {detail}")

    _ck("classify register (path)", _classify_page("https://h/register","",[],{})[0] == "register")
    _ck("classify login (path)", _classify_page("https://h/login.php","",[],{})[0] == "login")
    _ck("classify admin", _classify_page("https://h/admin/","",[],{})[0] == "admin")
    _ck("classify debug", _classify_page("https://h/debug","",[],{})[0] == "debug")
    form_no_confirm = [{"has_password": True, "has_file_upload": False,
                        "has_code_field": False, "action": "/register",
                        "fields": [{"name":"email","type":"email","value":"","csrf":False,"code":False},
                                   {"name":"username","type":"text","value":"","csrf":False,"code":False},
                                   {"name":"password","type":"password","value":"","csrf":False,"code":False}]}]
    k, _ = _classify_page("https://h/signup","",form_no_confirm,{})
    _ck("classify register (no confirm)", k == "register", f"got {k}")
    from types import SimpleNamespace
    def _fr(status=200, loc="", body=""):
        return SimpleNamespace(status=status, headers={"Location":loc} if loc else {},
                               body=body, url="u", final_url="u", latency_ms=0.0,
                               error=None, error_category=None, via_origin=None)
    b = frozenset(); a = frozenset([("session","abc")])
    st, _ = _detect_auth_state(_fr(status=302, loc="/dashboard"), b, a)
    _ck("auth: cookie+redirect → logged_in", st == "logged_in", f"got {st}")
    st, _ = _detect_auth_state(_fr(200), b, a)
    _ck("auth: cookie only → ambiguous", st == "ambiguous", f"got {st}")
    st, _ = _detect_auth_state(_fr(200, body="check your email for the verification link"), b, b)
    _ck("auth: verify marker → verify_needed", st == "verify_needed", f"got {st}")
    st, _ = _detect_auth_state(_fr(200, body="this username is already taken"), b, b, is_post_register=True)
    _ck("auth: exists → already_exists", st == "already_exists", f"got {st}")
    st, _ = _detect_auth_state(_fr(200, body="invalid credentials"), b, b)
    _ck("auth: failure → failed", st == "failed", f"got {st}")
    unauth = [{"url":"https://h/a"},{"url":"https://h/b"}]
    auth = [{"url":"https://h/b","authenticated":True}]
    m = _merge_auth_pages(unauth, auth)
    _ck("merge: auth replaces unauth", len(m) == 2 and
        any(p["url"] == "https://h/b" and p.get("authenticated") for p in m))
    html_csrf = ('<form action="/login" method="POST">'
                 '<input type="hidden" name="csrf_token" value="abc123">'
                 '<input type="text" name="email">'
                 '<input type="password" name="password"></form>')
    parsed = _parse_html(html_csrf, "https://h/login")
    _ck("csrf: detected hidden token",
        any(f.get("csrf") for form in parsed.get("forms", [])
            for f in form.get("fields", [])))
    _ck("secrets: AWS key detected",
        any(s["kind"] == "aws_access_key" for s in _detect_secrets("key is AKIAABCDEFGHIJKLMNOP end")))
    _ck("secrets: placeholder not flagged",
        not _detect_secrets('api_key="your_api_key_here_xxxxxxxx"'))
    _ck("secrets: private key block detected",
        any(s["kind"] == "private_key_block" for s in _detect_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")))
    _ck("sql error: mysqli signature",
        _detect_sql_error("Warning: mysqli_query(): Unknown column"))
    _ck("sql error: clean body not flagged",
        not _detect_sql_error("Welcome to our totally normal homepage"))
    _ck("stack trace: python traceback",
        _detect_stack_trace("Traceback (most recent call last):\n  File x"))
    _ck("dir listing: apache-style index",
        _detect_dir_listing("<html><body>Parent Directory</a></body></html>", "Index of /backups"))
    _ck("debug banner: werkzeug",
        _detect_debug_banner("The Werkzeug Debugger is active"))
    _ck("reflected param: query value echoed",
        _detect_reflected_params("https://h/s?q=unlikelytoken9981",
                                 "no results for unlikelytoken9981") == ["q"])
    _ck("reflected param: short/common values ignored",
        _detect_reflected_params("https://h/s?ok=true&id=5", "ok true 5 shown") == [])
    _ck("cookie audit: flags missing Secure/HttpOnly",
        _audit_cookie_flags(["session_id=abc123; Path=/"]) and
        set(_audit_cookie_flags(["session_id=abc123; Path=/"])[0]["missing"]) == {"Secure","HttpOnly","SameSite"})
    _ck("cookie audit: fully-flagged cookie passes clean",
        not _audit_cookie_flags(["session_id=abc; Path=/; Secure; HttpOnly; SameSite=Strict"]))
    _ck("cookie audit: non-auth cookie ignored",
        not _audit_cookie_flags(["theme=dark; Path=/"]))
    _ck("mixed content: http asset on https page",
        _detect_mixed_content("https://h/page", ["http://h/old.js"], [], []))
    _ck("mixed content: all-https page clean",
        not _detect_mixed_content("https://h/page", ["https://h/new.js"], [], []))
    secret_page = {"secrets_found": [{"kind": "aws_access_key", "sample": "AKIA…ABCD"}],
                   "kind": "public", "params": [], "forms": []}
    score, sev = _heuristic_score(secret_page)
    _ck("scoring: secret exposure forces CRITICAL", sev == Severity.CRITICAL, f"got {sev} (score={score})")
    ai_sig_a = _ai_content_signature({"kind":"public","status_code":200,"title":"Item",
                                      "params":["id"],"forms":[]})
    ai_sig_b = _ai_content_signature({"kind":"public","status_code":200,"title":"Item",
                                      "params":["id"],"forms":[]})
    _ck("ai cache: identical page structure hashes identically", ai_sig_a == ai_sig_b)

    # ── v9.0 new selftests ────────────────────────────────────────────────
    # Query-string tracking-param strip
    norm_nd = _normalize_url("https://h.example/?ND", "h.example")
    _ck("v9.0: ?ND normalizes to no-query", norm_nd == "https://h.example/", f"got {norm_nd}")
    norm_utm = _normalize_url("https://h.example/p?utm_source=x&page=2", "h.example")
    _ck("v9.0: utm_* stripped, page kept", norm_utm == "https://h.example/p?page=2", f"got {norm_utm}")
    norm_mix = _normalize_url("https://h.example/p?id=5&fbclid=abc", "h.example")
    _ck("v9.0: fbclid stripped, id kept", norm_mix == "https://h.example/p?id=5", f"got {norm_mix}")
    # BOM/CRLF/inline-comment handling in _load_targets
    import tempfile
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
        tf.write(b"\xef\xbb\xbfhost1.example\r\nhost2.example  # trailing\r\n\r\n# full-line\r\n")
        tmp = Path(tf.name)
    try:
        loaded = _load_targets(str(tmp))
        _ck("v9.0: BOM+CRLF+inline-comment in _load_targets",
            loaded == ["host1.example","host2.example"], f"got {loaded}")
    finally:
        tmp.unlink(missing_ok=True)
    # Locks exist
    _ck("v9.0: _AI_LOCK exists", isinstance(_AI_LOCK, type(threading.Lock())))
    _ck("v9.0: _CREDS_LOCK exists", isinstance(_CREDS_LOCK, type(threading.Lock())))
    _ck("v9.0: _STREAM_LOCK exists", isinstance(_STREAM_LOCK, type(threading.Lock())))

    log.info("")
    if fails == 0:
        log.ok(f"  ══ ALL {total} TESTS PASSED ══"); return 0
    log.error(f"  ══ {fails}/{total} TESTS FAILED ══"); return 1

def config_check():
    print_banner(); log.rune(Rune.KANO, "Config check")
    if not CFG_LOADED:
        log.error("  config.py could not be imported"); return 1
    keys = ["SCOPE","EMAIL","OUTPUT_DIR","AI_ENABLED","BBP_PROGRAM",
            "RateLimiter","KillSwitch","human_delay","random_user_agent",
            "build_headers","find_verification_email","log"]
    for k in keys:
        v = _cfg(k)
        if v is None: log.warn(f"  ✗ {k}  (missing)")
        else:         log.ok(f"  ✓ {k}  {type(v).__name__}")
    return 0

# ─── CLI ──────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(description="Sköll — site crawler v9.0")
    p.add_argument("--input", default=None,
                   help="Live hosts JSON or plaintext list (default: output/live_hosts.json)")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--creds-path", default=None)
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES_PER_HOST)
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p.add_argument("--aggressive", action="store_true", default=True)
    p.add_argument("--no-aggressive", dest="aggressive", action="store_false")
    p.add_argument("--auto-register", action="store_true", default=False,
                   help="⚠ Only on AUTHORIZED targets — registers accounts via config.EMAIL")
    p.add_argument("--respect-robots", action="store_true", default=False)
    p.add_argument("--bbp", default=None, help="bug bounty program (hackerone|bugcrowd|generic|none)")
    p.add_argument("--no-proxy", action="store_true", default=False)
    p.add_argument("--no-origin-fallback", action="store_true", default=False)
    p.add_argument("--resume", action="store_true", default=False)
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--log-level", default="info", choices=["debug","info","warn","error","fatal"])
    p.add_argument("--ai-max-pages", type=int, default=None,
                   help="override config.AI_MAX_PAGES for this run")
    p.add_argument("--no-ai", action="store_true", default=False,
                   help="force static-analysis-only triage even if config.AI_ENABLED is True")
    # v9.0 additions
    p.add_argument("--parallel-hosts", type=int, default=DEFAULT_PARALLEL_HOSTS,
                   help=f"parallel host workers (default {DEFAULT_PARALLEL_HOSTS}). "
                        f"Rate limit is divided across workers.")
    p.add_argument("--host-timeout", type=int, default=DEFAULT_HOST_TIMEOUT,
                   help=f"max seconds per host (default {DEFAULT_HOST_TIMEOUT}s)")
    p.add_argument("--quiet", action="store_true", default=False,
                   help="suppress per-page logging; keep summary")
    return p

def _load_targets(input_path):
    """v9.0: BOM-safe, inline-comment-aware, trailing-dot-stripped."""
    p = Path(input_path)
    if not p.exists():
        log.error(f"input not found: {input_path}"); return []
    try:
        raw = p.read_text(encoding="utf-8-sig").strip()
    except Exception:
        raw = p.read_text(encoding="utf-8", errors="replace").strip()
    if not raw: return []
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
            hosts = data.get("hosts", []) if isinstance(data, dict) else data
            out = []
            for h in hosts:
                if isinstance(h, str): out.append(h.lower().rstrip("."))
                elif isinstance(h, dict):
                    hn = h.get("host") or h.get("hostname") or h.get("url") or ""
                    if hn: out.append(hn.lower().rstrip("."))
            return sorted(set(out))
        except Exception: return []
    out = set()
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"): continue
        if " #" in ln: ln = ln.split(" #", 1)[0].strip()
        if ln: out.add(ln.lower().rstrip("."))
    return sorted(out)

def main(argv=None):
    args = build_parser().parse_args(argv)
    if hasattr(log, "min_level"): log.min_level = args.log_level
    if args.no_ai:
        _RUNTIME_CFG_OVERRIDES["AI_ENABLED"] = False
    if args.ai_max_pages is not None:
        _RUNTIME_CFG_OVERRIDES["AI_MAX_PAGES"] = args.ai_max_pages
    if args.selftest: return selftest()
    if args.config_check: return config_check()

    print_banner()
    outdir = Path(args.output_dir) if args.output_dir else (_cfg("OUTPUT_DIR") or Path("output"))
    input_path = args.input if args.input else str(outdir / "live_hosts.json")
    targets = _load_targets(input_path)
    if not targets:
        log.error(f"no targets loaded from {input_path}"); return 1
    log.info(f"  Targets  : {len(targets)}")

    audit = None
    try:
        AT = _cfg("AuditTrail")
        if AT and hasattr(AT, "create"):
            audit = AT.create("crawl", scope=str(_cfg("SCOPE", "unknown")))
    except Exception: pass

    proxy_pool = None
    if not args.no_proxy:
        try:
            PP = _cfg("ProxyPool")
            if PP: proxy_pool = PP.from_config()
        except Exception: pass

    try:
        result = run_site_crawl(
            targets, outdir=outdir,
            creds_path=Path(args.creds_path) if args.creds_path else None,
            max_pages=args.max_pages, max_depth=args.max_depth,
            aggressive=args.aggressive, auto_register=args.auto_register,
            respect_robots=args.respect_robots, bbp_program=args.bbp,
            use_proxy=not args.no_proxy,
            origin_fallback=not args.no_origin_fallback,
            resume=args.resume, audit_trail=audit, proxy_pool=proxy_pool,
            parallel_hosts=args.parallel_hosts,
            host_timeout=args.host_timeout,
            quiet=args.quiet,
        )
    except KeyboardInterrupt:
        log.warn("  interrupted"); return 130
    except Exception as e:
        log.error(f"  fatal: {type(e).__name__}: {e}")
        import traceback; traceback.print_exc()
        return 1

    host_count = len(result.get("hosts", []))
    if host_count == 0: return 1
    live = sum(1 for h in result.get("hosts", []) if not h.get("dead"))
    if live == 0: return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
