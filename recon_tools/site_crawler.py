#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛊ ᚲ ᛟ ᛚ ᛚ   ·   S I T E   C R A W L E R   ·   S K Ö L L   R A V E N B O U N D
================================================================================
  File      : recon_tools/site_crawler.py
  Version   : 8.0.0 "SKÖLL RAVENBOUND"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  v8.0 changes vs v7.0:
    [FIX]  URL patterns for /register.php /login.html /signup.aspx etc. now
           match with the file extension (was silently falling through to
           form analysis and often misclassifying as "login")
    [FIX]  _classify_page() no longer requires a "confirm password" field to
           classify as register. Uses a confidence-ordered heuristic:
           confirm-field → password+email+username → 3+ text inputs
    [FIX]  POST now supports allow_redirects=False so we can inspect Location
           headers for auth success/verify/failure signals
    [FIX]  CredentialStore version 2 — persists cookies for resume without
           re-auth
    [NEW]  _detect_auth_state() — 5-outcome classifier:
           logged_in / verify_needed / already_exists / failed / ambiguous
    [NEW]  Cookie-diff auth detection (session/token/jwt/connect.sid names)
    [NEW]  _attempt_login_v2() — inspect redirects, detect success markers
    [NEW]  Immediate-auth after register (no 180s wasted on email polling
           when the site drops the session cookie on the register response)
    [NEW]  Magic-link detection (verify link sets cookies → skip login)
    [NEW]  _handle_verification() — poll email, extract link OR code, submit
    [NEW]  _post_auth_crawl() — full BFS of authenticated surface (100 pages)
    [NEW]  Reused-cookies path — probe /dashboard, /account, /profile directly
    [NEW]  LOUD warning when auth pages detected but --auto-register is off
    [NEW]  auth_result embedded in host record for downstream consumers
================================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import html as html_lib
import http.cookiejar
import json
import logging
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.cookiejar import Cookie
from pathlib import Path
from typing import Any, Callable, Optional


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  CONFIG INTEGRATION
# ══════════════════════════════════════════════════════════════════════════

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    import config as CFG
    CFG_LOADED = True
    _CFG_IMPORT_ERROR: Optional[Exception] = None
except ImportError as _cfg_err:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False
    _CFG_IMPORT_ERROR = _cfg_err


def _cfg(key: str, default: Any = None) -> Any:
    return getattr(CFG, key, default) if CFG_LOADED else default


class _FallbackPalette:
    _enabled = sys.stdout.isatty()
    _R = {"reset": "\033[0m", "dim": "\033[2m",
          "gold": "\033[38;5;220m", "amber": "\033[38;5;214m",
          "purple": "\033[38;5;135m", "violet": "\033[38;5;93m",
          "crimson": "\033[38;5;160m", "blood": "\033[38;5;196m",
          "green": "\033[38;5;46m", "cyan": "\033[38;5;51m",
          "grey": "\033[38;5;242m"}

    @classmethod
    def c(cls, name: str) -> str:
        return cls._R.get(name, "") if cls._enabled else ""


def _c(name: str) -> str:
    if CFG_LOADED and hasattr(CFG, "_c"):
        return CFG._c(name)
    return _FallbackPalette.c(name)


class _FallbackLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self):
        self.min_level = "info"

    def _emit(self, level, msg, color, prefix):
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")

    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info (self, m): self._emit("info",  m, "cyan", "·")
    def warn (self, m): self._emit("warn",  m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def ok   (self, m): self._emit("info",  m, "green", "✓")

    def rune(self, rune, msg):
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")


log = _cfg("log") or _FallbackLogger()


class Sym:
    STAR = "★"; ARROW = "➤"; CHECK = "✓"; CROSS = "✗"
    WARN = "⚠"; INFO = "·"; DOT = "᛫"; SKULL = "☠"
    SHIELD = "🛡"; WOLF = "🐺"; LOCK = "🔒"; GEAR = "⚙"; SHAMROCK = "☘"
    LINK = "🔗"; KEY = "🔑"; MAIL = "📧"; FIRE = "🔥"; TROPHY = "🏆"


class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


__version__ = "8.0.0"
__codename__ = "SKÖLL RAVENBOUND"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛊ ᚲ ᛟ ᛚ ᛚ{R}
    {P}{rule}{R}
    {V}      S I T E   C R A W L E R   ·   T H E   P U R S U E R{R}
    {V}              R A V E N B O U N D   ·   v{__version__}{R}
    {D}{rule}{R}
    {G}        {Sym.WOLF}  "{__codename__}"  ·  auth-native · WAF-aware{R}
    {G}        {Sym.GEAR}  config v{_cfg('__version__', 'missing')} {R}
    {G}        {Sym.SHAMROCK}  BeardedVikingTX  ·  {_cfg('AUTHOR_EMAIL', 'security@beardedviking.org')}{R}
    {P}{rule}{R}
""")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SEVERITY
# ══════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════

DEFAULT_MAX_PAGES_PER_HOST = 200
DEFAULT_MAX_DEPTH          = 3
DEFAULT_TIMEOUT            = 15.0
DEFAULT_PAGE_DELAY         = 0.6
DEFAULT_MAX_BODY_BYTES     = 2_000_000
REGISTRATION_TIMEOUT       = 180.0
CIRCUIT_BREAK_THRESHOLD    = 3
CREDS_FILE_NAME            = ".argus_creds.json"

AI_PAGE_SUMMARY_LIMIT   = 15
JS_FETCH_LIMIT          = 10
CSS_FETCH_LIMIT         = 5
ENDPOINT_PROBE_LIMIT    = 30
POST_AUTH_CRAWL_LIMIT   = 100

HUMAN_PAUSE_CHANCE      = 0.10
HUMAN_PAUSE_RANGE       = (5.0, 15.0)
PAGE_SKIP_CHANCE        = 0.05

PROTOCOL_PATHS = ("/robots.txt", "/sitemap.xml")

# ═══ v8.0 AUTH DETECTION CONSTANTS ═══
AUTH_SUCCESS_PATHS = (
    "dashboard", "account", "profile", "home", "me", "user",
    "welcome", "my-account", "settings", "members", "admin/", "console",
)
AUTH_LOGIN_PATHS  = ("login", "signin", "sign-in", "log-in", "auth")
AUTH_VERIFY_PATHS = (
    "verify", "confirm", "activate", "check-email",
    "verify-email", "confirm-email", "email-verification",
)
AUTH_SUCCESS_BODY = (
    "welcome, ", "welcome back", "dashboard", "logged in", "signed in",
    "you're in", "sign out", "log out", "logout", "my account",
    "your profile", "account settings",
)
AUTH_VERIFY_BODY = (
    "check your email", "verify your email", "verification email",
    "confirmation email", "email sent", "verification sent",
    "check your inbox", "click the link", "we've sent", "we have sent",
    "confirmation link", "verify your account",
)
AUTH_FAILURE_BODY = (
    "wrong password", "bad credentials", "invalid credentials",
    "invalid password", "incorrect password", "login failed",
    "authentication failed", "invalid username",
)
AUTH_EXISTS_BODY = (
    "already exists", "already registered", "already taken",
    "email already", "username already", "account already",
)
AUTH_COOKIE_NAMES = (
    "session", "sessid", "phpsessid", "jsessionid", "auth",
    "token", "jwt", "logged_in", "user_id", "authenticated",
    "remember", "access_token", "refresh_token", "connect.sid",
)
# v8.1 — expanded success markers (only appear when logged in)
AUTH_SUCCESS_BODY = (
    "welcome, ", "welcome back", "signed in", "you're in",
    "sign out", "log out", "logout", "my account", "your profile",
    "account settings", "edit profile", "my orders", "purchase history",
    "sign out of", "session active",
)

# v8.1 — deny markers (only appear when NOT logged in — redirect fallback)
AUTH_DENY_BODY = (
    "please log in", "please login", "you must be logged in",
    "authentication required", "login required", "session expired",
    "access denied", "not authenticated", "unauthorized",
    "you need to sign in", "sign in to continue",
)

AUTH_COOKIE_NAMES = (
    "session", "sessid", "phpsessid", "jsessionid", "auth",
    "token", "jwt", "logged_in", "user_id", "authenticated",
    "remember", "access_token", "refresh_token", "connect.sid",
    # v8.1 — expanded framework-cookie patterns:
    "ci_session", "laravel_session", "django_session",
    "asp.net_sessionid", "codeigniter", "_session_id",
    "_shopify_s", "shopify_s", "wp_woocommerce_session",
    "wordpress_logged_in", "wp-settings", "drupal_session",
    "symfony", "sf_redirect", "grails", "play_session",
)

POST_AUTH_PROBE_PATHS = (
    # v8.1 — expanded probes:
    "/", "/dashboard", "/account", "/profile", "/settings",
    "/me", "/user", "/user/profile", "/user/settings", "/user/account",
    "/members", "/admin", "/admin/dashboard", "/home",
    "/my-account", "/my/profile", "/orders", "/order-history",
    "/wallet", "/balance", "/messages", "/inbox", "/invoices",
    "/billing", "/subscription", "/notifications", "/activity",
)

# ═══ v8.2 LANDING PAGE DETECTION ═══════════════════════════════════════════
# After POST /register or /login we land on some page. That page's URL,
# query params, body text, and forms tell us what to do next. We check
# in strict priority order so we never waste 180s polling email when the
# site already logged us in.

LANDING_STATE_LOGGED_IN      = "logged_in"
LANDING_STATE_VERIFY_CODE    = "verify_code"
LANDING_STATE_VERIFY_LINK    = "verify_link"
LANDING_STATE_VERIFY_EITHER  = "verify_either"
LANDING_STATE_VERIFY_AUTO    = "verify_auto"
LANDING_STATE_PENDING_MANUAL = "pending_manual"
LANDING_STATE_RATE_LIMITED   = "rate_limited"
LANDING_STATE_FAILED         = "failed"
LANDING_STATE_AMBIGUOUS      = "ambiguous"

# Body-text markers — check RATE_LIMITED and FAILED first (don't hammer, don't poll)
LANDING_BODY_RATE_LIMITED = (
    "too many attempts", "too many requests", "rate limited",
    "try again later", "try again in", "slow down",
    "captcha", "recaptcha", "hcaptcha", "cf-turnstile", "turnstile",
    "verify you are human", "verify you're human", "suspicious activity",
    "unusual traffic", "automated queries",
)
LANDING_BODY_FAILED = (
    "invalid credentials", "wrong password", "incorrect password",
    "bad credentials", "invalid password", "invalid username",
    "invalid email", "user not found", "account not found",
    "login failed", "authentication failed", "email not recognized",
    "unknown user", "invalid login", "access denied",
)
LANDING_BODY_ALREADY_EXISTS = (
    "already exists", "already registered", "already taken",
    "email already", "username already", "account already",
    "is already in use", "has been taken",
)
LANDING_BODY_VERIFY_CODE = (
    "enter the code", "enter code", "enter the verification code",
    "enter verification code", "enter your code", "enter the otp",
    "enter otp", "verification code", "verification pin",
    "one-time password", "one time password", "6-digit code",
    "4-digit code", "5-digit code", "8-digit code",
    "we sent", "we've sent", "we have sent", "sent to your email",
    "sent to your inbox", "code has been sent", "code was sent",
    "code sent to", "sent a code", "sent an otp",
)
LANDING_BODY_VERIFY_LINK = (
    "click the link", "click the verification link", "click here to verify",
    "click the link in the email", "click the link in your email",
    "follow the link", "verification link", "confirmation link",
    "activation link", "email verification link", "activation email",
    "we sent you a link", "we've sent you a link",
    "check your email for a link", "check your email for the link",
    "link has been sent", "link was sent",
)
LANDING_BODY_VERIFY_EITHER = (
    "check your email", "check your inbox", "check your mail",
    "verify your email", "verify your account", "confirm your email",
    "confirm your account", "email sent", "verification sent",
    "confirmation sent", "verification email sent",
    "confirmation email sent", "check your inbox to verify",
    "must be verified", "email not verified", "please verify",
    "please confirm", "confirm to continue", "verify to continue",
)
LANDING_BODY_PENDING_MANUAL = (
    "pending approval", "awaiting approval", "waiting for approval",
    "under review", "pending review", "awaiting review",
    "waiting for review", "account pending", "account under review",
    "will be reviewed", "will be activated", "will be approved",
    "administrator will", "admin will review",
)
LANDING_BODY_LOGGED_IN = (
    "sign out", "sign-out", "log out", "log-out", "logout",
    "my account", "your profile", "account settings", "edit profile",
    "welcome,", "welcome back", "you're logged in", "you are logged in",
    "signed in as", "logged in as", "my dashboard", "your dashboard",
    "change password", "update profile",
    "my orders", "order history", "purchase history",
    "my messages", "my notifications", "my inbox",
)

# URL path hints (checked as fallback when body is inconclusive, e.g. SPA)
LANDING_PATH_LOGGED_IN = (
    "dashboard", "account", "profile", "settings", "welcome", "home",
    "my-account", "members", "console", "control-panel", "portal",
    "private", "app", "app/", "user/",
)
LANDING_PATH_VERIFY_CODE = (
    "verify-code", "verify_code", "confirm-code", "enter-code",
    "enter_code", "verification-code", "otp", "2fa", "mfa",
    "check-email", "verify-otp",
)
LANDING_PATH_VERIFY_LINK = (
    "verify", "verification", "confirm", "activate", "validate",
    "verify-email", "confirm-email", "email-verification",
    "activate-account", "confirm-account",
)
LANDING_PATH_PENDING = (
    "pending", "awaiting", "waiting", "review", "approval",
    "pending-approval", "awaiting-verification",
)
LANDING_PATH_LOGIN  = ("login", "signin", "sign-in", "log-in", "auth")
LANDING_PATH_REGISTER = ("register", "signup", "sign-up", "create-account")

# Query-param key hints (checked on the LANDING url after following redirects)
LANDING_QUERY_SUCCESS = (
    "verified", "activated", "confirmed", "success", "welcome",
    "logged_in", "loggedin", "auth", "ok", "done", "complete", "verified_email",
)
LANDING_QUERY_PENDING = (
    "pending", "waiting", "awaiting", "review", "approval",
    "unverified", "not_verified", "needs_verification",
)
LANDING_QUERY_ERROR = (
    "error", "err", "failed", "fail", "invalid", "denied",
    "bad", "expired", "wrong", "invalid_token", "invalid_code",
)
LANDING_QUERY_TOKEN = (
    "code", "token", "verify", "verification", "activation",
    "activate", "confirm", "otp", "key", "hash", "sig", "t",
)

# Form field names we look for on the landing page
LANDING_FORM_CODE_FIELDS = (
    "code", "otp", "pin", "verification_code", "verify_code",
    "auth_code", "security_code", "totp", "mfa_code",
)

# WAF detection
WAF_BLOCK_STATUSES = {403, 429, 503, 520, 521, 522, 523, 524, 525, 526, 530}
WAF_HEADER_MARKERS = (
    "cf-mitigated", "cf-ray", "cf-chl-bypass", "cf-cache-status",
    "x-akamai-bot-manager", "x-akamai-transformed",
    "x-iinfo", "x-sucuri-block", "x-datadome",
    "x-wa-info", "bigipserver",
)
WAF_BODY_MARKERS = (
    "attention required! | cloudflare",
    "just a moment...",
    "checking your browser",
    "please wait while we verify",
    "ddos-guard",
    "enable javascript and cookies to continue",
)

# ── v8.0 URL PATH PATTERNS — with extension support ──
LOGIN_PATTERNS = re.compile(
    r"/(login|signin|sign-in|log-in|authenticate|auth|session|sso|signon)"
    r"(\.\w+)?(/|$|\?)", re.I)
REGISTER_PATTERNS = re.compile(
    r"/(register|signup|sign-up|create[-_]?account|join|onboard|registration)"
    r"(\.\w+)?(/|$|\?)", re.I)
ADMIN_PATTERNS = re.compile(
    r"/(admin|dashboard|console|management|internal|cp|panel|backoffice)"
    r"(\.\w+)?(/|$|\?)", re.I)
API_PATTERNS = re.compile(r"/(api|graphql|rest|gql|v\d+)(\.\w+)?(/|$|\?)", re.I)
DEBUG_PATTERNS = re.compile(
    r"/(debug|actuator|phpinfo|trace|swagger|api-docs|\.env)"
    r"(\.\w+)?(/|$|\?)", re.I)

STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib",
)

JS_ENDPOINT_RE = re.compile(
    r"""['"]((?:https?://|//)[A-Za-z0-9_\-./?=&%:{}]+|/[A-Za-z0-9_\-./?=&%:{}]{2,120})['"]""")
JS_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]""")
JS_AJAX_RE  = re.compile(r"""\$\.[a-z]+\s*\(\s*['"]([^'"]+)['"]""")
JS_AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""")

PASSWORD_FIELD_RE = re.compile(r"(password|passwd|pwd|pass)", re.I)
CONFIRM_FIELD_RE  = re.compile(r"(confirm|repeat|verify|retype)", re.I)
EMAIL_FIELD_RE    = re.compile(r"(email|e-mail|mail)", re.I)
USERNAME_FIELD_RE = re.compile(r"(user|login|account|name)", re.I)
CSRF_FIELD_RE     = re.compile(r"(csrf|_token|authenticity|__request|nonce)", re.I)
CODE_FIELD_RE     = re.compile(r"(code|otp|token|pin|verification)", re.I)

VERIFY_SUBJECTS = ("verify", "confirm", "activate", "welcome",
                    "validate", "complete your", "finish", "account")

VERIFY_CODE_PATTERNS = (
    re.compile(r"(?:code|pin)[\s:#]*(\d{4,8})", re.I),
    re.compile(r"(\d{4,8})[\s-]*(?:is|as)\s+your", re.I),
    re.compile(r"verification[^0-9]{0,20}(\d{4,8})", re.I),
    re.compile(r"token[\s:]*([A-Za-z0-9_\-]{6,32})", re.I),
)

FRAMEWORK_SIGNATURES: dict[str, tuple[list[str], list[str], list[str]]] = {
    "wordpress": (["wp-", "x-pingback", "wp-json"], ["wordpress"],
                  ["/wp-content/", "/wp-includes/", "wp-emoji", "wp-embed"]),
    "drupal": (["x-generator: drupal", "x-drupal-"], ["drupal"],
               ["/sites/default/", "drupal.js", "drupalsettings"]),
    "joomla": (["x-content-encoded-by: joomla"], ["joomla"],
               ["/media/system/js/", "joomla!"]),
    "django": (["csrftoken", "x-django"], [],
               ["csrftoken", "csrfmiddlewaretoken", "__admin_media_prefix__"]),
    "rails": (["x-runtime", "x-request-id"], [],
              ["rails", "turbolinks", "action_cable", "csrf-token"]),
    "laravel": (["x-powered-by: laravel", "laravel_session"], [],
                ["laravel", "csrf-token"]),
    "spring": (["x-application-context", "jsessionid"], [],
               ["spring", "j_spring", "/js_spring_security"]),
    "express": (["x-powered-by: express"], [], ["express"]),
    "nextjs": (["x-nextjs"], [], ["/_next/", "__next_data__"]),
    "nuxt": (["x-nuxt"], [], ["/_nuxt/", "__nuxt__"]),
    "react": ([], ["react"], ["react-dom", "__react"]),
    "vue": ([], ["vue"], ["vue.js", "__vue__", "vue-router", "vue.min.js"]),
    "angular": (["ng-"], ["angular"], ["angular.min.js", "ng-app"]),
    "jquery": ([], [], ["jquery", "jquery.min.js", "jquery-3"]),
    "bootstrap": ([], [], ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"]),
    "tailwind": ([], [], ["tailwind"]),
    "phpmyadmin": (["x-pma"], ["phpmyadmin"], ["phpmyadmin"]),
    "graphql": ([], [], ["graphql", "/graphiql", "__schema", "apollo"]),
    "swagger": ([], [], ["swagger-ui", "swagger.json"]),
    "cloudflare": (["cf-ray", "cloudflare"], [], ["cdn-cgi/"]),
}

CHAIN_SEVERITY: dict[str, Severity] = {
    "crawl-admin-surface":       Severity.HIGH,
    "crawl-auth-gated":          Severity.HIGH,
    "crawl-debug-exposed":       Severity.HIGH,
    "crawl-register-exposed":    Severity.MEDIUM,
    "crawl-api-surface":         Severity.MEDIUM,
    "crawl-parameterized-urls":  Severity.MEDIUM,
    "crawl-js-endpoints":        Severity.MEDIUM,
    "crawl-upload-form":         Severity.HIGH,
    "crawl-external-redirect":   Severity.MEDIUM,
    "crawl-cors-permissive":     Severity.MEDIUM,
    "crawl-mass-surface":        Severity.LOW,
    "crawl-authenticated":       Severity.HIGH,
    "crawl-waf-fallback":        Severity.MEDIUM,
    "crawl-post-auth-discovery": Severity.HIGH,
}

CHAIN_NAMES: dict[str, str] = {
    "crawl-admin-surface":       "Admin panel pages",
    "crawl-auth-gated":          "Auth-required pages",
    "crawl-debug-exposed":       "Debug/actuator pages",
    "crawl-register-exposed":    "Public registration forms",
    "crawl-api-surface":         "API endpoints",
    "crawl-parameterized-urls":  "Pages with query parameters",
    "crawl-js-endpoints":        "Endpoints discovered in JS",
    "crawl-upload-form":         "Forms with file upload",
    "crawl-external-redirect":   "Pages redirecting off-host",
    "crawl-cors-permissive":     "Permissive CORS",
    "crawl-mass-surface":        "Large surface (>50 pages)",
    "crawl-authenticated":       "Pages accessible after login",
    "crawl-waf-fallback":        "Pages fetched via origin (WAF bypass)",
    "crawl-post-auth-discovery": "Auth-discovered pages",
}


# ══════════════════════════════════════════════════════════════════════════
#  HOST CAPACITY
# ══════════════════════════════════════════════════════════════════════════

def _measure_host() -> tuple[int, int, str]:
    cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024
                        break
    except Exception:
        pass
    reasons = []
    if cores <= 2:
        reasons.append(f"{cores} cores")
    if ram_mb and ram_mb < 2048:
        reasons.append(f"{ram_mb} MB RAM")
    return cores, ram_mb, ", ".join(reasons) if reasons else ""


HOST_CORES, HOST_RAM_MB, LIGHTWEIGHT_REASON = _measure_host()
LIGHTWEIGHT_MODE = bool(LIGHTWEIGHT_REASON) or os.getenv("ARGUS_LIGHTWEIGHT") == "1"


def _effective_limits(max_pages: int, max_depth: int) -> tuple[int, int]:
    if not LIGHTWEIGHT_MODE:
        return max_pages, max_depth
    return min(max_pages, 75), min(max_depth, 2)


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _safe_filename(s: str, max_len: int = 80) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)[:max_len].strip("_") or "root"


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _normalize_url(url: str, base_host: str) -> Optional[str]:
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.hostname != base_host:
        return None
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return None
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc.lower(),
        parsed.path or "/", "", parsed.query, "",
    ))


def _extract_params(url: str) -> list[str]:
    try:
        qs = urllib.parse.urlparse(url).query
        return list(urllib.parse.parse_qs(qs).keys()) if qs else []
    except Exception:
        return []


def _categorize_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "ssl"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, urllib.error.HTTPError):
        return f"http{e.code}"
    if isinstance(exc, urllib.error.URLError):
        reason = str(exc.reason).lower()
        if "proxy" in reason: return "proxy"
        if "dns" in reason or "name" in reason: return "dns"
        if "refused" in reason: return "refused"
        if "timeout" in reason: return "timeout"
        if "ssl" in reason or "certificate" in reason: return "ssl"
        return "url"
    if "proxy" in str(exc).lower():
        return "proxy"
    return type(exc).__name__.lower()[:20]


def _text_preview(html: str, limit: int = 500) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html or "",
                  flags=re.I | re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;|&#\d+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  HTML PARSING
# ══════════════════════════════════════════════════════════════════════════

def _parse_html(html: str, base_url: str) -> dict:
    out = {
        "title": "", "links": [], "forms": [],
        "scripts": [], "stylesheets": [], "meta": {},
        "endpoints": [], "base_href": None,
    }
    m = re.search(r'<base\s+[^>]*href=["\']([^"\']+)["\']', html, re.I)
    if m:
        try:
            out["base_href"] = urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1)))
            base_url = out["base_href"]
        except Exception:
            pass

    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        out["title"] = html_lib.unescape(m.group(1).strip())[:200]

    for m in re.finditer(r'<meta\s+([^>]+?)/?>', html, re.I):
        attrs = m.group(1)
        name_m = re.search(r'name=["\']([^"\']+)["\']', attrs, re.I)
        content_m = re.search(r'content=["\']([^"\']*)["\']', attrs, re.I)
        if name_m and content_m:
            key = name_m.group(1).lower()
            if key in ("generator", "description", "author", "csrf-token",
                       "csrf-param", "viewport", "x-csrf-token"):
                out["meta"][key] = html_lib.unescape(content_m.group(1))[:300]

    for m in re.finditer(r'<a\s+[^>]*?href=["\']([^"\']+)["\']', html, re.I):
        href = html_lib.unescape(m.group(1))
        try:
            out["links"].append(urllib.parse.urljoin(base_url, href))
        except Exception:
            continue

    for m in re.finditer(r'<script\s+[^>]*?src=["\']([^"\']+)["\']', html, re.I):
        try:
            out["scripts"].append(urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1))))
        except Exception:
            continue

    for m in re.finditer(
            r'<link\s+[^>]*?rel=["\'][^"\']*stylesheet[^"\']*["\'][^>]*?href=["\']([^"\']+)["\']',
            html, re.I):
        try:
            out["stylesheets"].append(urllib.parse.urljoin(base_url, html_lib.unescape(m.group(1))))
        except Exception:
            continue

    for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        enctype_m = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)
        try:
            action = urllib.parse.urljoin(
                base_url, html_lib.unescape(action_m.group(1) if action_m else ""))
        except Exception:
            action = base_url
        method = (method_m.group(1) if method_m else "get").upper()
        enctype = (enctype_m.group(1) if enctype_m else "").lower()

        fields = []
        for im in re.finditer(r'<input\b([^>]*?)/?>', inner, re.I):
            iattrs = im.group(1)
            name_m  = re.search(r'name=["\']([^"\']+)["\']', iattrs, re.I)
            type_m  = re.search(r'type=["\']([^"\']+)["\']', iattrs, re.I)
            value_m = re.search(r'value=["\']([^"\']*)["\']', iattrs, re.I)
            if not name_m:
                continue
            fields.append({
                "name":  name_m.group(1),
                "type":  (type_m.group(1) if type_m else "text").lower(),
                "value": html_lib.unescape(value_m.group(1)) if value_m else "",
                "csrf":  bool(CSRF_FIELD_RE.search(name_m.group(1))),
                "code":  bool(CODE_FIELD_RE.search(name_m.group(1))),
            })
        for tm in re.finditer(r'<textarea\b([^>]*)>', inner, re.I):
            name_m = re.search(r'name=["\']([^"\']+)["\']', tm.group(1), re.I)
            if name_m:
                fields.append({"name": name_m.group(1), "type": "textarea",
                                "value": "", "csrf": False, "code": False})
        for sm in re.finditer(r'<select\b([^>]*)>', inner, re.I):
            name_m = re.search(r'name=["\']([^"\']+)["\']', sm.group(1), re.I)
            if name_m:
                fields.append({"name": name_m.group(1), "type": "select",
                                "value": "", "csrf": False, "code": False})

        out["forms"].append({
            "action": action, "method": method, "enctype": enctype,
            "fields": fields,
            "has_password": any((f["type"] == "password")
                                 or PASSWORD_FIELD_RE.search(f["name"])
                                 for f in fields),
            "has_file_upload": enctype == "multipart/form-data" or any(
                f["type"] == "file" for f in fields),
            "has_code_field": any(f.get("code") for f in fields),
        })

    endpoints = set()
    for m in re.finditer(r'<script\b[^>]*>(.*?)</script>', html, re.I | re.S):
        js = m.group(1)
        if not js.strip():
            continue
        for regex in (JS_FETCH_RE, JS_AJAX_RE, JS_AXIOS_RE):
            for jm in regex.finditer(js):
                ep = jm.group(1)
                try:
                    endpoints.add(urllib.parse.urljoin(base_url, ep))
                except Exception:
                    pass
        for jm in JS_ENDPOINT_RE.finditer(js):
            ep = jm.group(1)
            try:
                endpoints.add(urllib.parse.urljoin(base_url, ep))
            except Exception:
                pass
    out["endpoints"] = sorted(endpoints)[:200]
    return out


def _parse_robots_txt(body: str, base_url: str) -> dict:
    out = {"sitemaps": [], "disallow": [], "allow": []}
    for line in body.splitlines():
        line = line.split("#")[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "sitemap":
            try:
                out["sitemaps"].append(urllib.parse.urljoin(base_url, val))
            except Exception:
                pass
        elif key == "disallow" and val:
            out["disallow"].append(val)
        elif key == "allow" and val:
            out["allow"].append(val)
    return out


def _parse_sitemap_xml(body: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for m in re.finditer(r"<loc>\s*([^<]+?)\s*</loc>", body, re.I):
        try:
            urls.append(urllib.parse.urljoin(base_url, m.group(1).strip()))
        except Exception:
            continue
    return urls


def _is_disallowed(url: str, robots: dict) -> bool:
    try:
        path = urllib.parse.urlparse(url).path or "/"
    except Exception:
        return False
    for pattern in robots.get("allow", []):
        if path.startswith(pattern):
            return False
    for pattern in robots.get("disallow", []):
        if path.startswith(pattern):
            return True
    return False


def _detect_frameworks(html: str, headers: dict, scripts: list[str],
                        stylesheets: list[str], meta: dict) -> list[str]:
    detected: set[str] = set()
    headers_flat = " ".join(f"{k.lower()}:{v.lower()}"
                             for k, v in (headers or {}).items())
    meta_flat = " ".join(f"{k}={v}".lower() for k, v in (meta or {}).items())
    resources_flat = " ".join((scripts or []) + (stylesheets or [])).lower()
    html_lower = (html or "")[:50000].lower()

    for name, (h_pats, m_pats, r_pats) in FRAMEWORK_SIGNATURES.items():
        for pat in h_pats:
            if pat.lower() in headers_flat:
                detected.add(name); break
        else:
            for pat in m_pats:
                if pat.lower() in meta_flat:
                    detected.add(name); break
            else:
                for pat in r_pats:
                    if pat.lower() in resources_flat or pat.lower() in html_lower:
                        detected.add(name); break
    return sorted(detected)


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  CREDENTIAL STORE (v8.0 — cookie persistence)
# ══════════════════════════════════════════════════════════════════════════

class CredentialStore:
    def __init__(self, path: Path):
        self.path = path
        self._data: dict = {"version": 2, "accounts": {}}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "accounts" in data:
                self._data = data
        except Exception as e:
            log.warn(f"    credential store unreadable ({e}) — starting fresh")

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass
        except Exception as e:
            log.warn(f"    could not save credentials: {e}")

    def get(self, host: str) -> Optional[dict]:
        return self._data.get("accounts", {}).get(host)

    def set(self, host: str, entry: dict) -> None:
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._data.setdefault("accounts", {})[host] = entry
        self._save()

    def mark_invalid(self, host: str) -> None:
        acc = self._data.get("accounts", {}).get(host)
        if acc:
            acc["valid"] = False
            acc["invalidated_at"] = datetime.now(timezone.utc).isoformat()
            self._save()

    def save_cookies(self, host: str, cookiejar: http.cookiejar.CookieJar) -> None:
        """Persist a session's cookies to the store (for resume)."""
        acc = self._data.get("accounts", {}).get(host) or {}
        acc["cookies"] = _serialize_cookies(cookiejar)
        acc["cookies_updated_at"] = datetime.now(timezone.utc).isoformat()
        self._data.setdefault("accounts", {})[host] = acc
        self._save()

    def get_cookies(self, host: str) -> list[dict]:
        acc = self._data.get("accounts", {}).get(host) or {}
        return acc.get("cookies", [])

    def count(self) -> int:
        return len(self._data.get("accounts", {}))


def _creds_path(outdir: Path) -> Path:
    return _REPO_ROOT / CREDS_FILE_NAME


# ═══ v8.0 COOKIE HELPERS ═══
def _serialize_cookies(cookiejar: http.cookiejar.CookieJar) -> list[dict]:
    """Convert cookiejar to a JSON-safe list of cookie dicts."""
    return [
        {"name": c.name, "value": c.value, "domain": c.domain,
         "path": c.path, "secure": c.secure}
        for c in cookiejar
    ]


def _load_cookies_into_session(cookiejar: http.cookiejar.CookieJar,
                                cookies: list[dict], host: str) -> int:
    """Restore cookies into a session's cookiejar. Returns count loaded."""
    loaded = 0
    for c in cookies:
        try:
            cookie = Cookie(
                version=0, name=c.get("name", ""), value=c.get("value", ""),
                port=None, port_specified=False,
                domain=c.get("domain") or host, domain_specified=True,
                domain_initial_dot=False,
                path=c.get("path", "/"), path_specified=True,
                secure=c.get("secure", False),
                expires=None, discard=False,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            )
            cookiejar.set_cookie(cookie)
            loaded += 1
        except Exception:
            continue
    return loaded


def _cookie_signature(cookiejar: http.cookiejar.CookieJar) -> frozenset:
    """Snapshot of (name, value) pairs for diff comparison."""
    return frozenset((c.name, c.value) for c in cookiejar)


def _detect_new_auth_cookies(before: frozenset, after: frozenset) -> list[str]:
    """Return names of new cookies that look auth-related."""
    new_cookies = after - before
    return [
        name for name, _ in new_cookies
        if any(a in name.lower() for a in AUTH_COOKIE_NAMES)
    ]


def _classify_redirect(location: str) -> str:
    """
    Classify a Location header into a state.
    Returns: logged_in | verify_needed | failed | ambiguous
    """
    if not location:
        return "ambiguous"
    loc_l = location.lower()

    # 1. Success paths — highest confidence
    if any(p in loc_l for p in AUTH_SUCCESS_PATHS):
        return "logged_in"
    # 2. Verify paths
    if any(p in loc_l for p in AUTH_VERIFY_PATHS):
        return "verify_needed"
    # 3. Back to login = failed
    if any(p in loc_l for p in AUTH_LOGIN_PATHS):
        return "failed"
    # 4. Back to register = "already exists" or bad data
    if any(p in loc_l for p in ("register", "signup", "sign-up")):
        return "already_exists"
    # 5. Unknown redirect — often success (e.g. /welcome-abc, /u/123)
    return "logged_in"


def _detect_auth_state(
    res: "HttpResult",
    previous_cookies: frozenset,
    current_cookies: frozenset,
    is_post_register: bool = False,
    original_redirect: str = "",
) -> tuple[str, list[str]]:
    """
    v8.1 — classify auth outcome. Checks the ORIGINAL redirect (if any)
    BEFORE inspecting the followed response, because the Location header
    is the most reliable signal and gets lost after we follow it.

    States: logged_in | verify_needed | already_exists | failed | ambiguous
    """
    # ── 0. Original Location header (STRONGEST redirect signal) ──
    if original_redirect:
        loc_state = _classify_redirect(original_redirect)
        if loc_state != "ambiguous":
            if loc_state == "already_exists" and not is_post_register:
                loc_state = "failed"  # bare /register redirect on login = bad
            return loc_state, [f"redirect:{original_redirect[:80]}"]

    status   = res.status
    headers  = res.headers or {}
    body     = (res.body or "").lower()
    body_preview = body[:5000]

    # ── 1. Cookie-diff (STRONGEST content signal) ──
    new_auth_cookies = _detect_new_auth_cookies(previous_cookies, current_cookies)
    if new_auth_cookies:
        return "logged_in", [f"auth_cookies:{','.join(new_auth_cookies[:3])}"]

    # ── 2. Followed response redirect (in case original_redirect was empty) ──
    location = headers.get("Location", "") or headers.get("location", "")
    if status in (301, 302, 303, 307, 308) and location:
        loc_state = _classify_redirect(location)
        if loc_state != "ambiguous":
            if loc_state == "already_exists" and not is_post_register:
                loc_state = "failed"
            return loc_state, [f"follow_redirect:{location[:80]}"]

    # ── 3. Verify body markers (before success — verify pages often say "dashboard") ──
    for marker in AUTH_VERIFY_BODY:
        if marker in body_preview:
            return "verify_needed", [f"body:{marker}"]

    # ── 4. Failure markers ──
    for marker in AUTH_FAILURE_BODY:
        if marker in body_preview:
            return "failed", [f"body:{marker}"]

    # ── 4b. Deny markers (200 disguised as login wall) ──
    if not is_post_register:
        for marker in AUTH_DENY_BODY:
            if marker in body_preview:
                return "failed", [f"deny_body:{marker}"]

    # ── 5. Already-exists (register only) ──
    if is_post_register:
        for marker in AUTH_EXISTS_BODY:
            if marker in body_preview:
                return "already_exists", [f"body:{marker}"]

    # ── 6. Success markers (page-body heuristics) ──
    for marker in AUTH_SUCCESS_BODY:
        if marker in body_preview:
            return "logged_in", [f"body:{marker}"]

    # ── 7. 200 after register but no signals → ambiguous (probe /dashboard later) ──
    if status == 200 and is_post_register:
        return "ambiguous", ["200_after_register"]
    if status >= 500:
        return "failed", [f"server_error:{status}"]
    return "ambiguous", [f"status:{status}"]


def _probe_auth_success(session: "HostSession") -> tuple[bool, str]:
    """
    v8.1 — after an ambiguous register/login, actually TRY a protected URL.
    Returns (is_logged_in, evidence).
    """
    for probe in ("/dashboard", "/account", "/profile", "/settings",
                  "/me", "/user", "/my-account", "/members"):
        try:
            probe_res = session.get_with_origin_fallback(
                session.base_url.rstrip("/") + probe)
        except Exception:
            continue
        # 200 + not redirected back to login = we're in
        if probe_res.status == 200:
            final = (probe_res.final_url or "").lower()
            if not any(p in final for p in AUTH_LOGIN_PATHS):
                body_l = (probe_res.body or "").lower()[:3000]
                # If it's a login page disguised as 200, skip
                if "type=\"password\"" not in body_l and "type='password'" not in body_l:
                    return True, f"probe {probe} → 200"
    return False, "no protected path returned 200"


# ══════════════════════════════════════════════════════════════════════════
#  ᛟ  ORIGIN LOADER  ·  WAF bypass via origin_hunt.json
# ══════════════════════════════════════════════════════════════════════════

class OriginLoader:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or ((_cfg("OUTPUT_DIR") or Path("output")) / "origin_hunt.json")
        self._data: dict[str, dict] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        self._loaded = True
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for h in data.get("hosts", []):
                host = (h.get("host") or "").lower()
                if host:
                    self._data[host] = h
            if self._data:
                log.info(f"  origin_hunt.json: {len(self._data)} host(s) loaded")
        except Exception as e:
            log.warn(f"  origin_hunt.json unreadable: {e}")

    def reload(self) -> None:
        self._data.clear()
        self._load()

    def get_usable_origins(self, host: str) -> list[dict]:
        h = self._data.get(host.lower())
        if not h:
            return []
        out = []
        for cand in h.get("confirmed_origins", []):
            chain_ids = cand.get("chain_ids") or []
            if "origin-paas-edge" in chain_ids:
                continue
            if cand.get("confidence") not in ("CONFIRMED", "HIGH"):
                continue
            if cand.get("severity") not in ("HIGH", "CRITICAL", "MEDIUM"):
                continue
            ip = cand.get("ip")
            if not ip:
                continue
            out.append(cand)
        return out

    def has_any(self, host: str) -> bool:
        return bool(self.get_usable_origins(host))

    def host_count(self) -> int:
        return len(self._data)


# ══════════════════════════════════════════════════════════════════════════
#  ᛉ  WAF DETECTION
# ══════════════════════════════════════════════════════════════════════════

def _detect_waf_block(res: "HttpResult") -> tuple[bool, str]:
    headers_lower = {k.lower(): str(v) for k, v in (res.headers or {}).items()}
    body_lower = (res.body or "")[:5000].lower()

    for marker in WAF_HEADER_MARKERS:
        if marker in headers_lower:
            vendor = _waf_vendor_from_marker(marker, headers_lower)
            if res.status in WAF_BLOCK_STATUSES:
                return True, vendor
            if vendor == "cloudflare" and res.status == 200:
                if "just a moment" in body_lower or "checking your browser" in body_lower:
                    return True, "cloudflare-challenge"

    for marker in WAF_BODY_MARKERS:
        if marker in body_lower:
            return True, _waf_from_body_marker(marker)

    if res.status in WAF_BLOCK_STATUSES:
        for marker in WAF_HEADER_MARKERS:
            if marker in headers_lower:
                return True, _waf_vendor_from_marker(marker, headers_lower)

    return False, ""


def _waf_vendor_from_marker(marker: str, headers: dict) -> str:
    if "cf-" in marker:
        return "cloudflare"
    if "akamai" in marker:
        return "akamai"
    if "sucuri" in marker:
        return "sucuri"
    if "datadome" in marker:
        return "datadome"
    if "iinfo" in marker or "incapsula" in marker:
        return "imperva"
    if "bigip" in marker:
        return "f5"
    return "waf"


def _waf_from_body_marker(marker: str) -> str:
    if "cloudflare" in marker or "just a moment" in marker or "checking your browser" in marker:
        return "cloudflare"
    if "ddos-guard" in marker:
        return "ddos-guard"
    return "waf"


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  HTTP CLIENT
# ══════════════════════════════════════════════════════════════════════════

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

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses to follow redirects so we can inspect the Location header."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HostSession:
    """
    Per-host HTTP client:
      · Persistent cookiejar (v8.0: supports persistence via CredentialStore)
      · Per-request UA rotation (config.random_user_agent)
      · Per-request proxy rotation (config.ProxyPool)
      · Rate-limited (config.RateLimiter) + human_delay pacing
      · KillSwitch-guarded, AuditTrail-recorded
      · BBP headers via config.build_headers
      · Circuit breaker after CIRCUIT_BREAK_THRESHOLD failures
      · WAF detection + automatic origin fallback (origin_hunt.json)
    """

    def __init__(self, host: str, bbp_program: Optional[str],
                 proxy_pool: Any = None, audit_trail: Any = None,
                 extra_headers: Optional[dict] = None,
                 use_proxy: bool = True,
                 respect_robots: bool = False,
                 origin_loader: Optional[OriginLoader] = None,
                 origin_fallback: bool = True):
        self.host = host
        self.base_url = f"https://{host}"
        self.bbp_program = bbp_program
        self.audit = audit_trail
        self.proxy_pool = proxy_pool if use_proxy else None
        self.use_proxy = use_proxy
        self.cookiejar = http.cookiejar.CookieJar()
        self.rate_limiter = self._build_rate_limiter()
        self.static_headers = self._build_headers(bbp_program, extra_headers)
        self.respect_robots = respect_robots
        self.origin_loader = origin_loader
        self.origin_fallback = origin_fallback
        self.robots: dict = {"disallow": [], "allow": [], "sitemaps": []}
        self.stats = {
            "requests": 0, "errors": 0, "bytes": 0, "failures": 0,
            "origin_fallbacks": 0, "proxies_used": set(),
        }
        self.consecutive_failures = 0
        self.dead = False
        self.dead_reason = ""

    def _build_rate_limiter(self) -> Any:
        try:
            rl_cls = _cfg("RateLimiter")
            limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("crawl", {})
            rps = limits.get("rps", 4)
            return rl_cls(per_minute=rps * 60, per_hour=rps * 3600) if rl_cls else None
        except Exception:
            return None

    def _build_headers(self, bbp_program: Optional[str],
                        extra: Optional[dict]) -> dict:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            if bbp_program:
                builder = _cfg("build_headers")
                if callable(builder):
                    headers.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
        if extra:
            headers.update(extra)
        return headers

    def _next_proxy(self) -> Any:
        if self.proxy_pool is None:
            return None
        try:
            p = self.proxy_pool.pick()
            if p is not None:
                try:
                    self.stats["proxies_used"].add(p.url())
                except Exception:
                    pass
            return p
        except Exception:
            return None

    def _ua(self) -> str:
        try:
            fn = _cfg("random_user_agent")
            if callable(fn):
                return fn()
        except Exception:
            pass
        return "Mozilla/5.0 (compatible; Argus-Skoll/8.0)"

    def _guard(self) -> None:
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"):
                ks.check()
        except Exception:
            pass

    def _pace(self) -> None:
        try:
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()
            delay_fn = _cfg("human_delay")
            d = delay_fn() if callable(delay_fn) else random.uniform(0.4, 2.5)
            time.sleep(d)
            if random.random() < HUMAN_PAUSE_CHANCE:
                extra = random.uniform(*HUMAN_PAUSE_RANGE)
                log.debug(f"    human pause: {extra:.1f}s (reading)")
                time.sleep(extra)
        except Exception:
            pass

    def _enforce_scope(self, url: str) -> bool:
        try:
            scope = _cfg("SCOPE")
            if scope is None:
                return True
            if scope.is_in_scope(url):
                return True
            host = _host_of(url)
            if not host:
                return False
            for rule in getattr(scope, "_rules", []):
                if not getattr(rule, "include", True):
                    continue
                if getattr(rule, "regex", False):
                    continue
                pattern = (rule.pattern or "").lower().strip().lstrip("*.")
                if pattern and (host == pattern or host.endswith("." + pattern)):
                    return True
            return False
        except Exception:
            return True

    def _record_result(self, res: HttpResult) -> None:
        if res.ok or (res.status > 0 and res.status < 500):
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
            self.stats["failures"] += 1
            if self.consecutive_failures >= CIRCUIT_BREAK_THRESHOLD and not self.dead:
                self.dead = True
                self.dead_reason = res.error_category or res.error or "unknown"
                log.warn(f"    circuit breaker tripped after "
                          f"{self.consecutive_failures} failures "
                          f"({self.dead_reason}) — skipping rest of host")

    def _build_opener(self, proxy: Any,
                       follow_redirects: bool = True) -> urllib.request.OpenerDirector:
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar)]
        if not follow_redirects:
            handlers.append(_NoRedirectHandler())
        if proxy is not None:
            try:
                handlers.append(urllib.request.ProxyHandler({
                    "http": proxy.url(), "https": proxy.url()
                }))
            except Exception:
                pass
        return urllib.request.build_opener(*handlers)

    def _report_proxy_result(self, proxy: Any, success: bool,
                              latency: float = 0.0) -> None:
        if proxy is None or self.proxy_pool is None:
            return
        try:
            if success:
                self.proxy_pool.report_success(proxy, latency)
            else:
                self.proxy_pool.report_failure(proxy)
        except Exception:
            pass

    def get(self, url: str, allow_redirects: bool = True,
            referer: Optional[str] = None) -> HttpResult:
        if self.dead:
            return HttpResult(0, {}, "", url, url, 0,
                              error="host dead (circuit breaker)",
                              error_category="circuit")
        if not self._enforce_scope(url):
            return HttpResult(0, {}, "", url, url, 0,
                              error="out of scope", error_category="scope")

        self._guard()
        self._pace()

        headers = dict(self.static_headers)
        headers["User-Agent"] = self._ua()
        if referer:
            headers["Referer"] = referer

        proxy = self._next_proxy()
        req = urllib.request.Request(url, headers=headers, method="GET")
        opener = self._build_opener(proxy, follow_redirects=allow_redirects)

        start = time.monotonic()
        try:
            with opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                final_url = resp.geturl() if allow_redirects else url
                body_bytes = resp.read(DEFAULT_MAX_BODY_BYTES)
                latency = (time.monotonic() - start) * 1000
                body = body_bytes.decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in resp.headers.items()}

                self.stats["requests"] += 1
                self.stats["bytes"] += len(body_bytes)
                self._audit("GET", final_url, resp.getcode(), latency, error=None, proxy=proxy)
                self._report_proxy_result(proxy, True, latency / 1000)

                result = HttpResult(
                    status=resp.getcode(), headers=headers_dict, body=body,
                    url=url, final_url=final_url, latency_ms=latency,
                )
                self._record_result(result)
                return result

        except urllib.error.HTTPError as e:
            latency = (time.monotonic() - start) * 1000
            self.stats["requests"] += 1
            try:
                body = e.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                body, headers_dict = "", {}
            self._audit("GET", url, e.code, latency, error=f"HTTP {e.code}", proxy=proxy)
            self._report_proxy_result(proxy, e.code < 500)
            result = HttpResult(
                status=e.code, headers=headers_dict, body=body,
                url=url, final_url=url, latency_ms=latency,
                error=f"HTTP {e.code}", error_category=f"http{e.code}",
            )
            self.consecutive_failures = 0
            return result

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            category = _categorize_error(e)
            self._audit("GET", url, 0, latency, error=str(e)[:200], proxy=proxy)
            self._report_proxy_result(proxy, False)
            result = HttpResult(0, {}, "", url, url, latency,
                                error=f"{category}: {type(e).__name__}",
                                error_category=category)
            self._record_result(result)
            return result

    def get_with_origin_fallback(self, url: str, referer: Optional[str] = None) -> HttpResult:
        res = self.get(url, allow_redirects=True, referer=referer)
        if not self.origin_fallback or self.origin_loader is None:
            return res

        is_blocked, waf = _detect_waf_block(res)
        if not is_blocked:
            return res

        log.debug(f"    WAF block detected ({waf}) — checking origin fallback")
        origins = self.origin_loader.get_usable_origins(self.host)
        if not origins:
            log.debug(f"    no usable origin for {self.host}")
            return res

        for origin in origins[:3]:
            origin_ip = origin.get("ip")
            if not origin_ip:
                continue
            log.info(f"    {Sym.FIRE} origin fallback: {url[:60]} → {origin_ip}")
            origin_res = self._fetch_via_origin(url, origin_ip)
            if origin_res.status == 200 and not origin_res.error:
                self.stats["origin_fallbacks"] += 1
                log.ok(f"    origin delivered 200 ({len(origin_res.body)}B) via {origin_ip}")
                return origin_res
            elif origin_res.status > 0 and origin_res.status < 500:
                log.debug(f"    origin returned {origin_res.status} — trying next")

        return res

    def _fetch_via_origin(self, url: str, origin_ip: str) -> HttpResult:
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
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((origin_ip, port), timeout=DEFAULT_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    req_text = (f"GET {path}{qs} HTTP/1.1\r\n"
                                f"Host: {self.host}\r\n"
                                f"User-Agent: {ua}\r\n"
                                f"Accept: text/html,application/xhtml+xml,*/*\r\n"
                                f"Accept-Language: en-US,en;q=0.9\r\n"
                                f"Connection: close\r\n\r\n")
                    ssock.sendall(req_text.encode())
                    data = b""
                    while True:
                        chunk = ssock.recv(65536)
                        if not chunk: break
                        data += chunk
                        if len(data) > DEFAULT_MAX_BODY_BYTES: break
            else:
                sock = socket.create_connection((origin_ip, port), timeout=DEFAULT_TIMEOUT)
                with sock:
                    req_text = (f"GET {path}{qs} HTTP/1.1\r\n"
                                f"Host: {self.host}\r\n"
                                f"User-Agent: {ua}\r\n"
                                f"Connection: close\r\n\r\n")
                    sock.sendall(req_text.encode())
                    data = b""
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk: break
                        data += chunk
                        if len(data) > DEFAULT_MAX_BODY_BYTES: break

            latency = (time.monotonic() - start) * 1000
            text = data.decode("utf-8", errors="replace")
            parts = text.split("\r\n\r\n", 1)
            header_block = parts[0] if parts else ""
            body = parts[1] if len(parts) > 1 else ""
            lines = header_block.split("\r\n")
            m = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0] if lines else "")
            status = int(m.group(1)) if m else 0
            headers_dict: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers_dict[k.strip()] = v.strip()

            self._audit("GET", f"origin://{origin_ip}{path}{qs}",
                        status, latency, error=None, proxy=None)

            return HttpResult(
                status=status, headers=headers_dict, body=body,
                url=url, final_url=url, latency_ms=latency,
                error=None if status > 0 else "origin fetch failed",
                error_category=None if status > 0 else "origin",
                via_origin=origin_ip,
            )
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            self._audit("GET", f"origin://{origin_ip}{path}{qs}",
                        0, latency, error=str(e)[:200], proxy=None)
            return HttpResult(0, {}, "", url, url, latency,
                              error=f"origin: {type(e).__name__}",
                              error_category="origin",
                              via_origin=origin_ip)

    def post(self, url: str, data: dict,
             referer: Optional[str] = None,
             allow_redirects: bool = True) -> HttpResult:
        if self.dead:
            return HttpResult(0, {}, "", url, url, 0,
                              error="host dead", error_category="circuit")
        if not self._enforce_scope(url):
            return HttpResult(0, {}, "", url, url, 0,
                              error="out of scope", error_category="scope")
        self._guard()
        self._pace()

        headers = dict(self.static_headers)
        headers["User-Agent"] = self._ua()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        if referer:
            headers["Referer"] = referer

        body_bytes = urllib.parse.urlencode(data).encode("utf-8")
        proxy = self._next_proxy()
        req = urllib.request.Request(url, data=body_bytes,
                                      headers=headers, method="POST")
        opener = self._build_opener(proxy, follow_redirects=allow_redirects)

        start = time.monotonic()
        try:
            with opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                body = resp.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000
                headers_dict = {k: v for k, v in resp.headers.items()}
                final_url = resp.geturl() if allow_redirects else url
                self.stats["requests"] += 1
                self.stats["bytes"] += len(body)
                self._audit("POST", final_url, resp.getcode(), latency,
                             error=None, proxy=proxy)
                self._report_proxy_result(proxy, True, latency / 1000)
                result = HttpResult(
                    status=resp.getcode(), headers=headers_dict, body=body,
                    url=url, final_url=final_url, latency_ms=latency,
                )
                self._record_result(result)
                return result

        except urllib.error.HTTPError as e:
            # 3xx responses come here when redirects are disabled — expected
            latency = (time.monotonic() - start) * 1000
            self.stats["requests"] += 1
            try:
                body = e.read(DEFAULT_MAX_BODY_BYTES).decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                body, headers_dict = "", {}
            self._audit("POST", url, e.code, latency, error=f"HTTP {e.code}", proxy=proxy)
            self._report_proxy_result(proxy, e.code < 500)
            result = HttpResult(
                status=e.code, headers=headers_dict, body=body,
                url=url, final_url=url, latency_ms=latency,
                error=f"HTTP {e.code}", error_category=f"http{e.code}",
            )
            self.consecutive_failures = 0
            return result

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            category = _categorize_error(e)
            self._audit("POST", url, 0, latency, error=str(e)[:200], proxy=proxy)
            self._report_proxy_result(proxy, False)
            result = HttpResult(0, {}, "", url, url, latency,
                                error=f"{category}: {type(e).__name__}",
                                error_category=category)
            self._record_result(result)
            return result

    def _audit(self, method: str, url: str, status: int,
                latency_ms: float, error: Optional[str], proxy: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                method=method, url=url, status=status,
                latency_ms=latency_ms,
                proxy=proxy.url() if proxy else None,
                user_agent="(rotating)",
                error=error,
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  PAGE CLASSIFICATION + HEURISTIC SUMMARY
# ══════════════════════════════════════════════════════════════════════════

def _classify_page(url: str, title: str, forms: list, meta: dict
                    ) -> tuple[str, list[str]]:
    """
    v8.0 — confidence-ordered classification:
      1. URL path (fixed patterns now match .php/.html/.aspx/etc.)
      2. Title hints
      3. Form field analysis:
         · has_password + has_confirm   → register
         · has_password + email + user  → register
         · has_password + 3+ text fields → register
         · has_password + email OR user → login (only)
    """
    path = (urllib.parse.urlparse(url).path or "/").lower()
    title_l = (title or "").lower()
    chains: list[str] = []

    # ── Path first ──
    if DEBUG_PATTERNS.search(path):
        return "debug", ["crawl-debug-exposed"]
    if ADMIN_PATTERNS.search(path):
        return "admin", ["crawl-admin-surface"]
    if API_PATTERNS.search(path):
        return "api", ["crawl-api-surface"]
    if REGISTER_PATTERNS.search(path):
        return "register", ["crawl-register-exposed"]
    if LOGIN_PATTERNS.search(path):
        return "login", ["crawl-auth-gated"]

    # ── Title second ──
    if any(t in title_l for t in ("sign up", "register", "create account",
                                   "registration", "join us")):
        return "register", ["crawl-register-exposed"]
    if any(t in title_l for t in ("sign in", "login", "log in", "signin")):
        return "login", ["crawl-auth-gated"]

    # ── Form analysis (no confirm field required) ──
    has_password = has_confirm = has_email = has_username = has_upload = False
    text_field_count = 0

    for f in forms or []:
        for fld in f.get("fields", []):
            n = fld.get("name") or ""
            t = (fld.get("type") or "text").lower()
            if t == "password" or PASSWORD_FIELD_RE.search(n):
                has_password = True
                if CONFIRM_FIELD_RE.search(n):
                    has_confirm = True
            if EMAIL_FIELD_RE.search(n) or t == "email":
                has_email = True
            if USERNAME_FIELD_RE.search(n):
                has_username = True
            if t == "file":
                has_upload = True
            if t in ("text", "email", "tel") and not CSRF_FIELD_RE.search(n):
                text_field_count += 1
        if f.get("has_file_upload"):
            has_upload = True

    if has_upload:
        chains.append("crawl-upload-form")

    if has_password:
        if has_confirm:
            return "register", chains + ["crawl-register-exposed"]
        if has_email and has_username:
            return "register", chains + ["crawl-register-exposed"]
        if text_field_count >= 3:
            return "register", chains + ["crawl-register-exposed"]
        return "login", chains + ["crawl-auth-gated"]

    return "public", chains


def _heuristic_score(page: dict) -> tuple[int, Severity]:
    score = 0
    kind = page.get("kind", "public")
    if kind == "debug":   score += 45
    elif kind == "admin": score += 40
    elif kind == "login": score += 30
    elif kind == "register": score += 25
    elif kind == "api":   score += 20

    if page.get("params"):
        score += 5 * min(len(page["params"]), 5)
    if page.get("forms"):
        score += 10
        if "crawl-upload-form" in (page.get("chain_ids") or []):
            score += 20
    if page.get("headers_security", {}).get("cors_acao") == "*":
        score += 10
    if page.get("external_redirect"):
        score += 5
    if page.get("status_code") in (401, 403):
        score += 15
    if page.get("authenticated"):
        score += 20

    if score >= 70:   sev = Severity.CRITICAL
    elif score >= 45: sev = Severity.HIGH
    elif score >= 25: sev = Severity.MEDIUM
    elif score >= 10: sev = Severity.LOW
    else:             sev = Severity.INFO
    return score, sev


SQLI_HINT_PARAMS = (
    "id", "user", "uid", "pid", "page", "cat", "category", "product",
    "item", "order", "invoice", "search", "q", "query", "filter",
    "sort", "doc", "num", "view", "account", "profile", "pid",
)
REDIRECT_HINT_PARAMS = (
    "url", "redirect", "return", "next", "target", "callback",
    "to", "u", "r", "dest", "destination", "goto", "continue",
)
FILE_HINT_PARAMS = (
    "file", "path", "template", "include", "require", "doc",
    "page", "download", "src", "source", "load", "read",
)


def _heuristic_page_summary(page: dict) -> dict:
    kind = page.get("kind", "public")
    params = page.get("params") or []
    forms = page.get("forms") or []
    frameworks = page.get("framework") or []

    injectable_params: list[str] = []
    for p in params:
        pl = p.lower()
        if any(h in pl for h in SQLI_HINT_PARAMS):
            injectable_params.append(p)
        elif any(h == pl or h in pl for h in REDIRECT_HINT_PARAMS):
            injectable_params.append(p)
        elif any(h == pl or h in pl for h in FILE_HINT_PARAMS):
            injectable_params.append(p)

    injectable_fields: list[str] = []
    for f in forms:
        for fld in f.get("fields", []):
            name = fld.get("name") or ""
            ftype = (fld.get("type") or "").lower()
            if ftype in ("hidden", "submit", "button", "reset", "file"):
                continue
            if not name:
                continue
            injectable_fields.append(name)

    risk = "INFO"
    if page.get("authenticated"):
        risk = "HIGH"
    elif kind in ("debug", "admin") or page.get("status_code") in (401, 403):
        risk = "HIGH"
    elif kind in ("login", "register", "api"):
        risk = "MEDIUM"
    elif injectable_params or forms:
        risk = "MEDIUM"
    elif params:
        risk = "LOW"

    summary = f"{kind} page"
    if page.get("authenticated"):
        summary = f"AUTHENTICATED {summary}"
    if injectable_params:
        summary += f" · {len(injectable_params)} injectable-look param(s)"
    if injectable_fields:
        summary += f" · {len(injectable_fields)} input field(s)"
    if frameworks:
        summary += f" · {', '.join(frameworks[:3])}"

    notes_parts = []
    if page.get("origin_fallback_used"):
        notes_parts.append(f"served via origin {page.get('origin_ip_used', '')}")
    if page.get("headers_security", {}).get("cors_acao") == "*":
        notes_parts.append("permissive CORS")
    if "crawl-upload-form" in (page.get("chain_ids") or []):
        notes_parts.append("file upload present")
    if page.get("external_redirect"):
        notes_parts.append("off-host redirect")
    if page.get("authenticated"):
        notes_parts.append("requires auth to access")

    return {
        "summary":           summary,
        "risk_level":        risk,
        "injectable_params": injectable_params,
        "injectable_fields": injectable_fields,
        "notes":             "; ".join(notes_parts),
        "source":            "heuristic",
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  AI PAGE SUMMARY (per-page)
# ══════════════════════════════════════════════════════════════════════════

AI_PAGE_SYSTEM = (
    "You are an expert bug bounty web analyst. Analyze a single crawled "
    "page and return STRICT JSON only — no prose, no markdown fences."
)


def _ai_summarize_page(page: dict, host: str) -> Optional[dict]:
    if not CFG_LOADED or not bool(_cfg("AI_ENABLED", False)):
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None

    forms_brief = []
    for f in (page.get("forms") or [])[:3]:
        fields = [fld.get("name") for fld in f.get("fields", [])[:10]
                   if fld.get("name")]
        forms_brief.append({
            "action": f.get("action", "")[:200],
            "method": f.get("method", "GET"),
            "fields": fields,
            "has_password": f.get("has_password", False),
            "has_file_upload": f.get("has_file_upload", False),
        })

    prompt = f"""Analyze this single crawled page for bug bounty value.

URL: {page.get('url')}
Host: {host}
Status: {page.get('status_code')}
Authenticated: {page.get('authenticated', False)}
Title: {page.get('title', '')}
Kind: {page.get('kind', 'public')}
Params: {page.get('params', [])}
Forms: {forms_brief}
Framework: {page.get('framework', [])}
Headers: {page.get('headers_security', {})}
Body preview: {(page.get('body_preview') or '')[:500]}

Return STRICT JSON (no markdown):
{{
  "summary": "1-sentence description of this page",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "injectable_params": ["param names that look injectable"],
  "injectable_fields": ["form field names worth testing"],
  "notes": "any notable observations"
}}"""

    try:
        response = ai_fn(prompt, system=AI_PAGE_SYSTEM)
        if not response:
            return None
        text = response.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        data = json.loads(text)
        data["source"] = "ai"
        return data
    except Exception as e:
        log.debug(f"    AI page summary failed: {type(e).__name__}: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PAGE RECORD BUILDER
# ══════════════════════════════════════════════════════════════════════════

def _build_page_record(res: HttpResult, host: str, depth: int,
                        parsed: Optional[dict] = None,
                        referer: Optional[str] = None,
                        authenticated: bool = False) -> dict:
    final_url = res.final_url or res.url
    final_host = _host_of(final_url)
    redirected_off = (final_host != host and final_host != "")

    page = {
        "url":            final_url,
        "requested_url":  res.url,
        "host":           host,
        "path":           urllib.parse.urlparse(final_url).path or "/",
        "status_code":    res.status,
        "content_type":   res.headers.get("Content-Type", ""),
        "content_length": len(res.body),
        "title":          "",
        "kind":           "public",
        "chain_ids":      [],
        "params":         _extract_params(final_url),
        "links":          [],
        "forms":          [],
        "scripts":        [],
        "stylesheets":    [],
        "meta":           {},
        "endpoints":      [],
        "response_time_ms": round(res.latency_ms, 1),
        "depth":          depth,
        "referer":        referer,
        "redirected_to":  (final_url if final_url != res.url else None),
        "external_redirect": redirected_off,
        "headers_security": {},
        "framework":      [],
        "body_preview":   _text_preview(res.body or ""),
        "page_summary":   {},
        "error":          res.error,
        "error_category": res.error_category,
        "origin_fallback_used": bool(res.via_origin),
        "origin_ip_used": res.via_origin,
        "authenticated":  authenticated,
        "interesting":    False,
        "reasons":        [],
        "heuristic_score": 0,
        "severity":       Severity.INFO.value,
    }

    h = res.headers
    page["headers_security"] = {
        "hsts":       bool(h.get("Strict-Transport-Security")),
        "csp":        bool(h.get("Content-Security-Policy")),
        "xfo":        bool(h.get("X-Frame-Options")),
        "cors_acao":  h.get("Access-Control-Allow-Origin", ""),
        "server":     h.get("Server", ""),
        "powered_by": h.get("X-Powered-By", ""),
    }

    if parsed is not None:
        page["title"]       = parsed["title"]
        page["meta"]        = parsed["meta"]
        page["forms"]       = parsed["forms"]
        page["scripts"]     = parsed["scripts"][:50]
        page["stylesheets"] = parsed["stylesheets"][:50]
        page["endpoints"]   = parsed["endpoints"]
        page["links"]       = list(dict.fromkeys(parsed["links"]))[:200]

        kind, chains = _classify_page(final_url, parsed["title"],
                                       parsed["forms"], parsed["meta"])
        page["kind"]      = kind
        page["chain_ids"] = chains

    page["framework"] = _detect_frameworks(
        res.body or "", res.headers or {}, page["scripts"],
        page["stylesheets"], page["meta"],
    )

    if page["kind"] in ("admin", "login", "register", "debug", "api"):
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
    if score >= 45:
        page["interesting"] = True

    page["page_summary"] = _heuristic_page_summary(page)
    return page


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  JS / CSS ANALYZERS
# ══════════════════════════════════════════════════════════════════════════

def _analyze_js_file(url: str, session: HostSession) -> tuple[list[str], Optional[str]]:
    res = session.get_with_origin_fallback(url)
    if not res.ok or res.status != 200 or not res.body:
        return [], None
    endpoints = set()
    for regex in (JS_FETCH_RE, JS_AJAX_RE, JS_AXIOS_RE):
        for m in regex.finditer(res.body):
            try:
                endpoints.add(urllib.parse.urljoin(url, m.group(1)))
            except Exception:
                pass
    for m in JS_ENDPOINT_RE.finditer(res.body):
        try:
            endpoints.add(urllib.parse.urljoin(url, m.group(1)))
        except Exception:
            pass
    return sorted(endpoints)[:100], res.body[:50000]


def _analyze_css_file(url: str, session: HostSession) -> tuple[list[str], Optional[str]]:
    res = session.get_with_origin_fallback(url)
    if not res.ok or res.status != 200 or not res.body:
        return [], None
    urls = set()
    for m in re.finditer(r'url\(\s*[\'"]?([^\'")]+)[\'"]?\s*\)', res.body):
        try:
            urls.add(urllib.parse.urljoin(url, m.group(1)))
        except Exception:
            pass
    return sorted(urls)[:50], res.body[:20000]


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  CRAWL ENGINE
# ══════════════════════════════════════════════════════════════════════════

def _crawl_host(
    host: str,
    session: HostSession,
    *,
    max_pages: int,
    max_depth: int,
    aggressive: bool,
    page_stream_path: Optional[Path] = None,
) -> dict:
    base_url = session.base_url
    pages: list[dict] = []
    visited: set[str] = set()
    queue: list[tuple[str, int, Optional[str]]] = []
    assets_js: set[str] = set()
    assets_css: set[str] = set()
    endpoints_found: set[str] = set()
    js_content_analyzed: set[str] = set()
    css_content_analyzed: set[str] = set()
    ai_summary_count = 0
    last_url: Optional[str] = None

    def _stream_page(page_dict: dict) -> None:
        if page_stream_path is None:
            return
        try:
            with page_stream_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(page_dict, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _maybe_ai_summarize(page_dict: dict) -> None:
        nonlocal ai_summary_count
        if ai_summary_count >= AI_PAGE_SUMMARY_LIMIT:
            return
        if not page_dict.get("interesting") and not page_dict.get("params") \
                and not page_dict.get("forms"):
            return
        if not bool(_cfg("AI_ENABLED", False)):
            return
        ai_summary = _ai_summarize_page(page_dict, host)
        if ai_summary:
            page_dict["page_summary"] = ai_summary
            ai_summary_count += 1

    # STEP 1 — Front page
    front_res = session.get_with_origin_fallback(base_url + "/")
    front_blocked, front_waf = _detect_waf_block(front_res)

    if not front_blocked and (front_res.error or front_res.status == 0) \
            and session.consecutive_failures < CIRCUIT_BREAK_THRESHOLD:
        log.info(f"    {front_res.error_category} — trying http fallback")
        front_res = session.get_with_origin_fallback(f"http://{host}/")
        front_blocked, front_waf = _detect_waf_block(front_res)

    if front_blocked:
        log.warn(f"    {Sym.SHIELD} WAF-blocked ({front_waf}) — host is alive, "
                  f"returned {front_res.status}")
        return {
            "host": host, "base_url": base_url, "pages": [],
            "assets_js": [], "assets_css": [], "endpoints": [], "chains": [],
            "session_stats": _stats_snapshot(session.stats),
            "dead": False,
            "waf_blocked": True,
            "waf_vendor": front_waf,
            "waf_status": front_res.status,
            "waf_url": front_res.final_url or front_res.url,
            "waf_reason": f"blocked by {front_waf}",
            "ai_summaries": 0,
        }

    if front_res.error or front_res.status == 0:
        return {
            "host": host, "base_url": base_url, "pages": [],
            "assets_js": [], "assets_css": [], "endpoints": [], "chains": [],
            "session_stats": _stats_snapshot(session.stats),
            "dead": True, "dead_reason": front_res.error or "no response",
            "ai_summaries": 0,
        }

    visited.add(front_res.final_url or front_res.url)
    last_url = front_res.final_url or front_res.url

    # STEP 2 — parse front page
    front_parsed = _parse_html(front_res.body, last_url)
    front_page = _build_page_record(front_res, host, 0, front_parsed)
    _maybe_ai_summarize(front_page)
    pages.append(front_page)
    _stream_page(front_page)
    log.info(f"    [{front_page['kind']:<8}] {front_res.status:>3} "
              f"{front_page['url'][:70]}"
              + (f"  {Sym.FIRE}via {front_res.via_origin}" if front_res.via_origin else ""))

    front_host = _host_of(last_url)
    for s in front_parsed["scripts"]:
        if s and _host_of(s) == host:
            assets_js.add(s)
    for s in front_parsed["stylesheets"]:
        if s and _host_of(s) == host:
            assets_css.add(s)
    for ep in front_parsed["endpoints"]:
        if ep and _host_of(ep) == host:
            endpoints_found.add(ep)

    for link in front_parsed["links"]:
        n = _normalize_url(link, front_host)
        if n and n not in visited:
            queue.append((n, 1, last_url))

    # STEP 3 — protocol files
    for proto_path in PROTOCOL_PATHS:
        if len(pages) >= max_pages:
            break
        proto_url = base_url + proto_path
        if proto_url in visited:
            continue
        visited.add(proto_url)
        proto_res = session.get_with_origin_fallback(proto_url)
        if proto_res.error or proto_res.status not in (200, 203):
            continue
        if proto_path == "/robots.txt":
            session.robots = _parse_robots_txt(proto_res.body, base_url)
            log.info(f"    [robots  ] {proto_res.status:>3} {proto_url[:70]}  "
                      f"({len(session.robots['disallow'])} disallow, "
                      f"{len(session.robots['sitemaps'])} sitemap)")
            for sm_url in session.robots.get("sitemaps", []):
                if _host_of(sm_url) == host and sm_url not in visited:
                    queue.append((sm_url, 1, proto_url))
        elif proto_path == "/sitemap.xml":
            sm_urls = _parse_sitemap_xml(proto_res.body, base_url)
            log.info(f"    [sitemap ] {proto_res.status:>3} {proto_url[:70]}  "
                      f"({len(sm_urls)} urls)")
            for sm_url in sm_urls:
                n = _normalize_url(sm_url, front_host)
                if n and n not in visited:
                    queue.append((n, 1, proto_url))

    # STEP 4 — BFS
    while queue and len(pages) < max_pages:
        if session.dead:
            break
        url, depth, ref = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        if session.respect_robots and _is_disallowed(url, session.robots):
            continue
        # ★ v8.2.1 — don't skip pages that look auth-relevant; only skip random noise
        _auth_relevant = (
            "login" in url.lower() or "register" in url.lower()
            or "signin" in url.lower() or "signup" in url.lower()
            or "sign-in" in url.lower() or "sign-up" in url.lower()
            or "auth" in url.lower() or "account" in url.lower()
        )
        if not _auth_relevant and random.random() < PAGE_SKIP_CHANCE and len(queue) > 3:
            continue

        res = session.get_with_origin_fallback(url, referer=ref)
        if res.error or res.status == 0:
            continue

        final_host = _host_of(res.final_url or res.url)
        if final_host and final_host != host:
            page = _build_page_record(res, host, depth, parsed=None, referer=ref)
            _maybe_ai_summarize(page)
            pages.append(page)
            _stream_page(page)
            continue

        parsed = _parse_html(res.body, res.final_url or res.url)
        page = _build_page_record(res, host, depth, parsed, referer=ref)
        _maybe_ai_summarize(page)
        pages.append(page)
        _stream_page(page)
        last_url = page["url"]

        via_tag = f"  {Sym.FIRE}via {res.via_origin}" if res.via_origin else ""
        fw_tag = f"  [{','.join(page['framework'][:2])}]" if page['framework'] else ""
        log.info(f"    [{page['kind']:<8}] {res.status:>3} {page['url'][:70]}{fw_tag}{via_tag}")

        for s in parsed["scripts"]:
            if s and _host_of(s) == host:
                assets_js.add(s)
        for s in parsed["stylesheets"]:
            if s and _host_of(s) == host:
                assets_css.add(s)
        for ep in parsed["endpoints"]:
            if ep and _host_of(ep) == host:
                endpoints_found.add(ep)

        for link in parsed["links"]:
            n = _normalize_url(link, host)
            if n and n not in visited and depth + 1 <= max_depth:
                queue.append((n, depth + 1, page["url"]))

    # STEP 5 — JS / CSS content analysis
    if aggressive:
        for js_url in list(assets_js)[:JS_FETCH_LIMIT]:
            if js_url in js_content_analyzed:
                continue
            endpoints, _ = _analyze_js_file(js_url, session)
            js_content_analyzed.add(js_url)
            for ep in endpoints:
                if _host_of(ep) == host:
                    endpoints_found.add(ep)

        for css_url in list(assets_css)[:CSS_FETCH_LIMIT]:
            if css_url in css_content_analyzed:
                continue
            _, _ = _analyze_css_file(css_url, session)
            css_content_analyzed.add(css_url)

    # STEP 6 — probe discovered endpoints
    if aggressive and endpoints_found:
        for ep_url in list(endpoints_found)[:ENDPOINT_PROBE_LIMIT]:
            if len(pages) >= max_pages or session.dead:
                break
            if ep_url in visited:
                continue
            visited.add(ep_url)
            res = session.get_with_origin_fallback(ep_url, referer=last_url)
            if res.status in (200, 201, 401, 403, 500):
                page = {
                    "url": ep_url, "requested_url": ep_url, "host": host,
                    "path": urllib.parse.urlparse(ep_url).path or "/",
                    "status_code": res.status,
                    "content_type": res.headers.get("Content-Type", ""),
                    "content_length": len(res.body),
                    "title": "", "kind": "api",
                    "chain_ids": ["crawl-api-surface", "crawl-js-endpoints"],
                    "params": _extract_params(ep_url),
                    "links": [], "forms": [], "scripts": [], "stylesheets": [],
                    "meta": {}, "endpoints": [], "framework": [],
                    "body_preview": _text_preview(res.body or "", 300),
                    "response_time_ms": round(res.latency_ms, 1),
                    "depth": 99, "referer": last_url,
                    "redirected_to": None, "external_redirect": False,
                    "headers_security": {},
                    "origin_fallback_used": bool(res.via_origin),
                    "origin_ip_used": res.via_origin,
                    "authenticated": False,
                    "error": res.error, "error_category": res.error_category,
                    "interesting": True, "reasons": ["js_endpoint"],
                    "heuristic_score": 25,
                    "severity": Severity.MEDIUM.value,
                }
                page["page_summary"] = _heuristic_page_summary(page)
                _maybe_ai_summarize(page)
                pages.append(page)
                _stream_page(page)

    # Build chains
    chains_by_id: dict[str, list[str]] = {}
    for p in pages:
        for cid in p.get("chain_ids", []):
            chains_by_id.setdefault(cid, []).append(p["url"])
    if len(pages) > 50:
        chains_by_id.setdefault("crawl-mass-surface", []).append(
            f"total_pages={len(pages)}")

    return {
        "host":       host,
        "base_url":   base_url,
        "pages":      pages,
        "assets_js":  sorted(assets_js),
        "assets_css": sorted(assets_css),
        "endpoints":  sorted(endpoints_found),
        "chains":     [
            {
                "chain_id": cid,
                "name":     CHAIN_NAMES.get(cid, cid),
                "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
                "members":  members[:50],
                "count":    len(members),
            }
            for cid, members in chains_by_id.items()
        ],
        "session_stats":      _stats_snapshot(session.stats),
        "dead":               session.dead,
        "dead_reason":        session.dead_reason,
        "ai_summaries":       ai_summary_count,
        "js_content_analyzed":  len(js_content_analyzed),
        "css_content_analyzed": len(css_content_analyzed),
    }


def _stats_snapshot(stats: dict) -> dict:
    out = dict(stats)
    if isinstance(out.get("proxies_used"), set):
        out["proxies_used"] = sorted(out["proxies_used"])
    return out
# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  EMAIL VERIFICATION EXTRACTION (v8.0)
# ══════════════════════════════════════════════════════════════════════════

def _extract_verification(email_msg: Any, host: str) -> dict:
    """
    Extract verification URL/code from a find_verification_email() result.

    Handles dict, object, or raw-string messages.
    Returns dict with keys: method, url, code, sender, subject.
    """
    out = {"method": "none", "url": "", "code": "", "sender": "", "subject": ""}
    if email_msg is None:
        return out

    def _field(name, default=""):
        if isinstance(email_msg, dict):
            return email_msg.get(name, default) or default
        return getattr(email_msg, name, default) or default

    out["sender"]  = str(_field("sender") or _field("from_") or "")[:200]
    out["subject"] = str(_field("subject") or "")[:200]

    body_text = _field("body") or _field("text") or _field("html") or ""
    if not isinstance(body_text, str):
        body_text = str(body_text)

    # Collect URLs from body + explicit links field
    links_field = list(_field("links") or [])
    links_from_body = re.findall(r"https?://[^\s'\"<>]+", body_text, flags=re.IGNORECASE)
    all_links = list(dict.fromkeys(links_field + links_from_body))

    host_root = host.lower().rstrip(".")
    best_url = ""
    for cand in all_links:
        cl = cand.lower()
        if any(k in cl for k in ("verify", "confirm", "activate", "validate",
                                  "token=", "code=")):
            if host_root in cl:
                best_url = cand
                break
    if not best_url:
        for cand in all_links:
            if host_root in cand.lower():
                best_url = cand
                break
    if best_url:
        out["url"] = best_url
        out["method"] = "link"

    # Try code
    for pattern in VERIFY_CODE_PATTERNS:
        m = pattern.search(body_text)
        if m:
            code_val = m.group(1).strip()
            if len(code_val) >= 4 and not re.fullmatch(r"(19|20)\d{2}", code_val):
                out["code"] = code_val
                if out["method"] == "none":
                    out["method"] = "code"
                break

    return out


def _generate_password() -> str:
    """Cryptographically-strong password that satisfies most site rules."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "Arg_" + "".join(random.SystemRandom().choice(alphabet) for _ in range(16)) + "9!"


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  FORM HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _build_form_payload(form: dict, values: dict[str, str]) -> dict:
    """Build a POST payload from form fields, preserving CSRF/hidden values."""
    payload: dict[str, str] = {}
    for field in form.get("fields", []):
        name = field.get("name") or ""
        if not name:
            continue
        ftype = (field.get("type") or "text").lower()
        default = field.get("value") or ""

        if field.get("csrf"):
            payload[name] = default
        elif field.get("code"):
            payload[name] = values.get("code", default)
        elif PASSWORD_FIELD_RE.search(name) and not field.get("csrf"):
            if CONFIRM_FIELD_RE.search(name):
                payload[name] = values.get("password_confirm", values.get("password", ""))
            else:
                payload[name] = values.get("password", "")
        elif EMAIL_FIELD_RE.search(name) or ftype == "email":
            payload[name] = values.get("email", "")
        elif USERNAME_FIELD_RE.search(name) and ftype not in ("hidden",):
            payload[name] = values.get("username",
                                        (values.get("email") or "").split("@")[0])
        else:
            payload[name] = default
    return payload


def _find_register_form(pages: list[dict]) -> Optional[dict]:
    """
    v8.2.1 — return BOTH the page AND the best form on that page.
    Previously returned page only; caller used forms[0] which was often a
    search/newsletter form (0 password fields) → empty POST payload.
    Returns: {"page": <page dict>, "form": <form dict>} or None.
    """
    candidates: list[tuple[dict, dict]] = []

    def _form_score(form: dict) -> int:
        s = 0
        fields = form.get("fields", []) or []
        names = " ".join(f.get("name", "").lower() for f in fields)
        types = {(f.get("type") or "text").lower() for f in fields}
        if form.get("has_password") or "password" in types: s += 5
        if EMAIL_FIELD_RE.search(names) or "email" in types: s += 3
        if USERNAME_FIELD_RE.search(names): s += 2
        if CONFIRM_FIELD_RE.search(names):  s += 2
        # Prefer forms with SUBMIT but not search/newsletter
        if "search" in names or "newsletter" in names or "subscribe" in names:
            s -= 10
        return s

    # Priority 1: pages classified as 'register' — take their best form
    for p in pages:
        if p.get("kind") == "register" and p.get("forms"):
            best_form = max(p["forms"], key=_form_score)
            if _form_score(best_form) > 0:
                candidates.append((p, best_form))

    # Priority 2: any page with a form scoring high enough (fallback)
    if not candidates:
        for p in pages:
            for form in (p.get("forms") or []):
                if _form_score(form) >= 5:  # must have password field
                    candidates.append((p, form))

    if not candidates:
        return None

    # Pick the highest-scoring (page, form) pair
    best_pair = max(candidates, key=lambda pf: _form_score(pf[1]))
    page, form = best_pair

    log.info(f"    found register form: {page['url']} "
              f"({len(form.get('fields', []))} fields, "
              f"action={form.get('action', page['url'])[:50]})")

    return {"page": page, "form": form}


def _find_login_form(pages: list[dict]) -> Optional[dict]:
    """Pick the best login page from a host's crawled pages."""
    candidates = [p for p in pages
                  if p.get("kind") == "login" and p.get("forms")]
    if not candidates:
        return None

    def score(p):
        s = 0
        for f in p["forms"]:
            names = " ".join(fld.get("name", "") for fld in f.get("fields", []))
            if PASSWORD_FIELD_RE.search(names): s += 2
            if EMAIL_FIELD_RE.search(names):    s += 1
            if USERNAME_FIELD_RE.search(names): s += 1
        return s
    return max(candidates, key=score)


def _find_code_verification_form(pages: list[dict]) -> Optional[dict]:
    """Return {'page': ..., 'form': ...} for the first form that accepts a code."""
    for p in pages:
        path_l  = (p.get("path") or "").lower()
        title_l = (p.get("title") or "").lower()
        looks_like_verify = any(
            k in path_l or k in title_l
            for k in ("verify", "confirm", "activate", "check-email", "verification")
        )
        for form in (p.get("forms") or []):
            if form.get("has_code_field"):
                return {"page": p, "form": form}
            names = " ".join(fld.get("name", "") for fld in form.get("fields", []))
            if CODE_FIELD_RE.search(names) and looks_like_verify:
                return {"page": p, "form": form}
    return None


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  AUTH ATTEMPTS (v8.0)
# ══════════════════════════════════════════════════════════════════════════

def _analyze_landing_page(
    landing_res: "HttpResult",
    original_redirect: str = "",
    is_register: bool = False,
) -> dict:
    """
    v8.2 — Read the landing page thoroughly (URL, query, body, forms) and
    return a rich classification. Priority:
      1. rate_limited    (don't hammer)
      2. failed          (don't poll email)
      3. verify_code     (specific code form)
      4. verify_link     (specific "click link" text)
      5. verify_either   (generic "check your email")
      6. pending_manual  (admin review)
      7. logged_in       (sign out / my account / dashboard nav)
      8. URL/query heuristics
      9. ambiguous
    """
    out = {
        "state":           LANDING_STATE_AMBIGUOUS,
        "confidence":      "low",
        "landing_url":     landing_res.final_url or landing_res.url,
        "landing_path":    "",
        "query_params":    {},
        "signals":         [],
        "has_code_form":   False,
        "has_resend":      False,
        "has_password_form": False,
        "verify_code":     "",       # if we can extract from URL
        "status_code":     landing_res.status,
    }

    landing_url = out["landing_url"]
    try:
        parsed = urllib.parse.urlparse(landing_url)
        out["landing_path"] = (parsed.path or "/").lower()
        out["query_params"] = {
            k.lower(): v[0] if v else ""
            for k, v in urllib.parse.parse_qs(parsed.query).items()
        }
    except Exception:
        pass

    path = out["landing_path"]
    params = out["query_params"]
    body = (landing_res.body or "")
    body_low = body.lower()[:20000]
    status = landing_res.status

    def _has(markers):
        return [m for m in markers if m in body_low]

    # ── 1. Rate limited (check first — most urgent) ──
    rl = _has(LANDING_BODY_RATE_LIMITED)
    if rl or status == 429:
        out["state"] = LANDING_STATE_RATE_LIMITED
        out["confidence"] = "high"
        out["signals"].append(f"rate_limited:{rl[0] if rl else 'status 429'}")
        return out

    # ── 2. Explicit failure ──
    fail = _has(LANDING_BODY_FAILED)
    if fail:
        out["state"] = LANDING_STATE_FAILED
        out["confidence"] = "high"
        out["signals"].append(f"failed:{fail[0]}")
        return out

    # ── 2b. Already-exists (post-register only) ──
    if is_register:
        exists = _has(LANDING_BODY_ALREADY_EXISTS)
        if exists:
            out["state"] = LANDING_STATE_FAILED
            out["confidence"] = "high"
            out["signals"].append(f"already_exists:{exists[0]}")
            return out

    # ── 3. Analyze forms on landing page ──
    try:
        parsed_html = _parse_html(body, landing_url)
        for form in parsed_html.get("forms", []):
            fields = [f.get("name", "").lower() for f in form.get("fields", [])]
            if any(cf in fld for cf in LANDING_FORM_CODE_FIELDS for fld in fields):
                out["has_code_form"] = True
            if any("resend" in fld or "re-send" in fld for fld in fields):
                out["has_resend"] = True
            if form.get("has_password") and not form.get("has_code_field"):
                out["has_password_form"] = True
    except Exception:
        pass

    # ── 3b. Extract code from URL if present (auto-verify chance) ──
    for k, v in params.items():
        if k in LANDING_QUERY_TOKEN and len(v) >= 4:
            out["verify_code"] = v
            out["signals"].append(f"url_token:{k}={v[:8]}…")
            break

    # ── 4. Verify-code (specific "enter the code" markers OR code form) ──
    code_markers = _has(LANDING_BODY_VERIFY_CODE)
    if code_markers or (out["has_code_form"] and not out["has_password_form"]):
        out["state"] = LANDING_STATE_VERIFY_CODE
        out["confidence"] = "high" if code_markers else "medium"
        if code_markers:
            out["signals"].append(f"verify_code:{code_markers[0]}")
        if out["has_code_form"]:
            out["signals"].append("code_form_present")
        return out

    # ── 5. Verify-link ──
    link_markers = _has(LANDING_BODY_VERIFY_LINK)
    if link_markers:
        out["state"] = LANDING_STATE_VERIFY_LINK
        out["confidence"] = "high"
        out["signals"].append(f"verify_link:{link_markers[0]}")
        return out

    # ── 6. Verify-either ──
    either_markers = _has(LANDING_BODY_VERIFY_EITHER)
    if either_markers:
        out["state"] = LANDING_STATE_VERIFY_EITHER
        out["confidence"] = "medium"
        out["signals"].append(f"verify_either:{either_markers[0]}")
        return out

    # ── 7. Pending manual ──
    pending_markers = _has(LANDING_BODY_PENDING_MANUAL)
    if pending_markers:
        out["state"] = LANDING_STATE_PENDING_MANUAL
        out["confidence"] = "high"
        out["signals"].append(f"pending:{pending_markers[0]}")
        return out

    # ── 8. Logged in via body markers ──
    li_markers = _has(LANDING_BODY_LOGGED_IN)
    if li_markers:
        out["state"] = LANDING_STATE_LOGGED_IN
        out["confidence"] = "high"
        out["signals"].append(f"logged_in:{li_markers[0]}")
        return out

    # ── 9. URL path heuristics (SPAs that return bare div#root) ──
    if any(p in path for p in LANDING_PATH_VERIFY_CODE):
        out["state"] = LANDING_STATE_VERIFY_CODE
        out["confidence"] = "medium"
        out["signals"].append(f"path_verify_code:{path}")
        return out
    if any(p in path for p in LANDING_PATH_VERIFY_LINK):
        out["state"] = LANDING_STATE_VERIFY_LINK
        out["confidence"] = "medium"
        out["signals"].append(f"path_verify_link:{path}")
        return out
    if any(p in path for p in LANDING_PATH_PENDING):
        out["state"] = LANDING_STATE_PENDING_MANUAL
        out["confidence"] = "medium"
        out["signals"].append(f"path_pending:{path}")
        return out
    if any(p in path for p in LANDING_PATH_LOGGED_IN):
        out["state"] = LANDING_STATE_LOGGED_IN
        out["confidence"] = "medium"
        out["signals"].append(f"path_logged_in:{path}")
        return out
    if any(p in path for p in LANDING_PATH_LOGIN):
        out["state"] = LANDING_STATE_FAILED
        out["confidence"] = "medium"
        out["signals"].append(f"path_login_retry:{path}")
        return out
    if is_register and any(p in path for p in LANDING_PATH_REGISTER):
        out["state"] = LANDING_STATE_FAILED
        out["confidence"] = "medium"
        out["signals"].append(f"path_register_retry:{path}")
        return out

    # ── 10. Query-param heuristics ──
    qp_low = {k.lower(): str(v).lower() for k, v in params.items()}
    for k, v in qp_low.items():
        if k in LANDING_QUERY_ERROR:
            out["state"] = LANDING_STATE_FAILED
            out["confidence"] = "medium"
            out["signals"].append(f"query_error:{k}={v[:20]}")
            return out
        if k in LANDING_QUERY_PENDING:
            out["state"] = LANDING_STATE_PENDING_MANUAL
            out["confidence"] = "medium"
            out["signals"].append(f"query_pending:{k}={v[:20]}")
            return out
        if k in LANDING_QUERY_SUCCESS:
            out["state"] = LANDING_STATE_LOGGED_IN
            out["confidence"] = "medium"
            out["signals"].append(f"query_success:{k}={v[:20]}")
            return out

    # ── 11. Original redirect hint (only used if nothing else matched) ──
    if original_redirect:
        loc_l = original_redirect.lower()
        if any(p in loc_l for p in LANDING_PATH_LOGGED_IN):
            out["state"] = LANDING_STATE_LOGGED_IN
            out["confidence"] = "medium"
            out["signals"].append(f"orig_redirect:{loc_l[:60]}")
            return out
        if any(p in loc_l for p in LANDING_PATH_VERIFY_CODE):
            out["state"] = LANDING_STATE_VERIFY_CODE
            out["confidence"] = "medium"
            out["signals"].append(f"orig_redirect:{loc_l[:60]}")
            return out
        if any(p in loc_l for p in LANDING_PATH_VERIFY_LINK):
            out["state"] = LANDING_STATE_VERIFY_LINK
            out["confidence"] = "medium"
            out["signals"].append(f"orig_redirect:{loc_l[:60]}")
            return out

    return out

def _attempt_login_v2(
    host: str, session: "HostSession", pages: list[dict], creds: dict,
) -> tuple[str, list[str]]:
    login_page = _find_login_form(pages)
    if not login_page:
        log.warn("    login: no login form found in pages")
        return "failed", ["no_login_form"]

    form = login_page["forms"][0]
    action = form.get("action") or login_page["url"]
    payload = _build_form_payload(form, {
        "email": creds.get("email", ""),
        "password": creds.get("password", ""),
        "username": creds.get("username",
                              (creds.get("email") or "").split("@")[0]),
    })

    log.info(f"    login attempt: POST {action[:60]} ({len(payload)} fields)")
    pre_cookies = _cookie_signature(session.cookiejar)
    res = session.post(action, payload, referer=login_page["url"],
                        allow_redirects=False)
    post_cookies = _cookie_signature(session.cookiejar)

    original_redirect = (res.headers or {}).get("Location", "") or \
                        (res.headers or {}).get("location", "")

    # Follow the redirect so we land on the actual landing page
    landing_res = res
    if original_redirect and res.status in (301, 302, 303, 307, 308):
        follow_url = original_redirect
        if follow_url.startswith("/"):
            follow_url = urllib.parse.urljoin(login_page["url"], follow_url)
        landing_res = session.get_with_origin_fallback(follow_url)
        post_cookies = _cookie_signature(session.cookiejar)

    # ★ v8.2.1 — Deep-analyze the landing page
    landing = _analyze_landing_page(
        landing_res, original_redirect=original_redirect, is_register=False,
    )
    state = landing["state"]

    # ── Map landing state → login outcome + log clearly ──
    final_state, final_markers = "failed", ["unknown"]

    if state == LANDING_STATE_LOGGED_IN:
        final_state = "logged_in"
        final_markers = landing["signals"] or ["landing_logged_in"]
    elif state == LANDING_STATE_RATE_LIMITED:
        final_state = "rate_limited"
        final_markers = landing["signals"]
    elif state == LANDING_STATE_FAILED:
        final_state = "failed"
        final_markers = landing["signals"]
    elif state == LANDING_STATE_PENDING_MANUAL:
        final_state = "pending_manual"
        final_markers = landing["signals"]
    elif state in (LANDING_STATE_VERIFY_CODE, LANDING_STATE_VERIFY_LINK,
                    LANDING_STATE_VERIFY_EITHER, LANDING_STATE_VERIFY_AUTO):
        final_state = "verify_needed"
        final_markers = landing["signals"]
    else:
        # ── AMBIGUOUS — fall back to cookie diff, then /dashboard probe ──
        new_auth = _detect_new_auth_cookies(pre_cookies, post_cookies)
        if new_auth:
            final_state = "logged_in"
            final_markers = [f"auth_cookies:{','.join(new_auth[:3])}"]
        else:
            ok, evidence = _probe_auth_success(session)
            if ok:
                final_state = "logged_in"
                final_markers = [evidence]
            else:
                final_state = "failed"
                final_markers = ["login_ambiguous_no_protected_access"]

    # ★ v8.2.1 — LOG OUTCOME (was silent before!)
    if final_state == "logged_in":
        log.ok(f"    {Sym.CHECK} login SUCCESS ({','.join(final_markers[:2])})")
    elif final_state == "failed":
        log.warn(f"    {Sym.CROSS} login FAILED ({','.join(final_markers[:2])})")
    elif final_state == "rate_limited":
        log.warn(f"    {Sym.WARN} login RATE-LIMITED ({','.join(final_markers[:2])})")
    elif final_state == "pending_manual":
        log.warn(f"    {Sym.WARN} login PENDING-MANUAL ({','.join(final_markers[:2])})")
    else:
        log.warn(f"    {Sym.WARN} login {final_state} ({','.join(final_markers[:2])})")

    return final_state, final_markers


def _attempt_login(host: str, session: HostSession,
                    pages: list[dict], creds: dict) -> tuple[bool, str]:
    """v7.0 compat wrapper — use _attempt_login_v2 for richer signals."""
    state, markers = _attempt_login_v2(host, session, pages, creds)
    if state == "logged_in":
        return True, f"authenticated ({','.join(markers[:2])})"
    return False, f"{state} ({','.join(markers[:2])})"


def _attempt_code_verification(code: str, host: str, session: HostSession,
                                 pages: list[dict]) -> tuple[bool, str]:
    """Submit the OTP to whichever form looks like a code verifier."""
    verify = _find_code_verification_form(pages)
    if not verify:
        return False, "no code verification form found"

    page = verify["page"]
    form = verify["form"]
    action = form.get("action") or page["url"]
    method = form.get("method", "POST").upper()
    email_cfg = _cfg("EMAIL")
    payload = _build_form_payload(form, {
        "code": code,
        "email": (email_cfg.address if email_cfg else ""),
    })

    log.info(f"    submitting code '{code[:4]}…' to {action[:60]} "
              f"({len(payload)} fields, {method})")
    if method == "POST":
        res = session.post(action, payload, referer=page["url"])
    else:
        qs = urllib.parse.urlencode(payload)
        sep = "&" if "?" in action else "?"
        res = session.get(f"{action}{sep}{qs}", referer=page["url"])

    if res.error:
        return False, f"submission failed: {res.error}"

    body_lower = (res.body or "").lower()
    failure_markers = ("invalid code", "incorrect code", "expired",
                       "wrong code", "invalid token", "invalid otp")
    if any(m in body_lower for m in failure_markers):
        return False, "code rejected"

    if res.status in (301, 302, 303) or res.status == 200:
        return True, f"code accepted (status={res.status})"
    return False, f"ambiguous (status={res.status})"


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  VERIFICATION HANDLER (v8.0)
# ══════════════════════════════════════════════════════════════════════════

def _handle_verification(
    host: str,
    session: "HostSession",
    pages: list[dict],
    outdir: Path,
    creds_store: CredentialStore,
    entry: dict,
    email_cfg: Any,
    landing: Optional[dict] = None,
    email_timeout: float = REGISTRATION_TIMEOUT,
    attempt_email_verify: bool = True,
) -> dict:
    """
    v8.2 — only poll email if we KNOW we need to. Accepts the landing-page
    analysis so we can short-circuit "pending_manual" / "rate_limited"
    before wasting time.
    """
    landing = landing or {}

    # Short-circuit: some states should NEVER poll email
    if landing.get("state") in (LANDING_STATE_PENDING_MANUAL,
                                  LANDING_STATE_RATE_LIMITED,
                                  LANDING_STATE_FAILED):
        log.info(f"    skipping email poll (state={landing.get('state')})")
        creds_store.set(host, entry)
        return {**entry, "status": landing["state"]}

    if not attempt_email_verify:
        creds_store.set(host, entry)
        return {**entry, "status": "registered_verification_skipped"}

    find_fn = _cfg("find_verification_email")
    if not callable(find_fn):
        log.warn("    find_verification_email not available — skipping poll")
        creds_store.set(host, entry)
        return {**entry, "status": "registered_pending_manual",
                "note": "find_verification_email not configured"}

    # Use the tuned timeout
    per_subj = email_timeout / len(VERIFY_SUBJECTS)
    log.info(f"    polling inbox ({email_timeout:.0f}s cap, "
              f"{per_subj:.0f}s per subject)")

    verification_msg = None
    for subj in VERIFY_SUBJECTS:
        try:
            verification_msg = find_fn(
                subject_contains=subj,
                timeout_seconds=per_subj,
                poll_interval=4.0,
            )
        except Exception:
            verification_msg = None
        if verification_msg:
            break

    if not verification_msg:
        log.warn("    no verification email received")
        creds_store.set(host, entry)
        return {**entry, "status": "registered_pending_manual",
                "note": f"no email after {email_timeout:.0f}s"}

    verify_info = _extract_verification(verification_msg, host)
    entry["verification_method"] = verify_info["method"]
    entry["verification_url"]    = verify_info["url"]
    log.info(f"    email: from={verify_info['sender'][:50]} "
              f"subject={verify_info['subject'][:50]} "
              f"method={verify_info['method']}")

    # ── LINK verification ──
    if verify_info["method"] == "link":
        verify_url = verify_info["url"]
        log.ok(f"    {Sym.LINK} VERIFICATION URL: {verify_url[:80]}")
        pre_cookies = _cookie_signature(session.cookiejar)
        verify_res = session.get_with_origin_fallback(verify_url)
        post_cookies = _cookie_signature(session.cookiejar)
        new_auth = _detect_new_auth_cookies(pre_cookies, post_cookies)

        entry["verified"] = True
        entry["verify_status"] = verify_res.status

        # Re-analyze the verify landing page
        v_landing = _analyze_landing_page(verify_res, is_register=False)
        log.info(f"    verify landing: {v_landing['state']} "
                  f"({', '.join(v_landing['signals'][:2])})")

        # Magic link logged us in directly
        if new_auth or v_landing["state"] == LANDING_STATE_LOGGED_IN:
            log.ok(f"    {Sym.STAR} Magic link logged us in!")
            entry["cookies"] = _serialize_cookies(session.cookiejar)
            entry["login_status"] = "magic_link"
            entry["last_login"] = datetime.now(timezone.utc).isoformat()
            creds_store.set(host, entry)
            return {**entry, "status": "authenticated"}

        # Verified, now try explicit login
        log.info("    verification done, attempting login")
        state, markers = _attempt_login_v2(host, session, pages, entry)
        if state == "logged_in":
            log.ok(f"    {Sym.CHECK} Logged in after verification")
            entry["cookies"] = _serialize_cookies(session.cookiejar)
            entry["verified"] = True
            entry["login_status"] = "ok_after_verify_link"
            entry["last_login"] = datetime.now(timezone.utc).isoformat()
            creds_store.set(host, entry)
            return {**entry, "status": "authenticated"}

        log.warn(f"    login failed after verify: {state}")
        entry["login_status"] = f"failed_after_verify: {state}"
        creds_store.set(host, entry)
        return {**entry, "status": "registered_pending_manual",
                "note": f"verified but login failed: {state}"}

    # ── CODE verification ──
    if verify_info["method"] == "code":
        code = verify_info["code"]
        log.ok(f"    {Sym.KEY} VERIFICATION CODE: {code}")
        code_ok, code_detail = _attempt_code_verification(code, host, session, pages)
        entry["code_submit_status"] = "ok" if code_ok else code_detail

        if code_ok:
            log.info("    code accepted, attempting login")
            state, markers = _attempt_login_v2(host, session, pages, entry)
            if state == "logged_in":
                log.ok(f"    {Sym.CHECK} Logged in after code verification")
                entry["cookies"] = _serialize_cookies(session.cookiejar)
                entry["verified"] = True
                entry["login_status"] = "ok_after_verify_code"
                entry["last_login"] = datetime.now(timezone.utc).isoformat()
                creds_store.set(host, entry)
                return {**entry, "status": "authenticated"}
            log.warn(f"    login failed after code: {state}")
            creds_store.set(host, entry)
            return {**entry, "status": "registered_pending_manual",
                    "note": f"code verified but login failed: {state}"}

        log.warn(f"    code submission failed: {code_detail}")
        log.warn(f"    ⚠  Save for manual: code={code}")
        creds_store.set(host, entry)
        return {**entry, "status": "registered_pending_manual",
                "note": code_detail, "verification_code": code}

    creds_store.set(host, entry)
    return {**entry, "status": "registered_pending_manual",
            "note": "verification email has no link or code"}


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  REGISTER FLOW (v8.0 — 5-outcome detection)
# ══════════════════════════════════════════════════════════════════════════

def _attempt_register_and_login(
    host: str, pages: list[dict], session: "HostSession",
    outdir: Path, creds_store: CredentialStore,
) -> dict:
    if not CFG_LOADED:
        return {"status": "no_config"}
    email_cfg = _cfg("EMAIL")
    if email_cfg is None:
        log.warn("    auto-register: config.EMAIL not available")
        return {"status": "no_email"}

    found = _find_register_form(pages)
    if not found:
        log.info("    auto-register: no register form found")
        return {"status": "no_register_form"}
    register_page = found["page"]
    form          = found["form"]

    log.warn(f"    ⚠  AUTO-REGISTER on {host}")
    log.warn(f"       Form : {register_page['url']}  →  {form.get('action', '')[:60]}")

    password = _generate_password()
    username = f"argus_{int(time.time())}"
    action   = form.get("action") or register_page["url"]

    payload = _build_form_payload(form, {
        "email": email_cfg.address,
        "password": password,
        "password_confirm": password,
        "username": username,
    })

    if not payload:
        log.error(f"    ✗ ABORT: form has 0 usable fields (action={action[:60]})")
        return {"status": "empty_form_payload", "error": "0 fields extracted"}

    log.info(f"       Email: {email_cfg.address}")
    log.info(f"       Fields: {sorted(payload.keys())}")
    log.info(f"    POST register: {action[:60]} ({len(payload)} fields)")

    pre_cookies = _cookie_signature(session.cookiejar)
    reg_res = session.post(action, payload, referer=register_page["url"],
                            allow_redirects=False)
    post_cookies = _cookie_signature(session.cookiejar)

    original_redirect = (reg_res.headers or {}).get("Location", "") or \
                        (reg_res.headers or {}).get("location", "")

    # Follow the redirect so we land on the actual landing page
    landing_res = reg_res
    if original_redirect and reg_res.status in (301, 302, 303, 307, 308):
        follow_url = original_redirect
        if follow_url.startswith("/"):
            follow_url = urllib.parse.urljoin(register_page["url"], follow_url)
        landing_res = session.get_with_origin_fallback(follow_url)
        post_cookies = _cookie_signature(session.cookiejar)

    # Analyze landing page
    landing = _analyze_landing_page(
        landing_res, original_redirect=original_redirect, is_register=True,
    )
    state = landing["state"]

    entry = {
        "email": email_cfg.address,
        "password": password,
        "username": username,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "register_url": action,
        "register_status": reg_res.status,
        "landing_url": landing["landing_url"],
        "landing_state": state,
        "landing_signals": landing["signals"],
        "verified": False,
        "valid": True,
    }

    log.info(f"    register outcome: {state} "
              f"[{landing['confidence']}] "
              f"({', '.join(landing['signals'][:3])})")

    # ── RATE LIMITED — abort ──
    if state == LANDING_STATE_RATE_LIMITED:
        log.error(f"    {Sym.SKULL} RATE LIMITED — aborting on this host")
        creds_store.set(host, entry)
        return {**entry, "status": "rate_limited"}

    # ── FAILED — check if it's "already_exists" ──
    if state == LANDING_STATE_FAILED:
        exists_markers = [s for s in landing["signals"]
                          if s.startswith("already_exists")]

        if exists_markers:
            log.warn("    Account already exists on server")

            # ★ v8.2.1 — try OLD stored password first (in case login
            # earlier had a transient failure, not wrong creds)
            old_creds = creds_store.get(host)
            if old_creds and old_creds.get("password") and old_creds.get("valid") is False:
                log.info("    trying PREVIOUS stored password")
                st_old, m_old = _attempt_login_v2(host, session, pages, old_creds)
                if st_old == "logged_in":
                    old_creds["valid"] = True
                    old_creds["cookies"] = _serialize_cookies(session.cookiejar)
                    old_creds["login_status"] = "old_creds_after_exists"
                    old_creds["last_login"] = datetime.now(timezone.utc).isoformat()
                    creds_store.set(host, old_creds)
                    log.ok(f"    {Sym.STAR} old password works!")
                    return {**old_creds, "status": "authenticated"}

            # Then try login with the FRESH password (rare, but possible if
            # an account was pre-created with the same email+password)
            log.info("    trying login with FRESH credentials")
            st2, m2 = _attempt_login_v2(host, session, pages, entry)
            if st2 == "logged_in":
                entry["cookies"] = _serialize_cookies(session.cookiejar)
                entry["verified"] = True
                entry["login_status"] = "login_after_exists"
                entry["last_login"] = datetime.now(timezone.utc).isoformat()
                creds_store.set(host, entry)
                log.ok(f"    {Sym.STAR} logged in with fresh creds")
                return {**entry, "status": "authenticated"}

            log.warn(f"    ✗ both attempts failed — account needs MANUAL intervention")
            creds_store.set(host, entry)
            return {**entry, "status": "already_exists",
                    "error": f"login failed after exists: {st2}"}

        log.error(f"    Registration failed: {landing['signals']}")
        log.warn(f"    Landing body preview: {(landing_res.body or '')[:300]}")
        creds_store.set(host, entry)
        return {**entry, "status": "failed",
                "error": landing["signals"][0] if landing["signals"] else "unknown"}

    # ── LOGGED IN — no verification needed ──
    if state == LANDING_STATE_LOGGED_IN:
        log.ok(f"    {Sym.STAR} Registered + authenticated immediately "
                f"(cookies={len(list(session.cookiejar))})")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "immediate_after_register"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    # ── PENDING MANUAL — save, skip email ──
    if state == LANDING_STATE_PENDING_MANUAL:
        log.warn(f"    {Sym.WARN} Account pending manual approval — skip email")
        creds_store.set(host, entry)
        return {**entry, "status": "pending_manual"}

    # ── VERIFY_* — poll email with tuned timeout ──
    if state in (LANDING_STATE_VERIFY_CODE, LANDING_STATE_VERIFY_LINK,
                  LANDING_STATE_VERIFY_EITHER, LANDING_STATE_VERIFY_AUTO):
        if state == LANDING_STATE_VERIFY_CODE and landing["has_code_form"]:
            timeout = 90.0
        elif state == LANDING_STATE_VERIFY_LINK:
            timeout = 120.0
        else:
            timeout = 180.0

        log.info(f"    verification required ({state}) — "
                  f"polling email (up to {timeout:.0f}s)")
        creds_store.set(host, entry)
        return _handle_verification(
            host, session, pages, outdir, creds_store, entry, email_cfg,
            landing=landing, email_timeout=timeout,
        )

    # ── AMBIGUOUS — probe /dashboard first, then short email poll ──
    log.info("    ambiguous landing — probing protected paths first")
    ok, evidence = _probe_auth_success(session)
    if ok:
        log.ok(f"    {Sym.STAR} Registered + authenticated via {evidence}")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "post_register_probe"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    log.info("    probe failed — trying explicit login")
    st2, m2 = _attempt_login_v2(host, session, pages, entry)
    if st2 == "logged_in":
        log.ok(f"    {Sym.STAR} Logged in with freshly-created account")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "login_after_register"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    log.info("    trying email verification (60s cap)")
    creds_store.set(host, entry)
    return _handle_verification(
        host, session, pages, outdir, creds_store, entry, email_cfg,
        landing=landing, email_timeout=60.0,
    )

    # ══════════════════════════════════════════════════════════════════════
    # Act on state
    # ══════════════════════════════════════════════════════════════════════

    # ── RATE LIMITED — abort, do NOT retry ──
    if state == LANDING_STATE_RATE_LIMITED:
        log.error(f"    {Sym.SKULL} RATE LIMITED — aborting on this host")
        creds_store.set(host, entry)
        return {**entry, "status": "rate_limited"}

    # ── FAILED — bad data or account exists ──
    if state == LANDING_STATE_FAILED:
        exists_markers = [s for s in landing["signals"]
                          if s.startswith("already_exists")]
        if exists_markers:
            log.warn("    Account already exists — attempting login")
            st2, _ = _attempt_login_v2(host, session, pages, entry)
            if st2 == "logged_in":
                entry["cookies"] = _serialize_cookies(session.cookiejar)
                entry["verified"] = True
                entry["login_status"] = "login_after_exists"
                creds_store.set(host, entry)
                return {**entry, "status": "authenticated"}
            creds_store.set(host, entry)
            return {**entry, "status": "already_exists", "error": st2}
        log.error(f"    Registration failed: {landing['signals']}")
        creds_store.set(host, entry)
        return {**entry, "status": "failed", "error": landing["signals"][0]}

    # ── LOGGED IN — no verification needed! ──
    if state == LANDING_STATE_LOGGED_IN or new_auth:
        log.ok(f"    {Sym.STAR} Registered + authenticated immediately "
                f"(cookies={len(list(session.cookiejar))})")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "immediate_after_register"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    # ── PENDING MANUAL — save, don't poll email ──
    if state == LANDING_STATE_PENDING_MANUAL:
        log.warn(f"    {Sym.WARN} Account pending manual approval — "
                  f"skipping email poll")
        creds_store.set(host, entry)
        return {**entry, "status": "pending_manual"}

    # ── VERIFY_AUTO — URL had ?code= we can submit ──
    if state == LANDING_STATE_VERIFY_AUTO or landing.get("verify_code"):
        code = landing.get("verify_code", "")
        if code and landing.get("has_code_form"):
            log.ok(f"    {Sym.KEY} URL contains code + page has code form — "
                    f"auto-submitting")
            ok, detail = _attempt_code_verification(code, host, session, pages)
            if ok:
                st2, _ = _attempt_login_v2(host, session, pages, entry)
                if st2 == "logged_in":
                    entry["cookies"] = _serialize_cookies(session.cookiejar)
                    entry["verified"] = True
                    entry["login_status"] = "verify_auto"
                    entry["last_login"] = datetime.now(timezone.utc).isoformat()
                    creds_store.set(host, entry)
                    return {**entry, "status": "authenticated"}
            log.warn(f"    auto-verify failed: {detail}")

    # ── VERIFY_* — poll email with tuned timeout ──
    if state in (LANDING_STATE_VERIFY_CODE, LANDING_STATE_VERIFY_LINK,
                  LANDING_STATE_VERIFY_EITHER, LANDING_STATE_VERIFY_AUTO):
        # Tune timeout based on confidence
        if state == LANDING_STATE_VERIFY_CODE and landing["has_code_form"]:
            timeout = 90.0  # specific form → likely fast email
        elif state == LANDING_STATE_VERIFY_LINK:
            timeout = 120.0
        else:
            timeout = 180.0

        log.info(f"    verification required ({state}) — "
                  f"polling email (up to {timeout:.0f}s)")
        creds_store.set(host, entry)
        return _handle_verification(
            host, session, pages, outdir, creds_store, entry, email_cfg,
            landing=landing, email_timeout=timeout,
        )

    # ── AMBIGUOUS — probe /dashboard FIRST, then email (short) ──
    log.info("    ambiguous landing — probing protected paths first")
    ok, evidence = _probe_auth_success(session)
    if ok:
        log.ok(f"    {Sym.STAR} Registered + authenticated via {evidence}")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "post_register_probe"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    log.info("    probe failed — trying explicit login")
    st2, _ = _attempt_login_v2(host, session, pages, entry)
    if st2 == "logged_in":
        log.ok(f"    {Sym.STAR} Logged in with freshly-created account")
        entry["verified"] = True
        entry["cookies"] = _serialize_cookies(session.cookiejar)
        entry["login_status"] = "login_after_register"
        entry["last_login"] = datetime.now(timezone.utc).isoformat()
        creds_store.set(host, entry)
        return {**entry, "status": "authenticated"}

    log.info("    trying email verification (60s cap)")
    creds_store.set(host, entry)
    return _handle_verification(
        host, session, pages, outdir, creds_store, entry, email_cfg,
        landing=landing, email_timeout=60.0,
    )


def _do_auth_flow(
    host: str, pages: list[dict], session: HostSession,
    outdir: Path, creds_store: CredentialStore,
) -> Optional[dict]:
    """
    v8.2 — Master auth orchestration.

    Priority chain (each step short-circuits on success):
      1. Reused cookies  (fastest, zero noise)
      2. Stored creds    (if password present)
      3. Fresh register  (if config.EMAIL configured)

    The landing-page analyzer (_analyze_landing_page) now drives control
    flow through 6 more states than v8.1 knew how to handle. This function
    routes them all without wasting time:

      · rate_limited    → ABORT, keep creds, do NOT retry
      · pending_manual  → SAVE, skip email poll entirely
      · verify_needed   → poll email (only if EMAIL configured)
      · failed          → invalidate, fall through to register
      · authenticated   → return (cookies persisted by caller path)
      · reused_cookies  → return (fastest path)
    """
    existing = creds_store.get(host)

    # ══════════════════════════════════════════════════════════════════════
    # STEP 1 — Reused cookies (zero-cost probe)
    # ══════════════════════════════════════════════════════════════════════
    if existing and existing.get("valid", True):
        saved_cookies = existing.get("cookies") or []
        if saved_cookies:
            loaded = _load_cookies_into_session(
                session.cookiejar, saved_cookies, host,
            )
            if loaded > 0:
                log.info(f"    trying {loaded} saved cookie(s) from prior run")
                for probe in ("/dashboard", "/account", "/profile",
                              "/settings", "/me", "/user", "/my-account"):
                    try:
                        probe_res = session.get_with_origin_fallback(
                            session.base_url.rstrip("/") + probe,
                        )
                    except Exception:
                        continue

                    if probe_res.status != 200:
                        continue
                    final_url = (probe_res.final_url or "").lower()
                    # Bounced back to login → cookie is dead for this path
                    if any(p in final_url for p in AUTH_LOGIN_PATHS):
                        continue
                    # 200 disguised as login page
                    body_l = (probe_res.body or "")[:3000].lower()
                    if 'type="password"' in body_l or "type='password'" in body_l:
                        continue

                    log.ok(f"    {Sym.CHECK} reused cookies valid "
                           f"({probe} → 200)")
                    existing["last_login"] = datetime.now(timezone.utc).isoformat()
                    existing["login_status"] = "reused_cookies"
                    existing["valid"] = True
                    creds_store.set(host, existing)
                    return {**existing, "status": "reused_cookies"}

                log.info("    saved cookies stale — clearing and continuing")
                session.cookiejar.clear()
                creds_store.mark_invalid(host)

    # ══════════════════════════════════════════════════════════════════════
    # STEP 2 — Stored credentials login
    # ══════════════════════════════════════════════════════════════════════
    if existing and existing.get("valid", True) and existing.get("password"):
        log.info("    attempting login with stored credentials")
        try:
            state, markers = _attempt_login_v2(host, session, pages, existing)
        except Exception as e:
            log.warn(f"    login attempt raised: {type(e).__name__}: {e}")
            state, markers = "failed", [f"exception:{type(e).__name__}"]

        log.info(f"    login outcome: {state} ({', '.join(markers[:3])})")

        # ── 2a. Success ──
        if state == "logged_in":
            existing["cookies"] = _serialize_cookies(session.cookiejar)
            existing["last_login"] = datetime.now(timezone.utc).isoformat()
            existing["login_status"] = "ok_stored_creds"
            existing["valid"] = True
            creds_store.set(host, existing)
            log.ok(f"    {Sym.CHECK} authenticated with stored creds")
            return {**existing, "status": "authenticated"}

        # ── 2b. Rate-limited — do NOT invalidate, do NOT retry ──
        if state == "rate_limited":
            log.warn(f"    {Sym.WARN} rate-limited on login — "
                     f"preserving creds, aborting on this host")
            creds_store.set(host, existing)
            return {**existing,
                    "status": "rate_limited",
                    "error": "; ".join(markers[:2])}

        # ── 2c. Pending manual — account exists but needs admin approval ──
        if state == "pending_manual":
            log.warn(f"    {Sym.WARN} account pending admin approval — "
                     f"skip register, skip email")
            creds_store.set(host, existing)
            return {**existing,
                    "status": "pending_manual",
                    "note": "account exists but awaits admin approval"}

        # ── 2d. Account exists but unverified — try email verification ──
        if state == "verify_needed":
            email_cfg = _cfg("EMAIL")
            if email_cfg is None:
                log.warn("    account needs verification but no EMAIL configured")
                creds_store.set(host, existing)
                return {**existing,
                        "status": "verify_needed",
                        "note": "no EMAIL config to complete verification"}

            log.info("    account exists but unverified — "
                     "polling email to complete verification")
            # Synthesize a landing context so _handle_verification knows
            # it should poll email (not skip)
            synthetic_landing = {
                "state":    "verify_either",
                "signals":  markers,
                "confidence": "medium",
            }
            return _handle_verification(
                host, session, pages, outdir, creds_store, existing,
                email_cfg,
                landing=synthetic_landing,
                email_timeout=120.0,
            )

        # ── 2e. Failed — invalidate, fall through to register ──
        log.warn(f"    {Sym.CROSS} stored creds rejected — invalidating")
        creds_store.mark_invalid(host)
        # Note: do NOT return — fall through to STEP 3

    # ══════════════════════════════════════════════════════════════════════
    # STEP 3 — Fresh registration
    # ══════════════════════════════════════════════════════════════════════
    email_cfg = _cfg("EMAIL")
    if email_cfg is None:
        log.warn("    no EMAIL configured — cannot register")
        return {
            "status": "no_email_config",
            "note":   "config.EMAIL is required for auto-registration",
        }

    log.info("    attempting fresh registration")
    try:
        return _attempt_register_and_login(
            host, pages, session, outdir, creds_store,
        )
    except Exception as e:
        log.error(f"    register flow raised: {type(e).__name__}: {e}")
        return {
            "status": "exception",
            "error":  f"{type(e).__name__}: {e}",
        }


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  POST-AUTH CRAWL (v8.0 — full BFS of authenticated surface)
# ══════════════════════════════════════════════════════════════════════════

def _post_auth_crawl(
    host: str, session: "HostSession", host_result: dict,
    max_pages: int = POST_AUTH_CRAWL_LIMIT,
) -> dict:
    new_pages: list[dict] = []
    visited: set[str] = set()
    queue: list[tuple[str, int, Optional[str]]] = []
    base_url = session.base_url
    probed = 0
    hits = 0

    # ── Step 1: refresh front page with auth cookie ──
    try:
        front_res = session.get_with_origin_fallback(base_url + "/")
        probed += 1
        if front_res.status == 200 and not front_res.error:
            visited.add(front_res.final_url or front_res.url)
            front_parsed = _parse_html(front_res.body, front_res.final_url or front_res.url)
            front_page = _build_page_record(
                front_res, host, 0, front_parsed, authenticated=True,
            )
            front_page["kind"] = "auth"
            front_page["interesting"] = True
            if "authenticated_access" not in front_page["reasons"]:
                front_page["reasons"].append("authenticated_access")
            if "crawl-authenticated" not in front_page["chain_ids"]:
                front_page["chain_ids"].append("crawl-authenticated")
            new_pages.append(front_page)
            hits += 1
            log.ok(f"    {Sym.LOCK} AUTH page: [auth    ] "
                    f"{front_res.status:>3} {front_page['url'][:60]}  (front)")

            for link in front_parsed.get("links", []):
                n = _normalize_url(link, host)
                if n and n not in visited:
                    queue.append((n, 1, front_page["url"]))
    except Exception as e:
        log.debug(f"    front-page auth re-fetch failed: {e}")

    # ── Step 2: seed with standard paths ──
    for path in POST_AUTH_PROBE_PATHS:
        url = base_url.rstrip("/") + path
        if url not in visited:
            queue.append((url, 1, None))

    # ── Step 3: seed with previously 401/403 ──
    for p in host_result.get("pages", []):
        if p.get("status_code") in (401, 403):
            if p["url"] not in visited:
                queue.append((p["url"], 1, None))

    # ── Step 4: BFS ──
    while queue and len(new_pages) < max_pages:
        if session.dead:
            break
        url, depth, ref = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        probed += 1

        res = session.get_with_origin_fallback(url, referer=ref)
        if res.error or res.status == 0 or res.status in (401, 403):
            log.debug(f"    probe {url[:60]} → {res.status or 'err'} (skip)")
            continue

        final_url = res.final_url or res.url
        final_host = _host_of(final_url)
        if final_host != host:
            continue
        if any(p in final_url.lower() for p in AUTH_LOGIN_PATHS):
            log.debug(f"    probe {url[:60]} → redirected to login (skip)")
            continue

        parsed = _parse_html(res.body or "", final_url)
        page = _build_page_record(
            res, host, depth, parsed, referer=ref, authenticated=True,
        )
        page["kind"] = "auth"
        page["interesting"] = True
        if "authenticated_access" not in page["reasons"]:
            page["reasons"].append("authenticated_access")
        if "crawl-authenticated" not in page["chain_ids"]:
            page["chain_ids"].append("crawl-authenticated")

        new_pages.append(page)
        hits += 1
        log.ok(f"    {Sym.LOCK} AUTH page: [auth    ] "
                f"{res.status:>3} {page['url'][:60]}")

        if depth < 3:
            for link in parsed.get("links", []):
                n = _normalize_url(link, host)
                if n and n not in visited:
                    queue.append((n, depth + 1, page["url"]))

    # ── Summary ──
    if hits == 0:
        log.warn(f"    post-auth crawl: probed {probed} path(s), found 0 new — "
                  f"site may have no authenticated-only pages")
    else:
        log.ok(f"    post-auth crawl: probed {probed} path(s), found {hits}")

    return {"pages": new_pages, "authenticated_count": len(new_pages),
            "probed": probed}

# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  BATCH AI TRIAGE (per-host, saves markdown report)
# ══════════════════════════════════════════════════════════════════════════

AI_BATCH_SYSTEM = (
    "You are an expert web-application security analyst triaging crawl "
    "results. Reference actual URL paths, form fields, and query parameters. "
    "Never suggest running exploits. Be concise."
)


def _run_ai_page_eval(host_result: dict, outdir: Path) -> Optional[dict]:
    if not CFG_LOADED or not bool(_cfg("AI_ENABLED", False)):
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None

    pages = host_result["pages"]
    interesting = [p for p in pages if p.get("interesting")][:25]
    if not interesting:
        return None

    log.info(f"    AI batch triage: {len(interesting)} page(s)")
    block = "\n".join(
        f"  [{p.get('kind'):<8}] {p.get('status_code', 0):>3} {p['url']}\n"
        f"    params={p.get('params', [])[:5]} forms={len(p.get('forms', []))} "
        f"summary={p.get('page_summary', {}).get('summary', '')[:80]}"
        for p in interesting
    )

    prompt = (
        f"Crawl of {host_result['host']} found {len(pages)} pages "
        f"({len(interesting)} interesting).\n\n{block}\n\n"
        f"Provide:\n"
        f"1. Top 5 pages to investigate manually, with reasoning.\n"
        f"2. Specific vulns to test on each (name the field/param).\n"
        f"3. Any auth-flow weakness from form structure.\n"
        f"Under 600 words. Markdown."
    )
    try:
        response = ai_fn(prompt, system=AI_BATCH_SYSTEM)
    except Exception as e:
        log.warn(f"    AI batch failed: {type(e).__name__}: {e}")
        return None
    if not response:
        return None

    safe = _safe_filename(host_result["host"])
    md_path = outdir / f"crawl_ai_{safe}.md"
    md_path.write_text(
        f"# Sköll AI · {host_result['host']}\n\n"
        f"**Pages:** {len(pages)} · **Interesting:** {len(interesting)}\n\n"
        f"---\n\n{response}\n",
        encoding="utf-8",
    )
    log.ok(f"    AI batch saved: {md_path.name}")

    cost = None
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            cost = round(tracker.estimate_cost(), 6)
    except Exception:
        pass

    return {"path": str(md_path), "cost_estimate": cost,
            "interesting": len(interesting)}


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  INPUT LOADING
# ══════════════════════════════════════════════════════════════════════════

def _load_targets(input_file: Path, only_confirmed: bool) -> list[dict]:
    if not input_file.exists():
        raise FileNotFoundError(f"input not found: {input_file}")

    targets: list[dict] = []
    if input_file.suffix == ".json":
        try:
            data = json.loads(input_file.read_text())
            hosts = data.get("hosts") or data.get("findings") or []
            for h in hosts:
                if only_confirmed and h.get("severity") not in ("HIGH", "CRITICAL"):
                    continue
                url = h.get("url") or ""
                host = h.get("host") or _host_of(url)
                if host:
                    targets.append({
                        "url": url, "host": host,
                        "severity": h.get("severity", "LOW"),
                    })
            if targets:
                return targets
        except Exception as e:
            log.warn(f"JSON parse failed ({e}) — falling back to text")

    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        host = _host_of(token)
        if host and host not in seen:
            seen.add(host)
            targets.append({"url": token, "host": host, "severity": "LOW"})
    return targets


def _load_resume_hosts(host_path: Path) -> set[str]:
    done: set[str] = set()
    if not host_path.exists():
        return done
    try:
        for line in host_path.read_text(encoding="utf-8").splitlines():
            try:
                h = json.loads(line).get("host")
                if h:
                    done.add(h)
            except Exception:
                continue
    except Exception:
        pass
    return done


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  AGGREGATION
# ══════════════════════════════════════════════════════════════════════════

def _audit_hash(audit_path: Optional[Path]) -> Optional[str]:
    if not audit_path:
        return None
    try:
        h = hashlib.sha256()
        with open(audit_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _aggregate_chains(all_hosts: list[dict]) -> list[dict]:
    chains: dict[str, list[str]] = {}
    for h in all_hosts:
        for c in h.get("chains", []):
            chains.setdefault(c["chain_id"], []).extend(c.get("members", []))
    result = []
    for cid, members in chains.items():
        result.append({
            "chain_id": cid,
            "name":     CHAIN_NAMES.get(cid, cid),
            "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
            "members":  members[:100],
            "count":    len(members),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result.sort(key=lambda c: (order.get(c["severity"], 5), c["chain_id"]))
    return result


def _build_summary(all_hosts: list[dict]) -> dict:
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_framework: dict[str, int] = {}
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0,
                                "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_pages = 0
    dead_hosts = 0
    origin_fallbacks = 0
    ai_summaries = 0
    waf_blocked_hosts = 0
    authenticated_hosts: list[str] = []
    auth_pending_hosts: list[str] = []

    for h in all_hosts:
        if h.get("dead"):
            dead_hosts += 1
        elif h.get("waf_blocked"):
            waf_blocked_hosts += 1
        ai_summaries += h.get("ai_summaries", 0)

        ar = h.get("auth_result") or {}
        if ar.get("status") in ("authenticated", "reused_cookies"):
            authenticated_hosts.append(h["host"])
        elif ar.get("status") in ("verify_needed", "failed", "already_exists",
                                    "ambiguous", "registered_pending_manual"):
            auth_pending_hosts.append(h["host"])

        for p in h["pages"]:
            total_pages += 1
            by_kind[p["kind"]] = by_kind.get(p["kind"], 0) + 1
            by_status[str(p["status_code"])] = by_status.get(str(p["status_code"]), 0) + 1
            for fw in (p.get("framework") or []):
                by_framework[fw] = by_framework.get(fw, 0) + 1
            if p.get("origin_fallback_used"):
                origin_fallbacks += 1
            sev = p.get("severity", "INFO")
            by_sev[sev] = by_sev.get(sev, 0) + 1

    return {
        "waf_blocked_hosts":   waf_blocked_hosts,
        "hosts":               len(all_hosts),
        "dead_hosts":          dead_hosts,
        "total_pages":         total_pages,
        "origin_fallbacks":    origin_fallbacks,
        "ai_summaries":        ai_summaries,
        "authenticated_hosts": authenticated_hosts,
        "auth_pending_hosts":  auth_pending_hosts,
        "by_kind":             dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        "by_status_code":      dict(sorted(by_status.items(), key=lambda kv: int(kv[0]))),
        "by_framework":        dict(sorted(by_framework.items(), key=lambda kv: -kv[1])),
        "by_severity":         by_sev,
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def run_site_crawl(
    live_urls_file: Path,
    outdir: Path,
    *,
    max_pages: int = DEFAULT_MAX_PAGES_PER_HOST,
    max_depth: int = DEFAULT_MAX_DEPTH,
    page_delay: float = DEFAULT_PAGE_DELAY,
    force_requests: bool = False,
    scan_id: Optional[int] = None,
    bbp_program: Optional[str] = None,
    auto_register: bool = False,
    only_confirmed: bool = False,
    aggressive: bool = True,
    use_proxy: bool = True,
    respect_robots: bool = False,
    resume: bool = False,
    dry_run: bool = False,
    origin_fallback: bool = True,
    proxy_pool: Any = None,
    audit_trail: Any = None,
) -> Path:
    start = time.monotonic()
    outdir = outdir or (_cfg("OUTPUT_DIR") or Path("output"))
    outdir.mkdir(parents=True, exist_ok=True)

    targets = _load_targets(live_urls_file, only_confirmed)
    log.info(f"Input  : {len(targets)} target(s) from {live_urls_file.name}")
    if only_confirmed:
        log.info(f"         only_confirmed=on (HIGH+ from live_hosts.json)")

    if not targets:
        log.warn("no targets to crawl")
        return _write_empty(outdir, live_urls_file, start)

    host_stream_path = outdir / "site_pages_hosts.jsonl"
    page_stream_path = outdir / "site_pages_pages.jsonl"

    if resume:
        done = _load_resume_hosts(host_stream_path)
        if done:
            targets = [t for t in targets if t["host"] not in done]
            log.info(f"Resume : skipping {len(done)} host(s) — "
                      f"{len(targets)} remaining")
    else:
        if host_stream_path.exists():
            host_stream_path.unlink()
        if page_stream_path.exists():
            page_stream_path.unlink()

    max_pages, max_depth = _effective_limits(max_pages, max_depth)

    log.info("")
    log.info(f"Config : max_pages={max_pages}  max_depth={max_depth}  delay={page_delay}s")
    log.info(f"         aggressive={aggressive}  auto_register={auto_register}  "
              f"respect_robots={respect_robots}  proxy={use_proxy}")
    log.info(f"         origin_fallback={origin_fallback}  "
              f"ai_enabled={bool(_cfg('AI_ENABLED', False))}")
    if LIGHTWEIGHT_MODE:
        log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — limits capped")

    creds_store = CredentialStore(_creds_path(outdir))
    log.info(f"Creds  : {creds_store.count()} existing account(s) in {creds_store.path.name}")

    origin_loader = OriginLoader()
    log.info(f"Origins: {origin_loader.host_count()} host(s) in origin_hunt.json")

    if auto_register:
        log.warn("")
        log.warn("  ⚠  AUTO-REGISTER IS ENABLED")
        log.warn("     Sköll will register accounts using config.EMAIL")
        log.warn("     Only proceed on AUTHORIZED targets.")

    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        for t in targets[:20]:
            log.info(f"  would crawl  {t['host']}  [{t['severity']}]")
        if len(targets) > 20:
            log.info(f"  … and {len(targets) - 20} more")
        return outdir / "site_pages.json"

    if use_proxy and proxy_pool is None:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls is not None:
                proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
        except Exception as e:
            log.debug(f"ProxyPool load failed: {e}")

    if audit_trail is None:
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                audit_trail = factory("crawl-" + live_urls_file.stem)
        except Exception:
            pass

    all_hosts: list[dict] = []
    for i, t in enumerate(targets, 1):
        host = t["host"]
        log.rune(Rune.RAIDO, f"[{i}/{len(targets)}] {host}")

        try:
            session = HostSession(
                host=host, bbp_program=bbp_program,
                proxy_pool=proxy_pool, audit_trail=audit_trail,
                use_proxy=use_proxy, respect_robots=respect_robots,
                origin_loader=origin_loader,
                origin_fallback=origin_fallback,
            )
            if proxy_pool is not None:
                log.info(f"  proxy    : rotating from pool")
            else:
                log.info(f"  proxy    : direct")
            if origin_fallback and origin_loader.has_any(host):
                log.info(f"  origins  : {len(origin_loader.get_usable_origins(host))} "
                          f"usable fallback IP(s)")

            host_result = _crawl_host(
                host=host, session=session,
                max_pages=max_pages, max_depth=max_depth,
                aggressive=aggressive,
                page_stream_path=page_stream_path,
            )

            # ── v8.0 Auth flow ──
            auth_pages_in_result = [
                p for p in host_result["pages"]
                if p.get("kind") in ("login", "register")
            ]
            has_auth_surface = bool(auth_pages_in_result)

            # LOUD warning when auth pages found but --auto-register is off
            if has_auth_surface and not auto_register:
                log.warn("")
                log.warn(f"  {Sym.WARN} AUTH SURFACE DETECTED on {host}")
                for ap in auth_pages_in_result[:3]:
                    log.warn(f"       [{ap['kind']}] {ap['url']}")
                log.warn(f"       Re-run with --auto-register to crawl authenticated content")
                log.warn("")

            if auto_register and has_auth_surface:
                auth_result = _do_auth_flow(
                    host=host, pages=host_result["pages"],
                    session=session, outdir=outdir,
                    creds_store=creds_store,
                )
            if auth_result:
                host_result["auth_result"] = {
                    "status":              auth_result.get("status", "unknown"),
                    "method":              auth_result.get("login_status", "unknown"),
                    "email":               auth_result.get("email", ""),
                    "verification_method": auth_result.get("verification_method"),
                    "verification_url":    auth_result.get("verification_url"),
                    "landing_url":         auth_result.get("landing_url", ""),
                    "landing_state":       auth_result.get("landing_state", ""),
                    "landing_signals":     auth_result.get("landing_signals", []),
                    "note":                auth_result.get("note", ""),
                    "error":               auth_result.get("error", ""),
                }

                # ★ v8.2.1 — ONE clear auth result line per host
                status = auth_result.get("status", "unknown")
                if status in ("authenticated", "reused_cookies"):
                    log.ok(f"  {Sym.CHECK} AUTH: {status}  "
                            f"(method={auth_result.get('login_status', '?')}, "
                            f"email={auth_result.get('email', '?')})")
                    # → post-auth BFS
                    log.info(f"    {Sym.LOCK} Crawling authenticated surface")
                    auth_crawl = _post_auth_crawl(
                        host=host, session=session, host_result=host_result,
                    )
                    if auth_crawl.get("pages"):
                        auth_urls = {p["url"] for p in auth_crawl["pages"]}
                        host_result["pages"] = [
                            p for p in host_result["pages"]
                            if p["url"] not in auth_urls
                        ] + auth_crawl["pages"]
                        if not any(c.get("chain_id") == "crawl-authenticated"
                                    for c in host_result["chains"]):
                            host_result["chains"].append({
                                "chain_id": "crawl-authenticated",
                                "name":     CHAIN_NAMES["crawl-authenticated"],
                                "severity": CHAIN_SEVERITY["crawl-authenticated"].value,
                                "members":  [p["url"] for p in auth_crawl["pages"][:10]],
                                "count":    len(auth_crawl["pages"]),
                            })
                elif status == "already_exists":
                    log.error(f"  {Sym.CROSS} AUTH: account exists but login failed  "
                            f"({auth_result.get('error', '?')}) — MANUAL intervention")
                elif status == "failed":
                    log.error(f"  {Sym.CROSS} AUTH: failed  "
                            f"({auth_result.get('error', '?')})")
                elif status == "rate_limited":
                    log.warn(f"  {Sym.WARN} AUTH: rate-limited — skipping retry")
                elif status == "pending_manual":
                    log.warn(f"  {Sym.WARN} AUTH: pending manual  "
                            f"({auth_result.get('note', '?')})")
                elif status == "verify_needed":
                    log.warn(f"  {Sym.WARN} AUTH: needs email verification  "
                            f"({auth_result.get('note', '?')})")
                else:
                    log.info(f"  · AUTH: {status}")

                    if auth_result.get("status") in ("authenticated", "reused_cookies"):
                        # v8.0: full post-auth BFS
                        log.info(f"    {Sym.LOCK} Crawling authenticated surface")
                        auth_crawl = _post_auth_crawl(
                            host=host, session=session, host_result=host_result,
                        )
                        if auth_crawl.get("pages"):
                            auth_urls = {p["url"] for p in auth_crawl["pages"]}
                            host_result["pages"] = [
                                p for p in host_result["pages"]
                                if p["url"] not in auth_urls
                            ] + auth_crawl["pages"]
                            log.ok(f"    +{len(auth_crawl['pages'])} authenticated page(s)")

                            if not any(c.get("chain_id") == "crawl-authenticated"
                                        for c in host_result["chains"]):
                                host_result["chains"].append({
                                    "chain_id": "crawl-authenticated",
                                    "name":     CHAIN_NAMES["crawl-authenticated"],
                                    "severity": CHAIN_SEVERITY["crawl-authenticated"].value,
                                    "members":  [p["url"] for p in auth_crawl["pages"][:10]],
                                    "count":    len(auth_crawl["pages"]),
                                })

            ai_eval = _run_ai_page_eval(host_result, outdir)
            if ai_eval:
                host_result["ai_eval"] = ai_eval

            host_result["interesting_count"] = sum(
                1 for p in host_result["pages"] if p.get("interesting"))

            all_hosts.append(host_result)

            with host_stream_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(host_result, ensure_ascii=False) + "\n")

            status_marker = "☠ dead" if host_result.get("dead") else "✓"
            fw_count = len(set(fw for p in host_result["pages"]
                                for fw in (p.get("framework") or [])))
            fb_count = sum(1 for p in host_result["pages"]
                            if p.get("origin_fallback_used"))
            log.ok(f"  {status_marker} {len(host_result['pages'])} page(s), "
                    f"{host_result['interesting_count']} interesting, "
                    f"{len(host_result['assets_js'])} JS, "
                    f"{len(host_result['endpoints'])} endpoints, "
                    f"{fw_count} fw, {fb_count} origin-fb, "
                    f"{host_result.get('ai_summaries', 0)} AI")

        except Exception as e:
            log.error(f"  host failed: {type(e).__name__}: {e}")
            all_hosts.append({
                "host": host, "base_url": f"https://{host}",
                "pages": [], "assets_js": [], "assets_css": [],
                "endpoints": [], "chains": [],
                "session_stats": {}, "error": str(e),
                "dead": True, "dead_reason": str(e),
                "ai_summaries": 0,
            })

    chains = _aggregate_chains(all_hosts)
    summary = _build_summary(all_hosts)
    elapsed = time.monotonic() - start
    audit_path = getattr(audit_trail, "path", None) if audit_trail else None

    report = {
        "schema_version":  8,
        "producer":        f"site_crawler.py v{__version__} '{__codename__}'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":      str(live_urls_file),
        "bbp_program":     bbp_program,
        "auto_register":   auto_register,
        "respect_robots":  respect_robots,
        "aggressive":      aggressive,
        "origin_fallback": origin_fallback,
        "ai_enabled":      bool(_cfg("AI_ENABLED", False)),
        "host_capacity": {
            "cpu_cores": HOST_CORES, "ram_mb": HOST_RAM_MB,
            "lightweight": LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "max_pages": max_pages, "max_depth": max_depth,
            "page_delay": page_delay,
            "ai_page_summary_limit": AI_PAGE_SUMMARY_LIMIT,
            "js_fetch_limit": JS_FETCH_LIMIT,
            "css_fetch_limit": CSS_FETCH_LIMIT,
        },
        "origin_data": {
            "loaded_hosts": origin_loader.host_count(),
            "path":         str(origin_loader.path),
        },
        "audit": {
            "trail_path":   str(audit_path) if audit_path else None,
            "trail_sha256": _audit_hash(audit_path),
        },
        "credentials": {
            "store_path": str(creds_store.path),
            "count":      creds_store.count(),
        },
        "totals":  summary,
        "chains":  chains,
        "hosts":   all_hosts,
    }

    json_path = outdir / "site_pages.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    page_urls, auth_urls = [], []
    for h in all_hosts:
        for p in h["pages"]:
            page_urls.append(p["url"])
            if p["kind"] in ("login", "register"):
                auth_urls.append(p["url"])
    (outdir / "site_pages.txt").write_text("\n".join(page_urls) + "\n")
    (outdir / "auth_pages.txt").write_text("\n".join(auth_urls) + "\n")

    _print_summary(outdir, all_hosts, summary, chains, elapsed, creds_store)

    if scan_id is not None:
        _try_db_sync(scan_id, all_hosts)
    return json_path


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SUMMARY / OUTPUT
# ══════════════════════════════════════════════════════════════════════════

def _print_summary(outdir: Path, all_hosts: list[dict], summary: dict,
                    chains: list[dict], elapsed: float,
                    creds_store: CredentialStore) -> None:
    log.rune(Rune.SOWILO, "Summary")
    log.info(f"Hosts crawled    : {summary.get('hosts', 0)}")
    log.info(f"Dead (unreach.)  : {summary.get('dead_hosts', 0)}")
    if summary.get("waf_blocked_hosts", 0):
        log.info(f"WAF-blocked      : {summary['waf_blocked_hosts']}  "
                 f"(hosts alive, refused to serve)")
    log.info(f"Total pages      : {summary.get('total_pages', 0)}")

    auth_hosts = summary.get("authenticated_hosts", [])
    if auth_hosts:
        log.info(f"Authenticated    : {len(auth_hosts)} host(s)")
        for h in auth_hosts[:5]:
            log.info(f"  {Sym.CHECK} {h}")
    pending = summary.get("auth_pending_hosts", [])
    if pending:
        log.info(f"Auth pending     : {len(pending)} host(s)")

    by_kind = summary.get("by_kind") or {}
    if by_kind:
        log.info("By kind          : " + " · ".join(
            f"{k}({v})" for k, v in list(by_kind.items())[:8]))

    by_fw = summary.get("by_framework") or {}
    if by_fw:
        log.info("By framework     : " + " · ".join(
            f"{k}({v})" for k, v in list(by_fw.items())[:8]))

    by_sev = summary.get("by_severity") or {}
    log.info("Severity         : " + " ".join(
        f"{k}={by_sev.get(k, 0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))

    if creds_store.count() > 0:
        log.info("")
        log.info(f"Credentials      : {creds_store.count()} account(s)")

    if chains:
        log.info("")
        log.info("Chains:")
        for c in chains[:10]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<32} "
                     f"[{c['severity']}] {c['count']} member(s)")

    log.info("")
    log.info("Outputs:")
    log.info(f"  {Sym.ARROW} site_pages.json")
    log.info(f"  {Sym.ARROW} site_pages_hosts.jsonl       (per-host)")
    log.info(f"  {Sym.ARROW} site_pages_pages.jsonl       (per-page)")
    log.info(f"  {Sym.ARROW} site_pages.txt")
    log.info(f"  {Sym.ARROW} auth_pages.txt")
    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "schema_version": 8,
        "producer": f"site_crawler.py v{__version__} '{__codename__}'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "totals": {"hosts": 0, "dead_hosts": 0, "total_pages": 0,
                    "origin_fallbacks": 0, "ai_summaries": 0},
        "chains": [], "hosts": [],
    }
    p = outdir / "site_pages.json"
    p.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("site_pages.txt", "auth_pages.txt",
                  "site_pages_hosts.jsonl", "site_pages_pages.jsonl"):
        (outdir / name).write_text("")
    return p


def _try_db_sync(scan_id: int, all_hosts: list[dict]) -> None:
    try:
        from db import DB  # type: ignore
        if not getattr(DB, "available", False):
            return
        payloads = []
        for h in all_hosts:
            for p in h["pages"]:
                payloads.append({
                    "url": p["url"], "host": p["host"], "path": p["path"],
                    "title": p["title"], "status_code": p["status_code"],
                    "kind": p["kind"], "interesting": p.get("interesting", False),
                })
        if payloads:
            DB.upsert_site_pages(scan_id, payloads)
            log.info(f"DB sync: {len(payloads)} page(s)")
    except Exception as e:
        log.debug(f"DB sync skipped: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Sköll integrity")

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",           lambda: CFG_LOADED),
        ("Rune.RAIDO",              lambda: Rune.RAIDO == "ᚱ"),
        ("Severity ranks",          lambda: Severity.CRITICAL.rank == 4),
        ("_host_of works",          lambda: _host_of("https://a.b.com/x") == "a.b.com"),
        ("_host_of empty",          lambda: _host_of("") == ""),
        ("_safe_filename",          lambda: _safe_filename("a/b?c") == "a_b_c"),
        ("_normalize_url strips",   lambda: _normalize_url(
                                        "https://a.com/x.png", "a.com") is None),
        ("_normalize_url keeps",    lambda: _normalize_url(
                                        "https://a.com/page", "a.com") is not None),
        ("_extract_params",         lambda: _extract_params(
                                        "https://x/y?a=1&b=2") == ["a", "b"]),
        ("_parse_html title",       lambda: _parse_html(
                                        "<html><title>T</title></html>",
                                        "https://x")["title"] == "T"),
        ("_parse_html form code",   lambda: any(
                                        f.get("has_code_field")
                                        for f in _parse_html(
                                            '<form><input name="otp"></form>',
                                            "https://x")["forms"])),
        ("_parse_html csrf",        lambda: any(
                                        f.get("csrf")
                                        for form in _parse_html(
                                            '<form><input name="csrf_token" value="t"></form>',
                                            "https://x")["forms"]
                                        for f in form["fields"])),
        ("_parse_robots",           lambda: _parse_robots_txt(
                                        "Sitemap: https://x/sitemap.xml",
                                        "https://x/")["sitemaps"] == ["https://x/sitemap.xml"]),
        ("_parse_sitemap_xml",      lambda: _parse_sitemap_xml(
                                        "<urlset><url><loc>https://x/a</loc></url></urlset>",
                                        "https://x/") == ["https://x/a"]),
        ("_classify admin",         lambda: _classify_page(
                                        "https://x/admin", "", [], {})[0] == "admin"),
        ("_classify login",         lambda: _classify_page(
                                        "https://x/login", "", [], {})[0] == "login"),
        ("_classify register",      lambda: _classify_page(
                                        "https://x/register", "", [], {})[0] == "register"),
        # v8.0 — THE critical fix
        ("_classify /register.php", lambda: _classify_page(
                                        "https://x/register.php", "", [], {})[0] == "register"),
        ("_classify /login.php",    lambda: _classify_page(
                                        "https://x/login.php", "", [], {})[0] == "login"),
        ("_classify pw+email+user no confirm → register",
                                     lambda: _classify_page(
                                        "https://x/", "",
                                        [{"fields": [
                                            {"name": "password", "type": "password"},
                                            {"name": "email", "type": "email"},
                                            {"name": "username", "type": "text"},
                                        ]}], {})[0] == "register"),
        ("_classify pw+email only → login",
                                     lambda: _classify_page(
                                        "https://x/", "",
                                        [{"fields": [
                                            {"name": "password", "type": "password"},
                                            {"name": "email", "type": "email"},
                                        ]}], {})[0] == "login"),
        ("_heuristic debug HIGH",   lambda: _heuristic_score(
                                        {"kind": "debug", "params": [], "forms": [],
                                         "headers_security": {}, "status_code": 200,
                                         "chain_ids": []})[1] == Severity.HIGH),
        ("_detect_frameworks wp",   lambda: "wordpress" in _detect_frameworks(
                                        '<html><link href="/wp-content/x.css"></html>',
                                        {}, [], ["/wp-content/x.css"], {})),
        ("_detect_frameworks react", lambda: "react" in _detect_frameworks(
                                        "<html></html>", {}, ["react-dom.prod.js"],
                                        [], {"generator": "react"})),
        ("_detect_waf_block cf",    lambda: _detect_waf_block(HttpResult(
                                        403, {"cf-mitigated": "challenge"},
                                        "attention required", "", "", 0))[0] is True),
        ("_detect_waf_block ok",    lambda: _detect_waf_block(HttpResult(
                                        200, {"server": "nginx"},
                                        "<html>content</html>", "", "", 0))[0] is False),
        ("_text_preview strips",    lambda: "<script" not in _text_preview(
                                        "<html><script>x</script>body</html>")),
        ("_extract_verification link", lambda: _extract_verification(
                                            {"body": "Click https://x/verify?t=a to verify",
                                             "subject": "Verify", "from": "noreply@x"},
                                            "x")["method"] == "link"),
        ("_extract_verification code", lambda: _extract_verification(
                                            {"body": "Your code: 123456",
                                             "subject": "Verify", "from": "noreply@x"},
                                            "x")["method"] == "code"),
        ("_categorize_error ssl",   lambda: _categorize_error(ssl.SSLError("x")) == "ssl"),
        ("_categorize_error dns",   lambda: _categorize_error(socket.gaierror(1, "x")) == "dns"),
        ("HostSession init",        lambda: callable(HostSession)),
        ("HostSession.post has allow_redirects",
                                     lambda: "allow_redirects" in
                                     HostSession.post.__code__.co_varnames),
        ("_crawl_host callable",    lambda: callable(_crawl_host)),
        ("_analyze_js_file",        lambda: callable(_analyze_js_file)),
        ("_analyze_css_file",       lambda: callable(_analyze_css_file)),
        ("_find_register_form",     lambda: callable(_find_register_form)),
        ("_find_login_form",        lambda: callable(_find_login_form)),
        ("_find_code_verification_form",
                                     lambda: callable(_find_code_verification_form)),
        ("_attempt_code_verification",
                                     lambda: callable(_attempt_code_verification)),
        ("_generate_password",      lambda: len(_generate_password()) >= 12),
        ("_build_form_payload code", lambda: _build_form_payload(
                                        {"fields": [
                                            {"name": "otp", "code": True},
                                            {"name": "email", "type": "email"},
                                        ]},
                                        {"code": "123456", "email": "x@y"})["otp"] == "123456"),
        ("_load_targets callable",  lambda: callable(_load_targets)),
        ("_ai_summarize_page",      lambda: callable(_ai_summarize_page)),
        ("_heuristic_page_summary", lambda: "summary" in _heuristic_page_summary(
                                        {"kind": "login", "params": ["id"],
                                         "forms": [{"fields": [{"name": "user", "type": "text"}]}],
                                         "framework": ["react"]})),
        ("_run_ai_page_eval",       lambda: callable(_run_ai_page_eval)),
        ("_do_auth_flow",           lambda: callable(_do_auth_flow)),
        ("_detect_auth_state",      lambda: callable(_detect_auth_state)),
        ("_attempt_login_v2",       lambda: callable(_attempt_login_v2)),
        ("_post_auth_crawl",        lambda: callable(_post_auth_crawl)),
        ("_cookie_signature",       lambda: callable(_cookie_signature)),
        ("_detect_new_auth_cookies", lambda: _detect_new_auth_cookies(
                                        frozenset(), frozenset([("session", "x")])
                                        ) == ["session"]),
        ("OriginLoader init",       lambda: callable(OriginLoader)),
        ("CredentialStore init",    lambda: callable(CredentialStore)),
        ("run_site_crawl",          lambda: callable(run_site_crawl)),
        ("_aggregate_chains",       lambda: callable(_aggregate_chains)),
        ("_build_summary",          lambda: callable(_build_summary)),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                log.ok(name); passed += 1
            else:
                log.error(f"{name} → False"); failed += 1
        except Exception as e:
            log.error(f"{name} → {type(e).__name__}: {e}"); failed += 1

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ SELFTEST PASSED · {passed} checks ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('crimson')}{Sym.SKULL}  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  {Sym.SKULL}{_c('reset')}")
    return 1


def config_check() -> int:
    print_banner()
    log.rune(Rune.KANO, "Config integration check")

    if not CFG_LOADED:
        log.error("config.py NOT loaded")
        if _CFG_IMPORT_ERROR:
            log.info(f"  import error: {_CFG_IMPORT_ERROR}")
        return 1

    log.ok("config.py loaded")
    log.info(f"  version: {_cfg('__version__', '?')} \"{_cfg('__codename__', '?')}\"")

    items = [
        ("SCOPE",                    lambda: _cfg("SCOPE") is not None),
        ("ProxyPool",                lambda: _cfg("ProxyPool") is not None),
        ("KillSwitch",               lambda: _cfg("KillSwitch") is not None),
        ("new_audit_trail",          lambda: callable(_cfg("new_audit_trail"))),
        ("RateLimiter",              lambda: _cfg("RateLimiter") is not None),
        ("human_delay",              lambda: callable(_cfg("human_delay"))),
        ("random_user_agent",        lambda: callable(_cfg("random_user_agent"))),
        ("build_headers",            lambda: callable(_cfg("build_headers"))),
        ("EMAIL",                    lambda: _cfg("EMAIL") is not None),
        ("find_verification_email",  lambda: callable(_cfg("find_verification_email"))),
        ("ai_complete",              lambda: callable(_cfg("ai_complete"))),
    ]
    failed = 0
    for name, fn in items:
        try:
            if fn():
                log.ok(name)
            else:
                log.warn(f"{name} — not configured")
                failed += 1
        except Exception as e:
            log.error(f"{name} — {e}")
            failed += 1

    log.info(f"  AI_ENABLED    : {_cfg('AI_ENABLED', False)}")
    log.info(f"  PROXY_ROTATION: {_cfg('PROXY_ROTATION', True)}")
    log.info(f"  Credentials   : {_creds_path(Path.cwd())}")

    ol = OriginLoader()
    log.info(f"  Origin hunt   : {ol.host_count()} host(s) in {ol.path}")
    if ol.host_count() == 0:
        log.warn("  origin_hunt.json not found or empty — WAF fallback disabled")

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} item(s) unconfigured ══  {Sym.WARN}{_c('reset')}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_hosts.json"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"

    p = argparse.ArgumentParser(
        prog="site_crawler.py",
        description=f"Argus recon · site_crawler v{__version__} '{__codename__}'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=base / "output")
    p.add_argument("--bbp", type=str, default=None)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES_PER_HOST)
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p.add_argument("--delay", type=float, default=DEFAULT_PAGE_DELAY)
    p.add_argument("--auto-register", action="store_true",
                    help="attempt registration with config.EMAIL (creates real accounts)")
    p.add_argument("--only-confirmed", action="store_true",
                    help="crawl only HIGH+ hosts from live_hosts.json")
    p.add_argument("--fast", dest="aggressive", action="store_false",
                    default=True, help="fast mode: no JS/CSS/endpoint probing")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--respect-robots", action="store_true",
                    help="respect robots.txt Disallow rules")
    p.add_argument("--no-origin-fallback", action="store_true",
                    help="disable WAF → origin IP fallback")
    p.add_argument("--resume", action="store_true",
                    help="skip hosts already in site_pages_hosts.jsonl")
    p.add_argument("--requests", action="store_true",
                    help="accepted for backward compat")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                    version=f"site_crawler.py {__version__} '{__codename__}'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try:
            CFG.Palette._enabled = False  # type: ignore
        except Exception:
            pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    if args.selftest:
        return selftest()
    if args.config_check:
        return config_check()

    print_banner()

    try:
        run_site_crawl(
            live_urls_file=args.input,
            outdir=args.output,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            page_delay=args.delay,
            force_requests=args.requests,
            scan_id=args.scan_id,
            bbp_program=args.bbp,
            auto_register=args.auto_register,
            only_confirmed=args.only_confirmed,
            aggressive=args.aggressive,
            use_proxy=not args.no_proxy,
            respect_robots=args.respect_robots,
            resume=args.resume,
            dry_run=args.dry_run,
            origin_fallback=not args.no_origin_fallback,
        )
        return 0
    except KeyboardInterrupt:
        log.warn("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
