#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛗ ᛁ ᛗ ᛁ ᚱ   ·   J S   A N A L Y S I S   ·   M Í M I R ' S   E Y E
================================================================================
  File      : recon_tools/js_analysis.py
  Version   : 2.0.0 "MÍMIR'S EYE"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Deep JavaScript analysis — 24 detection methods, AI triage ready.

  Reads site_pages.json (from site_crawler.py) OR live_urls.txt OR a
  directory of pre-downloaded JS files. Every request passes through
  FENRIR config: SCOPE.enforce(), KillSwitch.check(), AuditTrail.record(),
  RateLimiter.acquire(), human_delay(), random_user_agent(), ProxyPool,
  build_headers(bbp).

  Detection categories (24 methods):
    ENDPOINTS  (18)  REST · absolute · GraphQL · WebSocket · socket.io ·
                     route · fetch/XHR · XHR.open · jQuery ajax · Angular ·
                     Vue router · Next.js API · GraphQL ops · Firebase ·
                     Supabase · S3 · CDN
    SECRETS    (50+) AWS · GCP · Azure · Stripe · GitHub · GitLab · Slack ·
                     Discord · Twilio · SendGrid · Mailgun · npm · PyPI ·
                     Anthropic · OpenAI · Cohere · HuggingFace · Replicate ·
                     Cloudflare · DigitalOcean · Heroku · Linear · Notion ·
                     Airtable · Algolia · Mapbox · Supabase · Firebase ·
                     Shopify · Contentful · Segment · Datadog · New Relic ·
                     PagerDuty · Snyk · Okta · Asana · JWT · Bearer · PEM ·
                     PGP · DB connection · DATABASE_URL · generic
    XSS SINKS  (9)   innerHTML · outerHTML · document.write · eval ·
                     Function() · dangerouslySetInnerHTML · v-html ·
                     [innerHTML] · .html()
    PROTO POLL (4)   __proto__ · constructor.prototype · Object.assign ·
                     lodash merge
    OTHER      (3)   postMessage(*) · dynamic imports · service workers
    LEAKS      (4)   TODO comments · internal URLs · debug flags · storage keys
    ANALYSIS   (3)   JWT alg:none / weak sig · source map fetch · framework ID

  AI triage (DeepSeek) when AI_ENABLED=True in config.py:
    ·  Per-host structured JSON report
    ·  Saved to js_ai_<host>.md alongside the aggregated JSON
    ·  Same output schema as heuristic fallback

  Heuristic triage (always on):
    ·  Same schema, built from finding data
    ·  Used when AI_ENABLED=False, or as fallback if AI fails
    ·  Zero API cost, zero network calls

  Outputs:
    js_findings.json               — aggregated report (contains real secrets!)
    js_analysis_hosts.jsonl        — per-host streamed (crash-safe)
    js_endpoints.txt               — one endpoint per line
    js_secrets.txt                 — subtype host redacted file:line
    js_sourcemaps.txt              — one URL per line
    js_files.txt                   — one JS URL per line
    js_ai_<host>.md                — per-host AI triage (when AI on)
    js_sourcemaps/<host>_<f>.json  — full .map evidence when found

  ⚠  WARNING: js_findings.json and js_sourcemaps/* contain REAL secrets.
     Do NOT commit to git. Do NOT share publicly. Add to .gitignore.

  Usage
  ─────
    python3 recon_tools/js_analysis.py                        # auto-detect
    python3 recon_tools/js_analysis.py --no-proxy --dry-run
    python3 recon_tools/js_analysis.py --bbp hackerone
    python3 recon_tools/js_analysis.py --resume               # resume crash
    python3 recon_tools/js_analysis.py --selftest
    python3 recon_tools/js_analysis.py --config-check
================================================================================
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import math
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
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


def _ai_enabled() -> bool:
    """Read AI_ENABLED dynamically. Works whether config.py is patched or not."""
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


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
    SHIELD = "🛡"; WOLF = "🐺"; EYE = "👁"; KEY = "🔑"; FIRE = "🔥"
    LOCK = "🔒"; GEAR = "⚙"; SHAMROCK = "☘"


class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


__version__ = "2.0.0"
__codename__ = "MÍMIR'S EYE"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛗ ᛁ ᛗ ᛁ ᚱ{R}
    {P}{rule}{R}
    {V}      J S   A N A L Y S I S   ·   M Í M I R ' S   E Y E{R}
    {V}              T H E   H I D D E N   B E C O M E S   K N O W N{R}
    {D}{rule}{R}
    {G}        {Sym.EYE}  v{__version__} "{__codename__}"  ·  24 methods · AI-ready{R}
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

DEFAULT_MAX_FILES        = 2000
DEFAULT_DOWNLOAD_THREADS = 10
DEFAULT_RATE_LIMIT       = 5
DOWNLOAD_TIMEOUT         = 20.0
MAX_JS_SIZE_BYTES        = 10_000_000
MAX_SOURCEMAP_SIZE       = 5_000_000
KATANA_TIMEOUT           = 600
KATANA_DEPTH             = 3
MAX_SOURCEMAP_PROBES     = 100
HUMAN_PAUSE_CHANCE       = 0.10
HUMAN_PAUSE_RANGE        = (3.0, 8.0)
MIN_REPORT_CONFIDENCE    = 25

# AI triage thresholds
AI_MIN_FINDINGS_PER_HOST = 3
AI_MAX_HOSTS_PER_RUN     = 50

# Redaction
REDACT_KEEP_CHARS = 4

# Chain severity map — 20 chains
CHAIN_SEVERITY: dict[str, Severity] = {
    "js-secret-exposed":         Severity.CRITICAL,
    "js-sourcemap-leak":         Severity.HIGH,
    "js-private-key-exposed":    Severity.CRITICAL,
    "js-database-creds-exposed": Severity.CRITICAL,
    "js-jwt-exposed":            Severity.HIGH,
    "js-jwt-weak":               Severity.HIGH,
    "js-admin-endpoint":         Severity.HIGH,
    "js-api-endpoint":           Severity.MEDIUM,
    "js-graphql-endpoint":       Severity.MEDIUM,
    "js-websocket-endpoint":     Severity.MEDIUM,
    "js-internal-url":           Severity.HIGH,
    "js-dom-xss-sink":           Severity.MEDIUM,
    "js-prototype-pollution":    Severity.MEDIUM,
    "js-postmessage-wildcard":   Severity.MEDIUM,
    "js-debug-flag":             Severity.MEDIUM,
    "js-todo-leak":              Severity.LOW,
    "js-framework-detected":     Severity.INFO,
    "js-webpack-modules":        Severity.INFO,
    "js-dynamic-imports":        Severity.INFO,
    "js-service-workers":        Severity.INFO,
}

CHAIN_NAMES: dict[str, str] = {
    "js-secret-exposed":         "Hardcoded secret in JS",
    "js-sourcemap-leak":         "Source map publicly accessible",
    "js-private-key-exposed":    "Private key in JS bundle",
    "js-database-creds-exposed": "Database credentials in JS",
    "js-jwt-exposed":            "JWT token in JS bundle",
    "js-jwt-weak":               "JWT with weak/none algorithm",
    "js-admin-endpoint":         "Admin/internal endpoint in JS",
    "js-api-endpoint":           "API endpoint in JS",
    "js-graphql-endpoint":       "GraphQL endpoint in JS",
    "js-websocket-endpoint":     "WebSocket endpoint in JS",
    "js-internal-url":           "Internal/dev URL in JS",
    "js-dom-xss-sink":           "DOM XSS sink in JS",
    "js-prototype-pollution":    "Prototype pollution sink in JS",
    "js-postmessage-wildcard":   "postMessage wildcard in JS",
    "js-debug-flag":             "Debug flag referenced in JS",
    "js-todo-leak":              "TODO/FIXME comment leak",
    "js-framework-detected":     "Frontend framework detected",
    "js-webpack-modules":        "Webpack module map extracted",
    "js-dynamic-imports":        "Dynamic import() URLs",
    "js-service-workers":        "Service worker URLs",
}

# Known public asset CDNs — fetching JS from these doesn't require SCOPE
CDN_ALLOWLIST = (
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "use.fontawesome.com",
    "kit.fontawesome.com",
    "cdn.shopify.com",
    "static.parastorage.com",
    "assets.website-files.com",
    "cdn.prod.website-files.com",
    "cdn.rawgit.com",
    "raw.githubusercontent.com",
)


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
    if cores <= 2: reasons.append(f"{cores} cores")
    if ram_mb and ram_mb < 2048: reasons.append(f"{ram_mb} MB RAM")
    return cores, ram_mb, ", ".join(reasons) if reasons else ""


HOST_CORES, HOST_RAM_MB, LIGHTWEIGHT_REASON = _measure_host()
LIGHTWEIGHT_MODE = bool(LIGHTWEIGHT_REASON) or os.getenv("ARGUS_LIGHTWEIGHT") == "1"


def _effective_limits(max_files: int, threads: int) -> tuple[int, int]:
    if not LIGHTWEIGHT_MODE:
        return max_files, threads
    return min(max_files, 500), min(threads, 4)


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  PATTERN LIBRARIES
# ══════════════════════════════════════════════════════════════════════════

# ── ENDPOINTS (18 patterns) ───────────────────────────────────────────────
ENDPOINT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("rest_api",
     re.compile(r"""["'`](/(?:api|rest|v\d+|internal|admin|debug|private|backend)/[^"'`\s]{1,200})["'`]""", re.I)),
    ("absolute_url",
     re.compile(r"""["'`](https?://[^"'`\s]{5,200})["'`]""", re.I)),
    ("graphql",
     re.compile(r"""["'`]([^"'`\s]*graphql[^"'`\s]*)["'`]""", re.I)),
    ("websocket_url",
     re.compile(r"""["'`](wss?://[^"'`\s]{5,200})["'`]""", re.I)),
    ("websocket_ctor",
     re.compile(r"""new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)),
    ("socketio",
     re.compile(r"""["'`]([^"'`\s]*socket\.io[^"'`\s]*)["'`]""", re.I)),
    ("route_definition",
     re.compile(r"""(?:path|route)\s*:\s*["'`]([^"'`]{3,100})["'`]""", re.I)),
    ("fetch_url",
     re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`\s]{3,200})["'`]""", re.I)),
    ("xhr_open",
     re.compile(r"""\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["'`]([^"'`]+)["'`]""", re.I)),
    ("jquery_ajax",
     re.compile(r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)),
    ("angular_http",
     re.compile(r"""http\.(?:get|post|put|delete|patch)\s*(?:<[^>]*>)?\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)),
    ("vue_router",
     re.compile(r"""path\s*:\s*["'`](/[^"'`]{2,100})["'`]""")),
    ("nextjs_api",
     re.compile(r"""["'`](/api/[^"'`]{2,200})["'`]""")),
    ("graphql_op",
     re.compile(r"""(?:query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]{2,60})\s*[\({]""")),
    ("firebase_url",
     re.compile(r"""["'`]([a-z0-9-]+\.firebaseio\.com[^"'`\s]*)["'`]""", re.I)),
    ("supabase_url",
     re.compile(r"""["'`]([a-z0-9-]+\.supabase\.co[^"'`\s]*)["'`]""", re.I)),
    ("s3_bucket",
     re.compile(r"""["'`](https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com[^"'`\s]*)["'`]""", re.I)),
    ("cdn_url",
     re.compile(r"""["'`](https?://(?:cdn|static|assets)\.[^"'`\s]{5,150})["'`]""", re.I)),
]

# ── SECRETS (50+ patterns) ────────────────────────────────────────────────
SECRET_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("aws_access_key",     re.compile(r"""\bAKIA[0-9A-Z]{16}\b"""), 95),
    ("aws_secret_key",     re.compile(r"""(?i)aws_secret_access_key["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{40})"""), 90),
    ("gcp_service_account",re.compile(r"""["']type["']\s*:\s*["']service_account["']"""), 90),
    ("gcp_private_key",    re.compile(r"""["']private_key["']\s*:\s*["'](-----BEGIN [A-Z ]+PRIVATE KEY-----)"""), 95),
    ("google_api_key",     re.compile(r"""\bAIza[0-9A-Za-z\-_]{35}\b"""), 95),
    ("google_oauth",       re.compile(r"""([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)"""), 80),
    ("azure_storage",      re.compile(r"""(?i)AccountKey\s*[=:]\s*["']?([A-Za-z0-9+/=]{86,})["']?"""), 90),
    ("stripe_secret",      re.compile(r"""\bsk_live_[A-Za-z0-9]{24,}\b"""), 95),
    ("stripe_publish",     re.compile(r"""\bpk_live_[A-Za-z0-9]{24,}\b"""), 70),
    ("stripe_webhook",     re.compile(r"""\bwhsec_[A-Za-z0-9]{32,}\b"""), 90),
    ("square_access",      re.compile(r"""\bsq0atp-[0-9A-Za-z\-_]{22}\b"""), 90),
    ("github_token",       re.compile(r"""\bgh[ps]_[A-Za-z0-9_]{36,}\b"""), 95),
    ("github_finegrained", re.compile(r"""\bgithub_pat_[A-Za-z0-9_]{22,}\b"""), 95),
    ("gitlab_token",       re.compile(r"""\bglpat-[A-Za-z0-9\-]{20,}\b"""), 95),
    ("bitbucket_token",    re.compile(r"""(?i)bitbucket[_-]?(?:token|secret)["'\s]*[:=]["'\s]*([A-Za-z0-9_\-]{30,})"""), 75),
    ("slack_token",        re.compile(r"""\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"""), 95),
    ("slack_webhook",      re.compile(r"""https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"""), 90),
    ("discord_bot",        re.compile(r"""\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"""), 90),
    ("twilio_sid",         re.compile(r"""\bAC[0-9a-fA-F]{32}\b"""), 80),
    ("twilio_auth",        re.compile(r"""(?i)twilio[_-]?auth[_-]?token["'\s]*[:=]["'\s]*([0-9a-fA-F]{32})"""), 85),
    ("sendgrid_key",       re.compile(r"""\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"""), 95),
    ("mailgun_key",        re.compile(r"""\bkey-[0-9a-zA-Z]{32}\b"""), 85),
    ("telegram_bot",       re.compile(r"""\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"""), 85),
    ("npm_token",          re.compile(r"""\bnpm_[A-Za-z0-9]{36}\b"""), 90),
    ("pypi_token",         re.compile(r"""\bpypi-[A-Za-z0-9\-_]{50,}\b"""), 90),
    ("anthropic_key",      re.compile(r"""\bsk-ant-[A-Za-z0-9\-_]{80,}\b"""), 95),
    ("openai_key",         re.compile(r"""\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"""), 95),
    ("cohere_key",         re.compile(r"""\bco-[A-Za-z0-9]{40}\b"""), 85),
    ("huggingface",        re.compile(r"""\bhf_[A-Za-z0-9]{30,}\b"""), 90),
    ("replicate",          re.compile(r"""\br8_[A-Za-z0-9]{30,}\b"""), 90),
    ("digitalocean",       re.compile(r"""\bdop_v1_[a-f0-9]{64}\b"""), 95),
    ("heroku_key",         re.compile(r"""(?i)heroku[_-]?(?:api|key)["'\s]*[:=]["'\s]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"""), 90),
    ("linear_key",         re.compile(r"""\blin_api_[A-Za-z0-9]{40,}\b"""), 90),
    ("notion_key",         re.compile(r"""\bsecret_[A-Za-z0-9]{43}\b"""), 85),
    ("airtable_key",       re.compile(r"""\bkey[A-Za-z0-9]{14}\b(?=["'\s]*(?:airtable|air))""", re.I), 75),
    ("algolia_key",        re.compile(r"""(?i)algolia[_-]?(?:api|admin)[_-]?key["'\s]*[:=]["'\s]*([a-f0-9]{32})"""), 85),
    ("mapbox_public",      re.compile(r"""\bpk\.eyJ[A-Za-z0-9_\-\.]{100,}\b"""), 60),
    ("mapbox_secret",      re.compile(r"""\bsk\.eyJ[A-Za-z0-9_\-\.]{100,}\b"""), 90),
    ("supabase_anon",      re.compile(r"""\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b(?=["'\s]*(?:supabase|anon))""", re.I), 75),
    ("supabase_service",   re.compile(r"""(?i)supabase[_-]?service[_-]?role["'\s]*[:=]["'\s]*([A-Za-z0-9_-]{100,})"""), 90),
    ("firebase_key",       re.compile(r"""(?i)apiKey["'\s]*:["'\s]*["'](AIza[0-9A-Za-z\-_]{35})["']"""), 90),
    ("shopify_token",      re.compile(r"""\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"""), 90),
    ("contentful_token",   re.compile(r"""(?i)contentful[_-]?(?:access|space|preview)[_-]?token["'\s]*[:=]["'\s]*([A-Za-z0-9_-]{40,})"""), 80),
    ("segment_write",      re.compile(r"""(?i)segment[_-]?(?:write)?[_-]?key["'\s]*[:=]["'\s]*([A-Za-z0-9]{32})"""), 75),
    ("datadog_key",        re.compile(r"""(?i)datadog[_-]?(?:api|app)[_-]?key["'\s]*[:=]["'\s]*([a-f0-9]{32,40})"""), 85),
    ("newrelic_key",       re.compile(r"""\bNRAK-[A-Z0-9]{27}\b"""), 90),
    ("pagerduty_key",      re.compile(r"""\bu\+[A-Za-z0-9_\-]{20,}\b"""), 75),
    ("snyk_token",         re.compile(r"""(?i)snyk[_-]?(?:api|token)["'\s]*[:=]["'\s]*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"""), 85),
    ("okta_token",         re.compile(r"""\b00[A-Za-z0-9_-]{40}\b(?=["'\s]*(?:okta))""", re.I), 75),
    ("asana_token",        re.compile(r"""\b[0-9]/[0-9]{16}/[0-9]{16}:[a-f0-9]{32}\b"""), 85),
    ("jwt",                re.compile(r"""\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"""), 85),
    ("bearer_token",       re.compile(r"""(?i)bearer\s+([A-Za-z0-9\-_\.=]{20,})"""), 70),
    ("private_key",        re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"""), 95),
    ("db_connection",      re.compile(r"""(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver)://[^:\s"']+:[^@\s"']+@"""), 90),
    ("database_url",       re.compile(r"""(?i)DATABASE_URL\s*=\s*["']?\S+://\S+:\S+@\S+"""), 85),
    ("generic_api_key",    re.compile(r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["'\s]*[:=]["'\s]*["']([A-Za-z0-9\-_]{20,})["']"""), 60),
]

# ── XSS SINKS (9 patterns) ────────────────────────────────────────────────
XSS_SINKS: list[tuple[str, re.Pattern]] = [
    ("innerHTML",         re.compile(r"""\.innerHTML\s*=""")),
    ("outerHTML",         re.compile(r"""\.outerHTML\s*=""")),
    ("document_write",    re.compile(r"""document\.write(?:ln)?\s*\(""")),
    ("eval",              re.compile(r"""(?<![\w.])eval\s*\(""")),
    ("Function_ctor",     re.compile(r"""new\s+Function\s*\(""")),
    ("react_dangerously", re.compile(r"""dangerouslySetInnerHTML""")),
    ("vue_v_html",        re.compile(r"""\bv-html\b""")),
    ("angular_innerHTML", re.compile(r"""\[innerHTML\]""")),
    ("jquery_html",       re.compile(r"""\.html\s*\(\s*[^'"]""")),
]

# ── PROTO POLLUTION (4 patterns) ──────────────────────────────────────────
PROTO_POLLUTION: list[tuple[str, re.Pattern]] = [
    ("proto_assign",       re.compile(r"""\b__proto__\b""")),
    ("constructor_proto",  re.compile(r"""\bconstructor\s*\.\s*prototype\b""")),
    ("object_assign_merge",re.compile(r"""(?:Object\.assign|\.merge|\.extend)\s*\([^)]*\+""")),
    ("lodash_merge",       re.compile(r"""\b(?:merge|mergeWith|defaultsDeep|set)\s*\(\s*[^,]+,\s*[^)]*(?:req|params|query|body)""")),
]

# ── OTHER (3 patterns) ────────────────────────────────────────────────────
POSTMESSAGE_WILDCARD = re.compile(r"""\.postMessage\s*\([^,]+,\s*["']\*["']""")
DYNAMIC_IMPORT       = re.compile(r"""import\s*\(\s*["'`]([^"'`]+)["'`]\s*\)""")
SERVICE_WORKER       = re.compile(r"""serviceWorker\.register\s*\(\s*["'`]([^"'`]+)["'`]""")

# ── LEAKS (4 patterns) ────────────────────────────────────────────────────
DEBUG_FLAGS = re.compile(
    r"""["'](?:DEBUG|DEBUG_MODE|NODE_ENV|development|is_dev|showDebug|enableAdmin|debug_mode|__DEV__)["']""",
    re.I)
TODO_COMMENTS = re.compile(
    r"""//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|WARNING|SECURITY|VULN)[\s:]([^\n]{10,300})""",
    re.I)
INTERNAL_URL_HINTS = re.compile(
    r"""["'`](https?://[^"'`\s]*(?:\.local|\.internal|\.corp|\.dev|\.staging|\.test|localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[^"'`\s]*)["'`]""",
    re.I)
STORAGE_KEY = re.compile(
    r"""\.(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]""")

# ── ANALYSIS (3 patterns) ─────────────────────────────────────────────────
SOURCEMAP_RE  = re.compile(r"""[#@]\s*sourceMappingURL=([^\s]+)""")
WEBPACK_REQ   = re.compile(r"""__webpack_require__\s*\(\s*(\d+)\s*\)""")

FRAMEWORK_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("react",     [re.compile(r"""React\.createElement"""),
                    re.compile(r"""__REACT"""),
                    re.compile(r"""react-dom""")]),
    ("vue",       [re.compile(r"""\bVue\.createApp"""),
                    re.compile(r"""__VUE__"""),
                    re.compile(r"""vue-router""")]),
    ("angular",   [re.compile(r"""@angular/core"""),
                    re.compile(r"""angular\.module"""),
                    re.compile(r"""ngOnInit""")]),
    ("svelte",    [re.compile(r"""SvelteComponent"""),
                    re.compile(r"""__svelte""")]),
    ("nextjs",    [re.compile(r"""__NEXT_DATA__"""),
                    re.compile(r"""/_next/""")]),
    ("nuxt",      [re.compile(r"""__NUXT__"""),
                    re.compile(r"""/_nuxt/""")]),
    ("jquery",    [re.compile(r"""jQuery\.fn\.jquery"""),
                    re.compile(r"""jquery\.min\.js""")]),
    ("lodash",    [re.compile(r"""\.VERSION\s*=\s*["']\d"""),
                    re.compile(r"""lodash""")]),
    ("threejs",   [re.compile(r"""\bTHREE\.""")]),
    ("d3",        [re.compile(r"""\bd3\.version"""),
                    re.compile(r"""d3\.select""")]),
    ("bootstrap", [re.compile(r"""bootstrap\.min\.js"""),
                    re.compile(r"""Bootstrap\.""")]),
    ("tailwind",  [re.compile(r"""tailwind""")]),
    ("alpinejs",  [re.compile(r"""x-data="""),
                    re.compile(r"""Alpine\.""")]),
    ("htmx",      [re.compile(r"""hx-(?:get|post|target)""")]),
    ("emberjs",   [re.compile(r"""Ember\.Application""")]),
    ("backbone",  [re.compile(r"""Backbone\.Model""")]),
]

# ── False-positive strings ────────────────────────────────────────────────
FALSE_POSITIVE_VALUES = {
    "your_api_key", "your-api-key", "replace_me", "changeme",
    "xxx", "todo", "fixme", "example", "test", "dummy",
    "api_key_here", "insert_key_here", "placeholder",
    "test_key", "sample_key", "your_key_here", "not_a_real_key",
}

# ── Interesting path words (endpoint scoring) ─────────────────────────────
INTERESTING_PATH_WORDS = {
    "admin", "internal", "debug", "private", "backend", "staging",
    "dev", "test", "graphql", "v1", "v2", "v3", "rest", "api",
}


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class JSFile:
    url: str
    host: str = ""           # parent host (site_pages owner)
    url_host: str = ""       # actual host of the JS URL
    content: str = ""
    size: int = 0
    sha256: str = ""
    error: str = ""
    error_category: str = ""
    source: str = ""         # site_pages / katana / input / subjs
    via_origin: Optional[str] = None
    sourcemap_url: Optional[str] = None
    sourcemap_content: str = ""
    sourcemap_size: int = 0
    sourcemap_error: str = ""
    sourcemap_sources: list[str] = field(default_factory=list)
    sourcemap_has_content: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.content)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "host": self.host, "url_host": self.url_host,
            "size": self.size, "sha256": self.sha256,
            "error": self.error, "error_category": self.error_category,
            "source": self.source, "via_origin": self.via_origin,
            "sourcemap_url": self.sourcemap_url,
            "sourcemap_size": self.sourcemap_size,
            "sourcemap_error": self.sourcemap_error,
            "sourcemap_sources": self.sourcemap_sources[:500],
            "sourcemap_has_content": self.sourcemap_has_content,
        }


@dataclass
class Finding:
    kind: str
    subtype: str
    value: str
    redacted: str
    file_url: str
    host: str = ""
    line_number: int = 0
    context: str = ""
    confidence: int = 0
    severity: Severity = Severity.LOW
    reasons: list[str] = field(default_factory=list)
    chain_ids: list[str] = field(default_factory=list)
    ai_evaluation: Optional[dict] = None
    first_seen: str = ""

    def add_chain(self, cid: str) -> None:
        if cid not in self.chain_ids:
            self.chain_ids.append(cid)

    def to_dict(self) -> dict:
        return {
            "kind":          self.kind,
            "subtype":       self.subtype,
            "value":         self.value,
            "redacted":      self.redacted,
            "file_url":      self.file_url,
            "host":          self.host,
            "line_number":   self.line_number,
            "context":       self.context,
            "confidence":    self.confidence,
            "severity":      self.severity.value,
            "reasons":       self.reasons,
            "chain_ids":     self.chain_ids,
            "ai_evaluation": self.ai_evaluation,
            "first_seen":    self.first_seen,
        }


@dataclass
class HostResult:
    host: str
    js_files: list[JSFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    triage: Optional[dict] = None
    triage_source: str = ""        # "ai" or "heuristic"
    errors: list[str] = field(default_factory=list)


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


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  HTTP SESSION (config-wired, per-request rotation, SCOPE-aware)
# ══════════════════════════════════════════════════════════════════════════

def _categorize_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)): return "timeout"
    if isinstance(exc, ssl.SSLError): return "ssl"
    if isinstance(exc, socket.gaierror): return "dns"
    if isinstance(exc, ConnectionRefusedError): return "refused"
    if isinstance(exc, urllib.error.URLError):
        r = str(exc.reason).lower()
        if "proxy" in r: return "proxy"
        if "dns" in r or "name" in r: return "dns"
        if "timeout" in r: return "timeout"
        if "ssl" in r or "certificate" in r: return "ssl"
        return "url"
    return type(exc).__name__.lower()[:20]


class HttpSession:
    """
    Per-host HTTP client. Every request:
      ·  KillSwitch.check()
      ·  SCOPE check (unless URL host is in CDN_ALLOWLIST)
      ·  RateLimiter.acquire() + human_delay()
      ·  random_user_agent()
      ·  ProxyPool.pick() (per-request, not per-host)
      ·  build_headers(bbp_program)
      ·  AuditTrail.record()
    """

    def __init__(self, host: str, bbp_program: Optional[str] = None,
                 proxy_pool: Any = None, audit_trail: Any = None,
                 use_proxy: bool = True):
        self.host = host
        self.bbp_program = bbp_program
        self.audit = audit_trail
        self.proxy_pool = proxy_pool if use_proxy else None
        self.use_proxy = use_proxy
        self.rate_limiter = self._build_rate_limiter()
        self.static_headers = self._build_headers(bbp_program)
        self.stats = {"requests": 0, "errors": 0, "bytes": 0,
                       "proxies_used": set(), "scope_skipped": 0}

    def _build_rate_limiter(self) -> Any:
        try:
            rl_cls = _cfg("RateLimiter")
            limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("js", {})
            rps = limits.get("rps", DEFAULT_RATE_LIMIT)
            return rl_cls(per_minute=rps * 60, per_hour=rps * 3600) if rl_cls else None
        except Exception:
            return None

    def _build_headers(self, bbp_program: Optional[str]) -> dict:
        headers = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
        try:
            if bbp_program:
                builder = _cfg("build_headers")
                if callable(builder):
                    headers.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
        return headers

    def _ua(self) -> str:
        try:
            fn = _cfg("random_user_agent")
            if callable(fn):
                return fn()
        except Exception:
            pass
        return "Mozilla/5.0 (compatible; Argus-Mimir/2.0)"

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
            if callable(delay_fn):
                time.sleep(min(delay_fn(), 2.0))
            if random.random() < HUMAN_PAUSE_CHANCE:
                time.sleep(random.uniform(*HUMAN_PAUSE_RANGE))
        except Exception:
            pass

    def _is_cdn_url(self, url: str) -> bool:
        try:
            host = (urllib.parse.urlparse(url).hostname or "").lower()
            return any(host == c or host.endswith("." + c) for c in CDN_ALLOWLIST)
        except Exception:
            return False

    def _in_scope(self, url: str) -> bool:
        # CDN assets are always fetchable — they're public files
        if self._is_cdn_url(url):
            return True
        try:
            scope = _cfg("SCOPE")
            if scope is None:
                return True
            if scope.is_in_scope(url):
                return True
            host = (urllib.parse.urlparse(url).hostname or "").lower()
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

    def _report_proxy(self, proxy: Any, success: bool, latency: float = 0.0) -> None:
        if proxy is None or self.proxy_pool is None:
            return
        try:
            if success:
                self.proxy_pool.report_success(proxy, latency)
            else:
                self.proxy_pool.report_failure(proxy)
        except Exception:
            pass

    def get(self, url: str, timeout: float = DOWNLOAD_TIMEOUT,
            referer: Optional[str] = None,
            max_bytes: int = MAX_JS_SIZE_BYTES) -> HttpResult:
        if not self._in_scope(url):
            self.stats["scope_skipped"] += 1
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
        opener = urllib.request.build_opener()
        if proxy is not None:
            try:
                opener.add_handler(urllib.request.ProxyHandler(
                    {"http": proxy.url(), "https": proxy.url()}))
            except Exception:
                pass

        start = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(max_bytes).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000
                headers_dict = {k: v for k, v in resp.headers.items()}
                self.stats["requests"] += 1
                self.stats["bytes"] += len(body)
                self._audit("GET", resp.geturl(), resp.getcode(), latency, None, proxy)
                self._report_proxy(proxy, True, latency / 1000)
                return HttpResult(resp.getcode(), headers_dict, body,
                                   url, resp.geturl(), latency)
        except urllib.error.HTTPError as e:
            latency = (time.monotonic() - start) * 1000
            try:
                body = e.read(max_bytes).decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                body, headers_dict = "", {}
            self.stats["requests"] += 1
            self._audit("GET", url, e.code, latency, f"HTTP {e.code}", proxy)
            self._report_proxy(proxy, e.code < 500)
            return HttpResult(e.code, headers_dict, body, url, url, latency,
                              error=f"HTTP {e.code}", error_category=f"http{e.code}")
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            category = _categorize_error(e)
            self._audit("GET", url, 0, latency, str(e)[:200], proxy)
            self._report_proxy(proxy, False)
            return HttpResult(0, {}, "", url, url, latency,
                              error=f"{category}: {type(e).__name__}",
                              error_category=category)

    def _audit(self, method: str, url: str, status: int, latency_ms: float,
                error: Optional[str], proxy: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                method=method, url=url, status=status,
                latency_ms=latency_ms,
                proxy=proxy.url() if proxy else None,
                user_agent="(rotating)", error=error)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())


def _redact(value: str) -> str:
    """First 4 + asterisks + last 4. Short values fully asterisked."""
    v = value.strip()
    if len(v) <= REDACT_KEEP_CHARS * 2:
        return "*" * len(v)
    keep = REDACT_KEEP_CHARS
    return v[:keep] + "*" * (len(v) - keep * 2) + v[-keep:]


def _line_offsets(content: str) -> list[int]:
    offsets = []
    pos = 0
    for line in content.splitlines():
        offsets.append(pos)
        pos += len(line) + 1
    return offsets


def _line_for_pos(line_offsets: list[int], pos: int) -> int:
    lo, hi = 0, len(line_offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_offsets[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _snippet(content: str, start: int, end: int,
              secret_value: str = "", ctx: int = 60) -> str:
    """Extract context. If secret_value given, redact it from the context."""
    left = max(0, start - ctx)
    right = min(len(content), end + ctx)
    s = content[left:right].replace("\n", " ").strip()
    if secret_value:
        s = s.replace(secret_value, "[REDACTED]")
    return s[:250]


def _severity_for_confidence(confidence: int, kind: str) -> Severity:
    if kind == "secret":
        if confidence >= 90: return Severity.CRITICAL
        if confidence >= 70: return Severity.HIGH
        if confidence >= 50: return Severity.MEDIUM
        return Severity.LOW
    if kind in ("private_key", "jwt_weakness"):
        return Severity.CRITICAL
    if confidence >= 80: return Severity.HIGH
    if confidence >= 60: return Severity.MEDIUM
    return Severity.LOW


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  ANALYSIS PASSES  ·  24 detection methods
# ══════════════════════════════════════════════════════════════════════════

def _analyze_endpoints(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for subtype, pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            if not value or value in seen:
                continue
            seen.add(value)

            confidence = 40
            reasons = [f"pattern:{subtype}"]

            value_lower = value.lower()
            if any(w in value_lower for w in INTERESTING_PATH_WORDS):
                confidence += 30
                reasons.append("sensitive_path")

            if subtype == "absolute_url":
                parsed = urllib.parse.urlparse(value)
                target = _host_of(js.url)
                if parsed.hostname and parsed.hostname != target:
                    confidence += 20
                    reasons.append("external_host")
                else:
                    confidence -= 10

            if subtype in ("graphql", "websocket_url", "websocket_ctor",
                            "socketio", "graphql_op"):
                confidence += 20
                reasons.append("api_surface")

            if subtype in ("firebase_url", "supabase_url", "s3_bucket"):
                confidence += 25
                reasons.append("storage_origin")

            if confidence < MIN_REPORT_CONFIDENCE:
                continue

            f = Finding(
                kind="endpoint", subtype=subtype,
                value=value, redacted=value,
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end()),
                confidence=min(confidence, 100),
                severity=_severity_for_confidence(confidence, "endpoint"),
                reasons=reasons,
                first_seen=now,
            )
            if any(w in value_lower for w in ("admin", "internal", "debug")):
                f.add_chain("js-admin-endpoint")
            if subtype in ("graphql", "graphql_op"):
                f.add_chain("js-graphql-endpoint")
            if subtype in ("websocket_url", "websocket_ctor", "socketio"):
                f.add_chain("js-websocket-endpoint")
            if subtype in ("rest_api", "fetch_url", "xhr_open", "jquery_ajax",
                            "angular_http", "nextjs_api", "vue_router",
                            "route_definition"):
                f.add_chain("js-api-endpoint")
            findings.append(f)
    return findings


def _analyze_secrets(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for subtype, pattern, base_conf in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            value = value.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            if value.lower() in FALSE_POSITIVE_VALUES:
                continue
            if len(value) < 8:
                continue

            confidence = base_conf
            reasons = [f"pattern:{subtype}"]

            entropy = _shannon_entropy(value)
            if entropy >= 4.0:
                confidence += 10
                reasons.append(f"entropy:{entropy:.1f}")
            elif entropy < 2.5 and subtype == "generic_api_key":
                confidence -= 20
                reasons.append("low_entropy")

            ctx = _snippet(content, match.start(), match.end(), value).lower()
            if any(w in ctx for w in ("live", "production", "prod")):
                confidence += 10
                reasons.append("production_context")
            if any(w in ctx for w in ("test", "example", "sample", "dummy")):
                confidence -= 15
                reasons.append("test_context")

            if confidence < MIN_REPORT_CONFIDENCE:
                continue

            f = Finding(
                kind="secret", subtype=subtype,
                value=value, redacted=_redact(value),
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end(), value),
                confidence=min(confidence, 100),
                severity=_severity_for_confidence(confidence, "secret"),
                reasons=reasons,
                first_seen=now,
            )
            if subtype in ("private_key", "gcp_private_key"):
                f.add_chain("js-private-key-exposed")
            if subtype in ("db_connection", "database_url"):
                f.add_chain("js-database-creds-exposed")
            if subtype == "jwt":
                f.add_chain("js-jwt-exposed")
            f.add_chain("js-secret-exposed")
            findings.append(f)
    return findings


def _analyze_jwt_weak(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    jwt_re = re.compile(r"""\b(eyJ[A-Za-z0-9_-]+)\.(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)\b""")
    for match in jwt_re.finditer(content):
        try:
            header_b64 = match.group(1) + "=" * (-len(match.group(1)) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode("utf-8", errors="replace")
            header = json.loads(header_json)
        except Exception:
            continue

        alg = (header.get("alg") or "").lower()
        signature = match.group(3)
        reasons = [f"jwt_alg:{alg or 'unknown'}"]

        if alg == "none" or not signature:
            findings.append(Finding(
                kind="jwt_weakness", subtype="alg_none",
                value=match.group(0), redacted=_redact(match.group(0)),
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end(), match.group(0)),
                confidence=95, severity=Severity.CRITICAL,
                reasons=reasons + ["alg_none_signature_stripped"],
                chain_ids=["js-jwt-weak"],
                first_seen=now,
            ))
        elif len(signature) < 40:
            findings.append(Finding(
                kind="jwt_weakness", subtype="short_signature",
                value=match.group(0), redacted=_redact(match.group(0)),
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end(), match.group(0)),
                confidence=70, severity=Severity.HIGH,
                reasons=reasons + [f"signature_len:{len(signature)}"],
                chain_ids=["js-jwt-weak"],
                first_seen=now,
            ))
    return findings


def _analyze_xss_sinks(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for subtype, pattern in XSS_SINKS:
        for match in pattern.finditer(content):
            ctx_lower = _snippet(content, match.start(), match.end()).lower()
            confidence = 40
            reasons = [f"sink:{subtype}"]
            if any(kw in ctx_lower for kw in
                    ("location", "params", "query", "input", "user", "value")):
                confidence += 30
                reasons.append("user_input_nearby")
            if confidence < MIN_REPORT_CONFIDENCE:
                continue
            findings.append(Finding(
                kind="xss_sink", subtype=subtype,
                value=subtype, redacted=subtype,
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end()),
                confidence=min(confidence, 100),
                severity=_severity_for_confidence(confidence, "sink"),
                reasons=reasons,
                chain_ids=["js-dom-xss-sink"],
                first_seen=now,
            ))
    return findings


def _analyze_prototype_pollution(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for subtype, pattern in PROTO_POLLUTION:
        for match in pattern.finditer(content):
            findings.append(Finding(
                kind="proto_pollution", subtype=subtype,
                value=subtype, redacted=subtype,
                file_url=js.url, host=js.host or _host_of(js.url),
                line_number=_line_for_pos(offsets, match.start()),
                context=_snippet(content, match.start(), match.end()),
                confidence=50, severity=Severity.MEDIUM,
                reasons=[f"proto_sink:{subtype}"],
                chain_ids=["js-prototype-pollution"],
                first_seen=now,
            ))
    return findings


def _analyze_postmessage(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for match in POSTMESSAGE_WILDCARD.finditer(content):
        findings.append(Finding(
            kind="postmessage", subtype="wildcard_target",
            value="postMessage(*)", redacted="postMessage(*)",
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=60, severity=Severity.MEDIUM,
            reasons=["targetOrigin_wildcard"],
            chain_ids=["js-postmessage-wildcard"],
            first_seen=now,
        ))
    return findings


def _analyze_storage_keys(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for match in STORAGE_KEY.finditer(content):
        key = match.group(1)
        if not key or key in seen or len(key) < 2:
            continue
        seen.add(key)

        confidence = 30
        reasons = ["storage_key"]
        key_lower = key.lower()
        if any(w in key_lower for w in ("admin", "auth", "token", "user",
                                          "session", "secret", "debug")):
            confidence += 30
            reasons.append("sensitive_key")
        if confidence < MIN_REPORT_CONFIDENCE:
            continue

        findings.append(Finding(
            kind="storage_key", subtype="localstorage",
            value=key, redacted=key,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=min(confidence, 100),
            severity=_severity_for_confidence(confidence, "endpoint"),
            reasons=reasons,
            first_seen=now,
        ))
    return findings


def _analyze_debug_flags(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for match in DEBUG_FLAGS.finditer(content):
        flag = match.group(0)
        if flag in seen:
            continue
        seen.add(flag)
        findings.append(Finding(
            kind="debug_flag", subtype="flag_reference",
            value=flag.strip("'\""), redacted=flag.strip("'\""),
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=45, severity=Severity.MEDIUM,
            reasons=["debug_flag"],
            chain_ids=["js-debug-flag"],
            first_seen=now,
        ))
    return findings


def _analyze_comments(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for match in TODO_COMMENTS.finditer(content):
        tag = match.group(1).upper()
        text = match.group(2).strip()[:200]
        confidence = 40
        if tag in ("SECURITY", "VULN", "BUG"):
            confidence = 60
        findings.append(Finding(
            kind="comment", subtype=f"tag_{tag.lower()}",
            value=text, redacted=text,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end(), ctx=20),
            confidence=confidence,
            severity=_severity_for_confidence(confidence, "endpoint"),
            reasons=[f"comment_tag:{tag}"],
            chain_ids=["js-todo-leak"],
            first_seen=now,
        ))
    return findings


def _analyze_internal_urls(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for match in INTERNAL_URL_HINTS.finditer(content):
        url = match.group(1)
        if url in seen:
            continue
        seen.add(url)
        findings.append(Finding(
            kind="internal_url", subtype="env_leak",
            value=url, redacted=url,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=80, severity=Severity.HIGH,
            reasons=["internal_hostname"],
            chain_ids=["js-internal-url"],
            first_seen=now,
        ))
    return findings


def _analyze_dynamic_imports(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()

    for match in DYNAMIC_IMPORT.finditer(content):
        url = match.group(1)
        if url in seen:
            continue
        seen.add(url)
        findings.append(Finding(
            kind="dynamic_import", subtype="import_url",
            value=url, redacted=url,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=35, severity=Severity.LOW,
            reasons=["dynamic_import"],
            chain_ids=["js-dynamic-imports"],
            first_seen=now,
        ))
    return findings


def _analyze_service_workers(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for match in SERVICE_WORKER.finditer(content):
        url = match.group(1)
        findings.append(Finding(
            kind="service_worker", subtype="sw_url",
            value=url, redacted=url,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=40, severity=Severity.LOW,
            reasons=["service_worker"],
            chain_ids=["js-service-workers"],
            first_seen=now,
        ))
    return findings


def _analyze_sourcemaps(js: JSFile) -> list[Finding]:
    findings: list[Finding] = []
    content = js.content
    offsets = _line_offsets(content)
    now = datetime.now(timezone.utc).isoformat()

    for match in SOURCEMAP_RE.finditer(content):
        map_url = match.group(1).strip()
        if not map_url.startswith(("http://", "https://")):
            map_url = urllib.parse.urljoin(js.url, map_url)
        js.sourcemap_url = map_url
        findings.append(Finding(
            kind="sourcemap", subtype="source_mapping_url",
            value=map_url, redacted=map_url,
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=_line_for_pos(offsets, match.start()),
            context=_snippet(content, match.start(), match.end()),
            confidence=85, severity=Severity.HIGH,
            reasons=["source_mapping_url"],
            chain_ids=["js-sourcemap-leak"],
            first_seen=now,
        ))
    return findings


def _analyze_frameworks(js: JSFile) -> list[Finding]:
    """Detect frontend frameworks from JS content."""
    findings: list[Finding] = []
    now = datetime.now(timezone.utc).isoformat()

    for fw_name, patterns in FRAMEWORK_PATTERNS:
        for pat in patterns:
            m = pat.search(js.content)
            if m:
                findings.append(Finding(
                    kind="framework", subtype=fw_name,
                    value=fw_name, redacted=fw_name,
                    file_url=js.url, host=js.host or _host_of(js.url),
                    line_number=_line_for_pos(_line_offsets(js.content), m.start()),
                    context=_snippet(js.content, m.start(), m.end()),
                    confidence=70, severity=Severity.INFO,
                    reasons=[f"framework_sig:{fw_name}"],
                    chain_ids=["js-framework-detected"],
                    first_seen=now,
                ))
                break  # one finding per framework
    return findings


def _analyze_webpack(js: JSFile) -> list[Finding]:
    """Detect webpack module map (indicates bundled app structure)."""
    findings: list[Finding] = []
    module_nums = set()
    for match in WEBPACK_REQ.finditer(js.content):
        module_nums.add(match.group(1))

    if len(module_nums) >= 5:  # meaningful module map
        findings.append(Finding(
            kind="webpack_module", subtype="module_map",
            value=f"{len(module_nums)} modules",
            redacted=f"{len(module_nums)} modules",
            file_url=js.url, host=js.host or _host_of(js.url),
            line_number=0, context=f"module IDs: {', '.join(sorted(module_nums)[:10])}",
            confidence=50, severity=Severity.INFO,
            reasons=[f"webpack_modules:{len(module_nums)}"],
            chain_ids=["js-webpack-modules"],
            first_seen=datetime.now(timezone.utc).isoformat(),
        ))
    return findings


def _fetch_sourcemap(js: JSFile, session: HttpSession) -> None:
    """Fetch and analyze the source map if present."""
    if not js.sourcemap_url:
        return
    res = session.get(js.sourcemap_url, timeout=DOWNLOAD_TIMEOUT,
                       max_bytes=MAX_SOURCEMAP_SIZE)
    if res.error or res.status != 200:
        js.sourcemap_error = res.error or f"HTTP {res.status}"
        return
    try:
        data = json.loads(res.body)
        sources = data.get("sources", [])
        js.sourcemap_sources = [str(s)[:300] for s in sources[:1000]]
        js.sourcemap_size = len(res.body)
        js.sourcemap_content = res.body[:100_000] if data.get("sourcesContent") else ""
        js.sourcemap_has_content = bool(data.get("sourcesContent"))
    except Exception as e:
        js.sourcemap_error = f"parse: {type(e).__name__}: {e}"


def analyze_js_file(js: JSFile, session: HttpSession,
                     fetch_sourcemaps: bool = True) -> list[Finding]:
    """Run all detection passes on a single JS file. Each pass fails soft."""
    all_findings: list[Finding] = []

    passes = [
        _analyze_endpoints, _analyze_secrets, _analyze_jwt_weak,
        _analyze_xss_sinks, _analyze_prototype_pollution,
        _analyze_postmessage, _analyze_storage_keys, _analyze_debug_flags,
        _analyze_comments, _analyze_internal_urls, _analyze_dynamic_imports,
        _analyze_service_workers, _analyze_sourcemaps, _analyze_frameworks,
        _analyze_webpack,
    ]

    for pass_fn in passes:
        try:
            all_findings.extend(pass_fn(js))
        except Exception as e:
            log.debug(f"    pass {pass_fn.__name__} failed on {js.url}: {e}")

    if fetch_sourcemaps:
        try:
            _fetch_sourcemap(js, session)
        except Exception:
            pass

    return all_findings


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  TRIAGE  ·  AI (when enabled) + heuristic (always)
# ══════════════════════════════════════════════════════════════════════════

AI_TRIAGE_SYSTEM = (
    "You are an expert bug-bounty JS analyst. Analyze the findings from "
    "one host's JavaScript bundles. Reference actual endpoints, secrets, "
    "and file paths. Never suggest running exploits. Return STRICT JSON only."
)


def _build_top_findings_block(findings: list[Finding], limit: int = 40) -> str:
    """Sort and format the top findings for the AI prompt."""
    top = sorted(findings, key=lambda f: (
        0 if f.kind == "secret" else
        1 if f.kind == "jwt_weakness" else
        2 if f.kind == "sourcemap" else
        3 if f.kind == "internal_url" else
        4,
        -f.severity.rank,
        -f.confidence,
    ))[:limit]

    lines = []
    for f in top:
        fname = f.file_url.split("/")[-1][:40]
        lines.append(
            f"  [{f.severity.value:<8}] {f.kind}:{f.subtype:<20} "
            f"{(f.redacted or '')[:60]:<60} ({fname}:{f.line_number})"
        )
    return "\n".join(lines) if lines else "  (no findings)"


def _ai_triage_host(host_result: HostResult, outdir: Path) -> Optional[dict]:
    """AI triage — returns None if AI disabled, no findings, or call failed."""
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.findings) < AI_MIN_FINDINGS_PER_HOST:
        return None

    findings = host_result.findings
    n_secrets = sum(1 for f in findings if f.kind == "secret")
    n_endpoints = sum(1 for f in findings if f.kind == "endpoint")
    n_sourcemaps = sum(1 for f in findings if f.kind == "sourcemap")

    prompt = f"""Analyze JavaScript findings for {host_result.host}.

Stats:
  Files analyzed: {len(host_result.js_files)}
  Total findings: {len(findings)}
  - Secrets:    {n_secrets}
  - Endpoints:  {n_endpoints}
  - Sourcemaps: {n_sourcemaps}

Top findings (by severity):
{_build_top_findings_block(findings)}

Return STRICT JSON:
{{
  "summary": "one paragraph overall assessment",
  "host_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "top_priorities": [
    {{"rank": 1, "finding": "which finding", "reason": "why it matters", "test_idea": "what to test manually"}}
  ],
  "real_vs_noise": "which findings look real vs likely false positives",
  "next_actions": ["specific manual test 1", "specific test 2", "specific test 3"]
}}"""

    try:
        response = ai_fn(prompt, system=AI_TRIAGE_SYSTEM)
    except Exception as e:
        log.warn(f"    AI triage failed: {type(e).__name__}: {e}")
        return None
    if not response:
        return None

    # Parse — handle markdown fences and invalid JSON gracefully
    text = response.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not a dict")
    except Exception:
        data = {"summary": response[:1500], "parse_error": True}

    # Save markdown report
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"js_ai_{safe}.md"
    try:
        md = (f"# Mímir's Eye · AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)} · "
              f"**Files:** {len(host_result.js_files)}  \n"
              f"**Model:** {_cfg('AI.model', 'deepseek-chat')}\n\n---\n\n")
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
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"    AI triage saved: {md_path.name}")

    cost = None
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            cost = round(tracker.estimate_cost(), 6)
    except Exception:
        pass

    return {
        "path": str(md_path),
        "summary": data.get("summary", ""),
        "host_risk": data.get("host_risk", ""),
        "top_priorities": data.get("top_priorities", [])[:10],
        "real_vs_noise": data.get("real_vs_noise", ""),
        "next_actions": data.get("next_actions", [])[:10],
        "cost_estimate": cost,
        "source": "ai",
    }


def _heuristic_triage(host_result: HostResult) -> dict:
    """Deterministic triage — always available, same schema as AI."""
    findings = host_result.findings
    if not findings:
        return {
            "summary": f"No findings in {len(host_result.js_files)} JS file(s) "
                        f"from {host_result.host}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "real_vs_noise": "n/a",
            "next_actions": [
                "Consider increasing --max-files if only a few JS files were fetched",
                "Check if katana can reach more pages on this host",
            ],
            "source": "heuristic",
        }

    # Group by kind and severity
    kind_counts: dict[str, int] = {}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        kind_counts[f.kind] = kind_counts.get(f.kind, 0) + 1
        sev_counts[f.severity.value] += 1

    # Host risk = max severity present
    if sev_counts["CRITICAL"] > 0: host_risk = "CRITICAL"
    elif sev_counts["HIGH"] > 0:   host_risk = "HIGH"
    elif sev_counts["MEDIUM"] > 0: host_risk = "MEDIUM"
    elif sev_counts["LOW"] > 0:    host_risk = "LOW"
    else:                          host_risk = "INFO"

    # Summary
    kind_summary = " · ".join(
        f"{k}({v})" for k, v in
        sorted(kind_counts.items(), key=lambda kv: -kv[1])[:6])
    summary = (f"{len(findings)} finding(s) across {len(host_result.js_files)} "
               f"JS file(s). {kind_summary}.")

    # Top priorities — top 5 by severity then confidence
    top = sorted(findings, key=lambda f: (-f.severity.rank, -f.confidence))[:5]
    top_priorities = []
    for i, f in enumerate(top, 1):
        reason = f"{f.severity.value} {f.kind}:{f.subtype}"
        if f.chain_ids:
            reason += f" ({', '.join(f.chain_ids[:2])})"
        test_idea = _suggest_test_for_finding(f)
        top_priorities.append({
            "rank": i,
            "finding": f"{f.subtype} ({f.redacted[:50]})",
            "reason": reason,
            "test_idea": test_idea,
        })

    # Real vs noise — confidence distribution
    high_conf = sum(1 for f in findings if f.confidence >= 70)
    med_conf = sum(1 for f in findings if 40 <= f.confidence < 70)
    low_conf = sum(1 for f in findings if f.confidence < 40)
    real_vs_noise = (
        f"Confidence distribution: {high_conf} high-confidence (≥70), "
        f"{med_conf} medium (40-69), {low_conf} low (<40). "
        f"High-confidence findings have strong pattern matches; "
        f"low-confidence findings warrant manual inspection before reporting."
    )

    # Next actions — derive from finding types
    next_actions: list[str] = []
    if kind_counts.get("secret", 0) > 0:
        next_actions.append(
            "Verify each secret in the target's provider console (AWS/GCP/etc.) "
            "— do NOT attempt to use it without authorization")
    if kind_counts.get("sourcemap", 0) > 0:
        next_actions.append(
            "Fetch js_sourcemaps.txt URLs in browser — full source may be exposed")
    if kind_counts.get("endpoint", 0) > 0:
        next_actions.append(
            "Feed endpoints into param_discovery.py and nuclei_scan.py")
    if kind_counts.get("internal_url", 0) > 0:
        next_actions.append(
            "Test internal URLs for accessibility from your network — "
            "internal-only services are often forgotten in patching")
    if kind_counts.get("jwt_weakness", 0) > 0:
        next_actions.append(
            "Investigate JWT alg:none — try stripping signature and see if "
            "server still accepts the token")
    if kind_counts.get("xss_sink", 0) > 0:
        next_actions.append(
            "Identify if any XSS sink receives user-controlled input via URL "
            "or form parameters")
    if not next_actions:
        next_actions.append("Manual review of findings with confidence ≥50")

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "real_vs_noise": real_vs_noise,
        "next_actions": next_actions,
        "source": "heuristic",
    }


def _suggest_test_for_finding(f: Finding) -> str:
    """Suggest a manual test based on the finding."""
    k, s = f.kind, f.subtype
    if k == "secret":
        if s == "aws_access_key":
            return "Verify key in AWS console; do not attempt use without authorization"
        if s == "private_key":
            return "Identify associated service from cert; check for matching public key exposure"
        if s in ("db_connection", "database_url"):
            return "Check if DB is publicly accessible; do NOT connect without authorization"
        return "Verify secret validity in provider console"
    if k == "endpoint":
        if "graphql" in s:
            return "Try GraphQL introspection query"
        if "websocket" in s or s == "socketio":
            return "Check WebSocket auth; test for CSRF over WS"
        return "Fetch endpoint with curl; check auth requirements"
    if k == "sourcemap":
        return "Open source map URL in browser — full source may be exposed"
    if k == "internal_url":
        return "Test if internal hostname resolves from public internet"
    if k == "jwt_weakness":
        return "Modify JWT header to alg:none; check if server accepts"
    if k == "xss_sink":
        return "Trace data flow from URL param to sink"
    if k == "proto_pollution":
        return "Check if user input reaches the sink without sanitization"
    if k == "admin_endpoint" or "admin" in f.value.lower():
        return "Check authentication on admin endpoint"
    return "Manual inspection of context and validation"


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  INPUT LOADING
# ══════════════════════════════════════════════════════════════════════════

def _load_from_site_pages(path: Path) -> dict[str, list[str]]:
    """Extract {host: [js_urls]} from site_crawler's site_pages.json."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        by_host: dict[str, list[str]] = {}
        for h in data.get("hosts", []):
            host = h.get("host") or ""
            if not host:
                continue
            urls: set[str] = set()
            for js_url in h.get("assets_js", []):
                if js_url:
                    urls.add(js_url)
            for p in h.get("pages", []):
                for s in p.get("scripts", []):
                    if s:
                        urls.add(s)
            if urls:
                by_host[host] = sorted(urls)
        return by_host
    except Exception as e:
        log.warn(f"site_pages.json parse failed: {e}")
        return {}


def _load_from_url_list(path: Path) -> dict[str, list[str]]:
    """Extract {host: [urls]} from a live_urls.txt or similar."""
    if not path.exists():
        return {}
    by_host: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        host = _host_of(url)
        if host:
            by_host.setdefault(host, []).append(url)
    return by_host


def _load_from_js_dir(path: Path) -> dict[str, list[str]]:
    """If input is a directory of .js files, treat each as a JS URL."""
    if not path.is_dir():
        return {}
    by_host: dict[str, list[str]] = {}
    for js_path in path.rglob("*.js"):
        try:
            url = js_path.as_uri()
            host = js_path.parent.name or "local"
            by_host.setdefault(host, []).append(url)
        except Exception:
            continue
    return by_host


def _discover_katana(base_urls: list[str], rate_limit: int, concurrency: int,
                      bbp_program: Optional[str]) -> dict[str, list[str]]:
    """Run katana to discover JS files from base URLs."""
    if not shutil.which("katana"):
        log.warning("    katana not installed — no crawl-based discovery")
        return {}

    header_args: list[str] = []
    try:
        builder = _cfg("build_headers")
        if callable(builder) and bbp_program:
            hdrs = builder(bbp_program, dynamic_ua=False)
            header_args = [f"{k}: {v}" for k, v in hdrs.items()]
    except Exception:
        pass

    by_host: dict[str, list[str]] = {}
    for base in base_urls[:20]:
        host = _host_of(base)
        if not host:
            continue
        cmd = ["katana", "-u", base, "-jc", "-d", str(KATANA_DEPTH),
                "-kf", "all", "-silent", "-timeout", "10",
                "-c", str(concurrency)]
        if rate_limit and rate_limit > 0:
            cmd.extend(["-rl", str(rate_limit)])
        for hdr in header_args:
            cmd.extend(["-H", hdr])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=KATANA_TIMEOUT)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        for line in result.stdout.splitlines():
            url = line.strip()
            if not url or not url.endswith((".js", ".mjs")):
                continue
            by_host.setdefault(host, []).append(url)

    total = sum(len(v) for v in by_host.values())
    log.info(f"    katana: {total} JS URL(s) across {len(by_host)} host(s)")
    return by_host


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  DOWNLOAD
# ══════════════════════════════════════════════════════════════════════════

def _download_one(session: HttpSession, f: JSFile) -> JSFile:
    res = session.get(f.url, timeout=DOWNLOAD_TIMEOUT,
                       max_bytes=MAX_JS_SIZE_BYTES)
    if res.error:
        f.error = res.error[:120]
        f.error_category = res.error_category or ""
        return f
    if res.status != 200:
        f.error = f"HTTP {res.status}"
        f.error_category = f"http{res.status}"
        return f
    f.content = res.body
    f.size = len(res.body)
    f.sha256 = hashlib.sha256(res.body.encode("utf-8", errors="replace")).hexdigest()
    return f


def download_js_files(js_files: list[JSFile], threads: int,
                        rate_limit: int, bbp_program: Optional[str],
                        proxy_pool: Any, audit_trail: Any,
                        use_proxy: bool = True) -> list[JSFile]:
    """Download JS files with per-host session."""
    if not js_files:
        return []

    log.info(f"  Downloading {len(js_files)} JS file(s)...")

    by_host: dict[str, list[JSFile]] = {}
    for f in js_files:
        by_host.setdefault(f.host or "", []).append(f)

    results: list[JSFile] = []
    rate_sleep = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0

    for host, files in by_host.items():
        if not host:
            for f in files:
                f.error = "no host"
                results.append(f)
            continue

        session = HttpSession(
            host=host, bbp_program=bbp_program,
            proxy_pool=proxy_pool, audit_trail=audit_trail,
            use_proxy=use_proxy)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_download_one, session, f): f for f in files}
            for fut in as_completed(futures):
                f = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as e:
                    f.error = str(e)[:120]
                    results.append(f)
                if rate_sleep > 0:
                    time.sleep(rate_sleep)

    ok = sum(1 for f in results if f.ok)
    log.info(f"    Downloaded: {ok} / {len(results)} successful")
    return results


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  CHAIN BUILDER
# ══════════════════════════════════════════════════════════════════════════

def _build_chains(findings: list[Finding]) -> list[dict]:
    groups: dict[str, list[str]] = {}
    for f in findings:
        for cid in f.chain_ids:
            groups.setdefault(cid, []).append(f.redacted or f.value)

    out = []
    for cid, members in groups.items():
        out.append({
            "chain_id": cid,
            "name":     CHAIN_NAMES.get(cid, cid),
            "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
            "members":  members[:100],
            "count":    len(members),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    out.sort(key=lambda c: (order.get(c["severity"], 5), c["chain_id"]))
    return out


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def run_js_analysis(
    input_file: Path,
    outdir: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    download_threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    headers: Optional[dict] = None,
    scan_id: Optional[int] = None,
    bbp_program: Optional[str] = None,
    use_proxy: bool = True,
    aggressive: bool = True,
    resume: bool = False,
    dry_run: bool = False,
    proxy_pool: Any = None,
    audit_trail: Any = None,
) -> Path:
    """Main entry point — discovers, downloads, analyzes, triages JS files."""
    start = time.monotonic()
    outdir = outdir or (_cfg("OUTPUT_DIR") or Path("output"))
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "js_sourcemaps"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Resolve limits from config
    limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("js", {}) or {}
    eff_threads = download_threads if download_threads is not None else limits.get("rps", DEFAULT_DOWNLOAD_THREADS)
    eff_rate = rate_limit if rate_limit is not None else limits.get("rps", DEFAULT_RATE_LIMIT)
    if not isinstance(eff_threads, int) or eff_threads < 1:
        eff_threads = DEFAULT_DOWNLOAD_THREADS
    if not isinstance(eff_rate, int) or eff_rate < 0:
        eff_rate = DEFAULT_RATE_LIMIT
    eff_threads, eff_rate = _effective_limits(eff_threads, eff_rate)

    # Load targets — try JSON, then dir, then text
    by_host: dict[str, list[str]] = {}
    source_type = "unknown"

    if input_file.exists():
        if input_file.suffix == ".json":
            by_host = _load_from_site_pages(input_file)
            source_type = "site_pages"
        elif input_file.is_dir():
            by_host = _load_from_js_dir(input_file)
            source_type = "js_dir"
        else:
            by_host = _load_from_url_list(input_file)
            source_type = "url_list"

    # If no JS found and we have base URLs, run katana
    if not by_host and input_file.exists():
        base_urls = []
        if source_type == "url_list":
            base_urls = [u for urls in _load_from_url_list(input_file).values()
                         for u in urls]
        elif source_type == "site_pages":
            try:
                data = json.loads(input_file.read_text())
                base_urls = [f"https://{h['host']}" for h in data.get("hosts", [])
                             if h.get("host")]
            except Exception:
                pass

        if base_urls and aggressive:
            log.info(f"  No JS URLs in input — running katana on {len(base_urls)} host(s)")
            by_host = _discover_katana(base_urls, eff_rate, eff_threads, bbp_program)
            source_type = f"{source_type}+katana"

    if not by_host:
        log.warn("No JS targets found")
        return _write_empty(outdir, input_file, start)

    # Aggregate totals
    total_js = sum(len(v) for v in by_host.values())
    if total_js > max_files:
        log.warn(f"Capping at {max_files} JS files (found {total_js})")
        factor = max_files / total_js
        for h in by_host:
            by_host[h] = by_host[h][:max(1, int(len(by_host[h]) * factor))]

    # Header + config display
    cfg_hdrs = {}
    try:
        builder = _cfg("build_headers")
        if callable(builder) and bbp_program:
            cfg_hdrs = builder(bbp_program, dynamic_ua=False)
    except Exception:
        pass

    log.info(f"Input  : {source_type}")
    log.info(f"         {len(by_host)} host(s) · {sum(len(v) for v in by_host.values())} JS URL(s)")
    log.info("")
    log.info(f"Config : threads={eff_threads}  rate_limit={eff_rate}/s")
    log.info(f"         bbp={bbp_program or 'none'}  proxy={use_proxy}  "
              f"ai_enabled={_ai_enabled()}")
    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured")
    if LIGHTWEIGHT_MODE:
        log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — limits capped")

    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        for h, urls in sorted(by_host.items()):
            log.info(f"  {h}: {len(urls)} JS file(s)")
        return outdir / "js_findings.json"

    # Proxy pool + audit
    if use_proxy and proxy_pool is None:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls is not None:
                proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
        except Exception:
            pass

    if audit_trail is None:
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                audit_trail = factory("js-" + (input_file.stem if input_file else "scan"))
        except Exception:
            pass

    # Resume
    stream_path = outdir / "js_analysis_hosts.jsonl"
    if resume:
        done = _load_resume_hosts(stream_path)
        if done:
            by_host = {h: v for h, v in by_host.items() if h not in done}
            log.info(f"Resume : skipping {len(done)} host(s)")
    elif stream_path.exists():
        stream_path.unlink()

    # Per-host loop
    all_hosts: list[HostResult] = []
    ai_hosts_done = 0

    for i, (host, urls) in enumerate(sorted(by_host.items()), 1):
        log.rune(Rune.OTHALA, f"[{i}/{len(by_host)}] {host} — {len(urls)} JS file(s)")
        host_start = time.monotonic()

        try:
            session = HttpSession(
                host=host, bbp_program=bbp_program,
                proxy_pool=proxy_pool, audit_trail=audit_trail,
                use_proxy=use_proxy)

            # Download all JS for this host
            js_files = [JSFile(url=u, host=host, url_host=_host_of(u),
                                source=source_type)
                        for u in urls]
            downloaded = download_js_files(
                js_files, eff_threads, eff_rate, bbp_program,
                proxy_pool, audit_trail, use_proxy)

            # Analyze
            findings: list[Finding] = []
            for js in downloaded:
                if not js.ok:
                    continue
                try:
                    fs = analyze_js_file(js, session, fetch_sourcemaps=aggressive)
                    findings.extend(fs)
                except Exception as e:
                    log.debug(f"    analyze failed on {js.url}: {e}")

            # Dedupe
            seen: set[tuple] = set()
            deduped: list[Finding] = []
            for f in findings:
                key = (f.kind, f.subtype, f.value, f.file_url)
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(f)

            deduped.sort(key=lambda f: (
                0 if f.kind == "secret" else
                1 if f.kind == "jwt_weakness" else
                2 if f.kind == "sourcemap" else
                3 if f.kind == "internal_url" else 4,
                -f.severity.rank,
                -f.confidence,
            ))

            chains = _build_chains(deduped)
            elapsed = time.monotonic() - host_start

            host_result = HostResult(
                host=host, js_files=downloaded, findings=deduped,
                chains=chains, elapsed_seconds=round(elapsed, 2),
            )

            # AI triage (only if enabled + enough findings)
            ai = None
            if _ai_enabled() and len(deduped) >= AI_MIN_FINDINGS_PER_HOST \
                    and ai_hosts_done < AI_MAX_HOSTS_PER_RUN:
                ai = _ai_triage_host(host_result, outdir)
                if ai:
                    ai_hosts_done += 1

            # Heuristic triage — always computed
            heuristic = _heuristic_triage(host_result)

            # Choose which to surface
            if ai:
                host_result.triage = ai
                host_result.triage_source = "ai"
            else:
                host_result.triage = heuristic
                host_result.triage_source = "heuristic"

            all_hosts.append(host_result)

            # Stream
            try:
                with stream_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "host": host,
                        "js_files": [j.to_dict() for j in downloaded],
                        "findings": [f.to_dict() for f in deduped],
                        "chains": chains,
                        "elapsed_seconds": host_result.elapsed_seconds,
                        "triage": host_result.triage,
                        "triage_source": host_result.triage_source,
                    }, ensure_ascii=False) + "\n")
            except Exception:
                pass

            # Log
            ok_count = sum(1 for j in downloaded if j.ok)
            n_sec = sum(1 for f in deduped if f.kind == "secret")
            n_crit = sum(1 for f in deduped if f.severity == Severity.CRITICAL)
            n_high = sum(1 for f in deduped if f.severity == Severity.HIGH)
            triage_tag = f" triage={host_result.triage_source}"
            log.ok(f"  {len(deduped)} finding(s) from {ok_count}/{len(downloaded)} "
                    f"JS · secrets={n_sec} · CRIT={n_crit} HIGH={n_high}{triage_tag}")

        except Exception as e:
            log.error(f"  host failed: {type(e).__name__}: {e}")
            all_hosts.append(HostResult(host=host, errors=[str(e)]))

    # Aggregate
    all_findings_flat: list[Finding] = []
    for h in all_hosts:
        all_findings_flat.extend(h.findings)

    agg_chains = _build_chains(all_findings_flat)

    # Flat outputs
    endpoints = sorted({f.value for f in all_findings_flat if f.kind == "endpoint"})
    secrets_list = [f for f in all_findings_flat if f.kind == "secret"]
    sourcemaps = sorted({f.value for f in all_findings_flat if f.kind == "sourcemap"})
    js_urls_all = sorted({j.url for h in all_hosts for j in h.js_files})

    (outdir / "js_endpoints.txt").write_text(
        "\n".join(endpoints) + ("\n" if endpoints else ""))
    (outdir / "js_secrets.txt").write_text(
        "\n".join(f"{f.subtype}\t{f.host}\t{f.redacted}\t{f.file_url}:{f.line_number}"
                   for f in secrets_list) + ("\n" if secrets_list else ""))
    (outdir / "js_sourcemaps.txt").write_text(
        "\n".join(sourcemaps) + ("\n" if sourcemaps else ""))
    (outdir / "js_files.txt").write_text(
        "\n".join(js_urls_all) + ("\n" if js_urls_all else ""))

    # Save sourcemap evidence for later
    for h in all_hosts:
        for js in h.js_files:
            if js.sourcemap_content:
                safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", js.url)[:80]
                (evidence_dir / f"{safe}.map.json").write_text(js.sourcemap_content)

    # Severity/kind counts
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_kind: dict[str, int] = {}
    for f in all_findings_flat:
        by_sev[f.severity.value] += 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1

    # Triage source breakdown
    ai_triaged = sum(1 for h in all_hosts if h.triage_source == "ai")
    heuristic_triaged = sum(1 for h in all_hosts if h.triage_source == "heuristic")

    elapsed = time.monotonic() - start
    audit_path = getattr(audit_trail, "path", None) if audit_trail else None

    report = {
        "schema_version":  2,
        "producer":        f"js_analysis.py v{__version__} '{__codename__}'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":      str(input_file),
        "input_type":      source_type,
        "bbp_program":     bbp_program,
        "use_proxy":       use_proxy,
        "ai_enabled":      _ai_enabled(),
        "host_capacity": {
            "cpu_cores":          HOST_CORES,
            "ram_mb":             HOST_RAM_MB,
            "lightweight":        LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "max_files":        max_files,
            "download_threads": eff_threads,
            "rate_limit":       eff_rate,
            "min_confidence":   MIN_REPORT_CONFIDENCE,
            "headers_count":    len(cfg_hdrs),
        },
        "audit": {
            "trail_path":   str(audit_path) if audit_path else None,
            "trail_sha256": _audit_hash(audit_path),
        },
        "totals": {
            "hosts":            len(all_hosts),
            "js_files":         len(js_urls_all),
            "findings":         len(all_findings_flat),
            "endpoints":        len(endpoints),
            "secrets":          len(secrets_list),
            "sourcemaps":       len(sourcemaps),
            "ai_triaged":       ai_triaged,
            "heuristic_triaged":heuristic_triaged,
            "by_severity":      by_sev,
            "by_kind":          dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        },
        "chains": agg_chains,
        "hosts":  [
            {
                "host":          h.host,
                "elapsed":       h.elapsed_seconds,
                "js_files":      [j.to_dict() for j in h.js_files],
                "findings":      [f.to_dict() for f in h.findings],
                "chains":        h.chains,
                "triage":        h.triage,
                "triage_source": h.triage_source,
                "errors":        h.errors,
            }
            for h in all_hosts
        ],
    }

    json_path = outdir / "js_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    _print_summary(outdir, report, elapsed)

    if scan_id is not None:
        _try_db_sync(scan_id, all_hosts)

    return json_path


def _audit_hash(p: Optional[Path]) -> Optional[str]:
    if not p: return None
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_resume_hosts(path: Path) -> set[str]:
    done = set()
    if not path.exists():
        return done
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                h = json.loads(line).get("host")
                if h:
                    done.add(h)
            except Exception:
                continue
    except Exception:
        pass
    return done


def _print_summary(outdir: Path, report: dict, elapsed: float) -> None:
    log.rune(Rune.SOWILO, "Summary")
    totals = report["totals"]
    log.info(f"Hosts analyzed    : {totals['hosts']}")
    log.info(f"JS files          : {totals['js_files']}")
    log.info(f"Total findings    : {totals['findings']}")
    log.info(f"  Endpoints       : {totals['endpoints']}")
    log.info(f"  Secrets         : {totals['secrets']}")
    log.info(f"  Source maps     : {totals['sourcemaps']}")
    if report["ai_enabled"]:
        log.info(f"AI triage         : {totals['ai_triaged']} host(s) AI · "
                  f"{totals['heuristic_triaged']} heuristic")
    else:
        log.info(f"Heuristic triage  : {totals['heuristic_triaged']} host(s)")

    by_sev = totals.get("by_severity") or {}
    log.info("Severity          : " + " ".join(
        f"{k}={by_sev.get(k, 0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))

    chains = report.get("chains") or []
    if chains:
        log.info("")
        log.info("Chains:")
        for c in chains[:10]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<32} "
                     f"[{c['severity']}] {c['count']} member(s)")

    log.info("")
    log.info("Outputs:")
    log.info(f"  {Sym.ARROW} js_findings.json            ({totals['findings']} findings — CONTAINS SECRETS)")
    log.info(f"  {Sym.ARROW} js_analysis_hosts.jsonl")
    log.info(f"  {Sym.ARROW} js_endpoints.txt")
    log.info(f"  {Sym.ARROW} js_secrets.txt              (redacted)")
    log.info(f"  {Sym.ARROW} js_sourcemaps.txt")
    log.info(f"  {Sym.ARROW} js_files.txt")
    if report["ai_enabled"] and totals["ai_triaged"] > 0:
        log.info(f"  {Sym.ARROW} js_ai_<host>.md")
    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "schema_version": 2,
        "producer": f"js_analysis.py v{__version__} '{__codename__}'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "ai_enabled": _ai_enabled(),
        "totals": {"hosts": 0, "js_files": 0, "findings": 0,
                    "endpoints": 0, "secrets": 0, "sourcemaps": 0,
                    "ai_triaged": 0, "heuristic_triaged": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0,
                                     "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    "by_kind": {}},
        "chains": [], "hosts": [],
    }
    p = outdir / "js_findings.json"
    p.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("js_endpoints.txt", "js_secrets.txt",
                  "js_sourcemaps.txt", "js_files.txt",
                  "js_analysis_hosts.jsonl"):
        (outdir / name).write_text("")
    return p


def _try_db_sync(scan_id: int, all_hosts: list[HostResult]) -> None:
    try:
        from db import DB  # type: ignore
        if not getattr(DB, "available", False):
            return
        payloads = []
        for h in all_hosts:
            for f in h.findings:
                payloads.append({
                    "host": h.host, "kind": f.kind, "subtype": f.subtype,
                    "value": f.redacted or f.value, "file_url": f.file_url,
                    "line": f.line_number, "severity": f.severity.value,
                    "confidence": f.confidence,
                })
        if payloads and hasattr(DB, "upsert_js_findings"):
            DB.upsert_js_findings(scan_id, payloads)
            log.info(f"DB sync: {len(payloads)} finding(s)")
    except Exception as e:
        log.debug(f"DB sync skipped: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Mímir's Eye integrity")

    # Synthetic fixtures — one per detection category
    TEST_AWS      = "AKIAIOSFODNN7EXAMPLE"
    TEST_PEM      = "-----BEGIN RSA PRIVATE KEY-----"
    TEST_JWT_NONE = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    TEST_XSS_CTX  = "document.getElementById('x').innerHTML = userInput;"
    TEST_INTERNAL = "const api = 'https://internal-api.corp.local/v1/users';"
    TEST_SOURCEMAP= "//# sourceMappingURL=main.js.map"
    TEST_ANTHRO   = "sk-ant-" + "a" * 90
    TEST_HF       = "hf_" + "a" * 32
    TEST_MONGO    = "mongodb://user:pass@db.example.com:27017/app"

    def _mk(content: str) -> JSFile:
        return JSFile(url="https://test.example/app.js",
                       host="test.example",
                       url_host="test.example",
                       content=content, size=len(content))

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",              lambda: CFG_LOADED),
        ("Rune.RAIDO",                 lambda: Rune.RAIDO == "ᚱ"),
        ("Severity ranks",             lambda: Severity.CRITICAL.rank == 4),
        ("_host_of works",             lambda: _host_of("https://a.b.com/x") == "a.b.com"),
        ("_host_of empty",             lambda: _host_of("") == ""),
        ("_shannon_entropy",           lambda: 0 < _shannon_entropy("abcd1234") < 4),
        ("_shannon_entropy empty",     lambda: _shannon_entropy("") == 0.0),
        ("_redact works",              lambda: _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"),
        ("_redact short",              lambda: _redact("abc") == "***"),
        ("_line_for_pos",              lambda: _line_for_pos([0, 10, 20], 15) == 2),
        ("_severity_for_confidence",   lambda: _severity_for_confidence(95, "secret") == Severity.CRITICAL),
        ("ENDPOINT_PATTERNS>=15",      lambda: len(ENDPOINT_PATTERNS) >= 15),
        ("SECRET_PATTERNS>=45",        lambda: len(SECRET_PATTERNS) >= 45),
        ("XSS_SINKS>=8",               lambda: len(XSS_SINKS) >= 8),
        ("PROTO_POLLUTION>=3",         lambda: len(PROTO_POLLUTION) >= 3),
        ("CHAIN_NAMES>=18",            lambda: len(CHAIN_NAMES) >= 18),
        ("CDN_ALLOWLIST>=10",          lambda: len(CDN_ALLOWLIST) >= 10),
        ("_analyze_endpoints fetch",   lambda: any(
            "api/v1" in f.value.lower()
            for f in _analyze_endpoints(_mk("fetch('/api/v1/users');")))),
        ("_analyze_endpoints axios",   lambda: any(
            "api" in f.value.lower()
            for f in _analyze_endpoints(_mk("axios.get('/api/data');")))),
        ("_analyze_endpoints graphql_op", lambda: any(
            f.subtype == "graphql_op"
            for f in _analyze_endpoints(_mk('const q = "query GetUser{user{id}}";')))),
        ("_analyze_endpoints ws_ctor", lambda: any(
            f.subtype == "websocket_ctor"
            for f in _analyze_endpoints(_mk('new WebSocket("wss://x.com/ws");')))),
        ("_analyze_secrets AWS",       lambda: any(
            f.subtype == "aws_access_key"
            for f in _analyze_secrets(_mk(f"k='{TEST_AWS}';")))),
        ("_analyze_secrets PEM",       lambda: any(
            f.subtype == "private_key"
            for f in _analyze_secrets(_mk(TEST_PEM)))),
        ("_analyze_secrets Anthropic", lambda: any(
            f.subtype == "anthropic_key"
            for f in _analyze_secrets(_mk(f"t='{TEST_ANTHRO}';")))),
        ("_analyze_secrets HF",        lambda: any(
            f.subtype == "huggingface"
            for f in _analyze_secrets(_mk(f"t='{TEST_HF}';")))),
        ("_analyze_secrets mongo",     lambda: any(
            f.subtype in ("db_connection", "database_url")
            for f in _analyze_secrets(_mk(f"c='{TEST_MONGO}';")))),
        ("_analyze_secrets fp_skipped", lambda: not any(
            "your_api_key" in f.value.lower()
            for f in _analyze_secrets(_mk('api_key="your_api_key_here" ')))),
        ("_analyze_secrets redacts context", lambda: all(
            "[REDACTED]" in f.context or f.value not in f.context
            for f in _analyze_secrets(_mk(f"k='{TEST_AWS}';")))),
        ("_analyze_jwt_weak alg_none", lambda: any(
            f.subtype == "alg_none"
            for f in _analyze_jwt_weak(_mk(TEST_JWT_NONE)))),
        ("_analyze_xss_sinks innerHTML", lambda: any(
            f.subtype == "innerHTML"
            for f in _analyze_xss_sinks(_mk(TEST_XSS_CTX)))),
        ("_analyze_xss_sinks eval",    lambda: any(
            f.subtype == "eval"
            for f in _analyze_xss_sinks(_mk("eval(userInput);")))),
        ("_analyze_prototype_pollution", lambda: any(
            f.subtype == "proto_assign"
            for f in _analyze_prototype_pollution(
                _mk("obj.__proto__.admin = true;")))),
        ("_analyze_postmessage wildcard", lambda: any(
            "wildcard" in f.subtype
            for f in _analyze_postmessage(_mk("t.postMessage(d, '*');")))),
        ("_analyze_storage_keys",      lambda: any(
            f.kind == "storage_key"
            for f in _analyze_storage_keys(
                _mk("localStorage.setItem('admin_token', x);")))),
        ("_analyze_debug_flags",       lambda: any(
            f.kind == "debug_flag"
            for f in _analyze_debug_flags(_mk('if (DEBUG) {}')))),
        ("_analyze_comments TODO",     lambda: any(
            f.subtype == "tag_todo"
            for f in _analyze_comments(_mk("// TODO: fix auth")))),
        ("_analyze_internal_urls",     lambda: any(
            f.kind == "internal_url"
            for f in _analyze_internal_urls(_mk(TEST_INTERNAL)))),
        ("_analyze_sourcemaps sets url", lambda: (lambda j: (
            _analyze_sourcemaps(j),
            j.sourcemap_url == "https://test.example/main.js.map"
        )[1])(_mk(TEST_SOURCEMAP))),
        ("_analyze_dynamic_imports",   lambda: any(
            f.kind == "dynamic_import"
            for f in _analyze_dynamic_imports(
                _mk("import('/chunks/v.js');")))),
        ("_analyze_service_workers",   lambda: any(
            f.kind == "service_worker"
            for f in _analyze_service_workers(
                _mk("serviceWorker.register('/sw.js');")))),
        ("_analyze_frameworks react",  lambda: any(
            f.subtype == "react"
            for f in _analyze_frameworks(
                _mk("React.createElement('div', null);")))),
        ("_analyze_frameworks vue",    lambda: any(
            f.subtype == "vue"
            for f in _analyze_frameworks(
                _mk("Vue.createApp({});")))),
        ("_analyze_webpack",           lambda: any(
            f.kind == "webpack_module"
            for f in _analyze_webpack(
                _mk("__webpack_require__(1);__webpack_require__(2);"
                     "__webpack_require__(3);__webpack_require__(4);"
                     "__webpack_require__(5);")))),
        ("HttpSession init",           lambda: callable(HttpSession)),
        ("HttpSession._in_scope CDN",  lambda: (lambda s: s._in_scope(
                                            "https://cdnjs.cloudflare.com/x.js"))(
                                            HttpSession("test.example"))),
        ("_build_chains",              lambda: isinstance(
                                            _build_chains(
                                                _analyze_secrets(_mk(f"'{TEST_AWS}'"))), list)),
        ("_ai_triage_host callable",   lambda: callable(_ai_triage_host)),
        ("_heuristic_triage callable", lambda: callable(_heuristic_triage)),
        ("_heuristic_triage empty",    lambda: _heuristic_triage(
                                            HostResult(host="x.com"))["host_risk"] == "INFO"),
        ("_ai_enabled callable",       lambda: callable(_ai_enabled)),
        ("_load_from_site_pages",      lambda: callable(_load_from_site_pages)),
        ("_load_from_url_list",        lambda: callable(_load_from_url_list)),
        ("_load_from_js_dir",          lambda: callable(_load_from_js_dir)),
        ("analyze_js_file",            lambda: callable(analyze_js_file)),
        ("run_js_analysis",            lambda: callable(run_js_analysis)),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn(): log.ok(name); passed += 1
            else: log.error(f"{name} → False"); failed += 1
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
            log.info(f"  error: {_CFG_IMPORT_ERROR}")
        return 1

    log.ok("config.py loaded")
    log.info(f"  version: {_cfg('__version__', '?')} \"{_cfg('__codename__', '?')}\"")

    items = [
        ("SCOPE",              lambda: _cfg("SCOPE") is not None),
        ("ProxyPool",          lambda: _cfg("ProxyPool") is not None),
        ("KillSwitch",         lambda: _cfg("KillSwitch") is not None),
        ("AuditTrail",         lambda: callable(_cfg("new_audit_trail"))),
        ("RateLimiter",        lambda: _cfg("RateLimiter") is not None),
        ("human_delay",        lambda: callable(_cfg("human_delay"))),
        ("random_user_agent",  lambda: callable(_cfg("random_user_agent"))),
        ("build_headers",      lambda: callable(_cfg("build_headers"))),
        ("ai_complete",        lambda: callable(_cfg("ai_complete"))),
    ]
    failed = 0
    for name, fn in items:
        try:
            if fn(): log.ok(name)
            else: log.warn(f"{name} — not configured"); failed += 1
        except Exception as e:
            log.error(f"{name} — {e}"); failed += 1

    # AI status
    log.info("")
    log.info(f"AI_ENABLED       : {_ai_enabled()}")
    if _ai_enabled():
        log.ok("AI triage will run on hosts with >=3 findings")
    else:
        log.info("Heuristic triage will run (same schema, no API cost)")

    # katana
    log.info(f"katana           : {'present' if shutil.which('katana') else 'NOT FOUND'}")

    # Input availability
    sp = (_cfg("OUTPUT_DIR") or Path("output")) / "site_pages.json"
    lu = (_cfg("OUTPUT_DIR") or Path("output")) / "live_urls.txt"
    log.info(f"site_pages.json  : {'present' if sp.exists() else 'NOT FOUND'}")
    log.info(f"live_urls.txt    : {'present' if lu.exists() else 'NOT FOUND'}")

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
    default_input = base / "output" / "site_pages.json"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"

    p = argparse.ArgumentParser(
        prog="js_analysis.py",
        description=f"Argus recon · js_analysis v{__version__} '{__codename__}'",
    )
    p.add_argument("--input", type=Path, default=default_input,
                    help="site_pages.json | live_urls.txt | directory of .js")
    p.add_argument("--output", type=Path, default=base / "output")
    p.add_argument("--bbp", type=str, default=None)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--fast", dest="aggressive", action="store_false",
                    default=True, help="fast: skip sourcemap fetching")
    p.add_argument("--resume", action="store_true",
                    help="skip hosts already in js_analysis_hosts.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                    version=f"js_analysis.py {__version__} '{__codename__}'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try: CFG.Palette._enabled = False  # type: ignore
        except Exception: pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()

    print_banner()

    try:
        run_js_analysis(
            input_file=args.input,
            outdir=args.output,
            max_files=args.max_files,
            download_threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
            bbp_program=args.bbp,
            use_proxy=not args.no_proxy,
            aggressive=args.aggressive,
            resume=args.resume,
            dry_run=args.dry_run,
        )
        return 0
    except KeyboardInterrupt:
        log.warn("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
