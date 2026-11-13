#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/dns_resolve.py — DNS Resolution & Wildcard Filtering
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/dns_resolve.py
  Version   : 3.0.0 "URÐR"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  DNS resolution stage. Sends ZERO traffic to the target — all queries go
  to public recursors (Cloudflare, Google, Quad9), never the target's
  nameservers or HTTP server. Platform headers and auth cookies are NOT
  applied (and don't need to be).

  v1.0 → v3.0 (silent-failure fixes):
    [FIX]  MODULE_RATE_LIMITS["dns"] → ["dns_enum"]. Config.py uses
           "dns_enum" — was defaulting to 10t/20rps regardless of config.
    [FIX]  entry.get("rate_limit") → entry.get("rps"). config.py uses "rps".
    [FIX]  _resolve_simple: gethostbyname_ex → getaddrinfo. IPv4-only bug
           meant AAAA wildcards were NEVER detected. Real coverage gap.
    [FIX]  _load_subdomains / _load_roots: BOM/CRLF/inline-comment safe.
    [FIX]  KillSwitch.check() before every DNS subprocess and socket call.
    [FIX]  _write_empty_report now accepts scan_id for empty-input DB sync.
    [FIX]  MAX_CNAME_CHAIN_DEPTH now enforced (was defined, never used).

  v3.0 — NEW:
    [NEW]  Email auth detection — DMARC, SPF, DKIM per root domain.
    [NEW]  CAA record parsing — cert issuance restriction per root.
    [NEW]  CNAME chain depth tracking + terminal resolution.
    [NEW]  Wildcard detection cache (.state/dns_wildcards.json, 1h TTL).
    [NEW]  Enriched dnsx input — auto-probes _dmarc.<root> for every root.
    [NEW]  Per-record manual_test + nuclei_tags + confidence.
    [NEW]  Per-host heuristic triage — clusters, chains, next_actions.
    [NEW]  AI triage with schema validation + corrective retry + cache.
    [NEW]  dns_findings_digest.md — top-50 markdown table.
    [NEW]  Structured warnings[] array in report.
    [NEW]  SIGINT/SIGTERM handler — finish current host, write partial.
    [NEW]  --dry-run, --quiet, --no-ai, --ai-max-hosts, --ai-max-cost,
           --ai-cache-ttl, --wildcard-file, --no-wildcard-cache.
    [NEW]  on_progress callback for TUI/dashboard integration.
    [NEW]  Selftest with 48 checks (was 0).
    [NEW]  Expanded TAKEOVER_FINGERPRINTS (40 → 55 services).
    [NEW]  Cloud provider classification from IP (static CIDR map).

  Config integration:
    ·  MODULE_RATE_LIMITS["dns_enum"]  → rps + concurrency + jitter
    ·  KillSwitch, RateLimiter, human_delay, SCOPE (no-op for DNS)
    ·  AI_ENABLED, AI.model, ai_complete, AI_COSTS
    ·  SYNC_TO_DB, BRIDGE_ENABLED, new_audit_trail
    ·  STATE_DIR (for wildcard cache)

  Outputs:
    dns_resolved.txt            — every subdomain with A/AAAA
    dns_wildcard_filtered.txt   — feed to httpx
    dns_takeover_candidates.txt — CNAME to known-vulnerable service
    dns_resolve.json            — full report with per-host triage
    dns_findings_digest.md      — top-50 markdown table
    dns_ai_<host>.md            — per-host AI triage (when AI on)
    dns_ai_cache/               — versioned AI cache
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional


# ═════════════════════════════════════════════════════════════════════════
#  LOGGER (v3.1) — config.log with _FallbackLogger
# ═════════════════════════════════════════════════════════════════════════

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
        return CFG._c(name)  # type: ignore[union-attr]
    return _FallbackPalette.c(name)


class _FallbackLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self) -> None:
        self.min_level = "info"

    def _emit(self, level: str, msg: str, color: str, prefix: str) -> None:
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")

    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info (self, m): self._emit("info",  m, "cyan", "·")
    def warn (self, m): self._emit("warn",  m, "amber", "⚠")
    def warning(self, m): self._emit("warn", m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def fatal(self, m): self._emit("fatal", m, "blood", "☠")
    def ok   (self, m): self._emit("info",  m, "green", "✓")

    def rune(self, rune: str, msg: str) -> None:
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")


# v3.1 CRITICAL: use config.log (ArgusLogger with .ok/.warn/.rune) instead of
# stdlib logging.getLogger. This fixes the AttributeError that killed the
# 2026-11-12 run at position 10 in the pipeline chain.
log = _cfg("log") or _FallbackLogger()


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG INTEGRATION
# ═════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False

try:
    from db import DB  # type: ignore
    DB_AVAILABLE = True
except ImportError:
    DB = None  # type: ignore[assignment]
    DB_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _ai_enabled() -> bool:
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


def _killswitch_check(label: str = "") -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG READERS — v3.0 FIX
# ═════════════════════════════════════════════════════════════════════════

def _dns_settings() -> dict:
    """
    v3.0: reads MODULE_RATE_LIMITS["dns_enum"] (config's canonical key)
    with legacy fallback to "dns". Returns rps + concurrency + jitter.
    """
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = all_limits.get("dns_enum") or all_limits.get("dns") or {}

    threads = entry.get("concurrency", 5)
    rate    = entry.get("rps", entry.get("rate_limit", 5))
    jitter  = entry.get("jitter", (0.0, 0.0))
    timeout = entry.get("timeout", 900)

    if not isinstance(threads, int) or threads < 1: threads = 5
    if not isinstance(rate, int) or rate < 0:       rate = 5
    if not isinstance(timeout, int) or timeout < 1: timeout = 900
    if not isinstance(jitter, (tuple, list)) or len(jitter) != 2:
        jitter = (0.0, 0.0)

    return {"threads": threads, "rate_limit": rate,
            "jitter": tuple(jitter), "timeout": timeout}


# ═════════════════════════════════════════════════════════════════════════
#  THREAD LOCKS
# ═════════════════════════════════════════════════════════════════════════

_AI_LOCK     = threading.Lock()
_LOG_LOCK    = threading.Lock()
_CACHE_LOCK  = threading.Lock()
_SHARED      = {"_quiet": False}


def _log_locked(level: str, msg: str) -> None:
    """
    v3.1: dispatches by logger type. stdlib Logger has .warning() not .warn();
    custom loggers (ArgusLogger, _FallbackLogger) have .warn() not .warning().
    Silent on both. Defense-in-depth — the primary fix is the log object swap
    above, but this ensures robustness even if a stdlib logger reaches here.
    """
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        try:
            if level == "warn":
                if isinstance(log, logging.Logger):
                    log.warning(msg)
                elif hasattr(log, "warn"):
                    log.warn(msg)
                elif hasattr(log, "warning"):
                    log.warning(msg)
                else:
                    log.info(msg)
            elif level == "ok":
                if hasattr(log, "ok"):
                    log.ok(msg)
                else:
                    log.info(f"✓ {msg}")
            else:
                getattr(log, level)(msg)
        except Exception:
            try:
                log.info(msg)
            except Exception:
                pass


def _safe_log(level: str, msg: str) -> None:
    """
    v3.1: logging that NEVER raises. Use for any non-critical log line
    (digest summaries, per-record notes) so a log-formatting bug can't
    kill the whole stage mid-write.
    """
    try:
        _log_locked(level, msg)
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

DNSX_THREADS             = 5
DNSX_RATE_LIMIT          = 5
DNSX_TIMEOUT             = 900
DNSX_RETRIES             = 2

WILDCARD_PROBES_PER_ROOT = 3
WILDCARD_MIN_AGREEMENT   = 2
WILDCARD_CHECK_THREADS   = 10
WILDCARD_CACHE_TTL_HOURS = 1.0
WILDCARD_CACHE_FILE      = "dns_wildcards.json"

MAX_INPUT                = 50000
MAX_CNAME_CHAIN_DEPTH    = 8
DEFAULT_MAX_FINDINGS     = 10000
MAX_CLUSTERS_IN_REPORT   = 200

# AI triage
AI_MIN_RECORDS_PER_HOST  = 1
AI_DEFAULT_MAX_HOSTS     = 20
AI_DEFAULT_CACHE_TTL_HOURS = 72
AI_ESTIMATE_PER_CALL_USD = 0.002
AI_PROMPT_VERSION        = "v3.0"

# TLD-aware apex computation
_SECOND_LEVEL_TLDS = frozenset({
    "co", "com", "net", "org", "ac", "gov", "edu", "mil", "sch",
})

# Common DKIM selectors
DKIM_SELECTORS = (
    "default", "mail", "email", "smtp", "dkim", "k1",
    "google", "selector1", "selector2", "s1", "s2",
    "mandrill", "everlytics", "protonmail",
)

# TXT record markers → service name
TXT_SERVICE_MARKERS: dict[str, str] = {
    "stripe-verification":                "Stripe",
    "google-site-verification":           "Google",
    "atlassian-domain-verification":      "Atlassian",
    "facebook-domain-verification":       "Facebook",
    "MS=":                                "Microsoft 365",
    "v=spf1 include:_spf.google.com":     "Google Workspace (SPF)",
    "v=spf1 include:spf.protection.outlook.com": "Microsoft 365 (SPF)",
    "v=spf1 include:mail.zendesk.com":    "Zendesk (SPF)",
    "v=spf1 include:sendgrid.net":        "SendGrid (SPF)",
    "v=spf1 include:_spf.mailgun.org":    "Mailgun (SPF)",
    "v=spf1 include:amazonses.com":       "Amazon SES (SPF)",
    "shopify-verification":               "Shopify",
    "adobe-idp-site-verification":        "Adobe",
    "have-a-valid-coupon":                "Coupon service",
    "amazonses":                          "Amazon SES",
    "mailgun":                            "Mailgun",
    "sendgrid":                           "SendGrid",
    "postmark":                           "Postmark",
    "v=dmarc1":                           "DMARC",
    "v=dkim1":                            "DKIM",
}

# CNAME targets matching these patterns are takeover candidates
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    # ── AWS ────────────────────────────────────────────────────────────────
    "s3.amazonaws.com":           "AWS S3 bucket",
    "s3-website":                 "AWS S3 static website",
    "s3.dualstack":               "AWS S3 dualstack",
    "cloudfront.net":             "AWS CloudFront",
    "elasticbeanstalk.com":       "AWS Elastic Beanstalk",
    "amplifyapp.com":             "AWS Amplify",
    "execute-api.":               "AWS API Gateway",
    # ── Azure ──────────────────────────────────────────────────────────────
    "azurewebsites.net":          "Azure App Service",
    "cloudapp.azure.com":         "Azure Cloud App",
    "cloudapp.net":               "Azure Cloud Services",
    "azure-api.net":              "Azure API Management",
    "trafficmanager.net":         "Azure Traffic Manager",
    "blob.core.windows.net":      "Azure Blob Storage",
    "azurestaticapps.net":        "Azure Static Web Apps",
    # ── GCP ────────────────────────────────────────────────────────────────
    "storage.googleapis.com":     "Google Cloud Storage",
    "firebaseapp.com":            "Firebase",
    "web.app":                    "Firebase Hosting",
    # ── PaaS / hosting ─────────────────────────────────────────────────────
    "github.io":                  "GitHub Pages",
    "herokuapp.com":              "Heroku",
    "herokudns.com":              "Heroku DNS",
    "netlify.app":                "Netlify",
    "netlify.com":                "Netlify",
    "vercel.app":                 "Vercel",
    "now.sh":                     "Vercel",
    "fly.dev":                    "Fly.io",
    "render.com":                 "Render",
    "pantheonsite.io":            "Pantheon",
    "surge.sh":                   "Surge",
    "bitbucket.io":               "Bitbucket",
    "gitlab.io":                  "GitLab Pages",
    # ── CDN ────────────────────────────────────────────────────────────────
    "fastly.net":                 "Fastly",
    "cdn.cloudflare.net":         "Cloudflare",
    "workers.dev":                "Cloudflare Workers",
    "pages.dev":                  "Cloudflare Pages",
    "b-cdn.net":                  "Bunny CDN",
    # ── SaaS / website builders ────────────────────────────────────────────
    "myshopify.com":              "Shopify",
    "shopifypreview.com":         "Shopify",
    "tumblr.com":                 "Tumblr",
    "wordpress.com":              "WordPress.com",
    "ghost.io":                   "Ghost",
    "zendesk.com":                "Zendesk",
    "uservoice.com":              "UserVoice",
    "statuspage.io":              "Statuspage",
    "readme.io":                  "ReadMe",
    "unbounce.com":               "Unbounce",
    "ngrok.io":                   "ngrok",
    "ngrok-free.app":             "ngrok",
    "aftership.com":              "AfterShip",
    "cargocollective.com":        "Cargo",
    "helpscoutdocs.com":          "Help Scout",
    "kajabi.com":                 "Kajabi",
    "createsend.com":             "Campaign Monitor",
    "pingdom.com":                "Pingdom",
    "tictail.com":                "Tictail",
    "strikingly.com":             "Strikingly",
    "agilecrm.com":               "Agile CRM",
    "short.io":                   "Short.io",
}

# Cloud provider classification from IP CIDR (static subset, best-effort)
_CLOUD_IP_HINTS = (
    ("cloudflare", "Cloudflare"),
    ("amazonaws", "AWS"),
    ("googleusercontent", "GCP"),
    ("azure", "Azure"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("heroku", "Heroku"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
)


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class DNSRecord:
    host: str
    a:       list[str] = field(default_factory=list)
    aaaa:    list[str] = field(default_factory=list)
    cname:   list[str] = field(default_factory=list)
    mx:      list[str] = field(default_factory=list)
    ns:      list[str] = field(default_factory=list)
    txt:     list[str] = field(default_factory=list)
    caa:     list[str] = field(default_factory=list)
    soa:     str = ""
    status:  str = ""
    wildcard: bool = False
    takeover: bool = False
    takeover_service: str = ""
    root: str = ""
    services_found: list[str] = field(default_factory=list)
    first_seen: str = ""
    # v3.0 additions
    cname_chain_depth: int = 0
    cname_chain_terminal: str = ""
    email_auth_spf: str = ""
    email_auth_dmarc: str = ""
    email_auth_dkim: list[str] = field(default_factory=list)
    confidence: int = 0
    manual_test: str = ""
    nuclei_tags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa)

    def to_dict(self) -> dict:
        return {
            "host":              self.host,
            "root":              self.root,
            "a":                 self.a,
            "aaaa":              self.aaaa,
            "cname":             self.cname,
            "mx":                self.mx,
            "ns":                self.ns,
            "txt":               self.txt,
            "caa":               self.caa,
            "soa":               self.soa,
            "status":            self.status,
            "resolves":          self.resolves,
            "wildcard":          self.wildcard,
            "takeover_candidate": self.takeover,
            "takeover_service":  self.takeover_service,
            "services_found":    self.services_found,
            "first_seen":        self.first_seen,
            "cname_chain_depth": self.cname_chain_depth,
            "cname_chain_terminal": self.cname_chain_terminal,
            "email_auth": {
                "spf":    self.email_auth_spf,
                "dmarc":  self.email_auth_dmarc,
                "dkim":   self.email_auth_dkim,
            },
            "confidence":        self.confidence,
            "manual_test":       self.manual_test,
            "nuclei_tags":       self.nuclei_tags,
            "reasons":           self.reasons,
        }


@dataclass
class WildcardInfo:
    root: str
    wildcard_ips: set[str] = field(default_factory=set)
    wildcard_cnames: set[str] = field(default_factory=set)
    detected: bool = False
    probes_attempted: int = 0
    probes_resolved: int = 0
    from_cache: bool = False

    def to_dict(self) -> dict:
        return {
            "root":             self.root,
            "detected":         self.detected,
            "wildcard_ips":     sorted(self.wildcard_ips),
            "wildcard_cnames":  sorted(self.wildcard_cnames),
            "probes_attempted": self.probes_attempted,
            "probes_resolved":  self.probes_resolved,
            "from_cache":       self.from_cache,
        }


@dataclass
class HostResult:
    host: str
    records: list[DNSRecord] = field(default_factory=list)
    triage: Optional[dict] = None
    triage_source: str = ""
    warnings: list[str] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════

def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _base_host(target_host: str) -> str:
    """v3.0: TLD-aware apex computation."""
    if not target_host:
        return ""
    parts = target_host.split(".")
    if len(parts) < 2:
        return target_host
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_dmarc_probe(host: str) -> bool:
    return host.lower().startswith("_dmarc.")


def _is_dkim_probe(host: str) -> bool:
    return "_domainkey." in host.lower()


def _looks_like_cloud(hostname: str) -> str:
    """v3.0: best-effort cloud provider from PTR hostname."""
    if not hostname:
        return ""
    hl = hostname.lower()
    for pattern, provider in _CLOUD_IP_HINTS:
        if pattern in hl:
            return provider
    return ""


# ═════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING (v3.0 — BOM/CRLF/inline-comment safe)
# ═════════════════════════════════════════════════════════════════════════

def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    if not wildcard_file or not wildcard_file.exists():
        return []
    roots: set[str] = set()
    raw = wildcard_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line and "." in line:
            roots.add(line.rstrip("."))
    return sorted(roots)


def _load_subdomains(subs_file: Path) -> list[str]:
    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    subs: set[str] = set()
    raw = subs_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
        line = line.split("/")[0].split(":")[0].rstrip(".")
        if line and "." in line:
            subs.add(line)
    return sorted(subs)


def _match_root(host: str, roots: list[str]) -> str:
    for r in roots:
        if host == r or host.endswith("." + r):
            return r
    return ""


# ═════════════════════════════════════════════════════════════════════════
#  WILDCARD DETECTION (2/3 agreement + cache + AAAA support)
# ═════════════════════════════════════════════════════════════════════════

def _wildcard_cache_path() -> Optional[Path]:
    state_dir = _cfg("STATE_DIR")
    if state_dir is None:
        return None
    p = Path(state_dir) / WILDCARD_CACHE_FILE
    return p


def _load_wildcard_cache() -> dict[str, dict]:
    p = _wildcard_cache_path()
    if p is None or not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        now = time.time()
        fresh = {}
        for root, entry in data.items():
            ts = entry.get("_cached_at", 0)
            age_hours = (now - ts) / 3600
            if age_hours <= WILDCARD_CACHE_TTL_HOURS:
                fresh[root] = entry
        return fresh
    except Exception:
        return {}


def _save_wildcard_cache(cache: dict[str, dict]) -> None:
    p = _wildcard_cache_path()
    if p is None:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_LOCK:
            p.write_text(json.dumps(cache, indent=2, default=str) + "\n",
                          encoding="utf-8")
    except Exception:
        pass


def _random_subdomain(prefix: str = "argus-wc-") -> str:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return prefix + rand


def _resolve_simple(host: str, timeout: float = 5.0) -> tuple[list[str], list[str]]:
    """
    v3.0: A + AAAA + CNAME resolution via getaddrinfo.
    gethostbyname_ex is IPv4-only — it silently missed IPv6 wildcards.
    """
    _killswitch_check(f"resolve-{host}")
    addrs: list[str] = []
    cnames: list[str] = []
    try:
        socket.setdefaulttimeout(timeout)
        # A + AAAA
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
            for info in infos:
                addr = info[4][0]
                if addr and addr not in addrs:
                    addrs.append(addr)
        except (socket.gaierror, socket.timeout):
            pass
        # CNAME via gethostbyname_ex (separate call — no IPv6 involvement)
        try:
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            for a in aliases:
                al = a.lower().rstrip(".")
                if al != host.lower() and al not in cnames:
                    cnames.append(al)
            canon = canonical.lower().rstrip(".")
            if canon != host.lower() and canon not in cnames:
                cnames.append(canon)
        except (socket.gaierror, socket.timeout):
            pass
    except Exception:
        pass
    return addrs, cnames


def _detect_wildcard_for_root(
    root: str, samples: int = WILDCARD_PROBES_PER_ROOT,
    cache: Optional[dict[str, dict]] = None,
) -> WildcardInfo:
    info = WildcardInfo(root=root)

    # Cache hit?
    if cache and root in cache:
        cached = cache[root]
        info.wildcard_ips = set(cached.get("wildcard_ips", []))
        info.wildcard_cnames = set(cached.get("wildcard_cnames", []))
        info.detected = bool(cached.get("detected", False))
        info.probes_attempted = int(cached.get("probes_attempted", 0))
        info.probes_resolved = int(cached.get("probes_resolved", 0))
        info.from_cache = True
        return info

    probe_ips: list[set[str]] = []
    probe_cnames: list[set[str]] = []

    for _ in range(samples):
        _killswitch_check(f"wildcard-{root}")
        probe = f"{_random_subdomain()}.{root}"
        a_records, cname_chain = _resolve_simple(probe)
        info.probes_attempted += 1
        if a_records or cname_chain:
            info.probes_resolved += 1
        probe_ips.append(set(a_records))
        probe_cnames.append(set(cname_chain))

    if info.probes_resolved < WILDCARD_MIN_AGREEMENT:
        return info

    ip_counts: dict[str, int] = defaultdict(int)
    cname_counts: dict[str, int] = defaultdict(int)
    for ips in probe_ips:
        for ip in ips:
            ip_counts[ip] += 1
    for cnames in probe_cnames:
        for c in cnames:
            cname_counts[c] += 1

    for ip, count in ip_counts.items():
        if count >= WILDCARD_MIN_AGREEMENT:
            info.wildcard_ips.add(ip)
            info.detected = True
    for cname, count in cname_counts.items():
        if count >= WILDCARD_MIN_AGREEMENT:
            info.wildcard_cnames.add(cname)
            info.detected = True

    return info


def _detect_wildcards_parallel(
    roots: list[str], use_cache: bool = True,
) -> dict[str, WildcardInfo]:
    if not roots:
        return {}

    cache: dict[str, dict] = _load_wildcard_cache() if use_cache else {}
    _log_locked("info",
        f"  Wildcard check : probing {len(roots)} root(s) "
        f"× {WILDCARD_PROBES_PER_ROOT} each "
        f"(agreement: {WILDCARD_MIN_AGREEMENT}/{WILDCARD_PROBES_PER_ROOT}"
        + (f", cache: {len(cache)} entries" if cache else "") + ")")

    results: dict[str, WildcardInfo] = {}
    new_cache: dict[str, dict] = dict(cache)

    with ThreadPoolExecutor(max_workers=min(WILDCARD_CHECK_THREADS, len(roots))) as pool:
        future_map = {
            pool.submit(_detect_wildcard_for_root, root,
                          WILDCARD_PROBES_PER_ROOT, cache): root
            for root in roots
        }
        for fut in as_completed(future_map):
            root = future_map[fut]
            try:
                info = fut.result()
            except Exception as e:
                log.debug(f"    wildcard check failed for {root}: {e}")
                info = WildcardInfo(root=root)
            results[root] = info

            # Persist to cache if it was a fresh probe
            if not info.from_cache and info.probes_attempted > 0:
                new_cache[root] = {
                    "wildcard_ips":    sorted(info.wildcard_ips),
                    "wildcard_cnames": sorted(info.wildcard_cnames),
                    "detected":        info.detected,
                    "probes_attempted": info.probes_attempted,
                    "probes_resolved": info.probes_resolved,
                    "_cached_at":      time.time(),
                }

            cache_tag = " (cached)" if info.from_cache else ""
            if info.detected:
                ips = ",".join(sorted(info.wildcard_ips)[:3]) or "(cname)"
                _log_locked("info",
                    f"    {root:<30} WILDCARD ({ips})  "
                    f"{info.probes_resolved}/{info.probes_attempted} probes{cache_tag}")
            else:
                _log_locked("info",
                    f"    {root:<30} clean  "
                    f"{info.probes_resolved}/{info.probes_attempted} probes{cache_tag}")

    _save_wildcard_cache(new_cache)
    return results


# ═════════════════════════════════════════════════════════════════════════
#  DNSX EXECUTION (v3.0 — enriched input, CAA, KillSwitch)
# ═════════════════════════════════════════════════════════════════════════

def _build_enriched_input(subs: list[str], roots: list[str]) -> list[str]:
    """v3.0: add DMARC probes for every root so one dnsx pass gets everything."""
    enriched = list(subs)
    seen = set(subs)
    for root in roots:
        dmarc = f"_dmarc.{root}"
        if dmarc not in seen:
            enriched.append(dmarc)
            seen.add(dmarc)
        if root not in seen:
            enriched.append(root)
            seen.add(root)
    return enriched


def _run_dnsx(
    subs: list[str], threads: int, rate_limit: int, workdir: Path,
    timeout: int = DNSX_TIMEOUT,
) -> Optional[Path]:
    if not shutil.which("dnsx"):
        _log_locked("warn",
            "    dnsx not installed — falling back to socket-based resolution")
        return None

    _killswitch_check("dnsx")

    input_file = workdir / "dnsx_input.txt"
    input_file.write_text("\n".join(subs) + "\n")
    output_file = workdir / "dnsx_raw.jsonl"

    cmd = [
        "dnsx",
        "-l", str(input_file),
        "-json",
        "-silent",
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-caa",
        "-resp",
        "-threads", str(threads),
        "-retry", str(DNSX_RETRIES),
        "-timeout", "5",
        "-o", str(output_file),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])

    _log_locked("info",
        f"    $ dnsx -l <{len(subs)} hosts> -a -aaaa -cname -mx -ns -txt -soa -caa ...")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        _log_locked("warn",
            f"    dnsx exceeded {timeout}s — using partial output")
        result = None
    except FileNotFoundError:
        return None
    except OSError as e:
        _log_locked("warn", f"    dnsx failed: {e}")
        return None

    if not output_file.exists():
        stderr = result.stderr[:160] if result else "n/a"
        _log_locked("warn", f"    dnsx produced no output (stderr: {stderr})")
        return None

    return output_file


def _parse_dnsx_jsonl(path: Path) -> dict[str, DNSRecord]:
    records: dict[str, DNSRecord] = {}
    parse_errors = 0

    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        host = (obj.get("host") or obj.get("input") or "").lower().strip().rstrip(".")
        if not host:
            continue

        rec = DNSRecord(host=host)

        for key, dest in (
            ("a", rec.a), ("AAAA", rec.aaaa), ("aaaa", rec.aaaa),
            ("cname", rec.cname), ("mx", rec.mx),
            ("ns", rec.ns), ("txt", rec.txt),
            ("caa", rec.caa), ("CAA", rec.caa),
        ):
            val = obj.get(key)
            if isinstance(val, list):
                for x in val:
                    if x:
                        s = str(x).strip()
                        # Dedupe
                        if s not in dest:
                            dest.append(s)

        soa = obj.get("soa")
        if isinstance(soa, list) and soa:
            rec.soa = str(soa[0])
        elif isinstance(soa, str):
            rec.soa = soa

        status = obj.get("status_code") or obj.get("rcode") or obj.get("status") or ""
        rec.status = str(status).upper() if status else "NOERROR"

        records[host] = rec

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    return records


# ═════════════════════════════════════════════════════════════════════════
#  FALLBACK RESOLVER (v3.0 — AAAA + CNAME support)
# ═════════════════════════════════════════════════════════════════════════

def _resolve_fallback(subs: list[str]) -> dict[str, DNSRecord]:
    _log_locked("info",
        f"    Fallback resolver: getaddrinfo + gethostbyname_ex  ({len(subs)} hosts)")

    def _worker(host: str) -> tuple[str, DNSRecord]:
        rec = DNSRecord(host=host)
        _killswitch_check(f"fallback-{host}")
        try:
            socket.setdefaulttimeout(5.0)
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
                for info in infos:
                    addr = info[4][0]
                    if ":" in addr:
                        if addr not in rec.aaaa:
                            rec.aaaa.append(addr)
                    else:
                        if addr not in rec.a:
                            rec.a.append(addr)
            except (socket.gaierror, socket.timeout):
                rec.status = "NXDOMAIN"
                return host, rec
            try:
                canonical, aliases, _ = socket.gethostbyname_ex(host)
                for alias in aliases:
                    al = alias.lower().rstrip(".")
                    if al != host.lower():
                        rec.cname.append(al)
                canon = canonical.lower().rstrip(".")
                if canon != host.lower() and canon not in rec.cname:
                    rec.cname.append(canon)
            except Exception:
                pass
            rec.status = "NOERROR"
        except Exception:
            rec.status = "ERROR"
        return host, rec

    results: dict[str, DNSRecord] = {}
    with ThreadPoolExecutor(max_workers=50) as pool:
        for host, rec in pool.map(_worker, subs):
            results[host] = rec
    return results


# ═════════════════════════════════════════════════════════════════════════
#  ANALYSIS (v3.0 — email auth, CAA, CNAME chain depth)
# ═════════════════════════════════════════════════════════════════════════

def _match_wildcard(
    rec: DNSRecord, wildcards: dict[str, WildcardInfo], roots: list[str],
) -> None:
    root = _match_root(rec.host, roots)
    rec.root = root
    if not root or root not in wildcards:
        return
    info = wildcards[root]
    if not info.detected:
        return
    if set(rec.a).intersection(info.wildcard_ips):
        rec.wildcard = True
    elif set(rec.aaaa).intersection(info.wildcard_ips):
        rec.wildcard = True
    elif set(rec.cname).intersection(info.wildcard_cnames):
        rec.wildcard = True


def _detect_takeover(rec: DNSRecord) -> None:
    for cname in rec.cname:
        cname_lower = cname.lower()
        for pattern, service_name in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname_lower:
                rec.takeover = True
                rec.takeover_service = service_name
                return


def _extract_services_from_txt(rec: DNSRecord) -> list[str]:
    services: set[str] = set()
    for txt in rec.txt:
        txt_lower = txt.lower()
        for marker, service_name in TXT_SERVICE_MARKERS.items():
            if marker.lower() in txt_lower:
                services.add(service_name)
    return sorted(services)


def _extract_email_auth(rec: DNSRecord, all_records: dict[str, DNSRecord]) -> None:
    """
    v3.0: extract SPF, DMARC, DKIM from TXT records.
    Root records carry SPF; _dmarc.<root> carries DMARC; selectors carry DKIM.
    """
    host_lower = rec.host.lower()

    # SPF from root TXT
    for txt in rec.txt:
        if txt.lower().startswith("v=spf1"):
            rec.email_auth_spf = txt
            break

    # DMARC from _dmarc.<root>
    if _is_dmarc_probe(host_lower):
        for txt in rec.txt:
            if "v=dmarc1" in txt.lower():
                rec.email_auth_dmarc = txt
                break

    # DKIM from _domainkey.<root>
    if _is_dkim_probe(host_lower):
        for txt in rec.txt:
            if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                selector = host_lower.split(".")[0]
                if selector not in rec.email_auth_dkim:
                    rec.email_auth_dkim.append(selector)
                break

    # Aggregate DMARC/DKIM from sibling probes onto root record
    root = _base_host(rec.host)
    if root and rec.host.lower() == root.lower():
        dmarc_probe = f"_dmarc.{root}"
        if dmarc_probe in all_records:
            dmarc_rec = all_records[dmarc_probe]
            for txt in dmarc_rec.txt:
                if "v=dmarc1" in txt.lower():
                    rec.email_auth_dmarc = txt
                    break


def _compute_cname_chain_depth(
    rec: DNSRecord, all_records: dict[str, DNSRecord],
    max_depth: int = MAX_CNAME_CHAIN_DEPTH,
) -> None:
    """
    v3.0: walk CNAME chain depth. Enforces MAX_CNAME_CHAIN_DEPTH.
    Sets cname_chain_depth and cname_chain_terminal.
    """
    if not rec.cname:
        return

    depth = 0
    current = rec.cname[0].lower()
    visited: set[str] = {rec.host.lower()}

    while depth < max_depth and current:
        if current in visited:
            rec.reasons.append(f"cname_loop:{current}")
            break
        visited.add(current)
        depth += 1
        if current in all_records:
            next_rec = all_records[current]
            if next_rec.cname:
                current = next_rec.cname[0].lower()
                continue
        break

    rec.cname_chain_depth = depth
    rec.cname_chain_terminal = current

    if depth > 3:
        rec.reasons.append(f"long_cname_chain:{depth}")
    if depth >= max_depth:
        rec.reasons.append("cname_chain_max_depth")


def _cluster_by_ip(
    records: dict[str, DNSRecord],
) -> dict[str, list[str]]:
    """v3.0: cluster by A AND AAAA. Only clusters with 2+ hosts."""
    clusters: dict[str, list[str]] = defaultdict(list)
    for rec in records.values():
        for ip in rec.a + rec.aaaa:
            clusters[ip].append(rec.host)
    return {
        ip: sorted(set(hosts))
        for ip, hosts in clusters.items()
        if len(set(hosts)) >= 2
    }


# ═════════════════════════════════════════════════════════════════════════
#  PER-RECORD DECORATION (v3.0)
# ═════════════════════════════════════════════════════════════════════════

def _decorate_record(rec: DNSRecord) -> None:
    """Add confidence, manual_test, nuclei_tags per record."""
    confidence = 30  # baseline for resolved host

    # Boost for anything suspicious
    if rec.takeover:
        confidence = 70
        if rec.cname and rec.cname_chain_terminal:
            confidence = 85
            rec.reasons.append("dangling_cname")
        if rec.wildcard:
            confidence = max(0, confidence - 30)
            rec.reasons.append("wildcard_reduces_confidence")

    if rec.cname_chain_depth > 3:
        confidence = min(100, confidence + 5)

    # Email auth absence = spoofing risk (only meaningful on root domains)
    root = _base_host(rec.host)
    is_root = rec.host.lower() == root.lower()
    if is_root and rec.mx and not rec.email_auth_spf:
        rec.reasons.append("no_spf_with_mx")
        confidence = min(100, confidence + 10)
    if is_root and rec.mx and not rec.email_auth_dmarc:
        rec.reasons.append("no_dmarc_with_mx")

    # CAA absence on root with TLS service
    if is_root and not rec.caa:
        rec.reasons.append("no_caa")

    rec.confidence = confidence

    # Manual test hint
    if rec.takeover:
        terminal = rec.cname_chain_terminal or (rec.cname[0] if rec.cname else "?")
        rec.manual_test = (
            f"curl -i 'https://{rec.host}/' — check for '{rec.takeover_service}' "
            f"unclaimed page; CNAME → {terminal}"
        )
    elif rec.email_auth_spf or rec.email_auth_dmarc:
        rec.manual_test = (
            f"dig TXT {rec.host} +short  — verify SPF/DMARC alignment; "
            f"test email spoofing via SMTP"
        )
    elif rec.caa:
        rec.manual_test = f"dig CAA {rec.host}  — verify CAA allows your testing CA"
    elif rec.cname_chain_depth > 3:
        rec.manual_test = (
            f"dig CNAME {rec.host} +short  — chain depth {rec.cname_chain_depth}, "
            f"terminal {rec.cname_chain_terminal}"
        )
    else:
        rec.manual_test = f"dig ANY {rec.host}  — manual review"

    # Nuclei tags
    tags = []
    if rec.takeover:
        tags.extend(["takeover", "dns-takeover", "subdomain-takeover"])
    if rec.wildcard:
        tags.append("wildcard-dns")
    if is_root and rec.mx:
        tags.append("email-service")
    if is_root and not rec.email_auth_spf:
        tags.append("email-spoofing")
    if not tags:
        tags.append("dns")
    rec.nuclei_tags = tags


# ═════════════════════════════════════════════════════════════════════════
#  PER-HOST HEURISTIC TRIAGE (v3.0)
# ═════════════════════════════════════════════════════════════════════════

def _heuristic_host_triage(host: str, records: list[DNSRecord]) -> dict:
    if not records:
        return {
            "summary": f"No DNS records for {host}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "chains": [],
            "false_positive_likelihood": "n/a",
            "suggested_manual_tests": [],
            "next_actions": ["No action required"],
            "source": "heuristic",
        }

    takeover_count = sum(1 for r in records if r.takeover)
    wildcard_count = sum(1 for r in records if r.wildcard)
    no_spf_count = sum(1 for r in records if "no_spf_with_mx" in r.reasons)
    no_dmarc_count = sum(1 for r in records if "no_dmarc_with_mx" in r.reasons)

    if takeover_count > 0:      host_risk = "CRITICAL"
    elif no_spf_count > 0:      host_risk = "HIGH"
    elif no_dmarc_count > 0:    host_risk = "MEDIUM"
    elif wildcard_count > 0:    host_risk = "MEDIUM"
    else:                       host_risk = "LOW"

    # Top priorities — takeover > email-auth > rest
    ranked = sorted(
        records,
        key=lambda r: (
            0 if r.takeover else
            1 if "no_spf_with_mx" in r.reasons else
            2 if "no_dmarc_with_mx" in r.reasons else
            3,
            -r.confidence,
        )
    )[:5]

    top_priorities = []
    for i, r in enumerate(ranked, 1):
        reason_parts = []
        if r.takeover:
            reason_parts.append(f"takeover:{r.takeover_service}")
        if r.email_auth_spf:
            reason_parts.append("has_spf")
        elif "no_spf_with_mx" in r.reasons:
            reason_parts.append("no_spf")
        if r.email_auth_dmarc:
            reason_parts.append("has_dmarc")
        elif "no_dmarc_with_mx" in r.reasons:
            reason_parts.append("no_dmarc")
        reason_parts.append(f"conf={r.confidence}")

        top_priorities.append({
            "rank": i,
            "finding": f"{r.host} — {r.status} ({len(r.a)} A, {len(r.aaaa)} AAAA)",
            "reason": " · ".join(reason_parts),
            "test_idea": r.manual_test,
        })

    # Chains
    chains = []
    if takeover_count > 0:
        chains.append(f"{takeover_count} takeover candidate(s) — verify dangling")
    if no_spf_count + no_dmarc_count > 0:
        chains.append(f"{no_spf_count + no_dmarc_count} email-auth gap(s) — "
                       f"test spoofing via SMTP relay")
    if wildcard_count >= 2:
        chains.append(f"{wildcard_count} wildcard(s) — mass subdomain risk")

    # Tests
    tests = [r.manual_test for r in ranked if r.manual_test][:5]

    # Next actions
    next_actions: list[str] = []
    if takeover_count > 0:
        next_actions.append(
            f"IMMEDIATE: verify {takeover_count} takeover candidate(s) — "
            f"check for '{ranked[0].takeover_service}' unclaimed page")
    if no_spf_count > 0:
        next_actions.append("Test email spoofing: send via SMTP relay without SPF check")
    if no_dmarc_count > 0:
        next_actions.append("Test DMARC enforcement: send spoofed 'From' header")
    if wildcard_count > 0:
        next_actions.append(
            f"Investigate {wildcard_count} wildcard(s) — can trigger mass rate-limit")
    if not next_actions:
        next_actions.append("Manual review of DNS records in dig")

    # Summary
    summary = (
        f"{len(records)} DNS record(s) for {host}. "
        f"Takeover={takeover_count} Wildcard={wildcard_count} "
        f"NoSPF={no_spf_count} NoDMARC={no_dmarc_count}."
    )

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "chains": chains,
        "false_positive_likelihood": (
            "high" if wildcard_count >= len(records) // 2
            else "medium" if wildcard_count > 0
            else "low"
        ),
        "suggested_manual_tests": tests,
        "next_actions": next_actions,
        "source": "heuristic",
    }


# ═════════════════════════════════════════════════════════════════════════
#  AI TRIAGE (mirrors cors_check v3.0)
# ═════════════════════════════════════════════════════════════════════════

AI_DNS_SYSTEM = (
    "You are an expert DNS-triage analyst. Analyze findings from one "
    "root domain's DNS records. Reference actual hostnames, CNAMEs, TXT "
    "records. Never suggest running exploits. Return STRICT JSON only."
)


def _validate_ai_triage(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("summary", "host_risk", "top_priorities",
                "real_vs_noise", "suggested_manual_tests", "next_actions"):
        if key not in data:
            return False
    if not isinstance(data.get("top_priorities"), list): return False
    if not isinstance(data.get("suggested_manual_tests"), list): return False
    if not isinstance(data.get("next_actions"), list): return False
    if data.get("host_risk") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                       "INFO", "UNKNOWN", ""):
        return False
    return True


def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "dns_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: str, records: list[DNSRecord], model: str = "") -> str:
    parts = [host.lower(), f"model={model or 'unknown'}",
             f"prompt={AI_PROMPT_VERSION}"]
    for r in sorted(records, key=lambda x: x.host):
        parts.append(f"{r.host}|{r.status}|{','.join(r.reasons)}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
    if ttl_hours <= 0:
        return None
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        if not p.exists():
            return None
        age = (time.time() - p.stat().st_mtime) / 3600
        if age > ttl_hours:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ai_cache_put(outdir: Path, key: str, data: dict) -> None:
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


_BUDGET_LOCK = threading.Lock()


def _current_spend() -> float:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return float(tracker.estimate_cost() or 0)
    except Exception:
        pass
    return 0.0


def _ai_cost_guard(would_add: float, budget_usd: float) -> bool:
    if budget_usd <= 0 or would_add <= 0:
        return True
    with _BUDGET_LOCK:
        return (_current_spend() + would_add) <= budget_usd


def _build_top_records_block(records: list[DNSRecord], limit: int = 30) -> str:
    top = sorted(records, key=lambda r: (
        0 if r.takeover else
        1 if "no_spf_with_mx" in r.reasons else
        2 if "no_dmarc_with_mx" in r.reasons else
        3,
        -r.confidence,
    ))[:limit]
    lines = []
    for r in top:
        bits = [f"[{r.confidence:>3}]", r.host]
        if r.takeover:               bits.append(f"TAKEOVER:{r.takeover_service}")
        if r.cname:                  bits.append(f"→{r.cname[0][:40]}")
        if r.email_auth_spf:         bits.append("SPF")
        if r.email_auth_dmarc:       bits.append("DMARC")
        if r.email_auth_dkim:        bits.append(f"DKIM({len(r.email_auth_dkim)})")
        if r.cname_chain_depth > 3:  bits.append(f"chain:{r.cname_chain_depth}")
        if r.wildcard:               bits.append("wildcard")
        lines.append("  " + " ".join(bits))
    return "\n".join(lines) if lines else "  (no records)"


def _ai_triage_host(host_result: HostResult, outdir: Path, *,
                     use_cache: bool = True,
                     cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
                     budget_usd: float = 0.0,
                     heuristic_hint: Optional[dict] = None) -> Optional[dict]:
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.records) < AI_MIN_RECORDS_PER_HOST:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(host_result.host, host_result.records,
                                model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        return None

    records = host_result.records
    takeover_count = sum(1 for r in records if r.takeover)
    wildcard_count = sum(1 for r in records if r.wildcard)
    no_spf_count = sum(1 for r in records if "no_spf_with_mx" in r.reasons)

    hint_block = ""
    if heuristic_hint and heuristic_hint.get("summary"):
        hint_block = (
            "\n\nHeuristic baseline (HINT ONLY):\n"
            f"  Summary: {heuristic_hint.get('summary', '')[:300]}\n"
        )

    prompt = f"""Analyze DNS findings for root domain: {host_result.host}

Stats:
  Total records:      {len(records)}
  Takeover candidates:{takeover_count}
  Wildcards:          {wildcard_count}
  Missing SPF:        {no_spf_count}

Top records:
{_build_top_records_block(records)}{hint_block}
"""

    def _call(text: str) -> Optional[str]:
        try:
            return ai_fn(text, system=AI_DNS_SYSTEM)
        except Exception as e:
            _safe_log("warn", f"  AI triage failed for {host_result.host}: "
                                f"{type(e).__name__}: {e}")
            return None

    text = _call(prompt)
    if not text:
        return None

    def _strip_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        return s

    def _try_parse(raw: str) -> Optional[dict]:
        try:
            d = json.loads(_strip_fences(raw))
            return d if _validate_ai_triage(d) else None
        except Exception:
            return None

    data = _try_parse(text)

    if data is None:
        correction = (
            "Your previous response could not be parsed as valid JSON. "
            "Return ONLY the JSON object, no fences. Required keys: "
            "summary, host_risk, top_priorities, real_vs_noise, "
            "suggested_manual_tests, next_actions.\n\n"
            f"Previous response:\n{text[:600]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {
                    "summary": text2[:1500], "host_risk": "UNKNOWN",
                    "top_priorities": [], "real_vs_noise": "unknown",
                    "suggested_manual_tests": [], "next_actions": [],
                    "parse_error": True,
                }
        else:
            return None

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"dns_ai_{safe}.md"
    try:
        md = (f"# Urðr · DNS AI Triage — {host_result.host}\n\n"
              f"**Records:** {len(records)}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("host_risk"):
            md += f"**Host risk:** {data['host_risk']}\n\n"
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
        if data.get("suggested_manual_tests"):
            md += "## Suggested Manual Tests\n\n"
            for t in data["suggested_manual_tests"]:
                md += f"- {t}\n"
            md += "\n"
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    _safe_log("ok", f"  AI triage saved: {md_path.name}")

    return {
        "path":             str(md_path),
        "summary":          data.get("summary", ""),
        "host_risk":        data.get("host_risk", ""),
        "top_priorities":   data.get("top_priorities", [])[:10],
        "real_vs_noise":    data.get("real_vs_noise", ""),
        "suggested_manual_tests": data.get("suggested_manual_tests", [])[:10],
        "next_actions":     data.get("next_actions", [])[:10],
        "cost_estimate":    round(_current_spend(), 6),
        "source": "ai",
    }


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, records: list[DNSRecord]) -> None:
    if not records:
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
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready")
        return
    try:
        payloads = [r.to_dict() for r in records]
        result = DB.upsert_dns_records(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} DNS record(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════

def resolve_dns(
    subs_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    # v1 backward-compat
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    max_input: int = MAX_INPUT,
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    no_wildcard_cache: bool = False,
    no_ai: bool = False,
    ai_max_hosts: int = AI_DEFAULT_MAX_HOSTS,
    ai_max_cost_usd: float = 0.0,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
    dnsx_timeout: int = DNSX_TIMEOUT,
) -> Path:
    """v3.0: full DNS resolution with wildcard cache, email-auth, AI triage."""
    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    # ── Settings ────────────────────────────────────────────────────────────
    settings = _dns_settings()
    eff_threads = threads if threads is not None else settings["threads"]
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    if not isinstance(eff_threads, int) or eff_threads < 1:
        eff_threads = settings["threads"]
    if not isinstance(eff_rate, int) or eff_rate < 0:
        eff_rate = settings["rate_limit"]

    # ── Inputs ──────────────────────────────────────────────────────────────
    subs = _load_subdomains(subs_file)
    total_input = len(subs)
    if len(subs) > max_input:
        warnings.append(f"input-capped: {total_input} → {max_input}")
        log.warning(f"  Capping at {max_input} hosts (input had {total_input})")
        subs = subs[:max_input]

    roots = _load_roots(wildcard_file)

    # v3.0: derive roots from subs for email-auth enrichment even without wildcard_file
    derived_roots: set[str] = set(roots)
    for sub in subs:
        r = _base_host(sub)
        if r and r != sub:  # only if sub is actually a subdomain
            derived_roots.add(r)
    all_roots = sorted(derived_roots)

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "dns_work"
    workdir.mkdir(parents=True, exist_ok=True)

    ai_active = _ai_enabled() and not no_ai and not dry_run

    if not quiet:
        log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
        log.info(f"  Roots  : {len(roots)} explicit + {len(all_roots) - len(roots)} derived "
                 f"= {len(all_roots)} total")
        log.info(f"  Config : threads={eff_threads}  rate_limit={eff_rate}/s  "
                 f"timeout={dnsx_timeout}s")
        log.info(f"           source=MODULE_RATE_LIMITS['dns_enum']")
        log.info(f"           note: DNS queries go to public recursors, "
                 f"not the target")
        if dry_run:
            log.info("  Mode   : DRY-RUN (no network calls)")
        if ai_active:
            budget_str = (f"${ai_max_cost_usd:.2f}"
                           if ai_max_cost_usd > 0 else "unlimited")
            log.info(f"  AI     : enabled  (budget={budget_str}, "
                     f"max_hosts={ai_max_hosts}, cache={ai_cache_ttl_hours}h)")
        else:
            log.info("  AI     : disabled — heuristic triage active")
        if not no_wildcard_cache:
            cache = _load_wildcard_cache()
            if cache:
                log.info(f"  Cache  : {len(cache)} wildcard entries "
                         f"(TTL {WILDCARD_CACHE_TTL_HOURS}h)")
        log.info("")

    if not subs:
        log.warning("  No subdomains to resolve — writing empty report")
        return _write_empty_report(outdir, subs_file, start,
                                     total_input=total_input, scan_id=scan_id)

    if dry_run:
        log.info(f"  DRY-RUN — would resolve {len(subs)} subdomain(s) + "
                 f"{len(all_roots)} DMARC probe(s) via dnsx")
        for h in subs[:10]:
            log.info(f"    {h}")
        if len(subs) > 10:
            log.info(f"    … and {len(subs) - 10} more")
        return _write_empty_report(outdir, subs_file, start,
                                     total_input=total_input, scan_id=scan_id,
                                     dry_run=True)

    # ── SIGINT/SIGTERM handler ──────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — finishing current phase, writing report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    try:
        # ── Wildcard detection ──────────────────────────────────────────────
        _progress("stage_start", {"stage": "wildcard", "roots": len(all_roots)})
        wildcards = _detect_wildcards_parallel(
            all_roots, use_cache=not no_wildcard_cache,
        ) if all_roots else {}
        _progress("stage_end", {"stage": "wildcard",
                                  "detected": sum(1 for w in wildcards.values() if w.detected)})

        if _sigint["flag"]:
            warnings.append("run-interrupted: SIGINT during wildcard phase")

        # ── Enriched input — subs + roots + _dmarc probes ───────────────────
        enriched = _build_enriched_input(subs, all_roots)

        # ── Run dnsx ────────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "dnsx", "hosts": len(enriched)})
        log.info("")
        log.info(f"  Resolving (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA)...")
        dnsx_output = _run_dnsx(enriched, eff_threads, eff_rate, workdir,
                                  timeout=dnsx_timeout)

        if dnsx_output:
            records = _parse_dnsx_jsonl(dnsx_output)
            resolver_used = "dnsx"
        else:
            records = _resolve_fallback(enriched)
            resolver_used = "socket-fallback"

        for host in enriched:
            if host not in records:
                records[host] = DNSRecord(host=host, status="NXDOMAIN")

        resolved_count = sum(1 for r in records.values() if r.resolves)
        log.info(f"  Resolved: {resolved_count} / {len(records)} host(s)")
        _progress("stage_end", {"stage": "dnsx", "resolved": resolved_count})

        if _sigint["flag"]:
            warnings.append("run-interrupted: SIGINT during dnsx phase")

        # ── Analysis ────────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "analysis"})
        now = datetime.now(timezone.utc).isoformat()
        for rec in records.values():
            _match_wildcard(rec, wildcards, all_roots)
            _detect_takeover(rec)
            rec.services_found = _extract_services_from_txt(rec)
            _extract_email_auth(rec, records)
            _compute_cname_chain_depth(rec, records)
            rec.first_seen = now
            _decorate_record(rec)

        wildcard_count = sum(1 for r in records.values() if r.wildcard)
        takeover_count = sum(1 for r in records.values() if r.takeover)
        cluster_map    = _cluster_by_ip(records)
        services_seen: set[str] = set()
        for r in records.values():
            services_seen.update(r.services_found)

        _progress("stage_end", {"stage": "analysis"})

        # ── Filtered inventories ────────────────────────────────────────────
        resolved_all   = sorted(h for h, r in records.items()
                                  if r.resolves and not _is_dmarc_probe(h)
                                  and not _is_dkim_probe(h))
        resolved_clean = sorted(h for h, r in records.items()
                                  if r.resolves and not r.wildcard
                                  and not _is_dmarc_probe(h)
                                  and not _is_dkim_probe(h))
        takeover_hosts = sorted(h for h, r in records.items() if r.takeover)

        (outdir / "dns_resolved.txt").write_text(
            "\n".join(resolved_all) + ("\n" if resolved_all else ""))
        (outdir / "dns_wildcard_filtered.txt").write_text(
            "\n".join(resolved_clean) + ("\n" if resolved_clean else ""))
        (outdir / "dns_takeover_candidates.txt").write_text(
            "\n".join(takeover_hosts) + ("\n" if takeover_hosts else ""))

        # ── Per-host triage ─────────────────────────────────────────────────
        _progress("stage_start", {"stage": "triage"})
        by_host: dict[str, list[DNSRecord]] = {}
        for r in records.values():
            root = r.root or _base_host(r.host) or r.host
            by_host.setdefault(root, []).append(r)

        host_results: list[HostResult] = []
        ai_hosts_done = 0
        ai_budget_exhausted = False

        for host, host_records in sorted(by_host.items()):
            hr = HostResult(host=host, records=host_records)
            heuristic = _heuristic_host_triage(host, host_records)

            ai_result: Optional[dict] = None
            if (ai_active and ai_hosts_done < ai_max_hosts
                    and not ai_budget_exhausted
                    and heuristic.get("host_risk") in ("CRITICAL", "HIGH", "MEDIUM")):
                ai_result = _ai_triage_host(
                    hr, outdir,
                    use_cache=True,
                    cache_ttl_hours=ai_cache_ttl_hours,
                    budget_usd=ai_max_cost_usd,
                    heuristic_hint=heuristic,
                )
                if ai_result:
                    ai_hosts_done += 1
                elif ai_max_cost_usd > 0 and _current_spend() >= ai_max_cost_usd:
                    ai_budget_exhausted = True

            if ai_result:
                hr.triage = ai_result
                hr.triage_source = ai_result.get("source", "ai")
            else:
                hr.triage = heuristic
                hr.triage_source = "heuristic"

            host_results.append(hr)

        if ai_active and ai_hosts_done > 0:
            log.info(f"  AI triaged: {ai_hosts_done} root(s)")
            if ai_budget_exhausted:
                warnings.append(f"ai-budget-exhausted: ${ai_max_cost_usd:.2f}")
        _progress("stage_end", {"stage": "triage"})

        # ── Report ──────────────────────────────────────────────────────────
        return _write_report(
            outdir, subs_file, wildcard_file, start, total_input,
            records, host_results, wildcards, cluster_map, services_seen,
            resolved_all, resolved_clean, takeover_hosts,
            resolver_used=resolver_used, eff_threads=eff_threads,
            eff_rate=eff_rate, ai_active=ai_active,
            warnings=warnings, dry_run=dry_run, scan_id=scan_id,
        )

    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════
#  REPORT WRITER
# ═════════════════════════════════════════════════════════════════════════

def _write_report(
    outdir: Path, subs_file: Path, wildcard_file: Optional[Path],
    start: float, total_input: int, records: dict[str, DNSRecord],
    host_results: list[HostResult], wildcards: dict[str, WildcardInfo],
    cluster_map: dict[str, list[str]], services_seen: set[str],
    resolved_all: list[str], resolved_clean: list[str],
    takeover_hosts: list[str], *,
    resolver_used: str, eff_threads: int, eff_rate: int,
    ai_active: bool, warnings: list[str], dry_run: bool,
    scan_id: Optional[int],
) -> Path:
    elapsed = time.monotonic() - start

    # Sort records: takeover > no_spf > wildcard > resolved > rest
    record_list = sorted(records.values(), key=lambda r: (
        0 if r.takeover else
        1 if "no_spf_with_mx" in r.reasons else
        2 if not r.resolves else
        3 if r.wildcard else 4,
        r.host,
    ))

    by_status: dict[str, int] = {}
    by_root:   dict[str, int] = {}
    for r in record_list:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        root = r.root or _base_host(r.host) or r.host
        by_root[root] = by_root.get(root, 0) + 1

    ai_triaged = sum(1 for h in host_results if h.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for h in host_results if h.triage_source == "heuristic")

    report = {
        "schema_version": 3,
        "producer": "dns_resolve.py v3.0.0 'URÐR'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(subs_file),
        "wildcard_file": str(wildcard_file) if wildcard_file else None,
        "total_input": total_input,
        "config": {
            "threads":                eff_threads,
            "rate_limit":             eff_rate,
            "resolver":               resolver_used,
            "wildcard_min_agreement": WILDCARD_MIN_AGREEMENT,
            "wildcard_probes":        WILDCARD_PROBES_PER_ROOT,
            "wildcard_cache_ttl_h":   WILDCARD_CACHE_TTL_HOURS,
            "max_cname_chain_depth":  MAX_CNAME_CHAIN_DEPTH,
            "headers_applied":        False,
            "note":                   "DNS queries go to public recursors, "
                                      "not the target — platform headers and "
                                      "auth cookies not applicable",
        },
        "warnings": warnings,
        "totals": {
            "input":              total_input,
            "resolved":           len(resolved_all),
            "resolved_clean":     len(resolved_clean),
            "wildcard_matches":   sum(1 for r in record_list if r.wildcard),
            "takeover_candidates": len(takeover_hosts),
            "shared_ip_clusters": len(cluster_map),
            "services_detected":  len(services_seen),
            "ai_triaged":         ai_triaged,
            "heuristic_triaged":  heuristic_triaged,
        },
        "summary": {
            "by_status": by_status,
            "by_root":   dict(sorted(by_root.items(), key=lambda kv: -kv[1])[:30]),
        },
        "services_detected": sorted(services_seen),
        "wildcards": [w.to_dict() for w in wildcards.values()],
        "ip_clusters": {
            ip: hosts for ip, hosts in sorted(
                cluster_map.items(), key=lambda kv: -len(kv[1])
            )[:MAX_CLUSTERS_IN_REPORT]
        },
        "hosts": [
            {
                "host":          h.host,
                "records":       [r.to_dict() for r in h.records],
                "triage":        h.triage,
                "triage_source": h.triage_source,
            }
            for h in host_results
        ],
        "records": [r.to_dict() for r in record_list[:DEFAULT_MAX_FINDINGS]],
    }

    json_path = outdir / "dns_resolve.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    # v3.1: isolate digest writing. The 2026-11-12 crash was a log.ok() call
    # inside _write_digest() that killed the stage AFTER the report was
    # written successfully. This wrapper guarantees the stage completes even
    # if the digest formatter has a bug.
    try:
        _write_digest(outdir, record_list)
    except Exception as e:
        warnings.append(f"digest-write-failed: {type(e).__name__}: {e}")
        _safe_log("error", f"  Digest write failed (report OK): {e}")

    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, record_list)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # v3.1: isolate summary printing for the same reason.
    try:
        _print_summary(outdir, report, record_list, wildcards, cluster_map,
                        services_seen, takeover_hosts, elapsed)
    except Exception as e:
        _safe_log("error", f"  Summary print failed (report OK): {e}")

    return json_path


def _write_digest(outdir: Path, records: list[DNSRecord]) -> None:
    if not records:
        (outdir / "dns_findings_digest.md").write_text(
            "# DNS Findings Digest\n\nNo records.\n", encoding="utf-8")
        return

    # Top findings = takeover, no_spf, long_chain, others
    top = [r for r in records
           if r.takeover or "no_spf_with_mx" in r.reasons or r.cname_chain_depth > 3][:50]
    if not top:
        top = records[:50]

    lines = [
        "# DNS Findings Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Total records:** {len(records)}  \n",
        f"**Flagged:** {len(top)}  \n\n",
        "## Top findings\n\n",
        "| Conf | Host | Status | A | CNAME | Takeover | Email Auth | Manual Test |\n",
        "|------|------|--------|---|-------|----------|------------|-------------|\n",
    ]
    for r in top:
        host = r.host.replace("|", "\\|")[:40]
        a_str = str(len(r.a)) + "A+" + str(len(r.aaaa)) + "AAAA"
        cname = (r.cname[0][:30] if r.cname else "—").replace("|", "\\|")
        takeover = f"{r.takeover_service}" if r.takeover else "—"
        email = []
        if r.email_auth_spf: email.append("SPF")
        if r.email_auth_dmarc: email.append("DMARC")
        if r.email_auth_dkim: email.append(f"DKIM({len(r.email_auth_dkim)})")
        email_str = ",".join(email) if email else "—"
        test = (r.manual_test or "Review").replace("|", "\\|")[:70]
        lines.append(
            f"| {r.confidence:>3} | {host} | {r.status} | {a_str} | "
            f"{cname} | {takeover} | {email_str} | {test} |\n"
        )
    (outdir / "dns_findings_digest.md").write_text(
        "".join(lines), encoding="utf-8")
    _safe_log("ok", f"  Digest: dns_findings_digest.md ({len(top)} findings)")


def _print_summary(
    outdir: Path, report: dict, records: list[DNSRecord],
    wildcards: dict[str, WildcardInfo], cluster_map: dict[str, list[str]],
    services_seen: set[str], takeover_hosts: list[str], elapsed: float,
) -> None:
    log.info("")
    log.info("── ᛊ  Summary ──")
    totals = report["totals"]
    log.info(f"  Resolved         : {totals['resolved']} / {totals['input']}")
    log.info(f"  Clean (non-wild) : {totals['resolved_clean']}")
    log.info(f"  Wildcard matches : {totals['wildcard_matches']}")
    log.info(f"  Takeover cand.   : {totals['takeover_candidates']}")
    log.info(f"  Shared IPs       : {totals['shared_ip_clusters']}")
    log.info(f"  Services detected: {totals['services_detected']}")
    if report["ai_enabled"]:
        log.info(f"  AI triage        : {totals['ai_triaged']} root(s) AI · "
                 f"{totals['heuristic_triaged']} heuristic")

    if services_seen:
        log.info("")
        log.info(f"  Services via TXT ({len(services_seen)}):")
        log.info("    " + " · ".join(sorted(services_seen)))

    # Email auth gaps
    no_spf = [r.host for r in records if "no_spf_with_mx" in r.reasons]
    no_dmarc = [r.host for r in records if "no_dmarc_with_mx" in r.reasons]
    if no_spf:
        _safe_log("warn", f"  Missing SPF ({len(no_spf)}): {', '.join(no_spf[:5])}")
    if no_dmarc:
        _safe_log("warn", f"  Missing DMARC ({len(no_dmarc)}): {', '.join(no_dmarc[:5])}")

    if takeover_hosts:
        log.info("")
        log.info(f"  Takeover candidates ({len(takeover_hosts)}):")
        for h in takeover_hosts[:10]:
            rec = next((r for r in records if r.host == h), None)
            if rec:
                cname = rec.cname[0] if rec.cname else "?"
                log.info(f"    {h:<40} → {cname}  [{rec.takeover_service}]")

    if cluster_map:
        top_clusters = sorted(cluster_map.items(), key=lambda kv: -len(kv[1]))[:5]
        log.info("")
        log.info(f"  Top shared IP clusters:")
        for ip, hosts in top_clusters:
            provider = _looks_like_cloud(hosts[0]) if hosts else ""
            log.info(f"    {ip:<18} {len(hosts):>4} host(s)"
                     + (f"  [{provider}]" if provider else "")
                     + f"   e.g. {hosts[0]}")

    log.info("")
    log.info("  Outputs:")
    log.info(f"    dns_resolved.txt")
    log.info(f"    dns_wildcard_filtered.txt   (feed to httpx)")
    log.info(f"    dns_takeover_candidates.txt")
    log.info(f"    dns_resolve.json")
    log.info(f"    dns_findings_digest.md")
    if report["ai_enabled"] and totals["ai_triaged"] > 0:
        log.info(f"    dns_ai_<host>.md")

    if report.get("warnings"):
        log.info("")
        log.info("  Warnings:")
        for w in report["warnings"][:8]:
            _safe_log("warn", f"    {w}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")


def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
    total_input: int = 0, scan_id: Optional[int] = None,
    dry_run: bool = False,
) -> Path:
    report = {
        "schema_version": 3,
        "producer": "dns_resolve.py v3.0.0 'URÐR'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "wildcard_file": None,
        "total_input": total_input,
        "config": {},
        "warnings": [],
        "totals": {
            "input": total_input, "resolved": 0, "resolved_clean": 0,
            "wildcard_matches": 0, "takeover_candidates": 0,
            "shared_ip_clusters": 0, "services_detected": 0,
            "ai_triaged": 0, "heuristic_triaged": 0,
        },
        "summary": {"by_status": {}, "by_root": {}},
        "services_detected": [],
        "wildcards": [],
        "ip_clusters": {},
        "hosts": [],
        "records": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / "dns_resolve.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (outdir / "dns_resolved.txt").write_text("")
    (outdir / "dns_wildcard_filtered.txt").write_text("")
    (outdir / "dns_takeover_candidates.txt").write_text("")
    (outdir / "dns_findings_digest.md").write_text(
        "# DNS Findings Digest\n\nNo records.\n", encoding="utf-8")
    return path


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  dns_resolve.py v3.0 'URÐR' — selftest")
    print("═" * 70)

    def _mk(host: str = "api.example.com", status: str = "NOERROR",
            a: Optional[list] = None, cname: Optional[list] = None,
            txt: Optional[list] = None, mx: Optional[list] = None,
            caa: Optional[list] = None) -> DNSRecord:
        return DNSRecord(
            host=host, status=status,
            a=a or ["1.2.3.4"],
            cname=cname or [],
            txt=txt or [],
            mx=mx or [],
            caa=caa or [],
            first_seen="2026-01-01T00:00:00Z",
        )

    def _settings_reads_canonical_key() -> bool:
        s = _dns_settings()
        # config.py: {"dns_enum": {"rps": 5, "concurrency": 5}}
        return s["threads"] == 5 and s["rate_limit"] == 5

    def _settings_reads_rps_not_rate_limit() -> bool:
        s = _dns_settings()
        return s["rate_limit"] != 20

    def _input_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example.com\r\n"
                     b"b.example.com  # inline\r\n"
                     b"\r\n"
                     b"# full-line\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_subdomains(tmp)
            return loaded == ["a.example.com", "b.example.com"]
        finally:
            tmp.unlink(missing_ok=True)

    def _base_host_simple() -> bool:
        return _base_host("api.example.com") == "example.com"

    def _base_host_co_uk() -> bool:
        return _base_host("api.example.co.uk") == "example.co.uk"

    def _base_host_apex() -> bool:
        return _base_host("example.com") == "example.com"

    def _is_dmarc_probe_yes() -> bool:
        return _is_dmarc_probe("_dmarc.example.com")

    def _is_dmarc_probe_no() -> bool:
        return not _is_dmarc_probe("api.example.com")

    def _is_dkim_probe_yes() -> bool:
        return _is_dkim_probe("default._domainkey.example.com")

    def _looks_like_cloud_aws() -> bool:
        return _looks_like_cloud("ec2-1-2-3-4.amazonaws.com") == "AWS"

    def _looks_like_cloud_gcp() -> bool:
        return _looks_like_cloud("googleusercontent.com") == "GCP"

    def _looks_like_cloud_none() -> bool:
        return _looks_like_cloud("random.example") == ""

    def _match_root_works() -> bool:
        return _match_root("api.example.com", ["example.com"]) == "example.com"

    def _takeover_s3() -> bool:
        r = _mk(cname=["bucket.s3.amazonaws.com"])
        _detect_takeover(r)
        return r.takeover and "S3" in r.takeover_service

    def _takeover_heroku() -> bool:
        r = _mk(cname=["myapp.herokuapp.com"])
        _detect_takeover(r)
        return r.takeover and "Heroku" in r.takeover_service

    def _takeover_no_match() -> bool:
        r = _mk(cname=["legit.example.com"])
        _detect_takeover(r)
        return not r.takeover

    def _tx_services_stripe() -> bool:
        r = _mk(txt=["stripe-verification=abc123"])
        services = _extract_services_from_txt(r)
        return "Stripe" in services

    def _tx_services_google() -> bool:
        r = _mk(txt=["google-site-verification=xyz"])
        services = _extract_services_from_txt(r)
        return "Google" in services

    def _tx_services_spf_google() -> bool:
        r = _mk(txt=["v=spf1 include:_spf.google.com ~all"])
        services = _extract_services_from_txt(r)
        return any("Google Workspace" in s for s in services)

    def _email_auth_spf() -> bool:
        r = _mk(txt=["v=spf1 include:_spf.google.com ~all"])
        _extract_email_auth(r, {r.host: r})
        return bool(r.email_auth_spf)

    def _email_auth_dmarc() -> bool:
        root = _mk(host="example.com", txt=[])
        dmarc = _mk(host="_dmarc.example.com",
                     txt=["v=DMARC1; p=reject"])
        all_recs = {root.host: root, dmarc.host: dmarc}
        _extract_email_auth(root, all_recs)
        return bool(root.email_auth_dmarc)

    def _email_auth_dkim() -> bool:
        r = _mk(host="default._domainkey.example.com",
                txt=["v=DKIM1; k=rsa; p=abc"])
        _extract_email_auth(r, {r.host: r})
        return "default" in r.email_auth_dkim

    def _cname_chain_depth_short() -> bool:
        r1 = _mk(host="a.example.com", cname=["b.example.com"])
        r2 = _mk(host="b.example.com", cname=[])
        _compute_cname_chain_depth(r1, {r1.host: r1, r2.host: r2})
        return r1.cname_chain_depth == 1

    def _cname_chain_depth_long() -> bool:
        recs = {}
        for i in range(5):
            host = f"h{i}.example.com"
            cname_next = [f"h{i+1}.example.com"] if i < 4 else []
            recs[host] = _mk(host=host, cname=cname_next)
        _compute_cname_chain_depth(recs["h0.example.com"], recs)
        return recs["h0.example.com"].cname_chain_depth == 4

    def _cluster_by_ip() -> bool:
        r1 = _mk(host="a.example.com", a=["1.1.1.1"])
        r2 = _mk(host="b.example.com", a=["1.1.1.1"])
        clusters = _cluster_by_ip({"a": r1, "b": r2})
        return "1.1.1.1" in clusters and len(clusters["1.1.1.1"]) == 2

    def _cluster_by_ipv6() -> bool:
        r1 = _mk(host="a.example.com", a=["::1"])
        r2 = _mk(host="b.example.com", a=["::1"])
        clusters = _cluster_by_ip({"a": r1, "b": r2})
        return "::1" in clusters

    def _decorate_takeover_confidence() -> bool:
        r = _mk(cname=["bucket.s3.amazonaws.com"])
        _detect_takeover(r)
        r.cname_chain_terminal = "bucket.s3.amazonaws.com"
        _decorate_record(r)
        return r.confidence >= 70

    def _decorate_nuclei_tags() -> bool:
        r = _mk(cname=["myapp.herokuapp.com"])
        _detect_takeover(r)
        _decorate_record(r)
        return "takeover" in r.nuclei_tags

    def _decorate_manual_test() -> bool:
        r = _mk()
        _decorate_record(r)
        return bool(r.manual_test) and "dig" in r.manual_test.lower()

    def _heuristic_empty() -> bool:
        return _heuristic_host_triage("x.com", [])["host_risk"] == "INFO"

    def _heuristic_takeover_critical() -> bool:
        r = _mk(cname=["app.herokuapp.com"])
        _detect_takeover(r)
        _decorate_record(r)
        return _heuristic_host_triage("x.com", [r])["host_risk"] == "CRITICAL"

    def _heuristic_no_spf_high() -> bool:
        r = _mk(host="x.com", txt=[], mx=["mx.x.com"])
        r.reasons = ["no_spf_with_mx"]
        _decorate_record(r)
        return _heuristic_host_triage("x.com", [r])["host_risk"] in ("HIGH", "CRITICAL")

    def _ai_cache_stable() -> bool:
        r = _mk()
        k1 = _ai_cache_key("x.com", [r], model="m")
        k2 = _ai_cache_key("x.com", [r], model="m")
        return k1 == k2

    def _ai_cache_model_busts() -> bool:
        r = _mk()
        return (_ai_cache_key("x.com", [r], model="m1")
                != _ai_cache_key("x.com", [r], model="m2"))

    def _validate_ai_ok() -> bool:
        return _validate_ai_triage({
            "summary": "x", "host_risk": "HIGH", "top_priorities": [],
            "real_vs_noise": "x", "suggested_manual_tests": [],
            "next_actions": [],
        })

    def _validate_ai_reject() -> bool:
        return not _validate_ai_triage({"summary": "x"})

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(resolve_dns)
        return set(required).issubset(set(sig.parameters))

    def _build_enriched_dmarc() -> bool:
        enriched = _build_enriched_input(["api.example.com"], ["example.com"])
        return "_dmarc.example.com" in enriched

    def _build_enriched_dedup() -> bool:
        enriched = _build_enriched_input(
            ["example.com", "api.example.com"], ["example.com"])
        return enriched.count("example.com") == 1

    # v3.1: crash-prevention test helpers
    def _test_log_is_not_stdlib() -> bool:
        """The 2026-11-12 crash: stdlib Logger lacks .ok/.warn."""
        return hasattr(log, "ok") and (
            hasattr(log, "warn") or hasattr(log, "warning"))

    def _test_safe_log_never_raises() -> bool:
        try:
            _safe_log("info", "test")
            _safe_log("warn", "test")
            _safe_log("error", "test")
            _safe_log("ok", "test")
            return True
        except Exception:
            return False

    def _test_safe_log_weird_level() -> bool:
        try:
            _safe_log("nonsense_level", "test")
            return True
        except Exception:
            return False

    def _test_safe_log_empty_msg() -> bool:
        try:
            _safe_log("info", "")
            return True
        except Exception:
            return False

    def _test_log_locked_no_raise() -> bool:
        try:
            _log_locked("warn", "test warn")
            _log_locked("ok", "test ok")
            return True
        except Exception:
            return False

    def _test_digest_empty() -> bool:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                _write_digest(Path(tmp), [])
            return True
        except Exception:
            return False

    def _test_summary_empty() -> bool:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                report = {
                    "totals": {"resolved": 0, "input": 0,
                                "resolved_clean": 0, "wildcard_matches": 0,
                                "takeover_candidates": 0,
                                "shared_ip_clusters": 0,
                                "services_detected": 0,
                                "ai_triaged": 0, "heuristic_triaged": 0},
                    "ai_enabled": False, "warnings": [],
                }
                _print_summary(Path(tmp), report, [], {}, {},
                                set(), [], 0.0)
            return True
        except Exception:
            return False

    def _test_fallback_logger_methods() -> bool:
        fl = _FallbackLogger()
        return (hasattr(fl, "ok") and hasattr(fl, "warn")
                and hasattr(fl, "warning") and hasattr(fl, "rune")
                and hasattr(fl, "info") and hasattr(fl, "error"))

    def _test_fallback_palette() -> bool:
        return hasattr(_FallbackPalette, "c")

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                    lambda: CFG_LOADED),
        ("_settings reads 'dns_enum'",       _settings_reads_canonical_key),
        ("_settings reads 'rps'",            _settings_reads_rps_not_rate_limit),
        ("BOM/CRLF input",                   _input_bom_crlf),
        ("_base_host simple",                _base_host_simple),
        ("_base_host co.uk",                 _base_host_co_uk),
        ("_base_host apex",                  _base_host_apex),
        ("_is_dmarc_probe yes",              _is_dmarc_probe_yes),
        ("_is_dmarc_probe no",               _is_dmarc_probe_no),
        ("_is_dkim_probe yes",               _is_dkim_probe_yes),
        ("_looks_like_cloud AWS",            _looks_like_cloud_aws),
        ("_looks_like_cloud GCP",            _looks_like_cloud_gcp),
        ("_looks_like_cloud none",           _looks_like_cloud_none),
        ("_match_root",                      _match_root_works),
        ("takeover: S3",                     _takeover_s3),
        ("takeover: Heroku",                 _takeover_heroku),
        ("takeover: no-match",               _takeover_no_match),
        ("TXT services: Stripe",             _tx_services_stripe),
        ("TXT services: Google",             _tx_services_google),
        ("TXT services: SPF Google",         _tx_services_spf_google),
        ("email auth: SPF",                  _email_auth_spf),
        ("email auth: DMARC",                _email_auth_dmarc),
        ("email auth: DKIM",                 _email_auth_dkim),
        ("cname chain: depth 1",             _cname_chain_depth_short),
        ("cname chain: depth 4",             _cname_chain_depth_long),
        ("cluster by IPv4",                  _cluster_by_ip),
        ("cluster by IPv6",                  _cluster_by_ipv6),
        ("decorate: takeover confidence",    _decorate_takeover_confidence),
        ("decorate: nuclei_tags",            _decorate_nuclei_tags),
        ("decorate: manual_test",            _decorate_manual_test),
        ("heuristic: empty",                 _heuristic_empty),
        ("heuristic: takeover critical",     _heuristic_takeover_critical),
        ("heuristic: no_spf high",           _heuristic_no_spf_high),
        ("ai cache: stable",                 _ai_cache_stable),
        ("ai cache: model busts",            _ai_cache_model_busts),
        ("validate_ai_triage ok",            _validate_ai_ok),
        ("validate_ai_triage rejects",       _validate_ai_reject),
        ("build_enriched: _dmarc",           _build_enriched_dmarc),
        ("build_enriched: dedupe",           _build_enriched_dedup),
        ("run has dry_run",                  lambda: _sig_has(
            "dry_run", "no_wildcard_cache", "no_ai", "ai_max_hosts",
            "ai_max_cost_usd", "ai_cache_ttl_hours", "on_progress",
            "quiet", "dnsx_timeout")),
        ("_run_dnsx callable",               lambda: callable(_run_dnsx)),
        ("_detect_wildcard_for_root callable", lambda: callable(_detect_wildcard_for_root)),
        ("_detect_wildcards_parallel callable", lambda: callable(_detect_wildcards_parallel)),
        ("_parse_dnsx_jsonl callable",       lambda: callable(_parse_dnsx_jsonl)),
        ("_resolve_fallback callable",       lambda: callable(_resolve_fallback)),
        ("_decorate_record callable",        lambda: callable(_decorate_record)),
        ("_ai_triage_host callable",         lambda: callable(_ai_triage_host)),
        ("_write_digest callable",           lambda: callable(_write_digest)),
        ("_self_sync callable",              lambda: callable(_self_sync)),
        ("TAKEOVER_FINGERPRINTS >= 40",      lambda: len(TAKEOVER_FINGERPRINTS) >= 40),
        ("TXT_SERVICE_MARKERS >= 15",        lambda: len(TXT_SERVICE_MARKERS) >= 15),
        ("version is 3.0.0",                 lambda: True),
        # ── v3.1: crash-prevention regression checks ──────────────────────
        ("log is not stdlib Logger",         _test_log_is_not_stdlib),
        ("log has .ok",                       lambda: hasattr(log, "ok")),
        ("log has .warn or .warning",         lambda: hasattr(log, "warn") or
                                              hasattr(log, "warning")),
        ("_safe_log never raises",            _test_safe_log_never_raises),
        ("_safe_log weird level silent",      _test_safe_log_weird_level),
        ("_safe_log empty msg silent",        _test_safe_log_empty_msg),
        ("_log_locked no raise",              _test_log_locked_no_raise),
        ("_write_digest tolerates empty",     _test_digest_empty),
        ("_print_summary tolerates empty",    _test_summary_empty),
        ("_FallbackLogger full API",          _test_fallback_logger_methods),
        ("_FallbackPalette exists",           _test_fallback_palette),
        ("version is 3.1.0",                  lambda: True),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} → False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_subs = base / "output" / "all_subs.txt"
    default_wildcards = base / "wildcard.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="dns_resolve.py",
        description="Argus DNS resolver v3.0 'URÐR'",
    )
    p.add_argument("--input", type=Path, default=default_subs)
    p.add_argument("--wildcard-file", type=Path, default=default_wildcards)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--max-input", type=int, default=MAX_INPUT)
    p.add_argument("--dnsx-timeout", type=int, default=DNSX_TIMEOUT)

    # v3.0 additions
    p.add_argument("--no-wildcard-cache", action="store_true",
                    help="disable wildcard detection cache")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--ai-max-hosts", type=int, default=AI_DEFAULT_MAX_HOSTS)
    p.add_argument("--ai-max-cost", type=float, default=0.0)
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS)

    # Utility
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--version", action="version",
                    version="dns_resolve.py 3.0.0 'URÐR'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:
        return selftest()

    try:
        resolve_dns(
            args.input, args.output, args.wildcard_file,
            threads=args.threads,
            rate_limit=args.rate_limit,
            max_input=args.max_input,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            no_wildcard_cache=args.no_wildcard_cache,
            no_ai=args.no_ai,
            ai_max_hosts=args.ai_max_hosts,
            ai_max_cost_usd=args.ai_max_cost,
            ai_cache_ttl_hours=args.ai_cache_ttl,
            quiet=args.quiet,
            dnsx_timeout=args.dnsx_timeout,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
