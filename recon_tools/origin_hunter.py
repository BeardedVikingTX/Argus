#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛟ ᚱ ᛁ ᚷ ᛁ ᚾ   ·   O R I G I N   H U N T E R   ·   F E N R I R ' S   S I G H T
================================================================================
  File      : recon_tools/origin_hunter.py
  Version   : 2.1.0 "FENRIR'S SIGHT REFORGED"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Aggressive, multi-source, CDN origin IP discovery with weighted validation.

  v2.1 CHANGELOG (from v2.0):
    [BUGFIX] Cert SNI now uses target hostname, not IP (Patch B)
    [BUGFIX] Favicon fetched as raw bytes, not UTF-8 string (Patch E)
    [BUGFIX] as_completed() replaced with wait() — no more early loop exit (Patch D)
    [BUGFIX] subdomain_leak candidates deduplicated by IP (Patch F)
    [BUGFIX] Selftest source count updated to 13 (Patch A)
    [BUGFIX] Rune.OTHAIA typo → Rune.OTHALA (Patch G)
    [NEW]    PaaS-edge detection — marks confirmed IPs that ARE the target's
             own resolution (Vercel/Netlify/etc.) as INFO, not CRITICAL (Patch C)
    [NEW]    Per-request proxy rotation from ProxyPool
    [NEW]    Smart pacing: target-host requests get human_delay + RateLimiter;
             third-party OSINT APIs get minimal delay (they self-rate-limit)
    [NEW]    Baseline fetch falls back to HTTP if HTTPS fails
    [NEW]    Direct validation tries HTTPS first, then HTTP
    [NEW]    Direct validation uses a real browser UA, not the Argus bot UA
    [NEW]    Small randomized sleep between candidate validations

  Sources (13 total, tried in parallel):
    No-key (9): crt.sh, rapiddns, anubis, threatcrowd, urlscan, otx,
                subdomain_leak, wayback, hackertarget
    Free-key (3): virustotal, securitytrails, censys
    Paid (1):     shodan_favicon

  Validation scoring (unwaf-inspired):
    HTML similarity   60%  — difflib on normalized text
    SSL cert match    25%  — serial (50%) + CN (25%) + SAN overlap (25%)
    Header match      15%  — server, x-powered-by, security headers
    Score ≥ 0.70 → CONFIRMED · ≥ 0.50 → HIGH · ≥ 0.30 → MEDIUM · < → rejected

  Safety: every connection through HttpSession passes SCOPE.enforce(),
  KillSwitch.check(), AuditTrail.record(), RateLimiter.acquire(),
  human_delay(), random UA, and per-request proxy rotation.

  Usage
  ─────
    python3 recon_tools/origin_hunter.py --input output/live_hosts.json
    python3 recon_tools/origin_hunter.py --domain arc.io --aggressive
    python3 recon_tools/origin_hunter.py --input output/live_hosts.json --fast
    python3 recon_tools/origin_hunter.py --domain x.com --no-proxy --dry-run
    python3 recon_tools/origin_hunter.py --selftest
    python3 recon_tools/origin_hunter.py --config-check
    python3 recon_tools/origin_hunter.py --check-keys
================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures as _cf
import difflib
import hashlib
import ipaddress
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
    CFG = None
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
    def fatal(self, m): self._emit("fatal", m, "blood", "☠")

    def rune(self, rune, msg):
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")


log = _cfg("log") or _FallbackLogger()


class Sym:
    STAR = "★"; ARROW = "➤"; CHECK = "✓"; CROSS = "✗"
    WARN = "⚠"; INFO = "·"; SKULL = "☠"; SHIELD = "🛡"
    WOLF = "🐺"; GEAR = "⚙"; SHAMROCK = "☘"; LOCK = "🔒"; KEY = "🔑"


class Rune:
    RAIDO = "ᚱ"; OTHALA = "ᛟ"; ALGIZ = "ᛉ"; KANO = "ᚲ"; GEBO = "ᚷ"
    TIWAZ = "ᛏ"; EHWAZ = "ᛖ"; ANSUZ = "ᚨ"; SOWILO = "ᛊ"


__version__ = "2.1.0"
__codename__ = "FENRIR'S SIGHT REFORGED"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛟ ᚱ ᛁ ᚷ ᛁ ᚾ{R}
    {P}{rule}{R}
    {V}    O R I G I N   H U N T E R   ·   F E N R I R ' S   S I G H T{R}
    {V}          R E F O R G E D   ·   T H I R T E E N   S O U R C E S{R}
    {D}{rule}{R}
    {G}      {Sym.WOLF}  v{__version__} "{__codename__}"  ·  CDN origin discovery{R}
    {G}      {Sym.GEAR}  config v{_cfg('__version__', 'missing')} {R}
    {G}      {Sym.SHAMROCK}  BeardedVikingTX  ·  {_cfg('AUTHOR_EMAIL', 'security@beardedviking.org')}{R}
    {P}{rule}{R}
""")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SEVERITY / CONFIDENCE
# ══════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


class Confidence(str, Enum):
    LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CONFIRMED = "CONFIRMED"
    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CONFIRMED": 3}[self.value]


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════

USER_AGENT_BASE = f"Argus-OriginHunter/{__version__}"
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BODY = 500_000
VALIDATION_WEIGHT_HTML   = 0.60
VALIDATION_WEIGHT_CERT   = 0.25
VALIDATION_WEIGHT_HEADER = 0.15
CONFIRMED_THRESHOLD      = 0.70
HIGH_THRESHOLD           = 0.50
MEDIUM_THRESHOLD         = 0.30

# Pacing (per request)
TARGET_DELAY_RANGE   = (0.5, 1.5)      # human-like when hitting target
OSINT_DELAY_RANGE    = (0.05, 0.20)    # minimal between third-party APIs
VALIDATION_SLEEP     = (0.3, 0.8)      # between candidate validation attempts

# Source collection
SOURCE_PARALLEL_WORKERS = 8
SOURCE_TIMEOUT_SECONDS  = 25
SOURCE_TOTAL_TIMEOUT    = SOURCE_TIMEOUT_SECONDS * 2

# Fallback browser UA for direct validation (looks like a real visitor)
FALLBACK_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

API_KEY_FILE = _REPO_ROOT / ".argus_api_keys.json"

CDN_RANGE_URLS: dict[str, list[str]] = {
    "cloudflare": [
        "https://www.cloudflare.com/ips-v4",
        "https://api.cloudflare.com/client/v4/ips",
    ],
    "aws_cloudfront": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
    "fastly":         ["https://api.fastly.com/public-ip-list"],
    "azure": [
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240101.json",
    ],
    "gcp":            ["https://www.gstatic.com/ipranges/cloud.json"],
    "akamai": [
        "https://raw.githubusercontent.com/mansourjabin/cdn-ip-database/main/data/akamai.json",
    ],
}

STATIC_CDN_FALLBACK = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    # Deliberately NOT including Vercel/Netlify/GitHub Pages here.
    # Those get treated as "unknown CDN" so direct_resolution candidates
    # are still validated. PaaS-edge detection in _apply_severity marks
    # them as INFO so they don't pollute real bypass findings.
}

CHAIN_NAMES: dict[str, str] = {
    "origin-confirmed-direct":   "Origin IP confirmed via direct connection",
    "origin-html-match":         "Origin matches by HTML similarity",
    "origin-cert-match":         "Origin matches by SSL certificate",
    "origin-https-direct":       "Origin responds on HTTPS with correct SNI",
    "origin-http-direct":        "Origin responds on HTTP port 80",
    "origin-subdomain-leak":     "Origin leaked via subdomain resolution",
    "origin-historical-dns":     "Origin found in historical DNS records",
    "origin-ct-cert-leak":       "Origin found in CT log certificate",
    "origin-favicon-pivot":      "Origin found via favicon hash pivot",
    "origin-multi-source":       "Origin confirmed by 3+ independent sources",
    "origin-cdn-range-bypass":   "Origin IP not in known CDN ranges",
    "origin-waf-disabled":       "Origin responds directly (no WAF headers)",
    "origin-paas-edge":          "PaaS edge — target's own resolution, not a bypass",
}

CHAIN_SEVERITY: dict[str, Severity] = {
    "origin-confirmed-direct":   Severity.CRITICAL,
    "origin-html-match":         Severity.HIGH,
    "origin-cert-match":         Severity.HIGH,
    "origin-https-direct":       Severity.HIGH,
    "origin-http-direct":        Severity.MEDIUM,
    "origin-subdomain-leak":     Severity.HIGH,
    "origin-historical-dns":     Severity.HIGH,
    "origin-ct-cert-leak":       Severity.MEDIUM,
    "origin-favicon-pivot":      Severity.MEDIUM,
    "origin-multi-source":       Severity.HIGH,
    "origin-cdn-range-bypass":   Severity.MEDIUM,
    "origin-waf-disabled":       Severity.HIGH,
    "origin-paas-edge":          Severity.INFO,
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


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Candidate:
    ip: str
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    in_cdn_range: bool = False
    cdn_provider: str = ""
    validated: bool = False
    confidence: Confidence = Confidence.LOW
    html_score: float = 0.0
    cert_score: float = 0.0
    header_score: float = 0.0
    overall_score: float = 0.0
    validation_details: dict = field(default_factory=dict)
    severity: Severity = Severity.LOW
    chain_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def add_source(self, source: str, evidence: str = "") -> None:
        if source not in self.sources:
            self.sources.append(source)
        if evidence:
            self.evidence.append(evidence)


@dataclass
class HostResult:
    host: str
    base_url: str = ""
    cdn_ips: list[str] = field(default_factory=list)
    cdn_provider: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    confirmed: list[Candidate] = field(default_factory=list)
    baseline: dict = field(default_factory=dict)
    sources_tried: list[dict] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  API KEY STORE
# ══════════════════════════════════════════════════════════════════════════

class ApiKeyStore:
    ENV_MAP = {
        "shodan":         "ARGUS_SHODAN_KEY",
        "censys_id":      "ARGUS_CENSYS_ID",
        "censys_secret":  "ARGUS_CENSYS_SECRET",
        "securitytrails": "ARGUS_SECURITYTRAILS_KEY",
        "virustotal":     "ARGUS_VIRUSTOTAL_KEY",
    }

    def __init__(self, overrides: Optional[dict] = None):
        self._keys: dict[str, str] = {}
        self._load_file()
        self._load_env()
        if overrides:
            for k, v in overrides.items():
                if v:
                    self._keys[k] = v

    def _load_file(self) -> None:
        if not API_KEY_FILE.exists():
            return
        try:
            data = json.loads(API_KEY_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                if isinstance(v, str) and v.strip():
                    self._keys[k] = v.strip()
        except Exception as e:
            log.warn(f"API key file unreadable: {e}")

    def _load_env(self) -> None:
        for key, env in self.ENV_MAP.items():
            val = os.getenv(env)
            if val:
                self._keys.setdefault(key, val.strip())

    def get(self, key: str) -> Optional[str]:
        return self._keys.get(key) or None

    def has(self, key: str) -> bool:
        return bool(self.get(key))

    def summary(self) -> dict[str, bool]:
        return {
            "shodan":         self.has("shodan"),
            "censys":         self.has("censys_id") and self.has("censys_secret"),
            "securitytrails": self.has("securitytrails"),
            "virustotal":     self.has("virustotal"),
        }


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CDN RANGE MANAGER
# ══════════════════════════════════════════════════════════════════════════

class CdnRangeManager:
    def __init__(self, cache_path: Optional[Path] = None):
        self.cache_path = cache_path or (_REPO_ROOT / "output" / ".cdn_ranges_cache.json")
        self.ranges: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
        self.loaded_at: Optional[str] = None

    def load(self, force_refresh: bool = False) -> None:
        if not force_refresh and self._load_cache():
            log.info(f"  CDN ranges: {sum(len(v) for v in self.ranges.values())} CIDRs (cached)")
            return
        log.info("  Fetching CDN ranges...")
        total = 0
        for provider, urls in CDN_RANGE_URLS.items():
            cidrs = self._fetch_provider(provider, urls)
            if not cidrs:
                for c in STATIC_CDN_FALLBACK.get(provider, []):
                    try:
                        cidrs.append(ipaddress.ip_network(c, strict=False))
                    except Exception:
                        pass
            if cidrs:
                self.ranges[provider] = cidrs
                total += len(cidrs)
                log.info(f"    {provider}: {len(cidrs)} CIDR(s)")
            else:
                log.warn(f"    {provider}: no ranges (skipped)")
        self.loaded_at = datetime.now(timezone.utc).isoformat()
        self._save_cache()
        log.ok(f"  CDN ranges loaded: {total} total")

    def _fetch_provider(self, provider, urls):
        result = []
        for url in urls:
            text = self._fetch(url)
            if not text:
                continue
            try:
                result.extend(self._parse_ranges(provider, text, url))
                if result:
                    return result
            except Exception as e:
                log.debug(f"    {provider} parse error from {url}: {e}")
        return result

    def _fetch(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT_BASE})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception:
            return None

    def _parse_ranges(self, provider, text, url):
        out = []
        if url.endswith("/ips-v4") or url.endswith("/ips-v6"):
            for line in text.strip().splitlines():
                line = line.strip()
                if line and "/" in line:
                    try:
                        out.append(ipaddress.ip_network(line, strict=False))
                    except Exception:
                        pass
            return out
        try:
            data = json.loads(text)
        except Exception:
            return out

        if provider == "cloudflare" and isinstance(data, dict) and "result" in data:
            for key in ("ipv4_cidrs", "ipv6_cidrs"):
                for c in data.get("result", {}).get(key, []):
                    try:
                        out.append(ipaddress.ip_network(c, strict=False))
                    except Exception:
                        pass
            return out
        if provider == "aws_cloudfront" and "prefixes" in data:
            for p in data["prefixes"]:
                if p.get("service") == "CLOUDFRONT" and p.get("ip_prefix"):
                    try:
                        out.append(ipaddress.ip_network(p["ip_prefix"], strict=False))
                    except Exception:
                        pass
            return out
        if provider == "fastly" and isinstance(data, dict):
            for key in ("addresses", "ipv6_addresses"):
                for c in data.get(key, []):
                    try:
                        out.append(ipaddress.ip_network(c, strict=False))
                    except Exception:
                        pass
            return out
        if provider == "gcp" and "prefixes" in data:
            for p in data["prefixes"]:
                prefix = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if prefix:
                    try:
                        out.append(ipaddress.ip_network(prefix, strict=False))
                    except Exception:
                        pass
            return out
        if provider == "azure" and "values" in data:
            for svc in data["values"]:
                for p in svc.get("properties", {}).get("addressPrefixes", []):
                    try:
                        out.append(ipaddress.ip_network(p, strict=False))
                    except Exception:
                        pass
            return out
        if isinstance(data, list):
            for c in data:
                if isinstance(c, str) and "/" in c:
                    try:
                        out.append(ipaddress.ip_network(c, strict=False))
                    except Exception:
                        pass
        return out

    def _load_cache(self) -> bool:
        if not self.cache_path.exists():
            return False
        try:
            data = json.loads(self.cache_path.read_text())
            ts = data.get("loaded_at", "")
            if not ts:
                return False
            loaded = datetime.fromisoformat(ts)
            if (datetime.now(timezone.utc) - loaded).days > 7:
                return False
            for provider, cidr_strs in data.get("ranges", {}).items():
                nets = []
                for c in cidr_strs:
                    try:
                        nets.append(ipaddress.ip_network(c, strict=False))
                    except Exception:
                        pass
                self.ranges[provider] = nets
            self.loaded_at = ts
            return bool(self.ranges)
        except Exception:
            return False

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "loaded_at": self.loaded_at,
                "ranges": {p: [str(n) for n in nets] for p, nets in self.ranges.items()},
            }
            self.cache_path.write_text(json.dumps(payload, indent=2))
        except Exception as e:
            log.debug(f"Could not save CDN cache: {e}")

    def is_cdn_ip(self, ip: str) -> tuple[bool, str]:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            return False, ""
        for provider, nets in self.ranges.items():
            for net in nets:
                try:
                    if ip_obj in net:
                        return True, provider
                except TypeError:
                    continue
        return False, ""


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  HTTP SESSION (per-host; per-request proxy rotation; smart pacing)
# ══════════════════════════════════════════════════════════════════════════

class HttpSession:
    """
    Per-host HTTP client with:
      ·  random UA per request (from config.random_user_agent)
      ·  BBP headers via config.build_headers()
      ·  per-request proxy rotation from ProxyPool
      ·  smart pacing — human-like for target; minimal for OSINT APIs
      ·  KillSwitch guard on every request
      ·  AuditTrail record on every request
      ·  SCOPE enforcement on target URLs only (third-party APIs always allowed)
    """

    def __init__(self, host: str, bbp_program: Optional[str] = None,
                 proxy_pool: Any = None, audit_trail: Any = None,
                 use_proxy: bool = True):
        self.host = host
        self.bbp_program = bbp_program
        self.audit = audit_trail
        self.proxy_pool = proxy_pool if use_proxy else None
        self.rate_limiter = self._build_rate_limiter()
        self.static_headers = self._build_headers(bbp_program)
        self.stats = {"requests": 0, "errors": 0, "proxies_used": set()}

    def _build_rate_limiter(self) -> Any:
        try:
            rl_cls = _cfg("RateLimiter")
            limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("origin_hunt", {})
            rps = limits.get("rps", 3)
            return rl_cls(per_minute=rps * 60, per_hour=rps * 3600) if rl_cls else None
        except Exception:
            return None

    def _build_headers(self, bbp_program: Optional[str]) -> dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            if bbp_program:
                builder = _cfg("build_headers")
                if callable(builder):
                    headers.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
        return headers

    def _next_proxy(self) -> Any:
        """Pick a fresh proxy from the pool (per request)."""
        if self.proxy_pool is None:
            return None
        try:
            p = self.proxy_pool.pick()
            if p is not None:
                self.stats["proxies_used"].add(p.url())
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
        return USER_AGENT_BASE

    def _guard(self) -> None:
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"):
                ks.check()
        except Exception:
            pass

    def _is_target_url(self, url: str) -> bool:
        try:
            host = (urllib.parse.urlparse(url).hostname or "").lower()
            return host == self.host or host.endswith("." + self.host)
        except Exception:
            return False

    def _pace(self, url: str) -> None:
        """
        Human-like delay for target requests; minimal for third-party OSINT.
        Prevents parallel source execution from serializing on a shared limiter.
        """
        try:
            if self._is_target_url(url):
                if self.rate_limiter is not None:
                    self.rate_limiter.acquire()
                delay_fn = _cfg("human_delay")
                if callable(delay_fn):
                    d = delay_fn()
                    # Cap at target range so OSINT doesn't wait absurdly
                    d = min(d, TARGET_DELAY_RANGE[1])
                    d = max(d, TARGET_DELAY_RANGE[0])
                    time.sleep(d)
                else:
                    time.sleep(random.uniform(*TARGET_DELAY_RANGE))
            else:
                # OSINT API — minimal delay
                time.sleep(random.uniform(*OSINT_DELAY_RANGE))
        except Exception:
            pass

    def _in_scope(self, url: str) -> bool:
        """Third-party APIs bypass SCOPE; only target-host requests are checked."""
        try:
            url_host = (urllib.parse.urlparse(url).hostname or "").lower()
            if not url_host:
                return True
            # Third-party API — always allowed
            if url_host != self.host and not url_host.endswith("." + self.host):
                return True
            # Target host — enforce SCOPE
            scope = _cfg("SCOPE")
            if scope is None:
                return True
            if scope.is_in_scope(url):
                return True
            for rule in getattr(scope, "_rules", []):
                if not getattr(rule, "include", True):
                    continue
                if getattr(rule, "regex", False):
                    continue
                pattern = (rule.pattern or "").lower().strip().lstrip("*.")
                if pattern and (url_host == pattern
                                 or url_host.endswith("." + pattern)):
                    return True
            return False
        except Exception:
            return True

    def _build_opener(self, proxy: Any):
        opener = urllib.request.build_opener()
        if proxy is not None:
            try:
                opener.add_handler(urllib.request.ProxyHandler(
                    {"http": proxy.url(), "https": proxy.url()}))
            except Exception:
                pass
        return opener

    def get(self, url: str, extra_headers: Optional[dict] = None,
            timeout: float = DEFAULT_TIMEOUT) -> tuple[int, dict[str, str], str, Optional[str]]:
        """Returns (status, headers_dict, body, error)."""
        if not self._in_scope(url):
            return (0, {}, "", "out of scope")
        self._guard()
        self._pace(url)

        headers = dict(self.static_headers)
        headers["User-Agent"] = self._ua()
        if extra_headers:
            headers.update(extra_headers)

        proxy = self._next_proxy()
        req = urllib.request.Request(url, headers=headers, method="GET")
        opener = self._build_opener(proxy)

        start = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(DEFAULT_MAX_BODY).decode("utf-8", errors="replace")
                latency_ms = (time.monotonic() - start) * 1000
                headers_dict = {k: v for k, v in resp.headers.items()}
                self.stats["requests"] += 1
                self._audit("GET", resp.geturl(), resp.getcode(), latency_ms, None, proxy)
                return (resp.getcode(), headers_dict, body, None)
        except urllib.error.HTTPError as e:
            latency_ms = (time.monotonic() - start) * 1000
            try:
                body = e.read(DEFAULT_MAX_BODY).decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                body, headers_dict = "", {}
            self.stats["requests"] += 1
            self._audit("GET", url, e.code, latency_ms, f"HTTP {e.code}", proxy)
            return (e.code, headers_dict, body, None)
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            self._audit("GET", url, 0, latency_ms, str(e)[:200], proxy)
            return (0, {}, "", f"{type(e).__name__}: {e}")

    def get_bytes(self, url: str, timeout: float = DEFAULT_TIMEOUT
                  ) -> tuple[int, dict[str, str], Optional[bytes], Optional[str]]:
        """
        Like get() but returns raw bytes — critical for favicon hashing.
        Binary content must NEVER be UTF-8 decoded or the hash will be wrong.
        """
        if not self._in_scope(url):
            return (0, {}, None, "out of scope")
        self._guard()
        self._pace(url)

        headers = dict(self.static_headers)
        headers["User-Agent"] = self._ua()

        proxy = self._next_proxy()
        req = urllib.request.Request(url, headers=headers, method="GET")
        opener = self._build_opener(proxy)

        start = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                data = resp.read(65536)
                latency_ms = (time.monotonic() - start) * 1000
                headers_dict = {k: v for k, v in resp.headers.items()}
                self.stats["requests"] += 1
                self._audit("GET", resp.geturl(), resp.getcode(), latency_ms, None, proxy)
                return (resp.getcode(), headers_dict, data, None)
        except urllib.error.HTTPError as e:
            latency_ms = (time.monotonic() - start) * 1000
            try:
                data = e.read(65536)
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                data, headers_dict = None, {}
            self.stats["requests"] += 1
            self._audit("GET", url, e.code, latency_ms, f"HTTP {e.code}", proxy)
            return (e.code, headers_dict, data, None)
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            self._audit("GET", url, 0, latency_ms, str(e)[:200], proxy)
            return (0, {}, None, f"{type(e).__name__}: {e}")

    def _audit(self, method: str, url: str, status: int,
                latency_ms: float, error: Optional[str], proxy: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                method=method, url=url, status=status, latency_ms=latency_ms,
                proxy=proxy.url() if proxy else None,
                user_agent="(rotating)", error=error,
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  BASELINE FETCH
# ══════════════════════════════════════════════════════════════════════════

def _fetch_baseline(host: str, session: HttpSession) -> dict:
    """
    Fetch the CDN-fronted baseline. Tries HTTPS first, falls back to HTTP.
    Returns: {title, body_norm, cert, headers, status, scheme, url, error}
    """
    result = {
        "title": "", "body_norm": "", "cert": {}, "headers": {},
        "status": 0, "scheme": "https", "url": f"https://{host}/",
        "error": None, "meaningful": False,
    }

    status, hdrs, body, err = session.get(f"https://{host}/")
    if err and any(k in err.lower() for k in
                   ("ssl", "certificate", "refused", "handshake")):
        log.info(f"  https baseline failed ({err}) — trying http")
        status, hdrs, body, err = session.get(f"http://{host}/")
        if not err:
            result["scheme"] = "http"
            result["url"] = f"http://{host}/"

    if err or status == 0:
        result["error"] = err
        return result

    result["status"] = status
    result["headers"] = hdrs
    result["title"] = _extract_title(body)
    result["body_norm"] = _normalize_body(body)

    try:
        cert = _fetch_ssl_cert(host, port=443, sni_host=host)
        if cert:
            result["cert"] = cert
    except Exception:
        pass

    result["meaningful"] = (
        status > 0 and status < 400 and len(result["body_norm"]) >= 200
    )
    return result


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:200] if m else ""


def _normalize_body(html: str) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;|&#\d+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text[:50_000]


def _fetch_ssl_cert(connect_to: str, port: int = 443,
                     sni_host: Optional[str] = None) -> Optional[dict]:
    """
    Fetch the peer SSL certificate.

    IMPORTANT: `connect_to` is what we dial (may be an IP); `sni_host`
    is what to send as TLS SNI (MUST be the hostname the cert is for).
    Sending SNI=IP is rejected by most HTTPS servers → wrong cert.
    """
    sni = sni_host or connect_to
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_to, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer":  dict(x[0] for x in cert.get("issuer", [])),
                    "serialNumber": cert.get("serialNumber", ""),
                    "subjectAltName": cert.get("subjectAltName", []),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter":  cert.get("notAfter", ""),
                }
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  PASSIVE SOURCES
# ══════════════════════════════════════════════════════════════════════════

def _resolve_host(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def source_crtsh(host, session, keys):
    out = []
    url = f"https://crt.sh/?q=%25.{host}&output=json"
    status, _, body, err = session.get(url, timeout=30)
    if err or status != 200:
        raise RuntimeError(f"crt.sh: {err or f'HTTP {status}'}")
    try:
        entries = json.loads(body)
    except Exception:
        raise RuntimeError("crt.sh: invalid JSON")
    seen_hosts = set()
    for entry in entries:
        for name in (entry.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name or name == host or not name.endswith(host):
                continue
            if name in seen_hosts:
                continue
            seen_hosts.add(name)
            for ip in _resolve_host(name):
                c = Candidate(ip=ip)
                c.add_source("crt.sh", f"CT entry: {name}")
                out.append(c)
    return out


def source_subdomain_leaks(host, session, keys):
    """Common subdomain wordlist resolution — deduped by IP."""
    out = []
    seen_ips = set()
    common = ("www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
              "cpanel", "direct", "origin", "dev", "staging", "test",
              "api", "admin", "portal", "vpn", "git", "jenkins", "jira",
              "beta", "internal", "backend", "cdn-origin")
    for sub in common:
        fqdn = f"{sub}.{host}"
        for ip in _resolve_host(fqdn):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("subdomain_leak", f"{fqdn} → {ip}")
            out.append(c)
    return out


def source_hackertarget(host, session, keys):
    out = []
    url = f"https://api.hackertarget.com/hostsearch/?q={host}"
    status, _, body, err = session.get(url)
    if err or status != 200:
        raise RuntimeError(f"hackertarget: {err or f'HTTP {status}'}")
    if body.strip().startswith("API count exceeded"):
        raise RuntimeError("hackertarget: API quota exceeded")
    for line in body.splitlines():
        if "," not in line:
            continue
        sub, ip = line.split(",", 1)
        sub, ip = sub.strip(), ip.strip()
        if _is_ip(ip):
            c = Candidate(ip=ip)
            c.add_source("hackertarget", f"{sub} → {ip}")
            out.append(c)
    return out


def source_wayback(host, session, keys):
    out = []
    url = (f"http://web.archive.org/cdx/search/cdx?"
           f"url=*.{host}&output=text&fl=original&collapse=urlkey&limit=2000")
    status, _, body, err = session.get(url, timeout=45)
    if err or status != 200:
        raise RuntimeError(f"wayback: {err or f'HTTP {status}'}")
    seen_hosts = set()
    for line in body.splitlines():
        try:
            uhost = urllib.parse.urlparse(line.strip()).hostname or ""
        except Exception:
            continue
        if not uhost or uhost == host or uhost in seen_hosts:
            continue
        seen_hosts.add(uhost)
        for ip in _resolve_host(uhost):
            c = Candidate(ip=ip)
            c.add_source("wayback", f"archived {uhost} → {ip}")
            out.append(c)
    return out


def source_rapiddns(host, session, keys):
    out = []
    url = f"https://rapiddns.io/subdomain/{host}?full=1"
    status, _, body, err = session.get(url, timeout=20)
    if err or status != 200:
        raise RuntimeError(f"rapiddns: {err or f'HTTP {status}'}")
    seen_ips = set()
    for m in re.finditer(r"<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>", body):
        ip = m.group(1)
        if _is_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("rapiddns", f"subdomain {host} → {ip}")
            out.append(c)
    return out


def source_threatcrowd(host, session, keys):
    out = []
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={host}"
    status, _, body, err = session.get(url, timeout=20)
    if err or status != 200:
        raise RuntimeError(f"threatcrowd: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("threatcrowd: invalid JSON")
    seen_ips = set()
    for sub in data.get("subdomains", [])[:30]:
        fqdn = sub if sub.endswith(host) else f"{sub}.{host}"
        for ip in _resolve_host(fqdn):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("threatcrowd", f"{fqdn} → {ip}")
            out.append(c)
    for r in data.get("resolutions", [])[:20]:
        if isinstance(r, dict) and _is_ip(r.get("ip_address", "")):
            ip = r["ip_address"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("threatcrowd",
                          f"historical ({r.get('last_resolved', '')})")
            out.append(c)
    return out


def source_urlscan(host, session, keys):
    out = []
    url = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=100"
    status, _, body, err = session.get(url, timeout=20)
    if err or status != 200:
        raise RuntimeError(f"urlscan: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("urlscan: invalid JSON")
    seen_ips = set()
    for result in data.get("results", []):
        ip = result.get("page", {}).get("ip", "")
        if _is_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("urlscan",
                          f"scan ({result.get('task', {}).get('time', '')})")
            out.append(c)
    return out


def source_anubis(host, session, keys):
    out = []
    url = f"https://jldc.me/anubis/subdomains/{host}"
    status, _, body, err = session.get(url, timeout=15)
    if err or status != 200:
        raise RuntimeError(f"anubis: {err or f'HTTP {status}'}")
    try:
        subdomains = json.loads(body)
    except Exception:
        raise RuntimeError("anubis: invalid JSON")
    seen_ips = set()
    for sub in subdomains[:50]:
        for ip in _resolve_host(sub):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("anubis", f"{sub} → {ip}")
            out.append(c)
    return out


def source_otx(host, session, keys):
    out = []
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{host}/passive_dns")
    status, _, body, err = session.get(url, timeout=20)
    if err or status != 200:
        raise RuntimeError(f"otx: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("otx: invalid JSON")
    seen_ips = set()
    for rec in data.get("passive_dns", []):
        hostname = rec.get("hostname", "")
        for ip in _resolve_host(hostname):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            c = Candidate(ip=ip)
            c.add_source("otx", f"{hostname} → {ip}")
            out.append(c)
    return out


def source_virustotal(host, session, keys):
    api_key = keys.get("virustotal")
    if not api_key:
        raise RuntimeError("virustotal: no API key")
    out = []
    url = f"https://www.virustotal.com/api/v3/domains/{host}/resolutions?limit=40"
    status, _, body, err = session.get(url, extra_headers={"x-apikey": api_key})
    if err or status != 200:
        raise RuntimeError(f"virustotal: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("virustotal: invalid JSON")
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        ip = attrs.get("ip_address", "")
        if _is_ip(ip):
            c = Candidate(ip=ip)
            c.add_source("virustotal", f"DNS resolution ({attrs.get('date', '')})")
            out.append(c)
    return out


def source_securitytrails(host, session, keys):
    api_key = keys.get("securitytrails")
    if not api_key:
        raise RuntimeError("securitytrails: no API key")
    out = []
    url = f"https://api.securitytrails.com/v1/history/{host}/dns/a"
    status, _, body, err = session.get(
        url, extra_headers={"APIKEY": api_key, "Accept": "application/json"})
    if err or status != 200:
        raise RuntimeError(f"securitytrails: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("securitytrails: invalid JSON")
    for rec in data.get("records", []):
        for val in rec.get("values", []):
            ip = val.get("ip")
            if _is_ip(ip):
                c = Candidate(ip=ip)
                c.add_source("securitytrails",
                              f"A record ({rec.get('first_seen', '')})")
                out.append(c)
    return out


def source_censys(host, session, keys):
    cid = keys.get("censys_id")
    csec = keys.get("censys_secret")
    if not (cid and csec):
        raise RuntimeError("censys: missing API id/secret")
    out = []
    import base64
    creds = base64.b64encode(f"{cid}:{csec}".encode()).decode()
    url = "https://search.censys.io/api/v2/hosts/search"
    payload = json.dumps({
        "q": f"services.tls.certificates.leaf_data.names: {host}",
        "per_page": 50,
    }).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {creds}",
            "User-Agent": USER_AGENT_BASE,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            resp = json.loads(r.read())
    except Exception as e:
        raise RuntimeError(f"censys: {e}")
    for hit in resp.get("result", {}).get("hits", []):
        ip = hit.get("ip")
        if _is_ip(ip):
            c = Candidate(ip=ip)
            c.add_source("censys", f"SSL cert match: {hit.get('name', '')}")
            out.append(c)
    return out


def source_shodan_favicon(host, session, keys):
    api_key = keys.get("shodan")
    if not api_key:
        raise RuntimeError("shodan: no API key")
    # Fetch favicon as BYTES (not str!)
    status, _, favicon_bytes, err = session.get_bytes(f"https://{host}/favicon.ico")
    if err or not favicon_bytes:
        raise RuntimeError(f"shodan: could not fetch favicon ({err})")

    import base64
    fav_b64 = base64.encodebytes(favicon_bytes)
    try:
        import mmh3
        fav_hash = mmh3.hash(fav_b64)
    except ImportError:
        fav_hash = _murmurhash3_32(fav_b64)

    url = (f"https://api.shodan.io/shodan/host/search?"
           f"key={api_key}&query=http.favicon.hash:{fav_hash}&limit=100")
    status, _, body, err = session.get(url)
    if err or status != 200:
        raise RuntimeError(f"shodan: {err or f'HTTP {status}'}")
    try:
        data = json.loads(body)
    except Exception:
        raise RuntimeError("shodan: invalid JSON")
    out = []
    for match in data.get("matches", []):
        ip = match.get("ip_str", "")
        if _is_ip(ip):
            c = Candidate(ip=ip)
            c.add_source("shodan_favicon", f"favicon hash {fav_hash}")
            out.append(c)
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32 (Shodan-compatible)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    for i in range(0, length & ~3, 4):
        k1 = (data[i] & 0xFF) | ((data[i+1] & 0xFF) << 8) | \
             ((data[i+2] & 0xFF) << 16) | ((data[i+3] & 0xFF) << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    k1 = 0
    tail = length & ~3
    if length & 3 >= 3: k1 ^= (data[tail+2] & 0xFF) << 16
    if length & 3 >= 2: k1 ^= (data[tail+1] & 0xFF) << 8
    if length & 3 >= 1:
        k1 ^= data[tail] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16; h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13; h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


SOURCE_REGISTRY: list[tuple[str, Callable, Optional[str]]] = [
    ("crt.sh",         source_crtsh,           None),
    ("rapiddns",       source_rapiddns,        None),
    ("anubis",         source_anubis,          None),
    ("threatcrowd",    source_threatcrowd,     None),
    ("urlscan",        source_urlscan,         None),
    ("otx",            source_otx,             None),
    ("subdomain_leak", source_subdomain_leaks, None),
    ("wayback",        source_wayback,         None),
    ("hackertarget",   source_hackertarget,    None),
    ("virustotal",     source_virustotal,      "virustotal"),
    ("securitytrails", source_securitytrails,  "securitytrails"),
    ("censys",         source_censys,          "censys_id"),
    ("shodan_favicon", source_shodan_favicon,  "shodan"),
]


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  DIRECT REQUEST  ·  raw socket, no proxy, browser UA
# ══════════════════════════════════════════════════════════════════════════

def _get_browser_ua() -> str:
    """Get a realistic browser UA for direct validation."""
    try:
        fn = _cfg("random_user_agent")
        if callable(fn):
            ua = fn()
            if ua and "bot" not in ua.lower() and "argus" not in ua.lower():
                return ua
    except Exception:
        pass
    return FALLBACK_BROWSER_UA


def _direct_request(ip: str, host: str, scheme: str = "https",
                     timeout: float = 15.0,
                     ua: Optional[str] = None) -> tuple[int, dict, str]:
    """Raw HTTP(S) request to specific IP with Host header + SNI."""
    port = 443 if scheme == "https" else 80
    ua = ua or _get_browser_ua()

    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((ip, port), timeout=timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                req = (f"GET / HTTP/1.1\r\n"
                       f"Host: {host}\r\n"
                       f"User-Agent: {ua}\r\n"
                       f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                       f"Accept-Language: en-US,en;q=0.9\r\n"
                       f"Connection: close\r\n\r\n")
                ssock.sendall(req.encode())
                data = b""
                while True:
                    chunk = ssock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > DEFAULT_MAX_BODY:
                        break
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                req = (f"GET / HTTP/1.1\r\n"
                       f"Host: {host}\r\n"
                       f"User-Agent: {ua}\r\n"
                       f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                       f"Accept-Language: en-US,en;q=0.9\r\n"
                       f"Connection: close\r\n\r\n")
                sock.sendall(req.encode())
                data = b""
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > DEFAULT_MAX_BODY:
                        break

        text = data.decode("utf-8", errors="replace")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        lines = header_block.split("\r\n")
        m = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0] if lines else "")
        status = int(m.group(1)) if m else 0
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        return status, headers, body
    except Exception:
        return 0, {}, ""


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  VALIDATION ENGINE
# ══════════════════════════════════════════════════════════════════════════

def _validate_candidate(cand: Candidate, host: str, baseline: dict,
                         session: HttpSession) -> Candidate:
    details: dict = {}
    scheme = baseline.get("scheme", "https")

    # Try baseline's scheme first, then fall back to the other
    status, hdrs, body = _direct_request(cand.ip, host, scheme)
    details["scheme"] = scheme
    if status == 0 and scheme == "https":
        status, hdrs, body = _direct_request(cand.ip, host, "http")
        details["scheme"] = "http"
    elif status == 0 and scheme == "http":
        status, hdrs, body = _direct_request(cand.ip, host, "https")
        details["scheme"] = "https"

    details["https_status"] = status
    details["https_error"] = None if status > 0 else "connection failed"

    # Skip validation when baseline has no meaningful content
    if not baseline.get("meaningful", True):
        cand.overall_score = 0.0
        cand.confidence = Confidence.LOW
        cand.validation_details = {"skipped": "baseline unusable",
                                    "https_status": status}
        return cand

    if status > 0:
        body_norm = _normalize_body(body)
        if baseline.get("body_norm") and body_norm:
            html_sim = difflib.SequenceMatcher(
                None, baseline["body_norm"], body_norm).ratio()
            cand.html_score = html_sim
            details["html_similarity"] = round(html_sim, 3)
            details["html_length"] = len(body_norm)

        # BUGFIX: pass sni_host explicitly so we get the right cert
        cand_cert = _fetch_ssl_cert(cand.ip, port=443, sni_host=host)
        if baseline.get("cert") and cand_cert:
            cert_score, cert_detail = _compare_certs(baseline["cert"], cand_cert)
            cand.cert_score = cert_score
            details["cert_comparison"] = cert_detail

        if baseline.get("headers") and hdrs:
            header_score, header_detail = _compare_headers(baseline["headers"], hdrs)
            cand.header_score = header_score
            details["header_comparison"] = header_detail

    cand.overall_score = (
        VALIDATION_WEIGHT_HTML   * cand.html_score +
        VALIDATION_WEIGHT_CERT   * cand.cert_score +
        VALIDATION_WEIGHT_HEADER * cand.header_score
    )
    details["overall_score"] = round(cand.overall_score, 3)

    if cand.overall_score >= CONFIRMED_THRESHOLD:
        cand.confidence = Confidence.CONFIRMED
        cand.validated = True
        cand.chain_ids.append("origin-confirmed-direct")
        if cand.html_score >= 0.70:
            cand.chain_ids.append("origin-html-match")
        if cand.cert_score >= 0.70:
            cand.chain_ids.append("origin-cert-match")
        if status == 200:
            cand.chain_ids.append("origin-https-direct" if scheme == "https"
                                   else "origin-http-direct")
    elif cand.overall_score >= HIGH_THRESHOLD:
        cand.confidence = Confidence.HIGH
        cand.validated = True
    elif cand.overall_score >= MEDIUM_THRESHOLD:
        cand.confidence = Confidence.MEDIUM
    else:
        cand.confidence = Confidence.LOW

    if len(cand.sources) >= 3:
        cand.chain_ids.append("origin-multi-source")
    if any("subdomain_leak" in s or "historical" in s.lower()
           or "ct" in s.lower() for s in cand.sources):
        cand.chain_ids.append("origin-historical-dns")
    if status > 0:
        lower_headers = {k.lower() for k in hdrs.keys()}
        has_waf = any(h in lower_headers
                       for h in ("cf-ray", "cf-cache-status",
                                  "x-akamai", "x-iinfo"))
        if not has_waf:
            cand.chain_ids.append("origin-waf-disabled")

    cand.validation_details = details
    return cand


def _compare_certs(baseline_cert: dict, cand_cert: dict) -> tuple[float, dict]:
    detail = {}
    score = 0.0
    if baseline_cert.get("serialNumber") and cand_cert.get("serialNumber"):
        if baseline_cert["serialNumber"] == cand_cert["serialNumber"]:
            score += 0.5
            detail["serial_match"] = True
        else:
            detail["serial_match"] = False
    base_cn = baseline_cert.get("subject", {}).get("commonName", "")
    cand_cn = cand_cert.get("subject", {}).get("commonName", "")
    if base_cn and cand_cn and base_cn == cand_cn:
        score += 0.25
        detail["cn_match"] = True
    base_sans = {e[1].lower() for e in baseline_cert.get("subjectAltName", [])
                 if len(e) >= 2}
    cand_sans = {e[1].lower() for e in cand_cert.get("subjectAltName", [])
                 if len(e) >= 2}
    if base_sans and cand_sans:
        overlap = len(base_sans & cand_sans) / max(len(base_sans), 1)
        score += 0.25 * overlap
        detail["san_overlap"] = round(overlap, 3)
    return min(score, 1.0), detail


def _compare_headers(baseline_hdrs: dict, cand_hdrs: dict) -> tuple[float, dict]:
    detail = {}
    interesting = ("server", "x-powered-by", "x-aspnet-version",
                   "x-generator", "content-security-policy",
                   "strict-transport-security")
    baseline_lower = {k.lower(): v for k, v in baseline_hdrs.items()}
    cand_lower = {k.lower(): v for k, v in cand_hdrs.items()}
    matches = total = 0
    for h in interesting:
        b = baseline_lower.get(h)
        c = cand_lower.get(h)
        if b and c:
            total += 1
            if b == c:
                matches += 1
                detail[h] = "match"
            else:
                detail[h] = f"diff ({b[:30]} vs {c[:30]})"
    return (matches / total) if total else 0.0, detail


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════

def hunt_host(host: str, *, session: HttpSession,
              cdn_mgr: CdnRangeManager, keys: ApiKeyStore,
              aggressive: bool = True,
              fast_exit_on_confirm: bool = True) -> HostResult:
    start = time.monotonic()
    result = HostResult(host=host, base_url=f"https://{host}")

    # Step 0: direct resolution
    result.cdn_ips = _resolve_host(host)
    if result.cdn_ips:
        _, provider = cdn_mgr.is_cdn_ip(result.cdn_ips[0])
        result.cdn_provider = provider
        log.info(f"  CDN IPs: {result.cdn_ips} ({provider or 'unknown'})")

    direct_candidates: list[Candidate] = []
    for ip in result.cdn_ips:
        in_cdn, _ = cdn_mgr.is_cdn_ip(ip)
        if not in_cdn:
            c = Candidate(ip=ip)
            c.add_source("direct_resolution", f"{host} resolves to {ip}")
            direct_candidates.append(c)
            log.info(f"  direct resolution: {ip} → candidate")

    # Step 1: baseline
    log.info("  Fetching baseline (CDN-fronted)...")
    baseline = _fetch_baseline(host, session)
    result.baseline = {
        "url":       baseline["url"],
        "scheme":    baseline["scheme"],
        "status":    baseline["status"],
        "title":     baseline["title"],
        "body_len":  len(baseline["body_norm"]),
        "has_cert":  bool(baseline["cert"]),
        "meaningful": baseline["meaningful"],
        "error":     baseline["error"],
    }
    if baseline["error"]:
        log.warn(f"  baseline failed: {baseline['error']}")
    else:
        log.ok(f"  baseline: {baseline['scheme']} status={baseline['status']} "
               f"title={baseline['title'][:40]!r} body={len(baseline['body_norm'])}B")
    if not baseline["meaningful"] and baseline["status"] > 0:
        log.info(f"  baseline too small to validate "
                  f"({len(baseline['body_norm'])}B) — validation will be skipped")

    # Step 2: parallel source collection
    log.rune(Rune.RAIDO, "Passive sources (parallel)")
    all_candidates: dict[str, Candidate] = {}
    for c in direct_candidates:
        all_candidates[c.ip] = c

    def _run_source(item):
        name, fn, requires_key = item
        if requires_key and not keys.has(requires_key):
            return (name, "skipped", None, 0.0, "no api key")
        try:
            t0 = time.monotonic()
            found = fn(host, session, keys)
            return (name, "ok", found, time.monotonic() - t0, None)
        except Exception as e:
            return (name, "error", None, 0.0, str(e))

    with _cf.ThreadPoolExecutor(max_workers=SOURCE_PARALLEL_WORKERS) as pool:
        futures = {pool.submit(_run_source, item): item
                   for item in SOURCE_REGISTRY}
        done, not_done = _cf.wait(futures, timeout=SOURCE_TOTAL_TIMEOUT)

        for fut in done:
            name = futures[fut][0]
            try:
                name, status, found, dt, err = fut.result(timeout=0)
            except Exception as e:
                log.warn(f"  {name:<16} exception: {e}")
                result.sources_tried.append({
                    "name": name, "status": "error", "error": str(e)})
                continue

            if status == "skipped":
                log.info(f"  {name:<16} skipped ({err})")
                result.sources_tried.append({
                    "name": name, "status": "skipped", "reason": err})
            elif status == "error":
                log.warn(f"  {name:<16} failed: {err}")
                result.sources_tried.append({
                    "name": name, "status": "error", "error": err})
            else:
                for c in found:
                    if c.ip in all_candidates:
                        for s in c.sources:
                            all_candidates[c.ip].add_source(
                                s, c.evidence[0] if c.evidence else "")
                    else:
                        all_candidates[c.ip] = c
                log.ok(f"  {name:<16} {len(found)} candidate(s) ({dt:.1f}s)")
                result.sources_tried.append({
                    "name": name, "status": "ok",
                    "candidates": len(found), "seconds": round(dt, 1)})

        for fut in not_done:
            name = futures[fut][0]
            log.warn(f"  {name:<16} timed out")
            result.sources_tried.append({"name": name, "status": "timeout"})

    result.candidates = list(all_candidates.values())
    log.ok(f"  Total unique candidates: {len(result.candidates)}")

    # Step 3: filter CDN ranges
    non_cdn: list[Candidate] = []
    for c in result.candidates:
        in_cdn, provider = cdn_mgr.is_cdn_ip(c.ip)
        c.in_cdn_range = in_cdn
        c.cdn_provider = provider
        if not in_cdn:
            non_cdn.append(c)
    log.info(f"  Non-CDN candidates: {len(non_cdn)}")

    if not non_cdn:
        log.info("  No non-CDN candidates to validate")
        result.elapsed_seconds = round(time.monotonic() - start, 2)
        return result

    # Step 4: validate
    log.rune(Rune.ALGIZ, "Validation")
    for cand in non_cdn:
        try:
            _validate_candidate(cand, host, baseline, session)
            if cand.confidence == Confidence.CONFIRMED:
                result.confirmed.append(cand)
                log.ok(f"  {cand.ip:<16} CONFIRMED "
                       f"(html={cand.html_score:.2f} cert={cand.cert_score:.2f} "
                       f"hdr={cand.header_score:.2f})")
                if fast_exit_on_confirm and not aggressive:
                    log.info("  fast mode: stopping validation on first confirm")
                    break
            elif cand.confidence == Confidence.HIGH:
                result.confirmed.append(cand)
                log.info(f"  {cand.ip:<16} HIGH "
                          f"(score={cand.overall_score:.2f})")
            elif cand.confidence == Confidence.MEDIUM:
                log.info(f"  {cand.ip:<16} MEDIUM "
                          f"(score={cand.overall_score:.2f})")
            else:
                log.debug(f"  {cand.ip:<16} LOW "
                           f"(score={cand.overall_score:.2f})")
        except Exception as e:
            log.warn(f"  validation failed for {cand.ip}: {e}")
        # Randomized sleep between validation attempts
        time.sleep(random.uniform(*VALIDATION_SLEEP))

    # Step 5: severity + chains
    for c in result.confirmed:
        _apply_severity(c, result.cdn_ips)

    result.elapsed_seconds = round(time.monotonic() - start, 2)
    return result


def _apply_severity(c: Candidate, target_cdn_ips: list[str]) -> None:
    """
    Attach risk severity. Handles PaaS edge detection — if the confirmed IP
    is one of the target's OWN resolution IPs, it's the CDN/PaaS edge, not
    a bypass. Mark as INFO + origin-paas-edge.
    """
    if c.confidence != Confidence.CONFIRMED:
        if c.confidence == Confidence.HIGH:
            c.severity = Severity.MEDIUM
            c.reasons.append("partial match")
        else:
            c.severity = Severity.LOW
            c.reasons.append("candidate but unconfirmed")
        return

    # PaaS edge: confirmed IP = target's own resolution (Vercel, Netlify, etc.)
    if c.ip in target_cdn_ips:
        c.chain_ids.append("origin-paas-edge")
        c.severity = Severity.INFO
        c.reasons.append("Confirmed IP = target's own resolution "
                          "(PaaS/CDN edge — not a bypass)")
        return

    # Real bypass found via alternative sources
    if c.html_score >= 0.85 and c.cert_score >= 0.75:
        c.severity = Severity.CRITICAL
        c.reasons.append("HTML + cert strong match on non-CDN IP")
    elif c.html_score >= 0.70:
        c.severity = Severity.HIGH
        c.reasons.append("HTML match on non-CDN IP")
    else:
        c.severity = Severity.HIGH
        c.reasons.append("validated direct origin")

    if "origin-waf-disabled" in c.chain_ids:
        c.reasons.append("WAF headers absent — origin not filtering")


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  AI TRIAGE
# ══════════════════════════════════════════════════════════════════════════

AI_SYSTEM_PROMPT = (
    "You are an expert offensive-security analyst reviewing CDN origin IP "
    "discovery results. For each confirmed origin, explain the risk and what "
    "manual tests to run next. Never suggest exploits. Be concise."
)


def _run_ai_triage(results: list[HostResult], outdir: Path) -> Optional[dict]:
    if not CFG_LOADED or not bool(_cfg("AI_ENABLED", False)):
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None

    # Only triage real bypass findings, not PaaS edges
    with_real_bypass = []
    for r in results:
        real = [c for c in r.confirmed if "origin-paas-edge" not in c.chain_ids]
        if real:
            with_real_bypass.append((r, real))

    if not with_real_bypass:
        log.info("AI triage: no real bypass findings to analyze")
        return None

    block = []
    for r, cands in with_real_bypass[:20]:
        for c in cands[:3]:
            block.append(
                f"  {r.host:<40} → {c.ip:<16} "
                f"[{c.confidence.value}] html={c.html_score:.2f} "
                f"cert={c.cert_score:.2f} sources={','.join(c.sources)}")
    if not block:
        return None

    prompt = (
        f"Origin IP discovery found CONFIRMED non-PaaS origins on "
        f"{len(with_real_bypass)} host(s):\n\n" + "\n".join(block) + "\n\n"
        "Provide:\n"
        "1. Top 5 origin IPs to investigate manually, with reasoning.\n"
        "2. Risk of each (what's directly reachable that shouldn't be).\n"
        "3. Manual verification steps to confirm each origin is real.\n"
        "Under 600 words. Markdown."
    )

    log.info("AI triage: requesting analyst summary...")
    try:
        response = ai_fn(prompt, system=AI_SYSTEM_PROMPT)
    except Exception as e:
        log.warn(f"AI triage failed: {e}")
        return None
    if not response:
        return None

    md_path = outdir / "origin_hunt_ai_analysis.md"
    md_path.write_text(
        f"# FENRIR'S SIGHT · Origin IP AI Triage\n\n"
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n"
        f"**Hosts with confirmed non-PaaS origins:** {len(with_real_bypass)}\n\n"
        f"---\n\n{response}\n",
        encoding="utf-8")
    log.ok(f"AI triage saved: {md_path.name}")

    cost = None
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            cost = round(tracker.estimate_cost(), 6)
    except Exception:
        pass
    return {"path": str(md_path), "cost_estimate": cost}


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  INPUT LOADING
# ══════════════════════════════════════════════════════════════════════════

def _load_targets(input_file, domain, only_confirmed):
    if domain:
        return [domain.lower().strip()]
    if not input_file or not input_file.exists():
        raise FileNotFoundError(f"input not found: {input_file}")

    hosts: set[str] = set()
    if input_file.suffix == ".json":
        try:
            data = json.loads(input_file.read_text(encoding="utf-8"))
            for h in data.get("hosts", []):
                if only_confirmed and h.get("severity") not in ("HIGH", "CRITICAL"):
                    continue
                host = h.get("host") or urllib.parse.urlparse(
                    h.get("url", "")).hostname
                if host:
                    hosts.add(host.lower())
            for rec in data.get("subdomains", []):
                if rec.get("resolves"):
                    hosts.add(rec["subdomain"].lower())
        except Exception as e:
            log.warn(f"JSON parse failed: {e}")

    if not hosts:
        for line in input_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            token = line.split()[0]
            host = urllib.parse.urlparse(
                token if "://" in token else f"https://{token}").hostname
            if host:
                hosts.add(host.lower())

    return sorted(hosts)


def _load_resume_hosts(jsonl_path: Path) -> set[str]:
    done = set()
    if not jsonl_path.exists():
        return done
    try:
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
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
#  ᛜ  OUTPUT
# ══════════════════════════════════════════════════════════════════════════

def _candidate_to_dict(c: Candidate) -> dict:
    return {
        "ip": c.ip,
        "sources": c.sources,
        "evidence": c.evidence[:10],
        "in_cdn_range": c.in_cdn_range,
        "cdn_provider": c.cdn_provider,
        "validated": c.validated,
        "confidence": c.confidence.value,
        "severity": c.severity.value,
        "scores": {
            "html": round(c.html_score, 3),
            "cert": round(c.cert_score, 3),
            "headers": round(c.header_score, 3),
            "overall": round(c.overall_score, 3),
        },
        "chain_ids": c.chain_ids,
        "reasons": c.reasons,
        "validation_details": c.validation_details,
    }


def _host_to_dict(r: HostResult) -> dict:
    return {
        "host": r.host,
        "base_url": r.base_url,
        "cdn_ips": r.cdn_ips,
        "cdn_provider": r.cdn_provider,
        "baseline": r.baseline,
        "totals": {
            "candidates": len(r.candidates),
            "confirmed": len(r.confirmed),
            "real_bypass": sum(1 for c in r.confirmed
                                if "origin-paas-edge" not in c.chain_ids),
        },
        "sources_tried": r.sources_tried,
        "confirmed_origins": [_candidate_to_dict(c) for c in r.confirmed],
        "all_candidates": [_candidate_to_dict(c)
                            for c in r.candidates if not c.in_cdn_range],
        "errors": r.errors,
    }


def _write_output(results, outdir, elapsed, cdn_mgr, keys, audit_path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    chains: dict[str, list[str]] = {}
    all_confirmed = 0
    all_candidates = 0
    real_bypass = 0
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for r in results:
        all_candidates += len(r.candidates)
        for c in r.confirmed:
            all_confirmed += 1
            by_sev[c.severity.value] = by_sev.get(c.severity.value, 0) + 1
            if "origin-paas-edge" not in c.chain_ids:
                real_bypass += 1
            for cid in c.chain_ids:
                chains.setdefault(cid, []).append(f"{r.host}→{c.ip}")

    chain_list = []
    for cid, members in chains.items():
        chain_list.append({
            "chain_id": cid,
            "name": CHAIN_NAMES.get(cid, cid),
            "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
            "members": members[:100],
            "count": len(members),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    chain_list.sort(key=lambda c: (order.get(c["severity"], 5), c["chain_id"]))

    report = {
        "schema_version": 2,
        "producer": f"origin_hunter.py v{__version__} '{__codename__}'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "host_capacity": {
            "cpu_cores": HOST_CORES, "ram_mb": HOST_RAM_MB,
            "lightweight": LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "api_keys": keys.summary(),
            "cdn_providers": {p: len(n) for p, n in cdn_mgr.ranges.items()},
            "source_count": len(SOURCE_REGISTRY),
        },
        "audit": {
            "trail_path": str(audit_path) if audit_path else None,
            "trail_sha256": _audit_hash(audit_path),
        },
        "totals": {
            "hosts": len(results),
            "candidates": all_candidates,
            "confirmed_origins": all_confirmed,
            "real_bypass_findings": real_bypass,
            "by_severity": by_sev,
        },
        "chains": chain_list,
        "hosts": [_host_to_dict(r) for r in results],
    }
    path = outdir / "origin_hunt.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                     encoding="utf-8")
    return path


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


def _print_summary(results, elapsed) -> None:
    log.rune(Rune.SOWILO, "Summary")
    total_confirmed = sum(len(r.confirmed) for r in results)
    total_real = sum(1 for r in results for c in r.confirmed
                     if "origin-paas-edge" not in c.chain_ids)
    total_candidates = sum(len(r.candidates) for r in results)

    log.info(f"Hosts scanned     : {len(results)}")
    log.info(f"Candidates found  : {total_candidates}")
    log.info(f"Confirmed origins : {total_confirmed}")
    log.info(f"  └─ real bypass  : {total_real}")
    log.info(f"  └─ paas edge    : {total_confirmed - total_real}")

    if total_confirmed:
        log.info("")
        log.ok("Confirmed origin IPs:")
        for r in results:
            for c in r.confirmed:
                paas = " (PaaS edge)" if "origin-paas-edge" in c.chain_ids else ""
                log.info(f"  {Sym.ARROW} {r.host[:42]:<42} → "
                          f"{c.ip:<16} [{c.severity.value:<8}] "
                          f"({c.confidence.value}){paas}")

    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def hunt_origins(input_file=None, outdir=None, *, domain=None,
                  only_confirmed=False, aggressive=True,
                  fast_exit_on_confirm=True, use_proxy=True,
                  bbp_program=None, api_keys=None, resume=False,
                  scan_id=None, dry_run=False) -> Path:
    start = time.monotonic()
    outdir = outdir or (_cfg("OUTPUT_DIR") or Path("output"))
    outdir.mkdir(parents=True, exist_ok=True)

    targets = _load_targets(input_file, domain, only_confirmed)
    log.info(f"Input  : {len(targets)} host(s)")
    if not targets:
        log.warn("no targets to hunt")
        return _write_empty(outdir, input_file, start)

    stream_path = outdir / "origin_hunt_hosts.jsonl"
    if resume:
        done = _load_resume_hosts(stream_path)
        if done:
            targets = [t for t in targets if t not in done]
            log.info(f"Resume : skipping {len(done)} host(s) — "
                      f"{len(targets)} remaining")
    elif stream_path.exists():
        stream_path.unlink()

    cdn_mgr = CdnRangeManager()
    cdn_mgr.load()

    keys = ApiKeyStore(overrides=api_keys)
    log.info("API keys: " + " ".join(
        f"{k}={'✓' if v else '✗'}" for k, v in keys.summary().items()))

    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        for h in targets[:20]:
            log.info(f"  would hunt {h}")
        if len(targets) > 20:
            log.info(f"  … and {len(targets) - 20} more")
        return outdir / "origin_hunt.json"

    proxy_pool = None
    if use_proxy:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls:
                proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
        except Exception:
            pass

    audit_trail = None
    try:
        factory = _cfg("new_audit_trail")
        if callable(factory):
            audit_trail = factory("origin-" + (input_file.stem if input_file else domain or "scan"))
    except Exception:
        pass

    all_results: list[HostResult] = []
    for i, host in enumerate(targets, 1):
        log.rune(Rune.OTHALA, f"[{i}/{len(targets)}] {host}")
        try:
            session = HttpSession(
                host=host, bbp_program=bbp_program,
                proxy_pool=proxy_pool, audit_trail=audit_trail,
                use_proxy=use_proxy,
            )
            if proxy_pool is not None:
                log.info(f"  proxies: rotating from pool")
            else:
                log.info(f"  proxies: direct")

            res = hunt_host(host, session=session, cdn_mgr=cdn_mgr,
                              keys=keys, aggressive=aggressive,
                              fast_exit_on_confirm=fast_exit_on_confirm)
            all_results.append(res)

            with stream_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(_host_to_dict(res), ensure_ascii=False) + "\n")

            real = sum(1 for c in res.confirmed
                       if "origin-paas-edge" not in c.chain_ids)
            log.ok(f"  {len(res.confirmed)} confirmed ({real} real bypass) / "
                    f"{len(res.candidates)} candidates ({res.elapsed_seconds:.1f}s)")

        except Exception as e:
            log.error(f"  host failed: {type(e).__name__}: {e}")
            all_results.append(HostResult(host=host, errors=[str(e)],
                                            elapsed_seconds=0))

    elapsed = time.monotonic() - start
    audit_path = getattr(audit_trail, "path", None) if audit_trail else None
    json_path = _write_output(all_results, outdir, elapsed, cdn_mgr,
                                keys, audit_path)

    log.rune(Rune.GEBO, "Mimir's Well · AI triage")
    _run_ai_triage(all_results, outdir)

    _print_summary(all_results, elapsed)
    log.info(f"Output: {json_path}")
    return json_path


def _write_empty(outdir, input_file, start):
    path = outdir / "origin_hunt.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "producer": f"origin_hunter.py v{__version__} '{__codename__}'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file) if input_file else None,
        "totals": {"hosts": 0, "candidates": 0, "confirmed_origins": 0,
                    "real_bypass_findings": 0,
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                                     "LOW": 0, "INFO": 0}},
        "chains": [], "hosts": [],
    }, indent=2) + "\n")
    return path


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST / CONFIG-CHECK / CHECK-KEYS
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · FENRIR'S SIGHT integrity")

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",            lambda: CFG_LOADED),
        ("Severity enum",            lambda: Severity.CRITICAL.rank == 4),
        ("Confidence enum",          lambda: Confidence.CONFIRMED.rank == 3),
        ("_is_ip v4",                lambda: _is_ip("1.2.3.4")),
        ("_is_ip reject",            lambda: not _is_ip("not-an-ip")),
        ("_extract_title",           lambda: _extract_title(
                                        "<html><title>Hi</title></html>") == "Hi"),
        ("_normalize_body strips",   lambda: "<script" not in _normalize_body(
                                        "<html><script>x</script>b</html>")),
        ("_murmurhash3_32 empty",    lambda: _murmurhash3_32(b"") == 0),
        ("_murmurhash3_32 known",    lambda: _murmurhash3_32(b"hello") == 613153351),
        ("CdnRangeManager init",     lambda: CdnRangeManager() is not None),
        ("ApiKeyStore init",         lambda: ApiKeyStore() is not None),
        ("ApiKeyStore summary",      lambda: set(ApiKeyStore().summary().keys()) ==
                                        {"shodan","censys","securitytrails","virustotal"}),
        # PATCH A: source count is now 13
        ("SOURCE_REGISTRY len == 13", lambda: len(SOURCE_REGISTRY) == 13),
        ("SOURCE_REGISTRY names",    lambda: [s[0] for s in SOURCE_REGISTRY] == [
                                        "crt.sh", "rapiddns", "anubis", "threatcrowd",
                                        "urlscan", "otx", "subdomain_leak",
                                        "wayback", "hackertarget", "virustotal",
                                        "securitytrails", "censys", "shodan_favicon"]),
        ("CHAIN_NAMES has paas-edge", lambda: "origin-paas-edge" in CHAIN_NAMES),
        ("CHAIN_NAMES count",        lambda: len(CHAIN_NAMES) >= 13),
        ("CHAIN_SEVERITY count",     lambda: len(CHAIN_SEVERITY) >= 13),
        ("PaaS edge = INFO",         lambda: CHAIN_SEVERITY["origin-paas-edge"] == Severity.INFO),
        ("HttpSession init",         lambda: callable(HttpSession)),
        ("HttpSession.get_bytes",    lambda: hasattr(HttpSession, "get_bytes")),
        ("hunt_host callable",       lambda: callable(hunt_host)),
        ("hunt_origins callable",    lambda: callable(hunt_origins)),
        ("_validate_candidate",      lambda: callable(_validate_candidate)),
        ("_direct_request",          lambda: callable(_direct_request)),
        ("_fetch_ssl_cert callable", lambda: callable(_fetch_ssl_cert)),
        ("_compare_certs",           lambda: _compare_certs(
                                        {"serialNumber": "abc", "subject": {"commonName": "x"}},
                                        {"serialNumber": "abc", "subject": {"commonName": "x"}})[0] >= 0.75),
        ("_compare_headers",         lambda: _compare_headers(
                                        {"Server": "nginx", "X-Powered-By": "PHP"},
                                        {"Server": "nginx", "X-Powered-By": "PHP"})[0] == 1.0),
        ("_apply_severity paas-edge", lambda: (lambda c: (
                                        _apply_severity(c, ["1.2.3.4"]) or
                                        c.severity == Severity.INFO
                                        ))(Candidate(ip="1.2.3.4",
                                                     confidence=Confidence.CONFIRMED,
                                                     html_score=0.9, cert_score=0.8))),
        ("_apply_severity real bypass", lambda: (lambda c: (
                                        _apply_severity(c, ["9.9.9.9"]) or
                                        c.severity == Severity.CRITICAL
                                        ))(Candidate(ip="1.2.3.4",
                                                     confidence=Confidence.CONFIRMED,
                                                     html_score=0.9, cert_score=0.8))),
        ("_load_targets domain",     lambda: _load_targets(None, "x.com", False) == ["x.com"]),
        ("_load_resume_hosts empty", lambda: _load_resume_hosts(Path("/tmp/no-such.jsonl")) == set()),
        ("VALIDATION weights sum 1", lambda: abs(VALIDATION_WEIGHT_HTML + VALIDATION_WEIGHT_CERT +
                                                  VALIDATION_WEIGHT_HEADER - 1.0) < 0.001),
        ("CONFIRMED_THRESHOLD",      lambda: 0.5 <= CONFIRMED_THRESHOLD <= 0.9),
        ("DEFAULT_TIMEOUT sane",     lambda: 5 <= DEFAULT_TIMEOUT <= 60),
        ("_write_empty callable",    lambda: callable(_write_empty)),
        ("_write_output callable",   lambda: callable(_write_output)),
        ("_run_ai_triage callable",  lambda: callable(_run_ai_triage)),
        ("is_cdn_ip callable",       lambda: callable(CdnRangeManager().is_cdn_ip)),
        ("source count matches reg", lambda: len(SOURCE_REGISTRY) == 13),
    ]

    passed = failed = 0
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

    log.info(f"  AI_ENABLED: {_cfg('AI_ENABLED', False)}")

    keys = ApiKeyStore()
    log.info("  API keys:")
    for k, present in keys.summary().items():
        log.info(f"    {k:<16} {'✓ configured' if present else '✗ absent'}")
    log.info(f"  Key file: {API_KEY_FILE}")

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} item(s) unconfigured ══  {Sym.WARN}{_c('reset')}")
    return 0


def check_keys() -> int:
    print_banner()
    log.rune(Rune.GEBO, "API key status")
    keys = ApiKeyStore()
    for k, present in keys.summary().items():
        mark = "✓" if present else "✗"
        log.info(f"  {mark} {k:<16} {'configured' if present else 'missing'}")
    log.info("")
    log.info(f"Key file: {API_KEY_FILE}")
    log.info("")
    log.info("Add keys via:")
    log.info(f"  · {API_KEY_FILE.name} (JSON: {{'shodan': 'KEY', ...}})")
    log.info("  · Env: ARGUS_SHODAN_KEY, ARGUS_CENSYS_ID + ARGUS_CENSYS_SECRET,")
    log.info("         ARGUS_SECURITYTRAILS_KEY, ARGUS_VIRUSTOTAL_KEY")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_hosts.json"
    if not default_input.exists():
        default_input = base / "output" / "subdomains.json"

    p = argparse.ArgumentParser(
        prog="origin_hunter.py",
        description=f"Argus origin hunter v{__version__} '{__codename__}'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--domain", help="hunt a single domain instead of --input")
    p.add_argument("--output", type=Path, default=base / "output")
    p.add_argument("--bbp", help="bug-bounty program profile")
    p.add_argument("--scan-id", type=int)
    p.add_argument("--only-confirmed", action="store_true")
    p.add_argument("--fast", dest="aggressive", action="store_false",
                   default=True, help="exit on first confirmed per host")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--shodan-key")
    p.add_argument("--censys-id")
    p.add_argument("--censys-secret")
    p.add_argument("--securitytrails-key")
    p.add_argument("--virustotal-key")
    p.add_argument("--check-keys", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                   version=f"origin_hunter.py {__version__} '{__codename__}'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try: CFG.Palette._enabled = False
        except Exception: pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()
    if args.check_keys:    return check_keys()

    print_banner()

    overrides = {
        "shodan": args.shodan_key, "censys_id": args.censys_id,
        "censys_secret": args.censys_secret,
        "securitytrails": args.securitytrails_key,
        "virustotal": args.virustotal_key,
    }

    try:
        hunt_origins(
            input_file=args.input if not args.domain else None,
            outdir=args.output, domain=args.domain,
            only_confirmed=args.only_confirmed,
            aggressive=args.aggressive,
            use_proxy=not args.no_proxy,
            bbp_program=args.bbp, api_keys=overrides,
            resume=args.resume, scan_id=args.scan_id,
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
