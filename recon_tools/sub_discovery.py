#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛞ ᚨ ᚷ ᚨ ᛉ   ·   S U B   D I S C O V E R Y   ·   L I V E   H O S T S
================================================================================
  File      : recon_tools/sub_discovery.py
  Version   : 5.1.0 "DAGAZ REBORN"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Live host discovery + deep enrichment for Argus.

  v5.1 changes vs v5.0:
    ·  Proxy PRE-VALIDATION: test the proxy before httpx runs, so a dead
       free proxy is caught in 5 seconds instead of producing 53 fake 403s
    ·  WAF-vs-auth-403 distinction: Cloudflare blocks are classified as
       "waf_blocked" (informational) not "auth_gated" (HIGH severity)
    ·  Full CHAIN_SEVERITY map: all subs.py-inherited chains carry their
       correct severity (recon-staging-environment → HIGH, not LOW)
    ·  Robust evidence writer: handles dict/list/string header shapes,
       logs skip reasons, no more silent zero-file runs
    ·  --no-proxy flag + use_proxy param: bypass proxies for Cloudflare
       targets, or when the pool is known-burned
    ·  --check-proxies mode: health-check the entire pool before scanning
    ·  --fast alias for --no-aggressive (shorter to type)
    ·  Summary shows waf_blocked count separately from auth_gated

  Usage
  ─────
    Standalone:
        python3 recon_tools/sub_discovery.py                    # auto
        python3 recon_tools/sub_discovery.py --no-proxy         # bypass pool
        python3 recon_tools/sub_discovery.py --check-proxies    # test pool
        python3 recon_tools/sub_discovery.py --bbp hackerone
        python3 recon_tools/sub_discovery.py --selftest
        python3 recon_tools/sub_discovery.py --config-check
        python3 recon_tools/sub_discovery.py --dry-run
================================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
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
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False
    _CFG_IMPORT_ERROR = _cfg_err


def _cfg(key: str, default: Any = None) -> Any:
    return getattr(CFG, key, default) if CFG_LOADED else default


# ── Fallback theme ────────────────────────────────────────────────────────

class _FallbackPalette:
    _enabled = sys.stdout.isatty()
    _R = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
          "gold": "\033[38;5;220m", "amber": "\033[38;5;214m",
          "purple": "\033[38;5;135m", "violet": "\033[38;5;93m",
          "crimson": "\033[38;5;160m", "blood": "\033[38;5;196m",
          "green": "\033[38;5;46m", "moss": "\033[38;5;118m",
          "blue": "\033[38;5;33m", "cyan": "\033[38;5;51m",
          "ice": "\033[38;5;159m", "grey": "\033[38;5;242m",
          "silver": "\033[38;5;250m", "orange": "\033[38;5;208m",
          "pink": "\033[38;5;213m"}

    @classmethod
    def c(cls, name: str) -> str:
        return cls._R.get(name, "") if cls._enabled else ""


def _c(name: str) -> str:
    if CFG_LOADED and hasattr(CFG, "_c"):
        return CFG._c(name)
    return _FallbackPalette.c(name)


class _FallbackLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self, log_file: Optional[Path] = None):
        self.min_level = "info"
        self._log = logging.getLogger("argus.sub_discovery")
        self._log.setLevel(logging.DEBUG)
        self._log.propagate = False
        if self._log.handlers:
            self._log.handlers.clear()
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(logging.Formatter(
                    "%(asctime)s [%(levelname)-8s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"))
                self._log.addHandler(fh)
            except OSError:
                pass

    def _emit(self, level, msg, color, prefix):
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")
        method = {"warn": "warning", "fatal": "critical"}.get(level, level)
        if self._log.handlers:
            getattr(self._log, method, self._log.info)(msg)

    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info (self, m): self._emit("info",  m, "cyan", "·")
    def warn (self, m): self._emit("warn",  m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def ok   (self, m): self._emit("info",  m, "green", "✓")
    def fatal(self, m): self._emit("fatal", m, "blood", "☠")

    def rune(self, rune, msg):
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")
        if self._log.handlers:
            self._log.info(f"[{rune}] {msg}")


log = _cfg("log") or _FallbackLogger()


class Sym:
    RAVEN = "🦅"; WOLF = "🐺"; SHIELD = "🛡"; SWORD = "⚔"; HAMMER = "🔨"
    TREE = "🌳"; FIRE = "🔥"; SHAMROCK = "☘"; STAR = "★"; ARROW = "➤"
    CHECK = "✓"; CROSS = "✗"; WARN = "⚠"; INFO = "·"; DOT = "᛫"
    SKULL = "☠"; LOCK = "🔒"; GEAR = "⚙"


class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛞ ᚨ ᚷ ᚨ ᛉ{R}
    {P}{rule}{R}
    {V}      S U B   D I S C O V E R Y   ·   L I V E   H O S T S{R}
    {V}             T H E   D A W N   B R E A K S{R}
    {D}{rule}{R}
    {G}          {Sym.STAR}  v{__version__} "{__codename__}"  ·  live recon{R}
    {G}          {Sym.GEAR}  config v{_cfg('__version__', 'missing')} {R}
    {G}          {Sym.SHAMROCK}  BeardedVikingTX  ·  {_cfg('AUTHOR_EMAIL', 'security@beardedviking.org')}{R}
    {P}{rule}{R}
""")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SEVERITY
# ══════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════

__version__ = "5.1.0"
__codename__ = "DAGAZ REBORN"

DEFAULT_THREADS    = 50
DEFAULT_RATE_LIMIT = 150
DEFAULT_TIMEOUT    = 10
DEFAULT_RETRIES    = 2

HTTPX_HARD_TIMEOUT        = 3600
BODY_PREVIEW_LEN          = 500
BODY_PREVIEW_AGGRESSIVE   = 2000

ENABLE_TECH_DETECT      = True
ENABLE_CNAME            = True
ENABLE_CDN              = True
ENABLE_FAVICON          = True
ENABLE_JARM             = False
ENABLE_TLS_GRAB         = False
ENABLE_FOLLOW_REDIRECTS = True
ENABLE_BODY_PREVIEW     = True

GEO_ENABLED     = True
GEO_BATCH_SIZE  = 100
GEO_RATE_SLEEP  = 1.5
GEO_TIMEOUT     = 15
GEO_CACHE_FILE  = "geo_cache.json"

PROXY_VALIDATE_TIMEOUT  = 8.0
PROXY_VALIDATE_MAX_TRIES = 3

ENRICH_FROM_SOURCES_JSON = True
SOURCES_JSON_NAME        = "subdomains.json"
INTERESTING_MIN_SCORE    = 20


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
        elif sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True).stdout
            ram_mb = int(out.strip()) // (1024 * 1024) if out.strip() else 0
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


def _effective_threads(requested: int) -> int:
    if not LIGHTWEIGHT_MODE:
        return requested
    return max(1, min(requested, 8))


# ── Service categorization ────────────────────────────────────────────────
SERVICE_CATEGORIES: dict[str, list[str]] = {
    "web_server": ["nginx", "apache", "iis", "caddy", "litespeed",
                   "openresty", "traefik", "haproxy", "varnish", "envoy",
                   "lighttpd"],
    "cdn": ["cloudflare", "akamai", "fastly", "cloudfront", "azure cdn",
            "bunny cdn", "stackpath", "keycdn", "sucuri", "imperva"],
    "framework": ["django", "flask", "rails", "laravel", "express", "next.js",
                  "nuxt", "gatsby", "spring", "asp.net", "phoenix", "sinatra",
                  "fastapi", "rocket", "actix", "vertx"],
    "cms": ["wordpress", "drupal", "joomla", "magento", "ghost", "wix",
            "squarespace", "webflow", "typo3", "craft cms", "concrete cms",
            "shopify", "woocommerce"],
    "language": ["php", "ruby", "python", "java", "node.js", "go", "rust",
                 "perl", ".net"],
    "database_ui": ["phpmyadmin", "adminer", "mongo-express",
                    "redis-commander", "pgadmin", "dbeaver", "sequel pro",
                    "mywebsql"],
    "monitoring": ["grafana", "kibana", "prometheus", "zabbix", "nagios",
                   "newrelic", "datadog", "sentry", "graylog", "jaeger"],
    "ci_cd": ["jenkins", "gitlab", "teamcity", "bamboo", "circleci",
              "travis ci", "drone", "argo", "tekton", "spinnaker"],
    "documentation": ["swagger ui", "redoc", "gitbook", "mkdocs", "confluence",
                      "docusaurus", "sphinx", "readme.io", "slate"],
    "auth": ["keycloak", "auth0", "okta", "cas", "shibboleth", "authentik",
             "fusionauth", "ory"],
}


TECH_MIN_SAFE_VERSION: dict[str, tuple[int, int, Optional[int], str]] = {
    "nginx":   (1, 20, 1,    "CVE-2021-23017"),
    "apache":  (2, 4,  51,   "CVE-2021-42013"),
    "httpd":   (2, 4,  51,   "CVE-2021-42013"),
    "openssh": (9, 8,  None, "CVE-2024-6387 (regreSSHion)"),
    "log4j":   (2, 17, 0,    "CVE-2021-44228 (Log4Shell)"),
    "spring":  (5, 3,  18,   "CVE-2022-22965 (Spring4Shell)"),
    "struts":  (2, 5,  30,   "CVE-2017-5638"),
    "tomcat":  (9, 0,  63,   "CVE-2021-25329"),
    "iis":     (10, 0, None, "unsupported version"),
}


WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai":      ["akamai-grn", "x-akamai-transformed", "_abck"],
    "Imperva":     ["x-iinfo", "incap_ses", "_incapsula_resource"],
    "AWS WAF":     ["x-amzn-requestid", "x-amzn-errortype", "awselb"],
    "F5 BIG-IP":   ["x-wa-info", "bigipserver"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "DataDome":    ["x-datadome", "datadome"],
    "ModSecurity": ["x-mod-security"],
}


# Definitive WAF-block signals (v5.1)
# cf-mitigated, x-datadome, x-sucuri-block are block-page-specific.
# Presence of these + 403 = WAF blocked, not origin auth boundary.
WAF_BLOCK_HEADERS = (
    "cf-mitigated", "x-datadome", "x-sucuri-block",
    "x-akamai-bot-manager", "incap-block",
)


ADMIN_TITLE_KEYWORDS = (
    "admin", "administrator", "dashboard", "management", "console",
    "control panel", "login", "sign in", "phpmyadmin", "adminer",
    "kibana", "grafana", "jenkins", "swagger ui", "prometheus",
    "tomcat manager", "webmin", "cpanel", "plesk",
)

DEBUG_PATH_KEYWORDS = (
    "/actuator", "/debug", "/trace", "/phpinfo", "/.env",
    "/swagger", "/api-docs", "/graphiql", "/api/graphql",
)

DEFAULT_PAGE_TITLES = (
    "welcome to nginx", "apache2 ubuntu default page",
    "apache2 debian default page", "apache http server test page",
    "iis windows server", "test page for the apache",
)


# ── Chain names + severity map (v5.1: FULL subs.py inheritance) ──────────
CHAIN_NAMES: dict[str, str] = {
    # httpx-detected
    "recon-admin-surface":    "Admin panel reachable",
    "recon-api-surface":      "API endpoints discovered",
    "recon-auth-gated":       "Auth-protected resources",
    "recon-debug-exposed":    "Debug/actuator endpoints exposed",
    "recon-database-ui":      "Database UI exposed (phpMyAdmin/Adminer)",
    "recon-eol-software":     "End-of-life software with known CVE",
    "recon-staging":          "Staging/dev environment live",
    "recon-default-install":  "Default vendor page",
    "recon-waf-protected":    "WAF-fronted host",
    "recon-waf-blocked":      "WAF-blocked (auto-detection)",
    "recon-cors-wildcard":    "Permissive CORS",
    "recon-multi-tenant":     "Multi-tenant IP (isolation risk)",
    "recon-cloud-hosted":     "Cloud-hosted (from CNAME)",
    "recon-security-headers": "Missing HSTS/CSP/XFO",
    # subs.py-inherited
    "recon-database-exposed":   "Exposed database service",
    "recon-cicd-exposed":       "Exposed CI/CD system",
    "recon-source-leak":        "Source code exposure",
    "recon-payment-surface":    "Payment / billing surface",
    "recon-identity-surface":   "Identity / auth surface",
    "recon-staging-environment":"Staging/dev environment",
    "recon-vpn-surface":        "VPN / remote access",
    "recon-backup-exposure":    "Backup/legacy infrastructure",
    "recon-monitoring-exposed": "Monitoring endpoint",
    "recon-internal-leak":      "Internal infrastructure leak",
    "recon-api-discovery":      "API surface",
    "recon-deprecated-api":     "Deprecated API version",
    "recon-commerce-surface":   "Commerce surface",
    "recon-storage-exposure":   "Storage / CDN",
    "recon-proxy-surface":      "Proxy / load balancer",
    "recon-wildcard":           "Wildcard DNS on root",
    "recon-mass-enum":          "Large enumeration result",
}

CHAIN_SEVERITY: dict[str, Severity] = {
    # httpx-native
    "recon-admin-surface":      Severity.HIGH,
    "recon-api-surface":        Severity.MEDIUM,
    "recon-auth-gated":         Severity.HIGH,
    "recon-debug-exposed":      Severity.HIGH,
    "recon-database-ui":        Severity.CRITICAL,
    "recon-eol-software":       Severity.HIGH,
    "recon-staging":            Severity.HIGH,
    "recon-default-install":    Severity.LOW,
    "recon-waf-protected":      Severity.INFO,
    "recon-waf-blocked":        Severity.INFO,
    "recon-cors-wildcard":      Severity.MEDIUM,
    "recon-multi-tenant":       Severity.MEDIUM,
    "recon-cloud-hosted":       Severity.INFO,
    "recon-security-headers":   Severity.LOW,
    # subs.py-inherited — CRITICAL
    "recon-database-exposed":   Severity.CRITICAL,
    "recon-cicd-exposed":       Severity.CRITICAL,
    "recon-source-leak":        Severity.CRITICAL,
    # subs.py-inherited — HIGH
    "recon-payment-surface":    Severity.HIGH,
    "recon-identity-surface":   Severity.HIGH,
    "recon-staging-environment":Severity.HIGH,
    "recon-vpn-surface":        Severity.HIGH,
    "recon-backup-exposure":    Severity.HIGH,
    "recon-monitoring-exposed": Severity.HIGH,
    "recon-internal-leak":      Severity.HIGH,
    # subs.py-inherited — MEDIUM
    "recon-api-discovery":      Severity.MEDIUM,
    "recon-deprecated-api":     Severity.MEDIUM,
    "recon-commerce-surface":   Severity.MEDIUM,
    "recon-storage-exposure":   Severity.MEDIUM,
    "recon-proxy-surface":      Severity.MEDIUM,
    "recon-wildcard":           Severity.MEDIUM,
    "recon-mass-enum":          Severity.MEDIUM,
}


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _normalize_host(name: str) -> Optional[str]:
    if not name:
        return None
    s = name.strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/")[0].split("?")[0]
    if ":" in s:
        s = s.split(":")[0]
    return s or None


def _first_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _get_header(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup — handles dict, list, string shapes."""
    if not headers:
        return None
    target = name.lower()

    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == target:
                if isinstance(v, list):
                    return str(v[0]) if v else None
                return str(v)
        return None

    if isinstance(headers, list):
        for line in headers:
            line_str = str(line)
            if ":" in line_str:
                k, _, v = line_str.partition(":")
                if k.strip().lower() == target:
                    return v.strip()
        return None

    if isinstance(headers, str):
        for line in headers.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                if k.strip().lower() == target:
                    return v.strip()
        return None

    return None


def _parse_version(version_str: str) -> Optional[tuple[int, int, Optional[int]]]:
    if not version_str:
        return None
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)),
            int(m.group(3)) if m.group(3) else None)


def _version_lt(v1: tuple, v2: tuple) -> bool:
    v1p = v1 + (0,) * (3 - len(v1)) if len(v1) < 3 else v1[:3]
    v2p = v2 + (0,) * (3 - len(v2)) if len(v2) < 3 else v2[:3]
    return v1p < v2p


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  PROXY — pick, validate, fall back
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ProxyChoice:
    url: str
    protocol: str
    host: str
    port: int
    latency_ms: float = 0.0


def _validate_proxy(proxy_choice: ProxyChoice,
                    timeout: float = PROXY_VALIDATE_TIMEOUT) -> tuple[bool, float, str]:
    """
    Test a proxy with a lightweight HTTP request before using it for httpx.
    Returns (ok, latency_seconds, detail).
    """
    handler = urllib.request.ProxyHandler({
        "http": proxy_choice.url, "https": proxy_choice.url,
    })
    opener = urllib.request.build_opener(handler)
    start = time.monotonic()
    try:
        with opener.open("http://httpbin.org/ip", timeout=timeout) as resp:
            body = resp.read(512)
        latency = time.monotonic() - start
        if b"origin" in body:
            return True, latency, "ok"
        return False, latency, "unexpected response"
    except urllib.error.HTTPError as e:
        return False, time.monotonic() - start, f"HTTP {e.code}"
    except Exception as e:
        return False, time.monotonic() - start, f"{type(e).__name__}: {e}"


def _pick_and_validate_proxy(proxy_pool: Any
                              ) -> tuple[Optional[ProxyChoice], str]:
    """
    Pick a proxy from the pool and validate it before use.
    Tries up to PROXY_VALIDATE_MAX_TRIES proxies.

    Returns (proxy_choice_or_None, status_message).
    """
    if proxy_pool is None:
        return None, "no pool"

    for attempt in range(1, PROXY_VALIDATE_MAX_TRIES + 1):
        try:
            raw = proxy_pool.pick()
        except Exception as e:
            return None, f"pool pick error: {e}"
        if raw is None:
            return None, "pool exhausted"

        choice = ProxyChoice(
            url=raw.url(), protocol=raw.protocol,
            host=raw.host, port=raw.port,
        )
        log.debug(f"    validating proxy {choice.host}:{choice.port} "
                  f"({attempt}/{PROXY_VALIDATE_MAX_TRIES})...")
        ok, latency, detail = _validate_proxy(choice)
        if ok:
            choice.latency_ms = latency * 1000
            try:
                if hasattr(proxy_pool, "report_success") and raw is not None:
                    proxy_pool.report_success(raw, latency)
            except Exception:
                pass
            return choice, f"validated ({choice.latency_ms:.0f}ms)"

        log.warn(f"    proxy {choice.host}:{choice.port} failed validation: {detail}")
        try:
            if hasattr(proxy_pool, "report_failure") and raw is not None:
                proxy_pool.report_failure(raw)
        except Exception:
            pass

    return None, f"all {PROXY_VALIDATE_MAX_TRIES} attempts failed validation"


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  HEADERS FOR HTTPX
# ══════════════════════════════════════════════════════════════════════════

def _headers_for_httpx(
    bbp_program: Optional[str] = None,
    extra_headers: Optional[dict] = None,
) -> tuple[list[str], bool, dict[str, str]]:
    merged: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if bbp_program:
        try:
            builder = _cfg("build_headers")
            if callable(builder):
                merged.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
    if extra_headers:
        merged.update(extra_headers)

    args: list[str] = []
    has_ua = False
    for k, v in merged.items():
        args.extend(["-H", f"{k}: {v}"])
        if k.lower() == "user-agent":
            has_ua = True
    return args, not has_ua, merged


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  HTTPX EXECUTION
# ══════════════════════════════════════════════════════════════════════════

def _build_httpx_cmd(
    subs_file: Path,
    threads: int,
    rate_limit: int,
    timeout: int,
    retries: int,
    header_args: list[str],
    randomize_ua: bool,
    body_preview_len: int,
    proxy: Optional[ProxyChoice],
    aggressive: bool,
) -> list[str]:
    cmd = [
        "httpx", "-l", str(subs_file),
        "-json", "-silent",
        "-sc", "-title", "-web-server", "-ip",
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-retries", str(retries),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])
    if ENABLE_TECH_DETECT:      cmd.append("-tech-detect")
    if ENABLE_CNAME:            cmd.append("-cname")
    if ENABLE_CDN:              cmd.append("-cdn")
    if ENABLE_FAVICON:          cmd.append("-favicon")
    if ENABLE_FOLLOW_REDIRECTS: cmd.append("-follow-redirects")
    if ENABLE_BODY_PREVIEW:
        cmd.extend(["-body-preview", str(body_preview_len)])
    cmd.append("-include-response-header")
    if aggressive and ENABLE_JARM:
        cmd.append("-jarm")
    if aggressive and ENABLE_TLS_GRAB:
        cmd.append("-tls-grab")
    if randomize_ua:
        cmd.append("-random-agent")
    if proxy:
        cmd.extend(["-proxy", proxy.url])
    cmd.extend(header_args)
    return cmd


def _run_httpx(
    subs_file: Path, threads: int, rate_limit: int, timeout: int, retries: int,
    header_args: list[str], randomize_ua: bool, evidence_dir: Path,
    body_preview_len: int, proxy: Optional[ProxyChoice],
    aggressive: bool, audit_trail: Any = None,
) -> tuple[list[dict], str, Optional[str]]:
    if not shutil.which("httpx"):
        raise RuntimeError("httpx not found — run `python3 tools.py --only httpx`")

    cmd = _build_httpx_cmd(subs_file, threads, rate_limit, timeout, retries,
                            header_args, randomize_ua, body_preview_len,
                            proxy, aggressive)
    log.debug(f"    $ {' '.join(cmd)}")

    if CFG_LOADED and hasattr(CFG, "KillSwitch"):
        CFG.KillSwitch.check()

    start = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=HTTPX_HARD_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"httpx exceeded {HTTPX_HARD_TIMEOUT}s wall-clock")
    except FileNotFoundError:
        raise RuntimeError("httpx binary vanished mid-run")
    duration = time.monotonic() - start

    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "raw_httpx.txt").write_text(result.stdout[:10_000_000])
    except Exception as e:
        log.debug(f"    raw evidence save failed: {e}")

    if audit_trail is not None:
        try:
            audit_trail.record(
                method="RUN", url=f"httpx://{subs_file.name}",
                status=result.returncode, latency_ms=duration * 1000,
                proxy=proxy.url if proxy else None,
                user_agent="(httpx)",
                error=result.stderr[:200] if result.returncode != 0 else None,
            )
        except Exception:
            pass

    records: list[dict] = []
    parse_errors = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if obj.get("failed") is True:
            continue
        if obj.get("status_code") in (None, 0):
            continue
        records.append(obj)

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")

    stderr = None
    if result.returncode != 0 and not records:
        stderr = result.stderr[:500] or f"httpx exit={result.returncode}"

    return records, result.stdout, stderr


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  GEO / ASN ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════

def _load_geo_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as e:
        log.warning(f"    geo cache unreadable ({e}) — starting fresh")
        return {}


def _save_geo_cache(path: Path, cache: dict[str, dict]) -> None:
    try:
        path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n")
    except Exception as e:
        log.warning(f"    could not save geo cache: {e}")


def _geo_batch(ips: list[str]) -> dict[str, dict]:
    if not ips:
        return {}
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        "http://ip-api.com/batch", data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": f"argus-sub-discovery/{__version__}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning(f"    geo batch failed: {e}")
        return {}

    out: dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, dict) or entry.get("status") != "success":
            continue
        ip = entry.get("query")
        if not ip:
            continue
        out[ip] = {
            "country": entry.get("country"),
            "country_code": entry.get("countryCode"),
            "region": entry.get("regionName"),
            "region_code": entry.get("region"),
            "city": entry.get("city"),
            "zip": entry.get("zip"),
            "lat": entry.get("lat"),
            "lon": entry.get("lon"),
            "timezone": entry.get("timezone"),
            "isp": entry.get("isp"),
            "org": entry.get("org"),
            "asn": entry.get("as"),
            "hosting": entry.get("hosting"),
            "proxy": entry.get("proxy"),
        }
    return out


def _extract_ips(record: dict) -> list[str]:
    ips: list[str] = []
    for key in ("a", "aaaa"):
        val = record.get(key)
        if isinstance(val, list):
            ips.extend(str(x) for x in val if x)
    single = record.get("ip")
    if single and single not in ips:
        ips.append(str(single))
    return ips


def _enrich_geo(records: list[dict], outdir: Path) -> dict[str, dict]:
    all_ips: set[str] = set()
    for rec in records:
        for ip in _extract_ips(rec):
            all_ips.add(ip)
    if not all_ips:
        return {}

    cache_path = outdir / GEO_CACHE_FILE
    cache = _load_geo_cache(cache_path)
    uncached = sorted(ip for ip in all_ips if ip not in cache)

    if uncached:
        log.info(f"    Geo lookup: {len(uncached)} uncached IP(s), "
                 f"{len(all_ips) - len(uncached)} from cache")
        batches = [uncached[i:i + GEO_BATCH_SIZE]
                   for i in range(0, len(uncached), GEO_BATCH_SIZE)]
        for i, batch in enumerate(batches, 1):
            log.info(f"      batch {i}/{len(batches)}: {len(batch)} IP(s)")
            cache.update(_geo_batch(batch))
            if i < len(batches):
                time.sleep(GEO_RATE_SLEEP)
        _save_geo_cache(cache_path, cache)
    else:
        log.info(f"    Geo lookup: all {len(all_ips)} IP(s) served from cache")

    for rec in records:
        ips = _extract_ips(rec)
        rec["geo"] = [cache[ip] for ip in ips if ip in cache]
    return cache


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  SOURCE ATTRIBUTION
# ══════════════════════════════════════════════════════════════════════════

def _load_source_map(outdir: Path) -> dict[str, dict]:
    if not ENRICH_FROM_SOURCES_JSON:
        return {}
    path = outdir / SOURCES_JSON_NAME
    if not path.exists():
        log.debug("    subdomains.json not present — skipping attribution")
        return {}
    try:
        data = json.loads(path.read_text())
        return {rec["subdomain"]: rec
                for rec in data.get("subdomains", [])
                if "subdomain" in rec}
    except Exception as e:
        log.warning(f"    could not parse subdomains.json: {e}")
        return {}


def _apply_attribution(record: dict, subs_rec: dict) -> None:
    if not subs_rec:
        return
    record["sources"]           = subs_rec.get("sources") or []
    record["source_count"]      = subs_rec.get("source_count", len(record["sources"]))
    record["first_seen"]        = subs_rec.get("first_seen")
    record["root"]              = subs_rec.get("root")
    record["wildcard"]          = bool(subs_rec.get("wildcard"))
    record["cloud_provider"]    = subs_rec.get("cloud_provider") or ""
    record["cname_chain"]       = subs_rec.get("cname_chain") or []
    record["subs_sensitive_category"] = subs_rec.get("sensitive_category") or ""
    record["subs_severity"]     = (subs_rec.get("severity") or "LOW").upper()
    record["subs_chain_ids"]    = subs_rec.get("chain_ids") or []
    record["subs_tactics"]      = subs_rec.get("tactics") or []


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  CLASSIFIERS
# ══════════════════════════════════════════════════════════════════════════

def _categorize_services(tech_list: list[str]) -> dict[str, list[str]]:
    tech_lower = [t.lower().strip() for t in (tech_list or [])]
    out: dict[str, list[str]] = {}
    for category, patterns in SERVICE_CATEGORIES.items():
        hits = [t for t in tech_lower
                if any(p in t or t in p for p in patterns)]
        if hits:
            out[category] = hits
    return out


def _detect_eol(tech_list: list[str]) -> list[dict]:
    eol: list[dict] = []
    for tech in (tech_list or []):
        tl = tech.lower()
        for name, min_safe in TECH_MIN_SAFE_VERSION.items():
            if name in tl:
                m = re.search(
                    rf"{re.escape(name)}[/\s-]?(\d+\.\d+(?:\.\d+)?)", tl, re.I)
                if not m:
                    continue
                ver = _parse_version(m.group(1))
                if not ver:
                    continue
                min_tuple = (min_safe[0], min_safe[1],
                             min_safe[2] if min_safe[2] is not None else 0)
                if _version_lt(ver, min_tuple):
                    eol.append({
                        "tech":     name,
                        "version":  m.group(1),
                        "min_safe": ".".join(str(x) for x in min_tuple),
                        "cve":      min_safe[3],
                    })
                break
    return eol


def _detect_waf(headers: Any, tech_list: Optional[list[str]] = None) -> str:
    """Detect WAF from headers OR tech stack (v5.1.1 — headers may be absent)."""
    flat = ""
    if isinstance(headers, dict):
        flat = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    elif isinstance(headers, list):
        flat = " ".join(str(x) for x in headers).lower()
    elif isinstance(headers, str):
        flat = headers.lower()

    # Header-based detection (primary)
    for vendor, patterns in WAF_SIGNATURES.items():
        if any(p in flat for p in patterns):
            return vendor

    # Tech-stack fallback (catches Cloudflare when headers are empty)
    tech_flat = " ".join(str(t).lower() for t in (tech_list or []))
    for vendor in WAF_SIGNATURES:
        vendor_key = vendor.lower().replace(" ", "").replace("-", "")
        if vendor_key in tech_flat.replace(" ", ""):
            return vendor
    if "bot management" in tech_flat or "botmanager" in tech_flat:
        return "Cloudflare"

    return ""


def _analyze_headers(headers: Any, scheme: str) -> dict:
    hsts       = _get_header(headers, "Strict-Transport-Security")
    csp        = _get_header(headers, "Content-Security-Policy")
    xfo        = _get_header(headers, "X-Frame-Options")
    acao       = _get_header(headers, "Access-Control-Allow-Origin")
    acac       = _get_header(headers, "Access-Control-Allow-Credentials")
    set_cookie = _get_header(headers, "Set-Cookie")

    cors_wildcard: Any = False
    if acao == "*":
        cors_wildcard = True
    elif acac and acac.lower() == "true" and acao and "*" not in acao:
        cors_wildcard = "credentials_reflected"

    return {
        "hsts_missing":     scheme == "https" and not hsts,
        "csp_missing":      not csp,
        "xfo_missing":      not xfo,
        "cors_wildcard":    cors_wildcard,
        "cookies_insecure": (bool(set_cookie)
                             and "secure" not in (set_cookie or "").lower()
                             and scheme == "https"),
        "hsts_value":       hsts[:80] if hsts else "",
        "csp_value":        csp[:120] if csp else "",
    }


def _is_waf_block(record: dict, status: int) -> bool:
    """
    Distinguish WAF-blocked 403 from origin auth-boundary 403.
    v5.1.1: handles the case where `web_server` == the WAF vendor name
    (Cloudflare sets `Server: cloudflare`, so `-web-server` reports
    "cloudflare" — never reached origin, but `not web_server` is False).
    """
    if status not in (401, 403):
        return False

    # Strongest signal: WAF block-page headers
    headers = record.get("_headers")
    for h in WAF_BLOCK_HEADERS:
        if _get_header(headers, h):
            return True

    waf_vendor  = (record.get("waf_vendor") or "").lower()
    web_server  = (record.get("web_server") or "").lower()
    tech_flat   = " ".join(str(t).lower() for t in (record.get("technologies") or []))

    # No WAF detected → not a WAF block
    if not waf_vendor:
        return False

    # WAF present AND web_server is empty, equals the WAF, or contains it
    # (Cloudflare's edge sends "Server: cloudflare", not the origin's server)
    if not web_server:
        return True
    if web_server == waf_vendor or waf_vendor in web_server:
        return True

    # WAF present but a *different* origin server leaked through → origin answered
    return False


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════

def _classify(record: dict, subs_rec: Optional[dict]
              ) -> tuple[Severity, list[str], list[str], list[str], int]:
    reasons: list[str] = []
    categories: list[str] = []
    chain_ids: list[str] = []
    sev = Severity.LOW
    score = 0

    status   = record.get("status_code") or 0
    title    = (record.get("title") or "").lower()
    ct       = (record.get("content_type") or "").lower()
    url      = (record.get("url") or "").lower()
    services = record.get("_services") or {}

    # ── Inherit subs.py classification ────────────────────────────────────
    if subs_rec:
        subs_sev  = (subs_rec.get("severity") or "LOW").upper()
        subs_cat  = subs_rec.get("sensitive_category") or ""
        subs_cids = subs_rec.get("chain_ids") or []
        try:
            s = Severity(subs_sev)
            if s.rank > sev.rank:
                sev = s
            if s.rank >= Severity.HIGH.rank:
                score += 20
                reasons.append(f"subs_{subs_cat or 'sensitive'}")
                categories.append(f"subs:{subs_cat}" if subs_cat else "subs")
                chain_ids.extend(c for c in subs_cids if c not in chain_ids)
        except ValueError:
            pass

    # ── Admin / DB UI / CI-CD / monitoring ────────────────────────────────
    is_admin = (any(k in title for k in ADMIN_TITLE_KEYWORDS)
                or "database_ui" in services
                or "ci_cd" in services
                or "monitoring" in services)
    if is_admin:
        if "database_ui" in services:
            sev = max(sev, Severity.CRITICAL, key=lambda s: s.rank)
            reasons.append("database_ui")
            categories.append("database_ui")
            chain_ids.append("recon-database-ui")
            score += 40
        else:
            sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
            reasons.append("admin_panel")
            categories.append("admin_panel")
            chain_ids.append("recon-admin-surface")
            score += 30

    # ── Debug / actuator ──────────────────────────────────────────────────
    if any(k in url for k in DEBUG_PATH_KEYWORDS):
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        reasons.append("debug_exposed")
        categories.append("debug")
        chain_ids.append("recon-debug-exposed")
        score += 30

    # ── API ───────────────────────────────────────────────────────────────
    if "json" in ct or "xml" in ct or "/api" in url or "/graphql" in url:
        sev = max(sev, Severity.MEDIUM, key=lambda s: s.rank)
        reasons.append("api_endpoint")
        categories.append("api")
        chain_ids.append("recon-api-surface")
        score += 15

    # ── 401/403 — WAF block vs origin auth boundary (v5.1) ────────────────
    if status in (401, 403):
        if _is_waf_block(record, status):
            reasons.append(f"waf_blocked_{status}")
            categories.append("waf_blocked")
            chain_ids.append("recon-waf-blocked")
            score += 2       # informational only
        else:
            sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
            reasons.append(f"auth_gated_{status}")
            categories.append("auth_gated")
            chain_ids.append("recon-auth-gated")
            score += 25

    # ── EOL software ──────────────────────────────────────────────────────
    eol = record.get("_eol") or []
    if eol:
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        reasons.append(f"eol:{','.join(e['tech'] for e in eol[:2])}")
        categories.append("eol_software")
        chain_ids.append("recon-eol-software")
        score += 25

    # ── Staging ───────────────────────────────────────────────────────────
    if "staging" in categories or (
            subs_rec and subs_rec.get("sensitive_category") == "staging"):
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        chain_ids.append("recon-staging")
        score += 15

    # ── Default install page ──────────────────────────────────────────────
    if any(t in title for t in DEFAULT_PAGE_TITLES):
        reasons.append("default_page")
        categories.append("default_install")
        chain_ids.append("recon-default-install")

    # ── CORS wildcard ─────────────────────────────────────────────────────
    if record.get("_headers_analysis", {}).get("cors_wildcard"):
        sev = max(sev, Severity.MEDIUM, key=lambda s: s.rank)
        reasons.append("cors_wildcard")
        categories.append("cors")
        chain_ids.append("recon-cors-wildcard")
        score += 10

    # ── Security headers ──────────────────────────────────────────────────
    ha = record.get("_headers_analysis", {})
    if ha.get("hsts_missing") or (ha.get("csp_missing") and ha.get("xfo_missing")):
        reasons.append("weak_headers")
        categories.append("headers")
        chain_ids.append("recon-security-headers")

    # ── WAF / cloud ───────────────────────────────────────────────────────
    if record.get("waf_vendor"):
        chain_ids.append("recon-waf-protected")
    if record.get("cloud_provider"):
        chain_ids.append("recon-cloud-hosted")

    chain_ids = list(dict.fromkeys(chain_ids))
    return sev, categories, chain_ids, reasons, score


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  RECORD BUILDERS
# ══════════════════════════════════════════════════════════════════════════

def _build_host_record(raw: dict) -> dict:
    host_name    = _normalize_host(raw.get("input") or raw.get("host") or "") or ""
    cdn          = raw.get("cdn_name") or raw.get("cdn")
    headers      = raw.get("header") or {}
    body_preview = raw.get("body_preview") or ""

    rec = {
        "subdomain":       host_name,
        "url":             raw.get("url"),
        "scheme":          raw.get("scheme"),
        "host":            raw.get("host"),
        "port":            raw.get("port"),
        "path":            raw.get("path", "/"),
        "status_code":     raw.get("status_code"),
        "content_type":    raw.get("content_type"),
        "content_length":  raw.get("content_length"),
        "title":           raw.get("title"),
        "web_server":      raw.get("webserver"),
        "technologies":    raw.get("tech") or [],
        "cname":           raw.get("cname"),
        "cdn":             cdn,
        "cdn_type":        raw.get("cdn_type"),
        "ip":              raw.get("a") or raw.get("ip"),
        "ipv6":            raw.get("aaaa"),
        "response_time":   raw.get("time"),
        "favicon_hash":    raw.get("favicon"),
        "jarm_hash":       raw.get("jarm_hash"),
        "final_url":       raw.get("final_url"),
        "redirect_chain":  raw.get("chain_status_codes"),
        "tls":             raw.get("tls"),
        "sources":         [],
        "source_count":    0,
        "root":            None,
        "first_seen":      None,
        "geo":             [],
        "interesting":     False,
        "reasons":         [],
        "score":           0,
        "wildcard":        False,
        "cloud_provider":  "",
        "cname_chain":     [],
        "subs_sensitive_category": "",
        "subs_severity":   "LOW",
        "subs_chain_ids":  [],
        "subs_tactics":    [],
        "severity":        Severity.LOW.value,
        "categories":      [],
        "chain_ids":       [],
        "waf_vendor":      "",
        "services":        {},
        "eol_software":    [],
        "body_preview":    body_preview[:500],
        "headers_analysis": {},
        # internal (stripped before write)
        "_headers":          headers,
        "_services":         {},
        "_eol":              [],
        "_headers_analysis": {},
    }

    rec["services"]        = _categorize_services(rec["technologies"])
    rec["_services"]       = rec["services"]
    rec["eol_software"]    = _detect_eol(rec["technologies"])
    rec["_eol"]            = rec["eol_software"]
    rec["waf_vendor"] = _detect_waf(headers, rec["technologies"])
    rec["headers_analysis"] = _analyze_headers(headers, rec.get("scheme") or "https")
    rec["_headers_analysis"] = rec["headers_analysis"]
    return rec


def _strip_internal(record: dict) -> dict:
    return {k: v for k, v in record.items() if not k.startswith("_")}


def _to_payload(rec: dict) -> Optional[dict]:
    url = rec.get("url")
    if not url:
        return None
    first_seen = rec.get("first_seen")
    first_seen_fmt = None
    if first_seen:
        first_seen_fmt = (first_seen.replace("T", " ").split(".")[0]
                          .split("+")[0].rstrip("Z"))
    favicon = rec.get("favicon_hash")
    return {
        "subdomain":      rec.get("subdomain") or "",
        "url":            url,
        "root":           rec.get("root"),
        "scheme":         rec.get("scheme"),
        "host":           rec.get("host"),
        "port":           str(rec["port"]) if rec.get("port") is not None else None,
        "path":           rec.get("path"),
        "status_code":    rec.get("status_code"),
        "content_type":   rec.get("content_type"),
        "content_length": rec.get("content_length"),
        "title":          rec.get("title"),
        "web_server":     rec.get("web_server"),
        "response_time":  rec.get("response_time"),
        "final_url":      rec.get("final_url"),
        "redirect_chain": rec.get("redirect_chain"),
        "ip":             _first_or_none(rec.get("ip")),
        "ipv6":           _first_or_none(rec.get("ipv6")),
        "cname":          rec.get("cname"),
        "cdn":            rec.get("cdn"),
        "cdn_type":       rec.get("cdn_type"),
        "technologies":   rec.get("technologies") or [],
        "favicon_hash":   str(favicon) if favicon is not None else None,
        "jarm_hash":      rec.get("jarm_hash"),
        "tls":            rec.get("tls"),
        "sources":        rec.get("sources") or [],
        "source_count":   rec.get("source_count", 0),
        "first_seen":     first_seen_fmt,
        "geo":            rec.get("geo") or [],
        "interesting":    bool(rec.get("interesting")),
        "reasons":        rec.get("reasons") or [],
        "score":          int(rec.get("score", 0)),
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  AI ANALYSIS
# ══════════════════════════════════════════════════════════════════════════

AI_SYSTEM_PROMPT = (
    "You are an expert offensive-security analyst reviewing live-host "
    "discovery results for a bug-bounty program. Identify the highest-value "
    "targets for MANUAL investigation and explain WHY — never suggest running "
    "exploits. Reference actual subdomains, tech stacks, and observed "
    "characteristics. Be specific and concise. Note realistic attack chaining "
    "but stay within bug-bounty rules of engagement."
)


def _build_ai_prompt(hosts: list[dict], chains: list[dict],
                      summary: dict, aggressive: bool) -> str:
    interesting = [h for h in hosts if h.get("interesting")][:25]
    interesting_block = "\n".join(
        f"  - {h.get('subdomain'):<42} "
        f"status={h.get('status_code')} "
        f"sev={h.get('severity'):<8} "
        f"tech={(','.join((h.get('technologies') or [])[:3]) or '-')[:40]:<40} "
        f"reasons={','.join((h.get('reasons') or [])[:3])}"
        for h in interesting) or "  (none)"

    chains_block = "\n".join(
        f"  - {c.get('chain_id'):<32} sev={c.get('severity'):<8} "
        f"members={c.get('count')}"
        for c in chains) or "  (none)"

    waf_block = ", ".join(
        f"{k}({v})" for k, v in (summary.get("by_waf") or {}).items()) or "(none)"
    cloud_block = ", ".join(
        f"{k}({v})" for k, v in (summary.get("by_cloud") or {}).items()) or "(none)"

    return f"""Live-host discovery scan summary:

  Total alive hosts:        {summary.get('alive', 0)}
  Healthy (2xx):            {summary.get('healthy', 0)}
  Interesting (flagged):    {summary.get('interesting', 0)}
  Scan mode:                {"AGGRESSIVE" if aggressive else "fast"}

  Severity breakdown:
    CRITICAL: {summary.get('by_severity', {}).get('CRITICAL', 0)}
    HIGH:     {summary.get('by_severity', {}).get('HIGH', 0)}
    MEDIUM:   {summary.get('by_severity', {}).get('MEDIUM', 0)}
    LOW:      {summary.get('by_severity', {}).get('LOW', 0)}

  WAFs detected:   {waf_block}
  Cloud providers: {cloud_block}

Chains detected:
{chains_block}

Top {len(interesting)} flagged hosts:
{interesting_block}

Provide:
1. A prioritized list of 5-10 live hosts that warrant immediate manual
   investigation, with specific reasoning.
2. Organizational patterns (e.g. "all auth hosts use Keycloak").
3. A short list of manual tests to run on the top priorities.
4. Any red flags suggesting the target detected automated probing.

Keep it under 800 words. Use markdown with clear headers."""


def _run_ai_analysis(hosts: list[dict], chains: list[dict],
                      summary: dict, aggressive: bool,
                      outdir: Path) -> Optional[dict]:
    if not CFG_LOADED or not hasattr(CFG, "ai_complete"):
        return None
    if not bool(_cfg("AI_ENABLED", False)):
        log.info("AI analysis: disabled (AI_ENABLED=False)")
        return None

    log.info("AI analysis: requesting triage from Mimir's Well...")
    prompt = _build_ai_prompt(hosts, chains, summary, aggressive)
    try:
        response = CFG.ai_complete(prompt, system=AI_SYSTEM_PROMPT)
    except Exception as e:
        log.warn(f"AI analysis failed: {type(e).__name__}: {e}")
        return None

    if not response:
        log.warn("AI analysis returned empty response")
        return None

    generated_at = datetime.now(timezone.utc).isoformat()
    md = (
        f"# Dagaz · Live Host AI Triage Report\n\n"
        f"**Generated:** {generated_at}  \n"
        f"**Alive hosts:** {summary.get('alive', 0)}  \n"
        f"**Interesting:** {summary.get('interesting', 0)}  \n"
        f"**Model:** {_cfg('AI.model', 'deepseek-chat')}\n\n"
        f"---\n\n{response}\n"
    )
    (outdir / "live_hosts_ai_analysis.md").write_text(md, encoding="utf-8")

    obj = {
        "generated_at":  generated_at,
        "model":         _cfg("AI.model", "deepseek-chat"),
        "alive":         summary.get("alive", 0),
        "interesting":   summary.get("interesting", 0),
        "chain_count":   len(chains),
        "response_md":   response,
        "cost_estimate": _safe_cost(),
    }
    (outdir / "live_hosts_ai_analysis.json").write_text(
        json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.ok(f"AI analysis saved ({len(response)} chars)")
    return obj


def _safe_cost() -> Optional[float]:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return round(tracker.estimate_cost(), 6)
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════
#  ᛗ  EVIDENCE + OUTPUT WRITERS  (v5.1 robust)
# ══════════════════════════════════════════════════════════════════════════

def _write_live_hosts_txt(records: list[dict], outdir: Path) -> Path:
    lines = []
    for r in records:
        url = r.get("url") or ""
        if not url:
            continue
        status = r.get("status_code", "")
        title = (r.get("title") or "").replace("\n", " ")[:60]
        tech = ",".join(r.get("technologies") or [])[:60]
        lines.append(f"{url} [{status}] [{title}] [{tech}]")
    path = outdir / "live_hosts.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_live_urls_txt(records: list[dict], outdir: Path) -> Path:
    urls = sorted({r["url"] for r in records if r.get("url")})
    path = outdir / "live_urls.txt"
    path.write_text("\n".join(urls) + ("\n" if urls else ""))
    return path


def _write_headers_evidence(records: list[dict], evidence_dir: Path) -> dict:
    """
    Write response headers for interesting hosts. Handles dict/list/string
    header shapes. Returns {written, skipped, failed} counts for logging.
    """
    counts = {"written": 0, "skipped": 0, "failed": 0}
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.warning(f"    could not create evidence dir: {e}")
        return counts

    for rec in records:
        if not rec.get("interesting"):
            continue

        raw_headers = rec.get("_headers")
        lines: list[str] = []

        if isinstance(raw_headers, dict) and raw_headers:
            for k, v in raw_headers.items():
                val = v[0] if isinstance(v, list) and v else v
                lines.append(f"{k}: {val}")
        elif isinstance(raw_headers, list) and raw_headers:
            lines = [str(x) for x in raw_headers]
        elif isinstance(raw_headers, str) and raw_headers:
            lines = raw_headers.splitlines()

        if not lines:
            counts["skipped"] += 1
            continue

        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_",
                       rec.get("subdomain") or "unknown")[:80]
        try:
            (evidence_dir / f"{safe}_headers.txt").write_text("\n".join(lines))
            counts["written"] += 1
        except OSError:
            counts["failed"] += 1

    return counts


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  CHAINS + SUMMARY
# ══════════════════════════════════════════════════════════════════════════

def _build_chains(records: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for rec in records:
        for cid in (rec.get("chain_ids") or []):
            groups.setdefault(cid, []).append(rec)

    by_ip: dict[str, list[str]] = {}
    for rec in records:
        ip = _first_or_none(rec.get("ip"))
        if ip:
            by_ip.setdefault(ip, []).append(rec.get("subdomain") or "")
    for ip, subs in by_ip.items():
        if len(subs) >= 2:
            groups.setdefault("recon-multi-tenant", []).append({
                "subdomain": ip, "ip": ip, "shared_by": subs[:20],
            })

    chains: list[dict] = []
    for cid, members in groups.items():
        member_subs = [m.get("subdomain") or "" for m in members]
        chains.append({
            "chain_id": cid,
            "name":     CHAIN_NAMES.get(cid, cid),
            "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
            "members":  member_subs[:100],
            "count":    len(members),
            "evidence": f"{len(members)} member(s): "
                        f"{', '.join(member_subs[:5])}"
                        + (f" … (+{len(members) - 5})"
                           if len(members) > 5 else ""),
        })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    chains.sort(key=lambda c: (sev_order.get(c["severity"], 5), c["chain_id"]))
    return chains


def _build_summary(records: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    by_tech:   dict[str, int] = {}
    by_cdn:    dict[str, int] = {}
    by_country: dict[str, int] = {}
    by_server: dict[str, int] = {}
    by_waf:    dict[str, int] = {}
    by_cloud:  dict[str, int] = {}
    by_sev:    dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    interesting_count = 0
    healthy_count = 0
    error_count = 0
    waf_blocked_count = 0
    auth_gated_count = 0

    for r in records:
        status = r.get("status_code") or 0
        by_status[str(status)] = by_status.get(str(status), 0) + 1
        if 200 <= status < 300:
            healthy_count += 1
        if 400 <= status < 600:
            error_count += 1

        cats = r.get("categories") or []
        if "waf_blocked" in cats:
            waf_blocked_count += 1
        if "auth_gated" in cats:
            auth_gated_count += 1

        for t in (r.get("technologies") or []):
            by_tech[t] = by_tech.get(t, 0) + 1
        if r.get("cdn"):
            by_cdn[r["cdn"]] = by_cdn.get(r["cdn"], 0) + 1
        for g in (r.get("geo") or []):
            cc = g.get("country_code")
            if cc:
                by_country[cc] = by_country.get(cc, 0) + 1
        srv = r.get("web_server")
        if srv:
            by_server[srv.split("/")[0].strip()] = by_server.get(
                srv.split("/")[0].strip(), 0) + 1
        waf = r.get("waf_vendor")
        if waf:
            by_waf[waf] = by_waf.get(waf, 0) + 1
        cp = r.get("cloud_provider")
        if cp:
            by_cloud[cp] = by_cloud.get(cp, 0) + 1
        sev = r.get("severity") or "LOW"
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if r.get("interesting"):
            interesting_count += 1

    return {
        "alive":             len(records),
        "healthy":           healthy_count,
        "error":             error_count,
        "interesting":       interesting_count,
        "waf_blocked":       waf_blocked_count,
        "auth_gated":        auth_gated_count,
        "by_status_code":    dict(sorted(by_status.items(),
                                          key=lambda kv: int(kv[0]))),
        "by_technology":     dict(sorted(by_tech.items(), key=lambda kv: -kv[1])),
        "by_cdn":            dict(sorted(by_cdn.items(), key=lambda kv: -kv[1])),
        "by_country":        dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "by_web_server":     dict(sorted(by_server.items(), key=lambda kv: -kv[1])),
        "by_waf":            dict(sorted(by_waf.items(), key=lambda kv: -kv[1])),
        "by_cloud":          dict(sorted(by_cloud.items(), key=lambda kv: -kv[1])),
        "by_severity":       by_sev,
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-SYNC
# ══════════════════════════════════════════════════════════════════════════

def _try_db_sync(scan_id: int, records: list[dict]) -> None:
    try:
        from db import DB  # type: ignore[import-not-found]
    except ImportError:
        log.info("DB sync: db.py not available — skipping")
        return
    if not getattr(DB, "available", False):
        log.warn("DB sync: bridge not ready")
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    payloads = [_to_payload(r) for r in records]
    payloads = [p for p in payloads if p and p.get("url")]
    if not payloads:
        return
    try:
        result = DB.upsert_live_hosts(scan_id, payloads)
        if result is not None:
            log.info(f"DB sync: {result} live host(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warn(f"DB sync: exception — {e}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def discover_live(
    subs_file: Path,
    outdir: Path,
    *,
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    headers: Optional[dict] = None,
    bbp_program: Optional[str] = None,
    resolve_geo: Optional[bool] = None,
    enrich_attribution: bool = ENRICH_FROM_SOURCES_JSON,
    aggressive: bool = True,
    scan_id: Optional[int] = None,
    proxy_pool: Any = None,
    audit_trail: Any = None,
    dry_run: bool = False,
    use_proxy: bool = True,
) -> Path:
    start = time.monotonic()
    outdir = outdir or (_cfg("OUTPUT_DIR") or Path("output"))
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "live_evidence"

    # ── Limits from config ────────────────────────────────────────────────
    module_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    live_limits = module_limits.get("live", {}) or {}
    cfg_threads = live_limits.get("concurrency", DEFAULT_THREADS)
    cfg_rate    = live_limits.get("rate_limit", DEFAULT_RATE_LIMIT)
    cfg_timeout = live_limits.get("timeout", DEFAULT_TIMEOUT)
    cfg_retries = live_limits.get("retries", DEFAULT_RETRIES)

    eff_threads = threads    if threads    is not None else cfg_threads
    eff_rate    = rate_limit if rate_limit is not None else cfg_rate
    eff_timeout = timeout    if timeout    is not None else cfg_timeout
    eff_retries = retries    if retries    is not None else cfg_retries
    if not isinstance(eff_threads, int) or eff_threads < 1:
        eff_threads = DEFAULT_THREADS
    eff_threads = _effective_threads(eff_threads)
    if not isinstance(eff_rate, int) or eff_rate < 0:
        eff_rate = DEFAULT_RATE_LIMIT
    if not isinstance(eff_timeout, int) or eff_timeout < 1:
        eff_timeout = DEFAULT_TIMEOUT
    if not isinstance(eff_retries, int) or eff_retries < 0:
        eff_retries = DEFAULT_RETRIES

    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    if not shutil.which("httpx"):
        raise RuntimeError("httpx not found — run `python3 tools.py --only httpx`")

    subs = [line.strip()
            for line in subs_file.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

    log.info(f"Input  : {len(subs)} subdomain(s) from {subs_file.name}")
    if not subs:
        log.info("(nothing to probe — writing empty report)")
        return _write_empty_report(outdir, subs_file, start)

    eff_aggressive = aggressive
    eff_geo = resolve_geo if resolve_geo is not None else (GEO_ENABLED and eff_aggressive)
    if LIGHTWEIGHT_MODE and eff_geo:
        log.warn("lightweight mode — disabling geo enrichment (network-heavy)")
        eff_geo = False
    body_preview_len = BODY_PREVIEW_AGGRESSIVE if eff_aggressive else BODY_PREVIEW_LEN

    rate_label = f"{eff_rate}/s" if eff_rate else "unlimited"
    log.info("")
    log.info(f"Config : threads={eff_threads}  rate_limit={rate_label}  "
             f"timeout={eff_timeout}s  retries={eff_retries}")
    log.info(f"         aggressive={eff_aggressive}  geo={eff_geo}  "
             f"body_preview={body_preview_len}B")
    if LIGHTWEIGHT_MODE:
        log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — threads capped")
    else:
        log.info(f"Host   : {HOST_CORES} cores / {HOST_RAM_MB} MB RAM")

    # ── Headers ───────────────────────────────────────────────────────────
    header_args, randomize_ua, merged_headers = _headers_for_httpx(
        bbp_program=bbp_program, extra_headers=headers)
    if merged_headers:
        log.info("")
        log.info(f"Headers: {len(merged_headers)} configured")
        for k in merged_headers:
            log.info(f"         {Sym.ARROW} {k}")
        if not randomize_ua:
            log.info(f"         {Sym.DOT} -random-agent disabled (explicit UA set)")

    # ── Proxy (v5.1: pick AND validate before use) ────────────────────────
    proxy_choice: Optional[ProxyChoice] = None
    proxy_status = "disabled (--no-proxy)"

    if use_proxy:
        if proxy_pool is None and CFG_LOADED and _cfg("PROXY_ROTATION", True):
            try:
                pool_cls = _cfg("ProxyPool")
                if pool_cls is not None:
                    proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
            except Exception as e:
                log.debug(f"ProxyPool load failed: {e}")

        if proxy_pool is not None:
            log.info("")
            log.info("Validating proxy before scan (v5.1)...")
            proxy_choice, proxy_status = _pick_and_validate_proxy(proxy_pool)
            if proxy_choice is None:
                log.warn(f"No working proxy found: {proxy_status}")
                log.warn("Falling back to DIRECT connection")
        else:
            proxy_status = "pool not available"

    log.info("")
    if proxy_choice:
        log.info(f"Proxy  : {proxy_choice.protocol}://{proxy_choice.host}:{proxy_choice.port} "
                 f"({proxy_status})")
    else:
        log.info(f"Proxy  : direct ({proxy_status})")

    # ── Dry-run ───────────────────────────────────────────────────────────
    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        log.info(f"Would probe {len(subs)} subdomain(s)")
        for s in subs[:10]:
            log.info(f"  {Sym.ARROW} {s}")
        if len(subs) > 10:
            log.info(f"  … and {len(subs) - 10} more")
        log.info("")
        log.info(f"Output would be written to: {outdir}")
        log.info(f"Evidence would go to     : {evidence_dir}")
        return outdir / "live_hosts.json"

    # ── Audit trail ───────────────────────────────────────────────────────
    if audit_trail is None:
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                audit_trail = factory("live-" + subs_file.stem)
        except Exception as e:
            log.debug(f"audit trail creation failed: {e}")
    audit_path = getattr(audit_trail, "path", None) if audit_trail else None
    if audit_path:
        log.info(f"Audit  : {audit_path}")

    # ── Run httpx ─────────────────────────────────────────────────────────
    log.rune(Rune.RAIDO, "Dagaz takes flight — probing")
    log.info(f"Probing {len(subs)} subdomain(s) with httpx...")

    try:
        raw_records, _, stderr = _run_httpx(
            subs_file=subs_file,
            threads=eff_threads,
            rate_limit=eff_rate,
            timeout=eff_timeout,
            retries=eff_retries,
            header_args=header_args,
            randomize_ua=randomize_ua,
            evidence_dir=evidence_dir,
            body_preview_len=body_preview_len,
            proxy=proxy_choice,
            aggressive=eff_aggressive,
            audit_trail=audit_trail,
        )
    except RuntimeError as e:
        log.error(f"httpx failed: {e}")
        return _write_empty_report(outdir, subs_file, start, len(subs))

    if stderr:
        log.warn(f"httpx stderr: {stderr[:200]}")

    log.ok(f"Alive: {len(raw_records)} / {len(subs)} responded")

    if not raw_records:
        log.warn("No live hosts — writing empty report")
        return _write_empty_report(outdir, subs_file, start, len(subs))

    log.info("Normalizing + classifying records...")
    records = [_build_host_record(r) for r in raw_records]

    if enrich_attribution:
        src_map = _load_source_map(outdir)
        propagated = 0
        for rec in records:
            subs_rec = src_map.get(rec.get("subdomain") or "")
            if subs_rec:
                _apply_attribution(rec, subs_rec)
                propagated += 1
        log.info(f"Attribution: {propagated}/{len(records)} host(s) matched")

    if eff_geo:
        log.rune(Rune.ANSUZ, "Geo / ASN enrichment")
        _enrich_geo(records, outdir)
    else:
        log.info("Geo enrichment disabled")

    src_map = _load_source_map(outdir) if enrich_attribution else {}
    for rec in records:
        subs_rec = src_map.get(rec.get("subdomain") or "")
        sev, categories, chain_ids, reasons, score = _classify(rec, subs_rec)
        rec["severity"]    = sev.value
        rec["categories"]  = categories
        rec["chain_ids"]   = chain_ids
        rec["reasons"]     = reasons
        rec["score"]       = score
        rec["interesting"] = (score >= INTERESTING_MIN_SCORE
                              or sev.rank >= Severity.HIGH.rank)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    records.sort(key=lambda h: (
        SEV_ORDER.get(h.get("severity") or "LOW", 5),
        0 if h.get("interesting") else 1,
        h.get("subdomain") or "",
    ))

    # Evidence (v5.1: log counts)
    ev_counts = _write_headers_evidence(records, evidence_dir)
    if any(ev_counts.values()):
        log.info(f"Evidence: {ev_counts['written']} written, "
                 f"{ev_counts['skipped']} skipped (no headers), "
                 f"{ev_counts['failed']} failed")

    chains  = _build_chains(records)
    summary = _build_summary(records)
    clean_records = [_strip_internal(r) for r in records]

    elapsed = time.monotonic() - start
    report = {
        "schema_version":  4,
        "producer":        f"sub_discovery.py v{__version__} '{__codename__}'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":      str(subs_file),
        "aggressive":      eff_aggressive,
        "host_capacity": {
            "cpu_cores":          HOST_CORES,
            "ram_mb":             HOST_RAM_MB,
            "lightweight":        LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "bbp_program":      bbp_program,
            "threads":          eff_threads,
            "rate_limit":       eff_rate,
            "timeout":          eff_timeout,
            "retries":          eff_retries,
            "headers_count":    len(merged_headers),
            "proxy_used":       proxy_choice.url if proxy_choice else None,
            "proxy_status":     proxy_status,
            "proxy_validation": "pre-validated" if proxy_choice else "direct",
            "tech_detect":      ENABLE_TECH_DETECT,
            "cname":            ENABLE_CNAME,
            "cdn":              ENABLE_CDN,
            "favicon":          ENABLE_FAVICON,
            "jarm":             eff_aggressive and ENABLE_JARM,
            "tls_grab":         eff_aggressive and ENABLE_TLS_GRAB,
            "follow_redirects": ENABLE_FOLLOW_REDIRECTS,
            "body_preview_len": body_preview_len,
            "geo_enabled":      eff_geo,
        },
        "audit": {
            "trail_path":   str(audit_path) if audit_path else None,
            "trail_sha256": _audit_hash(audit_path),
        },
        "totals": {
            "input":       len(subs),
            "alive":       len(records),
            "interesting": summary["interesting"],
            "waf_blocked": summary["waf_blocked"],
            "auth_gated":  summary["auth_gated"],
            "by_severity": summary["by_severity"],
        },
        "summary": summary,
        "chains":  chains,
        "hosts":   clean_records,
    }
    json_path = outdir / "live_hosts.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    confirmed = [r for r in clean_records
                 if (r.get("severity") or "LOW") in ("HIGH", "CRITICAL")]
    (outdir / "live_hosts_confirmed.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "input_file":     str(subs_file),
        "totals": {
            "confirmed": len(confirmed),
            "critical":  sum(1 for r in confirmed if r.get("severity") == "CRITICAL"),
            "high":      sum(1 for r in confirmed if r.get("severity") == "HIGH"),
            "by_chain":  {cid: sum(1 for r in confirmed if cid in (r.get("chain_ids") or []))
                          for cid in {c for r in confirmed
                                      for c in (r.get("chain_ids") or [])}},
        },
        "findings": confirmed,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    (outdir / "live_hosts_chains.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "chains":         chains,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    _write_live_hosts_txt(clean_records, outdir)
    _write_live_urls_txt(clean_records, outdir)

    log.rune(Rune.GEBO, "Mimir's Well · AI triage")
    ai_summary = _run_ai_analysis(clean_records, chains, summary,
                                   eff_aggressive, outdir)

    if scan_id is not None:
        log.info("")
        log.info(f"Syncing to remote database (scan_id={scan_id})...")
        _try_db_sync(scan_id, records)

    _print_summary(outdir, clean_records, confirmed, chains, summary,
                    elapsed, ai_summary, proxy_choice, proxy_status)
    return json_path


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


def _write_empty_report(outdir: Path, subs_file: Path, start: float,
                        input_count: int = 0) -> Path:
    empty_report = {
        "schema_version":  4,
        "producer":        f"sub_discovery.py v{__version__} '{__codename__}'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(subs_file),
        "config":          {},
        "totals":          {"input": input_count, "alive": 0,
                            "interesting": 0, "waf_blocked": 0, "auth_gated": 0,
                            "by_severity": {"CRITICAL": 0, "HIGH": 0,
                                            "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        "summary":         {},
        "chains":          [],
        "hosts":           [],
    }
    path = outdir / "live_hosts.json"
    path.write_text(json.dumps(empty_report, indent=2) + "\n")
    (outdir / "live_hosts_confirmed.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "input_file":     str(subs_file),
        "totals":         {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "findings":       [],
    }, indent=2) + "\n")
    (outdir / "live_hosts_chains.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "chains":         [],
    }, indent=2) + "\n")
    (outdir / "live_hosts.txt").write_text("")
    (outdir / "live_urls.txt").write_text("")
    return path


def _print_summary(
    outdir: Path, records: list[dict], confirmed: list[dict],
    chains: list[dict], summary: dict, elapsed: float,
    ai_summary: Optional[dict], proxy_choice: Optional[ProxyChoice],
    proxy_status: str,
) -> None:
    log.rune(Rune.SOWILO, "Summary")
    log.info(f"Alive            : {summary.get('alive', 0)}")
    log.info(f"Healthy (2xx)    : {summary.get('healthy', 0)}")
    log.info(f"Errors (4xx/5xx) : {summary.get('error', 0)}")
    log.info(f"WAF-blocked      : {summary.get('waf_blocked', 0)}")
    log.info(f"Auth-gated       : {summary.get('auth_gated', 0)}")
    log.info(f"Interesting      : {summary.get('interesting', 0)}")
    if proxy_choice:
        log.info(f"Proxy used       : {proxy_choice.protocol}://"
                 f"{proxy_choice.host}:{proxy_choice.port} ({proxy_status})")
    else:
        log.info(f"Proxy used       : direct ({proxy_status})")

    by_sev = summary.get("by_severity", {})
    log.info("")
    log.info(f"Severity : CRITICAL={by_sev.get('CRITICAL', 0)}  "
             f"HIGH={by_sev.get('HIGH', 0)}  "
             f"MEDIUM={by_sev.get('MEDIUM', 0)}  "
             f"LOW={by_sev.get('LOW', 0)}")

    waf = summary.get("by_waf") or {}
    if waf:
        log.info("WAF      : " + " · ".join(
            f"{k}({v})" for k, v in list(waf.items())[:5]))
    cloud = summary.get("by_cloud") or {}
    if cloud:
        log.info("Cloud    : " + " · ".join(
            f"{k}({v})" for k, v in list(cloud.items())[:5]))
    tech = summary.get("by_technology") or {}
    if tech:
        log.info("Tech     : " + " · ".join(
            f"{k}({v})" for k, v in list(tech.items())[:6]))

    interesting = [r for r in records if r.get("interesting")][:8]
    if interesting:
        log.info("")
        log.info("Top interesting hosts:")
        for r in interesting:
            sev = r.get("severity", "LOW")
            col = ("blood" if sev == "CRITICAL"
                   else "crimson" if sev == "HIGH" else "amber")
            tag = ",".join((r.get("reasons") or [])[:3])
            log.info(f"  {_c(col)}{sev:<8}{_c('reset')} "
                     f"{r.get('status_code', 0):>3}  "
                     f"{r.get('subdomain', '')[:42]:<42}  [{tag}]")

    if chains:
        log.info("")
        log.info("Chains detected:")
        for c in chains[:8]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<32} "
                     f"[{c['severity']}] {c['count']} member(s)")

    log.info("")
    log.info("Outputs:")
    log.info(f"  {Sym.ARROW} live_hosts.json              {len(records):>5}")
    log.info(f"  {Sym.ARROW} live_hosts_confirmed.json    {len(confirmed):>5}")
    log.info(f"  {Sym.ARROW} live_hosts_chains.json       {len(chains):>5}")
    log.info(f"  {Sym.ARROW} live_hosts.txt               {len(records):>5}")
    if (outdir / "live_urls.txt").exists():
        n = len((outdir / "live_urls.txt").read_text().splitlines())
        log.info(f"  {Sym.ARROW} live_urls.txt                {n:>5}")
    if (outdir / "live_evidence").exists():
        n = len(list((outdir / "live_evidence").glob("*_headers.txt")))
        log.info(f"  {Sym.ARROW} live_evidence/               {n:>5}")

    if ai_summary:
        log.info(f"  {Sym.ARROW} live_hosts_ai_analysis.md")
        if ai_summary.get("cost_estimate"):
            log.info(f"    AI cost: ${ai_summary['cost_estimate']:.6f}")

    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PROXY POOL HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════

def check_proxies() -> int:
    """Test every proxy in proxies.txt and report health."""
    print_banner()
    log.rune(Rune.TIWAZ, "Proxy pool health check")

    proxies_file = _cfg("PROXIES_FILE")
    if not proxies_file or not Path(proxies_file).exists():
        log.error(f"proxies.txt not found: {proxies_file}")
        return 1

    pool_cls = _cfg("ProxyPool")
    if pool_cls is None:
        log.error("ProxyPool not available in config.py")
        return 1

    try:
        pool = pool_cls.from_file(proxies_file)
    except Exception as e:
        log.error(f"could not load proxy pool: {e}")
        return 1

    snapshot = pool.snapshot() if hasattr(pool, "snapshot") else []
    log.info(f"Loaded {len(snapshot)} proxies from {proxies_file}")

    if not snapshot:
        log.warn("no proxies to test")
        return 1

    alive = 0
    dead = 0
    for entry in snapshot:
        url = entry.get("proxy")
        if not url:
            continue
        # Parse url into ProxyChoice
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            choice = ProxyChoice(
                url=url, protocol=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or 0,
            )
        except Exception:
            log.warn(f"  {url:<50} malformed")
            dead += 1
            continue

        ok, latency, detail = _validate_proxy(choice)
        if ok:
            log.ok(f"  {url:<50} ALIVE ({latency*1000:.0f}ms)")
            alive += 1
        else:
            log.error(f"  {url:<50} DEAD ({detail})")
            dead += 1

    print()
    log.info(f"Results: {alive} alive, {dead} dead, {len(snapshot)} total")
    if alive == 0:
        log.error("No working proxies — use --no-proxy for direct connections")
        return 1
    if alive < len(snapshot) // 2:
        log.warn(f"More than half the pool is dead — consider refreshing proxies.txt")
    return 0 if alive > 0 else 1


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Dagaz integrity")

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config module loaded",         lambda: CFG_LOADED),
        ("log callable",                 lambda: callable(log.info)),
        ("Sym.STAR present",             lambda: hasattr(Sym, "STAR")),
        ("Rune.DAGAZ present",           lambda: Rune.DAGAZ == "ᛞ"),
        ("Severity enum",                lambda: Severity.CRITICAL.rank == 4),
        ("host measure",                 lambda: HOST_CORES >= 1),
        ("service categories",           lambda: len(SERVICE_CATEGORIES) >= 10),
        ("eol versions",                 lambda: len(TECH_MIN_SAFE_VERSION) >= 8),
        ("waf signatures",               lambda: len(WAF_SIGNATURES) >= 8),
        ("chain names",                  lambda: len(CHAIN_NAMES) >= 25),
        ("chain severity",               lambda: len(CHAIN_SEVERITY) >= 25),
        ("staging-environment HIGH",     lambda: CHAIN_SEVERITY.get(
                                            "recon-staging-environment") == Severity.HIGH),
        ("database-exposed CRITICAL",    lambda: CHAIN_SEVERITY.get(
                                            "recon-database-exposed") == Severity.CRITICAL),
        ("normalize host",               lambda: _normalize_host("https://a.b.com/x") == "a.b.com"),
        ("normalize empty",              lambda: _normalize_host("") is None),
        ("_first_or_none list",          lambda: _first_or_none(["x", "y"]) == "x"),
        ("_first_or_none scalar",        lambda: _first_or_none("z") == "z"),
        ("_first_or_none None",          lambda: _first_or_none(None) is None),
        ("get header ci",                lambda: _get_header({"X-Test": "y"}, "x-test") == "y"),
        ("get header list",              lambda: _get_header(["X-Test: y"], "x-test") == "y"),
        ("get header string",            lambda: _get_header("X-Test: y\nOther: z", "x-test") == "y"),
        ("parse version",                lambda: _parse_version("1.18.0") == (1, 18, 0)),
        ("version lt",                   lambda: _version_lt((1, 18, 0), (1, 20, 1))),
        ("categorize nginx",             lambda: "web_server" in _categorize_services(["nginx/1.18.0"])),
        ("categorize phpmyadmin",        lambda: "database_ui" in _categorize_services(["phpMyAdmin"])),
        ("detect eol nginx 1.18",        lambda: any(e["tech"] == "nginx"
                                                    for e in _detect_eol(["nginx/1.18.0"]))),
        ("detect waf cf-ray",            lambda: _detect_waf({"cf-ray": "abc"}) == "Cloudflare"),
        ("detect waf empty",             lambda: _detect_waf({}) == ""),
        ("is_waf_block cf-mitigated",    lambda: _is_waf_block(
                                            {"status_code": 403,
                                             "_headers": {"cf-mitigated": "challenge"}},
                                            403) is True),
        ("is_waf_block not-blocked",     lambda: _is_waf_block(
                                            {"status_code": 403,
                                             "_headers": {"server": "nginx"},
                                             "waf_vendor": "",
                                             "web_server": "nginx/1.24.0"},
                                            403) is False),
        ("is_waf_block 401 false",       lambda: _is_waf_block({}, 401) is False),
        ("analyze headers hsts",         lambda: _analyze_headers({}, "https")["hsts_missing"]),
        ("analyze cors wildcard",        lambda: _analyze_headers(
                                            {"Access-Control-Allow-Origin": "*"},
                                            "https")["cors_wildcard"] is True),
        ("classify admin title",         lambda: _classify(
                                            {"title": "Admin Dashboard", "_services": {},
                                             "status_code": 200, "url": "https://x/admin",
                                             "_headers_analysis": {}, "_eol": [],
                                             "waf_vendor": "", "cloud_provider": "",
                                             "_headers": {}},
                                            None)[0].rank >= Severity.HIGH.rank),
        ("classify waf-blocked 403",     lambda: _classify(
                                            {"status_code": 403, "title": "",
                                             "url": "https://x/",
                                             "_services": {}, "_headers_analysis": {},
                                             "_eol": [], "waf_vendor": "Cloudflare",
                                             "cloud_provider": "",
                                             "_headers": {"cf-mitigated": "challenge"}},
                                            None)[4] < 20),  # low score, not HIGH
        ("classify plain 200",           lambda: _classify(
                                            {"status_code": 200, "title": "Welcome",
                                             "url": "https://x/", "_services": {},
                                             "_headers_analysis": {}, "_eol": [],
                                             "waf_vendor": "", "cloud_provider": "",
                                             "_headers": {}},
                                            None)[0] == Severity.LOW),
        ("build host record core",       lambda: all(
                                            k in _build_host_record({"input": "x.com"})
                                            for k in ("subdomain", "url",
                                                      "status_code", "severity"))),
        ("strip internal",               lambda: all(
                                            not k.startswith("_")
                                            for k in _strip_internal({"_a": 1, "b": 2}))),
        ("effective threads",            lambda: _effective_threads(50) >= 1),
        ("pick_and_validate none",       lambda: _pick_and_validate_proxy(None)[0] is None),
        ("headers from config",          lambda: isinstance(_headers_for_httpx(), tuple)),
        ("build chains",                 lambda: callable(_build_chains)),
        ("build summary",                lambda: callable(_build_summary)),
        ("ai analysis",                  lambda: callable(_run_ai_analysis)),
        ("discover_live",                lambda: callable(discover_live)),
        ("check_proxies",                lambda: callable(check_proxies)),
        ("write empty report",           lambda: callable(_write_empty_report)),
        ("_audit_hash",                  lambda: callable(_audit_hash)),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            result = fn()
            if result:
                log.ok(name)
                passed += 1
            else:
                log.error(f"{name} → returned False")
                failed += 1
        except Exception as e:
            log.error(f"{name} → {type(e).__name__}: {e}")
            failed += 1

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
        log.info(f"  sys.path[0] = {sys.path[0]}")
        log.info(f"  expected repo root on path: {_REPO_ROOT}")
        return 1

    log.ok("config.py loaded")
    log.info(f"  version      : {_cfg('__version__', '?')} \"{_cfg('__codename__', '?')}\"")
    log.info(f"  path         : {getattr(CFG, '__file__', '?')}")

    checks = [
        ("ProxyPool",                     lambda: _cfg("ProxyPool") is not None),
        ("new_audit_trail",               lambda: callable(_cfg("new_audit_trail"))),
        ("KillSwitch",                    lambda: _cfg("KillSwitch") is not None),
        ("build_headers",                 lambda: callable(_cfg("build_headers"))),
        ("ai_complete",                   lambda: callable(_cfg("ai_complete"))),
        ("MODULE_RATE_LIMITS['live']",    lambda: "live" in (_cfg("MODULE_RATE_LIMITS", {}) or {})),
        ("PROGRAMS['hackerone']",         lambda: "hackerone" in (_cfg("PROGRAMS", {}) or {})),
    ]
    failed = 0
    for name, check in checks:
        try:
            if check():
                log.ok(name)
            else:
                log.warn(f"{name} — not configured")
                failed += 1
        except Exception as e:
            log.error(f"{name} — {type(e).__name__}: {e}")
            failed += 1

    live_limits = ((_cfg("MODULE_RATE_LIMITS", {}) or {}).get("live") or {})
    if live_limits:
        log.info(f"  live rate    : concurrency={live_limits.get('concurrency')} "
                 f"rate_limit={live_limits.get('rate_limit')} "
                 f"timeout={live_limits.get('timeout')}")
    else:
        log.warn("  live rate    : NOT CONFIGURED — using defaults")

    log.info(f"  AI_ENABLED   : {_cfg('AI_ENABLED', False)}")
    log.info(f"  PROXY_ROTATION: {_cfg('PROXY_ROTATION', True)}")
    log.info(f"  httpx        : {'present' if shutil.which('httpx') else 'NOT FOUND'}")

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} optional item(s) unconfigured ══  {Sym.WARN}{_c('reset')}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    p = argparse.ArgumentParser(
        prog="sub_discovery.py",
        description=f"Argus recon · sub_discovery v{__version__} '{__codename__}'",
    )
    p.add_argument("--config-check", action="store_true",
                   help="verify config.py integration")
    p.add_argument("--input",  type=Path, default=base / "output" / "all_subs.txt",
                   help="input subdomain list")
    p.add_argument("--output", type=Path, default=base / "output",
                   help="output directory")
    p.add_argument("--bbp", type=str, default=None,
                   help="bug-bounty program profile")
    p.add_argument("--scan-id", type=int, default=None,
                   help="DB self-sync scan ID")
    p.add_argument("--threads",    type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--timeout",    type=int, default=None)
    p.add_argument("--retries",    type=int, default=None)

    p.add_argument("--aggressive", dest="aggressive", action="store_true",
                   default=True,
                   help="aggressive mode: longer body + JARM + TLS (default: ON)")
    p.add_argument("--no-aggressive", "--fast", dest="aggressive",
                   action="store_false",
                   help="fast mode: minimal body, skip JARM/TLS")

    p.add_argument("--no-geo", action="store_true",
                   help="skip geo/ASN enrichment")
    p.add_argument("--no-proxy", action="store_true",
                   help="bypass proxies entirely — recommended for Cloudflare targets")
    p.add_argument("--check-proxies", action="store_true",
                   help="health-check the entire proxy pool and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="print plan; do not touch the network")
    p.add_argument("--selftest", action="store_true",
                   help="verify Dagaz's integrity")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                   version=f"sub_discovery.py {__version__} '{__codename__}'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try:
            CFG.Palette._enabled = False  # type: ignore[attr-defined]
        except Exception:
            pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    # ── Short-circuit modes ─────────────────────────────────────────────
    if args.selftest:
        return selftest()
    if args.config_check:
        return config_check()
    if args.check_proxies:
        return check_proxies()

    print_banner()

    try:
        discover_live(
            subs_file=args.input,
            outdir=args.output,
            threads=args.threads,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            retries=args.retries,
            bbp_program=args.bbp,
            scan_id=args.scan_id,
            aggressive=args.aggressive,
            resolve_geo=False if args.no_geo else None,
            dry_run=args.dry_run,
            use_proxy=not args.no_proxy,
        )
        return 0
    except KeyboardInterrupt:
        log.warn("interrupted by user")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
