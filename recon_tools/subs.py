#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᚺ ᚢ ᚷ ᛁ ᚾ ᚾ   ·   S U B S   ·   O D I N ' S   R A V E N
================================================================================
  File      : recon_tools/subs.py
  Version   : 5.1.0 "HUGINN REBORN"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Passive subdomain enumeration for Argus, integrated with config.py v3.2+.

  v5.1 changes vs v5.0:
    ·  Fixed http_get typo that crashed alienvault on 429
    ·  Fixed scope filter — subdomains of a scoped root inherit scope
       (unless explicitly excluded via `!pattern` in scope.txt)
    ·  aggressive=True / strict=True by default (--no-aggressive / --no-strict)
    ·  Wildcard detection logs every check; --wildcard-deep extends to subs
    ·  Alienvault: 4 retries with backoff + plaintext rate-limit detection
    ·  TACTICS: 6 new categories (billing, identity, source-code,
       api-versioning, ecommerce) + expanded existing categories
    ·  Hardware-adaptive: LIGHTWEIGHT_MODE auto-detects low-spec hosts and
       skips amass + clamps concurrency
    ·  --config-check wired into main() (was defined but never called)
    ·  --test-sources includes wayback
    ·  Summary shows hardware profile + tactic distribution
================================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import shutil
import socket
import string
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


# ── Fallback theme (used only if config.py is absent) ────────────────────

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
        self._log = logging.getLogger("argus.subs")
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
    {G}ᚺ ᚢ ᚷ ᛁ ᚾ ᚾ{R}
    {P}{rule}{R}
    {V}         S U B S   ·   O D I N ' S   R A V E N{R}
    {V}            T H O U G H T   U N B O U N D{R}
    {D}{rule}{R}
    {G}          {Sym.RAVEN}  v{__version__} "{__codename__}"  ·  passive recon{R}
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
__codename__ = "HUGINN REBORN"

TIMEOUT_SUBFINDER   = 600
TIMEOUT_ASSETFINDER = 180
TIMEOUT_AMASS       = 600
TIMEOUT_FINDOMAIN   = 180
TIMEOUT_CRTSH       = 30
TIMEOUT_HACKERTGT   = 20
TIMEOUT_ALIENVAULT  = 20
TIMEOUT_WAYBACK     = 60
TIMEOUT_DNSX        = 300
TIMEOUT_WILDCARD    = 5

DEFAULT_SUBS_RATE = 20
DEFAULT_SUBS_CONCURRENCY = 4

ARGUS_UA = f"argus-subs/{__version__} (+https://github.com/BeardedVikingTX/Argus)"
WILDCARD_TEST_LABEL = "arguswildcardcheck"
MAX_SUBDOMAINS_AGGRESSIVE = 100


# ══════════════════════════════════════════════════════════════════════════
#  HOST CAPACITY  ·  adapts to laptop / server / phone / Pi
# ══════════════════════════════════════════════════════════════════════════

def _measure_host() -> tuple[int, int, str]:
    """Return (cpu_cores, ram_mb, reason). Empty reason = full-power host."""
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


def _effective_concurrency(requested: int) -> int:
    if not LIGHTWEIGHT_MODE:
        return requested
    return max(1, min(requested, 2))


def _should_run_amass(aggressive: bool) -> bool:
    if not aggressive:
        return False
    if LIGHTWEIGHT_MODE:
        log.warn("lightweight mode — skipping amass (memory-heavy)")
        return False
    return True


# ── Sensitive subdomain categories (expanded in v5.1) ────────────────────
SENSITIVE_CATEGORIES: dict[str, tuple[list[str], Severity]] = {
    "database": (
        ["db", "sql", "mysql", "postgres", "postgresql", "redis",
         "mongo", "mongodb", "cassandra", "elasticsearch", "elastic",
         "oracle", "sqlserver", "mssql", "mariadb", "clickhouse",
         "influx", "influxdb", "cockroach", "scylla", "neo4j"],
        Severity.CRITICAL,
    ),
    "cicd": (
        ["jenkins", "gitlab", "git", "github", "bitbucket",
         "jira", "confluence", "sonar", "sonarqube",
         "nexus", "artifactory", "harbor", "registry",
         "ci", "cd", "drone", "teamcity", "bamboo", "travis",
         "codebuild", "buildkite", "argo", "argocd", "flux",
         "spinnaker", "runner", "cicd", "actions", "pipeline"],
        Severity.CRITICAL,
    ),
    "source-code": (
        ["svn", "gitlab-ci", "gitignore", "hg", "mercurial", "codesearch",
         "code", "source", "sources", "repository", "repos"],
        Severity.CRITICAL,
    ),
    "billing": (
        ["pay", "payment", "payments", "billing", "invoice", "invoices",
         "checkout", "stripe", "paypal", "braintree", "subscription",
         "subscriptions", "orders", "receipts"],
        Severity.HIGH,
    ),
    "identity": (
        ["auth", "oauth", "oauth2", "oidc", "sso", "saml", "login",
         "signin", "signup", "register", "register2", "idp", "accounts",
         "account", "users", "user", "profile", "profiles", "session",
         "sessions", "mfa", "2fa", "otp"],
        Severity.HIGH,
    ),
    "admin": (
        ["admin", "administrator", "manage", "manager", "management",
         "portal", "control", "controlpanel", "cp", "cpanel", "whm",
         "plesk", "webmin", "console", "dashboard", "superadmin",
         "root", "sysadmin", "backoffice"],
        Severity.HIGH,
    ),
    "staging": (
        ["staging", "stage", "stg", "dev", "develop", "development",
         "test", "testing", "qa", "uat", "preprod", "pre-prod",
         "sandbox", "demo", "beta", "alpha", "rc", "preview",
         "canary", "edge"],
        Severity.HIGH,
    ),
    "vpn": (
        ["vpn", "jump", "jumpbox", "bastion", "gateway", "remote",
         "rdp", "fortinet", "cisco", "anyconnect", "pulse", "openvpn",
         "wireguard", "zerotier", "tailscale", "teleport"],
        Severity.HIGH,
    ),
    "backup": (
        ["backup", "bkp", "bak", "archive", "old", "legacy",
         "restore", "snapshot", "dump", "dumps", "export"],
        Severity.HIGH,
    ),
    "monitoring": (
        ["grafana", "kibana", "prometheus", "monitoring", "metrics",
         "logs", "datadog", "sentry", "jaeger", "zipkin", "graylog",
         "zabbix", "nagios", "newrelic", "splunk", "logstash",
         "alertmanager", "victoriametrics", "loki", "tempo",
         "jaeger-query", "signoz"],
        Severity.HIGH,
    ),
    "internal": (
        ["internal", "intranet", "corp", "corporate", "local", "private",
         "office", "vpn-only", "private-api"],
        Severity.HIGH,
    ),
    "api": (
        ["api", "graphql", "gql", "rest", "rpc", "grpc", "soap",
         "webhook", "webhooks", "callback", "callbacks", "openapi"],
        Severity.MEDIUM,
    ),
    "api-versioning": (
        ["v0", "v1", "v2", "v3", "v4", "v5", "v6",
         "api-v1", "api-v2", "api-v3", "v1-api", "v2-api", "v3-api",
         "old-api", "legacy-api", "next-api", "beta-api"],
        Severity.MEDIUM,
    ),
    "ecommerce": (
        ["shop", "store", "ecom", "commerce", "catalog", "products",
         "cart", "carts", "orders", "checkout", "wishlist"],
        Severity.MEDIUM,
    ),
    "storage": (
        ["s3", "storage", "blob", "files", "uploads", "cdn",
         "assets", "static", "media", "images", "img", "download",
         "content", "bucket", "buckets", "files-server"],
        Severity.MEDIUM,
    ),
    "proxy": (
        ["proxy", "nginx", "apache", "traefik", "haproxy", "varnish",
         "squid", "envoy", "istio", "kong", "api-gateway"],
        Severity.MEDIUM,
    ),
    "mail": (
        ["mail", "smtp", "imap", "pop3", "webmail", "mx",
         "exchange", "autodiscover", "autoconfig", "mailgun"],
        Severity.LOW,
    ),
    "documentation": (
        ["docs", "wiki", "help", "support", "knowledge", "kb",
         "swagger", "openapi", "api-docs", "redoc", "readme",
         "developer", "developers", "api-portal"],
        Severity.LOW,
    ),
}


# ── Tactics: attack strategy per category ────────────────────────────────
TACTICS: dict[str, list[str]] = {
    "database":       ["banner-grab", "default-creds", "tls-fingerprint",
                       "weak-auth", "unauth-query"],
    "cicd":           ["default-creds", "anonymous-project", "exposed-git",
                       "build-log-leak", "webhook-ssrf", "script-injection"],
    "source-code":    ["exposed-git", "svn-sync", "backup-file-leak",
                       "commit-history-recon"],
    "billing":        ["price-manipulation", "currency-confusion",
                       "subscription-bypass", "webhook-replay",
                       "invoice-idor", "payment-card-error"],
    "identity":       ["default-creds", "password-reset-abuse",
                       "username-enumeration", "session-fixation",
                       "oauth-misconfig", "open-redirect", "mfa-bypass"],
    "admin":          ["login-bypass", "default-creds", "auth-bypass",
                       "session-fixation", "idor", "sql-injection"],
    "staging":        ["debug-mode", "verbose-error", "test-credentials",
                       "backup-file", "old-api", "cors-misconfig"],
    "vpn":            ["product-version-fingerprint", "default-creds",
                       "known-cve", "pre-auth-rce"],
    "backup":         ["directory-listing", "sql-dump-discovery",
                       "old-api", "tls-expired"],
    "monitoring":     ["anonymous-dashboard", "grafana-sqli",
                       "kibana-es-injection", "prometheus-metrics-dump",
                       "alertmanager-silence"],
    "internal":       ["split-horizon-mismatch", "staff-directory",
                       "rfc1918-leak", "internal-api-enum"],
    "api":            ["swagger-openapi", "graphql-introspection",
                       "bola-idor", "mass-assignment", "api-version-diff"],
    "api-versioning": ["old-version-diff", "deprecated-auth",
                       "schema-leak", "unpinned-version"],
    "ecommerce":      ["cart-manipulation", "coupon-abuse", "price-idor",
                       "checkout-bypass", "stored-xss"],
    "storage":        ["bucket-listing", "signed-url-replay",
                       "acl-misconfig", "cdn-cache-poison"],
    "proxy":          ["request-smuggling", "cache-poisoning",
                       "host-header-injection", "x-forwarded-abuse"],
    "mail":           ["open-relay", "spoofing", "mailbox-enum",
                       "auto-config-leak"],
    "documentation":  ["api-spec-discovery", "hidden-endpoint",
                       "internal-url-leak"],
}


def _tactics_for_category(category: str) -> list[str]:
    return sorted(set(TACTICS.get(category, [])))


# ── Cloud provider CNAME patterns ─────────────────────────────────────────
CLOUD_PROVIDER_PATTERNS: dict[str, list[str]] = {
    "AWS":           [".elb.amazonaws.com", ".compute.amazonaws.com",
                      ".cloudfront.net", ".s3.amazonaws.com", ".s3-",
                      ".execute-api.", ".awsglobalaccelerator.com"],
    "GCP":           [".googlehosted.com", ".run.app", ".appspot.com",
                      ".storage.googleapis.com", ".googleapis.com"],
    "Azure":         [".azurewebsites.net", ".cloudapp.azure.com",
                      ".azurefd.net", ".trafficmanager.net", ".azureedge.net",
                      ".blob.core.windows.net", ".azure-api.net"],
    "Cloudflare":    [".cloudflare.net", ".cdn.cloudflare.net"],
    "Fastly":        [".fastly.net", ".fastlylb.net", ".global.ssl.fastly.net"],
    "DigitalOcean":  [".ondigitalocean.app", ".digitaloceanspaces.com"],
    "Vercel":        [".vercel-dns.com", ".vercel.app", ".now.sh"],
    "Netlify":       [".netlify.app", ".netlify.com"],
    "Heroku":        [".herokudns.com", ".herokuapp.com"],
    "Shopify":       [".myshopify.com"],
    "GitHub Pages":  [".github.io", ".githubusercontent.com"],
    "Firebase":      [".firebaseapp.com", ".web.app"],
}


# ── Chain metadata (expanded in v5.1 for new categories) ─────────────────
CHAIN_METADATA: dict[str, dict] = {
    "recon-database-exposed": {
        "name": "Exposed database service",
        "severity": Severity.CRITICAL,
        "reasoning": "Database subdomain publicly resolvable — indicates "
                     "the org exposes DB infra on the public internet.",
        "pivots":   ["TLS fingerprint", "Banner grab", "default credentials",
                     "weak auth"],
    },
    "recon-cicd-exposed": {
        "name": "Exposed CI/CD system",
        "severity": Severity.CRITICAL,
        "reasoning": "Jenkins/GitLab/Argo subdomain reachable — source code "
                     "and build pipelines are often the crown jewels.",
        "pivots":   ["default admin creds", "anonymous project read",
                     "exposed .git", "SSRF from build hooks"],
    },
    "recon-source-leak": {
        "name": "Source code exposure",
        "severity": Severity.CRITICAL,
        "reasoning": "Source repo subdomain — full code disclosure if "
                     "misconfigured. Highest-impact class of finding.",
        "pivots":   ["exposed .git", "svn sync", "commit history",
                     "backup-file-leak"],
    },
    "recon-payment-surface": {
        "name": "Payment / billing surface",
        "severity": Severity.HIGH,
        "reasoning": "Payment/billing subdomain — direct financial impact "
                     "if auth or pricing is bypassable.",
        "pivots":   ["price manipulation", "currency confusion",
                     "webhook replay", "invoice IDOR"],
    },
    "recon-identity-surface": {
        "name": "Identity / auth surface",
        "severity": Severity.HIGH,
        "reasoning": "Auth subdomain — credential handling and session "
                     "management are prime targets for account takeover.",
        "pivots":   ["default creds", "session fixation",
                     "password reset abuse", "username enumeration"],
    },
    "recon-admin-surface": {
        "name": "Admin panel",
        "severity": Severity.HIGH,
        "reasoning": "Admin/dashboard UI exposed — often the highest-value "
                     "single target for auth bypass and IDOR.",
        "pivots":   ["login bypass", "default creds", "password reset abuse",
                     "session fixation", "IDOR"],
    },
    "recon-staging-environment": {
        "name": "Staging/development environment",
        "severity": Severity.HIGH,
        "reasoning": "Staging environments frequently lag on patching and "
                     "may allow debug endpoints or bypassed auth.",
        "pivots":   ["debug=true", "verbose errors", "test credentials",
                     "backup files", "old API versions"],
    },
    "recon-vpn-surface": {
        "name": "VPN / remote access",
        "severity": Severity.HIGH,
        "reasoning": "VPN endpoint exposed — always worth reporting the "
                     "product/version for known CVEs.",
        "pivots":   ["product version fingerprint", "default credentials",
                     "known CVE"],
    },
    "recon-backup-exposure": {
        "name": "Backup/legacy infrastructure",
        "severity": Severity.HIGH,
        "reasoning": "Backups and legacy subdomains often contain stale code "
                     "with known-vulnerable dependencies.",
        "pivots":   ["directory listing", "SQL dumps", "old API versions",
                     "expired TLS"],
    },
    "recon-monitoring-exposed": {
        "name": "Monitoring endpoint",
        "severity": Severity.HIGH,
        "reasoning": "Grafana/Kibana/Prometheus exposed — often unauth'd in "
                     "default configurations with full internal metrics.",
        "pivots":   ["anonymous dashboard access", "SQL in Grafana",
                     "Kibana ES injection", "Prometheus /metrics dump"],
    },
    "recon-internal-leak": {
        "name": "Internal infrastructure leak",
        "severity": Severity.HIGH,
        "reasoning": "Internal/corp subdomain resolving publicly — likely a "
                     "split-horizon DNS misconfiguration worth noting.",
        "pivots":   ["internal API enumeration", "staff directory",
                     "RFC1918 leak in DNS"],
    },
    "recon-api-discovery": {
        "name": "API surface",
        "severity": Severity.MEDIUM,
        "reasoning": "API subdomain — enumerate versions and specs before "
                     "fuzzing.",
        "pivots":   ["/swagger /openapi /graphql", "old API versions",
                     "mass assignment", "BOLA/IDOR"],
    },
    "recon-deprecated-api": {
        "name": "Deprecated API version",
        "severity": Severity.MEDIUM,
        "reasoning": "Old API version still live — often missing patches, "
                     "rate limits, and modern auth.",
        "pivots":   ["auth bypass", "schema leak", "missing rate limit",
                     "legacy auth"],
    },
    "recon-commerce-surface": {
        "name": "Commerce surface",
        "severity": Severity.MEDIUM,
        "reasoning": "Shop/cart/checkout — economic attack surface with "
                     "direct monetary impact.",
        "pivots":   ["price manipulation", "coupon abuse", "cart IDOR",
                     "checkout bypass"],
    },
    "recon-storage-exposure": {
        "name": "Storage / CDN",
        "severity": Severity.MEDIUM,
        "reasoning": "Storage subdomain — check for misconfigured bucket ACLs.",
        "pivots":   ["S3 bucket listing", "Azure blob anonymous access",
                     "CDN cache poisoning", "signed URL replay"],
    },
    "recon-proxy-surface": {
        "name": "Proxy / load balancer",
        "severity": Severity.MEDIUM,
        "reasoning": "Reverse proxy — potential request smuggling, cache "
                     "poisoning, and origin-IP disclosure via headers.",
        "pivots":   ["HTTP request smuggling", "cache poisoning",
                     "Host header injection", "X-Forwarded-* abuse"],
    },
    "recon-wildcard": {
        "name": "Wildcard DNS on root",
        "severity": Severity.MEDIUM,
        "reasoning": "Wildcard DNS detected — many 'found' subdomains are "
                     "noise. Confidence should be reduced.",
        "pivots":   ["Filter to only resolving+non-wildcard entries"],
    },
    "recon-cloud-hosted": {
        "name": "Cloud provider fingerprint",
        "severity": Severity.MEDIUM,
        "reasoning": "Multiple subdomains on the same cloud provider — "
                     "shared infra where lateral movement may be possible.",
        "pivots":   ["Cross-service metadata query", "IMDS abuse",
                     "S3 bucket name enumeration"],
    },
    "recon-mass-enum": {
        "name": "Large enumeration result",
        "severity": Severity.MEDIUM,
        "reasoning": "More than 100 subdomains found — substantial attack "
                     "surface worth prioritized triage.",
        "pivots":   ["Prioritize by severity + cloud provider",
                     "Cross-reference with historical scan diffs"],
    },
}


CHAIN_FOR_CATEGORY: dict[str, str] = {
    "database":       "recon-database-exposed",
    "cicd":           "recon-cicd-exposed",
    "source-code":    "recon-source-leak",
    "billing":        "recon-payment-surface",
    "identity":       "recon-identity-surface",
    "admin":          "recon-admin-surface",
    "staging":        "recon-staging-environment",
    "vpn":            "recon-vpn-surface",
    "backup":         "recon-backup-exposure",
    "monitoring":     "recon-monitoring-exposed",
    "api":            "recon-api-discovery",
    "api-versioning": "recon-deprecated-api",
    "ecommerce":      "recon-commerce-surface",
    "storage":        "recon-storage-exposure",
    "internal":       "recon-internal-leak",
    "proxy":          "recon-proxy-surface",
}


_RFC1918 = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class SourceResult:
    source: str
    domain: str
    subdomains: set[str] = field(default_factory=set)
    error: Optional[str] = None
    duration: float = 0.0
    raw_output: str = ""
    source_url: str = ""
    proxy_used: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def count(self) -> int:
        return len(self.subdomains)


@dataclass
class SubdomainRecord:
    name: str
    sources: set[str] = field(default_factory=set)
    root: str = ""
    first_seen: str = ""
    is_apex: bool = False
    resolves: Optional[bool] = None
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    cloud_provider: str = ""
    wildcard: bool = False
    sensitive_category: str = ""
    severity: Severity = Severity.LOW
    chain_ids: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)   # v5.1
    in_scope: bool = True

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(self.name.encode()).hexdigest()[:16]


@dataclass
class ReconChain:
    chain_id: str
    name: str
    severity: Severity
    members: list[str]
    reasoning: str = ""
    pivots: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_id":    self.chain_id,
            "name":        self.name,
            "severity":    self.severity.value,
            "members":     self.members[:100],
            "count":       len(self.members),
            "reasoning":   self.reasoning,
            "pivots":      self.pivots,
            "entry_points":self.entry_points[:20],
            "evidence":    self.evidence[:600],
        }


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  NORMALIZATION
# ══════════════════════════════════════════════════════════════════════════

def normalize_subdomain(raw: str) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().lower()
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
    s = s.split("/")[0].split("?")[0]
    if ":" in s:
        s = s.split(":")[0]
    s = s.lstrip("*.").rstrip(".")
    if not s or not _DOMAIN_RE.match(s):
        return None
    return s


def extract_apex(subdomain: str, roots: list[str]) -> Optional[str]:
    for root in roots:
        r = root.lower().strip()
        if subdomain == r or subdomain.endswith("." + r):
            return r
    return None


def _random_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def roots_from_scope(scope_validator: Any) -> list[str]:
    if scope_validator is None:
        return []
    rules = getattr(scope_validator, "_rules", [])
    roots: set[str] = set()
    for rule in rules:
        if not getattr(rule, "include", True):
            continue
        if getattr(rule, "regex", False):
            continue
        pattern = (rule.pattern or "").lower().strip()
        if pattern.startswith("*."):
            pattern = pattern[2:]
        if pattern and _DOMAIN_RE.match(pattern):
            roots.add(pattern)
    return sorted(roots)


def _scope_rule_matches(scope_validator: Any, host: str, rule: Any) -> bool:
    """Safely invoke ScopeValidator._matches, tolerating API drift."""
    try:
        matcher = getattr(scope_validator, "_matches", None)
        if callable(matcher):
            return bool(matcher(host, rule))
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  AUDITED HTTP SESSION
# ══════════════════════════════════════════════════════════════════════════

def http_get(
    url: str,
    *,
    timeout: float = 30.0,
    accept: str = "*/*",
    label: str = "http",
    proxy_pool: Any = None,
    audit: Any = None,
    headers: Optional[dict[str, str]] = None,
    max_retries: int = 2,
) -> tuple[Optional[str], dict]:
    if CFG_LOADED and hasattr(CFG, "KillSwitch"):
        CFG.KillSwitch.check()

    merged_headers = {"User-Agent": ARGUS_UA, "Accept": accept}
    if headers:
        merged_headers.update(headers)

    last_meta: dict = {"status": 0, "latency_ms": 0, "proxy": None,
                       "user_agent": merged_headers["User-Agent"],
                       "error": None}

    for attempt in range(max_retries + 1):
        proxy = None
        if proxy_pool is not None:
            try:
                proxy = proxy_pool.pick()
            except Exception:
                proxy = None

        req = urllib.request.Request(url, headers=merged_headers)

        if proxy is not None:
            proxy_url = proxy.url()
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
            last_meta["proxy"] = proxy_url
        else:
            opener = urllib.request.build_opener()
            last_meta["proxy"] = None

        start = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read()
                latency = (time.monotonic() - start) * 1000
                status = resp.getcode()
                text = body.decode("utf-8", errors="replace")

                if proxy is not None and proxy_pool is not None:
                    try:
                        proxy_pool.report_success(proxy, latency / 1000)
                    except Exception:
                        pass

                if audit is not None:
                    try:
                        audit.record("GET", url, status, latency,
                                     user_agent=merged_headers["User-Agent"],
                                     proxy=last_meta["proxy"])
                    except Exception:
                        pass

                last_meta.update(status=status, latency_ms=latency)
                return text, last_meta

        except urllib.error.HTTPError as e:
            latency = (time.monotonic() - start) * 1000
            last_meta.update(status=e.code, latency_ms=latency,
                             error=f"HTTP {e.code}")
            if proxy is not None and proxy_pool is not None:
                try:
                    proxy_pool.report_failure(proxy)
                except Exception:
                    pass
            if audit is not None:
                try:
                    audit.record("GET", url, e.code, latency,
                                 user_agent=merged_headers["User-Agent"],
                                 proxy=last_meta["proxy"],
                                 error=f"HTTP {e.code}")
                except Exception:
                    pass

            # 429 → Retry-After aware backoff (bug fixed in v5.1)
            if e.code == 429:
                retry_after = None
                try:
                    ra = e.headers.get("Retry-After") if e.headers else None
                    if ra and ra.isdigit():
                        retry_after = min(int(ra), 30)
                except Exception:
                    retry_after = None
                if attempt >= max_retries:
                    return None, last_meta
                wait = retry_after if retry_after is not None else (2 ** attempt) + random.uniform(0, 1)
                log.debug(f"{label}: 429 rate-limited, sleeping {wait:.1f}s")
                time.sleep(wait)
                continue

            if e.code >= 500 and attempt < max_retries:
                time.sleep((2 ** attempt) + random.uniform(0, 1))
                continue
            return None, last_meta

        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            last_meta.update(status=0, latency_ms=latency,
                             error=f"{type(e).__name__}: {e}")
            if proxy is not None and proxy_pool is not None:
                try:
                    proxy_pool.report_failure(proxy)
                except Exception:
                    pass
            if audit is not None:
                try:
                    audit.record("GET", url, 0, latency,
                                 user_agent=merged_headers["User-Agent"],
                                 proxy=last_meta["proxy"],
                                 error=str(e)[:200])
                except Exception:
                    pass
            if attempt >= max_retries:
                return None, last_meta

        time.sleep(0.5 + random.random() * 1.0)

    return None, last_meta


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  PASSIVE SOURCE RUNNERS
# ══════════════════════════════════════════════════════════════════════════

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int, label: str) -> tuple[bool, str, str]:
    log.debug(f"[{label}] $ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.returncode == 0, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return (False, "", f"timeout after {timeout}s")
    except FileNotFoundError:
        return (False, "", f"binary not found: {cmd[0]}")
    except Exception as e:
        return (False, "", f"unexpected error: {e}")


def _run_subfinder(domain: str, rate_limit: Optional[int],
                   proxy: Optional[Any] = None) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("subfinder", domain)
    if not _tool_available("subfinder"):
        result.error = "subfinder not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["subfinder", "-d", domain, "-all", "-recursive", "-silent", "-oJ", "-cs"]
    if rate_limit is not None and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])
    if proxy is not None:
        cmd.extend(["-proxy", proxy.url()])
        result.proxy_used = proxy.url()

    ok, stdout, stderr = _run(cmd, TIMEOUT_SUBFINDER, "subfinder")
    result.raw_output = stdout[:50000]

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host") or obj.get("domain") or obj.get("subdomain")
            sub = normalize_subdomain(str(host)) if host else None
        except json.JSONDecodeError:
            sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "subfinder failed"
    result.duration = time.monotonic() - start
    return result


def _run_assetfinder(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("assetfinder", domain)
    if not _tool_available("assetfinder"):
        result.error = "assetfinder not installed"
        result.duration = time.monotonic() - start
        return result

    ok, stdout, stderr = _run(
        ["assetfinder", "--subs-only", domain], TIMEOUT_ASSETFINDER, "assetfinder",
    )
    result.raw_output = stdout[:50000]

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "assetfinder failed"
    result.duration = time.monotonic() - start
    return result


def _run_amass(domain: str, timeout: int = TIMEOUT_AMASS) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("amass", domain)
    if not _tool_available("amass"):
        result.error = "amass not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "10", "-silent"]
    ok, stdout, stderr = _run(cmd, timeout, "amass")
    result.raw_output = stdout[:50000]

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "amass failed"
    result.duration = time.monotonic() - start
    return result


def _run_findomain(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("findomain", domain)
    if not _tool_available("findomain"):
        result.error = "findomain not installed"
        result.duration = time.monotonic() - start
        return result

    ok, stdout, stderr = _run(
        ["findomain", "-t", domain, "-q"], TIMEOUT_FINDOMAIN, "findomain",
    )
    result.raw_output = stdout[:50000]

    for line in stdout.splitlines():
        sub = normalize_subdomain(line)
        if sub:
            result.subdomains.add(sub)

    if not ok and not result.subdomains:
        result.error = stderr.strip()[:200] or "findomain failed"
    result.duration = time.monotonic() - start
    return result


def _run_crtsh(domain: str, **http_kw) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("crt.sh", domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    result.source_url = url

    text, meta = http_get(url, timeout=TIMEOUT_CRTSH, label="crt.sh",
                          accept="application/json", **http_kw)
    result.proxy_used = meta.get("proxy")
    if text is None:
        result.error = f"crt.sh: {meta.get('error') or 'no response'}"
        result.duration = time.monotonic() - start
        return result

    try:
        data = json.loads(text)
    except Exception as e:
        result.error = f"crt.sh: invalid json: {e}"
        result.duration = time.monotonic() - start
        return result

    for entry in data:
        for name in (entry.get("name_value") or "").splitlines():
            sub = normalize_subdomain(name)
            if sub:
                result.subdomains.add(sub)

    result.raw_output = text[:50000]
    result.duration = time.monotonic() - start
    return result


def _run_hackertarget(domain: str, **http_kw) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("hackertarget", domain)
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    result.source_url = url

    text, meta = http_get(url, timeout=TIMEOUT_HACKERTGT, label="hackertarget",
                          **http_kw)
    result.proxy_used = meta.get("proxy")
    if text is None:
        result.error = f"hackertarget: {meta.get('error') or 'no response'}"
        result.duration = time.monotonic() - start
        return result

    # HackerTarget returns plaintext errors ("API count exceeded", etc.)
    first_line = text.strip().split("\n")[0] if text.strip() else ""
    if first_line and "," not in first_line and not _DOMAIN_RE.match(first_line.lower()):
        result.error = f"hackertarget: {first_line[:120]}"
        result.duration = time.monotonic() - start
        return result

    for line in text.splitlines():
        if "," not in line:
            continue
        host = line.split(",")[0].strip()
        sub = normalize_subdomain(host)
        if sub:
            result.subdomains.add(sub)

    result.raw_output = text[:50000]
    result.duration = time.monotonic() - start
    return result


def _run_alienvault(domain: str, **http_kw) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("alienvault", domain)
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{domain}/passive_dns")
    result.source_url = url

    # Alienvault returns 429 aggressively — 4 retries with backoff
    text, meta = http_get(
        url,
        timeout=TIMEOUT_ALIENVAULT,
        label="alienvault",
        accept="application/json",
        max_retries=4,
        **http_kw,
    )
    result.proxy_used = meta.get("proxy")
    if text is None:
        result.error = f"alienvault: {meta.get('error') or 'no response'}"
        result.duration = time.monotonic() - start
        return result

    stripped = text.strip()
    if stripped.startswith("Rate limit") or stripped.startswith("Too many"):
        result.error = "alienvault: rate-limited (try again later)"
        result.duration = time.monotonic() - start
        return result

    try:
        data = json.loads(text)
    except Exception as e:
        result.error = f"alienvault: invalid json: {e}"
        result.duration = time.monotonic() - start
        return result

    for record in data.get("passive_dns") or []:
        host = record.get("hostname") or ""
        sub = normalize_subdomain(host)
        if sub:
            result.subdomains.add(sub)

    result.raw_output = text[:50000]
    result.duration = time.monotonic() - start
    return result


def _run_wayback(domain: str, **http_kw) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("wayback", domain)
    url = (f"http://web.archive.org/cdx/search/cdx?"
           f"url=*.{domain}&output=text&fl=original"
           f"&collapse=urlkey&limit=10000")
    result.source_url = url

    text, meta = http_get(url, timeout=TIMEOUT_WAYBACK, label="wayback",
                          **http_kw)
    result.proxy_used = meta.get("proxy")
    if text is None:
        result.error = f"wayback: {meta.get('error') or 'no response'}"
        result.duration = time.monotonic() - start
        return result

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            host = urllib.parse.urlparse(line).hostname or ""
        except Exception:
            continue
        sub = normalize_subdomain(host)
        if sub:
            result.subdomains.add(sub)

    result.raw_output = text[:50000]
    result.duration = time.monotonic() - start
    return result


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  DNS ENRICHMENT + WILDCARD DETECTION
# ══════════════════════════════════════════════════════════════════════════

def _detect_wildcard_roots(
    roots: list[str],
    subdomains: Optional[list[str]] = None,
    deep: bool = False,
) -> set[str]:
    """
    Detect wildcard DNS.

    Roots are always tested. Subdomains are tested only when `deep=True`
    (N extra DNS lookups — useful before trusting sub-sub resolutions).

    Every check logs explicitly, including negatives.
    """
    wildcards: set[str] = set()
    targets: list[str] = list(roots)
    if deep and subdomains:
        targets.extend(subdomains[:200])

    tested = 0
    for target in targets:
        if CFG_LOADED and hasattr(CFG, "KillSwitch"):
            CFG.KillSwitch.check()
        probe = f"{WILDCARD_TEST_LABEL}-{_random_label()}.{target}"
        tested += 1
        try:
            socket.gethostbyname(probe)
            wildcards.add(target)
            log.warn(f"wildcard DNS: {target}  (probe resolved)")
        except socket.gaierror:
            log.debug(f"wildcard: {target} clean")
        except Exception as e:
            log.debug(f"wildcard: {target} probe failed: {e}")

    if tested == 0:
        log.info("wildcard: no targets to test")
    elif not wildcards:
        log.info(f"wildcard: tested {tested} target(s), none wildcard")
    else:
        log.warn(f"wildcard: {len(wildcards)}/{tested} target(s) are wildcard")

    return wildcards


def _resolve_with_dnsx(subdomains: list[str],
                       rate_limit: Optional[int] = None) -> dict[str, dict]:
    if not subdomains:
        return {}

    if _tool_available("dnsx"):
        cmd = ["dnsx", "-silent", "-json", "-a", "-aaaa", "-cname"]
        if rate_limit is not None and rate_limit > 0:
            cmd.extend(["-rl", str(rate_limit)])
        try:
            result = subprocess.run(
                cmd, input="\n".join(subdomains),
                capture_output=True, text=True, timeout=TIMEOUT_DNSX,
            )
            records: dict[str, dict] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = normalize_subdomain(obj.get("host") or "")
                if not host:
                    continue
                records[host] = {
                    "a":     obj.get("a") or [],
                    "aaaa":  obj.get("aaaa") or [],
                    "cname": obj.get("cname") or [],
                }
            return records
        except Exception as e:
            log.warn(f"dnsx failed: {e} — falling back to socket")

    log.info("dnsx unavailable — using threaded socket resolution")
    records = {}

    def _one(sub: str) -> tuple[str, dict]:
        try:
            _name, aliases, addrs = socket.gethostbyname_ex(sub)
            a_records = [a for a in addrs if "." in a]
            return sub, {"a": a_records, "aaaa": [], "cname": aliases or []}
        except socket.gaierror:
            return sub, {"a": [], "aaaa": [], "cname": []}
        except Exception:
            return sub, {"a": [], "aaaa": [], "cname": []}

    workers = _effective_concurrency(32)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_one, s): s for s in subdomains}
        for fut in as_completed(futures):
            try:
                sub, rec = fut.result()
                records[sub] = rec
            except Exception:
                pass
    return records


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════

def _classify_sensitive(name: str, root: str) -> tuple[str, Severity]:
    if name == root:
        return ("apex", Severity.INFO)

    prefix = name[: -(len(root) + 1)] if name.endswith("." + root) else name
    prefix_lower = prefix.lower()

    for category, (patterns, severity) in SENSITIVE_CATEGORIES.items():
        for pattern in patterns:
            if re.search(rf"(?:^|[.-]){re.escape(pattern)}(?:$|[.-])", prefix_lower):
                return (category, severity)
            if prefix_lower == pattern:
                return (category, severity)
            if (prefix_lower.startswith(pattern + "-")
                    or prefix_lower.startswith(pattern + ".")):
                return (category, severity)

    return ("", Severity.LOW)


def _detect_cloud_provider(cname_chain: list[str]) -> str:
    if not cname_chain:
        return ""
    joined = " " + " ".join(c.lower() for c in cname_chain)
    for provider, patterns in CLOUD_PROVIDER_PATTERNS.items():
        for pattern in patterns:
            if pattern in joined:
                return provider
    return ""


def _is_internal_ip(ip: str) -> bool:
    return bool(_RFC1918.match(ip))


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  AGGREGATION
# ══════════════════════════════════════════════════════════════════════════

def _aggregate(
    results: list[SourceResult],
    roots: list[str],
    wildcard_roots: set[str],
    dns_records: dict[str, dict],
    scope_validator: Any = None,
) -> dict[str, SubdomainRecord]:
    now = datetime.now(timezone.utc).isoformat()
    merged: dict[str, SubdomainRecord] = {}

    for sr in results:
        if not sr.ok:
            continue
        for sub in sr.subdomains:
            if sub not in merged:
                root = extract_apex(sub, roots) or ""
                merged[sub] = SubdomainRecord(
                    name=sub, root=root, first_seen=now,
                    is_apex=(sub == root),
                )
            merged[sub].sources.add(sr.source)

    # ── Scope filter (v5.1 FIX) ──────────────────────────────────────────
    # Semantics:
    #   1. Explicit `!pattern` exclude → OUT
    #   2. Subdomain of a root that came FROM scope.txt → IN
    #      (inheritance — `arc.io` in scope.txt means `*.arc.io` too,
    #       unless explicitly excluded)
    #   3. Full scope check as final fallback
    #   4. Exception → treat as IN (fail-open for safety of the scan)
    if scope_validator is not None:
        _scope_rules = getattr(scope_validator, "_rules", [])
        for name, rec in list(merged.items()):
            try:
                excluded = False
                for rule in _scope_rules:
                    if not getattr(rule, "include", True):
                        if _scope_rule_matches(scope_validator, name, rule):
                            excluded = True
                            break
                if excluded:
                    rec.in_scope = False
                    continue
                if rec.root and rec.root in roots:
                    rec.in_scope = True
                    continue
                rec.in_scope = scope_validator.is_in_scope(name)
            except Exception:
                rec.in_scope = True

    # ── Enrich ───────────────────────────────────────────────────────────
    for name, rec in merged.items():
        dns = dns_records.get(name) or {}
        rec.a_records = dns.get("a") or []
        rec.aaaa_records = dns.get("aaaa") or []
        rec.cname_chain = dns.get("cname") or []
        rec.resolves = bool(rec.a_records or rec.aaaa_records or rec.cname_chain) \
            if dns_records else None
        rec.cloud_provider = _detect_cloud_provider(rec.cname_chain)
        rec.wildcard = rec.root in wildcard_roots

        category, severity = _classify_sensitive(name, rec.root)
        rec.sensitive_category = category
        rec.severity = severity
        rec.tactics = _tactics_for_category(category)

        cid = CHAIN_FOR_CATEGORY.get(category)
        if cid:
            rec.chain_ids.append(cid)

    return merged


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  RECORD + CHAIN BUILDERS
# ══════════════════════════════════════════════════════════════════════════

def _to_records(merged: dict[str, SubdomainRecord]) -> list[dict]:
    records: list[dict] = []
    for name in sorted(merged):
        rec = merged[name]
        if not rec.in_scope:
            continue
        records.append({
            "subdomain":      rec.name,
            "root":           rec.root,
            "sources":        sorted(rec.sources),
            "source_count":   len(rec.sources),
            "resolves":       rec.resolves,
            "first_seen":     rec.first_seen.replace("T", " ").split(".")[0],
            "is_apex":            rec.is_apex,
            "sensitive_category": rec.sensitive_category,
            "severity":           rec.severity.value,
            "wildcard":           rec.wildcard,
            "cloud_provider":     rec.cloud_provider,
            "a_records":          rec.a_records,
            "aaaa_records":       rec.aaaa_records,
            "cname_chain":        rec.cname_chain,
            "chain_ids":          rec.chain_ids,
            "tactics":            rec.tactics,
            "finding_hash":       rec.finding_hash,
        })
    return records


def _build_findings(records: list[dict]) -> list[dict]:
    return [r for r in records if r.get("severity") in ("HIGH", "CRITICAL")]


def _build_chains(
    records: list[dict],
    wildcard_roots: set[str],
    roots: list[str],
) -> list[dict]:
    chains: dict[str, list[dict]] = {}

    for r in records:
        for cid in (r.get("chain_ids") or []):
            chains.setdefault(cid, []).append(r)

    for root in wildcard_roots:
        chains.setdefault("recon-wildcard", []).append({
            "subdomain": root, "root": root,
            "severity": "MEDIUM", "wildcard": True, "resolves": True,
        })

    provider_groups: dict[str, list[dict]] = {}
    for r in records:
        cp = r.get("cloud_provider")
        if cp:
            provider_groups.setdefault(cp, []).append(r)
    for provider, recs in provider_groups.items():
        chains.setdefault("recon-cloud-hosted", []).extend(recs)

    if len(records) >= MAX_SUBDOMAINS_AGGRESSIVE:
        chains.setdefault("recon-mass-enum", []).append({
            "subdomain": f"count={len(records)}",
            "count": len(records),
            "threshold": MAX_SUBDOMAINS_AGGRESSIVE,
            "resolves": True,
        })

    out: list[ReconChain] = []
    for cid, members in chains.items():
        meta = CHAIN_METADATA.get(cid, {})
        members_subs = [
            m.get("subdomain") or f"count={m.get('count')}"
            for m in members
        ]
        entry_points = [
            m.get("subdomain") for m in members
            if m.get("subdomain") and m.get("resolves")
        ]
        out.append(ReconChain(
            chain_id     = cid,
            name         = meta.get("name", cid),
            severity     = meta.get("severity", Severity.LOW),
            members      = members_subs,
            reasoning    = meta.get("reasoning", ""),
            pivots       = meta.get("pivots", []),
            entry_points = entry_points,
            evidence     = (f"{len(members)} member(s): "
                            f"{', '.join(members_subs[:5])}"
                            + (f" … (+{len(members_subs) - 5})"
                               if len(members_subs) > 5 else "")),
        ))
    out.sort(key=lambda c: (-c.severity.rank, c.chain_id))
    return [c.to_dict() for c in out]


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  AI ANALYSIS
# ══════════════════════════════════════════════════════════════════════════

AI_SYSTEM_PROMPT = (
    "You are an expert offensive-security analyst reviewing passive subdomain "
    "enumeration results for a bug-bounty program. Your job is to identify the "
    "most promising targets for MANUAL investigation and explain WHY — never "
    "to suggest running exploits. Reference actual subdomain names. Be specific "
    "and concise. If the results look unremarkable, say so plainly."
)


def _build_ai_prompt(
    roots: list[str],
    records: list[dict],
    findings: list[dict],
    chains: list[dict],
    wildcard_roots: set[str],
    provider_counts: dict[str, int],
) -> str:
    total = len(records)
    resolved = sum(1 for r in records if r.get("resolves"))
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in records:
        by_sev[r.get("severity", "LOW")] = by_sev.get(r.get("severity", "LOW"), 0) + 1

    top_findings = findings[:20]
    findings_block = "\n".join(
        f"  - {f['subdomain']:<40} sev={f['severity']:<8} "
        f"cat={f.get('sensitive_category','') or '-':<12} "
        f"resolves={f.get('resolves')} cloud={f.get('cloud_provider','') or '-'}"
        for f in top_findings
    ) or "  (none)"

    chains_block = "\n".join(
        f"  - {c['chain_id']:<32} sev={c['severity']:<8} "
        f"members={c['count']} entry_points={len(c.get('entry_points', []))}"
        for c in chains
    ) or "  (none)"

    cloud_block = (", ".join(f"{k}({v})" for k, v in
                             sorted(provider_counts.items(), key=lambda kv: -kv[1]))
                   or "(none)")

    return f"""Target root domains: {', '.join(roots)}

Scan stats:
  Total unique subdomains: {total}
  Resolving:               {resolved} ({int(resolved*100/max(total,1))}%)
  Wildcard roots:          {', '.join(wildcard_roots) or '(none)'}
  Cloud providers:         {cloud_block}

Severity breakdown:
  CRITICAL: {by_sev['CRITICAL']}
  HIGH:     {by_sev['HIGH']}
  MEDIUM:   {by_sev['MEDIUM']}
  LOW:      {by_sev['LOW']}
  INFO:     {by_sev['INFO']}

Chains detected:
{chains_block}

Top {len(top_findings)} HIGH/CRITICAL findings:
{findings_block}

Provide:
1. A prioritized list of 5-10 subdomains that warrant immediate manual
   investigation, with specific reasoning for each (reference the actual name).
2. Any organizational patterns across the results (e.g. "all CI infra on AWS",
   "staging and prod share a wildcard root").
3. A short list of manual tests to run on the top priorities (DO NOT run them —
   just describe what to test and why).
4. Any red flags suggesting the target may have already detected automated
   enumeration (wildcard-heavy responses, unexpected CNAME sinks).

Keep it under 800 words. Use markdown with clear headers."""


def _run_ai_analysis(
    roots: list[str],
    records: list[dict],
    findings: list[dict],
    chains: list[dict],
    wildcard_roots: set[str],
    provider_counts: dict[str, int],
    outdir: Path,
) -> Optional[dict]:
    if not CFG_LOADED or not hasattr(CFG, "ai_complete"):
        return None
    if not bool(_cfg("AI_ENABLED", False)):
        log.info("AI analysis: disabled (AI_ENABLED=False)")
        return None

    log.info("AI analysis: requesting triage from Mimir's Well...")
    prompt = _build_ai_prompt(roots, records, findings, chains,
                              wildcard_roots, provider_counts)
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
        f"# Huginn · AI Triage Report\n\n"
        f"**Generated:** {generated_at}  \n"
        f"**Targets:** {', '.join(roots)}  \n"
        f"**Subdomains scanned:** {len(records)}  \n"
        f"**Model:** {_cfg('AI.model', 'deepseek-chat')}\n\n"
        f"---\n\n{response}\n"
    )
    md_path = outdir / "subdomains_ai_analysis.md"
    md_path.write_text(md, encoding="utf-8")

    summary = {
        "generated_at":  generated_at,
        "model":         _cfg("AI.model", "deepseek-chat"),
        "targets":       roots,
        "record_count":  len(records),
        "finding_count": len(findings),
        "chain_count":   len(chains),
        "response_md":   response,
        "cost_estimate": _safe_cost(),
    }
    (outdir / "subdomains_ai_analysis.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    log.ok(f"AI analysis saved to {md_path.name} ({len(response)} chars)")
    return summary


def _safe_cost() -> Optional[float]:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return round(tracker.estimate_cost(), 6)
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════
#  ᛗ  EVIDENCE PRESERVATION
# ══════════════════════════════════════════════════════════════════════════

def _save_evidence(source_results: list[SourceResult], evidence_dir: Path) -> None:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for sr in source_results:
            if not sr.raw_output:
                continue
            safe = re.sub(r"[^a-zA-Z0-9._-]+", "_",
                          f"{sr.source}_{sr.domain}")[:80]
            (evidence_dir / f"{safe}.txt").write_text(sr.raw_output[:200000])
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  JSON REPORTS
# ══════════════════════════════════════════════════════════════════════════

def _build_json_report(
    roots: list[str],
    records: list[dict],
    findings: list[dict],
    chains: list[dict],
    source_results: list[SourceResult],
    resolved: set[str],
    wildcard_roots: set[str],
    elapsed: float,
    applied_rate: Optional[int],
    applied_concurrency: int,
    aggressive: bool,
    strict: bool,
    bbp_program: Optional[str],
    audit_path: Optional[str],
    wildcard_deep: bool = False,
) -> dict:
    by_source: dict[str, dict] = {}
    for sr in source_results:
        by_source.setdefault(sr.source, {
            "domain_runs": 0, "ok_runs": 0,
            "total_found": 0, "total_duration": 0.0,
            "last_error": None, "proxy_used": sr.proxy_used,
        })
        entry = by_source[sr.source]
        entry["domain_runs"] += 1
        entry["total_duration"] += sr.duration
        entry["total_found"] += sr.count
        if sr.ok:
            entry["ok_runs"] += 1
        else:
            entry["last_error"] = sr.error

    for v in by_source.values():
        v["total_duration"] = round(v["total_duration"], 2)

    by_category: dict[str, int] = {}
    by_cloud: dict[str, int] = {}
    tactics_counts: dict[str, int] = {}
    for r in records:
        cat = r.get("sensitive_category") or ""
        if cat and cat != "apex":
            by_category[cat] = by_category.get(cat, 0) + 1
        cp = r.get("cloud_provider") or ""
        if cp:
            by_cloud[cp] = by_cloud.get(cp, 0) + 1
        for t in (r.get("tactics") or []):
            tactics_counts[t] = tactics_counts.get(t, 0) + 1

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in records:
        sev = r.get("severity", "LOW")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    return {
        "schema_version":    5,
        "producer":          f"subs.py v{__version__} '{__codename__}'",
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":   round(elapsed, 2),
        "wildcards":         roots,
        "host_capacity": {
            "cpu_cores":       HOST_CORES,
            "ram_mb":          HOST_RAM_MB,
            "lightweight":     LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "bbp_program":    bbp_program,
            "rate_limit":     applied_rate,
            "concurrency":    applied_concurrency,
            "aggressive":     aggressive,
            "strict":         strict,
            "wildcard_deep":  wildcard_deep,
            "dns_validation": bool(resolved),
            "scope_enforced": True,
            "sources":        ["subfinder", "assetfinder", "findomain",
                               "crt.sh", "hackertarget", "alienvault"]
                              + (["amass"] if _should_run_amass(aggressive) else [])
                              + (["wayback"] if aggressive else []),
        },
        "audit": {
            "trail_path":   audit_path,
            "trail_sha256": _audit_hash(audit_path),
        },
        "totals": {
            "unique_subdomains": len(records),
            "resolved":          len(resolved) if resolved else None,
            "sources_run":       len(source_results),
            "sources_ok":        sum(1 for s in source_results if s.ok),
            "sensitive":         len(findings),
            "wildcard_roots":    len(wildcard_roots),
            "by_severity":       by_sev,
            "by_category":       dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "by_cloud_provider": dict(sorted(by_cloud.items(), key=lambda kv: -kv[1])),
            "by_tactic":         dict(sorted(tactics_counts.items(), key=lambda kv: -kv[1])),
        },
        "sources":    by_source,
        "subdomains": records,
        "findings":   findings,
        "chains":     chains,
    }


def _audit_hash(audit_path: Optional[str]) -> Optional[str]:
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


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def enumerate_subdomains(
    scope_file: Optional[Path] = None,
    outdir: Optional[Path] = None,
    *,
    targets: Optional[list[str]] = None,
    resolve: bool = True,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
    aggressive: bool = True,
    strict: bool = True,
    bbp_program: Optional[str] = None,
    proxy_pool: Any = None,
    audit_trail: Any = None,
    dry_run: bool = False,
    wildcard_deep: bool = False,
) -> Path:
    start = time.monotonic()

    outdir = outdir or (_cfg("OUTPUT_DIR") or Path("output"))
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "subs_evidence"

    bbp_headers: dict[str, str] = {}
    if bbp_program:
        try:
            builder = _cfg("build_headers")
            if callable(builder):
                bbp_headers = builder(bbp_program, dynamic_ua=False)
                log.info(f"BBP profile: {bbp_program} "
                         f"({len(bbp_headers)} headers staged)")
        except Exception as e:
            log.warn(f"build_headers({bbp_program}) failed: {e}")

    # ── Roots ────────────────────────────────────────────────────────────
    if targets:
        roots = sorted({t.strip().lower() for t in targets if t.strip()})
        log.info(f"Targets (explicit): {len(roots)} root(s)")
    elif scope_file:
        if not scope_file.exists():
            raise FileNotFoundError(f"scope file not found: {scope_file}")
        validator = _cfg("SCOPE")
        if validator is not None and hasattr(validator, "load_from_file"):
            validator.load_from_file(scope_file)
            roots = roots_from_scope(validator)
        else:
            roots = _parse_scope_file_fallback(scope_file)
        log.info(f"Targets (from {scope_file.name}): {len(roots)} root(s)")
    else:
        validator = _cfg("SCOPE")
        roots = roots_from_scope(validator) if validator else []
        if not roots:
            raise ValueError("no targets: pass --scope, --targets, or populate scope.txt")
        log.info(f"Targets (from config.SCOPE): {len(roots)} root(s)")

    if not roots:
        raise ValueError("no valid root domains resolved from input")

    for r in roots:
        log.info(f"  {Sym.ARROW} {r}")

    # ── Rate / concurrency ───────────────────────────────────────────────
    cfg_rate = None
    cfg_concurrency = DEFAULT_SUBS_CONCURRENCY
    module_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    subs_limits = module_limits.get("subs", {})
    if isinstance(subs_limits, dict):
        cfg_rate = subs_limits.get("rps")
        cfg_concurrency = subs_limits.get("concurrency", DEFAULT_SUBS_CONCURRENCY)
    eff_rate = rate_limit if rate_limit is not None else cfg_rate
    eff_concurrency = concurrency if concurrency is not None else cfg_concurrency
    if not isinstance(eff_concurrency, int) or eff_concurrency < 1:
        eff_concurrency = DEFAULT_SUBS_CONCURRENCY
    eff_concurrency = _effective_concurrency(eff_concurrency)

    log.info("")
    log.info(f"Config: rate_limit={eff_rate or 'unlimited'}  "
             f"concurrency={eff_concurrency}  "
             f"resolve={resolve}  aggressive={aggressive}  strict={strict}  "
             f"wildcard_deep={wildcard_deep}")
    if LIGHTWEIGHT_MODE:
        log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — concurrency capped")
    if bbp_headers:
        log.info(f"Headers: {', '.join(sorted(bbp_headers))} (staged, not applied to passive APIs)")

    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        tasks = _plan_tasks(roots, aggressive)
        for source, domain in tasks:
            log.info(f"  would run  {source:<12} on {domain}")
        log.info("")
        log.info(f"Output would be written to: {outdir}")
        log.info(f"Evidence would go to     : {evidence_dir}")
        if _cfg("AI_ENABLED", False):
            log.info(f"AI analysis would be enabled")
        return outdir / "all_subs.txt"

    # ── Proxy + audit ────────────────────────────────────────────────────
    if proxy_pool is None:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls is not None:
                proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
                if proxy_pool is not None:
                    snap = getattr(proxy_pool, "snapshot", lambda: [])()
                    log.info(f"ProxyPool: {len(snap)} proxies loaded")
        except Exception as e:
            log.warn(f"ProxyPool load failed: {e}")
            proxy_pool = None

    if audit_trail is None:
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                audit_trail = factory(roots[0])
        except Exception as e:
            log.debug(f"audit trail creation failed: {e}")

    audit_path_str: Optional[str] = None
    if audit_trail is not None and hasattr(audit_trail, "path"):
        audit_path_str = str(audit_trail.path)
        log.info(f"Audit trail: {audit_trail.path}")

    # ── Execute ──────────────────────────────────────────────────────────
    log.rune(Rune.RAIDO, "Huginn takes flight")
    tasks = _plan_tasks(roots, aggressive)
    log.info(f"Dispatching {len(tasks)} source task(s) with {eff_concurrency} worker(s)")

    source_results: list[SourceResult] = []
    source_failure_counts: dict[str, int] = {}
    http_kw = dict(proxy_pool=proxy_pool, audit=audit_trail,
                   headers=bbp_headers or None)

    def _dispatch(source: str, domain: str) -> Optional[SourceResult]:
        if source_failure_counts.get(source, 0) >= 2:
            log.debug(f"circuit open: {source} — skipping {domain}")
            return None
        if CFG_LOADED and hasattr(CFG, "KillSwitch"):
            CFG.KillSwitch.check()
        try:
            if source == "subfinder":
                return _run_subfinder(domain, eff_rate,
                                      proxy=_proxy_for_subfinder(proxy_pool))
            if source == "assetfinder":  return _run_assetfinder(domain)
            if source == "amass":        return _run_amass(domain,
                                                           timeout=TIMEOUT_AMASS * (2 if aggressive else 1))
            if source == "findomain":    return _run_findomain(domain)
            if source == "hackertarget": return _run_hackertarget(domain, **http_kw)
            if source == "alienvault":   return _run_alienvault(domain, **http_kw)
            if source == "wayback":      return _run_wayback(domain, **http_kw)
            if source == "crt.sh":       return _run_crtsh(domain, **http_kw)
        except Exception as e:
            log.debug(f"{source} crashed: {type(e).__name__}: {e}")
            return SourceResult(source, domain, error=str(e))
        return None

    with ThreadPoolExecutor(max_workers=eff_concurrency) as pool:
        futures = {pool.submit(_dispatch, s, d): (s, d) for s, d in tasks}
        for fut in as_completed(futures):
            source, domain = futures[fut]
            try:
                sr = fut.result()
            except Exception as e:
                sr = SourceResult(source, domain, error=str(e))
            if sr is None:
                continue
            source_results.append(sr)
            if sr.ok:
                source_failure_counts[source] = 0
                log.info(f"  {source:<12} {domain:<28} "
                         f"{Sym.CHECK} {sr.count:>4}  ({sr.duration:.1f}s)")
            else:
                source_failure_counts[source] = source_failure_counts.get(source, 0) + 1
                log.info(f"  {source:<12} {domain:<28} "
                         f"{Sym.CROSS} {sr.error or 'failed'}  ({sr.duration:.1f}s)")

    # ── Fallback ─────────────────────────────────────────────────────────
    pre_merged = _aggregate(source_results, roots, set(), {},
                            scope_validator=_cfg("SCOPE"))
    if not pre_merged:
        log.warn("all sources empty — attempting crt.sh fallback")
        for domain in roots:
            sr = _run_crtsh(domain, **http_kw)
            source_results.append(sr)
        pre_merged = _aggregate(source_results, roots, set(), {},
                                scope_validator=_cfg("SCOPE"))

    # ── Wildcard ─────────────────────────────────────────────────────────
    wildcard_roots: set[str] = set()
    if resolve and pre_merged:
        log.rune(Rune.THURISAZ, "Wildcard detection")
        wildcard_roots = _detect_wildcard_roots(
            roots,
            subdomains=list(pre_merged.keys()) if wildcard_deep else None,
            deep=wildcard_deep,
        )

    # ── DNS ──────────────────────────────────────────────────────────────
    dns_records: dict[str, dict] = {}
    resolved: set[str] = set()
    if resolve and pre_merged:
        log.rune(Rune.ANSUZ, "DNS enrichment")
        sub_list = sorted(pre_merged.keys())
        dns_records = _resolve_with_dnsx(sub_list, rate_limit=eff_rate)
        resolved = {n for n, rec in dns_records.items()
                    if rec.get("a") or rec.get("aaaa") or rec.get("cname")}
        log.info(f"resolved {len(resolved)}/{len(sub_list)} "
                 f"({int(len(resolved)*100/max(len(sub_list),1))}%)")

    # ── Aggregate w/ scope + strict, and TRIM resolved to in-scope ───────
    merged_pre_scope = _aggregate(source_results, roots, wildcard_roots,
                                   dns_records, scope_validator=None)
    merged = _aggregate(source_results, roots, wildcard_roots, dns_records,
                        scope_validator=_cfg("SCOPE"))

    dropped = len(merged_pre_scope) - len(merged)
    if dropped > 0:
        pct = int(dropped * 100 / max(len(merged_pre_scope), 1))
        if pct >= 25:
            log.warn(f"scope filter dropped {dropped}/{len(merged_pre_scope)} "
                     f"({pct}%) records")
            log.warn(f"  → check scope.txt: `{roots[0]}` may need `*.{roots[0]}`")
        else:
            log.debug(f"scope filter dropped {dropped} out-of-scope entries")

    if strict and resolved:
        merged = {k: v for k, v in merged.items() if k in resolved}
        log.info(f"strict mode: filtered to {len(merged)} resolving entries")

    # FIX: trim resolved set to in-scope names only (bug fix v5.1)
    if resolved:
        resolved = resolved & set(merged.keys())

    records = _to_records(merged)
    findings = _build_findings(records)
    chains = _build_chains(records, wildcard_roots, roots)

    provider_counts: dict[str, int] = {}
    for r in records:
        cp = r.get("cloud_provider")
        if cp:
            provider_counts[cp] = provider_counts.get(cp, 0) + 1

    _save_evidence(source_results, evidence_dir)

    # ── Write outputs ────────────────────────────────────────────────────
    txt_path = outdir / "all_subs.txt"
    all_names = sorted(r["subdomain"] for r in records)
    txt_path.write_text("\n".join(all_names) + ("\n" if all_names else ""))

    if resolved:
        (outdir / "subs_resolved.txt").write_text(
            "\n".join(sorted(resolved)) + "\n")

    sensitive = sorted(r["subdomain"] for r in findings)
    (outdir / "subs_sensitive.txt").write_text(
        "\n".join(sensitive) + ("\n" if sensitive else ""))

    elapsed = time.monotonic() - start
    report = _build_json_report(
        roots, records, findings, chains, source_results, resolved,
        wildcard_roots, elapsed, applied_rate=eff_rate,
        applied_concurrency=eff_concurrency,
        aggressive=aggressive, strict=strict,
        bbp_program=bbp_program, audit_path=audit_path_str,
        wildcard_deep=wildcard_deep,
    )
    (outdir / "subdomains.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    (outdir / "subdomains_confirmed.json").write_text(
        json.dumps({
            "schema_version": 5,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "totals": {
                "confirmed": len(findings),
                "critical":  sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high":      sum(1 for f in findings if f["severity"] == "HIGH"),
                "by_category": report["totals"]["by_category"],
            },
            "findings": findings,
        }, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    (outdir / "subdomains_chains.json").write_text(
        json.dumps({
            "schema_version": 5,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "chains": chains,
        }, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # ── AI ───────────────────────────────────────────────────────────────
    log.rune(Rune.GEBO, "Mimir's Well · AI triage")
    ai_summary = _run_ai_analysis(
        roots, records, findings, chains, wildcard_roots,
        provider_counts, outdir,
    )

    if scan_id is not None:
        _try_db_sync(scan_id, records)

    _print_summary(
        outdir, txt_path, records, findings, chains, source_results,
        resolved, wildcard_roots, provider_counts, elapsed, ai_summary,
    )
    return txt_path


def _plan_tasks(roots: list[str], aggressive: bool) -> list[tuple[str, str]]:
    tasks: list[tuple[str, str]] = []
    run_amass = _should_run_amass(aggressive)
    for domain in roots:
        tasks.append(("subfinder",    domain))
        tasks.append(("assetfinder",  domain))
        if run_amass:
            tasks.append(("amass", domain))
        tasks.append(("findomain",    domain))
        tasks.append(("hackertarget", domain))
        tasks.append(("alienvault",   domain))
        if aggressive:
            tasks.append(("wayback", domain))
    return tasks


def _proxy_for_subfinder(pool: Any) -> Any:
    if pool is None:
        return None
    try:
        return pool.pick()
    except Exception:
        return None


def _parse_scope_file_fallback(path: Path) -> list[str]:
    roots: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        pattern = line[2:] if line.startswith("*.") else line
        if _DOMAIN_RE.match(pattern.lower()):
            roots.add(pattern.lower())
    return sorted(roots)


def _try_db_sync(scan_id: int, records: list[dict]) -> None:
    try:
        from db import DB  # type: ignore[import-not-found]
        if not getattr(DB, "available", False):
            log.warn("DB sync: bridge not ready")
            return
        result = DB.upsert_subdomains(scan_id, records)
        log.info(f"DB sync: {result} subdomain(s) upserted (scan_id={scan_id})")
    except ImportError:
        log.info("DB sync: db.py not available — skipping")
    except Exception as e:
        log.warn(f"DB sync failed: {type(e).__name__}: {e}")


def _print_summary(
    outdir: Path, txt_path: Path, records: list[dict], findings: list[dict],
    chains: list[dict], source_results: list[SourceResult],
    resolved: set[str], wildcard_roots: set[str],
    provider_counts: dict[str, int], elapsed: float,
    ai_summary: Optional[dict],
) -> None:
    log.rune(Rune.SOWILO, "Summary")
    if LIGHTWEIGHT_MODE:
        log.info(f"Host           : LIGHTWEIGHT ({LIGHTWEIGHT_REASON})")
    else:
        log.info(f"Host           : {HOST_CORES} cores / {HOST_RAM_MB} MB RAM")
    log.info(f"Total unique subdomains : {len(records)}")
    log.info(f"Resolved                : {len(resolved)}"
             + (f" ({int(len(resolved)*100/max(len(records),1))}%)" if records else ""))
    log.info(f"Sensitive (HIGH+CRIT)   : {len(findings)}")
    log.info(f"Wildcard roots          : {len(wildcard_roots)}")
    if provider_counts:
        log.info("Cloud providers         : " + " · ".join(
            f"{k}({v})" for k, v in sorted(provider_counts.items(), key=lambda kv: -kv[1])))

    # Tactic distribution
    tactic_counts: dict[str, int] = {}
    for r in records:
        for t in (r.get("tactics") or []):
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
    if tactic_counts:
        log.info("Top tactics             : " + " · ".join(
            f"{k}({v})" for k, v in
            sorted(tactic_counts.items(), key=lambda kv: -kv[1])[:6]))

    if findings:
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        log.info("")
        log.warn(f"Severity: CRITICAL={critical} HIGH={high}")
        for f in findings[:10]:
            sev = f["severity"]
            col = "blood" if sev == "CRITICAL" else "crimson"
            log.info(f"  {_c(col)}{sev:<8}{_c('reset')}  {f['subdomain']}  "
                     f"({f.get('sensitive_category', '')})")

    if chains:
        log.info("")
        log.info("Chains detected:")
        for c in chains[:8]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<32} "
                     f"[{c['severity']}] {c['count']} member(s)")

    log.info("")
    log.info("Outputs:")
    for name, count in [
        ("all_subs.txt",               len(records)),
        ("subdomains.json",            len(records)),
        ("subdomains_confirmed.json",  len(findings)),
        ("subdomains_chains.json",     len(chains)),
        ("subs_resolved.txt",          len(resolved)),
        ("subs_sensitive.txt",         len(findings)),
    ]:
        if (outdir / name).exists():
            log.info(f"  {Sym.ARROW} {name:<32} {count:>5}")
    evidence_count = sum(1 for sr in source_results if sr.raw_output)
    if evidence_count:
        log.info(f"  {Sym.ARROW} subs_evidence/                {evidence_count:>5}")

    if ai_summary:
        log.info(f"  {Sym.ARROW} subdomains_ai_analysis.md")
        if ai_summary.get("cost_estimate"):
            log.info(f"    AI cost: ${ai_summary['cost_estimate']:.6f}")

    log.info("")
    log.info(f"Completed in {elapsed:.1f}s  →  {txt_path}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Huginn integrity")

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config module loaded",       lambda: CFG_LOADED),
        ("log callable",               lambda: callable(log.info)),
        ("Sym.RAVEN present",          lambda: hasattr(Sym, "RAVEN")),
        ("Severity enum",              lambda: Severity.CRITICAL.rank == 4),
        ("sensitive categories",       lambda: len(SENSITIVE_CATEGORIES) >= 15),
        ("tactics dict",               lambda: len(TACTICS) >= 15),
        ("cloud patterns",             lambda: len(CLOUD_PROVIDER_PATTERNS) >= 10),
        ("chain metadata",             lambda: len(CHAIN_METADATA) >= 12),
        ("normalize_subdomain",        lambda: callable(normalize_subdomain)),
        ("normalize strips scheme",    lambda: normalize_subdomain("https://a.b.com/x") == "a.b.com"),
        ("normalize rejects empty",    lambda: normalize_subdomain("") is None),
        ("roots_from_scope",           lambda: callable(roots_from_scope)),
        ("http_get",                   lambda: callable(http_get)),
        ("_run_subfinder",             lambda: callable(_run_subfinder)),
        ("_run_crtsh",                 lambda: callable(_run_crtsh)),
        ("_run_wayback",               lambda: callable(_run_wayback)),
        ("_run_alienvault",            lambda: callable(_run_alienvault)),
        ("_detect_wildcard_roots",     lambda: callable(_detect_wildcard_roots)),
        ("_resolve_with_dnsx",         lambda: callable(_resolve_with_dnsx)),
        ("_classify_sensitive",        lambda: callable(_classify_sensitive)),
        ("_tactics_for_category",      lambda: callable(_tactics_for_category)),
        ("_detect_cloud_provider",     lambda: callable(_detect_cloud_provider)),
        ("_aggregate",                 lambda: callable(_aggregate)),
        ("_to_records",                lambda: callable(_to_records)),
        ("_build_findings",            lambda: callable(_build_findings)),
        ("_build_chains",              lambda: callable(_build_chains)),
        ("_run_ai_analysis",           lambda: callable(_run_ai_analysis)),
        ("_save_evidence",             lambda: callable(_save_evidence)),
        ("enumerate_subdomains",       lambda: callable(enumerate_subdomains)),
        ("_measure_host",              lambda: callable(_measure_host)),
        ("_effective_concurrency",     lambda: callable(_effective_concurrency)),
        ("_should_run_amass",          lambda: callable(_should_run_amass)),
        ("classify 'db' → CRITICAL",   lambda: _classify_sensitive("db.example.com",
                                                                     "example.com")[1] == Severity.CRITICAL),
        ("classify 'jenkins' → CRIT",  lambda: _classify_sensitive("jenkins.example.com",
                                                                     "example.com")[1] == Severity.CRITICAL),
        ("classify 'staging' → HIGH",  lambda: _classify_sensitive("staging.example.com",
                                                                     "example.com")[1] == Severity.HIGH),
        ("classify 'www' → LOW",       lambda: _classify_sensitive("www.example.com",
                                                                     "example.com")[1] == Severity.LOW),
        ("classify 'api' → MEDIUM",    lambda: _classify_sensitive("api.example.com",
                                                                     "example.com")[1] == Severity.MEDIUM),
        ("classify 'v1' → MEDIUM",     lambda: _classify_sensitive("v1.example.com",
                                                                     "example.com")[1] == Severity.MEDIUM),
        ("classify 'billing' → HIGH",  lambda: _classify_sensitive("billing.example.com",
                                                                     "example.com")[1] == Severity.HIGH),
        ("tactics for admin",          lambda: "login-bypass" in _tactics_for_category("admin")),
        ("tactics empty for apex",     lambda: _tactics_for_category("apex") == []),
        ("cloud detect cloudfront",    lambda: _detect_cloud_provider(
                                            ["d123.cloudfront.net"]) == "AWS"),
        ("cloud detect vercel",        lambda: _detect_cloud_provider(
                                            ["x.vercel.app"]) == "Vercel"),
        ("RFC1918 detect 10.x",        lambda: _is_internal_ip("10.0.0.1")),
        ("RFC1918 detect 192.168",     lambda: _is_internal_ip("192.168.1.1")),
        ("RFC1918 reject 8.8.8.8",     lambda: not _is_internal_ip("8.8.8.8")),
        ("host measure sane",          lambda: HOST_CORES >= 1),
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

    log.ok(f"config.py loaded")
    log.info(f"  version      : {_cfg('__version__', '?')} \"{_cfg('__codename__', '?')}\"")
    log.info(f"  path         : {getattr(CFG, '__file__', '?')}")

    checks = [
        ("SCOPE",                     lambda: _cfg("SCOPE") is not None),
        ("ProxyPool",                 lambda: _cfg("ProxyPool") is not None),
        ("new_audit_trail",           lambda: callable(_cfg("new_audit_trail"))),
        ("KillSwitch",                lambda: _cfg("KillSwitch") is not None),
        ("build_headers",             lambda: callable(_cfg("build_headers"))),
        ("ai_complete",               lambda: callable(_cfg("ai_complete"))),
        ("MODULE_RATE_LIMITS['subs']",lambda: "subs" in (_cfg("MODULE_RATE_LIMITS", {}) or {})),
        ("PROGRAMS['hackerone']",     lambda: "hackerone" in (_cfg("PROGRAMS", {}) or {})),
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

    subs_limits = ((_cfg("MODULE_RATE_LIMITS", {}) or {}).get("subs") or {})
    if subs_limits:
        log.info(f"  subs rate    : rps={subs_limits.get('rps')} "
                 f"concurrency={subs_limits.get('concurrency')}")
    else:
        log.warn("  subs rate    : NOT CONFIGURED — will default to unlimited")

    log.info(f"  AI_ENABLED   : {_cfg('AI_ENABLED', False)}")
    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} optional item(s) unconfigured — subs will still run ══  {Sym.WARN}{_c('reset')}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    p = argparse.ArgumentParser(
        prog="subs.py",
        description=f"Argus recon · subs v{__version__} '{__codename__}'",
    )
    p.add_argument("--config-check", action="store_true",
                   help="verify config.py integration before running")
    p.add_argument("--scope", type=Path, default=None,
                   help="path to scope.txt (default: ./scope.txt)")
    p.add_argument("--targets", type=str, default=None,
                   help="comma-separated root domains (overrides --scope)")
    p.add_argument("--output", type=Path, default=base / "output",
                   help="output directory")
    p.add_argument("--bbp", type=str, default=None,
                   help="bug-bounty program profile")
    p.add_argument("--scan-id", type=int, default=None,
                   help="DB self-sync scan ID")
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--concurrency", type=int, default=None)
    p.add_argument("--no-resolve", action="store_true",
                   help="skip DNS enrichment")

    # aggressive: default ON, opt out with --no-aggressive
    p.add_argument("--aggressive", dest="aggressive", action="store_true",
                   default=True,
                   help="enable wayback + extended amass (default: ON)")
    p.add_argument("--no-aggressive", dest="aggressive", action="store_false",
                   help="disable aggressive mode")

    # strict: default ON, opt out with --no-strict
    p.add_argument("--strict", dest="strict", action="store_true",
                   default=True,
                   help="drop non-resolving entries (default: ON)")
    p.add_argument("--no-strict", dest="strict", action="store_false",
                   help="keep non-resolving entries")

    p.add_argument("--wildcard-deep", action="store_true",
                   help="test wildcard DNS on subdomains too (slower)")
    p.add_argument("--dry-run", action="store_true",
                   help="print plan; do not touch the network")
    p.add_argument("--selftest", action="store_true",
                   help="verify Huginn's integrity")
    p.add_argument("--test-sources", action="store_true",
                   help="test each passive source once with a known domain")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                   version=f"subs.py {__version__} '{__codename__}'")
    return p


def _test_sources() -> int:
    print_banner()
    log.rune(Rune.KANO, "Source test · plumbing check")
    test_domain = "example.com"
    http_kw: dict = {}
    if CFG_LOADED:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls is not None:
                http_kw["proxy_pool"] = pool_cls.from_file(_cfg("PROXIES_FILE"))
        except Exception:
            pass
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                http_kw["audit"] = factory(f"selftest-{test_domain}")
        except Exception:
            pass

    results: list[SourceResult] = []
    for name, fn in [
        ("subfinder",    lambda: _run_subfinder(test_domain, 5)),
        ("assetfinder",  lambda: _run_assetfinder(test_domain)),
        ("amass",        lambda: _run_amass(test_domain, timeout=90)),
        ("findomain",    lambda: _run_findomain(test_domain)),
        ("hackertarget", lambda: _run_hackertarget(test_domain, **http_kw)),
        ("alienvault",   lambda: _run_alienvault(test_domain, **http_kw)),
        ("crt.sh",       lambda: _run_crtsh(test_domain, **http_kw)),
        ("wayback",      lambda: _run_wayback(test_domain, **http_kw)),
    ]:
        try:
            sr = fn()
            results.append(sr)
            if sr.ok:
                log.ok(f"{name:<12} {sr.count:>4} results  ({sr.duration:.1f}s)")
            else:
                if "not installed" in (sr.error or ""):
                    log.info(f"{name:<12} not installed — skipped")
                else:
                    log.warn(f"{name:<12} {sr.error}")
        except Exception as e:
            log.error(f"{name:<12} raised {type(e).__name__}: {e}")

    healthy = sum(1 for r in results if r.ok)
    print()
    if healthy > 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ {healthy} source(s) healthy ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('crimson')}{Sym.SKULL}  ══ no sources responsive ══  {Sym.SKULL}{_c('reset')}")
    return 1


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

    if args.test_sources:
        return _test_sources()

    print_banner()

    try:
        targets_list: Optional[list[str]] = None
        if args.targets:
            targets_list = [t.strip() for t in args.targets.split(",") if t.strip()]

        enumerate_subdomains(
            scope_file=args.scope,
            outdir=args.output,
            targets=targets_list,
            resolve=not args.no_resolve,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            scan_id=args.scan_id,
            aggressive=args.aggressive,
            strict=args.strict,
            bbp_program=args.bbp,
            dry_run=args.dry_run,
            wildcard_deep=args.wildcard_deep,
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
