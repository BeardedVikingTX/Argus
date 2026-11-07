#!/usr/bin/env python3
"""
recon_tools/subs.py — Subdomain Enumeration (v4.0, military-grade)
═══════════════════════════════════════════════════════════════════════════════

Orchestrates eight passive subdomain sources in parallel, enriches each
result with CNAME chains, cloud provider attribution, wildcard detection,
and sensitive-subdomain classification, then writes a structured JSON report
plus a HIGH+/CRITICAL-only confirmed report and recon chains.

SOURCES (parallel, per root domain)
───────────────────────────────────
  • subfinder    — ProjectDiscovery, 40+ passive APIs
  • assetfinder  — TomNomNom, different source mix
  • amass        — OWASP, deepest passive coverage (slow)
  • findomain    — Rust-based, fast passive (if installed)
  • crt.sh       — Certificate Transparency (HTTP, no install)
  • hackertarget — Free CSV API (HTTP, no key)
  • alienvault   — OTX passive DNS (HTTP, no key)
  • wayback      — CDX hosts (aggressive-only, HTTP, no key)

ENRICHMENT
──────────
  1. DNS resolution via dnsx -json -a -aaaa -cname (structured output).
     Falls back to threaded socket.gethostbyname_ex if dnsx unavailable.
  2. Wildcard detection per root domain: queries a random subdomain,
     flags roots where it resolves (indicates wildcard DNS — high noise).
  3. Cloud provider detection from CNAME chain (AWS/GCP/Azure/Cloudflare/
     Fastly/DigitalOcean/Vercel/Netlify/Heroku/Shopify/GitHub Pages/
     Firebase).
  4. Sensitive subdomain classification: db/mysql/redis/mongo → CRITICAL,
     jenkins/gitlab/ci → CRITICAL, admin/staging/vpn → HIGH,
     api/storage/monitoring → MEDIUM, mail/docs → LOW.

CONFIRMATION MODEL
──────────────────
Findings are only emitted for classified sensitive subdomains. Severity is
taken from the classification table, then adjusted:
  +1 level if wildcard root (reduces signal — false positives common)
  +1 level if is_apex (unusual for apex to be db/admin)
  Not adjusted for resolution status — that's recorded but doesn't
  affect severity (a non-resolving jenkins.* still matters).

CHAINS
──────
  recon-database-exposed    db/mysql/redis/mongo family found
  recon-cicd-exposed        jenkins/gitlab/ci/cd family found
  recon-admin-surface       admin/portal/manage family found
  recon-staging-environment staging/dev/test/qa family found
  recon-vpn-surface         vpn/jump/bastion/gateway family found
  recon-backup-exposure     backup/archive/old/legacy family found
  recon-monitoring-exposed  grafana/kibana/prometheus family found
  recon-api-discovery       api/graphql/rest family found
  recon-storage-exposure    s3/cdn/assets/storage family found
  recon-internal-leak       internal/intranet/corp family found
  recon-wildcard            wildcard DNS detected on root
  recon-cloud-hosted        resolves to a known cloud provider
  recon-mass-enum           >100 subdomains (active program indicator)

OUTPUTS
───────
  all_subs.txt                 sorted dedup list (unchanged)
  subdomains.json              full structured report
  subdomains_confirmed.json    HIGH+/CRITICAL findings only
  subdomains_chains.json       recon chains
  subs_resolved.txt            only resolving subdomains
  subs_sensitive.txt           flat list of classified sensitive subs
  subs_evidence/<src>_<dom>.txt  raw per-source output

BACKWARD COMPAT
───────────────
  The `subdomains[]` array in subdomains.json preserves the original
  6 fields plus new additions — main.py's _sync_recon_stage("subs") →
  DB.upsert_subdomains() keeps working unchanged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.subs")


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
    from db import DB, ArgusDB  # noqa: F401
    DB_AVAILABLE = True
except ImportError:
    DB = None
    DB_AVAILABLE = False


def _cfg(key: str, default=None):
    return getattr(CFG, key, default) if CFG_LOADED else default


def _subs_settings() -> tuple[Optional[int], int]:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("subs", {})
    rl = entry.get("rate_limit", SUBFINDER_RATE_LIMIT)
    cc = entry.get("concurrency", 3)
    if rl is not None and rl <= 0:
        rl = None
    if not isinstance(cc, int) or cc < 1:
        cc = 3
    return rl, cc


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY
# ═════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

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

SUBFINDER_RATE_LIMIT: Optional[int] = 20
SUBFINDER_PROXY: Optional[str] = None

ENABLE_CRTSH_FALLBACK = True
WILDCARD_TEST_LABEL = "arguswildcardcheck"

ARGUS_UA = "argus-subs/4.0 (+https://github.com/BeardedVikingTX/Argus)"
MAX_SUBDOMAINS_AGGRESSIVE = 100


# ── Sensitive subdomain categories ──────────────────────────────────────────
# Each category: (list of pattern tokens, baseline severity)
SENSITIVE_CATEGORIES: dict[str, tuple[list[str], Severity]] = {
    "database": (
        ["db", "sql", "mysql", "postgres", "postgresql", "redis",
         "mongo", "mongodb", "cassandra", "elasticsearch", "elastic",
         "oracle", "sqlserver", "mssql", "mariadb", "clickhouse",
         "influx", "influxdb"],
        Severity.CRITICAL,
    ),
    "cicd": (
        ["jenkins", "gitlab", "git", "github", "bitbucket",
         "jira", "confluence", "sonar", "sonarqube",
         "nexus", "artifactory", "harbor", "registry",
         "ci", "cd", "drone", "teamcity", "bamboo", "travis",
         "codebuild", "buildkite", "argo", "argocd", "flux",
         "spinnaker", "runner", "cicd", "actions"],
        Severity.CRITICAL,
    ),
    "admin": (
        ["admin", "administrator", "manage", "manager", "management",
         "portal", "control", "controlpanel", "cp", "cpanel", "whm",
         "plesk", "webmin", "console", "dashboard"],
        Severity.HIGH,
    ),
    "staging": (
        ["staging", "stage", "stg", "dev", "develop", "development",
         "test", "testing", "qa", "uat", "preprod", "pre-prod",
         "sandbox", "demo", "beta", "alpha", "rc", "preview"],
        Severity.HIGH,
    ),
    "vpn": (
        ["vpn", "jump", "jumpbox", "bastion", "gateway", "remote",
         "rdp", "fortinet", "cisco", "anyconnect", "pulse", "openvpn",
         "wireguard"],
        Severity.HIGH,
    ),
    "backup": (
        ["backup", "bkp", "bak", "archive", "old", "legacy",
         "restore", "snapshot"],
        Severity.HIGH,
    ),
    "monitoring": (
        ["grafana", "kibana", "prometheus", "monitoring", "metrics",
         "logs", "datadog", "sentry", "jaeger", "zipkin", "graylog",
         "zabbix", "nagios", "newrelic", "splunk", "logstash",
         "alertmanager"],
        Severity.HIGH,
    ),
    "internal": (
        ["internal", "intranet", "corp", "corporate", "local", "private"],
        Severity.HIGH,
    ),
    "api": (
        ["api", "graphql", "rest", "rpc", "grpc", "soap", "webhook"],
        Severity.MEDIUM,
    ),
    "storage": (
        ["s3", "storage", "blob", "files", "uploads", "cdn",
         "assets", "static", "media", "images", "img", "download"],
        Severity.MEDIUM,
    ),
    "proxy": (
        ["proxy", "nginx", "apache", "traefik", "haproxy", "varnish",
         "squid", "envoy"],
        Severity.MEDIUM,
    ),
    "mail": (
        ["mail", "smtp", "imap", "pop3", "webmail", "mx",
         "exchange", "autodiscover", "autoconfig"],
        Severity.LOW,
    ),
    "documentation": (
        ["docs", "wiki", "help", "support", "knowledge", "kb",
         "swagger", "openapi", "api-docs", "redoc", "readme"],
        Severity.LOW,
    ),
}

# ── Cloud provider CNAME patterns ───────────────────────────────────────────
CLOUD_PROVIDER_PATTERNS: dict[str, list[str]] = {
    "AWS": [
        ".elb.amazonaws.com", ".compute.amazonaws.com",
        ".cloudfront.net", ".s3.amazonaws.com", ".s3-",
        ".execute-api.", ".awsglobalaccelerator.com",
    ],
    "GCP": [
        ".googlehosted.com", ".run.app", ".appspot.com",
        ".storage.googleapis.com", ".googleapis.com",
    ],
    "Azure": [
        ".azurewebsites.net", ".cloudapp.azure.com",
        ".azurefd.net", ".trafficmanager.net", ".azureedge.net",
        ".blob.core.windows.net", ".azure-api.net",
    ],
    "Cloudflare": [".cloudflare.net", ".cdn.cloudflare.net"],
    "Fastly": [".fastly.net", ".fastlylb.net", ".global.ssl.fastly.net"],
    "DigitalOcean": [".ondigitalocean.app", ".digitaloceanspaces.com"],
    "Vercel": [".vercel-dns.com", ".vercel.app", ".now.sh"],
    "Netlify": [".netlify.app", ".netlify.com"],
    "Heroku": [".herokudns.com", ".herokuapp.com"],
    "Shopify": [".myshopify.com"],
    "GitHub Pages": [".github.io", ".githubusercontent.com"],
    "Firebase": [".firebaseapp.com", ".web.app"],
}

# Chain ID mapping from category
CHAIN_FOR_CATEGORY: dict[str, str] = {
    "database":      "recon-database-exposed",
    "cicd":          "recon-cicd-exposed",
    "admin":         "recon-admin-surface",
    "staging":       "recon-staging-environment",
    "vpn":           "recon-vpn-surface",
    "backup":        "recon-backup-exposure",
    "monitoring":    "recon-monitoring-exposed",
    "api":           "recon-api-discovery",
    "storage":       "recon-storage-exposure",
    "internal":      "recon-internal-leak",
    "proxy":         "recon-proxy-surface",
}

CHAIN_NAMES: dict[str, str] = {
    "recon-database-exposed":    "Exposed database subdomain",
    "recon-cicd-exposed":        "Exposed CI/CD subdomain",
    "recon-admin-surface":       "Admin panel subdomain",
    "recon-staging-environment": "Staging/dev environment subdomain",
    "recon-vpn-surface":         "VPN/remote access subdomain",
    "recon-backup-exposure":     "Backup/legacy subdomain",
    "recon-monitoring-exposed":  "Monitoring subdomain",
    "recon-api-discovery":       "API subdomain",
    "recon-storage-exposure":    "Storage/CDN subdomain",
    "recon-internal-leak":       "Internal/corp subdomain",
    "recon-proxy-surface":       "Proxy/load-balancer subdomain",
    "recon-wildcard":            "Wildcard DNS detected",
    "recon-cloud-hosted":        "Cloud-hosted infrastructure",
    "recon-mass-enum":           "Large enumeration result (active program)",
}

# RFC1918 IPs — internal leak indicator
_RFC1918 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)"
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SourceResult:
    source: str
    domain: str
    subdomains: set[str] = field(default_factory=set)
    error: Optional[str] = None
    duration: float = 0.0
    raw_output: str = ""

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
    # Enrichment
    resolves: Optional[bool] = None
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    cloud_provider: str = ""
    wildcard: bool = False
    # Classification
    sensitive_category: str = ""
    severity: Severity = Severity.LOW
    chain_ids: list[str] = field(default_factory=list)

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(self.name.encode()).hexdigest()[:16]


@dataclass
class ReconChain:
    chain_id: str
    name: str
    severity: Severity
    members: list[str]
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name":     self.name,
            "severity": self.severity.value,
            "members":  self.members[:100],     # cap for JSON size
            "count":    len(self.members),
            "evidence": self.evidence[:600],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  NORMALIZATION
# ═════════════════════════════════════════════════════════════════════════════

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


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


# ═════════════════════════════════════════════════════════════════════════════
#  TOOL EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

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


def _http_get(url: str, timeout: int, label: str,
              accept: str = "*/*") -> Optional[str]:
    """Fetch a URL with retries. Returns text or None."""
    req = urllib.request.Request(url, headers={
        "User-Agent": ARGUS_UA, "Accept": accept,
    })
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt == 0:
                time.sleep(0.5 + random.random() * 0.5)
                continue
            log.debug(f"[{label}] http failed: {e}")
            return None
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCES
# ═════════════════════════════════════════════════════════════════════════════

def _run_subfinder(domain: str, rate_limit: Optional[int] = None) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("subfinder", domain)
    if not _tool_available("subfinder"):
        result.error = "subfinder not installed"
        result.duration = time.monotonic() - start
        return result

    cmd = ["subfinder", "-d", domain, "-all", "-recursive", "-silent", "-oJ", "-cs"]
    if rate_limit is not None and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])
    if SUBFINDER_PROXY:
        cmd.extend(["-proxy", SUBFINDER_PROXY])

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


def _run_crtsh(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("crt.sh", domain)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    text = _http_get(url, TIMEOUT_CRTSH, "crt.sh", accept="application/json")
    if text is None:
        result.error = "crt.sh: no response"
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


def _run_hackertarget(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("hackertarget", domain)

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = _http_get(url, TIMEOUT_HACKERTGT, "hackertarget")
    if text is None:
        result.error = "hackertarget: no response"
        result.duration = time.monotonic() - start
        return result

    # Format: "subdomain,ip" per line
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


def _run_alienvault(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("alienvault", domain)

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    text = _http_get(url, TIMEOUT_ALIENVAULT, "alienvault",
                     accept="application/json")
    if text is None:
        result.error = "alienvault: no response"
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


def _run_wayback(domain: str) -> SourceResult:
    start = time.monotonic()
    result = SourceResult("wayback", domain)

    url = (
        f"http://web.archive.org/cdx/search/cdx?"
        f"url=*.{domain}&output=text&fl=original"
        f"&collapse=urlkey&limit=10000"
    )
    text = _http_get(url, TIMEOUT_WAYBACK, "wayback")
    if text is None:
        result.error = "wayback: no response"
        result.duration = time.monotonic() - start
        return result

    import urllib.parse as up
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            host = up.urlparse(line).hostname or ""
        except Exception:
            continue
        sub = normalize_subdomain(host)
        if sub:
            result.subdomains.add(sub)

    result.raw_output = text[:50000]
    result.duration = time.monotonic() - start
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  ENRICHMENT — DNS RESOLUTION (with CNAME chains + wildcard detection)
# ═════════════════════════════════════════════════════════════════════════════

def _detect_wildcard_roots(roots: list[str], timeout: int = TIMEOUT_WILDCARD) -> set[str]:
    """
    Query a random-label subdomain per root. If it resolves, the root has
    wildcard DNS — downstream results for that root are noisy.
    """
    wildcards: set[str] = set()
    for root in roots:
        test = f"{WILDCARD_TEST_LABEL}-{_random_label()}.{root}"
        try:
            socket.gethostbyname(test)
            wildcards.add(root)
            log.info(f"    wildcard  : {root}  (random subdomain resolves)")
        except socket.gaierror:
            pass
        except Exception:
            pass
    return wildcards


def _resolve_with_dnsx(subdomains: list[str], rate_limit: Optional[int] = None) -> dict[str, dict]:
    """
    Resolve via dnsx -json. Returns {subdomain: {a, aaaa, cname}}.
    Falls back to threaded socket resolution if dnsx is unavailable.
    """
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
            log.warning(f"    dnsx failed: {e} — falling back to socket")

    # Threaded socket fallback
    log.info("    dnsx unavailable — using threaded socket resolution")
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

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(_one, s): s for s in subdomains}
        for fut in as_completed(futures):
            try:
                sub, rec = fut.result()
                records[sub] = rec
            except Exception:
                pass
    return records


# ═════════════════════════════════════════════════════════════════════════════
#  ENRICHMENT — CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _classify_sensitive(name: str, root: str) -> tuple[str, Severity]:
    """Return (category, severity) for a subdomain."""
    if name == root:
        return ("apex", Severity.INFO)

    # The left part before the root: "admin.staging" in "admin.staging.root"
    prefix = name[: -(len(root) + 1)] if name.endswith("." + root) else name
    prefix_lower = prefix.lower()

    for category, (patterns, severity) in SENSITIVE_CATEGORIES.items():
        for pattern in patterns:
            # Whole-token match: preceded/followed by dot or dash or boundary
            if re.search(rf"(?:^|[.-]){re.escape(pattern)}(?:$|[.-])", prefix_lower):
                return (category, severity)
            # Prefix match: "api-prod", "db1", "admin2"
            if prefix_lower == pattern:
                return (category, severity)
            if prefix_lower.startswith(pattern + "-") or prefix_lower.startswith(pattern + "."):
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


# ═════════════════════════════════════════════════════════════════════════════
#  AGGREGATION + ENRICHMENT
# ═════════════════════════════════════════════════════════════════════════════

def _aggregate(
    results: list[SourceResult],
    roots: list[str],
    wildcard_roots: set[str],
    dns_records: dict[str, dict],
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

    # Enrich each record
    for name, rec in merged.items():
        dns = dns_records.get(name) or {}
        rec.a_records = dns.get("a") or []
        rec.aaaa_records = dns.get("aaaa") or []
        rec.cname_chain = dns.get("cname") or []
        rec.resolves = bool(rec.a_records or rec.aaaa_records or rec.cname_chain) \
            if dns_records else None
        rec.cloud_provider = _detect_cloud_provider(rec.cname_chain)
        rec.wildcard = rec.root in wildcard_roots

        # Classify
        category, severity = _classify_sensitive(name, rec.root)
        rec.sensitive_category = category
        rec.severity = severity

        # Chain IDs
        cid = CHAIN_FOR_CATEGORY.get(category)
        if cid:
            rec.chain_ids.append(cid)

    # Global chains (wildcard, cloud, mass)
    for root in wildcard_roots:
        # Just record once — the chain is root-scoped, not per-subdomain
        pass

    return merged


# ═════════════════════════════════════════════════════════════════════════════
#  RECORDS + PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

def _to_records(
    merged: dict[str, SubdomainRecord],
) -> list[dict]:
    """
    Convert merged records into JSON records. Backward compatible:
    the first 6 fields are exactly what main.py's _sync_recon_stage
    expects for DB.upsert_subdomains().
    """
    records: list[dict] = []
    for name in sorted(merged):
        rec = merged[name]
        records.append({
            # ── Backward-compatible core (6 fields) ─────────────────────
            "subdomain":      rec.name,
            "root":           rec.root,
            "sources":        sorted(rec.sources),
            "source_count":   len(rec.sources),
            "resolves":       rec.resolves,
            "first_seen":     rec.first_seen.replace("T", " ").split(".")[0],
            # ── v4.0 additions ──────────────────────────────────────────
            "is_apex":            rec.is_apex,
            "sensitive_category": rec.sensitive_category,
            "severity":           rec.severity.value,
            "wildcard":           rec.wildcard,
            "cloud_provider":     rec.cloud_provider,
            "a_records":          rec.a_records,
            "aaaa_records":       rec.aaaa_records,
            "cname_chain":        rec.cname_chain,
            "chain_ids":          rec.chain_ids,
        })
    return records


def _build_findings(records: list[dict]) -> list[dict]:
    """Extract HIGH+/CRITICAL records as findings."""
    findings = []
    for r in records:
        sev = r.get("severity", "LOW")
        if sev in ("HIGH", "CRITICAL"):
            findings.append(r)
    return findings


def _build_chains(
    records: list[dict],
    wildcard_roots: set[str],
    roots: list[str],
) -> list[dict]:
    """Aggregate chain IDs from records into structured chain records."""
    chains: dict[str, list[dict]] = {}
    for r in records:
        for cid in (r.get("chain_ids") or []):
            chains.setdefault(cid, []).append(r)

    # Wildcard chains (root-scoped, not per-subdomain)
    for root in wildcard_roots:
        chains.setdefault("recon-wildcard", []).append({
            "subdomain": root, "root": root,
            "severity": "MEDIUM", "wildcard": True,
        })

    # Cloud provider chains
    provider_groups: dict[str, list[str]] = {}
    for r in records:
        cp = r.get("cloud_provider")
        if cp:
            provider_groups.setdefault(cp, []).append(r.get("subdomain", ""))
    for provider, subs in provider_groups.items():
        chains.setdefault("recon-cloud-hosted", []).extend(
            [{"subdomain": s, "cloud_provider": provider} for s in subs]
        )

    # Mass enumeration chain
    if len(records) >= MAX_SUBDOMAINS_AGGRESSIVE:
        chains.setdefault("recon-mass-enum", []).append({
            "count": len(records),
            "threshold": MAX_SUBDOMAINS_AGGRESSIVE,
        })

    # Convert to ReconChain objects
    out: list[ReconChain] = []
    SEV_BY_CHAIN = {
        "recon-database-exposed":    Severity.CRITICAL,
        "recon-cicd-exposed":        Severity.CRITICAL,
        "recon-admin-surface":       Severity.HIGH,
        "recon-staging-environment": Severity.HIGH,
        "recon-vpn-surface":         Severity.HIGH,
        "recon-backup-exposure":     Severity.HIGH,
        "recon-monitoring-exposed":  Severity.HIGH,
        "recon-internal-leak":       Severity.HIGH,
        "recon-api-discovery":       Severity.MEDIUM,
        "recon-storage-exposure":    Severity.MEDIUM,
        "recon-proxy-surface":       Severity.MEDIUM,
        "recon-wildcard":            Severity.MEDIUM,
        "recon-cloud-hosted":        Severity.MEDIUM,
        "recon-mass-enum":           Severity.MEDIUM,
    }
    for cid, members in chains.items():
        members_subs = [m.get("subdomain") or str(m.get("count", "")) for m in members]
        out.append(ReconChain(
            chain_id=cid,
            name=CHAIN_NAMES.get(cid, cid),
            severity=SEV_BY_CHAIN.get(cid, Severity.LOW),
            members=members_subs,
            evidence=f"{len(members)} member(s): "
                     f"{', '.join(members_subs[:5])}"
                     + (f" … (+{len(members_subs) - 5})" if len(members_subs) > 5 else ""),
        ))
    out.sort(key=lambda c: (-c.severity.rank, c.chain_id))
    return [c.to_dict() for c in out]


# ═════════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRESERVATION
# ═════════════════════════════════════════════════════════════════════════════

def _save_evidence(source_results: list[SourceResult], evidence_dir: Path) -> None:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for sr in source_results:
            if not sr.raw_output:
                continue
            safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", f"{sr.source}_{sr.domain}")[:80]
            (evidence_dir / f"{safe}.txt").write_text(sr.raw_output[:200000])
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  JSON REPORT
# ═════════════════════════════════════════════════════════════════════════════

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
) -> dict:
    by_source: dict[str, dict] = {}
    for sr in source_results:
        by_source[sr.source] = {
            "domain":           sr.domain,
            "ok":               sr.ok,
            "count":            sr.count,
            "duration_seconds": round(sr.duration, 2),
            "error":            sr.error,
        }

    by_category: dict[str, int] = {}
    by_cloud: dict[str, int] = {}
    for r in records:
        cat = r.get("sensitive_category") or ""
        if cat and cat != "apex":
            by_category[cat] = by_category.get(cat, 0) + 1
        cp = r.get("cloud_provider") or ""
        if cp:
            by_cloud[cp] = by_cloud.get(cp, 0) + 1

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in records:
        sev = r.get("severity", "LOW")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    return {
        "schema_version":    4,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":   round(elapsed, 2),
        "wildcards":         roots,
        "config": {
            "rate_limit":     applied_rate,
            "concurrency":    applied_concurrency,
            "aggressive":     aggressive,
            "strict":         strict,
            "crtsh_fallback": ENABLE_CRTSH_FALLBACK,
            "dnsx_validation": bool(resolved),
            "sources":        ["subfinder", "assetfinder", "amass",
                               "findomain", "crt.sh", "hackertarget",
                               "alienvault"] + (["wayback"] if aggressive else []),
            "note":           "rate_limit applies to third-party APIs, not "
                              "the target; platform headers are NOT used in "
                              "this stage",
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
        },
        "sources":    by_source,
        "subdomains": records,      # ← main.py's DB sync reads this
        "findings":   findings,
        "chains":     chains,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC (standalone only)
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, records: list[dict]) -> None:
    if not records:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not available — skipping")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB is False — skipping")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED is False — skipping")
        return
    if not DB.available:
        log.warning("  DB sync: bridge client not ready (check BRIDGE_KEY)")
        return
    try:
        result = DB.upsert_subdomains(scan_id, records)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} subdomain(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def enumerate_subdomains(
    wildcard_file: Path,
    outdir: Path,
    resolve: bool = True,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
    aggressive: bool = False,
    strict: bool = False,
) -> Path:
    """
    Enumerate subdomains for every root domain in `wildcard_file`.

    Args:
        wildcard_file: one root domain per line
        outdir:        output directory
        resolve:       enrich with DNS resolution + CNAME chains
        rate_limit:    override MODULE_RATE_LIMITS["subs"]["rate_limit"]
        concurrency:   override MODULE_RATE_LIMITS["subs"]["concurrency"]
        scan_id:       self-sync to DB (standalone use only — main.py handles
                       this in the pipeline)
        aggressive:    enable extra sources (wayback) + extended amass timeout
        strict:        only include subdomains that resolve

    Returns: path to all_subs.txt
    """
    start = time.monotonic()

    cfg_rate, cfg_concurrency = _subs_settings()
    eff_rate = rate_limit if rate_limit is not None else cfg_rate
    eff_concurrency = concurrency if concurrency is not None else cfg_concurrency

    # ── Load targets ────────────────────────────────────────────────────────
    if not wildcard_file.exists():
        raise FileNotFoundError(f"wildcard file not found: {wildcard_file}")
    roots = [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not roots:
        raise ValueError(f"wildcard file is empty: {wildcard_file}")

    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "subs_evidence"

    log.info(f"  Targets : {len(roots)} wildcard(s)")
    for r in roots:
        log.info(f"            · {r}")
    log.info("")

    source_label = f"{eff_rate}/s" if eff_rate else "unlimited"
    log.info(f"  Config  : rate_limit={source_label}  concurrency={eff_concurrency}")
    log.info(f"            source: MODULE_RATE_LIMITS['subs']")
    log.info(f"  Mode    : {'AGGRESSIVE' if aggressive else 'fast'}"
             f"{'  strict=ON' if strict else ''}")

    if eff_rate is not None and eff_rate < 5:
        log.info(f"  {chr(9888)}  rate_limit={eff_rate}/s is very slow for passive APIs.")
        log.info(f"     Consider raising MODULE_RATE_LIMITS['subs']['rate_limit']")

    headers = _cfg("ACTIVE_HEADERS", {}) or {}
    if headers:
        log.info(f"  Headers : {len(headers)} configured")
        log.info(f"            NOT applied here — subs makes no target traffic.")
    log.info("")

    # ── Build source tasks ──────────────────────────────────────────────────
    # Default sources (fast)
    tasks: list[tuple[str, str]] = []
    for domain in roots:
        tasks.append(("subfinder",   domain))
        tasks.append(("assetfinder", domain))
        tasks.append(("amass",       domain))
        tasks.append(("findomain",   domain))
        tasks.append(("hackertarget", domain))
        tasks.append(("alienvault",  domain))

    # Aggressive-only sources
    if aggressive:
        for domain in roots:
            tasks.append(("wayback", domain))

    def _dispatch(source: str, domain: str) -> SourceResult:
        if source == "subfinder":   return _run_subfinder(domain, rate_limit=eff_rate)
        if source == "assetfinder": return _run_assetfinder(domain)
        if source == "amass":       return _run_amass(domain,
                                                      timeout=TIMEOUT_AMASS * (2 if aggressive else 1))
        if source == "findomain":   return _run_findomain(domain)
        if source == "hackertarget":return _run_hackertarget(domain)
        if source == "alienvault":  return _run_alienvault(domain)
        if source == "wayback":     return _run_wayback(domain)
        if source == "crt.sh":      return _run_crtsh(domain)
        raise ValueError(f"unknown source: {source}")

    max_workers = max(1, min(eff_concurrency * len(roots) * 2, len(tasks)))
    log.info(f"  Running {len(tasks)} source task(s) with {max_workers} worker(s)...")
    log.info("")

    source_results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_dispatch, s, d): (s, d) for s, d in tasks}
        for fut in as_completed(future_map):
            source_name, domain = future_map[fut]
            try:
                sr = fut.result()
            except Exception as e:
                sr = SourceResult(source_name, domain, error=str(e))
            source_results.append(sr)
            if sr.ok:
                log.info(f"    {source_name:<12} {domain:<24} "
                         f"✓ {sr.count:>4} subdomains  ({sr.duration:.1f}s)")
            else:
                log.info(f"    {source_name:<12} {domain:<24} "
                         f"✗ {sr.error or 'failed'}  ({sr.duration:.1f}s)")

    # ── Aggregate ───────────────────────────────────────────────────────────
    pre_records = _aggregate(source_results, roots, set(), {})
    unique_subs = sorted(pre_records.keys())
    log.info("")
    log.info(f"  Aggregate : {len(unique_subs)} unique subdomain(s) before enrichment")

    # ── crt.sh fallback if empty ────────────────────────────────────────────
    if ENABLE_CRTSH_FALLBACK and not unique_subs:
        log.info("")
        log.info("  No results — falling back to crt.sh...")
        for domain in roots:
            sr = _run_crtsh(domain)
            source_results.append(sr)
            log.info(f"    crt.sh       {domain:<24} "
                     f"{'✓' if sr.ok else '✗'} {sr.count:>4}  ({sr.duration:.1f}s)")
        pre_records = _aggregate(source_results, roots, set(), {})
        unique_subs = sorted(pre_records.keys())
        log.info(f"  crt.sh aggregate: {len(unique_subs)} unique subdomain(s)")

    # ── Wildcard detection ─────────────────────────────────────────────────
    wildcard_roots: set[str] = set()
    if unique_subs and resolve:
        log.info("")
        log.info("  Wildcard detection...")
        wildcard_roots = _detect_wildcard_roots(roots)

    # ── DNS enrichment (CNAME chains, A/AAAA records) ──────────────────────
    dns_records: dict[str, dict] = {}
    resolved: set[str] = set()
    if resolve and unique_subs:
        log.info("")
        log.info("  Resolving via dnsx (structured)...")
        dns_records = _resolve_with_dnsx(unique_subs, rate_limit=eff_rate)
        resolved = {
            name for name, rec in dns_records.items()
            if rec.get("a") or rec.get("aaaa") or rec.get("cname")
        }
        log.info(f"  Resolved  : {len(resolved)} / {len(unique_subs)} "
                 f"({(len(resolved) / len(unique_subs) * 100):.0f}%)")

        # Cloud provider breakdown
        cp_counter: dict[str, int] = {}
        for name in resolved:
            cname = (dns_records.get(name) or {}).get("cname") or []
            cp = _detect_cloud_provider(cname)
            if cp:
                cp_counter[cp] = cp_counter.get(cp, 0) + 1
        if cp_counter:
            log.info("  Cloud     : " + " · ".join(
                f"{k}({v})" for k, v in sorted(cp_counter.items(), key=lambda kv: -kv[1])
            ))

    # ── Full aggregation with enrichment ───────────────────────────────────
    merged = _aggregate(source_results, roots, wildcard_roots, dns_records)
    unique_subs = sorted(merged.keys())

    # ── Strict mode filter ──────────────────────────────────────────────────
    if strict and resolved:
        merged = {k: v for k, v in merged.items() if k in resolved}
        unique_subs = sorted(merged.keys())
        log.info(f"  Strict    : filtered to {len(merged)} resolving subdomain(s)")

    # ── Build records + findings + chains ──────────────────────────────────
    records = _to_records(merged)
    findings = _build_findings(records)
    chains = _build_chains(records, wildcard_roots, roots)

    # ── Save evidence ──────────────────────────────────────────────────────
    _save_evidence(source_results, evidence_dir)

    # ── Write outputs ───────────────────────────────────────────────────────
    txt_path = outdir / "all_subs.txt"
    txt_path.write_text("\n".join(unique_subs) + ("\n" if unique_subs else ""))

    if resolved:
        (outdir / "subs_resolved.txt").write_text("\n".join(sorted(resolved)) + "\n")

    sensitive_subs = sorted(r["subdomain"] for r in findings)
    (outdir / "subs_sensitive.txt").write_text(
        "\n".join(sensitive_subs) + ("\n" if sensitive_subs else "")
    )

    elapsed = time.monotonic() - start
    report = _build_json_report(
        roots, records, findings, chains, source_results, resolved,
        wildcard_roots, elapsed,
        applied_rate=eff_rate, applied_concurrency=eff_concurrency,
        aggressive=aggressive, strict=strict,
    )
    json_path = outdir / "subdomains.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Confirmed-only report (HIGH+) ───────────────────────────────────────
    confirmed_path = outdir / "subdomains_confirmed.json"
    confirmed_path.write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "input_file":     str(wildcard_file),
        "totals": {
            "confirmed": len(findings),
            "critical":  sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":      sum(1 for f in findings if f.get("severity") == "HIGH"),
            "by_category": report["totals"]["by_category"],
        },
        "findings": findings,
    }, indent=2, ensure_ascii=False) + "\n")

    # ── Chains report ──────────────────────────────────────────────────────
    chains_path = outdir / "subdomains_chains.json"
    chains_path.write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "chains": chains,
    }, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync (standalone only) ─────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, records)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    all_subs.txt                 {len(unique_subs):>5} subdomain(s)")
    log.info(f"    subdomains.json              {len(records):>5} record(s)")
    log.info(f"    subdomains_confirmed.json    {len(findings):>5} HIGH+ finding(s)")
    log.info(f"    subdomains_chains.json       {len(chains):>5} chain(s)")
    if resolved:
        log.info(f"    subs_resolved.txt            {len(resolved):>5} resolving")
    log.info(f"    subs_sensitive.txt           {len(sensitive_subs):>5} classified")
    log.info(f"    subs_evidence/               {len([sr for sr in source_results if sr.raw_output]):>5} raw output(s)")

    if report["totals"]["by_severity"]["CRITICAL"] or report["totals"]["by_severity"]["HIGH"]:
        log.info("")
        log.info(f"  Severity : CRITICAL={report['totals']['by_severity']['CRITICAL']}  "
                 f"HIGH={report['totals']['by_severity']['HIGH']}  "
                 f"MEDIUM={report['totals']['by_severity']['MEDIUM']}  "
                 f"LOW={report['totals']['by_severity']['LOW']}")

    if report["totals"]["by_category"]:
        log.info("  Category : " + " · ".join(
            f"{k}({v})" for k, v in list(report["totals"]["by_category"].items())[:8]
        ))

    if chains:
        log.info("")
        log.info("  Chains   : " + " · ".join(
            f"{c['chain_id']}({c['severity']})" for c in chains[:6]
        ))

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return txt_path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Argus subs v4.0 (standalone)")
    parser.add_argument("--wildcard", type=Path, default=base / "wildcard.txt")
    parser.add_argument("--output",   type=Path, default=base / "output")
    parser.add_argument("--scan-id",  type=int, default=None)
    parser.add_argument("--rate-limit",  type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--no-resolve",  action="store_true")
    parser.add_argument("--aggressive",  action="store_true")
    parser.add_argument("--strict",      action="store_true")
    args = parser.parse_args()
    try:
        enumerate_subdomains(
            args.wildcard, args.output,
            resolve=not args.no_resolve,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            scan_id=args.scan_id,
            aggressive=args.aggressive,
            strict=args.strict,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
