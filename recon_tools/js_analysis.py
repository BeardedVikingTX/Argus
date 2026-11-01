#!/usr/bin/env python3
"""
recon_tools/js_analysis.py — JavaScript Endpoint & Secret Mining
═══════════════════════════════════════════════════════════════════════════════

JavaScript analysis stage for Argus. Modern SPAs embed the entire API surface
in their bundles — endpoints the UI never links to, WebSocket routes, GraphQL
queries, and sometimes hardcoded credentials.

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every HTTP request. Rate limits protect both the target and the JS bundle
CDN that serves them.

Config integration (config.py):
  • MODULE_RATE_LIMITS["js"]       → katana -rl / -c and download rate
  • ACTIVE_HEADERS + AUTH_HEADERS  → merged, applied to katana and downloads
  • AUTH_COOKIES                   → applied to requests session
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Three analysis passes:
  1. Endpoint extraction — REST/GraphQL/WSS/socket.io/route/fetch patterns
  2. Secret detection    — 40+ provider patterns with entropy + context scoring
  3. Source-map discovery — //# sourceMappingURL directives

Outputs (into `outdir`):
  • js_findings.json   — full structured report
  • js_endpoints.txt   — endpoint value, one per line
  • js_secrets.txt     — redacted secrets with file:line
  • js_sourcemaps.txt  — discovered .map URLs
  • js_files.txt       — every analyzed JS URL

Remote DB (if scan_id is provided):
  • js_findings table  — one row per (scan_id, kind, subtype, hash)

Integration:
  main.py → run_one("js") → run_js_analysis(live_urls_file, outdir)
  main.py also syncs js_findings.json via _sync_stage_artifacts()
  Standalone: run_js_analysis(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import shutil
import subprocess
import sys
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

log = logging.getLogger("argus.js_analysis")

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


def _js_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("js", {})
    threads = entry.get("concurrency", 10)
    rate = entry.get("rate_limit", 5)
    if not isinstance(threads, int) or threads < 1:
        threads = 10
    if not isinstance(rate, int) or rate < 0:
        rate = 5
    return {"threads": threads, "rate_limit": rate}


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _tool_header_args() -> list[str]:
    """Return ['Name: Value', ...] for katana's -H flag."""
    return [f"{k}: {v}" for k, v in _target_headers().items()]


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DOWNLOAD_THREADS      = 10
DOWNLOAD_RATE_LIMIT   = 5
DOWNLOAD_TIMEOUT      = 20
DOWNLOAD_RETRIES      = 2
MAX_JS_SIZE_BYTES     = 10_000_000
MAX_FILES             = 2000
KATANA_TIMEOUT        = 600
KATANA_DEPTH          = 3

MAX_SOURCEMAP_PROBES  = 50

CONFIDENCE_HIGH       = 75
CONFIDENCE_MEDIUM     = 50
CONFIDENCE_LOW        = 25
MIN_REPORT_CONFIDENCE = CONFIDENCE_LOW


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class JSFile:
    url: str
    content: str = ""
    size: int = 0
    sha256: str = ""
    error: str = ""
    source: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.content)

    def to_dict(self) -> dict:
        return {
            "url":    self.url,
            "size":   self.size,
            "sha256": self.sha256,
            "error":  self.error,
            "source": self.source,
        }


@dataclass
class Finding:
    kind: str
    subtype: str
    value: str
    redacted: str
    file_url: str
    line_number: int
    context: str
    confidence: int
    severity: str
    reasons: list[str] = field(default_factory=list)
    auth_enabled: bool = False
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "kind":         self.kind,
            "subtype":      self.subtype,
            "value":        self.value,
            "redacted":     self.redacted,
            "file_url":     self.file_url,
            "line_number":  self.line_number,
            "context":      self.context,
            "confidence":   self.confidence,
            "severity":     self.severity,
            "reasons":      self.reasons,
            "auth_enabled": self.auth_enabled,
            "first_seen":   self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  PATTERN LIBRARIES (unchanged from previous version)
# ═════════════════════════════════════════════════════════════════════════════

ENDPOINT_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("rest_api", "REST API path",
     re.compile(r"""["'`](/(?:api|rest|v\d+|internal|admin|debug|private|backend)/[^"'`\s]{1,200})["'`]""", re.I)),
    ("absolute_url", "Absolute URL",
     re.compile(r"""["'`](https?://[^"'`\s]{5,200})["'`]""", re.I)),
    ("graphql", "GraphQL endpoint",
     re.compile(r"""["'`]([^"'`\s]*graphql[^"'`\s]*)["'`]""", re.I)),
    ("websocket_url", "WebSocket URL",
     re.compile(r"""["'`](wss?://[^"'`\s]{5,200})["'`]""", re.I)),
    ("websocket_ctor", "WebSocket constructor",
     re.compile(r"""new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)),
    ("socketio", "socket.io endpoint",
     re.compile(r"""["'`]([^"'`\s]*socket\.io[^"'`\s]*)["'`]""", re.I)),
    ("route_definition", "Route definition",
     re.compile(r"""(?:path|route)\s*:\s*["'`]([^"'`]{3,100})["'`]""", re.I)),
    ("fetch_url", "fetch/XHR URL",
     re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`\s]{3,200})["'`]""", re.I)),
]

SECRET_PATTERNS: list[tuple[str, str, re.Pattern, int]] = [
    ("aws_access_key", "AWS Access Key ID", re.compile(r"""AKIA[0-9A-Z]{16}"""), 95),
    ("aws_secret_key", "AWS Secret Access Key", re.compile(r"""(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?"""), 90),
    ("aws_session_token", "AWS Session Token", re.compile(r"""(?i)aws_session_token\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?"""), 85),
    ("google_api_key", "Google API Key", re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), 95),
    ("google_oauth_client", "Google OAuth Client ID", re.compile(r"""([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)"""), 80),
    ("gcp_service_account", "GCP Service Account Key", re.compile(r"""["']type["']\s*:\s*["']service_account["']"""), 90),
    ("gcp_private_key", "GCP Private Key", re.compile(r"""["']private_key["']\s*:\s*["'](-----BEGIN [A-Z ]+PRIVATE KEY-----)"""), 95),
    ("azure_storage_key", "Azure Storage Account Key", re.compile(r"""(?i)(?:AccountKey|account_key)\s*[=:]\s*["']?([A-Za-z0-9+/=]{86,})["']?"""), 90),
    ("stripe_secret", "Stripe Secret Key", re.compile(r"""sk_live_[A-Za-z0-9]{24,}"""), 95),
    ("stripe_publishable", "Stripe Publishable Key", re.compile(r"""pk_live_[A-Za-z0-9]{24,}"""), 70),
    ("square_access_token", "Square Access Token", re.compile(r"""sq0atp-[0-9A-Za-z\-_]{22}"""), 90),
    ("github_token", "GitHub Personal Access Token", re.compile(r"""gh[ps]_[A-Za-z0-9_]{36,}"""), 95),
    ("github_finegrained", "GitHub Fine-grained Token", re.compile(r"""github_pat_[A-Za-z0-9_]{22,}"""), 95),
    ("gitlab_token", "GitLab Personal Access Token", re.compile(r"""glpat-[A-Za-z0-9\-]{20,}"""), 95),
    ("bitbucket_token", "Bitbucket App Password", re.compile(r"""(?i)(?:bitbucket|bb)[_-]?(?:token|secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{30,})["']?"""), 75),
    ("slack_token", "Slack Token", re.compile(r"""xox[baprs]-[A-Za-z0-9\-]{10,}"""), 95),
    ("slack_webhook", "Slack Webhook URL", re.compile(r"""https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"""), 90),
    ("discord_bot_token", "Discord Bot Token", re.compile(r"""[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"""), 90),
    ("twilio_sid", "Twilio Account SID", re.compile(r"""AC[0-9a-fA-F]{32}"""), 80),
    ("twilio_auth_token", "Twilio Auth Token", re.compile(r"""(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*["']?([0-9a-fA-F]{32})["']?"""), 85),
    ("sendgrid_key", "SendGrid API Key", re.compile(r"""SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"""), 95),
    ("mailgun_key", "Mailgun API Key", re.compile(r"""key-[0-9a-zA-Z]{32}"""), 85),
    ("telegram_bot", "Telegram Bot Token", re.compile(r"""[0-9]{8,10}:[A-Za-z0-9_-]{35}"""), 85),
    ("npm_token", "npm Access Token", re.compile(r"""npm_[A-Za-z0-9]{36}"""), 90),
    ("pypi_token", "PyPI API Token", re.compile(r"""pypi-[A-Za-z0-9\-_]{50,}"""), 90),
    ("jwt", "JSON Web Token", re.compile(r"""eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"""), 85),
    ("bearer_token", "Bearer Token", re.compile(r"""(?i)bearer\s+([A-Za-z0-9\-_\.=]{20,})"""), 70),
    ("private_key", "Private Key Block", re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""), 95),
    ("pgp_private_key", "PGP Private Key Block", re.compile(r"""-----BEGIN PGP PRIVATE KEY BLOCK-----"""), 95),
    ("db_connection", "Database Connection String", re.compile(r"""(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql|sqlserver)://[^:]+:[^@\s]+@"""), 90),
    ("database_url", "DATABASE_URL with credentials", re.compile(r"""(?i)DATABASE_URL\s*=\s*["']?\S+://\S+:\S+@\S+"""), 85),
    ("generic_api_key", "Generic API Key Assignment", re.compile(r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']"""), 60),
]


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT
# ═════════════════════════════════════════════════════════════════════════════

def _extract_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    urls: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname:
            base = f"{parsed.scheme}://{parsed.netloc}"
            urls.add(base.rstrip("/"))
    return sorted(urls)


# ═════════════════════════════════════════════════════════════════════════════
#  JS DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def _discover_js_katana(
    base_urls: list[str],
    workdir: Path,
    rate_limit: int,
    concurrency: int,
) -> list[JSFile]:
    if not shutil.which("katana"):
        log.warning("    katana not installed — skipping crawl discovery")
        return []

    js_files: list[JSFile] = []
    seen: set[str] = set()
    headers = _tool_header_args()

    for base in base_urls:
        log.info(f"      katana  {base}")
        cmd = [
            "katana",
            "-u", base,
            "-jc",
            "-d", str(KATANA_DEPTH),
            "-kf", "all",
            "-silent",
            "-timeout", "10",
            "-c", str(concurrency),
        ]
        if rate_limit and rate_limit > 0:
            cmd.extend(["-rl", str(rate_limit)])
        for hdr in headers:
            cmd.extend(["-H", hdr])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=KATANA_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.warning(f"      katana timeout on {base}")
            continue
        except FileNotFoundError:
            return []

        for line in result.stdout.splitlines():
            url = line.strip()
            if not url:
                continue
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            if not path.endswith(".js") and ".js" not in path:
                continue
            if url in seen:
                continue
            seen.add(url)
            js_files.append(JSFile(url=url, source="katana"))

    log.info(f"      katana found {len(js_files)} JS URL(s)")
    return js_files


def _discover_js_subjs(base_urls: list[str]) -> list[JSFile]:
    """
    subjs does not support custom headers, so when auth is enabled it will
    only find public JS. That's still useful — we run it anyway.
    """
    if not shutil.which("subjs"):
        return []

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    if auth_on:
        log.info("      subjs    (no header support — public JS only)")

    input_data = "\n".join(base_urls)
    try:
        result = subprocess.run(
            ["subjs"],
            input=input_data, capture_output=True, text=True, timeout=300,
        )
    except Exception:
        return []

    js_files: list[JSFile] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        js_files.append(JSFile(url=url, source="subjs"))
    return js_files


def _discover_js_from_input(input_file: Path) -> list[JSFile]:
    files: list[JSFile] = []
    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        url = line.strip().split()[0] if line.strip() else ""
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.path.lower().endswith(".js") and url not in seen:
            seen.add(url)
            files.append(JSFile(url=url, source="input"))
    return files


def discover_js_files(
    base_urls: list[str],
    input_file: Path,
    workdir: Path,
    rate_limit: int,
    concurrency: int,
) -> list[JSFile]:
    log.info("  Discovering JS files...")
    all_files: list[JSFile] = []
    seen: set[str] = set()

    for f in _discover_js_from_input(input_file):
        if f.url not in seen:
            seen.add(f.url)
            all_files.append(f)

    for f in _discover_js_katana(base_urls, workdir, rate_limit, concurrency):
        if f.url not in seen:
            seen.add(f.url)
            all_files.append(f)

    for f in _discover_js_subjs(base_urls):
        if f.url not in seen:
            seen.add(f.url)
            all_files.append(f)

    if not all_files:
        log.warning("    No JS files discovered")
    else:
        log.info(f"    Total: {len(all_files)} unique JS file(s)")

    return all_files


# ═════════════════════════════════════════════════════════════════════════════
#  JS DOWNLOAD
# ═════════════════════════════════════════════════════════════════════════════

def _make_session() -> requests.Session:
    s = requests.Session()
    hdrs = _target_headers()
    if hdrs:
        s.headers.update(hdrs)
    cookies = _auth_cookies()
    if cookies:
        for name, value in cookies.items():
            s.cookies.set(name, value)
    s.verify = False
    return s


def _download_one(session: requests.Session, js_file: JSFile) -> JSFile:
    if not js_file.url:
        js_file.error = "empty url"
        return js_file

    for attempt in range(DOWNLOAD_RETRIES + 1):
        try:
            resp = session.get(
                js_file.url,
                timeout=DOWNLOAD_TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
            if resp.status_code >= 400:
                js_file.error = f"HTTP {resp.status_code}"
                return js_file

            content = b""
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_JS_SIZE_BYTES:
                    js_file.error = f"exceeds {MAX_JS_SIZE_BYTES} bytes"
                    return js_file

            js_file.content = content.decode("utf-8", errors="replace")
            js_file.size = len(content)
            js_file.sha256 = hashlib.sha256(content).hexdigest()
            return js_file

        except requests.RequestException as e:
            if attempt < DOWNLOAD_RETRIES:
                time.sleep(0.5 * (attempt + 1))
                continue
            js_file.error = str(e)[:120]
            return js_file

    return js_file


def download_js_files(
    js_files: list[JSFile],
    threads: int,
    rate_limit: int,
) -> list[JSFile]:
    if not js_files:
        return []

    log.info(f"  Downloading {len(js_files)} JS file(s)...")
    session = _make_session()

    results: list[JSFile] = []
    rate_sleep = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {pool.submit(_download_one, session, f): f for f in js_files}
        for fut in as_completed(future_map):
            f = future_map[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                f.error = str(e)[:120]
                results.append(f)
            if rate_sleep > 0:
                time.sleep(rate_sleep)

    session.close()
    ok = sum(1 for f in results if f.ok)
    log.info(f"    Downloaded: {ok} / {len(results)} successful")
    return results


# ═════════════════════════════════════════════════════════════════════════════
#  ENTROPY & REDACTION
# ═════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    keep = 4
    return v[:keep] + "*" * (len(v) - keep * 2) + v[-keep:]


def _snippet(content: str, start: int, end: int, context_chars: int = 60) -> str:
    left = max(0, start - context_chars)
    right = min(len(content), end + context_chars)
    snippet = content[left:right].replace("\n", " ").strip()
    return snippet[:200]


# ═════════════════════════════════════════════════════════════════════════════
#  ANALYSIS PASSES
# ═════════════════════════════════════════════════════════════════════════════

INTERESTING_PATH_WORDS = {
    "admin", "internal", "debug", "private", "backend", "staging",
    "dev", "test", "api", "graphql", "v1", "v2", "v3", "rest",
}


def _line_for_pos(line_offsets: list[int], pos: int) -> int:
    lo, hi = 0, len(line_offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_offsets[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _analyze_endpoints(js_file: JSFile, auth_on: bool) -> list[Finding]:
    findings: list[Finding] = []
    content = js_file.content

    line_offsets: list[int] = []
    offset = 0
    for line in content.splitlines():
        line_offsets.append(offset)
        offset += len(line) + 1

    now = datetime.now(timezone.utc).isoformat()
    seen_values: set[str] = set()

    for subtype, label, pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            if not value or value in seen_values:
                continue
            seen_values.add(value)

            confidence = 40
            reasons = [f"pattern:{subtype}"]

            value_lower = value.lower()
            if any(w in value_lower for w in INTERESTING_PATH_WORDS):
                confidence += 30
                reasons.append("sensitive_path")

            if subtype == "absolute_url":
                parsed = urllib.parse.urlparse(value)
                target_host = urllib.parse.urlparse(js_file.url).hostname or ""
                if parsed.hostname and parsed.hostname != target_host:
                    confidence += 20
                    reasons.append("external_host")
                else:
                    confidence -= 10

            if subtype in ("graphql", "websocket_url", "websocket_ctor", "socketio"):
                confidence += 20
                reasons.append("api_surface")

            if confidence < MIN_REPORT_CONFIDENCE:
                continue

            findings.append(Finding(
                kind="endpoint",
                subtype=subtype,
                value=value,
                redacted=value,
                file_url=js_file.url,
                line_number=_line_for_pos(line_offsets, match.start()),
                context=_snippet(content, match.start(), match.end()),
                confidence=min(confidence, 100),
                severity=_severity_for_confidence(confidence, "endpoint"),
                reasons=reasons,
                auth_enabled=auth_on,
                first_seen=now,
            ))

    return findings


FALSE_POSITIVE_VALUES = {
    "your_api_key", "your-api-key", "replace_me", "changeme",
    "xxx", "todo", "fixme", "example", "test", "dummy",
    "api_key_here", "insert_key_here", "placeholder",
}


def _analyze_secrets(js_file: JSFile, auth_on: bool) -> list[Finding]:
    findings: list[Finding] = []
    content = js_file.content

    line_offsets: list[int] = []
    offset = 0
    for line in content.splitlines():
        line_offsets.append(offset)
        offset += len(line) + 1

    now = datetime.now(timezone.utc).isoformat()
    seen_values: set[str] = set()

    for subtype, label, pattern, base_confidence in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            value = value.strip()
            if not value or value in seen_values:
                continue
            seen_values.add(value)

            if value.lower() in FALSE_POSITIVE_VALUES:
                continue
            if len(value) < 8:
                continue

            confidence = base_confidence
            reasons = [f"pattern:{subtype}"]

            entropy = _shannon_entropy(value)
            if entropy >= 4.0:
                confidence += 10
                reasons.append(f"entropy:{entropy:.1f}")
            elif entropy < 2.5 and subtype == "generic_api_key":
                confidence -= 20
                reasons.append("low_entropy")

            context_lower = _snippet(content, match.start(), match.end()).lower()
            if any(w in context_lower for w in ("live", "production", "prod")):
                confidence += 10
                reasons.append("production_context")
            if any(w in context_lower for w in ("test", "example", "sample", "dummy")):
                confidence -= 15
                reasons.append("test_context")

            if confidence < MIN_REPORT_CONFIDENCE:
                continue

            findings.append(Finding(
                kind="secret",
                subtype=subtype,
                value=value,
                redacted=_redact(value),
                file_url=js_file.url,
                line_number=_line_for_pos(line_offsets, match.start()),
                context=_snippet(content, match.start(), match.end()),
                confidence=min(confidence, 100),
                severity=_severity_for_confidence(confidence, "secret"),
                reasons=reasons,
                auth_enabled=auth_on,
                first_seen=now,
            ))

    return findings


SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s]+)""")


def _analyze_sourcemaps(js_file: JSFile, auth_on: bool) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc).isoformat()

    for match in SOURCEMAP_RE.finditer(js_file.content):
        map_url = match.group(1).strip()
        if not map_url.startswith(("http://", "https://")):
            map_url = urllib.parse.urljoin(js_file.url, map_url)

        findings.append(Finding(
            kind="sourcemap",
            subtype="source_mapping_url",
            value=map_url,
            redacted=map_url,
            file_url=js_file.url,
            line_number=js_file.content[:match.start()].count("\n") + 1,
            context=_snippet(js_file.content, match.start(), match.end()),
            confidence=85,
            severity="HIGH",
            reasons=["source_mapping_url"],
            auth_enabled=auth_on,
            first_seen=now,
        ))

    return findings


def _severity_for_confidence(confidence: int, kind: str) -> str:
    if kind == "secret":
        if confidence >= 90:
            return "CRITICAL"
        if confidence >= 70:
            return "HIGH"
        if confidence >= 50:
            return "MEDIUM"
        return "LOW"
    if confidence >= 80:
        return "HIGH"
    if confidence >= 60:
        return "MEDIUM"
    return "LOW"


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[Finding]) -> None:
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

    try:
        payloads = [f.to_dict() for f in findings]
        result = DB.upsert_js_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} JS finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_js_analysis(
    input_file: Path,
    outdir: Path,
    *,
    max_files: int = MAX_FILES,
    download_threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    headers: Optional[dict] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Discover, download, and analyze JS files from every host in `input_file`.

    Threads and rate_limit come from MODULE_RATE_LIMITS["js"] unless overridden.
    Headers come from config.py (ACTIVE_HEADERS + AUTH_HEADERS) unless overridden.
    If scan_id is provided, self-syncs to the `js_findings` table.
    """
    start = time.monotonic()

    settings = _js_settings()
    eff_threads = download_threads if download_threads is not None else settings["threads"]
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]

    base_urls = _extract_urls(input_file)
    if not base_urls:
        log.warning("  No base URLs — writing empty report")
        return _write_empty_report(outdir, input_file, start)

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "js_work"
    workdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()

    log.info(f"  Input  : {len(base_urls)} host(s) from {input_file.name}")
    rate_label = f"{eff_rate}/s" if eff_rate and eff_rate > 0 else "unlimited"
    log.info(f"  Config : threads={eff_threads}  rate_limit={rate_label}")
    log.info(f"           source: MODULE_RATE_LIMITS['js']")

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to katana + downloads")
        for k, v in list(cfg_hdrs.items())[:4]:
            v_short = v[:50] + "…" if len(v) > 50 else v
            log.info(f"           · {k}: {v_short}")
        if len(cfg_hdrs) > 4:
            log.info(f"           · ... and {len(cfg_hdrs) - 4} more")
    else:
        log.info(f"  Headers: none configured")

    if auth_on:
        log.info(f"  Auth   : ENABLED (request.txt) — authenticated JS discovery")
    else:
        log.info(f"  Auth   : disabled")
    log.info("")

    # ── Discovery ───────────────────────────────────────────────────────────
    js_files = discover_js_files(base_urls, input_file, workdir, eff_rate, eff_threads)
    if len(js_files) > max_files:
        log.warning(f"  Capping at {max_files} JS files (found {len(js_files)})")
        js_files = js_files[:max_files]

    if not js_files:
        log.warning("  No JS files to analyze — writing empty report")
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass
        return _write_empty_report(outdir, input_file, start)

    # ── Download ────────────────────────────────────────────────────────────
    js_files = download_js_files(js_files, eff_threads, eff_rate)

    ok_files = [f for f in js_files if f.ok]
    log.info(f"  Analyzable: {len(ok_files)} / {len(js_files)} file(s)")

    if not ok_files:
        log.warning("  No downloadable JS files — writing empty report")
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass
        return _write_empty_report(outdir, input_file, start)

    # ── Analysis ────────────────────────────────────────────────────────────
    log.info("  Analyzing endpoints, secrets, and source maps...")
    all_findings: list[Finding] = []
    endpoint_count = 0
    secret_count = 0
    map_count = 0

    for i, js_file in enumerate(ok_files, 1):
        try:
            ep = _analyze_endpoints(js_file, auth_on)
            sc = _analyze_secrets(js_file, auth_on)
            sm = _analyze_sourcemaps(js_file, auth_on)
            all_findings.extend(ep + sc + sm)
            endpoint_count += len(ep)
            secret_count += len(sc)
            map_count += len(sm)
        except Exception as e:
            log.debug(f"    analysis error on {js_file.url}: {e}")

        if i % 25 == 0:
            log.info(f"    ... analyzed {i}/{len(ok_files)} file(s)")

    log.info(f"    Endpoints: {endpoint_count}  "
             f"Secrets: {secret_count}  "
             f"Source maps: {map_count}")

    # ── Dedupe by (kind, subtype, value) ────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for f in all_findings:
        key = (f.kind, f.subtype, f.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def _sort_key(f: Finding) -> tuple:
        kind_order = {"secret": 0, "sourcemap": 1, "endpoint": 2}
        return (kind_order.get(f.kind, 3), SEV_ORDER.get(f.severity, 4), -f.confidence, f.value)

    deduped.sort(key=_sort_key)

    # ── Flat outputs ────────────────────────────────────────────────────────
    endpoints = sorted({f.value for f in deduped if f.kind == "endpoint"})
    secrets = [f for f in deduped if f.kind == "secret"]
    sourcemaps = sorted({f.value for f in deduped if f.kind == "sourcemap"})
    js_urls = sorted({f.url for f in js_files})

    (outdir / "js_endpoints.txt").write_text(
        "\n".join(endpoints) + ("\n" if endpoints else "")
    )
    (outdir / "js_secrets.txt").write_text(
        "\n".join(f"{f.subtype}\t{f.redacted}\t{f.file_url}:{f.line_number}" for f in secrets)
        + ("\n" if secrets else "")
    )
    (outdir / "js_sourcemaps.txt").write_text(
        "\n".join(sourcemaps) + ("\n" if sourcemaps else "")
    )
    (outdir / "js_files.txt").write_text(
        "\n".join(js_urls) + ("\n" if js_urls else "")
    )

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_kind: dict[str, int] = {"endpoint": 0, "secret": 0, "sourcemap": 0}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(input_file),
        "hosts_scanned": len(base_urls),
        "auth_enabled": auth_on,
        "config": {
            "max_files":             max_files,
            "download_threads":      eff_threads,
            "rate_limit":            eff_rate,
            "headers_count":         len(cfg_hdrs),
            "min_report_confidence": MIN_REPORT_CONFIDENCE,
        },
        "totals": {
            "js_files_discovered": len(js_files),
            "js_files_analyzed":   len(ok_files),
            "total_findings":      len(deduped),
            "endpoints":           by_kind["endpoint"],
            "secrets":             by_kind["secret"],
            "sourcemaps":          by_kind["sourcemap"],
            "critical":            by_severity["CRITICAL"],
            "high":                by_severity["HIGH"],
            "medium":              by_severity["MEDIUM"],
            "low":                 by_severity["LOW"],
        },
        "summary": {
            "by_kind":     by_kind,
            "by_severity": by_severity,
        },
        "js_files": [f.to_dict() for f in js_files],
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "js_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Summary ─────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(deduped):>5} finding(s)")
    log.info(f"    js_endpoints.txt         {len(endpoints):>5} endpoint(s)")
    log.info(f"    js_secrets.txt           {len(secrets):>5} secret(s)")
    log.info(f"    js_sourcemaps.txt        {len(sourcemaps):>5} source map(s)")
    log.info(f"    js_files.txt             {len(js_urls):>5} JS file URL(s)")

    log.info("")
    log.info(f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
             f"HIGH={by_severity['HIGH']}  "
             f"MEDIUM={by_severity['MEDIUM']}  "
             f"LOW={by_severity['LOW']}")

    if secrets:
        log.info("")
        log.info("  Top secret findings:")
        for f in [x for x in secrets if x.severity in ("CRITICAL", "HIGH")][:10]:
            log.info(f"    [{f.severity}] {f.subtype:<24} "
                     f"{f.redacted:<30}  {f.file_url}:{f.line_number}")

    if endpoints:
        log.info("")
        log.info("  Interesting endpoints:")
        interesting = [e for e in endpoints if any(
            w in e.lower() for w in ("admin", "internal", "graphql", "debug", "api/v")
        )][:10]
        for e in interesting:
            log.info(f"    {e}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(input_file),
        "hosts_scanned":   0,
        "auth_enabled":    bool(_cfg("AUTH_ENABLED", False)),
        "config":          {},
        "totals": {
            "js_files_discovered": 0, "js_files_analyzed": 0,
            "total_findings": 0, "endpoints": 0, "secrets": 0,
            "sourcemaps": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary":   {"by_kind": {}, "by_severity": {}},
        "js_files":  [],
        "findings":  [],
    }
    path = outdir / "js_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("js_endpoints.txt", "js_secrets.txt", "js_sourcemaps.txt", "js_files.txt"):
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
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus JS analyzer (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    args = parser.parse_args()

    try:
        run_js_analysis(
            args.input, args.output,
            max_files=args.max_files,
            download_threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
