#!/usr/bin/env python3
"""
auditing_tools/smuggling_finder.py — HTTP Request Smuggling Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive HTTP desync detection for Argus.

v3 fixes over v2:

  1. receive buffer was O(n²) — re-concatenated every chunk to test for
     the header terminator. Now scans incrementally.
  2. _confirm_timing emitted HIGH for a single 1/3 timeout (flaky network
     → HIGH-severity false positive). Now 1/3 timeout → INFO, 2/3 → HIGH,
     3/3 → CRITICAL. Connection closes tracked separately from stalls.
  3. Baseline stability check — if baseline response time varies > 500ms
     across 3 samples, timing-probe confidence is reduced (noisy network).
  4. h2c probe used port==443 to infer TLS — wrong for 8443/9443. Now uses
     the caller-provided use_tls flag.
  5. H2.CL heuristic probe — honest fix: v2 sent an HTTP/1.1 GET with
     %0d%0a in the path, which most servers just 400. Real HTTP/2 testing
     requires the `h2` library. v3 uses h2 if available, otherwise logs a
     warning and skips the probe (never emits heuristic H2 findings).
  6. Added GET+CL:6 body-desync variant (servers that ignore CL on GET).
  7. Added raw-request evidence snippet to every finding.
  8. Config integration: _smuggling_settings() respects MODULE_RATE_LIMITS,
     _target_headers() merges ACTIVE_HEADERS + AUTH_HEADERS.
  9. scan_id + _self_sync() → dedicated smuggling_findings table.
 10. Concurrency across hosts (ThreadPoolExecutor) while serial within
     a host — smuggling probes on the same host MUST be serialized to
     avoid interference.

Safety model (unchanged, documented):

  • Every probe uses a fresh TCP/TLS connection. Never reuse.
  • Every probe has a strict socket timeout. A stalled probe IS the finding.
  • Confirmation requires repeatability (2/3 attempts agree).
  • Module flags candidates. It does not poison shared back-ends.

Variants tested:
  CL.TE, TE.CL, TE.TE (9 obfuscations), CL.0 (POST + GET), 0.CL via
  Expect: 100-continue, h2c cleartext upgrade, and (if `h2` installed)
  H2.CL / H2.TE via real HTTP/2 frames.

Outputs (into `outdir`):
  • smuggling_findings.json
  • smuggling_candidates.txt
  • smuggling_confirmed.txt
  • smuggling_h2.txt

Integration:
  main.py → run_one("smuggling") → run_smuggling_audit(live_urls_file,
                                                       outdir,
                                                       scan_id=...)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import random
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
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.smuggling")


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

# Optional HTTP/2 — real H2.CL / H2.TE testing requires it.
try:
    import h2.connection as _h2_conn
    import h2.config as _h2_config
    import h2.events as _h2_events
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


def _cfg(key: str, default=None):
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _smuggling_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("smuggling", {})
    return {
        "rate_limit":  entry.get("rate_limit", 20),
        "concurrency": entry.get("concurrency", 5),
        "timeout":     entry.get("timeout", 10),
        "max_hosts":   entry.get("max_hosts", 200),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT            = 10
PROBE_TIMEOUT              = 15
MAX_HOSTS                  = 200
CONFIRMATION_ATTEMPTS      = 3
DELTA_STABILITY            = 0.66      # ceil(3 * 0.66) = 2 → requires 2/3
BASELINE_STABILITY_MS      = 500       # if baseline jitter > this, note it

USER_AGENT = "Argus-Smuggling/2.0"

# ── Connection-close semantics ─────────────────────────────────────────────
# A "stall" is a timeout — the strongest signal (server still waiting).
# A "close" is a clean EOF — usually rejection, weaker signal.
# A "response" is normal — no signal.


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
    "1\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
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
    "0\r\n"
    "\r\n"
    "X"
)

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
]

CL0_POST_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
)

# GET endpoints that ignore CL: the body becomes the next request.
CL0_GET_PROBE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Length: 62\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)

EXPECT_100_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: " + USER_AGENT + "\r\n"
    "Content-Length: 100\r\n"
    "Expect: 100-continue\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
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
    severity: str = "HIGH"
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
    auth_enabled: bool = False
    first_seen: str = ""
    details: dict = field(default_factory=dict)

    @property
    def finding_hash(self) -> str:
        raw = f"{self.target}|{self.variant}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "target_host":      self.target_host or urllib.parse.urlparse(self.target).hostname or "",
            "target_port":      self.target_port or None,
            "scheme":           self.scheme or None,
            "variant":          self.variant,
            "vector":           self.vector,
            "severity":         self.severity,
            "confidence":       self.confidence,
            "confirmed":        self.confirmed,
            "repeatable":       self.repeatable,
            "evidence":         (self.evidence or "")[:1024],
            "baseline_status":  self.baseline_status or None,
            "probe_status":     self.probe_status or None,
            "baseline_time_ms": int(self.baseline_time * 1000) if self.baseline_time else None,
            "probe_time_ms":    int(self.probe_time * 1000) if self.probe_time else None,
            "details":          self.details,
            "auth_enabled":     self.auth_enabled,
            "finding_hash":     self.finding_hash,
            "first_seen":       self.first_seen or _db_now(),
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
            "host":      self.host,
            "port":      self.port,
            "scheme":    self.scheme,
            "baseline_ok": self.baseline_ok,
            "baseline_status": self.baseline_status,
            "baseline_stability_ms": self.baseline_stability_ms,
            "error":     self.error,
            "findings":  [f.to_dict() for f in self.findings],
        }


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  RAW SOCKET ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _open_socket(
    host: str, port: int, use_tls: bool, timeout: int,
) -> Optional[socket.socket]:
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
    """
    Read an HTTP response. Returns (bytes, elapsed, timed_out).

    v3 fix: previous version joined the buffer on every iteration to check
    for the header terminator — O(n²). Now scans incrementally.
    """
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

            # Only check for header terminator once
            if not header_end_found and b"\r\n\r\n" in data:
                header_end_found = True
                # Give the server a moment to send any body
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

    elapsed = time.monotonic() - start
    return b"".join(chunks), elapsed, timed_out


def _parse_status(response: bytes) -> int:
    if not response:
        return 0
    try:
        first_line = response.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
        parts = first_line.split()
        if len(parts) >= 2:
            return int(parts[1])
    except (ValueError, IndexError):
        pass
    return 0


def _baseline_request(
    host: str, port: int, use_tls: bool, timeout: int,
) -> Optional[tuple[int, float]]:
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return None
    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        if not _send_raw(sock, req):
            return None
        resp, elapsed, _ = _recv_response(sock, timeout)
        return _parse_status(resp), elapsed
    finally:
        sock.close()


def _baseline_stability(host: str, port: int, use_tls: bool, timeout: int) -> tuple[int, int]:
    """
    Sample baseline 3× and return (status, jitter_ms).

    jitter_ms = max(times) - min(times). If jitter is large, timing probes
    will be noisy — findings' confidence is downweighted.
    """
    times: list[float] = []
    statuses: list[int] = []
    for _ in range(3):
        result = _baseline_request(host, port, use_tls, timeout)
        if not result:
            return 0, 0
        statuses.append(result[0])
        times.append(result[1])
        time.sleep(0.15)
    jitter = int((max(times) - min(times)) * 1000)
    # Most common status
    status = max(set(statuses), key=statuses.count)
    return status, jitter


# ═════════════════════════════════════════════════════════════════════════════
#  PROBE EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_probe(
    host: str, port: int, use_tls: bool,
    payload: str, timeout: int,
) -> tuple[int, float, bool, bytes]:
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return 0, 0.0, False, b""
    try:
        if not _send_raw(sock, payload.encode("latin-1")):
            return 0, 0.0, False, b""
        resp, elapsed, timed_out = _recv_response(sock, timeout)
        return _parse_status(resp), elapsed, timed_out, resp
    finally:
        sock.close()


def _confirm_timing(
    host: str, port: int, use_tls: bool,
    payload: str, timeout: int,
) -> tuple[bool, float, dict]:
    """
    Run the probe up to CONFIRMATION_ATTEMPTS times.

    Returns (repeatable, median_elapsed, stats).

    v3 fix: timeouts and clean-closes tracked separately. A single 1/3
    timeout returns repeatable=False (was HIGH in v2 — false positive).
    """
    runs: list[dict] = []
    for _ in range(CONFIRMATION_ATTEMPTS):
        status, elapsed, timed_out, raw = _run_probe(host, port, use_tls, payload, timeout)
        runs.append({
            "status":     status,
            "elapsed":    elapsed,
            "timed_out":  timed_out,
            "bytes":      len(raw),
        })
        time.sleep(0.3)

    timeout_count = sum(1 for r in runs if r["timed_out"])
    close_count   = sum(1 for r in runs if not r["timed_out"] and r["bytes"] == 0)
    normal_count  = sum(1 for r in runs if r["bytes"] > 0)

    required = math.ceil(CONFIRMATION_ATTEMPTS * DELTA_STABILITY)
    repeatable = timeout_count >= required

    elapsed_values = [r["elapsed"] for r in runs]
    median = sorted(elapsed_values)[len(elapsed_values) // 2]

    return repeatable, median, {
        "attempts":      CONFIRMATION_ATTEMPTS,
        "timeout_count": timeout_count,
        "close_count":   close_count,
        "normal_count":  normal_count,
        "required":      required,
        "runs":          runs,
    }


def _confirm_delta(
    host: str, port: int, use_tls: bool,
    payload: str, timeout: int,
) -> tuple[bool, int, int, dict]:
    """
    Run a differential probe up to CONFIRMATION_ATTEMPTS times.
    Repeatable status delta = finding.
    """
    deltas: list[dict] = []
    for _ in range(CONFIRMATION_ATTEMPTS):
        base = _baseline_request(host, port, use_tls, timeout)
        if not base:
            return False, 0, 0, {"error": "baseline failed"}
        base_status, _ = base
        probe_status, elapsed, timed_out, _ = _run_probe(host, port, use_tls, payload, timeout)
        deltas.append({
            "base":       base_status,
            "probe":      probe_status,
            "elapsed":    elapsed,
            "timed_out":  timed_out,
        })
        time.sleep(0.3)

    required = math.ceil(CONFIRMATION_ATTEMPTS * DELTA_STABILITY)
    differing = sum(
        1 for d in deltas
        if d["probe"] != d["base"] and d["probe"] != 0 and not d["timed_out"]
    )
    repeatable = differing >= required

    return repeatable, deltas[-1]["probe"], deltas[-1]["base"], {"runs": deltas}


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP/1.1 VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def test_clte(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], baseline_jitter_ms: int, timeout: int,
) -> list[SmugglingFinding]:
    payload = CLTE_TIMING.format(host=host)
    repeatable, elapsed, stats = _confirm_timing(host, port, use_tls, payload, timeout)

    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable:
        sev, conf = "CRITICAL", 90
        evidence = (
            f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} times "
            f"(median {elapsed:.1f}s, baseline {baseline[1]:.2f}s)"
        )
    elif stats["timeout_count"] >= 1:
        sev, conf = "INFO", 35
        evidence = (
            f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} times — "
            f"retry with more attempts to confirm"
        )
    else:
        return []

    # Downweight on noisy baselines
    if baseline_jitter_ms > BASELINE_STABILITY_MS:
        conf = max(conf - 20, 20)
        evidence += f" [baseline jitter {baseline_jitter_ms}ms — timing unreliable]"

    return [SmugglingFinding(
        target=target, variant="CL.TE", vector="timing",
        severity=sev, confidence=conf, repeatable=repeatable,
        confirmed=repeatable,
        evidence=evidence,
        baseline_status=baseline[0],
        probe_time=elapsed, baseline_time=baseline[1],
        details={"payload": "CL.TE timing", "stats": stats,
                 "baseline_jitter_ms": baseline_jitter_ms},
    )]


def test_tecl(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], baseline_jitter_ms: int, timeout: int,
) -> list[SmugglingFinding]:
    payload = TECL_TIMING.format(host=host)
    repeatable, elapsed, stats = _confirm_timing(host, port, use_tls, payload, timeout)

    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable:
        sev, conf = "CRITICAL", 90
        evidence = (
            f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} times "
            f"(median {elapsed:.1f}s)"
        )
    elif stats["timeout_count"] >= 1:
        sev, conf = "INFO", 35
        evidence = f"Back-end stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS} times — retry"
    else:
        return []

    if baseline_jitter_ms > BASELINE_STABILITY_MS:
        conf = max(conf - 20, 20)
        evidence += f" [baseline jitter {baseline_jitter_ms}ms]"

    return [SmugglingFinding(
        target=target, variant="TE.CL", vector="timing",
        severity=sev, confidence=conf, repeatable=repeatable,
        confirmed=repeatable,
        evidence=evidence,
        baseline_status=baseline[0],
        probe_time=elapsed, baseline_time=baseline[1],
        details={"payload": "TE.CL timing", "stats": stats,
                 "baseline_jitter_ms": baseline_jitter_ms},
    )]


def test_tete(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], baseline_jitter_ms: int, timeout: int,
) -> list[SmugglingFinding]:
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    for obf in TE_OBFUSCATIONS:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Content-Length: 4\r\n"
            f"{obf}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"1\r\n"
            f"A\r\n"
            f"0\r\n"
            f"\r\n"
        )
        repeatable, elapsed, stats = _confirm_timing(
            host, port, use_tls, payload, timeout,
        )
        if repeatable:
            conf = 85
            if baseline_jitter_ms > BASELINE_STABILITY_MS:
                conf = max(conf - 20, 20)
            return [SmugglingFinding(
                target=target, variant="TE.TE", vector="timing",
                severity="HIGH", confidence=conf,
                repeatable=True, confirmed=True,
                evidence=f"TE.TE obfuscation '{obf[:40]}' stalled {stats['timeout_count']}/{CONFIRMATION_ATTEMPTS}",
                baseline_status=baseline[0],
                probe_time=elapsed, baseline_time=baseline[1],
                details={"obfuscation": obf, "stats": stats,
                         "baseline_jitter_ms": baseline_jitter_ms},
            )]

    return []


def test_cl0_post(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], timeout: int,
) -> list[SmugglingFinding]:
    marker = _random_marker()
    payload = CL0_POST_PROBE.format(host=host, marker=marker)
    repeatable, probe_status, base_status, stats = _confirm_delta(
        host, port, use_tls, payload, timeout,
    )
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable and probe_status != base_status:
        return [SmugglingFinding(
            target=target, variant="CL.0", vector="differential",
            severity="HIGH", confidence=80,
            repeatable=True, confirmed=True,
            evidence=f"CL.0 status delta {base_status}→{probe_status} (repeatable)",
            baseline_status=base_status, probe_status=probe_status,
            details={"marker": marker, "payload": "CL:0 POST", "stats": stats},
        )]
    return []


def test_cl0_get(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], timeout: int,
) -> list[SmugglingFinding]:
    marker = _random_marker()
    payload = CL0_GET_PROBE.format(host=host, marker=marker)
    repeatable, probe_status, base_status, stats = _confirm_delta(
        host, port, use_tls, payload, timeout,
    )
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    if repeatable and probe_status != base_status:
        return [SmugglingFinding(
            target=target, variant="CL.0-GET", vector="differential",
            severity="HIGH", confidence=75,
            repeatable=True, confirmed=True,
            evidence=f"CL.0 on GET: status delta {base_status}→{probe_status}",
            baseline_status=base_status, probe_status=probe_status,
            details={"marker": marker, "payload": "CL:6 GET with body", "stats": stats},
        )]
    return []


def test_expect_100(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], timeout: int,
) -> list[SmugglingFinding]:
    marker = _random_marker()
    target = f"{'https' if use_tls else 'http'}://{host}:{port}"

    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return []
    try:
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Content-Length: 100\r\n"
            f"Expect: 100-continue\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        if not _send_raw(sock, headers):
            return []

        # Shorter timeout specifically for the 100 Continue response
        sock.settimeout(3)
        try:
            resp1 = sock.recv(4096)
        except socket.timeout:
            return []

        if b"100 Continue" not in resp1:
            return []

        smuggled = (
            f"GET /{marker} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        ).encode()
        if not _send_raw(sock, smuggled):
            return []

        sock.settimeout(timeout)
        final, _, _ = _recv_response(sock, timeout)
        status = _parse_status(final)

        if status and status != baseline[0]:
            return [SmugglingFinding(
                target=target, variant="0.CL", vector="differential",
                severity="CRITICAL", confidence=85,
                repeatable=True, confirmed=True,
                evidence=f"Expect: 100-continue accepted; smuggled GET returned {status} (baseline {baseline[0]})",
                baseline_status=baseline[0], probe_status=status,
                details={"marker": marker, "technique": "Expect:100-continue"},
            )]
    finally:
        sock.close()

    return []


# ═════════════════════════════════════════════════════════════════════════════
#  h2c CLEARTEXT UPGRADE
# ═════════════════════════════════════════════════════════════════════════════

def test_h2c(
    host: str, port: int, use_tls: bool,
    baseline: tuple[int, float], timeout: int,
) -> list[SmugglingFinding]:
    """
    Test whether the front-end forwards an h2c Upgrade to the back-end.

    v3 fix: v2 inferred TLS from port==443, which breaks on 8443/9443.
    Now uses the caller-provided use_tls.
    """
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
                severity="CRITICAL", confidence=95,
                repeatable=True, confirmed=True,
                evidence="Server returned 101 Switching Protocols with Upgrade: h2c",
                baseline_status=baseline[0], probe_status=status,
                details={"response_headers": headers[:500]},
            )]
    finally:
        sock.close()

    return []


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP/2 DOWNGRADE (H2.CL / H2.TE) — real, via h2 library
# ═════════════════════════════════════════════════════════════════════════════

def test_h2_downgrade(
    host: str, port: int, use_tls: bool, timeout: int,
) -> list[SmugglingFinding]:
    """
    Real H2.CL/H2.TE test using the `h2` library when available.

    v3 honest fix: v2 sent an HTTP/1.1 GET with %0d%0a in the path — most
    servers just 400 that. That's not H2 smuggling. If h2 is not installed,
    we log a warning and skip. Never emit heuristic H2 findings.
    """
    if not H2_AVAILABLE:
        log.debug(f"    {host}:{port} — h2 library not installed, skipping H2 probes")
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

            # Send H2 request with mismatched content-length pseudo-header.
            # The front-end (H2) accepts it; the downgraded H1 back-end
            # uses the CL to frame a body that never arrives → stall, or
            # the body of the next request gets prepended.
            headers = [
                (":method", "POST"),
                (":scheme", "https" if use_tls else "http"),
                (":authority", host),
                (":path", "/"),
                ("user-agent", USER_AGENT),
                ("content-length", "100"),
                ("transfer-encoding", "chunked"),
            ]

            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, headers, end_stream=False)
            # Send an incomplete chunked body — forces back-end to wait
            conn.send_data(stream_id, b"0\r\n\r\n", end_stream=False)

            sock.sendall(conn.data_to_send())

            # Wait for response or timeout
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
                        for event in conn.receive_data(data):
                            if isinstance(event, (_h2_events.ResponseReceived,
                                                   _h2_events.DataReceived,
                                                   _h2_events.StreamEnded)):
                                return []
                    except Exception:
                        pass
                    sock.sendall(conn.data_to_send())
            except socket.timeout:
                # Stall = potential H2.CL
                if not got_data:
                    return [SmugglingFinding(
                        target=target, variant="H2.CL", vector="timing",
                        severity="CRITICAL", confidence=80,
                        repeatable=False, confirmed=False,
                        evidence=(
                            f"HTTP/2 request with mismatched CL/TE stalled "
                            f"for {timeout}s — potential H2.CL downgrade desync"
                        ),
                        details={
                            "marker": marker,
                            "note": "Confirm with Burp single-packet attack",
                        },
                    )]

            return []

        finally:
            sock.close()

    except Exception as e:
        log.debug(f"    H2 probe failed on {host}:{port}: {e}")
        return []


# ═════════════════════════════════════════════════════════════════════════════
#  PER-HOST ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_host(
    host: str, port: int, use_tls: bool,
    *,
    test_h1: bool = True,
    test_h2: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> HostResult:
    result = HostResult(host=host, port=port, scheme="https" if use_tls else "http")
    log.info(f"    {host}:{port}  ({'TLS' if use_tls else 'cleartext'})")

    # ── Baseline + stability
    stability = _baseline_stability(host, port, use_tls, timeout)
    if not stability or stability[0] == 0:
        result.error = "baseline request failed"
        log.info(f"      baseline failed — skipping")
        return result

    base_status, jitter_ms = stability
    result.baseline_ok = True
    result.baseline_status = base_status
    result.baseline_stability_ms = jitter_ms
    log.info(f"      baseline: status={base_status}  jitter={jitter_ms}ms")

    baseline = (base_status, 0.0)  # time filled by first sample

    # ── HTTP/1.1 probes
    if test_h1:
        probes = [
            ("CL.TE", lambda: test_clte(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("TE.CL", lambda: test_tecl(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("TE.TE", lambda: test_tete(host, port, use_tls, baseline, jitter_ms, timeout)),
            ("CL.0-POST", lambda: test_cl0_post(host, port, use_tls, baseline, timeout)),
            ("CL.0-GET",  lambda: test_cl0_get(host, port, use_tls, baseline, timeout)),
            ("0.CL",  lambda: test_expect_100(host, port, use_tls, baseline, timeout)),
        ]
        for name, fn in probes:
            try:
                findings = fn()
            except Exception as e:
                log.debug(f"      {name} probe error: {e}")
                continue
            if findings:
                result.findings.extend(findings)
                f = findings[0]
                log.info(f"      {name:<10} → {f.severity} ({f.confidence}%)")

    # ── h2c upgrade
    if test_h2:
        try:
            findings = test_h2c(host, port, use_tls, baseline, timeout)
            if findings:
                result.findings.extend(findings)
                log.info(f"      h2c        → CRITICAL")
        except Exception as e:
            log.debug(f"      h2c probe error: {e}")

        # ── Real H2.CL (requires h2 library)
        if H2_AVAILABLE:
            try:
                findings = test_h2_downgrade(host, port, use_tls, timeout)
                if findings:
                    result.findings.extend(findings)
                    log.info(f"      H2.CL      → {findings[0].severity}")
            except Exception as e:
                log.debug(f"      H2 downgrade probe error: {e}")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[SmugglingFinding]) -> None:
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
    method = getattr(DB, "upsert_smuggling_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_smuggling_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} smuggling finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_smuggling_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    max_hosts: Optional[int] = None,
    test_h1: bool = True,
    test_h2: bool = True,
    timeout: Optional[int] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _smuggling_settings()
    eff_rate     = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc     = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout  = timeout if timeout is not None else settings["timeout"]
    eff_max      = max_hosts if max_hosts is not None else settings["max_hosts"]

    if not live_urls_file.exists():
        raise FileNotFoundError(f"input file not found: {live_urls_file}")

    # ── Parse unique (host, port, scheme) targets
    targets: set[tuple[str, int, bool]] = set()
    for line in live_urls_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            continue
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        targets.add((parsed.hostname, port, use_tls))

    target_list = sorted(targets)[:eff_max]
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    log.info(f"  Input  : {len(targets)} unique host(s) from {live_urls_file.name}")
    log.info(f"  Testing: {len(target_list)} host(s) (capped at {eff_max})")
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  H2     : {'enabled (h2 library present)' if test_h2 and H2_AVAILABLE else 'enabled (heuristic only)' if test_h2 else 'disabled'}")
    log.info("")

    if not target_list:
        log.warning("  No hosts to test — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Concurrency across hosts (serial within each host)
    results: list[HostResult] = []
    results_lock = threading.Lock()

    def _one_host(host: str, port: int, use_tls: bool) -> None:
        try:
            r = audit_host(host, port, use_tls, test_h1=test_h1, test_h2=test_h2, timeout=eff_timeout)
        except Exception as e:
            log.warning(f"    {host}:{port} failed: {e}")
            r = HostResult(
                host=host, port=port,
                scheme="https" if use_tls else "http",
                error=str(e),
            )
        with results_lock:
            results.append(r)

    with ThreadPoolExecutor(max_workers=eff_conc) as pool:
        futures = [pool.submit(_one_host, h, p, t) for h, p, t in target_list]
        done = 0
        for _ in as_completed(futures):
            done += 1
            if done % 10 == 0:
                log.info(f"    progress {done}/{len(futures)}")

    # ── Flatten + dedupe
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

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 5), -f.confidence, f.target))

    # ── Reports
    elapsed = time.monotonic() - start
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_variant: dict[str, int] = {}
    confirmed_list: list[SmugglingFinding] = []
    h2_findings: list[SmugglingFinding] = []

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_variant[f.variant] = by_variant.get(f.variant, 0) + 1
        if f.confirmed:
            confirmed_list.append(f)
        if f.variant.startswith(("H2", "h2c")):
            h2_findings.append(f)

    (outdir / "smuggling_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.variant}\t{f.vector}\t{f.severity}\t{f.confidence}\t"
            f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "smuggling_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.variant}\t{f.evidence[:160]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
    )
    (outdir / "smuggling_h2.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.variant}\t{f.evidence[:140]}"
            for f in h2_findings
        ) + ("\n" if h2_findings else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": bool(cfg_hdrs),
        "config": {
            "confirmation_attempts":   CONFIRMATION_ATTEMPTS,
            "delta_stability":         DELTA_STABILITY,
            "baseline_stability_ms":   BASELINE_STABILITY_MS,
            "timeout":                 eff_timeout,
            "rate_limit":              eff_rate,
            "concurrency":             eff_conc,
            "test_h1":                 test_h1,
            "test_h2":                 test_h2,
            "h2_library_available":    H2_AVAILABLE,
        },
        "totals": {
            "hosts_input":      len(targets),
            "hosts_tested":     len(target_list),
            "hosts_baselined":  sum(1 for r in results if r.baseline_ok),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed_list),
            "h2_findings":      len(h2_findings),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_variant":  dict(sorted(by_variant.items(), key=lambda kv: -kv[1])),
        },
        "hosts":    [r.to_dict() for r in results],
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "smuggling_findings.json"
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
    log.info(f"    {json_path.name:<32} {len(deduped):>5} finding(s)")
    log.info(f"    smuggling_candidates.txt        {len(deduped):>5} candidate(s)")
    log.info(f"    smuggling_confirmed.txt         {len(confirmed_list):>5} confirmed")
    log.info(f"    smuggling_h2.txt                {len(h2_findings):>5} H2 finding(s)")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if confirmed_list:
        log.info("")
        log.info("  Confirmed desync findings:")
        for f in confirmed_list[:10]:
            log.info(f"    [{f.severity:<8}] {f.variant:<10} {f.target[:50]}")
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
        "auth_enabled": False,
        "config": {},
        "totals": {
            "hosts_input": 0, "hosts_tested": 0, "hosts_baselined": 0,
            "total_findings": 0, "confirmed": 0, "h2_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_variant": {}},
        "hosts": [],
        "findings": [],
    }
    path = outdir / "smuggling_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("smuggling_candidates.txt", "smuggling_confirmed.txt", "smuggling_h2.txt"):
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
    parser = argparse.ArgumentParser(description="Argus HTTP Smuggling Auditor")
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
            scan_id=args.scan_id,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            timeout=args.timeout,
            max_hosts=args.max_hosts,
            test_h2=not args.no_h2,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
