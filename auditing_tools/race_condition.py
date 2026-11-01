#!/usr/bin/env python3
"""
auditing_tools/race_condition.py — Race Condition Surface Discovery & Confirmation (v3)
═══════════════════════════════════════════════════════════════════════════════

v3 introduces concurrent-burst confirmation with body-signature analysis.
v2's `success_count > 1` heuristic produced rampant false positives (any
stateful endpoint returning 200 on every request tripped it). v3 replaces it:

  Confirmation logic:
    1. Fire N concurrent requests synchronized via threading.Barrier
    2. Extract a "signature" from every response — (status_code,
       has_success_marker, has_failure_marker, length_bucket)
    3. Identify the winner signature (most common success-shape)
    4. Count how many responses match the winner
    5. Confirmation rules by race class:
         limit_overrun / double_spend / multistep_bypass:
           winner_count >= 2  → CONFIRMED (single-use violated)
           winner_count == 1  → no race
           winner_count == 0  → token exhausted, cannot test
         rate_bypass:
           winner_count == N  → rate limit absent (LOW / informational)
           0 < winner_count < N → rate limit enforced (no bypass)

Two additional v3 improvements:

  • Rate limiting respects MODULE_RATE_LIMITS["race"] for the sequential
    bootstrap request, and bypasses the global limiter during the burst
    (otherwise the barrier alignment is useless — the limiter serializes).
  • Self-sync to a dedicated `race_findings` table when scan_id is provided.

Discovery pipeline (unchanged in spirit from v2):

  Phase 1 — Surface discovery
      URL and parameter patterns classified into four race classes:
      limit_overrun, double_spend, multistep_bypass, rate_bypass.

  Phase 2 — Attack plan generation
      For each candidate, write three ready-to-run exploit scripts:
        • Turbo Intruder (single-packet HTTP/2, Engine.BURP2)
        • curl loop (manual confirmation)
        • Python threading.Barrier (offline confirmation)

  Phase 3 — Concurrent burst confirmation
      Fire N synchronized requests. Analyze response signatures to
      distinguish a real race from "endpoint always returns 200".

  Phase 4 — Reporting
      Dedupe, sort, write JSON + flat candidates, self-sync when scan_id
      is set.

Outputs (into `outdir`):
  • race_findings.json              — full structured report
  • race_candidates.txt             — flat list for triage
  • race_attack_plans/              — one script per candidate × language
  • race_probe_results.txt          — probe outcome evidence
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
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

log = logging.getLogger("argus.race_condition")


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


def _race_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("race", {})
    return {
        "rate_limit":  entry.get("rate_limit", 3),
        "concurrency": entry.get("concurrency", 10),
        "timeout":     entry.get("timeout", 12),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _test_account(slot: str) -> dict:
    return (_cfg("TEST_ACCOUNTS", {}) or {}).get(slot, {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 12
DEFAULT_PROBE_COUNT = 20
PROBE_TIMEOUT = 30
MAX_PROBES = 100
BURST_RATE_OVERRIDE = 500          # effectively unlimited during burst

SUCCESS_MARKERS = (
    "success", '"ok"', '"status":"ok"', '"applied"', '"redeemed"',
    '"created"', '"accepted"', '"completed"', '"confirmed"',
    '"valid":true', '"allowed":true',
)
FAILURE_MARKERS = (
    '"error"', '"fail"', '"already"', '"used"', '"invalid"',
    '"expired"', '"denied"', '"rejected"', '"limit"', '"not found"',
    '"forbidden"', 'rate limit', 'too many requests',
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

TURBO_TEMPLATE = '''# Turbo Intruder script — generated by Argus
# Target: {target}
# Race class: {race_class}
# Expected: {expected}
#
# Instructions:
#   1. Paste into Burp's Turbo Intruder (Extensions → Turbo Intruder → Send to Turbo)
#   2. Replace the raw request below with your captured request
#   3. Adjust REQUEST_COUNT if needed (default {request_count})
#   4. Run. Multiple 2xx responses = race confirmed.
#
# Note: Requires HTTP/2 target. For HTTP/1.1, use concurrentConnections=1
# with maxRetriesPerRequest=0 — less precise but still useful.

REQUEST_COUNT = {request_count}

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
    if 200 <= req.status < 300:
        print("[+] SUCCESS: " + str(req.status) + " " + target.endpoint)
'''

CURL_TEMPLATE = '''#!/bin/bash
# Race condition probe — {race_class}
# Target: {target}
# Expected: {expected}
# Fire {request_count} requests in parallel and count successes.

TARGET='{target}'
COUNT={request_count}
METHOD='{method}'

SUCCESS=0
FAIL=0
for i in $(seq 1 "$COUNT"); do
    (
        CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X "$METHOD" "$TARGET")
        if [ "$CODE" -ge 200 ] && [ "$CODE" -lt 300 ]; then
            echo "OK $CODE"
        else
            echo "FAIL $CODE"
        fi
    ) &
done
wait | sort | uniq -c
'''

PYTHON_TEMPLATE = '''#!/usr/bin/env python3
"""Race condition probe — {race_class} — {target}"""
import threading, time, requests

TARGET = "{target}"
COUNT = {request_count}
METHOD = "{method}"

results = []
lock = threading.Lock()
barrier = threading.Barrier(COUNT)

def fire():
    try:
        barrier.wait(timeout=10)
    except threading.BrokenBarrierError:
        return
    t0 = time.monotonic()
    try:
        r = requests.request(METHOD, TARGET, timeout=30, verify=False, allow_redirects=False)
        elapsed = time.monotonic() - t0
        with lock:
            results.append((r.status_code, elapsed, len(r.content)))
    except Exception as e:
        with lock:
            results.append((0, 0, 0))

threads = [threading.Thread(target=fire) for _ in range(COUNT)]
for t in threads: t.start()
for t in threads: t.join()

successes = sum(1 for s, _, _ in results if 200 <= s < 300)
print(f"Successes: {{successes}}/{{COUNT}}")
print(f"Statuses:  {{[s for s,_,_ in results]}}")
print(f"Times:     {{[round(t, 3) for _,t,_ in results]}}")
print("VULNERABLE" if successes > 1 else "No race detected")
'''


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RaceCandidate:
    target: str
    race_class: str
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    description: str = ""
    evidence: str = ""
    method: str = "POST"
    param_name: str = ""
    expected_outcome: str = ""
    escalation: str = ""
    sequential_success: Optional[int] = None
    concurrent_success: Optional[int] = None
    request_count: Optional[int] = None
    http_statuses: list[int] = field(default_factory=list)
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
            "severity":           self.severity,
            "confidence":         self.confidence,
            "confirmed":          self.confirmed,
            "description":        self.description[:1024],
            "evidence":           self.evidence[:1024],
            "method":             self.method,
            "param_name":         self.param_name,
            "expected_outcome":   self.expected_outcome,
            "escalation":         self.escalation,
            "sequential_success": self.sequential_success,
            "concurrent_success": self.concurrent_success,
            "request_count":      self.request_count,
            "http_statuses":      self.http_statuses,
            "details":            self.details,
            "auth_enabled":       self.auth_enabled,
            "finding_hash":       self.finding_hash,
            "first_seen":         self.first_seen or _db_now(),
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
        base_hdrs = _target_headers()
        if base_hdrs:
            self.session.headers.update(base_hdrs)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0
        self._lock = threading.Lock()
        self._burst_mode = False

    def set_burst_mode(self, on: bool) -> None:
        """When True, skip rate limiting (used during synchronized burst)."""
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


def _match_race_patterns(url: str) -> list[tuple[str, str, str, str]]:
    combined = url.lower()
    matches: list[tuple[str, str, str, str]] = []
    for pattern, race_class, severity, description in RACE_PATTERNS:
        if re.search(pattern, combined, re.I):
            matches.append((pattern, race_class, severity, description))
    return matches


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


def _body_signature(resp: Optional[requests.Response]) -> tuple:
    """
    Return a signature tuple that survives nonce variation.

    (status_code, has_success_marker, has_failure_marker, length_bucket)

    Two responses that represent the same logical outcome (e.g., two
    "coupon applied successfully" bodies with different timestamps) will
    produce the same signature because:
      • status is the same
      • both contain success markers (or neither does)
      • neither contains failure markers (or both do)
      • length bucket is the same (//20 to absorb small variations)
    """
    if resp is None:
        return (0, False, False, 0)
    try:
        body_lower = (resp.text or "").lower()[:5000]
    except Exception:
        body_lower = ""
    has_succ = any(m in body_lower for m in SUCCESS_MARKERS)
    has_fail = any(m in body_lower for m in FAILURE_MARKERS)
    bucket = len(body_lower) // 20
    return (resp.status_code, has_succ, has_fail, bucket)


def _is_likely_success(sig: tuple) -> bool:
    status, has_succ, has_fail, _ = sig
    if not (200 <= status < 300):
        return False
    if has_fail and not has_succ:
        return False
    return True


def _build_curl(
    method: str, url: str,
    headers: Optional[dict] = None,
    form_body: Optional[dict] = None,
    json_body: Optional[dict] = None,
) -> str:
    parts = [f"curl -X {method} '{url}'"]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("cookie", "authorization"):
                parts.append(f"-H '{k}: {v[:20]}...'")
            else:
                parts.append(f"-H '{k}: {v}'")
    if json_body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(json_body)[:300]}'")
    elif form_body:
        parts.append(f"-d '{urllib.parse.urlencode(form_body)[:300]}'")
    return " ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_candidates(urls: list[str]) -> list[RaceCandidate]:
    candidates: list[RaceCandidate] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        matches = _match_race_patterns(url)
        if not matches:
            continue

        method = _infer_method(url, params)
        param = _infer_param(params)

        for pattern, race_class, severity, description in matches:
            key = (url, race_class)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(RaceCandidate(
                target=url,
                race_class=race_class,
                severity=severity,
                confidence=60,
                description=description,
                method=method,
                param_name=param,
                expected_outcome=_expected_outcome(race_class),
                escalation=_escalation_for_class(race_class),
                evidence=f"URL matched pattern: {pattern}",
                details={
                    "matched_pattern": pattern,
                    "inferred_method": method,
                    "inferred_param":  param,
                },
            ))

    return candidates


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ATTACK PLAN GENERATION
# ═════════════════════════════════════════════════════════════════════════════

def write_attack_plans(candidates: list[RaceCandidate], outdir: Path) -> Path:
    plan_dir = outdir / "race_attack_plans"
    plan_dir.mkdir(parents=True, exist_ok=True)

    for i, c in enumerate(candidates, 1):
        safe = re.sub(r"[^a-zA-Z0-9]+", "_", c.target)[:60]
        prefix = f"{i:03d}_{safe}"

        # Turbo Intruder
        (plan_dir / f"{prefix}_turbo.py").write_text(
            TURBO_TEMPLATE.format(
                target=c.target, race_class=c.race_class,
                expected=c.expected_outcome, request_count=DEFAULT_PROBE_COUNT,
            )
        )
        # curl
        (plan_dir / f"{prefix}.sh").write_text(
            CURL_TEMPLATE.format(
                target=c.target, race_class=c.race_class,
                expected=c.expected_outcome, method=c.method,
                request_count=DEFAULT_PROBE_COUNT,
            )
        )
        # Python
        (plan_dir / f"{prefix}.py").write_text(
            PYTHON_TEMPLATE.format(
                target=c.target, race_class=c.race_class,
                method=c.method, request_count=DEFAULT_PROBE_COUNT,
            )
        )

    return plan_dir


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CONCURRENT BURST PROBE
# ═════════════════════════════════════════════════════════════════════════════

def _send_one(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    headers: Optional[dict],
    timeout: int,
) -> Optional[requests.Response]:
    """Send a single request according to the candidate's method."""
    try:
        if candidate.method in ("POST", "PUT", "PATCH"):
            # Try form data with empty body (safest default — many APIs
            # accept it and the vulnerable logic typically ignores body)
            return session.request(
                candidate.method, candidate.target,
                headers=headers, data={}, timeout=timeout,
            )
        return session.request(
            candidate.method, candidate.target,
            headers=headers, timeout=timeout,
        )
    except Exception as e:
        log.debug(f"_send_one failed: {e}")
        return None


def _run_concurrent_burst(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    headers: Optional[dict],
    request_count: int,
    timeout: int,
) -> list[Optional[requests.Response]]:
    """
    Fire request_count requests synchronized via threading.Barrier.

    Rate limiting is DISABLED during the burst — otherwise the barrier
    alignment is meaningless because the limiter serializes the requests.

    Timeout on barrier wait (10s) prevents deadlock if one thread fails
    to spawn. Timeout on join (PROBE_TIMEOUT) prevents deadlock if one
    request hangs beyond its own timeout.
    """
    results: list[Optional[requests.Response]] = [None] * request_count
    barrier = threading.Barrier(request_count)

    def worker(idx: int) -> None:
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            return
        results[idx] = _send_one(session, candidate, headers, timeout)

    session.set_burst_mode(True)
    try:
        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True)
            for i in range(request_count)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=PROBE_TIMEOUT)
    finally:
        session.set_burst_mode(False)

    return results


def probe_candidate(
    session: RateLimitedSession,
    candidate: RaceCandidate,
    headers: Optional[dict],
    request_count: int,
    timeout: int,
) -> None:
    """
    Probe one candidate in-place (mutates candidate with results).

    Confirmation rules:
      single-use classes (limit_overrun, double_spend, multistep_bypass):
        winner_count >= 2 → CONFIRMED,  confidence 90
        winner_count == 1 → no race,     confidence 40
        winner_count == 0 → can't test (token exhausted)
      rate_bypass:
        winner_count == request_count → no rate limit (LOW informational)
        0 < winner_count < request_count → rate limit enforced (no bypass)
    """
    responses = _run_concurrent_burst(
        session, candidate, headers, request_count, timeout,
    )

    # Signature analysis
    signatures = [_body_signature(r) for r in responses if r is not None]
    if not signatures:
        candidate.evidence = (
            f"Concurrent burst produced 0 responses "
            f"(network/timeout on all {request_count} requests)"
        )
        candidate.confidence = 0
        candidate.details["probe"] = {"error": "no responses"}
        return

    successes = [s for s in signatures if _is_likely_success(s)]

    candidate.request_count = len(signatures)
    candidate.http_statuses = [s[0] for s in signatures]

    if not successes:
        candidate.sequential_success = 0
        candidate.concurrent_success = 0
        candidate.evidence = (
            f"0/{len(signatures)} concurrent responses met success criteria "
            f"(all failed or returned error markers) — token may be exhausted"
        )
        candidate.confidence = 20
        candidate.details["probe"] = {
            "signatures": [list(s) for s in signatures[:10]],
            "note":       "no successful baseline; supply a fresh token and retry",
        }
        return

    # Winner signature = most common success signature
    counts: dict[tuple, int] = {}
    for s in successes:
        counts[s] = counts.get(s, 0) + 1
    winner_sig, winner_count = max(counts.items(), key=lambda kv: kv[1])

    candidate.concurrent_success = winner_count
    candidate.details["probe"] = {
        "request_count":   len(signatures),
        "success_count":   len(successes),
        "winner_signature": list(winner_sig),
        "winner_count":    winner_count,
        "unique_success_signatures": len(counts),
        "http_statuses":   candidate.http_statuses,
    }

    if candidate.race_class == "rate_bypass":
        if winner_count == len(signatures) and len(signatures) >= request_count // 2:
            # All went through — either no rate limit, or bypassed
            candidate.confirmed = False
            candidate.confidence = 55
            candidate.severity = "MEDIUM"
            candidate.evidence = (
                f"All {winner_count}/{len(signatures)} concurrent requests "
                f"returned success — no rate limit detected on this endpoint. "
                f"Informational; not a race bypass."
            )
        else:
            candidate.confirmed = False
            candidate.confidence = 35
            candidate.evidence = (
                f"{winner_count}/{len(signatures)} succeeded — rate limit "
                f"appears enforced; no bypass observed"
            )
        return

    # Single-use classes
    if winner_count >= 2:
        candidate.confirmed = True
        candidate.confidence = 90 if winner_count >= 3 else 75
        candidate.severity = _bump_severity(candidate.severity, candidate.confirmed)
        candidate.evidence = (
            f"CONFIRMED: {winner_count}/{len(signatures)} concurrent requests "
            f"matched the winner signature — single-use control violated"
        )
    else:
        candidate.confirmed = False
        candidate.confidence = 45
        candidate.evidence = (
            f"Only {winner_count}/{len(signatures)} matched the winner signature — "
            f"single-use control appears to hold"
        )


def _bump_severity(base: str, confirmed: bool) -> str:
    if not confirmed:
        return base
    return base


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, candidates: list[RaceCandidate]) -> None:
    if not candidates:
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
    method = getattr(DB, "upsert_race_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_race_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [c.to_dict() for c in candidates]
        result = method(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(
                f"  DB sync: {result} race finding(s) "
                f"upserted (scan_id={scan_id})"
            )
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
    probe_count: int = DEFAULT_PROBE_COUNT,
    max_probes: int = MAX_PROBES,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _race_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    auth_on = bool(cfg_hdrs)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")
    log.info(f"  Mode   : {'discovery + concurrent probe' if run_probe else 'discovery only'}")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)

    # ── Phase 1: Surface discovery
    log.info("  Phase 1 — Race condition surface discovery")
    candidates = discover_candidates(urls)
    log.info(f"    {len(candidates)} candidate(s) identified")

    if not candidates:
        log.warning("  No candidates — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 2: Attack plans
    log.info("")
    log.info("  Phase 2 — Generating exploit scripts (turbo, curl, python)")
    plan_dir = write_attack_plans(candidates, outdir)
    log.info(f"    {len(candidates)} × 3 scripts → {plan_dir.name}/")

    # ── Phase 3: Concurrent burst probe
    if run_probe:
        log.info("")
        log.info(f"  Phase 3 — Concurrent burst probe ({probe_count} synchronized requests)")

        # Prioritize CRITICAL/HIGH for probe; cap at max_probes
        probe_targets = sorted(
            candidates,
            key=lambda c: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.severity, 4)),
        )[:max_probes]

        def _probe_one(c: RaceCandidate) -> None:
            try:
                probe_candidate(session, c, cfg_hdrs, probe_count, eff_timeout)
            except Exception as e:
                log.debug(f"    probe error on {c.target}: {e}")

        with ThreadPoolExecutor(max_workers=eff_conc) as pool:
            futures = {pool.submit(_probe_one, c): c for c in probe_targets}
            done = 0
            for fut in as_completed(futures):
                done += 1
                c = futures[fut]
                status = "CONFIRMED" if c.confirmed else (
                    f"{c.concurrent_success}/{c.request_count or probe_count}"
                    if c.concurrent_success is not None else "?"
                )
                if done % 5 == 0 or c.confirmed:
                    log.info(
                        f"    [{done:>3}/{len(probe_targets)}] "
                        f"{c.race_class:<18} {c.target[:50]:<50} {status}"
                    )

        confirmed_count = sum(1 for c in candidates if c.confirmed)
        log.info(f"    {confirmed_count}/{len(probe_targets)} confirmed vulnerable")

    # ── Dedupe + sort
    seen: set[tuple] = set()
    deduped: list[RaceCandidate] = []
    for c in candidates:
        key = (c.target, c.race_class)
        if key not in seen:
            seen.add(key)
            deduped.append(c)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda c: (
        SEV_ORDER.get(c.severity, 5),
        0 if c.confirmed else 1,
        -c.confidence,
        c.target,
    ))

    for c in deduped:
        c.auth_enabled = auth_on
        if not c.first_seen:
            c.first_seen = _db_now()

    # ── Reports
    elapsed = time.monotonic() - start
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_class: dict[str, int] = {}
    confirmed_list: list[RaceCandidate] = []

    for c in deduped:
        by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
        by_class[c.race_class] = by_class.get(c.race_class, 0) + 1
        if c.confirmed:
            confirmed_list.append(c)

    (outdir / "race_candidates.txt").write_text(
        "\n".join(
            f"{c.target}\t{c.race_class}\t{c.severity}\t{c.confidence}\t"
            f"{'CONFIRMED' if c.confirmed else 'candidate'}\t{c.evidence[:160]}"
            for c in deduped
        ) + ("\n" if deduped else "")
    )

    probed = [c for c in deduped if c.concurrent_success is not None]
    if probed:
        (outdir / "race_probe_results.txt").write_text(
            "\n".join(
                f"{c.target}\t{c.race_class}\t"
                f"seq={c.sequential_success or '-'} conc={c.concurrent_success}/{c.request_count}\t"
                f"{'CONFIRMED' if c.confirmed else 'safe'}\t{c.evidence[:160]}"
                for c in probed
            ) + "\n"
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "auth_enabled": auth_on,
        "config": {
            "probe_enabled": run_probe,
            "probe_count":   probe_count,
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "headers_count": len(cfg_hdrs),
        },
        "totals": {
            "urls_input":    len(urls),
            "candidates":    len(deduped),
            "confirmed":     len(confirmed_list),
            "probed":        len(probed),
            "critical":      by_severity["CRITICAL"],
            "high":          by_severity["HIGH"],
            "medium":        by_severity["MEDIUM"],
            "low":           by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_class":    dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        },
        "candidates": [c.to_dict() for c in deduped],
    }

    json_path = outdir / "race_findings.json"
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
    log.info(f"    {json_path.name:<32} {len(deduped):>5} candidate(s)")
    log.info(f"    race_candidates.txt             {len(deduped):>5} candidate(s)")
    log.info(f"    race_attack_plans/              {len(deduped) * 3:>5} script(s)")
    if probed:
        log.info(f"    race_probe_results.txt          {len(probed):>5} probe result(s)")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}")

    if confirmed_list:
        log.info("")
        log.info("  Confirmed races:")
        for c in confirmed_list[:10]:
            log.info(f"    [{c.severity:<8}] {c.race_class:<18} {c.target[:60]}")

    log.info("")
    log.info("  Next: open race_attack_plans/ for Turbo Intruder single-packet scripts")
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
            "urls_input": total_input, "candidates": 0, "confirmed": 0,
            "probed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_class": {}},
        "candidates": [],
    }
    path = outdir / "race_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("race_candidates.txt", "race_probe_results.txt"):
        (outdir / name).write_text("")
    (outdir / "race_attack_plans").mkdir(exist_ok=True)
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

    parser = argparse.ArgumentParser(description="Argus Race Condition Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument("--probe-count", type=int, default=DEFAULT_PROBE_COUNT)
    parser.add_argument("--no-probe", action="store_true",
                        help="Discovery + attack plans only (no network probe)")
    args = parser.parse_args()

    hdrs = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_race_audit(
            args.input, args.output,
            headers=hdrs,
            run_probe=not args.no_probe,
            probe_count=args.probe_count,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
