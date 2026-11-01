#!/usr/bin/env python3
"""
auditing_tools/race_condition.py — Race Condition Surface Discovery & Attack Planning
═══════════════════════════════════════════════════════════════════════════════

Race conditions are the highest-payout business logic class and the one class
that automated scanners cannot touch. The vulnerable window is measured in
microseconds, and exploitation is probabilistic.

This module does NOT attempt to reliably confirm race conditions through
simple HTTP requests. Instead, it does what automation CAN do reliably:

  1. Discover state-changing surface
       Identify endpoints that perform one-time, limit-controlled, or
       balance-dependent operations. These are the only places TOCTOU
       windows exist.

  2. Classify attack category
       Map each endpoint to its race class:
         • Limit Overrun (coupon reuse, vote inflation, inventory bypass)
         • Double-Spend (balance transfer, gift card, wallet)
         • Multi-Step Bypass (password reset, email change, MFA)
         • Rate-Limit Bypass (login attempts, OTP brute-force)

  3. Generate attack plans
       For each candidate, produce a ready-to-paste Turbo Intruder script
       with the single-packet attack configuration (Engine.BURP2,
       concurrentConnections=1, gate synchronization).

  4. Optional automated probe
       Fire N synchronized requests via a Python threading barrier. This is
       a low-precision probe — it will only catch wide windows — but it can
       surface obvious TOCTOU gaps without manual tooling.

  5. Produce triage-ready evidence
       Every candidate includes the exact request to replay, the
       expected-vs-observed outcome, and the escalation path (ATO,
       financial impact, privilege escalation).

Outputs (into `outdir`):
  • race_findings.json            — full structured report
  • race_candidates.txt           — flat list for triage
  • race_attack_plans/            — one Turbo Intruder script per candidate
  • race_probe_results.txt        — automated probe outcomes (if enabled)

Integration:
  main.py → run_one("race") → run_race_audit(urls_file, outdir)
"""

from __future__ import annotations

import argparse
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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-Race-Auditor/1.0"

# Automated probe settings
DEFAULT_PROBE_COUNT  = 20         # requests per probe
PROBE_TIMEOUT        = 30
MAX_PROBES           = 20         # cap total probes to avoid noise

# ── Race condition endpoint patterns ───────────────────────────────────────
# Each pattern maps a URL/parameter signature to a race class and severity.
RACE_PATTERNS: list[tuple[str, str, str, str]] = [
    # (pattern, race_class, severity, description)
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

# Parameters that signal a state-changing operation
STATE_PARAMS = {
    "action", "operation", "cmd", "do", "execute", "submit",
    "redeem", "apply", "transfer", "withdraw", "vote", "like",
    "confirm", "verify", "reset", "create", "delete", "update",
}

# Body field patterns that signal a race target
BODY_FIELD_PATTERNS = [
    "coupon_code", "voucher", "promo_code", "gift_card",
    "amount", "quantity", "price", "total", "balance",
    "token", "otp", "code", "verification", "invite",
    "vote", "like", "rating",
]

# Turbo Intruder template
TURBO_INTRUDER_TEMPLATE = '''# Turbo Intruder script — generated by Argus
# Target: {target}
# Race class: {race_class}
# Expected outcome: {expected}
# Instructions:
#   1. Paste this into Burp Suite's Turbo Intruder (Extensions > Turbo Intruder)
#   2. Update the raw request below with your captured request
#   3. Adjust REQUEST_COUNT (default 20) for your probe
#   4. Run — inspect responses for multiple success indicators

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2,
    )
    for i in range({request_count}):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
    # Flag multiple 2xx responses — a single-use operation should return
    # exactly one success. Multiple 2xx = limit overrun / double-spend.
    if req.status >= 200 and req.status < 300:
        table.add(req)
        print("[+] SUCCESS: " + str(req.status) + " " + target.endpoint)
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
    description: str = ""
    evidence: str = ""
    method: str = "POST"
    param_name: str = ""
    expected_outcome: str = ""
    escalation: str = ""
    turbo_script: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "race_class":       self.race_class,
            "severity":         self.severity,
            "confidence":       self.confidence,
            "description":      self.description,
            "evidence":         self.evidence[:500],
            "method":           self.method,
            "param_name":       self.param_name,
            "expected_outcome": self.expected_outcome,
            "escalation":       self.escalation,
            "details":          self.details,
        }


@dataclass
class ProbeResult:
    target: str
    request_count: int = 0
    success_count: int = 0
    status_codes: list[int] = field(default_factory=list)
    body_lengths: list[int] = field(default_factory=list)
    likely_vulnerable: bool = False
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "target":            self.target,
            "request_count":     self.request_count,
            "success_count":     self.success_count,
            "status_codes":      self.status_codes,
            "body_lengths":      self.body_lengths,
            "likely_vulnerable": self.likely_vulnerable,
            "evidence":          self.evidence[:500],
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


def _safe_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    data: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url,
            headers=headers or {},
            json=json_body,
            data=data,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body_snippet(resp: requests.Response, max_len: int = 300) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


def _match_race_pattern(url: str, body: str = "") -> list[tuple[str, str, str, str]]:
    """Return all race patterns matching a URL or its parameters."""
    combined = (url + " " + body).lower()
    matches: list[tuple[str, str, str, str]] = []
    for pattern, race_class, severity, description in RACE_PATTERNS:
        if re.search(pattern, combined, re.I):
            matches.append((pattern, race_class, severity, description))
    return matches


def _infer_method(url: str, params: dict) -> str:
    """Infer the HTTP method a state-changing endpoint is likely to use."""
    state_params = set(params.keys()).intersection(STATE_PARAMS)
    if state_params:
        return "POST"
    path = urllib.parse.urlparse(url).path.lower()
    if any(kw in path for kw in ("redeem", "transfer", "create", "update", "delete")):
        return "POST"
    return "GET"


def _infer_param(url: str, params: dict) -> str:
    """Identify the most likely state-changing parameter."""
    for k in params:
        if k.lower() in STATE_PARAMS:
            return k
    for k in params:
        if any(fp in k.lower() for fp in BODY_FIELD_PATTERNS):
            return k
    return next(iter(params), "")


def _escalation_for_class(race_class: str) -> str:
    escalations = {
        "limit_overrun": "Multiple coupon/invite/vote applications → financial loss or reputation inflation",
        "double_spend":  "Multiple successful financial transactions → direct monetary loss",
        "multistep_bypass": "Multiple valid tokens issued → account takeover via parallel workflow",
        "rate_bypass":   "Rate-limit bypass → credential stuffing or OTP brute-force",
    }
    return escalations.get(race_class, "Business logic bypass")


def _expected_outcome(race_class: str) -> str:
    outcomes = {
        "limit_overrun": "Exactly 1 success response; >1 indicates limit overrun",
        "double_spend":  "Balance debited once; >1 success indicates double-spend",
        "multistep_bypass": "Exactly 1 valid token; >1 indicates token race",
        "rate_bypass":   "Rate limit enforced after N requests; bypass if all succeed",
    }
    return outcomes.get(race_class, "Single success expected")


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_candidates(urls: list[str]) -> list[RaceCandidate]:
    """
    Scan URLs for race-condition-prone endpoints.
    """
    candidates: list[RaceCandidate] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        body = ""

        matches = _match_race_pattern(url, body)
        if not matches:
            continue

        method = _infer_method(url, params)
        param = _infer_param(url, params)

        for pattern, race_class, severity, description in matches:
            key = (url, race_class)
            if key in seen:
                continue
            seen.add(key)

            candidates.append(RaceCandidate(
                target=url,
                race_class=race_class,
                severity=severity,
                confidence=65,
                description=description,
                method=method,
                param_name=param,
                expected_outcome=_expected_outcome(race_class),
                escalation=_escalation_for_class(race_class),
                evidence=f"URL pattern matched: {pattern}",
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

def generate_turbo_script(candidate: RaceCandidate, request_count: int = 20) -> str:
    """Generate a Turbo Intruder script for a candidate."""
    return TURBO_INTRUDER_TEMPLATE.format(
        target=candidate.target,
        race_class=candidate.race_class,
        expected=candidate.expected_outcome,
        request_count=request_count,
    )


def write_attack_plans(candidates: list[RaceCandidate], outdir: Path) -> Path:
    """Write one Turbo Intruder script per candidate."""
    plan_dir = outdir / "race_attack_plans"
    plan_dir.mkdir(parents=True, exist_ok=True)

    for i, c in enumerate(candidates, 1):
        safe_name = re.sub(r"[^a-zA-Z0-9]+", "_", c.target)[:60]
        script = generate_turbo_script(c)
        path = plan_dir / f"{i:03d}_{safe_name}.py"
        path.write_text(script)

    return plan_dir


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — AUTOMATED PROBE (LOW PRECISION)
# ═════════════════════════════════════════════════════════════════════════════

class RaceProbe:
    """
    A synchronized burst of N requests to a target endpoint.

    Uses a threading.Barrier to align all threads at the same starting point,
    then releases them simultaneously. This is a low-precision approximation
    of the single-packet attack — it catches wide TOCTOU windows but will
    miss sub-millisecond races. For those, use the generated Turbo Intruder
    scripts with HTTP/2 single-packet mode.
    """

    def __init__(
        self,
        session: requests.Session,
        target: str,
        method: str,
        request_count: int,
        headers: Optional[dict] = None,
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
    ):
        self.session = session
        self.target = target
        self.method = method
        self.request_count = request_count
        self.headers = headers
        self.json_body = json_body
        self.data = data
        self.results: list[dict] = []
        self.lock = threading.Lock()

    def _worker(self, barrier: threading.Barrier) -> None:
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            return

        start = time.monotonic()
        resp = _safe_request(
            self.session, self.method, self.target,
            headers=self.headers,
            json_body=self.json_body,
            data=self.data,
            timeout=PROBE_TIMEOUT,
        )
        elapsed = time.monotonic() - start

        with self.lock:
            if resp:
                self.results.append({
                    "status": resp.status_code,
                    "length": len(resp.content) if resp.content else 0,
                    "elapsed": elapsed,
                    "body": _body_snippet(resp),
                })
            else:
                self.results.append({
                    "status": 0,
                    "length": 0,
                    "elapsed": elapsed,
                    "body": "",
                })

    def run(self) -> ProbeResult:
        barrier = threading.Barrier(self.request_count)
        threads = [
            threading.Thread(target=self._worker, args=(barrier,))
            for _ in range(self.request_count)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = [r["status"] for r in self.results]
        lengths = [r["length"] for r in self.results]
        success_count = sum(1 for s in statuses if 200 <= s < 300)

        # Heuristic: a single-use operation should return exactly 1 success.
        # >1 success = likely race condition.
        likely = success_count > 1

        evidence = ""
        if likely:
            evidence = (
                f"{success_count}/{self.request_count} requests succeeded "
                f"(expected 1). Status codes: {statuses[:10]}"
            )

        return ProbeResult(
            target=self.target,
            request_count=self.request_count,
            success_count=success_count,
            status_codes=statuses,
            body_lengths=lengths,
            likely_vulnerable=likely,
            evidence=evidence,
        )


def probe_candidate(
    session: requests.Session,
    candidate: RaceCandidate,
    request_count: int = DEFAULT_PROBE_COUNT,
    headers: Optional[dict] = None,
) -> Optional[ProbeResult]:
    """Run a synchronized probe against a single candidate."""
    # Build body if the method requires it
    json_body = None
    data = None

    if candidate.method in ("POST", "PUT", "PATCH"):
        # Try to extract a body from the URL's query params as a heuristic
        parsed = urllib.parse.urlparse(candidate.target)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if params:
            json_body = params

    probe = RaceProbe(
        session, candidate.target, candidate.method,
        request_count, headers=headers,
        json_body=json_body, data=data,
    )
    try:
        return probe.run()
    except Exception as e:
        log.debug(f"probe failed on {candidate.target}: {e}")
        return None


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_race_audit(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    run_probe: bool = False,
    probe_count: int = DEFAULT_PROBE_COUNT,
    max_probes: int = MAX_PROBES,
) -> Path:
    """
    Run the race condition audit against every URL in `urls_file`.

    Returns the path to `race_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    if headers:
        log.info("  Auth   : headers supplied (authenticated probing enabled)")
    log.info(f"  Mode   : {'discovery + probe' if run_probe else 'discovery only'}")
    log.info("")

    if not urls:
        log.warning("  No URLs to audit — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    # ── Phase 1: Surface discovery ──────────────────────────────────────────
    log.info("  Phase 1 — Race condition surface discovery")
    candidates = discover_candidates(urls)
    log.info(f"    {len(candidates)} candidate(s) identified")

    if not candidates:
        log.warning("  No race-condition candidates found — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 2: Attack plan generation ─────────────────────────────────────
    log.info("")
    log.info("  Phase 2 — Generating Turbo Intruder attack plans")
    plan_dir = write_attack_plans(candidates, outdir)
    log.info(f"    {len(candidates)} script(s) written to {plan_dir.name}/")

    # ── Phase 3: Automated probe (optional) ─────────────────────────────────
    probe_results: list[ProbeResult] = []
    if run_probe:
        log.info("")
        log.info(f"  Phase 3 — Automated probe ({probe_count} synchronized requests)")
        log.info("    Note: This is LOW PRECISION. Use Turbo Intruder for real confirmation.")

        for i, c in enumerate(candidates[:max_probes], 1):
            log.info(f"    probing {i}/{min(len(candidates), max_probes)}: {c.target[:60]}")
            result = probe_candidate(session, c, probe_count, headers)
            if result:
                probe_results.append(result)
                if result.likely_vulnerable:
                    log.info(f"      ⚠ LIKELY VULNERABLE: {result.evidence[:100]}")

        log.info(f"    {sum(1 for r in probe_results if r.likely_vulnerable)} likely vulnerable")

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[RaceCandidate] = []
    for c in candidates:
        key = (c.target, c.race_class)
        if key not in seen:
            seen.add(key)
            deduped.append(c)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda c: (SEV_ORDER.get(c.severity, 4), -c.confidence, c.target))

    # ── Attach probe results to candidates ──────────────────────────────────
    probe_map = {r.target: r for r in probe_results}
    for c in deduped:
        if c.target in probe_map:
            r = probe_map[c.target]
            if r.likely_vulnerable:
                c.confidence = min(c.confidence + 25, 95)
                c.evidence = r.evidence
                c.details["probe"] = r.to_dict()

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_class: dict[str, int] = {}

    for c in deduped:
        by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
        by_class[c.race_class] = by_class.get(c.race_class, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{c.target}\t{c.race_class}\t{c.severity}\t{c.confidence}\t{c.description[:80]}"
        for c in deduped
    ]
    (outdir / "race_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Probe results flat file
    if probe_results:
        probe_lines = [
            f"{r.target}\t{r.success_count}/{r.request_count} success\t"
            f"{'VULNERABLE' if r.likely_vulnerable else 'safe'}\t{r.evidence[:120]}"
            for r in probe_results
        ]
        (outdir / "race_probe_results.txt").write_text("\n".join(probe_lines) + "\n")

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "probe_enabled": run_probe,
            "probe_count":   probe_count,
            "authenticated": headers is not None,
        },
        "totals": {
            "urls_input":       len(urls),
            "candidates":       len(deduped),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
            "probes_run":       len(probe_results),
            "probe_vulnerable": sum(1 for r in probe_results if r.likely_vulnerable),
        },
        "summary": {
            "by_severity": by_severity,
            "by_class":    dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        },
        "candidates": [c.to_dict() for c in deduped],
        "probe_results": [r.to_dict() for r in probe_results],
    }

    json_path = outdir / "race_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} candidate(s)")
    log.info(f"    race_candidates.txt              {len(deduped):>5} candidate(s)")
    log.info(f"    race_attack_plans/               {len(deduped):>5} Turbo script(s)")
    if probe_results:
        log.info(f"    race_probe_results.txt           {len(probe_results):>5} probe result(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if deduped:
        log.info("")
        log.info("  Top candidates:")
        for c in deduped[:10]:
            log.info(f"    [{c.severity:<8}] {c.race_class:<16} {c.target[:60]}")

    log.info("")
    log.info("  Next step: open race_attack_plans/ and run each script in Turbo Intruder")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": total_input, "candidates": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "probes_run": 0, "probe_vulnerable": 0,
        },
        "summary": {"by_severity": {}, "by_class": {}},
        "candidates": [],
        "probe_results": [],
    }
    path = outdir / "race_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("race_candidates.txt", "race_probe_results.txt"):
        (outdir / name).write_text("")
    (outdir / "race_attack_plans").mkdir(exist_ok=True)
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE TEST
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
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus Race Condition Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument("--probe", action="store_true", help="Run low-precision automated probe")
    parser.add_argument("--probe-count", type=int, default=DEFAULT_PROBE_COUNT, help="Requests per probe")
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_race_audit(
            args.input, args.output,
            headers=headers,
            run_probe=args.probe,
            probe_count=args.probe_count,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
