#!/usr/bin/env python3
"""
recon_tools/cors_check.py — CORS Misconfiguration Scanner
═══════════════════════════════════════════════════════════════════════════════

A production-grade CORS scanner for Argus. Sends a battery of crafted
`Origin` headers against every endpoint and inspects the response for
`Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials`
(ACAC).

The scanner is built around the exploitation reality of CORS:
  • ACAO reflecting an attacker origin + ACAC: true  = CRITICAL
  • `null` origin trusted with credentials          = HIGH
  • Subdomain / prefix / suffix bypass with creds   = HIGH to CRITICAL
  • ACAO: * without credentials                     = INFO (usually intended)
  • ACAO: * with credentials (invalid but seen)     = HIGH

The goal is signal, not volume: every finding is scored, classified, and
written to a structured JSON report for manual triage.

Outputs (into `outdir`):
  • cors_findings.json       — full structured report, primary output
  • cors_critical.txt        — CRITICAL/HIGH findings only, one URL per line
  • cors_all.txt             — every flagged endpoint, one URL per line

Integration:
  main.py → run_one("cors") → run_cors_check(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import shutil
import string
import sys
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

log = logging.getLogger("argus.cors")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 10
DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 2
USER_AGENT           = "Argus-CORS-Scanner/1.0"

# Overall wall-clock ceiling for the entire scan (seconds)
SCAN_HARD_TIMEOUT    = 3600

# Maximum URLs to process in one run — prevents runaway scans
MAX_URLS             = 5000

# If a response body is larger than this, we still inspect headers but
# we don't try to read the whole body into memory.
MAX_BODY_BYTES       = 65536

# ── Severity thresholds ──────────────────────────────────────────────────────
# Scores are additive. The final severity is derived from the total score.
SEV_CRITICAL_SCORE   = 80
SEV_HIGH_SCORE       = 50
SEV_MEDIUM_SCORE     = 30
SEV_LOW_SCORE        = 10


# ═════════════════════════════════════════════════════════════════════════════
#  ORIGIN PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class OriginProbe:
    name: str
    origin: str
    description: str
    weight: int = 0


def _build_probes(target_host: str) -> list[OriginProbe]:
    """
    Build the full battery of Origin probes for a given target host.

    `target_host` should be the bare hostname (e.g. "api.example.com").
    """
    # A random token used to make the attacker origin unmistakable in the
    # response. If the server reflects it, that's a guaranteed reflection.
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    attacker_origin = f"https://evil-{rand}.example"
    attacker_host   = f"evil-{rand}.example"

    probes = [
        # 1. Pure arbitrary reflection — the classic
        OriginProbe(
            "arbitrary_reflection",
            attacker_origin,
            "Server reflects an entirely attacker-controlled origin",
            weight=40,
        ),
        # 2. Null origin — sandboxed iframe / data: URI bypass
        OriginProbe(
            "null_origin",
            "null",
            "Server trusts the 'null' origin (sandboxed iframe, data: URI)",
            weight=40,
        ),
        # 3. Suffix match bypass: target.com.evil.com
        OriginProbe(
            "suffix_bypass",
            f"https://{target_host}.{attacker_host}",
            "Server uses endsWith(target_host) and accepts target.com.evil.com",
            weight=35,
        ),
        # 4. Prefix match bypass: evil-target.com
        OriginProbe(
            "prefix_bypass",
            f"https://{attacker_host}-{target_host}",
            "Server uses startsWith(target_host) and accepts evil-target.com",
            weight=35,
        ),
        # 5. Subdomain trust: attacker.target.com
        OriginProbe(
            "subdomain_trust",
            f"https://{attacker_host}.{target_host}",
            "Server trusts *.target.com and accepts an attacker-controlled subdomain",
            weight=30,
        ),
        # 6. Scheme downgrade: http://target.com on an https endpoint
        OriginProbe(
            "scheme_downgrade",
            f"http://{target_host}",
            "Server accepts an HTTP origin on an HTTPS endpoint",
            weight=25,
        ),
        # 7. Pre-domain injection: https://attacker.com.target.com
        OriginProbe(
            "pre_domain_injection",
            f"https://{attacker_host}.{target_host}",
            "Server naively contains('target.com') and accepts attacker.com.target.com",
            weight=30,
        ),
    ]

    return probes


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CORSFinding:
    url: str
    method: str = "GET"
    probe_name: str = ""
    sent_origin: str = ""
    reflected: bool = False
    acao: str = ""
    acac: bool = False
    acam: str = ""
    acah: str = ""
    status: int = 0
    content_type: str = ""
    score: int = 0
    severity: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "probe": self.probe_name,
            "sent_origin": self.sent_origin,
            "reflected": self.reflected,
            "access_control_allow_origin": self.acao,
            "access_control_allow_credentials": self.acac,
            "access_control_allow_methods": self.acam,
            "access_control_allow_headers": self.acah,
            "status": self.status,
            "content_type": self.content_type,
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "response_snippet": self.response_snippet,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_urls(input_file: Path) -> list[str]:
    """
    Accept live_urls.txt (bare URLs) or live_hosts.txt
    ('URL [status] [title] [tech]').
    """
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    urls: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        urls.add(url.rstrip("/"))

    return sorted(urls)


def _host_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or ""


# ═════════════════════════════════════════════════════════════════════════════
#  REQUEST ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _make_session(cookie: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    if cookie:
        s.headers["Cookie"] = cookie
    s.verify = False
    return s


def _send_probe(
    session: requests.Session,
    url: str,
    probe: OriginProbe,
    timeout: int,
    retries: int,
    method: str = "GET",
) -> Optional[CORSFinding]:
    """
    Send one request with a crafted Origin header and build a finding
    from the response headers.
    """
    headers = {"Origin": probe.origin}

    last_error = None
    for attempt in range(retries + 1):
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
            break
        except requests.RequestException as e:
            last_error = e
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            log.debug(f"    probe failed: {method} {url} origin={probe.name}: {e}")
            return None

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac_raw = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
    acac = acac_raw == "true"
    acam = resp.headers.get("Access-Control-Allow-Methods", "")
    acah = resp.headers.get("Access-Control-Allow-Headers", "")

    reflected = bool(acao) and (
        acao == probe.origin
        or probe.origin in acao
        or (probe.origin == "null" and acao == "null")
    )

    # Snippet of the body — only if it's small enough to be safe
    body_snippet = ""
    try:
        content_length = int(resp.headers.get("Content-Length", "0") or 0)
    except ValueError:
        content_length = 0
    if 0 < content_length <= MAX_BODY_BYTES:
        try:
            body_snippet = resp.raw.read(MAX_BODY_BYTES, decode_content=True).decode(
                "utf-8", errors="replace"
            )[:500]
        except Exception:
            pass

    resp.close()

    finding = CORSFinding(
        url=url,
        method=method,
        probe_name=probe.name,
        sent_origin=probe.origin,
        reflected=reflected,
        acao=acao,
        acac=acac,
        acam=acam,
        acah=acah,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", ""),
        response_snippet=body_snippet,
    )

    _score_finding(finding, probe)
    return finding


# ═════════════════════════════════════════════════════════════════════════════
#  SCORING & CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _score_finding(f: CORSFinding, probe: OriginProbe) -> None:
    """
    Assign a score and severity to a finding based on the response headers.

    The exploitation reality:
      • Reflected origin + ACAC:true  = critical (credentialed cross-origin read)
      • Null origin + ACAC:true       = high (sandboxed iframe bypass)
      • Wildcard ACAO + ACAC:true     = high (invalid but some servers send it)
      • Reflected origin without ACAC = medium (exploitable with token auth)
      • ACAO:* without ACAC           = informational (usually intended public CORS)
    """
    score = 0
    reasons: list[str] = []

    # ── Reflected origin ────────────────────────────────────────────────────
    if f.reflected:
        reasons.append("origin_reflected")
        score += probe.weight

        # Null origin is its own category
        if probe.name == "null_origin":
            reasons.append("null_origin_trusted")
            score += 10

        # Prefix / suffix / subdomain / pre-domain bypasses are particularly
        # dangerous because they often chain with subdomain takeover.
        if probe.name in (
            "suffix_bypass", "prefix_bypass",
            "subdomain_trust", "pre_domain_injection",
        ):
            reasons.append("regex_bypass")
            score += 15

    # ── Credentialed reflection is the money case ───────────────────────────
    if f.reflected and f.acac:
        reasons.append("credentials_allowed")
        score += 50

    # ── Wildcard with credentials (invalid spec, but seen in the wild) ──────
    if f.acao == "*" and f.acac:
        reasons.append("wildcard_with_credentials")
        score += 40

    # ── Scheme downgrade ────────────────────────────────────────────────────
    if probe.name == "scheme_downgrade" and f.reflected:
        reasons.append("scheme_downgrade")
        score += 10

    # ── Informational wildcard ──────────────────────────────────────────────
    if f.acao == "*" and not f.acac:
        reasons.append("wildcard_without_credentials")
        score += 5

    # ── No CORS headers at all — nothing to report ─────────────────────────
    if not f.acao and not f.acac:
        f.score = 0
        f.severity = "INFO"
        f.reasons = []
        return

    f.score = min(score, 100)

    # ── Derive severity from score ──────────────────────────────────────────
    if f.score >= SEV_CRITICAL_SCORE:
        f.severity = "CRITICAL"
    elif f.score >= SEV_HIGH_SCORE:
        f.severity = "HIGH"
    elif f.score >= SEV_MEDIUM_SCORE:
        f.severity = "MEDIUM"
    elif f.score >= SEV_LOW_SCORE:
        f.severity = "LOW"
    else:
        f.severity = "INFO"

    f.reasons = reasons


# ═════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT (OPTIONS) PROBE
# ═════════════════════════════════════════════════════════════════════════════

def _send_preflight(
    session: requests.Session,
    url: str,
    origin: str,
    timeout: int,
) -> Optional[CORSFinding]:
    """
    Send an OPTIONS preflight request with an attacker origin.
    Some servers only reveal their CORS policy on preflight.
    """
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    try:
        resp = session.options(
            url, headers=headers, timeout=timeout, allow_redirects=False
        )
    except requests.RequestException:
        return None

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    acam = resp.headers.get("Access-Control-Allow-Methods", "")
    acah = resp.headers.get("Access-Control-Allow-Headers", "")

    reflected = bool(acao) and (acao == origin or origin in acao)

    if not reflected and not (acao == "*" and acac):
        return None

    finding = CORSFinding(
        url=url,
        method="OPTIONS",
        probe_name="preflight",
        sent_origin=origin,
        reflected=reflected,
        acao=acao,
        acac=acac,
        acam=acam,
        acah=acah,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", ""),
    )

    score = 0
    reasons = ["preflight_reflection"]
    if reflected:
        score += 30
    if acac:
        score += 40
        reasons.append("credentials_allowed")
    if acam:
        score += 5
        reasons.append(f"methods:{acam[:60]}")

    finding.score = min(score, 100)
    if finding.score >= SEV_CRITICAL_SCORE:
        finding.severity = "CRITICAL"
    elif finding.score >= SEV_HIGH_SCORE:
        finding.severity = "HIGH"
    elif finding.score >= SEV_MEDIUM_SCORE:
        finding.severity = "MEDIUM"
    else:
        finding.severity = "LOW"
    finding.reasons = reasons

    return finding


# ═════════════════════════════════════════════════════════════════════════════
#  PER-URL SCAN
# ═════════════════════════════════════════════════════════════════════════════

def _scan_url(
    url: str,
    cookie: Optional[str],
    timeout: int,
    retries: int,
) -> list[CORSFinding]:
    """Run the full probe battery against one URL."""
    host = _host_from_url(url)
    if not host:
        return []

    probes = _build_probes(host)
    session = _make_session(cookie)
    findings: list[CORSFinding] = []

    try:
        # ── Main GET probes ─────────────────────────────────────────────────
        for probe in probes:
            f = _send_probe(session, url, probe, timeout, retries, method="GET")
            if f and f.severity != "INFO":
                findings.append(f)

        # ── Preflight OPTIONS probe (only if we haven't already found
        #    something critical — preflight is noisy and slower) ─────────────
        if not any(x.severity in ("CRITICAL", "HIGH") for x in findings):
            attacker = probes[0].origin  # arbitrary reflection origin
            pf = _send_preflight(session, url, attacker, timeout)
            if pf and pf.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                findings.append(pf)

    finally:
        session.close()

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_cors_check(
    live_urls_file: Path,
    outdir: Path,
    *,
    cookie: Optional[str] = None,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    max_urls: int = MAX_URLS,
) -> Path:
    """
    Scan every URL in `live_urls_file` for CORS misconfigurations.

    Returns the path to `cors_findings.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    urls = _extract_urls(live_urls_file)
    if not urls:
        log.warning("  No URLs to scan — writing empty report")
        report = _empty_report(live_urls_file, start)
        path = outdir / "cors_findings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
        return path

    if len(urls) > max_urls:
        log.warning(f"  Capping scan at {max_urls} URL(s) (input had {len(urls)})")
        urls = urls[:max_urls]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    if cookie:
        log.info("  Auth   : cookie supplied (credentialed probes enabled)")
    log.info(f"  Threads: {threads}  ·  timeout: {timeout}s  ·  retries: {retries}")
    log.info("")

    # ── Scan in parallel ────────────────────────────────────────────────────
    all_findings: list[CORSFinding] = []
    scanned = 0
    errored = 0

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(_scan_url, url, cookie, timeout, retries): url
            for url in urls
        }

        for future in as_completed(future_map):
            url = future_map[future]
            scanned += 1
            try:
                findings = future.result()
            except Exception as e:
                log.debug(f"    scan error on {url}: {e}")
                errored += 1
                continue

            if findings:
                all_findings.extend(findings)
                crit = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
                if crit:
                    log.info(
                        f"    [{crit[0].severity}] {url}  "
                        f"({crit[0].probe_name}, score={crit[0].score})"
                    )

            # Light progress indicator every 25 URLs
            if scanned % 25 == 0:
                log.info(f"    ... scanned {scanned}/{len(urls)}")

    # ── Deduplicate: keep the highest-severity finding per URL ──────────────
    best_per_url: dict[str, CORSFinding] = {}
    for f in all_findings:
        key = f.url.rstrip("/")
        existing = best_per_url.get(key)
        if not existing or f.score > existing.score:
            best_per_url[key] = f

    final = sorted(best_per_url.values(), key=lambda f: (-f.score, f.url))

    # ── Write outputs ───────────────────────────────────────────────────────
    critical_urls = [f.url for f in final if f.severity in ("CRITICAL", "HIGH")]
    all_urls_flagged = [f.url for f in final]

    crit_path = outdir / "cors_critical.txt"
    crit_path.write_text("\n".join(critical_urls) + ("\n" if critical_urls else ""))

    all_path = outdir / "cors_all.txt"
    all_path.write_text("\n".join(all_urls_flagged) + ("\n" if all_urls_flagged else ""))

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in final:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "scanned": scanned,
        "errored": errored,
        "config": {
            "threads": threads,
            "timeout": timeout,
            "retries": retries,
            "authenticated": cookie is not None,
        },
        "totals": {
            "urls_scanned": scanned,
            "findings": len(final),
            "critical": by_sev["CRITICAL"],
            "high": by_sev["HIGH"],
            "medium": by_sev["MEDIUM"],
            "low": by_sev["LOW"],
        },
        "by_severity": by_sev,
        "findings": [f.to_dict() for f in final],
    }

    json_path = outdir / "cors_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<22} {len(final):>4} finding(s)")
    log.info(f"    {crit_path.name:<22} {len(critical_urls):>4} URL(s)")
    log.info(f"    {all_path.name:<22} {len(all_urls_flagged):>4} URL(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_sev['CRITICAL']}  "
        f"HIGH={by_sev['HIGH']}  "
        f"MEDIUM={by_sev['MEDIUM']}  "
        f"LOW={by_sev['LOW']}"
    )

    if critical_urls:
        log.info("")
        log.info("  Critical / high findings:")
        for f in final:
            if f.severity in ("CRITICAL", "HIGH"):
                reasons = ",".join(f.reasons[:4])
                log.info(
                    f"    [{f.severity}] {f.url:<60} "
                    f"probe={f.probe_name:<22} score={f.score:>3}  [{reasons}]"
                )

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _empty_report(input_file: Path, start: float) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "scanned": 0,
        "errored": 0,
        "config": {},
        "totals": {"urls_scanned": 0, "findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "findings": [],
    }


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
    live_urls = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus CORS scanner (standalone)")
    parser.add_argument("--cookie", help="Cookie header for authenticated probes")
    args = parser.parse_args()

    try:
        run_cors_check(live_urls, out, cookie=args.cookie)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
