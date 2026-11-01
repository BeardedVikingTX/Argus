#!/usr/bin/env python3
"""
recon_tools/takeover_check.py — Subdomain Takeover Detection
═══════════════════════════════════════════════════════════════════════════════

Detects subdomain takeover vulnerabilities via dangling CNAMEs.

Three-stage validation:
  1. CNAME chain resolution (dnsx or socket fallback)
  2. Hostname fingerprint matching against 40+ vulnerable services
  3. HTTP body confirmation for services with known "unclaimed" pages

A finding is VULNERABLE only when the HTTP body fingerprint confirms the
unclaimed state. POTENTIAL is returned when the CNAME matches but HTTP
confirmation is not possible.

Fingerprint data is based on the can-i-take-over-xyz project and community
research. The service list is embedded for zero-dependency operation.

Outputs (into `outdir`):
  • takeover_findings.json      — full structured report, primary output
  • takeover_vulnerable.txt     — confirmed vulnerable hosts
  • takeover_potential.txt      — potential (unconfirmed) hosts
  • takeover_cnames.txt         — all resolved CNAME chains

Integration:
  main.py → run_one("takeover") → run_takeover_check(subs_file, outdir)
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
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

log = logging.getLogger("argus.takeover")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DNSX_THREADS        = 50
DNSX_TIMEOUT        = 300
HTTP_THREADS        = 15
HTTP_TIMEOUT        = 12
HTTP_RETRIES        = 2
MAX_INPUT           = 20000


# ═════════════════════════════════════════════════════════════════════════════
#  FINGERPRINT DATABASE
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ServiceFingerprint:
    name: str
    cname_patterns: list[str]          # substring matches against CNAME target
    http_fingerprints: list[str]       # substring matches against HTTP body
    status_code: Optional[int] = 404   # expected status for unclaimed
    vulnerable: bool = True
    cvss: float = 8.0
    notes: str = ""


# Comprehensive fingerprint set — based on can-i-take-over-xyz and community
# research. The `vulnerable` field reflects current status; some services
# have patched takeover, others remain exploitable.
FINGERPRINTS: list[ServiceFingerprint] = [
    ServiceFingerprint(
        "GitHub Pages",
        ["github.io", "github.com"],
        ["There isn't a GitHub Pages site here."],
        404, True, 8.1,
        "Claim by creating a repo with matching CNAME",
    ),
    ServiceFingerprint(
        "Heroku",
        ["herokuapp.com", "herokudns.com"],
        ["No such app", "heroku | no such app"],
        404, True, 8.8,
        "Claim by creating an app with the same name",
    ),
    ServiceFingerprint(
        "AWS S3",
        ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
        ["NoSuchBucket", "The specified bucket does not exist"],
        404, True, 9.3,
        "Claim by creating a bucket with the same name",
    ),
    ServiceFingerprint(
        "AWS CloudFront",
        ["cloudfront.net"],
        ["Bad request.", "ERROR: The request could not be satisfied"],
        403, True, 7.5,
        "Requires distribution deletion + recreation",
    ),
    ServiceFingerprint(
        "AWS Elastic Beanstalk",
        ["elasticbeanstalk.com"],
        ["404 Not Found"],
        404, True, 8.0,
    ),
    ServiceFingerprint(
        "Azure App Service",
        ["azurewebsites.net"],
        ["Error 404 - Web app not found."],
        404, True, 8.5,
    ),
    ServiceFingerprint(
        "Azure Cloud App",
        ["cloudapp.azure.com", "cloudapp.net"],
        ["404 Web Site not found."],
        404, True, 8.0,
    ),
    ServiceFingerprint(
        "Azure Traffic Manager",
        ["trafficmanager.net"],
        ["Not Found", "404"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Netlify",
        ["netlify.app", "netlify.com"],
        ["Not Found - Request ID:", "Page not found"],
        404, True, 8.8,
    ),
    ServiceFingerprint(
        "Vercel",
        ["vercel.app", "now.sh"],
        ["The deployment could not be found on Vercel.", "DEPLOYMENT_NOT_FOUND"],
        404, True, 8.8,
    ),
    ServiceFingerprint(
        "Shopify",
        ["myshopify.com"],
        ["Sorry, this shop is currently unavailable.", "Only one step left!"],
        404, True, 8.0,
    ),
    ServiceFingerprint(
        "Pantheon",
        ["pantheonsite.io"],
        ["The gods are wise, but do not know of the site which you seek."],
        404, True, 8.0,
    ),
    ServiceFingerprint(
        "Tumblr",
        ["tumblr.com"],
        ["Whatever you were looking for doesn't currently exist at this address."],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "WordPress.com",
        ["wordpress.com"],
        ["Do you want to register"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Ghost",
        ["ghost.io"],
        ["The thing you were looking for is no longer here"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Zendesk",
        ["zendesk.com"],
        ["Help Center Closed", "Oops, this help center no longer exists"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Statuspage",
        ["statuspage.io"],
        ["You are being redirected", "Status page not found"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "UserVoice",
        ["uservoice.com"],
        ["This UserVoice subdomain is currently available!"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Bitbucket",
        ["bitbucket.io"],
        ["Repository not found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Fastly",
        ["fastly.net"],
        ["Fastly error: unknown domain"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Surge.sh",
        ["surge.sh"],
        ["project not found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Unbounce",
        ["unbounce.com"],
        ["The requested URL was not found on this server."],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "ngrok",
        ["ngrok.io", "ngrok-free.app"],
        ["Tunnel", "not found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "ReadMe",
        ["readme.io"],
        ["The requested page could not be found."],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Cargo",
        ["cargocollective.com"],
        ["404 Not Found"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Kajabi",
        ["kajabi.com"],
        ["The page you were looking for doesn't exist"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Campaign Monitor",
        ["createsend.com"],
        ["Double check the URL", "404"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Pingdom",
        ["pingdom.com"],
        ["This resource is not available"],
        404, True, 6.0,
    ),
    ServiceFingerprint(
        "Tictail",
        ["tictail.com"],
        ["to target this here", "404"],
        404, True, 6.0,
    ),
    ServiceFingerprint(
        "Strikingly",
        ["strikingly.com"],
        ["page not found"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Agile CRM",
        ["agilecrm.com"],
        ["Sorry, this page is no longer available."],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Short.io",
        ["short.io"],
        ["Link doesn't exist", "404"],
        404, True, 6.0,
    ),
    ServiceFingerprint(
        "SmartJob",
        ["smartjob.io"],
        ["Job board not found"],
        404, True, 6.0,
    ),
    ServiceFingerprint(
        "Help Scout",
        ["helpscoutdocs.com"],
        ["No settings were found for this company"],
        404, True, 7.0,
    ),
    # Additional modern services from community research
    ServiceFingerprint(
        "Fly.io",
        ["fly.dev"],
        ["404", "not found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Render",
        ["render.com"],
        ["Not Found", "404"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "GitLab Pages",
        ["gitlab.io"],
        ["404 Not Found", "The page you're looking for could not be found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Workers.dev",
        ["workers.dev"],
        ["Error 1016", "Origin DNS error"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Pages.dev",
        ["pages.dev"],
        ["404", "Not Found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Replit",
        ["repl.co", "replit.app"],
        ["404", "not found"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Glitch",
        ["glitch.me"],
        ["404", "not found"],
        404, True, 6.5,
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TakeoverFinding:
    subdomain: str
    cname_chain: list[str] = field(default_factory=list)
    service: str = ""
    status: str = "SAFE"          # VULNERABLE | POTENTIAL | SAFE
    cname_match: bool = False
    http_confirmed: bool = False
    http_status: int = 0
    fingerprint: str = ""
    cvss: float = 0.0
    notes: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "subdomain":         self.subdomain,
            "cname_chain":       self.cname_chain,
            "service":           self.service,
            "status":            self.status,
            "cname_match":       self.cname_match,
            "http_confirmed":    self.http_confirmed,
            "http_status":       self.http_status,
            "fingerprint":       self.fingerprint,
            "cvss":              self.cvss,
            "notes":             self.notes,
            "error":             self.error,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — CNAME RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _load_subdomains(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    subs: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
        line = line.split("/")[0].split(":")[0]
        if line:
            subs.add(line)
    return sorted(subs)


def _resolve_cnames_dnsx(subs: list[str], workdir: Path) -> dict[str, list[str]]:
    """
    Run dnsx with -cname -resp to resolve CNAME chains.
    Returns mapping of subdomain → list of CNAME targets.
    """
    if not shutil.which("dnsx"):
        return {}

    input_file = workdir / "takeover_input.txt"
    input_file.write_text("\n".join(subs) + "\n")
    output_file = workdir / "takeover_dnsx.jsonl"

    cmd = [
        "dnsx",
        "-l", str(input_file),
        "-cname",
        "-resp",
        "-json",
        "-silent",
        "-o", str(output_file),
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=DNSX_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning("    dnsx timeout — using partial output")
    except FileNotFoundError:
        return {}

    if not output_file.exists():
        return {}

    cname_map: dict[str, list[str]] = {}
    for line in output_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get("host") or obj.get("input") or "").lower()
        cnames = obj.get("cname") or []
        if isinstance(cnames, str):
            cnames = [cnames]
        if host and cnames:
            cname_map[host] = [str(c) for c in cnames if c]

    return cname_map


def _resolve_cnames_socket(subs: list[str]) -> dict[str, list[str]]:
    """Socket-based CNAME resolution fallback."""
    cname_map: dict[str, list[str]] = {}

    def _worker(host: str) -> tuple[str, list[str]]:
        try:
            socket.setdefaulttimeout(5)
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            chain = [a for a in aliases if a.lower() != host.lower()]
            if canonical.lower() != host.lower() and canonical not in chain:
                chain.append(canonical)
            return host, chain
        except Exception:
            return host, []

    with ThreadPoolExecutor(max_workers=50) as pool:
        for host, chain in pool.map(_worker, subs):
            if chain:
                cname_map[host] = chain

    return cname_map


def resolve_cname_chains(subs: list[str], workdir: Path) -> dict[str, list[str]]:
    """Resolve CNAME chains with dnsx first, socket fallback second."""
    cname_map = _resolve_cnames_dnsx(subs, workdir)
    if not cname_map:
        log.info("    dnsx unavailable or returned no CNAMEs — using socket fallback")
        cname_map = _resolve_cnames_socket(subs)

    log.info(f"    {len(cname_map)} subdomain(s) with CNAME records")
    return cname_map


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — FINGERPRINT MATCHING
# ═════════════════════════════════════════════════════════════════════════════

def _match_fingerprint(cname_chain: list[str]) -> Optional[ServiceFingerprint]:
    """Match the final CNAME target against the fingerprint database."""
    if not cname_chain:
        return None

    # Check the last CNAME in the chain (the actual service)
    target = cname_chain[-1].lower().rstrip(".")

    for fp in FINGERPRINTS:
        for pattern in fp.cname_patterns:
            if pattern.lower() in target:
                return fp

    return None


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 3 — HTTP CONFIRMATION
# ═════════════════════════════════════════════════════════════════════════════

def _confirm_http(subdomain: str, fp: ServiceFingerprint) -> tuple[bool, int, str]:
    """
    Fetch the subdomain over HTTP and check the response body against the
    service's unclaimed-page fingerprint.

    Returns (confirmed, status_code, matched_fingerprint_text).
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; Argus-Takeover/1.0)",
    })
    session.verify = False

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        for attempt in range(HTTP_RETRIES + 1):
            try:
                resp = session.get(
                    url, timeout=HTTP_TIMEOUT,
                    allow_redirects=True, stream=True,
                )
                # Read a bounded chunk of the body
                body = resp.raw.read(65536, decode_content=True).decode(
                    "utf-8", errors="replace"
                )
                resp.close()

                for fingerprint in fp.http_fingerprints:
                    if fingerprint.lower() in body.lower():
                        return True, resp.status_code, fingerprint

                # If status matches the expected unclaimed code but no
                # fingerprint matched, it's still suspicious
                if fp.status_code and resp.status_code == fp.status_code:
                    # Don't confirm — but the caller can treat this as POTENTIAL
                    return False, resp.status_code, ""

                return False, resp.status_code, ""

            except requests.RequestException:
                if attempt < HTTP_RETRIES:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break

    return False, 0, ""


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_takeover_check(
    subs_file: Path,
    outdir: Path,
    *,
    max_input: int = MAX_INPUT,
    http_threads: int = HTTP_THREADS,
) -> Path:
    """
    Check every subdomain in `subs_file` for takeover vulnerability.

    Returns the path to `takeover_findings.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    subs = _load_subdomains(subs_file)
    if len(subs) > max_input:
        log.warning(f"  Capping at {max_input} hosts (input had {len(subs)})")
        subs = subs[:max_input]

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "takeover_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
    log.info("")

    if not subs:
        log.warning("  No subdomains — writing empty report")
        return _write_empty_report(outdir, subs_file, start)

    # ── Stage 1: CNAME resolution ──────────────────────────────────────────
    log.info("  Stage 1 — CNAME chain resolution")
    cname_map = resolve_cname_chains(subs, workdir)

    if not cname_map:
        log.info("  No CNAME records found — nothing to check")
        return _write_empty_report(outdir, subs_file, start, total_input=len(subs))

    # Write the CNAME chain inventory
    cname_lines = []
    for host in sorted(cname_map):
        cname_lines.append(f"{host}\t{' -> '.join(cname_map[host])}")
    (outdir / "takeover_cnames.txt").write_text(
        "\n".join(cname_lines) + "\n"
    )

    # ── Stage 2: Fingerprint matching ──────────────────────────────────────
    log.info("")
    log.info("  Stage 2 — Fingerprint matching")

    candidates: list[tuple[str, list[str], ServiceFingerprint]] = []
    for host, chain in cname_map.items():
        fp = _match_fingerprint(chain)
        if fp:
            candidates.append((host, chain, fp))
            log.info(f"    [{fp.name}] {host}  → {' -> '.join(chain)}")

    log.info(f"    {len(candidates)} candidate(s) matched a known service")

    if not candidates:
        log.info("  No fingerprint matches — writing report")
        return _write_report(
            outdir, subs_file, start, len(subs), cname_map, [],
        )

    # ── Stage 3: HTTP confirmation ─────────────────────────────────────────
    log.info("")
    log.info("  Stage 3 — HTTP body confirmation")

    findings: list[TakeoverFinding] = []

    def _process(candidate):
        host, chain, fp = candidate
        finding = TakeoverFinding(
            subdomain=host,
            cname_chain=chain,
            service=fp.name,
            cname_match=True,
            cvss=fp.cvss,
            notes=fp.notes,
        )
        confirmed, status, matched = _confirm_http(host, fp)
        finding.http_status = status
        finding.http_confirmed = confirmed

        if confirmed:
            finding.status = "VULNERABLE"
            finding.fingerprint = matched
        else:
            finding.status = "POTENTIAL"
            finding.notes = f"{fp.notes} (HTTP confirmation not possible)"

        return finding

    with ThreadPoolExecutor(max_workers=http_threads) as pool:
        for finding in pool.map(_process, candidates):
            findings.append(finding)
            icon = "VULN" if finding.status == "VULNERABLE" else "POT "
            log.info(f"    [{icon}] {finding.subdomain:<40} "
                     f"{finding.service:<20} status={finding.http_status}")

    # ── Build report ────────────────────────────────────────────────────────
    return _write_report(
        outdir, subs_file, start, len(subs), cname_map, findings,
    )


def _write_report(
    outdir: Path,
    input_file: Path,
    start: float,
    total_input: int,
    cname_map: dict[str, list[str]],
    findings: list[TakeoverFinding],
) -> Path:
    """Write the JSON report and flat text outputs."""
    elapsed = time.monotonic() - start

    vulnerable = [f for f in findings if f.status == "VULNERABLE"]
    potential  = [f for f in findings if f.status == "POTENTIAL"]

    # Flat text outputs
    (outdir / "takeover_vulnerable.txt").write_text(
        "\n".join(f.subdomain for f in vulnerable) + ("\n" if vulnerable else "")
    )
    (outdir / "takeover_potential.txt").write_text(
        "\n".join(f.subdomain for f in potential) + ("\n" if potential else "")
    )

    # Summary by service
    by_service: dict[str, int] = {}
    for f in findings:
        by_service[f.service] = by_service.get(f.service, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(input_file),
        "config": {
            "fingerprint_count": len(FINGERPRINTS),
            "http_threads": HTTP_THREADS,
            "http_timeout": HTTP_TIMEOUT,
        },
        "totals": {
            "subdomains_input": total_input,
            "with_cname": len(cname_map),
            "fingerprint_matches": len(findings),
            "vulnerable": len(vulnerable),
            "potential": len(potential),
        },
        "summary": {
            "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in findings],
    }

    json_path = outdir / "takeover_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(findings):>5} finding(s)")
    log.info(f"    takeover_vulnerable.txt      {len(vulnerable):>5} VULNERABLE")
    log.info(f"    takeover_potential.txt       {len(potential):>5} POTENTIAL")
    log.info(f"    takeover_cnames.txt          {len(cname_map):>5} CNAME chain(s)")

    if vulnerable:
        log.info("")
        log.info("  VULNERABLE findings:")
        for f in vulnerable:
            log.info(f"    {f.subdomain:<40} {f.service:<20} "
                     f"CVSS={f.cvss}  fingerprint={f.fingerprint[:60]}")

    if by_service:
        log.info("")
        log.info("  Matches by service:")
        for svc, count in list(by_service.items())[:8]:
            log.info(f"    {svc:<30} {count:>3}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    return _write_report(outdir, input_file, start, total_input, {}, [])


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
    subs = base / "output" / "dns_resolved.txt"
    out = base / "output"
    try:
        run_takeover_check(subs, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
