#!/usr/bin/env python3
"""
recon_tools/takeover_check.py — Subdomain Takeover Detection
═══════════════════════════════════════════════════════════════════════════════

Detects subdomain takeover vulnerabilities via dangling CNAMEs.

Three-stage validation with multi-signal confirmation:
  1. CNAME chain resolution — full chain traversal, not just last hop
  2. Fingerprint matching — scans EVERY hop in the chain, not just the leaf
  3. HTTP body confirmation — service-specific unclaimed-page fingerprints

Additional signals (new in v2):
  • Dangling detection — CNAME chain exists but terminal host has no A/AAAA
    record. This is the single strongest indicator of a dormant takeover:
    the resource is gone from the backend, but the DNS pointer still exists.
  • Shared-CNAME detection — 2+ subdomains pointing to the same terminal
    target indicates a wildcard DNS misconfiguration (someone may have
    removed a wildcard record without cleaning up individual CNAMEs).
  • Passive mode — DNS-only, no HTTP. Fastest way to surface dangling
    CNAMEs at scale before spending HTTP budget on confirmation.

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every HTTP confirmation request.

Config integration (config.py):
  • MODULE_RATE_LIMITS["takeover"]["concurrency"]  → HTTP thread pool size
  • ACTIVE_HEADERS + AUTH_HEADERS                   → merged, applied to HTTP
  • AUTH_COOKIES                                    → applied to requests session
  • SYNC_TO_DB, BRIDGE_*                            → remote database sync

Outputs (into `outdir`):
  • takeover_findings.json      — full structured report
  • takeover_vulnerable.txt     — confirmed vulnerable hosts
  • takeover_potential.txt      — potential (unconfirmed) hosts
  • takeover_cnames.txt         — all resolved CNAME chains

Remote DB (if scan_id is provided):
  • takeover_findings table     — one row per (scan_id, subdomain)

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


def _takeover_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("takeover", {})
    threads = entry.get("concurrency", 15)
    rate = entry.get("rate_limit", 100)
    if not isinstance(threads, int) or threads < 1:
        threads = 15
    if not isinstance(rate, int) or rate < 0:
        rate = 100
    return {"threads": threads, "rate_limit": rate}


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DNSX_THREADS    = 50
DNSX_TIMEOUT    = 300
HTTP_THREADS    = 15
HTTP_TIMEOUT    = 12
HTTP_RETRIES    = 2
MAX_INPUT       = 20000
MAX_HTTP_BODY   = 131072   # 128KB — some unclaimed pages are large


# ═════════════════════════════════════════════════════════════════════════════
#  FINGERPRINT DATABASE (expanded)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ServiceFingerprint:
    name: str
    cname_patterns: list[str]
    http_fingerprints: list[str]
    status_code: Optional[int] = 404
    vulnerable: bool = True
    cvss: float = 8.0
    notes: str = ""


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
        "Azure Blob Storage",
        ["blob.core.windows.net"],
        ["BlobNotFound", "The specified blob does not exist"],
        404, True, 8.5,
        "Claim by creating a blob storage account with matching name",
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
        ["myshopify.com", "shopifypreview.com"],
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
        "Help Scout",
        ["helpscoutdocs.com"],
        ["No settings were found for this company"],
        404, True, 7.0,
    ),
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
        "Cloudflare Workers",
        ["workers.dev"],
        ["Error 1016", "Origin DNS error"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Cloudflare Pages",
        ["pages.dev"],
        ["404", "Not Found"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Cloudflared Tunnel",
        ["trycloudflare.com", "cloudflare.net"],
        ["Argo Tunnel error", "404"],
        404, True, 7.5,
        "Ephemeral tunnels — takeover requires intercepting the tunnel URL",
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
    # ── New additions from community research ───────────────────────────────
    ServiceFingerprint(
        "Firebase",
        ["firebaseapp.com", "web.app"],
        ["Site Not Found", "Firebase Hosting Site Not Found"],
        404, True, 8.0,
        "Claim by creating a Firebase project with matching site name",
    ),
    ServiceFingerprint(
        "DigitalOcean Spaces",
        ["digitaloceanspaces.com"],
        ["NoSuchBucket", "The specified bucket does not exist"],
        404, True, 8.5,
        "Claim by creating a Spaces bucket with the same name",
    ),
    ServiceFingerprint(
        "Google Cloud Storage",
        ["storage.googleapis.com"],
        ["NoSuchBucket", "The specified bucket does not exist"],
        404, True, 8.5,
        "Claim by creating a GCS bucket with the same name",
    ),
    ServiceFingerprint(
        "Webflow",
        ["webflow.io"],
        ["This site is not published", "404"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Squarespace",
        ["squarespace.com"],
        ["No Such Domain", "404"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "HubSpot",
        ["hubspotpagebuilder.com", "hubspot.net"],
        ["Domain not found", "404"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Salesforce Sites",
        ["salesforce-sites.com", "force.com"],
        ["Invalid URL", "404"],
        404, True, 7.5,
    ),
    ServiceFingerprint(
        "Airtable",
        ["airtableblocks.com"],
        ["404", "not found"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Notion Sites",
        ["notion.site"],
        ["404", "not found"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Retool",
        ["retool.com"],
        ["Not Found", "404"],
        404, True, 7.0,
    ),
    ServiceFingerprint(
        "Wix",
        ["wixsite.com", "wix.com"],
        ["404", "not found"],
        404, True, 6.5,
    ),
    ServiceFingerprint(
        "Weebly",
        ["weebly.com"],
        ["404", "not found"],
        404, True, 6.0,
    ),
    ServiceFingerprint(
        "SendGrid",
        ["sendgrid.net"],
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
    status: str = "SAFE"
    cname_match: bool = False
    http_confirmed: bool = False
    http_status: int = 0
    fingerprint: str = ""
    cvss: float = 0.0
    severity_score: int = 0
    dangling: bool = False
    shared_cname: bool = False
    notes: str = ""
    error: str = ""
    auth_enabled: bool = False
    first_seen: str = ""

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
            "severity_score":    self.severity_score,
            "dangling":          self.dangling,
            "shared_cname":      self.shared_cname,
            "notes":             self.notes,
            "error":             self.error,
            "auth_enabled":      self.auth_enabled,
            "first_seen":        self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
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


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — CNAME RESOLUTION (full chain)
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_cnames_dnsx(subs: list[str], workdir: Path) -> dict[str, list[str]]:
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
        subprocess.run(cmd, capture_output=True, text=True, timeout=DNSX_TIMEOUT)
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
            cname_map[host] = [str(c).lower().rstrip(".") for c in cnames if c]

    return cname_map


def _resolve_cnames_socket(subs: list[str]) -> dict[str, list[str]]:
    cname_map: dict[str, list[str]] = {}

    def _worker(host: str) -> tuple[str, list[str]]:
        try:
            socket.setdefaulttimeout(5)
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            chain = [a.lower() for a in aliases if a.lower() != host.lower()]
            if canonical.lower() != host.lower() and canonical.lower() not in chain:
                chain.append(canonical.lower())
            return host, chain
        except Exception:
            return host, []

    with ThreadPoolExecutor(max_workers=50) as pool:
        for host, chain in pool.map(_worker, subs):
            if chain:
                cname_map[host] = chain

    return cname_map


def _resolve_terminal_a(terminal: str) -> tuple[bool, list[str]]:
    """
    Check if a terminal CNAME target has an A/AAAA record.
    Returns (resolves, ips).

    When this returns False but the CNAME exists, the subdomain is DANGLING —
    the strongest signal of a takeover candidate. The DNS pointer still
    exists, but the backend resource is gone.
    """
    try:
        socket.setdefaulttimeout(5)
        _, _, ips = socket.gethostbyname_ex(terminal)
        return bool(ips), list(ips)
    except Exception:
        return False, []


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — FINGERPRINT MATCHING (scans every hop)
# ═════════════════════════════════════════════════════════════════════════════

def _match_fingerprint_chain(chain: list[str]) -> Optional[tuple[ServiceFingerprint, str]]:
    """
    Scan EVERY hop in the chain for a fingerprint match, not just the last.
    Returns (fingerprint, matched_cname) or None.
    """
    if not chain:
        return None

    for hop in chain:
        hop_lower = hop.lower().rstrip(".")
        for fp in FINGERPRINTS:
            for pattern in fp.cname_patterns:
                if pattern.lower() in hop_lower:
                    return fp, hop_lower

    return None


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 3 — HTTP CONFIRMATION
# ═════════════════════════════════════════════════════════════════════════════

def _confirm_http(
    subdomain: str, fp: ServiceFingerprint, auth_on: bool,
) -> tuple[bool, int, str, str]:
    """
    Try HTTPS → HTTP → HTTPS-with-www to confirm the unclaimed state.

    Returns (confirmed, status_code, matched_fingerprint_text, final_url).
    """
    session = requests.Session()
    hdrs = _target_headers()
    if hdrs:
        session.headers.update(hdrs)
    cookies = _auth_cookies()
    if cookies:
        for k, v in cookies.items():
            session.cookies.set(k, v)
    session.verify = False

    if "User-Agent" not in session.headers:
        session.headers["User-Agent"] = "Mozilla/5.0 (compatible; Argus-Takeover/2.0)"

    url_attempts = [
        f"https://{subdomain}",
        f"http://{subdomain}",
    ]
    if not subdomain.startswith("www."):
        url_attempts.append(f"https://www.{subdomain}")

    for url in url_attempts:
        for attempt in range(HTTP_RETRIES + 1):
            try:
                resp = session.get(
                    url, timeout=HTTP_TIMEOUT,
                    allow_redirects=True, stream=True,
                )
                body = resp.raw.read(MAX_HTTP_BODY, decode_content=True).decode(
                    "utf-8", errors="replace"
                )
                resp.close()

                for fingerprint in fp.http_fingerprints:
                    if fingerprint.lower() in body.lower():
                        return True, resp.status_code, fingerprint, url

                # Wrong scheme — try next
                if resp.status_code >= 500:
                    break

                # Definitive 404 without match — check next URL variant
                return False, resp.status_code, "", url

            except requests.RequestException:
                if attempt < HTTP_RETRIES:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break

    return False, 0, "", ""


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _score_severity(f: TakeoverFinding) -> None:
    """Compute severity_score 0-100 from the accumulated signals."""
    score = 0

    if f.status == "VULNERABLE":
        score += 60
    elif f.status == "POTENTIAL":
        score += 30

    if f.cname_match:
        score += 10

    if f.http_confirmed:
        score += 15

    if f.dangling:
        score += 20

    if f.shared_cname:
        score += 5

    if f.cvss:
        score += int(f.cvss * 3)

    f.severity_score = min(100, score)


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[TakeoverFinding]) -> None:
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

    try:
        payloads = [f.to_dict() for f in findings]
        result = DB.upsert_takeover_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} takeover finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_takeover_check(
    subs_file: Path,
    outdir: Path,
    *,
    max_input: int = MAX_INPUT,
    http_threads: Optional[int] = None,
    headers: Optional[dict] = None,
    passive_only: bool = False,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Check every subdomain in `subs_file` for takeover vulnerability.

    If `passive_only` is True, skip HTTP confirmation — only DNS analysis
    runs. This surfaces dangling CNAMEs at scale in a fraction of the time,
    and lets you triage before spending HTTP budget.

    Returns the path to `takeover_findings.json`.
    """
    start = time.monotonic()

    settings = _takeover_settings()
    eff_threads = http_threads if http_threads is not None else settings["threads"]

    subs = _load_subdomains(subs_file)
    if len(subs) > max_input:
        log.warning(f"  Capping at {max_input} hosts (input had {len(subs)})")
        subs = subs[:max_input]

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "takeover_work"
    workdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()

    log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
    log.info(f"  Config : threads={eff_threads}  passive_only={passive_only}")
    log.info(f"           source: MODULE_RATE_LIMITS['takeover']")
    if passive_only:
        log.info(f"  Mode   : PASSIVE (DNS-only, no HTTP confirmation)")
    else:
        log.info(f"  Mode   : ACTIVE (DNS + HTTP confirmation)")
    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to HTTP confirmation")
    if auth_on and not passive_only:
        log.info(f"  Auth   : ENABLED (request.txt)")
    log.info("")

    if not subs:
        log.warning("  No subdomains — writing empty report")
        return _write_empty_report(outdir, subs_file, start)

    # ── Stage 1: CNAME resolution ──────────────────────────────────────────
    log.info("  Stage 1 — CNAME chain resolution")
    cname_map = _resolve_cnames_dnsx(subs, workdir)
    if not cname_map:
        log.info("    dnsx unavailable or returned no CNAMEs — using socket fallback")
        cname_map = _resolve_cnames_socket(subs)

    if not cname_map:
        log.info("  No CNAME records found — writing empty report")
        return _write_empty_report(outdir, subs_file, start, total_input=len(subs))

    log.info(f"    {len(cname_map)} subdomain(s) with CNAME records")

    # Write CNAME inventory
    cname_lines = []
    for host in sorted(cname_map):
        cname_lines.append(f"{host}\t{' -> '.join(cname_map[host])}")
    (outdir / "takeover_cnames.txt").write_text("\n".join(cname_lines) + "\n")

    # ── Dangling detection (per terminal CNAME) ────────────────────────────
    log.info("")
    log.info("  Dangling detection")

    terminal_targets: dict[str, str] = {}
    for host, chain in cname_map.items():
        if chain:
            terminal_targets[host] = chain[-1]

    # Deduplicate terminals — one DNS check per unique terminal
    unique_terminals = sorted(set(terminal_targets.values()))
    terminal_resolves: dict[str, bool] = {}

    def _check_terminal(terminal: str) -> tuple[str, bool]:
        resolves, _ = _resolve_terminal_a(terminal)
        return terminal, resolves

    if unique_terminals:
        with ThreadPoolExecutor(max_workers=min(20, len(unique_terminals))) as pool:
            for terminal, resolves in pool.map(_check_terminal, unique_terminals):
                terminal_resolves[terminal] = resolves

    dangling_terminals = {t for t, r in terminal_resolves.items() if not r}
    dangling_hosts = {
        host for host, terminal in terminal_targets.items()
        if terminal in dangling_terminals
    }

    if dangling_hosts:
        log.info(f"    {len(dangling_hosts)} DANGLING subdomain(s) "
                 f"({len(dangling_terminals)} unique terminal(s) with no A record)")
        for host in sorted(dangling_hosts)[:10]:
            log.info(f"      {host}  → {terminal_targets[host]}  (NO A RECORD)")
    else:
        log.info("    No dangling CNAMEs detected")

    # ── Shared CNAME detection ─────────────────────────────────────────────
    log.info("")
    log.info("  Shared CNAME detection")

    by_terminal: dict[str, list[str]] = {}
    for host, terminal in terminal_targets.items():
        by_terminal.setdefault(terminal, []).append(host)

    shared_terminals = {t for t, hosts in by_terminal.items() if len(hosts) >= 2}
    shared_hosts = set()
    for terminal in shared_terminals:
        shared_hosts.update(by_terminal[terminal])

    if shared_hosts:
        log.info(f"    {len(shared_hosts)} subdomain(s) share a terminal CNAME")
        for terminal in sorted(shared_terminals)[:5]:
            hosts = by_terminal[terminal]
            log.info(f"      {terminal}  ←  {len(hosts)} subdomain(s)")
    else:
        log.info("    No shared CNAME targets")

    # ── Stage 2: Fingerprint matching ──────────────────────────────────────
    log.info("")
    log.info("  Stage 2 — Fingerprint matching")

    candidates: list[tuple[str, list[str], ServiceFingerprint]] = []
    for host, chain in cname_map.items():
        match = _match_fingerprint_chain(chain)
        if match:
            fp, matched_hop = match
            candidates.append((host, chain, fp))
            log.info(f"    [{fp.name}] {host}  → {' -> '.join(chain)}")

    log.info(f"    {len(candidates)} candidate(s) matched a known service")

    if not candidates and not dangling_hosts:
        log.info("  No fingerprint matches and no dangling CNAMEs — writing report")
        return _write_report(
            outdir, subs_file, start, len(subs), cname_map,
            [], dangling_hosts, shared_hosts, auth_on,
        )

    # ── Stage 3: HTTP confirmation (unless passive_only) ───────────────────
    findings: list[TakeoverFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    if passive_only:
        log.info("")
        log.info("  Stage 3 — HTTP confirmation SKIPPED (passive_only=True)")

        for host, chain, fp in candidates:
            finding = TakeoverFinding(
                subdomain=host,
                cname_chain=chain,
                service=fp.name,
                cname_match=True,
                cvss=fp.cvss,
                dangling=host in dangling_hosts,
                shared_cname=host in shared_hosts,
                notes=f"{fp.notes} (HTTP not checked — passive mode)",
                auth_enabled=auth_on,
                first_seen=now,
                status="POTENTIAL",
            )
            _score_severity(finding)
            findings.append(finding)
    else:
        log.info("")
        log.info("  Stage 3 — HTTP body confirmation")

        def _process(candidate):
            host, chain, fp = candidate
            finding = TakeoverFinding(
                subdomain=host,
                cname_chain=chain,
                service=fp.name,
                cname_match=True,
                cvss=fp.cvss,
                dangling=host in dangling_hosts,
                shared_cname=host in shared_hosts,
                notes=fp.notes,
                auth_enabled=auth_on,
                first_seen=now,
            )
            confirmed, status, matched, final_url = _confirm_http(host, fp, auth_on)
            finding.http_status = status
            finding.http_confirmed = confirmed

            if confirmed:
                finding.status = "VULNERABLE"
                finding.fingerprint = matched
                finding.notes = f"{fp.notes} (confirmed at {final_url})"
            else:
                finding.status = "POTENTIAL"
                if status == 0:
                    finding.notes = f"{fp.notes} (HTTP unreachable — dangling is likely)"
                else:
                    finding.notes = f"{fp.notes} (HTTP {status}, no fingerprint match)"

            _score_severity(finding)
            return finding

        with ThreadPoolExecutor(max_workers=eff_threads) as pool:
            for finding in pool.map(_process, candidates):
                findings.append(finding)
                icon = "VULN" if finding.status == "VULNERABLE" else "POT "
                tag = " [dangling]" if finding.dangling else ""
                log.info(f"    [{icon}] {finding.subdomain:<40} "
                         f"{finding.service:<20} status={finding.http_status}{tag}")

    # ── Report ──────────────────────────────────────────────────────────────
    return _write_report(
        outdir, subs_file, start, len(subs), cname_map,
        findings, dangling_hosts, shared_hosts, auth_on, scan_id=scan_id,
    )


def _write_report(
    outdir: Path,
    input_file: Path,
    start: float,
    total_input: int,
    cname_map: dict[str, list[str]],
    findings: list[TakeoverFinding],
    dangling_hosts: set[str],
    shared_hosts: set[str],
    auth_on: bool,
    scan_id: Optional[int] = None,
) -> Path:
    """Write the JSON report and flat text outputs, then self-sync if requested."""
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

    by_service: dict[str, int] = {}
    for f in findings:
        by_service[f.service] = by_service.get(f.service, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(input_file),
        "auth_enabled": auth_on,
        "config": {
            "fingerprint_count": len(FINGERPRINTS),
            "http_threads":      HTTP_THREADS,
            "http_timeout":      HTTP_TIMEOUT,
        },
        "totals": {
            "subdomains_input":   total_input,
            "with_cname":         len(cname_map),
            "fingerprint_matches": len(findings),
            "vulnerable":         len(vulnerable),
            "potential":          len(potential),
            "dangling":           len(dangling_hosts),
            "shared_cname":       len(shared_hosts),
        },
        "summary": {
            "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in findings],
    }

    json_path = outdir / "takeover_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, findings)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

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
                     f"CVSS={f.cvss}  fp={f.fingerprint[:60]}")

    if dangling_hosts:
        log.info("")
        log.info(f"  Dangling CNAMEs ({len(dangling_hosts)}) — strongest takeover signal:")
        for host in sorted(dangling_hosts)[:10]:
            log.info(f"    {host}")

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
    return _write_report(
        outdir, input_file, start, total_input, {}, [],
        set(), set(), auth_on=bool(_cfg("AUTH_ENABLED", False)),
    )


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
    default_input = base / "output" / "dns_wildcard_filtered.txt"
    if not default_input.exists():
        default_input = base / "output" / "dns_resolved.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_subs.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus takeover check (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--passive", action="store_true",
                        help="DNS-only, skip HTTP confirmation")
    args = parser.parse_args()

    try:
        run_takeover_check(
            args.input, args.output,
            http_threads=args.threads,
            passive_only=args.passive,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
