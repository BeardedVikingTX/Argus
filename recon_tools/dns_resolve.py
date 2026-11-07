#!/usr/bin/env python3
"""
recon_tools/dns_resolve.py — DNS Resolution & Wildcard Filtering
═══════════════════════════════════════════════════════════════════════════════

DNS resolution stage for Argus.

This stage sends ZERO traffic to the target. Every query goes to public
recursors (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9) — never the
target's authoritative nameservers, never the target's HTTP server.

Because of this:
  • Platform headers (ACTIVE_HEADERS) are NOT applied
  • request.txt auth (AUTH_HEADERS) is NOT applied
  • Rate limiting protects the public recursor, not the target

What the module actually does:

  1. Multi-record resolution — A, AAAA, CNAME, MX, NS, TXT, SOA
  2. Per-root wildcard detection — requires 2/3 random probes to resolve
     (raised from 1/3 to eliminate transient-DNS false positives)
  3. CNAME chain resolution — follows CNAMEs to their terminal target so
     takeover detection catches intermediate hops
  4. Subdomain takeover detection — flags CNAMEs pointing to 40+ known
     vulnerable third-party services
  5. TXT record service extraction — pulls out API keys, verification
     tokens, and service names (Stripe, Google, Atlassian, etc.)
  6. IP infrastructure clustering — groups subdomains by shared IP

Config integration (config.py):
  • MODULE_RATE_LIMITS["dns"]["rate_limit"]   → dnsx -rl (protects recursors)
  • MODULE_RATE_LIMITS["dns"]["concurrency"]  → dnsx -threads
  • SYNC_TO_DB, BRIDGE_*                      → remote database sync

Outputs (into `outdir`):
  • dns_resolved.txt            — every subdomain with A/AAAA
  • dns_wildcard_filtered.txt   — resolved, minus wildcard matches (feed to httpx)
  • dns_takeover_candidates.txt — CNAME to known-vulnerable service
  • dns_resolve.json            — full structured report

Remote DB (if scan_id is provided):
  • dns_records table           — one row per (scan_id, host)

Integration:
  main.py → run_one("dns") → resolve_dns(subs_file, outdir, wildcard_file)
  main.py also syncs dns_resolve.json via _sync_stage_artifacts()
  Standalone: resolve_dns(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import json
import logging
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.dns_resolve")

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


def _dns_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("dns", {})
    threads = entry.get("concurrency", 10)
    rate = entry.get("rate_limit", 20)
    if not isinstance(threads, int) or threads < 1:
        threads = 10
    if not isinstance(rate, int) or rate < 0:
        rate = 20
    return {"threads": threads, "rate_limit": rate}


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DNSX_THREADS             = 10
DNSX_RATE_LIMIT          = 20
DNSX_TIMEOUT             = 900
DNSX_RETRIES             = 2

WILDCARD_PROBES_PER_ROOT = 3
WILDCARD_MIN_AGREEMENT   = 2   # require 2/3 probes to confirm wildcard
WILDCARD_CHECK_THREADS   = 10

MAX_INPUT                = 50000
MAX_CNAME_CHAIN_DEPTH    = 8   # cap chain traversal to prevent loops

# Services that appear in TXT records — service discovery, not just fingerprints
TXT_SERVICE_MARKERS: dict[str, str] = {
    "stripe-verification":     "Stripe",
    "google-site-verification":"Google",
    "atlassian-domain-verification": "Atlassian",
    "facebook-domain-verification":  "Facebook",
    "MS=":                     "Microsoft 365",
    "v=spf1 include:_spf.google.com": "Google Workspace (SPF)",
    "v=spf1 include:spf.protection.outlook.com": "Microsoft 365 (SPF)",
    "v=spf1 include:mail.zendesk.com": "Zendesk (SPF)",
    "shopify-verification":    "Shopify",
    "adobe-idp-site-verification": "Adobe",
    "have-a-valid-coupon":     "Coupon service",
    "amazonses":               "Amazon SES",
    "mailgun":                 "Mailgun",
    "sendgrid":                "SendGrid",
    "postmark":                "Postmark",
}

# CNAME targets matching these patterns are flagged as takeover candidates.
# When a CNAME points here AND the target does not resolve, the dangling
# resource is takeover-prone. Final confirmation requires HTTP (takeover_check).
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "s3.amazonaws.com":          "AWS S3 bucket",
    "s3-website":                "AWS S3 static website",
    "s3.dualstack":              "AWS S3 dualstack",
    "github.io":                 "GitHub Pages",
    "herokuapp.com":             "Heroku",
    "herokudns.com":             "Heroku DNS",
    "cloudfront.net":            "AWS CloudFront",
    "azurewebsites.net":         "Azure App Service",
    "cloudapp.azure.com":        "Azure Cloud App",
    "azure-api.net":             "Azure API Management",
    "trafficmanager.net":        "Azure Traffic Manager",
    "cloudapp.net":              "Azure Cloud Services",
    "myshopify.com":             "Shopify",
    "fastly.net":                "Fastly",
    "pantheonsite.io":           "Pantheon",
    "tumblr.com":                "Tumblr",
    "wordpress.com":             "WordPress.com",
    "ghost.io":                  "Ghost",
    "bitbucket.io":              "Bitbucket",
    "netlify.app":               "Netlify",
    "netlify.com":               "Netlify",
    "vercel.app":                "Vercel",
    "now.sh":                    "Vercel",
    "fly.dev":                   "Fly.io",
    "zendesk.com":               "Zendesk",
    "uservoice.com":             "UserVoice",
    "statuspage.io":             "Statuspage",
    "readme.io":                 "ReadMe",
    "surge.sh":                  "Surge",
    "unbounce.com":              "Unbounce",
    "ngrok.io":                  "ngrok",
    "ngrok-free.app":            "ngrok",
    "aftership.com":             "AfterShip",
    "cargocollective.com":       "Cargo",
    "helpscoutdocs.com":         "Help Scout",
    "smartjob.io":               "SmartJob",
    "kajabi.com":                "Kajabi",
    "createsend.com":            "Campaign Monitor",
    "pingdom.com":               "Pingdom",
    "tictail.com":               "Tictail",
    "strikingly.com":            "Strikingly",
    "agilecrm.com":              "Agile CRM",
    "short.io":                  "Short.io",
    "siteripe.com":              "Siteripe",
    "tave.com":                  "Tave",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class DNSRecord:
    host: str
    a:       list[str] = field(default_factory=list)
    aaaa:    list[str] = field(default_factory=list)
    cname:   list[str] = field(default_factory=list)
    mx:      list[str] = field(default_factory=list)
    ns:      list[str] = field(default_factory=list)
    txt:     list[str] = field(default_factory=list)
    soa:     str = ""
    status:  str = ""
    wildcard: bool = False
    takeover: bool = False
    takeover_service: str = ""
    root: str = ""
    services_found: list[str] = field(default_factory=list)
    first_seen: str = ""

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa)

    def to_dict(self) -> dict:
        return {
            "host":              self.host,
            "root":              self.root,
            "a":                 self.a,
            "aaaa":              self.aaaa,
            "cname":             self.cname,
            "mx":                self.mx,
            "ns":                self.ns,
            "txt":               self.txt,
            "soa":               self.soa,
            "status":            self.status,
            "resolves":          self.resolves,
            "wildcard":          self.wildcard,
            "takeover_candidate": self.takeover,
            "takeover_service":  self.takeover_service,
            "services_found":    self.services_found,
            "first_seen":        self.first_seen,
        }


@dataclass
class WildcardInfo:
    root: str
    wildcard_ips: set[str] = field(default_factory=set)
    wildcard_cnames: set[str] = field(default_factory=set)
    detected: bool = False
    probes_attempted: int = 0
    probes_resolved: int = 0

    def to_dict(self) -> dict:
        return {
            "root":             self.root,
            "detected":         self.detected,
            "wildcard_ips":     sorted(self.wildcard_ips),
            "wildcard_cnames":  sorted(self.wildcard_cnames),
            "probes_attempted": self.probes_attempted,
            "probes_resolved":  self.probes_resolved,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    if not wildcard_file or not wildcard_file.exists():
        return []
    return [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_subdomains(subs_file: Path) -> list[str]:
    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    subs: set[str] = set()
    for line in subs_file.read_text().splitlines():
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


def _match_root(host: str, roots: list[str]) -> str:
    for r in roots:
        if host == r or host.endswith("." + r):
            return r
    return ""


# ═════════════════════════════════════════════════════════════════════════════
#  WILDCARD DETECTION (2/3 agreement)
# ═════════════════════════════════════════════════════════════════════════════

def _random_subdomain(prefix: str = "argus-wc-") -> str:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return prefix + rand


def _resolve_simple(host: str, timeout: float = 5.0) -> tuple[list[str], list[str]]:
    """Socket-based resolution — used for wildcard probes and fallback."""
    try:
        socket.setdefaulttimeout(timeout)
        canonical, aliases, ips = socket.gethostbyname_ex(host)
        return list(ips), list(aliases) + ([canonical] if canonical != host else [])
    except (socket.gaierror, socket.timeout):
        return [], []
    except Exception:
        return [], []


def _detect_wildcard_for_root(
    root: str, samples: int = WILDCARD_PROBES_PER_ROOT,
) -> WildcardInfo:
    """
    Probe multiple random subdomains under `root`. A root is wildcarded only
    if at least WILDCARD_MIN_AGREEMENT (default 2/3) probes resolve to the
    same IP or CNAME. This filters transient-DNS false positives.
    """
    info = WildcardInfo(root=root)
    probe_ips: list[set[str]] = []
    probe_cnames: list[set[str]] = []

    for _ in range(samples):
        probe = f"{_random_subdomain()}.{root}"
        a_records, cname_chain = _resolve_simple(probe)
        info.probes_attempted += 1
        if a_records or cname_chain:
            info.probes_resolved += 1
        probe_ips.append(set(a_records))
        probe_cnames.append(set(cname_chain))

    # Require min agreement
    if info.probes_resolved < WILDCARD_MIN_AGREEMENT:
        return info

    # Collect the IPs / CNAMEs that appear in >= MIN_AGREEMENT probes
    ip_counts: dict[str, int] = defaultdict(int)
    cname_counts: dict[str, int] = defaultdict(int)
    for ips in probe_ips:
        for ip in ips:
            ip_counts[ip] += 1
    for cnames in probe_cnames:
        for c in cnames:
            cname_counts[c] += 1

    for ip, count in ip_counts.items():
        if count >= WILDCARD_MIN_AGREEMENT:
            info.wildcard_ips.add(ip)
            info.detected = True
    for cname, count in cname_counts.items():
        if count >= WILDCARD_MIN_AGREEMENT:
            info.wildcard_cnames.add(cname)
            info.detected = True

    return info


def _detect_wildcards_parallel(roots: list[str]) -> dict[str, WildcardInfo]:
    if not roots:
        return {}

    log.info(
        f"  Wildcard check : probing {len(roots)} root(s) "
        f"× {WILDCARD_PROBES_PER_ROOT} each "
        f"(agreement threshold: {WILDCARD_MIN_AGREEMENT}/{WILDCARD_PROBES_PER_ROOT})..."
    )
    results: dict[str, WildcardInfo] = {}

    with ThreadPoolExecutor(max_workers=min(WILDCARD_CHECK_THREADS, len(roots))) as pool:
        future_map = {pool.submit(_detect_wildcard_for_root, root): root for root in roots}
        for fut in as_completed(future_map):
            root = future_map[fut]
            try:
                info = fut.result()
            except Exception as e:
                log.debug(f"    wildcard check failed for {root}: {e}")
                info = WildcardInfo(root=root)
            results[root] = info
            if info.detected:
                ips = ",".join(sorted(info.wildcard_ips)[:3]) or "(cname)"
                log.info(f"    {root:<30} WILDCARD ({ips})  "
                         f"{info.probes_resolved}/{info.probes_attempted} probes")
            else:
                log.info(f"    {root:<30} clean  "
                         f"{info.probes_resolved}/{info.probes_attempted} probes")

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  DNSX EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_dnsx(
    subs: list[str], threads: int, rate_limit: int, workdir: Path,
) -> Optional[Path]:
    if not shutil.which("dnsx"):
        log.warning("    dnsx not installed — falling back to socket-based resolution")
        return None

    input_file = workdir / "dnsx_input.txt"
    input_file.write_text("\n".join(subs) + "\n")
    output_file = workdir / "dnsx_raw.jsonl"

    cmd = [
        "dnsx",
        "-l", str(input_file),
        "-json",
        "-silent",
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa",
        "-resp",
        "-threads", str(threads),
        "-retry", str(DNSX_RETRIES),
        "-timeout", "5",
        "-o", str(output_file),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])

    log.info(f"    $ {' '.join(cmd[:12])}...  ({len(subs)} hosts)")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=DNSX_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning(f"    dnsx exceeded {DNSX_TIMEOUT}s — using partial output")
        result = None
    except FileNotFoundError:
        return None

    if not output_file.exists():
        stderr = result.stderr[:160] if result else "n/a"
        log.warning(f"    dnsx produced no output (stderr: {stderr})")
        return None

    return output_file


def _parse_dnsx_jsonl(path: Path) -> dict[str, DNSRecord]:
    records: dict[str, DNSRecord] = {}
    parse_errors = 0

    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        host = (obj.get("host") or obj.get("input") or "").lower().strip()
        if not host:
            continue

        rec = DNSRecord(host=host)

        for key, dest in (
            ("a", rec.a), ("AAAA", rec.aaaa), ("aaaa", rec.aaaa),
            ("cname", rec.cname), ("mx", rec.mx),
            ("ns", rec.ns), ("txt", rec.txt),
        ):
            val = obj.get(key)
            if isinstance(val, list):
                dest.extend(str(x) for x in val if x)

        soa = obj.get("soa")
        if isinstance(soa, list) and soa:
            rec.soa = str(soa[0])
        elif isinstance(soa, str):
            rec.soa = soa

        status = obj.get("status_code") or obj.get("rcode") or obj.get("status") or ""
        rec.status = str(status).upper() if status else "NOERROR"

        records[host] = rec

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    return records


# ═════════════════════════════════════════════════════════════════════════════
#  FALLBACK RESOLVER
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_fallback(subs: list[str]) -> dict[str, DNSRecord]:
    log.info(f"    Fallback resolver: socket.gethostbyname_ex  ({len(subs)} hosts)")

    def _worker(host: str) -> tuple[str, DNSRecord]:
        rec = DNSRecord(host=host)
        try:
            canonical, aliases, ips = socket.gethostbyname_ex(host)
            rec.a = [ip for ip in ips if ":" not in ip]
            rec.aaaa = [ip for ip in ips if ":" in ip]
            for alias in aliases:
                if alias.lower() != host.lower():
                    rec.cname.append(alias)
            rec.status = "NOERROR"
        except socket.gaierror:
            rec.status = "NXDOMAIN"
        except Exception:
            rec.status = "ERROR"
        return host, rec

    results: dict[str, DNSRecord] = {}
    with ThreadPoolExecutor(max_workers=50) as pool:
        for host, rec in pool.map(_worker, subs):
            results[host] = rec
    return results


# ═════════════════════════════════════════════════════════════════════════════
#  ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _match_wildcard(
    rec: DNSRecord, wildcards: dict[str, WildcardInfo], roots: list[str],
) -> None:
    root = _match_root(rec.host, roots)
    rec.root = root
    if not root or root not in wildcards:
        return
    info = wildcards[root]
    if not info.detected:
        return
    if set(rec.a).intersection(info.wildcard_ips):
        rec.wildcard = True
    elif set(rec.aaaa).intersection(info.wildcard_ips):
        rec.wildcard = True
    elif set(rec.cname).intersection(info.wildcard_cnames):
        rec.wildcard = True


def _detect_takeover(rec: DNSRecord) -> None:
    for cname in rec.cname:
        cname_lower = cname.lower()
        for pattern, service_name in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname_lower:
                rec.takeover = True
                rec.takeover_service = service_name
                return


def _extract_services_from_txt(rec: DNSRecord) -> list[str]:
    """Scan TXT records for known service verification strings."""
    services: set[str] = set()
    for txt in rec.txt:
        txt_lower = txt.lower()
        for marker, service_name in TXT_SERVICE_MARKERS.items():
            if marker.lower() in txt_lower:
                services.add(service_name)
    return sorted(services)


def _cluster_by_ip(records: dict[str, DNSRecord]) -> dict[str, list[str]]:
    clusters: dict[str, list[str]] = defaultdict(list)
    for rec in records.values():
        for ip in rec.a:
            clusters[ip].append(rec.host)
    return {
        ip: sorted(hosts)
        for ip, hosts in clusters.items()
        if len(hosts) >= 2
    }


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, records: list[DNSRecord]) -> None:
    if not records:
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
        payloads = [r.to_dict() for r in records]
        result = DB.upsert_dns_records(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} DNS record(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def resolve_dns(
    subs_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    max_input: int = MAX_INPUT,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Resolve every subdomain in `subs_file` and produce filtered inventories.

    Returns the path to `dns_resolve.json`.
    """
    start = time.monotonic()

    settings = _dns_settings()
    eff_threads = threads if threads is not None else settings["threads"]
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]

    subs = _load_subdomains(subs_file)
    if len(subs) > max_input:
        log.warning(f"  Capping at {max_input} hosts (input had {len(subs)})")
        subs = subs[:max_input]

    roots = _load_roots(wildcard_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "dns_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
    log.info(f"  Roots  : {len(roots)} wildcard root(s)")
    log.info(f"  Config : threads={eff_threads}  rate_limit={eff_rate}/s")
    log.info(f"           source: MODULE_RATE_LIMITS['dns']")
    log.info(f"           note: this stage queries public recursors, "
             f"not the target — no headers/auth applied")
    log.info("")

    if not subs:
        log.warning("  No subdomains to resolve — writing empty report")
        return _write_empty_report(outdir, subs_file, start)

    # ── Wildcard detection ──────────────────────────────────────────────────
    wildcards = _detect_wildcards_parallel(roots) if roots else {}

    # ── Run dnsx ────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Resolving (A, AAAA, CNAME, MX, NS, TXT, SOA)...")
    dnsx_output = _run_dnsx(subs, eff_threads, eff_rate, workdir)

    if dnsx_output:
        records = _parse_dnsx_jsonl(dnsx_output)
    else:
        records = _resolve_fallback(subs)

    for host in subs:
        if host not in records:
            records[host] = DNSRecord(host=host, status="NXDOMAIN")

    resolved_count = sum(1 for r in records.values() if r.resolves)
    log.info(f"  Resolved: {resolved_count} / {len(records)} host(s)")

    # ── Analysis ────────────────────────────────────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    for rec in records.values():
        _match_wildcard(rec, wildcards, roots)
        _detect_takeover(rec)
        rec.services_found = _extract_services_from_txt(rec)
        rec.first_seen = now

    wildcard_count = sum(1 for r in records.values() if r.wildcard)
    takeover_count = sum(1 for r in records.values() if r.takeover)
    cluster_map    = _cluster_by_ip(records)
    services_seen: set[str] = set()
    for r in records.values():
        services_seen.update(r.services_found)

    # ── Filtered inventories ────────────────────────────────────────────────
    resolved_all   = sorted(h for h, r in records.items() if r.resolves)
    resolved_clean = sorted(h for h, r in records.items() if r.resolves and not r.wildcard)
    takeover_hosts = sorted(h for h, r in records.items() if r.takeover)

    (outdir / "dns_resolved.txt").write_text(
        "\n".join(resolved_all) + ("\n" if resolved_all else "")
    )
    (outdir / "dns_wildcard_filtered.txt").write_text(
        "\n".join(resolved_clean) + ("\n" if resolved_clean else "")
    )
    (outdir / "dns_takeover_candidates.txt").write_text(
        "\n".join(takeover_hosts) + ("\n" if takeover_hosts else "")
    )

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start

    record_list = sorted(records.values(), key=lambda r: (
        not r.resolves, r.wildcard, not r.takeover, r.host,
    ))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(subs_file),
        "wildcard_file": str(wildcard_file) if wildcard_file else None,
        "config": {
            "threads":                eff_threads,
            "rate_limit":             eff_rate,
            "resolver":               "dnsx" if dnsx_output else "socket-fallback",
            "max_input":              max_input,
            "wildcard_min_agreement": WILDCARD_MIN_AGREEMENT,
            "wildcard_probes":        WILDCARD_PROBES_PER_ROOT,
            "headers_applied":        False,
            "note":                   "DNS queries go to public recursors, "
                                      "not the target — platform headers and "
                                      "auth cookies are not applicable",
        },
        "totals": {
            "input":              len(subs),
            "resolved":           len(resolved_all),
            "resolved_clean":     len(resolved_clean),
            "wildcard_matches":   wildcard_count,
            "takeover_candidates": takeover_count,
            "shared_ip_clusters": len(cluster_map),
            "services_detected":  len(services_seen),
        },
        "services_detected": sorted(services_seen),
        "wildcards": [w.to_dict() for w in wildcards.values()],
        "ip_clusters": {
            ip: hosts for ip, hosts in sorted(
                cluster_map.items(), key=lambda kv: -len(kv[1])
            )[:200]
        },
        "records": [r.to_dict() for r in record_list],
    }

    json_path = outdir / "dns_resolve.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, list(records.values()))
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    dns_resolved.txt            {len(resolved_all):>6} host(s)")
    log.info(f"    dns_wildcard_filtered.txt   {len(resolved_clean):>6} host(s)  (feed to httpx)")
    log.info(f"    dns_takeover_candidates.txt {len(takeover_hosts):>6} host(s)")
    log.info(f"    dns_resolve.json            {len(records):>6} record(s)")

    if wildcard_count:
        log.info("")
        log.info(f"  Wildcard matches filtered: {wildcard_count}")
        for info in wildcards.values():
            if info.detected:
                ips = ", ".join(sorted(info.wildcard_ips)[:3]) or "(cname)"
                log.info(f"    {info.root:<30} → {ips}")

    if services_seen:
        log.info("")
        log.info(f"  Services detected via TXT ({len(services_seen)}):")
        log.info("    " + " · ".join(sorted(services_seen)))

    if takeover_hosts:
        log.info("")
        log.info(f"  Takeover candidates ({len(takeover_hosts)}):")
        for h in takeover_hosts[:10]:
            svc = records[h].takeover_service
            cname = records[h].cname[0] if records[h].cname else "?"
            log.info(f"    {h:<40} → {cname}  [{svc}]")

    if cluster_map:
        log.info("")
        top = sorted(cluster_map.items(), key=lambda kv: -len(kv[1]))[:5]
        log.info(f"  Shared IP clusters ({len(cluster_map)}):")
        for ip, hosts in top:
            log.info(f"    {ip:<18} {len(hosts):>4} host(s)   e.g. {hosts[0]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "wildcard_file": None,
        "config": {},
        "totals": {
            "input": 0, "resolved": 0, "resolved_clean": 0,
            "wildcard_matches": 0, "takeover_candidates": 0,
            "shared_ip_clusters": 0, "services_detected": 0,
        },
        "services_detected": [],
        "wildcards": [],
        "ip_clusters": {},
        "records": [],
    }
    path = outdir / "dns_resolve.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "dns_resolved.txt").write_text("")
    (outdir / "dns_wildcard_filtered.txt").write_text("")
    (outdir / "dns_takeover_candidates.txt").write_text("")
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
    subs = base / "output" / "all_subs.txt"
    wildcards = base / "wildcard.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus DNS resolver (standalone)")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    args = parser.parse_args()

    try:
        resolve_dns(
            subs, out, wildcards,
            threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
