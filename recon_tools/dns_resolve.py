#!/usr/bin/env python3
"""
recon_tools/dns_resolve.py — DNS Resolution & Wildcard Filtering
═══════════════════════════════════════════════════════════════════════════════

The DNS resolution stage for Argus. Does more than just "does this resolve":

  1. Multi-record resolution — A, AAAA, CNAME, MX, NS, TXT, SOA
  2. Per-root wildcard detection — filters wildcard-DNS false positives that
     would otherwise flood HTTPX with thousands of identical responses
  3. Subdomain takeover detection — flags CNAMEs pointing to known-vulnerable
     third-party services (S3, GitHub Pages, Heroku, Azure, etc.)
  4. IP infrastructure clustering — groups subdomains by shared IP so you can
     pivot on hosting providers and shared infrastructure
  5. Structured JSON output — full attribution for downstream stages

Outputs (into `outdir`):
  • dns_resolved.txt            — every subdomain with at least one A/AAAA record
  • dns_wildcard_filtered.txt   — resolved, minus wildcard-DNS matches (feed to HTTPX)
  • dns_takeover_candidates.txt — CNAME to known-vulnerable service (manual review)
  • dns_resolve.json            — full structured report

Integration:
  main.py → run_one("dns") → resolve_dns(subs_file, outdir, wildcard_file)
"""

from __future__ import annotations

import json
import logging
import random
import shutil
import socket
import string
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.dns_resolve")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DNSX_THREADS      = 100
DNSX_RATE_LIMIT   = 250        # queries/second
DNSX_TIMEOUT      = 900        # overall wall-clock ceiling (seconds)
DNSX_RETRIES      = 2

WILDCARD_PROBES_PER_ROOT = 3   # number of random subdomains per root to detect wildcards
WILDCARD_CHECK_THREADS   = 10

# Max subdomains to resolve in one run — prevents runaway cost
MAX_INPUT         = 50000

# CNAME targets matching these patterns are flagged as takeover candidates
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "s3.amazonaws.com":          "AWS S3 bucket (unclaimed bucket takeover)",
    "s3-website":                "AWS S3 static website (unclaimed bucket)",
    "s3.dualstack":              "AWS S3 (dualstack endpoint)",
    "github.io":                 "GitHub Pages (unclaimed repository)",
    "herokuapp.com":             "Heroku (unclaimed app)",
    "herokudns.com":             "Heroku DNS (dangling route)",
    "cloudfront.net":            "AWS CloudFront (dangling distribution)",
    "azurewebsites.net":         "Azure App Service (unclaimed app)",
    "cloudapp.azure.com":        "Azure Cloud App",
    "azure-api.net":             "Azure API Management",
    "trafficmanager.net":        "Azure Traffic Manager",
    "cloudapp.net":              "Azure Cloud Services",
    "myshopify.com":             "Shopify (unclaimed store)",
    "fastly.net":                "Fastly (unclaimed service)",
    "pantheonsite.io":           "Pantheon (unclaimed site)",
    "tumblr.com":                "Tumblr (unclaimed blog)",
    "wordpress.com":             "WordPress.com (unclaimed blog)",
    "ghost.io":                  "Ghost (unclaimed publication)",
    "bitbucket.io":              "Bitbucket (unclaimed repository)",
    "netlify.app":               "Netlify (unclaimed site)",
    "netlify.com":               "Netlify (unclaimed site)",
    "vercel.app":                "Vercel (unclaimed deployment)",
    "now.sh":                    "Vercel (unclaimed deployment)",
    "fly.dev":                   "Fly.io (unclaimed app)",
    "zendesk.com":               "Zendesk (unclaimed helpdesk)",
    "uservoice.com":             "UserVoice (unclaimed portal)",
    "statuspage.io":             "Statuspage (unclaimed page)",
    "readme.io":                 "ReadMe (unclaimed docs)",
    "surge.sh":                  "Surge (unclaimed site)",
    "unbounce.com":              "Unbounce (unclaimed page)",
    "ngrok.io":                  "ngrok (unclaimed tunnel)",
    "ngrok-free.app":            "ngrok (unclaimed tunnel)",
    "aftership.com":             "AfterShip (unclaimed tracking)",
    "cargocollective.com":       "Cargo (unclaimed portfolio)",
    "helpscoutdocs.com":         "Help Scout (unclaimed docs)",
    "smartjob.io":               "SmartJob (unclaimed board)",
    "kajabi.com":                "Kajabi (unclaimed site)",
    "createsend.com":            "Campaign Monitor (unclaimed sender)",
    "pingdom.com":               "Pingdom (unclaimed check)",
    "tictail.com":               "Tictail (unclaimed shop)",
    "strikingly.com":            "Strikingly (unclaimed site)",
    "agilecrm.com":              "Agile CRM (unclaimed tenant)",
    "short.io":                  "Short.io (unclaimed short domain)",
    "siteripe.com":              "Siteripe (unclaimed site)",
    "tave.com":                  "Tave (unclaimed studio)",
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
    status:  str = ""       # NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT, etc.
    wildcard: bool = False  # True if this matches a wildcard A record
    takeover: bool = False  # True if CNAME points to vulnerable service
    takeover_service: str = ""
    root: str = ""

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "root": self.root,
            "a": self.a,
            "aaaa": self.aaaa,
            "cname": self.cname,
            "mx": self.mx,
            "ns": self.ns,
            "txt": self.txt,
            "soa": self.soa,
            "status": self.status,
            "resolves": self.resolves,
            "wildcard": self.wildcard,
            "takeover_candidate": self.takeover,
            "takeover_service": self.takeover_service,
        }


@dataclass
class WildcardInfo:
    root: str
    wildcard_ips: set[str] = field(default_factory=set)
    wildcard_cnames: set[str] = field(default_factory=set)
    detected: bool = False

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "detected": self.detected,
            "wildcard_ips": sorted(self.wildcard_ips),
            "wildcard_cnames": sorted(self.wildcard_cnames),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    if not wildcard_file or not wildcard_file.exists():
        return []
    roots = [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return roots


def _load_subdomains(subs_file: Path) -> list[str]:
    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    subs = set()
    for line in subs_file.read_text().splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # Accept either bare names or URLs
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
#  WILDCARD DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _random_subdomain(prefix: str = "argus-wc-") -> str:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return prefix + rand


def _resolve_simple(host: str, timeout: float = 5.0) -> tuple[list[str], list[str]]:
    """
    Fallback resolver using Python's socket. Returns (a_records, cname_chain).
    Used only if dnsx is unavailable, and for wildcard detection probes.
    """
    try:
        socket.setdefaulttimeout(timeout)
        canonical, aliases, ips = socket.gethostbyname_ex(host)
        return list(ips), list(aliases) + ([canonical] if canonical != host else [])
    except (socket.gaierror, socket.timeout):
        return [], []
    except Exception:
        return [], []


def _detect_wildcard_for_root(root: str, samples: int = WILDCARD_PROBES_PER_ROOT) -> WildcardInfo:
    """
    Probe several random subdomains under `root`. If any resolve, record
    the resulting IPs / CNAMEs as wildcard matches for that root.
    """
    info = WildcardInfo(root=root)
    for _ in range(samples):
        probe = f"{_random_subdomain()}.{root}"
        a_records, cname_chain = _resolve_simple(probe)
        if a_records:
            info.wildcard_ips.update(a_records)
            info.detected = True
        if cname_chain:
            info.wildcard_cnames.update(cname_chain)
            info.detected = True
    return info


def _detect_wildcards_parallel(roots: list[str]) -> dict[str, WildcardInfo]:
    """Detect wildcard DNS across all roots concurrently."""
    if not roots:
        return {}

    log.info(f"  Wildcard check : probing {len(roots)} root(s) "
             f"× {WILDCARD_PROBES_PER_ROOT} probes each...")
    results: dict[str, WildcardInfo] = {}

    with ThreadPoolExecutor(max_workers=min(WILDCARD_CHECK_THREADS, len(roots))) as pool:
        future_map = {
            pool.submit(_detect_wildcard_for_root, root): root
            for root in roots
        }
        for fut in as_completed(future_map):
            root = future_map[fut]
            try:
                info = fut.result()
            except Exception as e:
                log.debug(f"    wildcard check failed for {root}: {e}")
                info = WildcardInfo(root=root)
            results[root] = info
            if info.detected:
                ips = ",".join(sorted(info.wildcard_ips)[:3])
                log.info(f"    {root:<30} WILDCARD ({ips or 'CNAME only'})")
            else:
                log.info(f"    {root:<30} clean")

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  DNSX EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_dnsx(subs: list[str], threads: int, rate_limit: int,
              workdir: Path) -> Optional[Path]:
    """
    Run dnsx against the subdomain list in JSON mode with all record types.
    Writes to `workdir/dnsx_raw.jsonl` and returns the path.
    """
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
        "-a",
        "-aaaa",
        "-cname",
        "-mx",
        "-ns",
        "-txt",
        "-soa",
        "-resp",
        "-threads", str(threads),
        "-rate-limit", str(rate_limit),
        "-retry", str(DNSX_RETRIES),
        "-timeout", "5",
        "-o", str(output_file),
    ]
    log.info(f"    $ {' '.join(cmd[:12])}...  ({len(subs)} hosts)")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=DNSX_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        log.warning(f"    dnsx exceeded {DNSX_TIMEOUT}s — using partial output")
    except FileNotFoundError:
        return None

    if not output_file.exists():
        log.warning(f"    dnsx produced no output (stderr: {result.stderr[:160] if 'result' in dir() else 'n/a'})")
        return None

    return output_file


def _parse_dnsx_jsonl(path: Path) -> dict[str, DNSRecord]:
    """
    Parse dnsx JSON Lines into a mapping of host → DNSRecord.
    dnsx JSON shape (varies slightly by version):
      {"host":"x.com","a":["1.2.3.4"],"cname":["y.com"],"status_code":"NOERROR"}
    """
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

        # Records — dnsx uses different key names across versions
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

        status = (
            obj.get("status_code")
            or obj.get("rcode")
            or obj.get("status")
            or ""
        )
        rec.status = str(status).upper() if status else "NOERROR"

        records[host] = rec

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    return records


# ═════════════════════════════════════════════════════════════════════════════
#  FALLBACK RESOLVER (socket-based)
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_fallback(subs: list[str]) -> dict[str, DNSRecord]:
    """Socket-based resolution for when dnsx is missing."""
    log.info(f"    Fallback resolver: socket.gethostbyname_ex  ({len(subs)} hosts)")

    def _worker(host: str) -> tuple[str, DNSRecord]:
        rec = DNSRecord(host=host)
        try:
            canonical, aliases, ips = socket.gethostbyname_ex(host)
            rec.a = [ip for ip in ips if ":" not in ip]
            rec.aaaa = [ip for ip in ips if ":" in ip]
            # Aliases include the canonical name when it differs
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

def _match_wildcard(rec: DNSRecord, wildcards: dict[str, WildcardInfo],
                    roots: list[str]) -> None:
    """Mark `rec` as wildcard if its resolved IPs or CNAMEs match the root's wildcard."""
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
    """Flag records whose CNAME points to a known-vulnerable service."""
    for cname in rec.cname:
        cname_lower = cname.lower()
        for pattern, service_name in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname_lower:
                rec.takeover = True
                rec.takeover_service = service_name
                return


def _cluster_by_ip(records: dict[str, DNSRecord]) -> dict[str, list[str]]:
    """Group hosts by shared A record IP for infrastructure pivoting."""
    clusters: dict[str, list[str]] = defaultdict(list)
    for rec in records.values():
        for ip in rec.a:
            clusters[ip].append(rec.host)
    # Only keep IPs shared by 2+ hosts — single-host IPs aren't interesting clusters
    return {
        ip: sorted(hosts)
        for ip, hosts in clusters.items()
        if len(hosts) >= 2
    }


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def resolve_dns(
    subs_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    threads: int = DNSX_THREADS,
    rate_limit: int = DNSX_RATE_LIMIT,
    max_input: int = MAX_INPUT,
) -> Path:
    """
    Resolve every subdomain in `subs_file` and produce filtered inventories.

    Returns the path to `dns_resolve.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    subs = _load_subdomains(subs_file)
    if len(subs) > max_input:
        log.warning(f"  Capping at {max_input} hosts (input had {len(subs)})")
        subs = subs[:max_input]

    roots = _load_roots(wildcard_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "dns_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input   : {len(subs)} subdomain(s) from {subs_file.name}")
    log.info(f"  Roots   : {len(roots)} wildcard root(s)")
    log.info("")

    if not subs:
        log.warning("  No subdomains to resolve — writing empty report")
        return _write_empty_report(outdir, subs_file, start)

    # ── Wildcard detection ──────────────────────────────────────────────────
    wildcards = _detect_wildcards_parallel(roots) if roots else {}

    # ── Run dnsx ────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Resolving (A, AAAA, CNAME, MX, NS, TXT, SOA)...")
    dnsx_output = _run_dnsx(subs, threads, rate_limit, workdir)

    if dnsx_output:
        records = _parse_dnsx_jsonl(dnsx_output)
    else:
        records = _resolve_fallback(subs)

    # Ensure every input host is in the map (some tools omit NXDOMAINs)
    for host in subs:
        if host not in records:
            records[host] = DNSRecord(host=host, status="NXDOMAIN")

    log.info(f"  Resolved: {sum(1 for r in records.values() if r.resolves)} "
             f"/ {len(records)} host(s)")

    # ── Analysis ────────────────────────────────────────────────────────────
    for rec in records.values():
        _match_wildcard(rec, wildcards, roots)
        _detect_takeover(rec)

    wildcard_count = sum(1 for r in records.values() if r.wildcard)
    takeover_count = sum(1 for r in records.values() if r.takeover)
    cluster_map    = _cluster_by_ip(records)

    # ── Filtered inventories ────────────────────────────────────────────────
    resolved_all   = sorted(h for h, r in records.items() if r.resolves)
    resolved_clean = sorted(
        h for h, r in records.items() if r.resolves and not r.wildcard
    )
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
        not r.resolves,       # resolved first
        r.wildcard,           # then non-wildcard
        not r.takeover,       # then takeover
        r.host,
    ))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(subs_file),
        "wildcard_file": str(wildcard_file) if wildcard_file else None,
        "config": {
            "threads": threads,
            "rate_limit": rate_limit,
            "resolver": "dnsx" if dnsx_output else "socket-fallback",
            "max_input": max_input,
        },
        "totals": {
            "input": len(subs),
            "resolved": len(resolved_all),
            "resolved_clean": len(resolved_clean),
            "wildcard_matches": wildcard_count,
            "takeover_candidates": takeover_count,
            "shared_ip_clusters": len(cluster_map),
        },
        "wildcards": [w.to_dict() for w in wildcards.values()],
        "ip_clusters": {
            ip: hosts for ip, hosts in sorted(
                cluster_map.items(), key=lambda kv: -len(kv[1])
            )[:200]  # cap at 200 clusters to keep the JSON manageable
        },
        "records": [r.to_dict() for r in record_list],
    }

    json_path = outdir / "dns_resolve.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup workdir ─────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    dns_resolved.txt           {len(resolved_all):>6} host(s)")
    log.info(f"    dns_wildcard_filtered.txt  {len(resolved_clean):>6} host(s)  (feed to httpx)")
    log.info(f"    dns_takeover_candidates.txt {len(takeover_hosts):>5} host(s)")
    log.info(f"    dns_resolve.json           {len(records):>6} record(s)")

    if wildcard_count:
        log.info("")
        log.info(f"  Wildcard matches filtered: {wildcard_count}")
        for info in wildcards.values():
            if info.detected:
                ips = ", ".join(sorted(info.wildcard_ips)[:3]) or "(cname)"
                log.info(f"    {info.root:<30} → {ips}")

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
            "shared_ip_clusters": 0,
        },
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
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    subs = base / "output" / "all_subs.txt"
    wildcards = base / "wildcard.txt"
    out = base / "output"

    try:
        resolve_dns(subs, out, wildcards)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
