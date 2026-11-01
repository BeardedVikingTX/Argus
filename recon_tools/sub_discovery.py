#!/usr/bin/env python3
"""
recon_tools/sub_discover.py — Live Host Discovery & Enrichment
═══════════════════════════════════════════════════════════════════════════════

Takes the subdomain inventory produced by `subs.py`, probes every host with
HTTPX using its full enrichment stack (status, title, tech, CDN, favicon,
JARM, redirects), layers on IP geolocation and ASN data via cached batch
lookups, attributes each host back to the sources that found it, and
classifies hosts by triage "interestingness".

Outputs (into `outdir`):
  • live_hosts.json   — full structured report (primary output)
  • live_hosts.txt    — URL + status + title + tech (nmap-compatible)
  • live_urls.txt     — plain URLs, one per line
  • geo_cache.json    — IP → geo mapping (persistent cache)

Integration:
  main.py → run_one("live") → discover_live(subs_file, outdir)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.sub_discover")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS    = 50
DEFAULT_RATE_LIMIT = 150
DEFAULT_TIMEOUT    = 10
DEFAULT_RETRIES    = 2
HTTPX_HARD_TIMEOUT = 3600   # overall wall-clock ceiling for the httpx process

# Enrichment toggles — disable slower ones if runtime matters
ENABLE_TECH_DETECT      = True
ENABLE_CNAME            = True
ENABLE_CDN              = True
ENABLE_FAVICON          = True
ENABLE_JARM             = True
ENABLE_FOLLOW_REDIRECTS = True
ENABLE_TLS_GRAB         = False   # 2–3x slower — leave off by default
ENABLE_RANDOM_AGENT     = True

# Geolocation (ip-api.com free tier: 45 req/min, 100 IPs/request)
GEO_ENABLED      = True
GEO_BATCH_SIZE   = 100
GEO_RATE_SLEEP   = 1.5      # seconds between batches → ~40 req/min
GEO_TIMEOUT      = 15
GEO_CACHE_FILE   = "geo_cache.json"

# Attribution — read sources from subdomains.json if it exists
ENRICH_FROM_SOURCES_JSON = True
SOURCES_JSON_NAME = "subdomains.json"

# Interesting-host thresholds
INTERESTING_MIN_SCORE = 20


# ═════════════════════════════════════════════════════════════════════════════
#  NORMALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_host(name: str) -> Optional[str]:
    """Lowercase, strip schemes / paths / ports. Returns None on empty."""
    if not name:
        return None
    s = name.strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/")[0].split("?")[0]
    if ":" in s:
        s = s.split(":")[0]
    return s or None


# ═════════════════════════════════════════════════════════════════════════════
#  HTTPX
# ═════════════════════════════════════════════════════════════════════════════

def _build_httpx_cmd(
    subs_file: Path,
    threads: int,
    rate_limit: int,
    timeout: int,
    retries: int,
) -> list[str]:
    """Assemble the HTTPX command line with all enabled enrichment flags."""
    cmd = [
        "httpx",
        "-l", str(subs_file),
        "-json",
        "-silent",
        "-sc",
        "-title",
        "-web-server",
        "-ip",
        "-threads",     str(threads),
        "-rate-limit",  str(rate_limit),
        "-timeout",     str(timeout),
        "-retries",     str(retries),
    ]
    if ENABLE_TECH_DETECT:      cmd.append("-tech-detect")
    if ENABLE_CNAME:            cmd.extend(["-cname"])
    if ENABLE_CDN:              cmd.append("-cdn")
    if ENABLE_FAVICON:          cmd.append("-favicon")
    if ENABLE_JARM:             cmd.append("-jarm")
    if ENABLE_FOLLOW_REDIRECTS: cmd.append("-follow-redirects")
    if ENABLE_TLS_GRAB:         cmd.append("-tls-grab")
    if ENABLE_RANDOM_AGENT:     cmd.append("-random-agent")
    return cmd


def _run_httpx(
    subs_file: Path,
    threads: int,
    rate_limit: int,
    timeout: int,
    retries: int,
) -> list[dict]:
    """Run HTTPX and return the parsed JSONL records."""
    if not shutil.which("httpx"):
        raise RuntimeError(
            "httpx not found on PATH. Run `python3 tools.py --only httpx` first."
        )

    cmd = _build_httpx_cmd(subs_file, threads, rate_limit, timeout, retries)
    log.info(f"    $ {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=HTTPX_HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"httpx exceeded {HTTPX_HARD_TIMEOUT}s wall-clock timeout")
    except FileNotFoundError:
        raise RuntimeError("httpx binary vanished mid-run")

    records: list[dict] = []
    parse_errors = 0

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        # Skip dead hosts — httpx marks these failed:true (or no status)
        if obj.get("failed") is True:
            continue
        if obj.get("status_code") in (None, 0):
            continue
        records.append(obj)

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    if result.returncode != 0 and not records:
        log.warning(f"    httpx exit={result.returncode} stderr={result.stderr[:200]}")

    return records


# ═════════════════════════════════════════════════════════════════════════════
#  GEO / ASN ENRICHMENT
# ═════════════════════════════════════════════════════════════════════════════

def _load_geo_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as e:
        log.warning(f"    geo cache unreadable ({e}) — starting fresh")
        return {}


def _save_geo_cache(path: Path, cache: dict[str, dict]) -> None:
    try:
        path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n")
    except Exception as e:
        log.warning(f"    could not save geo cache: {e}")


def _geo_batch(ips: list[str]) -> dict[str, dict]:
    """Query ip-api.com's batch endpoint. Returns ip → geo dict."""
    if not ips:
        return {}
    url = "http://ip-api.com/batch"
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type":     "application/json",
            "User-Agent":       "argus-sub-discover/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning(f"    geo batch failed: {e}")
        return {}

    out: dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "success":
            continue
        ip = entry.get("query")
        if not ip:
            continue
        out[ip] = {
            "country":      entry.get("country"),
            "country_code": entry.get("countryCode"),
            "region":       entry.get("regionName"),
            "region_code":  entry.get("region"),
            "city":         entry.get("city"),
            "zip":          entry.get("zip"),
            "lat":          entry.get("lat"),
            "lon":          entry.get("lon"),
            "timezone":     entry.get("timezone"),
            "isp":          entry.get("isp"),
            "org":          entry.get("org"),
            "asn":          entry.get("as"),
            "hosting":      entry.get("hosting"),
            "proxy":        entry.get("proxy"),
        }
    return out


def _enrich_geo(records: list[dict], outdir: Path) -> dict[str, dict]:
    """
    Attach geo data to each record via `record["geo"]`.
    Uses a persistent on-disk cache to minimise API calls.
    """
    # Collect all unique IPs across records
    all_ips: set[str] = set()
    for rec in records:
        for ip in _extract_ips(rec):
            all_ips.add(ip)

    if not all_ips:
        return {}

    cache_path = outdir / GEO_CACHE_FILE
    cache = _load_geo_cache(cache_path)

    uncached = sorted(ip for ip in all_ips if ip not in cache)
    if uncached:
        log.info(f"    Geo lookup: {len(uncached)} uncached IP(s), "
                 f"{len(all_ips) - len(uncached)} from cache")

        batches = [uncached[i:i + GEO_BATCH_SIZE]
                   for i in range(0, len(uncached), GEO_BATCH_SIZE)]
        for i, batch in enumerate(batches, 1):
            log.info(f"      batch {i}/{len(batches)}: {len(batch)} IP(s)")
            results = _geo_batch(batch)
            cache.update(results)
            if i < len(batches):
                time.sleep(GEO_RATE_SLEEP)

        _save_geo_cache(cache_path, cache)
    else:
        log.info(f"    Geo lookup: all {len(all_ips)} IP(s) served from cache")

    # Attach to records
    for rec in records:
        ips = _extract_ips(rec)
        geo_list = [cache[ip] for ip in ips if ip in cache]
        rec["geo"] = geo_list

    return cache


def _extract_ips(record: dict) -> list[str]:
    """Pull IPv4/IPv6 addresses out of an httpx JSON record."""
    ips: list[str] = []
    for key in ("a", "aaaa"):
        val = record.get(key)
        if isinstance(val, list):
            ips.extend(str(x) for x in val if x)
    # Some httpx versions use a single "ip" field
    single = record.get("ip")
    if single and single not in ips:
        ips.append(str(single))
    return ips


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE ATTRIBUTION
# ═════════════════════════════════════════════════════════════════════════════

def _load_source_map(outdir: Path) -> dict[str, dict]:
    """Read subdomains.json and build subdomain → record mapping."""
    if not ENRICH_FROM_SOURCES_JSON:
        return {}
    path = outdir / SOURCES_JSON_NAME
    if not path.exists():
        log.debug("    subdomains.json not present — skipping attribution")
        return {}
    try:
        data = json.loads(path.read_text())
        return {
            rec["subdomain"]: rec
            for rec in data.get("subdomains", [])
            if "subdomain" in rec
        }
    except Exception as e:
        log.warning(f"    could not parse subdomains.json: {e}")
        return {}


def _attach_attribution(record: dict, source_map: dict[str, dict]) -> None:
    """Add sources / first_seen from subdomains.json onto an httpx record."""
    if not source_map:
        return
    host = _normalize_host(record.get("input") or record.get("host") or "")
    if not host:
        return
    src = source_map.get(host)
    if not src:
        return
    record["sources"] = src.get("sources", [])
    record["source_count"] = src.get("source_count", len(record["sources"]))
    record["first_seen"] = src.get("first_seen")
    record["root"] = src.get("root")


# ═════════════════════════════════════════════════════════════════════════════
#  TRIAGE CLASSIFIER
# ═════════════════════════════════════════════════════════════════════════════

TITLE_KEYWORDS = (
    "admin", "login", "dashboard", "internal", "debug",
    "staging", "dev", "test", "management", "console",
    "phpmyadmin", "grafana", "kibana", "jenkins", "swagger",
)

PATH_KEYWORDS = (
    "/admin", "/api", "/graphql", "/actuator", "/swagger",
    "/debug", "/internal", "/v1", "/v2", "/v3",
    "/jenkins", "/grafana", "/kibana", "/phpmyadmin",
)


def _classify(record: dict) -> tuple[bool, list[str], int]:
    """
    Return (interesting, reasons, score).

    Score accumulates from independent signals:
      +30  status 401/403 (protected resource — something is there)
      +25  content-type is JSON/XML (API endpoint)
      +20  sensitive word in title
      +15  sensitive path segment in URL
      +10  framework in tech stack implying admin (Jenkins, Grafana, etc.)
      +10  status 5xx (potential bug)
    """
    reasons: list[str] = []
    score = 0

    status = record.get("status_code") or 0
    title = (record.get("title") or "").lower()
    ct = (record.get("content_type") or "").lower()
    url = (record.get("url") or "").lower()
    tech = [t.lower() for t in (record.get("tech") or [])]

    if status in (401, 403):
        reasons.append("access_gated")
        score += 30

    if "json" in ct or "xml" in ct:
        reasons.append("api_content_type")
        score += 25

    if any(k in title for k in TITLE_KEYWORDS):
        reasons.append("sensitive_title")
        score += 20

    if any(k in url for k in PATH_KEYWORDS):
        reasons.append("sensitive_path")
        score += 15

    admin_tech = {"jenkins", "grafana", "kibana", "phpmyadmin", "prometheus",
                  "swagger ui", "spring boot actuator"}
    if any(t in admin_tech for t in tech):
        reasons.append("admin_framework")
        score += 10

    if 500 <= status < 600:
        reasons.append("server_error")
        score += 10

    return (score >= INTERESTING_MIN_SCORE, reasons, score)


# ═════════════════════════════════════════════════════════════════════════════
#  RECORD NORMALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def _build_host_record(raw: dict) -> dict:
    """Flatten an httpx JSONL record into our canonical shape."""
    host_name = _normalize_host(raw.get("input") or raw.get("host") or "") or ""
    cdn = raw.get("cdn_name") or raw.get("cdn")
    return {
        "subdomain":       host_name,
        "url":             raw.get("url"),
        "scheme":          raw.get("scheme"),
        "host":            raw.get("host"),
        "port":            raw.get("port"),
        "path":            raw.get("path", "/"),
        "status_code":     raw.get("status_code"),
        "content_type":    raw.get("content_type"),
        "content_length":  raw.get("content_length"),
        "title":           raw.get("title"),
        "web_server":      raw.get("webserver"),
        "technologies":    raw.get("tech") or [],
        "cname":           raw.get("cname"),
        "cdn":             cdn,
        "cdn_type":        raw.get("cdn_type"),
        "ip":              raw.get("a") or raw.get("ip"),
        "ipv6":            raw.get("aaaa"),
        "response_time":   raw.get("time"),
        "favicon_hash":    raw.get("favicon"),
        "jarm_hash":       raw.get("jarm_hash"),
        "final_url":       raw.get("final_url"),
        "redirect_chain":  raw.get("chain_status_codes"),
        "tls":             raw.get("tls"),
        "sources":         [],
        "source_count":    0,
        "root":            None,
        "first_seen":      None,
        "geo":             [],
        "interesting":     False,
        "reasons":         [],
        "score":           0,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_live_hosts_txt(records: list[dict], outdir: Path) -> Path:
    """Backward-compatible one-line-per-host file for nmap consumption."""
    lines = []
    for r in records:
        url = r.get("url") or ""
        if not url:
            continue
        status = r.get("status_code", "")
        title = (r.get("title") or "").replace("\n", " ")[:60]
        tech = ",".join(r.get("technologies") or [])[:60]
        lines.append(f"{url} [{status}] [{title}] [{tech}]")
    path = outdir / "live_hosts.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_live_urls_txt(records: list[dict], outdir: Path) -> Path:
    """Plain URLs, one per line."""
    urls = sorted({r["url"] for r in records if r.get("url")})
    path = outdir / "live_urls.txt"
    path.write_text("\n".join(urls) + ("\n" if urls else ""))
    return path


def _build_summary(records: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    by_tech:   dict[str, int] = {}
    by_cdn:    dict[str, int] = {}
    by_country: dict[str, int] = {}
    by_server: dict[str, int] = {}

    interesting_count = 0
    healthy_count = 0
    error_count = 0

    for r in records:
        status = r.get("status_code") or 0
        by_status[str(status)] = by_status.get(str(status), 0) + 1
        if 200 <= status < 300:
            healthy_count += 1
        if 400 <= status < 600:
            error_count += 1

        for t in (r.get("technologies") or []):
            by_tech[t] = by_tech.get(t, 0) + 1

        cdn = r.get("cdn")
        if cdn:
            by_cdn[cdn] = by_cdn.get(cdn, 0) + 1

        for g in (r.get("geo") or []):
            cc = g.get("country_code")
            if cc:
                by_country[cc] = by_country.get(cc, 0) + 1

        srv = r.get("web_server")
        if srv:
            # Strip version numbers for grouping
            base = srv.split("/")[0].strip()
            by_server[base] = by_server.get(base, 0) + 1

        if r.get("interesting"):
            interesting_count += 1

    return {
        "alive":           len(records),
        "healthy":         healthy_count,
        "error":           error_count,
        "interesting":     interesting_count,
        "by_status_code":  dict(sorted(by_status.items(), key=lambda kv: int(kv[0]))),
        "by_technology":   dict(sorted(by_tech.items(), key=lambda kv: -kv[1])),
        "by_cdn":          dict(sorted(by_cdn.items(), key=lambda kv: -kv[1])),
        "by_country":      dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "by_web_server":   dict(sorted(by_server.items(), key=lambda kv: -kv[1])),
    }


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def discover_live(
    subs_file: Path,
    outdir: Path,
    *,
    threads: int = DEFAULT_THREADS,
    rate_limit: int = DEFAULT_RATE_LIMIT,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    resolve_geo: bool = GEO_ENABLED,
    enrich_attribution: bool = ENRICH_FROM_SOURCES_JSON,
) -> Path:
    """
    Probe every subdomain in `subs_file` for HTTP liveness and enrichment.

    Returns the path to `live_hosts.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    if not shutil.which("httpx"):
        raise RuntimeError("httpx not found — run `python3 tools.py --only httpx`")

    subs = [
        line.strip()
        for line in subs_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
    if not subs:
        log.info("  (nothing to probe — writing empty report)")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": 0.0,
            "input_file": str(subs_file),
            "config": {
                "threads": threads, "rate_limit": rate_limit,
                "timeout": timeout, "retries": retries,
            },
            "totals": {"input": 0, "alive": 0},
            "summary": {},
            "hosts": [],
        }
        path = outdir / "live_hosts.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        return path

    # ── Run HTTPX ───────────────────────────────────────────────────────────
    log.info("")
    log.info(f"  Probing with httpx (threads={threads}, "
             f"rate-limit={rate_limit}/s, timeout={timeout}s)...")
    raw_records = _run_httpx(subs_file, threads, rate_limit, timeout, retries)
    log.info(f"  Alive  : {len(raw_records)} / {len(subs)} responded")

    if not raw_records:
        log.warning("  No live hosts — writing empty report")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(time.monotonic() - start, 2),
            "input_file": str(subs_file),
            "config": {
                "threads": threads, "rate_limit": rate_limit,
                "timeout": timeout, "retries": retries,
            },
            "totals": {"input": len(subs), "alive": 0},
            "summary": {},
            "hosts": [],
        }
        path = outdir / "live_hosts.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        # Still emit empty text companions
        _write_live_hosts_txt([], outdir)
        _write_live_urls_txt([], outdir)
        return path

    # ── Normalize records ───────────────────────────────────────────────────
    log.info("  Normalizing records...")
    records = [_build_host_record(r) for r in raw_records]

    # ── Source attribution ──────────────────────────────────────────────────
    if enrich_attribution:
        log.info("  Attaching source attribution from subdomains.json...")
        src_map = _load_source_map(outdir)
        for rec in records:
            # Temporary proxy so _attach_attribution can read `input`
            proxy = {"input": rec.get("subdomain"), "host": rec.get("host")}
            _attach_attribution(proxy, src_map)
            if proxy.get("sources"):
                rec["sources"] = proxy["sources"]
                rec["source_count"] = proxy.get("source_count", 0)
                rec["first_seen"] = proxy.get("first_seen")
                rec["root"] = proxy.get("root")

    # ── Geo enrichment ──────────────────────────────────────────────────────
    if resolve_geo:
        log.info("  Enriching with geo / ASN data...")
        _enrich_geo(records, outdir)
    else:
        log.info("  Geo enrichment disabled")

    # ── Classification ──────────────────────────────────────────────────────
    for rec in records:
        interesting, reasons, score = _classify(rec)
        rec["interesting"] = interesting
        rec["reasons"] = reasons
        rec["score"] = score

    # ── Sort for triage priority ────────────────────────────────────────────
    STATUS_PRIORITY = {
        200: 1, 201: 1, 202: 1, 204: 1,
        401: 2, 403: 2,
        301: 3, 302: 3, 303: 3, 307: 3, 308: 3,
        500: 4, 502: 4, 503: 4, 504: 4,
    }

    def _sort_key(h: dict) -> tuple:
        status = h.get("status_code") or 0
        priority = STATUS_PRIORITY.get(status, 5)
        return (0 if h.get("interesting") else 1, priority, h.get("subdomain") or "")

    records.sort(key=_sort_key)

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    summary = _build_summary(records)

    report = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":     str(subs_file),
        "config": {
            "threads":              threads,
            "rate_limit":           rate_limit,
            "timeout":              timeout,
            "retries":              retries,
            "tech_detect":          ENABLE_TECH_DETECT,
            "cname":                ENABLE_CNAME,
            "cdn":                  ENABLE_CDN,
            "favicon":              ENABLE_FAVICON,
            "jarm":                 ENABLE_JARM,
            "follow_redirects":     ENABLE_FOLLOW_REDIRECTS,
            "tls_grab":             ENABLE_TLS_GRAB,
            "geo_enabled":          resolve_geo,
        },
        "totals": {
            "input":       len(subs),
            "alive":       len(records),
            "interesting": summary["interesting"],
        },
        "summary": summary,
        "hosts": records,
    }

    # ── Write outputs ───────────────────────────────────────────────────────
    json_path = outdir / "live_hosts.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    txt_path  = _write_live_hosts_txt(records, outdir)
    urls_path = _write_live_urls_txt(records, outdir)

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info(f"  Outputs :")
    log.info(f"    {json_path.name:<20} {len(records):>5} host(s)")
    log.info(f"    {txt_path.name:<20} {len(records):>5} line(s)")
    log.info(f"    {urls_path.name:<20} {len({r['url'] for r in records if r.get('url')}):>5} URL(s)")

    log.info("")
    log.info(f"  Interesting: {summary['interesting']} host(s) flagged for triage")
    top = [r for r in records if r["interesting"]][:5]
    for r in top:
        tag = ",".join(r["reasons"])
        log.info(f"    {r['status_code']:>3} {r['subdomain']:<40} [{tag}]")

    log.info("")
    log.info(f"  Status  : " + " · ".join(
        f"{code}→{n}" for code, n in list(summary["by_status_code"].items())[:8]
    ))
    if summary["by_technology"]:
        top_tech = list(summary["by_technology"].items())[:6]
        log.info(f"  Tech    : " + " · ".join(f"{t}({n})" for t, n in top_tech))
    if summary["by_cdn"]:
        log.info(f"  CDN     : " + " · ".join(
            f"{c}({n})" for c, n in list(summary["by_cdn"].items())[:5]
        ))
    if summary["by_country"]:
        log.info(f"  Geo     : " + " · ".join(
            f"{c}({n})" for c, n in list(summary["by_country"].items())[:5]
        ))

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


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
    out  = base / "output"
    try:
        discover_live(subs, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
