#!/usr/bin/env python3
"""
recon_tools/sub_discovery.py — Live Host Discovery & Enrichment (v4.0)
═══════════════════════════════════════════════════════════════════════════════

Probes every subdomain with HTTPX's full enrichment stack, layers on IP
geolocation + ASN data, propagates sensitivity classification from subs.py,
classifies hosts by triage interest, analyzes security headers, and emits
HIGH+/CRITICAL confirmed findings plus exploit chains.

THIS IS THE FIRST STAGE THAT SENDS TRAFFIC TO THE TARGET. Platform headers
from config.py ACTIVE_HEADERS are applied to every httpx request. AUTH_HEADERS
are optionally applied when `headers=` is passed to discover_live() — main.py
currently does NOT pass auth headers so this stays an anonymous sweep.

ENRICHMENT
──────────
  1. HTTPX liveness probe (-sc -title -web-server -ip -tech-detect -cname
     -cdn -favicon -jarm -follow-redirects)
  2. Geo / ASN via ip-api.com batch (100 IPs/req, cached in geo_cache.json)
  3. Source attribution from subdomains.json (sources, source_count, first_seen)
  4. subs.py v4.0 propagation: sensitive_category, severity, wildcard,
     cloud_provider, cname_chain, chain_ids
  5. Service categorization from httpx tech[]:
       web_server / cdn / framework / cms / language / database_ui /
       monitoring / ci_cd / documentation / eol_software
  6. Security header analysis (from httpx -json `header` field):
       HSTS, CSP, X-Frame-Options, CORS wildcard, Set-Cookie flags
  7. WAF detection from response headers (8-vendor signature match)
  8. Shared IP detection: flags IPs serving >1 subdomain (multi-tenant risk)

CONFIRMATION MODEL
──────────────────
Hosts inherit severity from multiple signals, taking the maximum:
  · subs.py sensitive classification  (CRITICAL/HIGH → inherited)
  · admin_panel / database_ui / debug_exposed detected → HIGH
  · auth_gated (401/403) → HIGH
  · eol_software (version below known-safe threshold) → HIGH
  · cors_wildcard + auth_gated → HIGH (chain to XSS)
  · api_endpoint → MEDIUM
  · staging (from subs.py) → HIGH
  · default_page → LOW
  · plain 200 page → LOW

CHAINS
──────
  recon-admin-surface     admin panels reachable (feeds auth_tester)
  recon-api-surface       API endpoints found (feeds graphql, idor)
  recon-auth-gated        auth-protected resources (feeds auth_tester)
  recon-debug-exposed     debug/actuator endpoints exposed
  recon-database-ui       phpMyAdmin/Adminer etc. exposed
  recon-eol-software      end-of-life version with CVE hint
  recon-staging           staging/dev environment confirmed live
  recon-default-install   default vendor page (informational)
  recon-waf-protected     WAF in front (tunes later stages)
  recon-cors-wildcard     permissive CORS (feeds XSS, exfil chains)
  recon-multi-tenant      multiple subdomains on the same IP
  recon-cloud-hosted      cloud provider attribution (from CNAME)
  recon-security-headers  missing HSTS + CSP + XFO (defense gaps)

OUTPUTS
───────
  live_hosts.json            full structured report (backward-compatible)
  live_hosts_confirmed.json  HIGH+/CRITICAL findings only
  live_hosts_chains.json     recon chains
  live_hosts.txt             nmap-compatible text summary
  live_urls.txt              plain URLs
  live_evidence/raw_httpx.txt  raw httpx JSONL output
  live_evidence/<host>_headers.txt  per-host response headers (interesting only)
  geo_cache.json             IP → geo cache

BACKWARD COMPAT
───────────────
  The `hosts[]` array in live_hosts.json preserves every original field —
  main.py's _sync_recon_stage("live") → DB.upsert_live_hosts() keeps
  working unchanged. New fields are additive only.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.sub_discovery")


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
    from db import DB, ArgusDB  # noqa: F401
    DB_AVAILABLE = True
except ImportError:
    DB = None
    DB_AVAILABLE = False


def _cfg(key: str, default=None):
    return getattr(CFG, key, default) if CFG_LOADED else default


def _live_settings() -> tuple[int, int, int, int]:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("live", {})
    threads = entry.get("concurrency", DEFAULT_THREADS)
    rate    = entry.get("rate_limit", DEFAULT_RATE_LIMIT)
    timeout = entry.get("timeout", DEFAULT_TIMEOUT)
    retries = entry.get("retries", DEFAULT_RETRIES)
    if not isinstance(threads, int) or threads < 1:
        threads = DEFAULT_THREADS
    if not isinstance(rate, int) or rate < 0:
        rate = DEFAULT_RATE_LIMIT
    if not isinstance(timeout, int) or timeout < 1:
        timeout = DEFAULT_TIMEOUT
    if not isinstance(retries, int) or retries < 0:
        retries = DEFAULT_RETRIES
    return threads, rate, timeout, retries


def _headers_for_httpx(extra_headers: Optional[dict] = None) -> tuple[list[str], bool]:
    """
    Return (header_args, should_randomize_ua).

    Merges ACTIVE_HEADERS + AUTH_HEADERS (when AUTH_ENABLED) + extra_headers.
    If any source sets User-Agent, -random-agent is disabled (they conflict).
    """
    merged: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        merged.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    if extra_headers:
        merged.update(extra_headers)

    args: list[str] = []
    has_ua = False
    for k, v in merged.items():
        args.extend(["-H", f"{k}: {v}"])
        if k.lower() == "user-agent":
            has_ua = True
    return args, not has_ua


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
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS    = 50
DEFAULT_RATE_LIMIT = 150
DEFAULT_TIMEOUT    = 10
DEFAULT_RETRIES    = 2
HTTPX_HARD_TIMEOUT = 3600
BODY_PREVIEW_LEN   = 500
BODY_PREVIEW_AGGRESSIVE = 2000

ENABLE_TECH_DETECT      = True
ENABLE_CNAME            = True
ENABLE_CDN              = True
ENABLE_FAVICON          = True
ENABLE_JARM             = True
ENABLE_FOLLOW_REDIRECTS = True
ENABLE_TLS_GRAB         = False
ENABLE_BODY_PREVIEW     = True
ENABLE_RANDOM_AGENT     = True

GEO_ENABLED      = True
GEO_BATCH_SIZE   = 100
GEO_RATE_SLEEP   = 1.5
GEO_TIMEOUT      = 15
GEO_CACHE_FILE   = "geo_cache.json"

ENRICH_FROM_SOURCES_JSON = True
SOURCES_JSON_NAME = "subdomains.json"

INTERESTING_MIN_SCORE = 20


# ── Service categorization (tech → category) ────────────────────────────────
SERVICE_CATEGORIES: dict[str, list[str]] = {
    "web_server": [
        "nginx", "apache", "iis", "caddy", "litespeed", "openresty",
        "traefik", "haproxy", "varnish", "envoy", "lighttpd",
    ],
    "cdn": [
        "cloudflare", "akamai", "fastly", "cloudfront", "azure cdn",
        "bunny cdn", "stackpath", "keycdn", "sucuri", "imperva",
    ],
    "framework": [
        "django", "flask", "rails", "laravel", "express", "next.js",
        "nuxt", "gatsby", "spring", "asp.net", "phoenix", "sinatra",
        "fastapi", "rocket", "actix", "vertx",
    ],
    "cms": [
        "wordpress", "drupal", "joomla", "magento", "ghost", "wix",
        "squarespace", "webflow", "typo3", "craft cms", "concrete cms",
        "shopify", "woocommerce",
    ],
    "language": [
        "php", "ruby", "python", "java", "node.js", "go", "rust",
        "perl", ".net",
    ],
    "database_ui": [
        "phpmyadmin", "adminer", "mongo-express", "redis-commander",
        "pgadmin", "dbeaver", "sequel pro", "mywebsql",
    ],
    "monitoring": [
        "grafana", "kibana", "prometheus", "zabbix", "nagios",
        "newrelic", "datadog", "sentry", "graylog", "jaeger",
    ],
    "ci_cd": [
        "jenkins", "gitlab", "teamcity", "bamboo", "circleci",
        "travis ci", "drone", "argo", "tekton", "spinnaker",
    ],
    "documentation": [
        "swagger ui", "redoc", "gitbook", "mkdocs", "confluence",
        "docusaurus", "sphinx", "readme.io", "slate",
    ],
    "auth": [
        "keycloak", "auth0", "okta", "cas", "shibboleth", "authentik",
        "fusionauth", "ory",
    ],
}

# ── End-of-life threshold map: tech → (min_major, min_minor, min_patch, CVE hint) ──
TECH_MIN_SAFE_VERSION: dict[str, tuple[int, int, Optional[int], str]] = {
    "nginx":   (1, 20, 1,    "CVE-2021-23017"),
    "apache":  (2, 4,  51,   "CVE-2021-42013"),
    "httpd":   (2, 4,  51,   "CVE-2021-42013"),
    "openssh": (9, 8,  None, "CVE-2024-6387 (regreSSHion)"),
    "log4j":   (2, 17, 0,    "CVE-2021-44228 (Log4Shell)"),
    "spring":  (5, 3,  18,   "CVE-2022-22965 (Spring4Shell)"),
    "struts":  (2, 5,  30,   "CVE-2017-5638"),
    "tomcat":  (9, 0,  63,   "CVE-2021-25329"),
    "iis":     (10, 0, None, "unsupported version"),
}

# ── WAF signatures (from response headers) ──────────────────────────────────
WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai":      ["akamai-grn", "x-akamai-transformed", "_abck"],
    "Imperva":     ["x-iinfo", "incap_ses", "_incapsula_resource"],
    "AWS WAF":     ["x-amzn-requestid", "x-amzn-errortype", "awselb"],
    "F5 BIG-IP":   ["x-wa-info", "bigipserver"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "DataDome":    ["x-datadome", "datadome"],
    "ModSecurity": ["x-mod-security"],
}

# ── Sensitive admin panel titles/tech ───────────────────────────────────────
ADMIN_TITLE_KEYWORDS = (
    "admin", "administrator", "dashboard", "management", "console",
    "control panel", "login", "sign in", "phpmyadmin", "adminer",
    "kibana", "grafana", "jenkins", "swagger ui", "prometheus",
    "tomcat manager", "webmin", "cpanel", "plesk",
)

DEBUG_PATH_KEYWORDS = (
    "/actuator", "/debug", "/trace", "/phpinfo", "/.env",
    "/swagger", "/api-docs", "/graphiql", "/api/graphql",
)

DEFAULT_PAGE_TITLES = (
    "welcome to nginx", "apache2 ubuntu default page",
    "apache2 debian default page", "apache http server test page",
    "iis windows server", "test page for the apache",
)

# ── Chain names ─────────────────────────────────────────────────────────────
CHAIN_NAMES: dict[str, str] = {
    "recon-admin-surface":    "Admin panel reachable (feeds auth_tester)",
    "recon-api-surface":      "API endpoints discovered",
    "recon-auth-gated":       "Auth-protected resources (feeds auth_tester/idor)",
    "recon-debug-exposed":    "Debug/actuator endpoints exposed",
    "recon-database-ui":      "Database UI exposed (phpMyAdmin/Adminer)",
    "recon-eol-software":     "End-of-life software with known CVE",
    "recon-staging":          "Staging/dev environment live",
    "recon-default-install":  "Default vendor page (info)",
    "recon-waf-protected":    "WAF-fronted host (tunes later stages)",
    "recon-cors-wildcard":    "Permissive CORS (feeds XSS/exfil)",
    "recon-multi-tenant":     "Multi-tenant IP (isolation risk)",
    "recon-cloud-hosted":     "Cloud-hosted (from CNAME)",
    "recon-security-headers": "Missing HSTS/CSP/XFO",
}


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_host(name: str) -> Optional[str]:
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


def _first_or_none(value):
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _get_header(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup from httpx's dict-of-lists format."""
    if not headers:
        return None
    target = name.lower()
    for k, v in headers.items():
        if str(k).lower() == target:
            if isinstance(v, list):
                return v[0] if v else None
            return str(v)
    return None


def _parse_version(version_str: str) -> Optional[tuple[int, int, Optional[int]]]:
    """'1.18.0-ubuntu' → (1, 18, 0); returns None if unparseable."""
    if not version_str:
        return None
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)),
            int(m.group(3)) if m.group(3) else None)


def _version_lt(v1: tuple, v2: tuple) -> bool:
    """Compare versions; None patch counts as 0."""
    v1p = v1 + (0,) * (3 - len(v1)) if len(v1) < 3 else v1[:3]
    v2p = v2 + (0,) * (3 - len(v2)) if len(v2) < 3 else v2[:3]
    return v1p < v2p


# ═════════════════════════════════════════════════════════════════════════════
#  HTTPX
# ═════════════════════════════════════════════════════════════════════════════

def _build_httpx_cmd(
    subs_file: Path, threads: int, rate_limit: int, timeout: int, retries: int,
    header_args: list[str], randomize_ua: bool,
    body_preview_len: int = BODY_PREVIEW_LEN,
) -> list[str]:
    cmd = [
        "httpx",
        "-l", str(subs_file),
        "-json", "-silent",
        "-sc", "-title", "-web-server", "-ip",
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-retries", str(retries),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])

    if ENABLE_TECH_DETECT:      cmd.append("-tech-detect")
    if ENABLE_CNAME:            cmd.append("-cname")
    if ENABLE_CDN:              cmd.append("-cdn")
    if ENABLE_FAVICON:          cmd.append("-favicon")
    if ENABLE_JARM:             cmd.append("-jarm")
    if ENABLE_FOLLOW_REDIRECTS: cmd.append("-follow-redirects")
    if ENABLE_TLS_GRAB:         cmd.append("-tls-grab")
    if ENABLE_BODY_PREVIEW:     cmd.extend(["-body-preview", str(body_preview_len)])
    if ENABLE_RANDOM_AGENT and randomize_ua:
        cmd.append("-random-agent")

    cmd.extend(header_args)
    return cmd


def _run_httpx(
    subs_file: Path, threads: int, rate_limit: int, timeout: int, retries: int,
    header_args: list[str], randomize_ua: bool,
    evidence_dir: Path, body_preview_len: int = BODY_PREVIEW_LEN,
) -> tuple[list[dict], str]:
    if not shutil.which("httpx"):
        raise RuntimeError("httpx not found — run `python3 tools.py --only httpx`")

    cmd = _build_httpx_cmd(
        subs_file, threads, rate_limit, timeout, retries,
        header_args, randomize_ua, body_preview_len,
    )
    log.info(f"    $ {' '.join(cmd[:8])}...  ({len(cmd)} args)")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=HTTPX_HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"httpx exceeded {HTTPX_HARD_TIMEOUT}s wall-clock")
    except FileNotFoundError:
        raise RuntimeError("httpx binary vanished mid-run")

    # Save raw output for evidence
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "raw_httpx.txt").write_text(result.stdout[:10_000_000])
    except Exception as e:
        log.debug(f"    evidence save failed: {e}")

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
        if obj.get("failed") is True:
            continue
        if obj.get("status_code") in (None, 0):
            continue
        records.append(obj)

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")
    if result.returncode != 0 and not records:
        log.warning(f"    httpx exit={result.returncode} stderr={result.stderr[:200]}")

    return records, result.stdout


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
    if not ips:
        return {}
    payload = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        "http://ip-api.com/batch", data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": "argus-sub-discovery/4.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning(f"    geo batch failed: {e}")
        return {}

    out: dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, dict) or entry.get("status") != "success":
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


def _extract_ips(record: dict) -> list[str]:
    ips: list[str] = []
    for key in ("a", "aaaa"):
        val = record.get(key)
        if isinstance(val, list):
            ips.extend(str(x) for x in val if x)
    single = record.get("ip")
    if single and single not in ips:
        ips.append(str(single))
    return ips


def _enrich_geo(records: list[dict], outdir: Path) -> dict[str, dict]:
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
            cache.update(_geo_batch(batch))
            if i < len(batches):
                time.sleep(GEO_RATE_SLEEP)
        _save_geo_cache(cache_path, cache)
    else:
        log.info(f"    Geo lookup: all {len(all_ips)} IP(s) served from cache")

    for rec in records:
        ips = _extract_ips(rec)
        rec["geo"] = [cache[ip] for ip in ips if ip in cache]
    return cache


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE ATTRIBUTION (from subs.py v4.0)
# ═════════════════════════════════════════════════════════════════════════════

def _load_source_map(outdir: Path) -> dict[str, dict]:
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


def _apply_attribution(record: dict, subs_rec: dict) -> None:
    """Copy subs.py fields into the live host record."""
    if not subs_rec:
        return
    record["sources"]           = subs_rec.get("sources") or []
    record["source_count"]      = subs_rec.get("source_count", len(record["sources"]))
    record["first_seen"]        = subs_rec.get("first_seen")
    record["root"]              = subs_rec.get("root")
    record["wildcard"]          = bool(subs_rec.get("wildcard"))
    record["cloud_provider"]    = subs_rec.get("cloud_provider") or ""
    record["cname_chain"]       = subs_rec.get("cname_chain") or []
    record["subs_sensitive_category"] = subs_rec.get("sensitive_category") or ""
    record["subs_severity"]     = (subs_rec.get("severity") or "LOW").upper()
    record["subs_chain_ids"]    = subs_rec.get("chain_ids") or []


# ═════════════════════════════════════════════════════════════════════════════
#  SERVICE CATEGORIZATION
# ═════════════════════════════════════════════════════════════════════════════

def _categorize_services(tech_list: list[str]) -> dict[str, list[str]]:
    """Group httpx tech[] into categories."""
    tech_lower = [t.lower().strip() for t in (tech_list or [])]
    out: dict[str, list[str]] = {}
    for category, patterns in SERVICE_CATEGORIES.items():
        hits = [t for t in tech_lower
                if any(p in t or t in p for p in patterns)]
        if hits:
            out[category] = hits
    return out


def _detect_eol(tech_list: list[str]) -> list[dict]:
    """Return [{tech, version, min_safe, cve}] for EOL software."""
    eol: list[dict] = []
    for tech in (tech_list or []):
        tl = tech.lower()
        for name, min_safe in TECH_MIN_SAFE_VERSION.items():
            if name in tl:
                # Extract version from strings like "nginx/1.18.0", "Apache/2.4.41"
                m = re.search(rf"{re.escape(name)}[/\s-]?(\d+\.\d+(?:\.\d+)?)", tl, re.I)
                if not m:
                    continue
                ver = _parse_version(m.group(1))
                if not ver:
                    continue
                min_tuple = (min_safe[0], min_safe[1],
                             min_safe[2] if min_safe[2] is not None else 0)
                if _version_lt(ver, min_tuple):
                    eol.append({
                        "tech":      name,
                        "version":   m.group(1),
                        "min_safe":  ".".join(str(x) for x in min_tuple),
                        "cve":       min_safe[3],
                    })
                break
    return eol


# ═════════════════════════════════════════════════════════════════════════════
#  HEADER + WAF ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _detect_waf(headers: dict) -> str:
    if not headers:
        return ""
    flat = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for vendor, patterns in WAF_SIGNATURES.items():
        if any(p in flat for p in patterns):
            return vendor
    return ""


def _analyze_headers(headers: dict, scheme: str) -> dict:
    """Analyze security headers. Returns a dict of findings."""
    hsts      = _get_header(headers, "Strict-Transport-Security")
    csp       = _get_header(headers, "Content-Security-Policy")
    xfo       = _get_header(headers, "X-Frame-Options")
    acao      = _get_header(headers, "Access-Control-Allow-Origin")
    acac      = _get_header(headers, "Access-Control-Allow-Credentials")
    set_cookie = _get_header(headers, "Set-Cookie")

    cors_wildcard = False
    if acao == "*":
        # '*' with credentials is actually rejected by browsers, but it's
        # still a signal for public APIs that don't need CORS
        cors_wildcard = True
    elif acac and acac.lower() == "true" and acao and "*" not in acao:
        # Origin reflected with credentials — suspicious, flag it
        cors_wildcard = "credentials_reflected"

    return {
        "hsts_missing":   scheme == "https" and not hsts,
        "csp_missing":    not csp,
        "xfo_missing":    not xfo,
        "cors_wildcard":  cors_wildcard,
        "cookies_insecure": (
            bool(set_cookie)
            and "secure" not in (set_cookie or "").lower()
            and scheme == "https"
        ),
        "hsts_value":   hsts[:80] if hsts else "",
        "csp_value":    csp[:120] if csp else "",
    }


# ═════════════════════════════════════════════════════════════════════════════
#  CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _classify(record: dict, subs_rec: Optional[dict]) -> tuple[Severity, list[str], list[str], list[str], int]:
    """
    Return (severity, categories, chain_ids, reasons, score).

    Multiple signals → maximum severity wins.
    """
    reasons: list[str] = []
    categories: list[str] = []
    chain_ids: list[str] = []
    sev = Severity.LOW
    score = 0

    status   = record.get("status_code") or 0
    title    = (record.get("title") or "").lower()
    ct       = (record.get("content_type") or "").lower()
    url      = (record.get("url") or "").lower()
    tech     = [t.lower() for t in (record.get("technologies") or [])]
    headers  = record.get("_headers") or {}
    scheme   = record.get("scheme") or "https"

    services = record.get("_services") or {}

    # ── Inherit subs.py classification ─────────────────────────────────────
    if subs_rec:
        subs_sev = (subs_rec.get("severity") or "LOW").upper()
        subs_cat = subs_rec.get("sensitive_category") or ""
        subs_cids = subs_rec.get("chain_ids") or []
        try:
            s = Severity(subs_sev)
            if s.rank > sev.rank:
                sev = s
            if s.rank >= Severity.HIGH.rank:
                score += 20
                reasons.append(f"subs_{subs_cat or 'sensitive'}")
                categories.append(f"subs:{subs_cat}" if subs_cat else "subs")
                chain_ids.extend(c for c in subs_cids if c not in chain_ids)
        except ValueError:
            pass

    # ── Admin panel detection ──────────────────────────────────────────────
    is_admin = (
        any(k in title for k in ADMIN_TITLE_KEYWORDS)
        or "database_ui" in services
        or "ci_cd" in services
        or "monitoring" in services
    )
    if is_admin:
        if "database_ui" in services:
            sev = max(sev, Severity.CRITICAL, key=lambda s: s.rank)
            reasons.append("database_ui")
            categories.append("database_ui")
            chain_ids.append("recon-database-ui")
            score += 40
        else:
            sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
            reasons.append("admin_panel")
            categories.append("admin_panel")
            chain_ids.append("recon-admin-surface")
            score += 30

    # ── Debug/actuator exposure ────────────────────────────────────────────
    if any(k in url for k in DEBUG_PATH_KEYWORDS):
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        reasons.append("debug_exposed")
        categories.append("debug")
        chain_ids.append("recon-debug-exposed")
        score += 30

    # ── API endpoints ──────────────────────────────────────────────────────
    if "json" in ct or "xml" in ct or "/api" in url or "/graphql" in url:
        sev = max(sev, Severity.MEDIUM, key=lambda s: s.rank)
        reasons.append("api_endpoint")
        categories.append("api")
        chain_ids.append("recon-api-surface")
        score += 15

    # ── Auth gated ─────────────────────────────────────────────────────────
    if status in (401, 403):
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        reasons.append(f"auth_gated_{status}")
        categories.append("auth_gated")
        chain_ids.append("recon-auth-gated")
        score += 25

    # ── EOL software ───────────────────────────────────────────────────────
    eol = record.get("_eol") or []
    if eol:
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        reasons.append(f"eol:{','.join(e['tech'] for e in eol[:2])}")
        categories.append("eol_software")
        chain_ids.append("recon-eol-software")
        score += 25

    # ── Staging/dev environment ────────────────────────────────────────────
    if "staging" in categories or (subs_rec and subs_rec.get("sensitive_category") == "staging"):
        sev = max(sev, Severity.HIGH, key=lambda s: s.rank)
        chain_ids.append("recon-staging")
        score += 15

    # ── Default install page ───────────────────────────────────────────────
    if any(t in title for t in DEFAULT_PAGE_TITLES):
        reasons.append("default_page")
        categories.append("default_install")
        chain_ids.append("recon-default-install")

    # ── CORS wildcard ──────────────────────────────────────────────────────
    if record.get("_headers_analysis", {}).get("cors_wildcard"):
        sev = max(sev, Severity.MEDIUM, key=lambda s: s.rank)
        reasons.append("cors_wildcard")
        categories.append("cors")
        chain_ids.append("recon-cors-wildcard")
        score += 10

    # ── Security headers ───────────────────────────────────────────────────
    ha = record.get("_headers_analysis", {})
    if ha.get("hsts_missing") or (ha.get("csp_missing") and ha.get("xfo_missing")):
        reasons.append("weak_headers")
        categories.append("headers")
        chain_ids.append("recon-security-headers")

    # ── WAF ────────────────────────────────────────────────────────────────
    if record.get("waf_vendor"):
        chain_ids.append("recon-waf-protected")

    # ── Cloud hosted ───────────────────────────────────────────────────────
    if record.get("cloud_provider"):
        chain_ids.append("recon-cloud-hosted")

    # ── Dedup chain_ids ────────────────────────────────────────────────────
    chain_ids = list(dict.fromkeys(chain_ids))

    # Score threshold
    interesting = score >= INTERESTING_MIN_SCORE or sev.rank >= Severity.HIGH.rank

    return sev, categories, chain_ids, reasons, score


# ═════════════════════════════════════════════════════════════════════════════
#  RECORD BUILDING
# ═════════════════════════════════════════════════════════════════════════════

def _build_host_record(raw: dict) -> dict:
    host_name = _normalize_host(raw.get("input") or raw.get("host") or "") or ""
    cdn = raw.get("cdn_name") or raw.get("cdn")
    headers = raw.get("header") or {}
    body_preview = raw.get("body_preview") or ""

    rec = {
        # ── Core fields (backward-compatible with prior payload) ────────────
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
        # ── v4.0 additions ─────────────────────────────────────────────────
        "wildcard":        False,
        "cloud_provider":  "",
        "cname_chain":     [],
        "subs_sensitive_category": "",
        "subs_severity":   "LOW",
        "subs_chain_ids":  [],
        "severity":        Severity.LOW.value,
        "categories":      [],
        "chain_ids":       [],
        "waf_vendor":      "",
        "services":        {},
        "eol_software":    [],
        "body_preview":    body_preview[:500],
        "headers_analysis": {},
        "_headers":        headers,        # internal only; stripped before write
        "_services":       {},
        "_eol":            [],
        "_headers_analysis": {},
    }

    # ── Service categorization ─────────────────────────────────────────────
    rec["services"] = _categorize_services(rec["technologies"])
    rec["_services"] = rec["services"]

    # ── EOL detection ──────────────────────────────────────────────────────
    rec["eol_software"] = _detect_eol(rec["technologies"])
    rec["_eol"] = rec["eol_software"]

    # ── WAF detection ──────────────────────────────────────────────────────
    rec["waf_vendor"] = _detect_waf(headers)

    # ── Security header analysis ───────────────────────────────────────────
    rec["headers_analysis"] = _analyze_headers(headers, rec.get("scheme") or "https")
    rec["_headers_analysis"] = rec["headers_analysis"]

    return rec


def _to_payload(rec: dict) -> Optional[dict]:
    """
    Convert a local record to the wire shape live_hosts.upsert expects.
    Preserves every original field so main.py's DB sync is unchanged.
    """
    url = rec.get("url")
    if not url:
        return None

    first_seen = rec.get("first_seen")
    first_seen_fmt = None
    if first_seen:
        first_seen_fmt = (first_seen.replace("T", " ").split(".")[0]
                          .split("+")[0].rstrip("Z"))

    favicon = rec.get("favicon_hash")
    favicon_str = str(favicon) if favicon is not None else None

    return {
        # ── Backward-compatible fields ─────────────────────────────────────
        "subdomain":       rec.get("subdomain") or "",
        "url":             url,
        "root":            rec.get("root"),
        "scheme":          rec.get("scheme"),
        "host":            rec.get("host"),
        "port":            str(rec["port"]) if rec.get("port") is not None else None,
        "path":            rec.get("path"),
        "status_code":     rec.get("status_code"),
        "content_type":    rec.get("content_type"),
        "content_length":  rec.get("content_length"),
        "title":           rec.get("title"),
        "web_server":      rec.get("web_server"),
        "response_time":   rec.get("response_time"),
        "final_url":       rec.get("final_url"),
        "redirect_chain":  rec.get("redirect_chain"),
        "ip":              _first_or_none(rec.get("ip")),
        "ipv6":            _first_or_none(rec.get("ipv6")),
        "cname":           rec.get("cname"),
        "cdn":             rec.get("cdn"),
        "cdn_type":        rec.get("cdn_type"),
        "technologies":    rec.get("technologies") or [],
        "favicon_hash":    favicon_str,
        "jarm_hash":       rec.get("jarm_hash"),
        "tls":             rec.get("tls"),
        "sources":         rec.get("sources") or [],
        "source_count":    rec.get("source_count", 0),
        "first_seen":      first_seen_fmt,
        "geo":             rec.get("geo") or [],
        "interesting":     bool(rec.get("interesting")),
        "reasons":         rec.get("reasons") or [],
        "score":           int(rec.get("score", 0)),
    }


def _strip_internal(record: dict) -> dict:
    """Remove _-prefixed internal fields before writing to JSON."""
    return {k: v for k, v in record.items() if not k.startswith("_")}


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_live_hosts_txt(records: list[dict], outdir: Path) -> Path:
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
    urls = sorted({r["url"] for r in records if r.get("url")})
    path = outdir / "live_urls.txt"
    path.write_text("\n".join(urls) + ("\n" if urls else ""))
    return path


def _write_headers_evidence(records: list[dict], evidence_dir: Path) -> None:
    """Save headers for interesting hosts only."""
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for rec in records:
            if not rec.get("interesting"):
                continue
            headers = rec.get("_headers") or {}
            if not headers:
                continue
            safe = re.sub(r"[^a-zA-Z0-9._-]+", "_",
                          rec.get("subdomain") or "unknown")[:80]
            body = "\n".join(f"{k}: {v}" for k, v in headers.items())
            (evidence_dir / f"{safe}_headers.txt").write_text(body)
    except Exception as e:
        log.debug(f"    header evidence save failed: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def _build_chains(records: list[dict]) -> list[dict]:
    """Group records by chain_id and emit structured chain records."""
    groups: dict[str, list[dict]] = {}

    for rec in records:
        for cid in (rec.get("chain_ids") or []):
            groups.setdefault(cid, []).append(rec)

    # Multi-tenant: group by IP
    by_ip: dict[str, list[str]] = {}
    for rec in records:
        ip = _first_or_none(rec.get("ip"))
        if ip:
            by_ip.setdefault(ip, []).append(rec.get("subdomain") or "")
    for ip, subs in by_ip.items():
        if len(subs) >= 2:
            groups.setdefault("recon-multi-tenant", []).append({
                "subdomain": ip, "ip": ip, "shared_by": subs[:20],
            })

    SEV_BY_CHAIN = {
        "recon-admin-surface":    Severity.HIGH,
        "recon-api-surface":      Severity.MEDIUM,
        "recon-auth-gated":       Severity.HIGH,
        "recon-debug-exposed":    Severity.HIGH,
        "recon-database-ui":      Severity.CRITICAL,
        "recon-eol-software":     Severity.HIGH,
        "recon-staging":          Severity.HIGH,
        "recon-default-install":  Severity.LOW,
        "recon-waf-protected":    Severity.INFO,
        "recon-cors-wildcard":    Severity.MEDIUM,
        "recon-multi-tenant":     Severity.MEDIUM,
        "recon-cloud-hosted":     Severity.INFO,
        "recon-security-headers": Severity.LOW,
    }

    chains: list[dict] = []
    for cid, members in groups.items():
        member_subs = [m.get("subdomain") or "" for m in members]
        chains.append({
            "chain_id": cid,
            "name":     CHAIN_NAMES.get(cid, cid),
            "severity": SEV_BY_CHAIN.get(cid, Severity.LOW).value,
            "members":  member_subs[:100],
            "count":    len(members),
            "evidence": f"{len(members)} member(s): "
                        f"{', '.join(member_subs[:5])}"
                        + (f" … (+{len(members) - 5})"
                           if len(members) > 5 else ""),
        })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    chains.sort(key=lambda c: (sev_order.get(c["severity"], 5), c["chain_id"]))
    return chains


# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def _build_summary(records: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    by_tech:   dict[str, int] = {}
    by_cdn:    dict[str, int] = {}
    by_country: dict[str, int] = {}
    by_server: dict[str, int] = {}
    by_waf:    dict[str, int] = {}
    by_cloud:  dict[str, int] = {}
    by_sev:    dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

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

        if r.get("cdn"):
            by_cdn[r["cdn"]] = by_cdn.get(r["cdn"], 0) + 1

        for g in (r.get("geo") or []):
            cc = g.get("country_code")
            if cc:
                by_country[cc] = by_country.get(cc, 0) + 1

        srv = r.get("web_server")
        if srv:
            base = srv.split("/")[0].strip()
            by_server[base] = by_server.get(base, 0) + 1

        waf = r.get("waf_vendor")
        if waf:
            by_waf[waf] = by_waf.get(waf, 0) + 1

        cp = r.get("cloud_provider")
        if cp:
            by_cloud[cp] = by_cloud.get(cp, 0) + 1

        sev = r.get("severity") or "LOW"
        by_sev[sev] = by_sev.get(sev, 0) + 1

        if r.get("interesting"):
            interesting_count += 1

    return {
        "alive":         len(records),
        "healthy":       healthy_count,
        "error":         error_count,
        "interesting":   interesting_count,
        "by_status_code": dict(sorted(by_status.items(),
                                       key=lambda kv: int(kv[0]))),
        "by_technology":  dict(sorted(by_tech.items(), key=lambda kv: -kv[1])),
        "by_cdn":         dict(sorted(by_cdn.items(), key=lambda kv: -kv[1])),
        "by_country":     dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "by_web_server":  dict(sorted(by_server.items(), key=lambda kv: -kv[1])),
        "by_waf":         dict(sorted(by_waf.items(), key=lambda kv: -kv[1])),
        "by_cloud":       dict(sorted(by_cloud.items(), key=lambda kv: -kv[1])),
        "by_severity":    by_sev,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC (standalone only)
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, records: list[dict]) -> None:
    if not records or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not DB.available:
        return

    payloads = [_to_payload(r) for r in records]
    payloads = [p for p in payloads if p and p.get("url")]
    if not payloads:
        return

    try:
        result = DB.upsert_live_hosts(scan_id, payloads)
        if result is not None:
            log.info(f"  DB sync: {result} live host(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def discover_live(
    subs_file: Path,
    outdir: Path,
    *,
    threads: Optional[int] = None,
    rate_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    headers: Optional[dict] = None,
    resolve_geo: bool = GEO_ENABLED,
    enrich_attribution: bool = ENRICH_FROM_SOURCES_JSON,
    aggressive: bool = False,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Probe every subdomain in `subs_file` for HTTP liveness and enrichment.

    Backward-compatible: existing main.py callers work unchanged.

    Returns: path to live_hosts.json
    """
    start = time.monotonic()

    cfg_threads, cfg_rate, cfg_timeout, cfg_retries = _live_settings()
    eff_threads = threads if threads is not None else cfg_threads
    eff_rate    = rate_limit if rate_limit is not None else cfg_rate
    eff_timeout = timeout if timeout is not None else cfg_timeout
    eff_retries = retries if retries is not None else cfg_retries
    body_preview_len = BODY_PREVIEW_AGGRESSIVE if aggressive else BODY_PREVIEW_LEN

    if not subs_file.exists():
        raise FileNotFoundError(f"subdomain file not found: {subs_file}")
    if not shutil.which("httpx"):
        raise RuntimeError("httpx not found — run `python3 tools.py --only httpx`")

    subs = [line.strip()
            for line in subs_file.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

    outdir.mkdir(parents=True, exist_ok=True)
    evidence_dir = outdir / "live_evidence"

    log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")

    if not subs:
        log.info("  (nothing to probe — writing empty report)")
        return _write_empty_report(outdir, subs_file, start)

    # ── Config display ──────────────────────────────────────────────────────
    rate_label = f"{eff_rate}/s" if eff_rate else "unlimited"
    log.info(f"  Config : threads={eff_threads}  rate_limit={rate_label}  "
             f"timeout={eff_timeout}s  retries={eff_retries}")
    log.info(f"           source: MODULE_RATE_LIMITS['live']")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'fast'}")

    if eff_rate and eff_rate < 10:
        log.info("")
        log.info(f"  {chr(9888)}  rate_limit={eff_rate}/s is very conservative for httpx.")
        log.info(f"     httpx's default is {DEFAULT_RATE_LIMIT}/s. This stage DOES send")
        log.info(f"     target traffic — tune for your program's rules.")
        log.info("")

    # ── Headers ─────────────────────────────────────────────────────────────
    header_args, randomize_ua = _headers_for_httpx(headers)
    if header_args:
        log.info(f"  Headers: {(len(header_args) // 2)} configured")
        for i in range(0, min(len(header_args), 6), 2):
            log.info(f"           · {header_args[i + 1][:60]}")
        if not randomize_ua:
            log.info(f"           · (-random-agent disabled — UA set explicitly)")
        log.info("")
    else:
        log.info(f"  Headers: none — using httpx default UA")
        log.info("")

    # ── Run HTTPX ───────────────────────────────────────────────────────────
    log.info("  Probing with httpx...")
    raw_records, _ = _run_httpx(
        subs_file, eff_threads, eff_rate, eff_timeout, eff_retries,
        header_args, randomize_ua, evidence_dir, body_preview_len,
    )
    log.info(f"  Alive  : {len(raw_records)} / {len(subs)} responded")

    if not raw_records:
        log.warning("  No live hosts — writing empty report")
        return _write_empty_report(outdir, subs_file, start, len(subs))

    # ── Normalize ───────────────────────────────────────────────────────────
    log.info("  Normalizing records...")
    records = [_build_host_record(r) for r in raw_records]

    # ── Attribution + subs.py propagation ──────────────────────────────────
    if enrich_attribution:
        log.info("  Applying subs.py attribution + sensitivity...")
        src_map = _load_source_map(outdir)
        propagated = 0
        for rec in records:
            subs_rec = src_map.get(rec.get("subdomain") or "")
            if subs_rec:
                _apply_attribution(rec, subs_rec)
                propagated += 1
        log.info(f"    {propagated}/{len(records)} host(s) matched in subdomains.json")

    # ── Geo ─────────────────────────────────────────────────────────────────
    if resolve_geo:
        log.info("  Enriching with geo / ASN data...")
        _enrich_geo(records, outdir)
    else:
        log.info("  Geo enrichment disabled")

    # ── Classify ────────────────────────────────────────────────────────────
    log.info("  Classifying hosts...")
    src_map = _load_source_map(outdir) if enrich_attribution else {}
    for rec in records:
        subs_rec = src_map.get(rec.get("subdomain") or "")
        sev, categories, chain_ids, reasons, score = _classify(rec, subs_rec)
        rec["severity"]   = sev.value
        rec["categories"] = categories
        rec["chain_ids"]  = chain_ids
        rec["reasons"]    = reasons
        rec["score"]      = score
        rec["interesting"] = (score >= INTERESTING_MIN_SCORE
                              or sev.rank >= Severity.HIGH.rank)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    records.sort(key=lambda h: (
        SEV_ORDER.get(h.get("severity") or "LOW", 5),
        0 if h.get("interesting") else 1,
        h.get("subdomain") or "",
    ))

    # ── Save per-host evidence ──────────────────────────────────────────────
    _write_headers_evidence(records, evidence_dir)

    # ── Build chains + summary ──────────────────────────────────────────────
    chains  = _build_chains(records)
    summary = _build_summary(records)

    # ── Strip internal fields before JSON serialization ────────────────────
    clean_records = [_strip_internal(r) for r in records]

    # ── Full report ─────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    hdrs = _cfg("ACTIVE_HEADERS", {}) or {}
    report = {
        "schema_version":  4,
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":      str(subs_file),
        "aggressive":      aggressive,
        "config": {
            "threads":              eff_threads,
            "rate_limit":           eff_rate,
            "timeout":              eff_timeout,
            "retries":              eff_retries,
            "headers_count":        len(hdrs) + (len(headers) if headers else 0),
            "tech_detect":          ENABLE_TECH_DETECT,
            "cname":                ENABLE_CNAME,
            "cdn":                  ENABLE_CDN,
            "favicon":              ENABLE_FAVICON,
            "jarm":                 ENABLE_JARM,
            "follow_redirects":     ENABLE_FOLLOW_REDIRECTS,
            "tls_grab":             ENABLE_TLS_GRAB,
            "body_preview_len":     body_preview_len,
            "geo_enabled":          resolve_geo,
        },
        "totals": {
            "input":       len(subs),
            "alive":       len(records),
            "interesting": summary["interesting"],
            "by_severity": summary["by_severity"],
        },
        "summary": summary,
        "chains":  chains,
        "hosts":   clean_records,
    }
    json_path = outdir / "live_hosts.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Confirmed-only report (HIGH+) ──────────────────────────────────────
    confirmed = [r for r in clean_records
                 if (r.get("severity") or "LOW") in ("HIGH", "CRITICAL")]
    (outdir / "live_hosts_confirmed.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "input_file":     str(subs_file),
        "totals": {
            "confirmed": len(confirmed),
            "critical":  sum(1 for r in confirmed
                             if r.get("severity") == "CRITICAL"),
            "high":      sum(1 for r in confirmed
                             if r.get("severity") == "HIGH"),
            "by_chain":  {cid: sum(1 for r in confirmed if cid in (r.get("chain_ids") or []))
                          for cid in {c for r in confirmed
                                      for c in (r.get("chain_ids") or [])}},
        },
        "findings": confirmed,
    }, indent=2, ensure_ascii=False) + "\n")

    # ── Chains report ──────────────────────────────────────────────────────
    (outdir / "live_hosts_chains.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "chains":         chains,
    }, indent=2, ensure_ascii=False) + "\n")

    # ── Text outputs ────────────────────────────────────────────────────────
    txt_path  = _write_live_hosts_txt(clean_records, outdir)
    urls_path = _write_live_urls_txt(clean_records, outdir)

    # ── Self-sync (standalone only) ────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, records)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    live_hosts.json              {len(records):>5} host(s)")
    log.info(f"    live_hosts_confirmed.json    {len(confirmed):>5} HIGH+ finding(s)")
    log.info(f"    live_hosts_chains.json       {len(chains):>5} chain(s)")
    log.info(f"    live_hosts.txt               {len(records):>5} line(s)")
    log.info(f"    live_urls.txt                {len({r['url'] for r in records if r.get('url')}):>5} URL(s)")
    log.info(f"    live_evidence/               "
             f"{len([r for r in records if r.get('interesting')]):>5} header file(s)")

    log.info("")
    log.info(f"  Interesting: {summary['interesting']} host(s) flagged for triage")
    for r in [x for x in clean_records if x["interesting"]][:5]:
        tag = ",".join((r.get("reasons") or [])[:3])
        log.info(f"    [{r['severity']:<8}] {r['status_code']:>3} "
                 f"{r['subdomain']:<38} [{tag}]")

    log.info("")
    log.info(f"  Severity : CRITICAL={summary['by_severity']['CRITICAL']}  "
             f"HIGH={summary['by_severity']['HIGH']}  "
             f"MEDIUM={summary['by_severity']['MEDIUM']}  "
             f"LOW={summary['by_severity']['LOW']}")

    if summary["by_waf"]:
        log.info(f"  WAF      : " + " · ".join(
            f"{k}({v})" for k, v in list(summary["by_waf"].items())[:5]))
    if summary["by_cloud"]:
        log.info(f"  Cloud    : " + " · ".join(
            f"{k}({v})" for k, v in list(summary["by_cloud"].items())[:5]))
    if summary["by_technology"]:
        log.info(f"  Tech     : " + " · ".join(
            f"{t}({n})" for t, n in list(summary["by_technology"].items())[:6]))

    if chains:
        log.info("")
        log.info("  Chains   : " + " · ".join(
            f"{c['chain_id']}({c['severity']})" for c in chains[:6]))

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, subs_file: Path, start: float, input_count: int = 0,
) -> Path:
    empty_report = {
        "schema_version":  4,
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(subs_file),
        "config":          {},
        "totals":          {"input": input_count, "alive": 0,
                            "interesting": 0,
                            "by_severity": {"CRITICAL": 0, "HIGH": 0,
                                            "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        "summary":         {},
        "chains":          [],
        "hosts":           [],
    }
    path = outdir / "live_hosts.json"
    path.write_text(json.dumps(empty_report, indent=2) + "\n")
    (outdir / "live_hosts_confirmed.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "input_file":     str(subs_file),
        "totals":         {"confirmed": 0, "critical": 0, "high": 0, "by_chain": {}},
        "findings":       [],
    }, indent=2) + "\n")
    (outdir / "live_hosts_chains.json").write_text(json.dumps({
        "schema_version": 4,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "chains":         [],
    }, indent=2) + "\n")
    (outdir / "live_hosts.txt").write_text("")
    (outdir / "live_urls.txt").write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(message)s",
                        handlers=[logging.StreamHandler(sys.stdout)])
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Argus sub_discovery v4.0 (standalone)")
    parser.add_argument("--input",  type=Path, default=base / "output" / "all_subs.txt")
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id",    type=int, default=None)
    parser.add_argument("--threads",    type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--no-geo",     action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    args = parser.parse_args()

    try:
        discover_live(
            args.input, args.output,
            threads=args.threads,
            rate_limit=args.rate_limit,
            resolve_geo=not args.no_geo,
            aggressive=args.aggressive,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback; log.debug(traceback.format_exc()); sys.exit(1)
