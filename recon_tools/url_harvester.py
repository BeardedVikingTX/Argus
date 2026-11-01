#!/usr/bin/env python3
"""
recon_tools/url_harvester.py — URL & Endpoint Harvesting
═══════════════════════════════════════════════════════════════════════════════

URL collection stage for Argus. Turns live hosts into a comprehensive,
deduplicated, verified inventory of every URL the target exposes.

Two-traffic-mode module
───────────────────────
  • Archives (gau, waybackurls) — query THIRD-PARTY services (Wayback,
    Common Crawl, OTX, URLScan). NO target traffic. NO headers.
  • Target (katana, subjs, httpx) — hit the target directly. Platform
    headers + request.txt auth ARE applied. Rate limits ARE honored.

Config integration:
  • MODULE_RATE_LIMITS["urls"]     → katana -rl, httpx -rate-limit
  • ACTIVE_HEADERS + AUTH_HEADERS  → katana -H, httpx -H
  • AUTH_COOKIES                   → httpx -b
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Accuracy improvements over v1:
  • Katana JSONL field preservation: tag (a/form/script/img), attribute,
    method, source, forms. A URL from `<form action>` is 10× more interesting
    than one from `<img src>`. We now distinguish them.
  • httpx enrichment: title, tech, web-server, redirect chain, IP, CNAME.
  • Interesting-pattern reasons: instead of a boolean, we capture WHICH
    pattern matched (admin, login, debug, upload, ssrf_param, ...).
  • Passive-only mode: skip katana + subjs + httpx for speed.
  • Root-scope enforcement: `-fs rdn` on katana + post-hoc wildcard filter.

Outputs (into `outdir`):
  • all_urls.txt                — every verified URL
  • urls_with_params.txt        — URLs containing query strings
  • urls_js_files.txt           — JavaScript file URLs
  • urls_interesting.txt        — URLs matching high-value patterns
  • url_harvest.json            — full structured report

Remote DB (if scan_id is provided):
  • urls table                  — one row per (scan_id, url)

Integration:
  main.py → run_one("urls") → run_url_harvest(live_urls_file, outdir, wildcard_file)
"""

from __future__ import annotations

import json
import logging
import re
import shutil
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

log = logging.getLogger("argus.url_harvester")

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


def _url_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("urls", {})
    return {
        "rate_limit":  entry.get("rate_limit", 50),
        "concurrency": entry.get("concurrency", 10),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _tool_header_args() -> list[str]:
    return [f"{k}: {v}" for k, v in _target_headers().items()]


def _auth_cookie_header() -> Optional[str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return None
    cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

GAU_TIMEOUT             = 600
WAYBACKURLS_TIMEOUT     = 300
KATANA_TIMEOUT          = 900
SUBJS_TIMEOUT           = 180
URO_TIMEOUT             = 120
HTTPX_TIMEOUT           = 1800

MAX_HOSTS               = 1000
MAX_URLS_PER_HOST       = 50000
MAX_DB_URLS             = 200000

# Katana defaults (overridable via config)
KATANA_DEPTH            = 3
KATANA_CONCURRENCY      = 10
KATANA_PARALLELISM      = 10
KATANA_RATE_LIMIT       = 50
KATANA_HEADLESS         = False
KATANA_JS_CRAWL         = True
KATANA_XHR_CRAWL        = True
KATANA_EXTRACT_FORMS    = True

GAU_PROVIDERS           = ["wayback", "commoncrawl", "otx", "urlscan"]
GAU_THREADS             = 5
GAU_BLACKLIST           = [
    "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
    "ttf", "eot", "css", "map",
]

HTTPX_THREADS           = 50
HTTPX_RATE_LIMIT        = 150
HTTPX_STATUS_CODES      = "200,201,204,301,302,307,308,401,403"

# ── Interesting patterns with labels ────────────────────────────────────────
INTERESTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("admin",     re.compile(r"/(admin|administrator|dashboard|console|management|panel|cp|control)(/|$|\?)", re.I)),
    ("login",     re.compile(r"/(login|signin|sign-in|logout|signout|register|signup|sign-up|auth|sso|oauth|saml|cas|ldap)(/|$|\?)", re.I)),
    ("api",       re.compile(r"/(api|rest|v\d+|graphql|graphiql)(/|$|\?|\.)", re.I)),
    ("internal",  re.compile(r"/(internal|private|backend|backoffice|intranet)(/|$|\?)", re.I)),
    ("debug",     re.compile(r"/(debug|test|dev|develop|staging|trace|actuator|metrics|health|status|info|env|config)(/|$|\?)", re.I)),
    ("docs",      re.compile(r"/(swagger|openapi|api-docs|docs|redoc|rapidoc)(/|$|\?)", re.I)),
    ("backup",    re.compile(r"(\.bak|\.backup|\.old|\.orig|\.swp|\.save|/backup|/backups)(/|$|\?)", re.I)),
    ("source_git",re.compile(r"(\.git|\.svn|\.hg|\.bzr)(/|$)", re.I)),
    ("secrets",   re.compile(r"(\.env|\.htaccess|\.DS_Store|wp-config|credentials|secrets)(/|$|\.)", re.I)),
    ("wp",        re.compile(r"/wp-(admin|content|includes|config|login)", re.I)),
    ("upload",    re.compile(r"/(upload|uploads|attachment|attachments|file|files|download|media)(/|$|\?)", re.I)),
    ("panel",     re.compile(r"/(jenkins|grafana|kibana|prometheus|consul|vault|jira|confluence|gitlab|phpmyadmin|webmin|cpanel|plesk)(/|$|\?)", re.I)),
    ("ssrf_param",re.compile(r"[?&](url|uri|redirect|next|return|dest|destination|target|callback|continue|goto|proxy|fetch|load)=", re.I)),
    ("file_param",re.compile(r"[?&](file|filename|path|filepath|doc|document|page|include|template)=", re.I)),
    ("inject_param", re.compile(r"[?&](cmd|exec|execute|command|run|shell|query|q|search|sql|select)=", re.I)),
]

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp4", ".webm", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class URLSource:
    name: str
    urls: set[str] = field(default_factory=set)
    error: str = ""
    duration: float = 0.0

    @property
    def count(self) -> int:
        return len(self.urls)


@dataclass
class HarvestResult:
    url: str
    sources: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    attributes: set[str] = field(default_factory=set)
    form_actions: list[str] = field(default_factory=list)
    is_form: bool = False
    has_params: bool = False
    is_js: bool = False
    is_interesting: bool = False
    interesting_reasons: list[str] = field(default_factory=list)
    status: int = 0
    content_type: str = ""
    content_length: Optional[int] = None
    title: str = ""
    webserver: str = ""
    technologies: list[str] = field(default_factory=list)
    final_url: str = ""
    redirect_chain: list[int] = field(default_factory=list)
    response_time: str = ""
    resolved_ip: str = ""
    cname: str = ""
    alive: bool = False
    auth_enabled: bool = False
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "url":                 self.url,
            "sources":             sorted(self.sources),
            "source_count":        len(self.sources),
            "methods":             sorted(self.methods),
            "tags":                sorted(self.tags),
            "attributes":          sorted(self.attributes),
            "form_actions":        self.form_actions[:50],
            "is_form":             self.is_form,
            "has_params":          self.has_params,
            "is_js":               self.is_js,
            "is_interesting":      self.is_interesting,
            "interesting_reasons": self.interesting_reasons,
            "status":              self.status,
            "content_type":        self.content_type,
            "content_length":      self.content_length,
            "title":               self.title,
            "webserver":           self.webserver,
            "technologies":        self.technologies,
            "final_url":           self.final_url,
            "redirect_chain":      self.redirect_chain,
            "response_time":       self.response_time,
            "resolved_ip":         self.resolved_ip,
            "cname":               self.cname,
            "alive":               self.alive,
            "auth_enabled":        self.auth_enabled,
            "first_seen":          self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT
# ═════════════════════════════════════════════════════════════════════════════

def _load_hosts(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    hosts: list[str] = []
    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        parsed = urllib.parse.urlparse(token)
        if not parsed.hostname:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if base not in seen:
            seen.add(base)
            hosts.append(base)
    return hosts


def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    if not wildcard_file or not wildcard_file.exists():
        return []
    return [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# ═════════════════════════════════════════════════════════════════════════════
#  NORMALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_url(url: str) -> Optional[str]:
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return None
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return None
    path_lower = parsed.path.lower()
    for ext in STATIC_EXTENSIONS:
        if path_lower.endswith(ext):
            return None
    normalized = urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        "",
    ))
    return normalized


# ═════════════════════════════════════════════════════════════════════════════
#  INTERESTING CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _classify_interesting(url: str) -> tuple[bool, list[str]]:
    """Return (is_interesting, reasons) with all matching pattern labels."""
    reasons: list[str] = []
    for label, pattern in INTERESTING_PATTERNS:
        if pattern.search(url):
            reasons.append(label)
    return (bool(reasons), reasons)


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE 1 — ARCHIVES (no target traffic)
# ═════════════════════════════════════════════════════════════════════════════

def _run_gau(domain: str) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="gau")

    if not shutil.which("gau"):
        source.error = "gau not installed"
        source.duration = time.monotonic() - start
        return source

    cmd = [
        "gau", domain,
        "--threads", str(GAU_THREADS),
        "--subs",
        "--providers", ",".join(GAU_PROVIDERS),
        "--blacklist", ",".join(GAU_BLACKLIST),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GAU_TIMEOUT)
    except subprocess.TimeoutExpired:
        source.error = f"timeout after {GAU_TIMEOUT}s"
        source.duration = time.monotonic() - start
        return source
    except FileNotFoundError:
        source.error = "gau binary not found"
        source.duration = time.monotonic() - start
        return source

    for line in result.stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            source.urls.add(url)

    if not source.urls and result.returncode != 0:
        source.error = result.stderr.strip()[:200] or "gau failed"

    source.duration = time.monotonic() - start
    return source


def _run_waybackurls(domain: str) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="waybackurls")

    if not shutil.which("waybackurls"):
        source.error = "waybackurls not installed"
        source.duration = time.monotonic() - start
        return source

    try:
        result = subprocess.run(
            ["waybackurls", domain],
            capture_output=True, text=True, timeout=WAYBACKURLS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        source.error = f"timeout after {WAYBACKURLS_TIMEOUT}s"
        source.duration = time.monotonic() - start
        return source
    except FileNotFoundError:
        source.error = "waybackurls binary not found"
        source.duration = time.monotonic() - start
        return source

    for line in result.stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            source.urls.add(url)

    source.duration = time.monotonic() - start
    return source


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE 2 — KATANA (target traffic, headers applied)
# ═════════════════════════════════════════════════════════════════════════════

def _run_katana(
    hosts: list[str], workdir: Path,
    rate_limit: int, concurrency: int,
    header_args: list[str], root_domains: list[str],
) -> tuple[URLSource, dict[str, dict]]:
    """
    Crawl every host with katana. Returns (URLSource, per-URL metadata dict).

    Metadata captures katana JSONL fields beyond the URL: tag, attribute,
    method, source, forms — so we can distinguish a link from a form action
    from an XHR endpoint.
    """
    start = time.monotonic()
    source = URLSource(name="katana")
    metadata: dict[str, dict] = {}

    if not shutil.which("katana"):
        source.error = "katana not installed"
        source.duration = time.monotonic() - start
        return source, metadata

    hostfile = workdir / "katana_hosts.txt"
    hostfile.write_text("\n".join(hosts) + "\n")

    cmd = [
        "katana",
        "-list", str(hostfile),
        "-d", str(KATANA_DEPTH),
        "-kf", "all",
        "-c", str(concurrency),
        "-p", str(KATANA_CONCURRENCY),
        "-timeout", "10",
        "-retry", "1",
        "-silent",
        "-jsonl",
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])
    if KATANA_JS_CRAWL:
        cmd.append("-jc")
    if KATANA_XHR_CRAWL:
        cmd.append("-xhr")
    if KATANA_EXTRACT_FORMS:
        cmd.append("-fx")
    if KATANA_HEADLESS:
        cmd.extend(["-hl", "-nos"])

    # Root-domain scope filter (prevents crawling off-scope)
    if root_domains:
        cmd.extend(["-fs", "rdn"])

    # Auth headers
    for hdr in header_args:
        cmd.extend(["-H", hdr])

    log.info(f"      katana  {len(hosts)} host(s)  depth={KATANA_DEPTH}  "
             f"js={KATANA_JS_CRAWL}  xhr={KATANA_XHR_CRAWL}  "
             f"forms={KATANA_EXTRACT_FORMS}  headless={KATANA_HEADLESS}  "
             f"rl={rate_limit}/s")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=KATANA_TIMEOUT)
    except subprocess.TimeoutExpired:
        source.error = f"timeout after {KATANA_TIMEOUT}s (partial results used)"
        log.warning(f"      katana timeout — using partial output")
    except FileNotFoundError:
        source.error = "katana binary not found"
        source.duration = time.monotonic() - start
        return source, metadata

    # Parse even on timeout — partial stdout is still useful
    stdout = getattr(result, "stdout", "") if "result" in dir() else ""

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            url = _normalize_url(line)
            if url:
                source.urls.add(url)
            continue

        raw_url = obj.get("url") or obj.get("endpoint") or ""
        url = _normalize_url(raw_url)
        if not url:
            continue
        source.urls.add(url)

        # Preserve rich katana metadata
        entry = metadata.setdefault(url, {
            "methods": set(),
            "tags": set(),
            "attributes": set(),
            "form_actions": [],
        })
        if obj.get("method"):
            entry["methods"].add(str(obj["method"]).upper())
        if obj.get("tag"):
            entry["tags"].add(str(obj["tag"]).lower())
        if obj.get("attribute"):
            entry["attributes"].add(str(obj["attribute"]).lower())
        # Katana `-fx` emits nested form data
        for form in (obj.get("forms") or []):
            if isinstance(form, dict):
                action = form.get("action") or form.get("url")
                if action:
                    entry["form_actions"].append(str(action))

    if not source.urls and "result" in dir() and result.returncode != 0:
        source.error = result.stderr.strip()[:200] or "katana failed"

    source.duration = time.monotonic() - start
    return source, metadata


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE 3 — SUBJS (target traffic, but no header support)
# ═════════════════════════════════════════════════════════════════════════════

def _run_subjs(hosts: list[str]) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="subjs")

    if not shutil.which("subjs"):
        source.error = "subjs not installed"
        source.duration = time.monotonic() - start
        return source

    input_data = "\n".join(hosts)
    try:
        result = subprocess.run(
            ["subjs"], input=input_data,
            capture_output=True, text=True, timeout=SUBJS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        source.error = f"timeout after {SUBJS_TIMEOUT}s"
        source.duration = time.monotonic() - start
        return source
    except FileNotFoundError:
        source.error = "subjs binary not found"
        source.duration = time.monotonic() - start
        return source

    for line in result.stdout.splitlines():
        url = _normalize_url(line.strip())
        if url and url.lower().split("?")[0].endswith(".js"):
            source.urls.add(url)

    source.duration = time.monotonic() - start
    return source


# ═════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION (uro)
# ═════════════════════════════════════════════════════════════════════════════

def _run_uro(urls: list[str], workdir: Path) -> list[str]:
    if not urls:
        return []
    if not shutil.which("uro"):
        log.info("      uro not installed — using basic Python deduplication")
        return _basic_dedupe(urls)

    input_file = workdir / "uro_input.txt"
    input_file.write_text("\n".join(urls) + "\n")

    try:
        result = subprocess.run(
            ["uro", "-i", str(input_file)],
            capture_output=True, text=True, timeout=URO_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning("      uro timeout — falling back to basic dedup")
        return _basic_dedupe(urls)
    except FileNotFoundError:
        return _basic_dedupe(urls)

    deduped: list[str] = []
    for line in result.stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            deduped.append(url)
    if not deduped:
        return _basic_dedupe(urls)
    log.info(f"      uro reduced {len(urls)} → {len(deduped)} URL(s)")
    return deduped


def _basic_dedupe(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        key = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            "",
            urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query))),
            "",
        ))
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  LIVENESS VERIFICATION (httpx, headers + cookies applied)
# ═════════════════════════════════════════════════════════════════════════════

def _verify_liveness(
    urls: list[str], workdir: Path,
    rate_limit: int, concurrency: int,
    header_args: list[str], cookie_header: Optional[str],
) -> tuple[set[str], dict[str, dict]]:
    """Pipe URLs through httpx. Returns (live_urls, metadata)."""
    if not urls:
        return set(), {}

    if not shutil.which("httpx"):
        log.warning("      httpx not installed — skipping liveness verification")
        return set(urls), {}

    input_file = workdir / "httpx_input.txt"
    input_file.write_text("\n".join(urls) + "\n")

    cmd = [
        "httpx",
        "-l", str(input_file),
        "-silent",
        "-sc",
        "-ct",
        "-title",
        "-tech-detect",
        "-web-server",
        "-location",
        "-follow-redirects",
        "-ip",
        "-threads", str(concurrency),
        "-timeout", "10",
        "-mc", HTTPX_STATUS_CODES,
        "-jsonl",
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])
    for hdr in header_args:
        cmd.extend(["-H", hdr])
    if cookie_header:
        cmd.extend(["-b", cookie_header])

    log.info(f"      httpx  {len(urls)} URL(s)  rl={rate_limit}/s  "
             f"c={concurrency}  headers={len(header_args)}  cookie={'yes' if cookie_header else 'no'}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTPX_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("      httpx timeout — using unverified URL list")
        return set(urls), {}
    except FileNotFoundError:
        return set(urls), {}

    live_urls: set[str] = set()
    metadata: dict[str, dict] = {}

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = _normalize_url(obj.get("url") or obj.get("input") or "")
        if not url:
            continue

        live_urls.add(url)
        metadata[url] = {
            "status":          obj.get("status_code") or 0,
            "content_type":    obj.get("content_type") or "",
            "content_length":  obj.get("content_length"),
            "title":           obj.get("title") or "",
            "webserver":       obj.get("webserver") or "",
            "technologies":    obj.get("tech") or [],
            "final_url":       obj.get("final_url") or "",
            "redirect_chain":  obj.get("chain_status_codes") or [],
            "response_time":   obj.get("time") or "",
            "resolved_ip":     obj.get("host") if obj.get("host") and _looks_like_ip(obj.get("host")) else "",
            "cname":           obj.get("cname") or "",
        }

    log.info(f"      httpx confirmed {len(live_urls)} / {len(urls)} live")
    return live_urls, metadata


def _looks_like_ip(s: str) -> bool:
    if not s:
        return False
    # IPv4 or IPv6 — very light heuristic
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in s


# ═════════════════════════════════════════════════════════════════════════════
#  ASSEMBLY & CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _build_results(
    urls: list[str],
    source_map: dict[str, set[str]],
    katana_meta: dict[str, dict],
    httpx_meta: dict[str, dict],
    auth_on: bool,
) -> list[HarvestResult]:
    """Assemble per-URL HarvestResult with all accumulated data."""
    now = datetime.now(timezone.utc).isoformat()
    results: list[HarvestResult] = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path_lower = parsed.path.lower()

        r = HarvestResult(
            url=url,
            sources=source_map.get(url, set()),
            auth_enabled=auth_on,
            first_seen=now,
        )
        r.has_params = bool(parsed.query)
        r.is_js = path_lower.endswith(".js")

        # Katana metadata
        km = katana_meta.get(url, {})
        if km:
            r.methods = set(km.get("methods") or set())
            r.tags = set(km.get("tags") or set())
            r.attributes = set(km.get("attributes") or set())
            r.form_actions = list(km.get("form_actions") or [])[:50]
            r.is_form = "form" in r.tags or bool(r.form_actions)

        # httpx metadata
        hm = httpx_meta.get(url, {})
        if hm:
            r.status = hm.get("status", 0)
            r.content_type = hm.get("content_type", "")
            r.content_length = hm.get("content_length")
            r.title = hm.get("title", "")
            r.webserver = hm.get("webserver", "")
            r.technologies = hm.get("technologies") or []
            r.final_url = hm.get("final_url", "")
            r.redirect_chain = hm.get("redirect_chain") or []
            r.response_time = hm.get("response_time", "")
            r.resolved_ip = hm.get("resolved_ip", "")
            r.cname = hm.get("cname", "")
            r.alive = r.status > 0

        # Interesting classification
        is_int, reasons = _classify_interesting(url)
        r.is_interesting = is_int
        r.interesting_reasons = reasons

        results.append(r)

    return results


def _write_split_outputs(results: list[HarvestResult], outdir: Path) -> dict[str, Path]:
    all_urls = sorted(r.url for r in results)
    with_params = sorted(r.url for r in results if r.has_params)
    js_files = sorted(r.url for r in results if r.is_js)
    interesting = sorted(r.url for r in results if r.is_interesting)

    paths = {
        "all":         outdir / "all_urls.txt",
        "params":      outdir / "urls_with_params.txt",
        "js":          outdir / "urls_js_files.txt",
        "interesting": outdir / "urls_interesting.txt",
    }
    paths["all"].write_text("\n".join(all_urls) + ("\n" if all_urls else ""))
    paths["params"].write_text("\n".join(with_params) + ("\n" if with_params else ""))
    paths["js"].write_text("\n".join(js_files) + ("\n" if js_files else ""))
    paths["interesting"].write_text("\n".join(interesting) + ("\n" if interesting else ""))
    return paths


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, results: list[HarvestResult]) -> None:
    if not results:
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
    if len(results) > MAX_DB_URLS:
        log.warning(f"  DB sync: capping at {MAX_DB_URLS} URLs (had {len(results)})")
        results = results[:MAX_DB_URLS]

    try:
        payloads = [r.to_dict() for r in results]
        result = DB.upsert_urls(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} URL(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_url_harvest(
    live_urls_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    use_archives: bool = True,
    use_katana: bool = True,
    use_subjs: bool = True,
    verify_liveness: bool = True,
    passive_only: bool = False,
    max_hosts: int = MAX_HOSTS,
    katana_rate_limit: Optional[int] = None,
    katana_concurrency: Optional[int] = None,
    headers: Optional[dict] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Harvest every URL and endpoint from the hosts in `live_urls_file`.

    Passive-only mode skips katana + subjs + httpx — archive sources only.
    Use it for fast first-pass discovery.

    Returns the path to `url_harvest.json`.
    """
    start = time.monotonic()

    settings = _url_settings()
    eff_rate = katana_rate_limit if katana_rate_limit is not None else settings["rate_limit"]
    eff_conc = katana_concurrency if katana_concurrency is not None else settings["concurrency"]

    hosts = _load_hosts(live_urls_file)
    if len(hosts) > max_hosts:
        log.warning(f"  Capping at {max_hosts} hosts (input had {len(hosts)})")
        hosts = hosts[:max_hosts]

    roots = _load_roots(wildcard_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "url_work"
    workdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)
    header_args = [f"{k}: {v}" for k, v in cfg_hdrs.items()]
    cookie_header = _auth_cookie_header()

    log.info(f"  Input  : {len(hosts)} host(s) from {live_urls_file.name}")
    log.info(f"  Roots  : {len(roots)} wildcard(s)")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
             f"passive_only={passive_only}")
    log.info(f"           source: MODULE_RATE_LIMITS['urls']")

    if cfg_hdrs and not passive_only:
        log.info(f"  Headers: {len(cfg_hdrs)} configured → katana + httpx")
        for k, v in list(cfg_hdrs.items())[:4]:
            v_short = v[:50] + "…" if len(v) > 50 else v
            log.info(f"           · {k}: {v_short}")
        if len(cfg_hdrs) > 4:
            log.info(f"           · ... and {len(cfg_hdrs) - 4} more")
    elif not passive_only:
        log.info(f"  Headers: none configured")

    if auth_on and not passive_only:
        log.info(f"  Auth   : ENABLED (request.txt){' + cookies' if cookie_header else ''}")
    elif not passive_only:
        log.info(f"  Auth   : disabled")

    if passive_only:
        log.info(f"  Mode   : PASSIVE (archives only — no target traffic)")
    log.info("")

    if not hosts:
        log.warning("  No hosts to harvest — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Collect sources ────────────────────────────────────────────────────
    sources: list[URLSource] = []
    katana_meta: dict[str, dict] = {}
    source_map: dict[str, set[str]] = {}

    def _record_source(src: URLSource) -> None:
        sources.append(src)
        for url in src.urls:
            source_map.setdefault(url, set()).add(src.name)

    # ── Archives ───────────────────────────────────────────────────────────
    if use_archives and roots:
        log.info("  Source 1 — Archives (no target traffic)")
        with ThreadPoolExecutor(max_workers=min(len(roots) * 2, 8)) as pool:
            futures = {}
            for root in roots:
                futures[pool.submit(_run_gau, root)] = ("gau", root)
                futures[pool.submit(_run_waybackurls, root)] = ("waybackurls", root)

            for fut in as_completed(futures):
                src_name, root = futures[fut]
                try:
                    src = fut.result()
                except Exception as e:
                    src = URLSource(name=src_name, error=str(e))
                _record_source(src)
                status = f"✓ {src.count:>5} URLs" if not src.error else f"✗ {src.error}"
                log.info(f"    {src_name:<14} {root:<24} {status}  ({src.duration:.1f}s)")
    else:
        log.info("  Source 1 — Archives skipped")

    # ── Katana (target traffic) ────────────────────────────────────────────
    if use_katana and not passive_only:
        log.info("")
        log.info("  Source 2 — Live crawl (katana, headers applied)")
        katana_src, katana_meta = _run_katana(
            hosts, workdir, eff_rate, eff_conc, header_args, roots,
        )
        _record_source(katana_src)
        status = f"✓ {katana_src.count:>5} URLs" if not katana_src.error else f"✗ {katana_src.error}"
        log.info(f"    katana         {status}  ({katana_src.duration:.1f}s)")
    else:
        log.info("")
        log.info("  Source 2 — katana skipped" + (" (passive)" if passive_only else ""))

    # ── subjs ──────────────────────────────────────────────────────────────
    if use_subjs and not passive_only:
        log.info("")
        log.info("  Source 3 — JavaScript refs (subjs, no header support)")
        subjs_src = _run_subjs(hosts)
        _record_source(subjs_src)
        status = f"✓ {subjs_src.count:>5} JS files" if not subjs_src.error else f"✗ {subjs_src.error}"
        log.info(f"    subjs          {status}  ({subjs_src.duration:.1f}s)")
    else:
        log.info("")
        log.info("  Source 3 — subjs skipped" + (" (passive)" if passive_only else ""))

    # ── Merge ──────────────────────────────────────────────────────────────
    all_urls: set[str] = set()
    for src in sources:
        all_urls.update(src.urls)
    log.info("")
    log.info(f"  Merged : {len(all_urls)} unique URL(s) before filtering")

    # ── Scope filter ───────────────────────────────────────────────────────
    if roots:
        scoped: set[str] = set()
        for url in all_urls:
            host = urllib.parse.urlparse(url).hostname or ""
            if any(host == r or host.endswith("." + r) for r in roots):
                scoped.add(url)
        if len(scoped) < len(all_urls):
            log.info(f"  Scope  : {len(all_urls)} → {len(scoped)} "
                     f"(filtered {len(all_urls) - len(scoped)} out-of-scope)")
        all_urls = scoped

    url_list = sorted(all_urls)
    if len(url_list) > MAX_URLS_PER_HOST * len(hosts):
        cap = MAX_URLS_PER_HOST * len(hosts)
        log.warning(f"  Capping at {cap} URLs (had {len(url_list)})")
        url_list = url_list[:cap]

    # ── Dedupe ─────────────────────────────────────────────────────────────
    log.info("")
    log.info("  Deduplication (uro)")
    deduped = _run_uro(url_list, workdir)

    # ── Verify liveness ────────────────────────────────────────────────────
    httpx_meta: dict[str, dict] = {}
    if verify_liveness and not passive_only and deduped:
        log.info("")
        log.info("  Liveness verification (httpx, headers applied)")
        live_set, httpx_meta = _verify_liveness(
            deduped, workdir, eff_rate, eff_conc, header_args, cookie_header,
        )
        if live_set:
            deduped = sorted(live_set)
        else:
            log.info("      (httpx unavailable — keeping unverified list)")

    # ── Build results ──────────────────────────────────────────────────────
    results = _build_results(
        deduped, source_map, katana_meta, httpx_meta, auth_on,
    )
    paths = _write_split_outputs(results, outdir)

    # ── Report ─────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_source: dict[str, dict] = {}
    for src in sources:
        by_source[src.name] = {
            "count":    src.count,
            "error":    src.error,
            "duration": round(src.duration, 2),
        }

    params_count = sum(1 for r in results if r.has_params)
    js_count = sum(1 for r in results if r.is_js)
    interesting_count = sum(1 for r in results if r.is_interesting)
    forms_count = sum(1 for r in results if r.is_form)
    multi_source = sum(1 for r in results if len(r.sources) > 1)

    # Aggregate interesting reasons
    reason_counts: dict[str, int] = {}
    for r in results:
        for reason in r.interesting_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "passive_only": passive_only,
        "config": {
            "use_archives":     use_archives,
            "use_katana":       use_katana and not passive_only,
            "use_subjs":        use_subjs and not passive_only,
            "verify_liveness":  verify_liveness and not passive_only,
            "rate_limit":       eff_rate,
            "concurrency":      eff_conc,
            "headers_count":    len(cfg_hdrs),
            "cookie_set":       bool(cookie_header),
            "katana_depth":     KATANA_DEPTH,
            "katana_headless":  KATANA_HEADLESS,
            "katana_xhr":       KATANA_XHR_CRAWL,
            "katana_forms":     KATANA_EXTRACT_FORMS,
            "gau_providers":    GAU_PROVIDERS,
        },
        "totals": {
            "hosts":            len(hosts),
            "raw_urls":         len(all_urls),
            "deduped_urls":     len(results),
            "with_params":      params_count,
            "js_files":         js_count,
            "forms":            forms_count,
            "interesting":      interesting_count,
            "multi_source":     multi_source,
            "alive":            sum(1 for r in results if r.alive),
        },
        "interesting_reasons": dict(sorted(reason_counts.items(), key=lambda kv: -kv[1])),
        "sources": by_source,
        "urls": [r.to_dict() for r in results],
    }

    json_path = outdir / "url_harvest.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ──────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, results)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    all_urls.txt              {len(results):>6} URL(s)")
    log.info(f"    urls_with_params.txt      {params_count:>6} URL(s)")
    log.info(f"    urls_js_files.txt         {js_count:>6} JS file(s)")
    log.info(f"    urls_interesting.txt      {interesting_count:>6} URL(s)")

    log.info("")
    log.info(f"  Alive  : {sum(1 for r in results if r.alive)} / {len(results)} verified")
    log.info(f"  Forms  : {forms_count} URLs came from <form> elements")
    log.info(f"  Multi  : {multi_source} URLs found by 2+ sources")

    if reason_counts:
        log.info("")
        log.info("  Interesting reasons:")
        for label, count in list(reason_counts.items())[:10]:
            log.info(f"    {label:<14} {count:>5} URL(s)")

    if interesting_count:
        log.info("")
        log.info("  Sample interesting URLs:")
        for r in [x for x in results if x.is_interesting][:10]:
            reasons = ",".join(r.interesting_reasons[:3])
            log.info(f"    {r.status:>3}  {r.url[:80]:<80}  [{reasons}]")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(input_file),
        "auth_enabled":    bool(_cfg("AUTH_ENABLED", False)),
        "passive_only":    False,
        "config":          {},
        "totals": {
            "hosts": 0, "raw_urls": 0, "deduped_urls": 0,
            "with_params": 0, "js_files": 0, "forms": 0,
            "interesting": 0, "multi_source": 0, "alive": 0,
        },
        "interesting_reasons": {},
        "sources": {},
        "urls": [],
    }
    path = outdir / "url_harvest.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("all_urls.txt", "urls_with_params.txt",
                 "urls_js_files.txt", "urls_interesting.txt"):
        (outdir / name).write_text("")
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
    live = base / "output" / "live_urls.txt"
    wildcards = base / "wildcard.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus URL harvester (standalone)")
    parser.add_argument("--input", type=Path, default=live)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--wildcard-file", type=Path, default=wildcards)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--passive", action="store_true",
                        help="archives only — no katana, no httpx")
    parser.add_argument("--no-archives", action="store_true")
    parser.add_argument("--no-katana", action="store_true")
    parser.add_argument("--no-subjs", action="store_true")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    args = parser.parse_args()

    try:
        run_url_harvest(
            args.input, args.output,
            wildcard_file=args.wildcard_file,
            use_archives=not args.no_archives,
            use_katana=not args.no_katana,
            use_subjs=not args.no_subjs,
            verify_liveness=not args.no_verify,
            passive_only=args.passive,
            katana_rate_limit=args.rate_limit,
            katana_concurrency=args.concurrency,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
