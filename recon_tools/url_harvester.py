#!/usr/bin/env python3
"""
recon_tools/url_harvester.py — URL & Endpoint Harvesting
═══════════════════════════════════════════════════════════════════════════════

The URL collection stage for Argus. Turns live hosts into a comprehensive,
deduplicated, and verified map of every URL and endpoint the target exposes.

Three collection sources:

  1. Archives (gau + waybackurls)
       Historical URLs from the Wayback Machine, Common Crawl, AlienVault OTX,
       URLScan, and VirusTotal. Finds endpoints removed from the UI but often
       still live on the server[reference:1].

  2. Live crawl (katana)
       Current URLs, including JavaScript-rendered routes and endpoints that
       static HTML never links to. Uses -jc for JS parsing and optional -hl
       for headless rendering of SPAs[reference:2].

  3. JavaScript references (subjs)
       Discovers .js files that are then mined for embedded endpoints.

Post-collection pipeline:
  • Merge       — combine all sources, strip noise
  • Deduplicate — uro removes semantic duplicates (pagination, param values,
                  static assets) without making a single HTTP request[reference:3]
  • Verify      — httpx confirms which URLs actually respond
  • Split       — output separated by purpose (params, JS files, interesting)

Outputs (into `outdir`):
  • all_urls.txt                — every verified URL (deduplicated)
  • urls_with_params.txt        — URLs containing query strings (param_discovery input)
  • urls_js_files.txt           — JavaScript file URLs (js_analysis input)
  • urls_interesting.txt        — URLs matching high-value path patterns
  • url_harvest.json            — full structured report

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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# ── Execution limits ────────────────────────────────────────────────────────
GAU_TIMEOUT             = 600
WAYBACKURLS_TIMEOUT     = 300
KATANA_TIMEOUT          = 900
SUBJS_TIMEOUT           = 180
URO_TIMEOUT             = 120
HTTPX_TIMEOUT           = 1800

MAX_HOSTS               = 1000
MAX_URLS_PER_HOST       = 50000

# ── Crawler settings ────────────────────────────────────────────────────────
KATANA_DEPTH            = 3
KATANA_CONCURRENCY      = 10
KATANA_PARALLELISM      = 10
KATANA_RATE_LIMIT       = 50
KATANA_HEADLESS         = False   # set True for SPA-heavy targets
KATANA_JS_CRAWL         = True

# ── Archive sources ─────────────────────────────────────────────────────────
GAU_PROVIDERS           = ["wayback", "commoncrawl", "otx", "urlscan"]
GAU_THREADS             = 5
GAU_BLACKLIST           = ["png", "jpg", "jpeg", "gif", "svg", "ico", "woff",
                          "woff2", "ttf", "eot", "css", "map"]

# ── HTTPX verification ──────────────────────────────────────────────────────
HTTPX_THREADS           = 50
HTTPX_RATE_LIMIT        = 150
HTTPX_STATUS_CODES      = "200,201,204,301,302,307,308,401,403"

# ── Interesting path patterns ───────────────────────────────────────────────
INTERESTING_PATTERNS = [
    r"/api/", r"/v\d+/", r"/graphql", r"/admin", r"/internal",
    r"/debug", r"/actuator", r"/swagger", r"/openapi", r"/backup",
    r"/config", r"/\.git/", r"/\.env", r"/phpmyadmin", r"/jenkins",
    r"/grafana", r"/kibana", r"/prometheus", r"/metrics",
]
INTERESTING_RE = re.compile("|".join(INTERESTING_PATTERNS), re.I)

# ── Static asset extensions to skip ─────────────────────────────────────────
STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp4", ".webm", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
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
    has_params: bool = False
    is_js: bool = False
    is_interesting: bool = False
    status: int = 0
    content_type: str = ""
    alive: bool = False

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "sources":        sorted(self.sources),
            "has_params":     self.has_params,
            "is_js":          self.is_js,
            "is_interesting": self.is_interesting,
            "status":         self.status,
            "content_type":   self.content_type,
            "alive":          self.alive,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _load_hosts(input_file: Path) -> list[str]:
    """
    Accept live_urls.txt (bare URLs) or live_hosts.txt
    ('URL [status] [title] [tech]'). Return deduplicated base URLs.
    """
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
    """
    Clean a URL: lowercase scheme/host, strip fragments, remove default ports.
    Returns None for malformed or static-asset URLs.
    """
    if not url:
        return None

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return None

    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return None

    # Skip static assets by extension
    path_lower = parsed.path.lower()
    for ext in STATIC_EXTENSIONS:
        if path_lower.endswith(ext):
            return None

    # Strip fragment; keep query
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
#  SOURCE 1 — ARCHIVES (GAU + WAYBACKURLS)
# ═════════════════════════════════════════════════════════════════════════════

def _run_gau(domain: str) -> URLSource:
    """Run gau against a domain. Returns a URLSource."""
    start = time.monotonic()
    source = URLSource(name="gau")

    if not shutil.which("gau"):
        source.error = "gau not installed"
        source.duration = time.monotonic() - start
        return source

    cmd = [
        "gau",
        domain,
        "--threads", str(GAU_THREADS),
        "--subs",
        "--providers", ",".join(GAU_PROVIDERS),
        "--blacklist", ",".join(GAU_BLACKLIST),
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=GAU_TIMEOUT,
        )
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
    """Run waybackurls against a domain."""
    start = time.monotonic()
    source = URLSource(name="waybackurls")

    if not shutil.which("waybackurls"):
        source.error = "waybackurls not installed"
        source.duration = time.monotonic() - start
        return source

    cmd = ["waybackurls", domain]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=WAYBACKURLS_TIMEOUT,
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
#  SOURCE 2 — LIVE CRAWL (KATANA)
# ═════════════════════════════════════════════════════════════════════════════

def _run_katana(hosts: list[str], workdir: Path) -> URLSource:
    """
    Crawl every host with katana. Uses -jc for JS parsing, -kf for known
    files (robots.txt, sitemap.xml), and -jsonl for structured output.
    """
    start = time.monotonic()
    source = URLSource(name="katana")

    if not shutil.which("katana"):
        source.error = "katana not installed"
        source.duration = time.monotonic() - start
        return source

    hostfile = workdir / "katana_hosts.txt"
    hostfile.write_text("\n".join(hosts) + "\n")

    cmd = [
        "katana",
        "-list", str(hostfile),
        "-d", str(KATANA_DEPTH),
        "-jc",                                  # JS endpoint parsing[reference:4]
        "-kf", "all",                           # robots.txt + sitemap.xml[reference:5]
        "-c", str(KATANA_CONCURRENCY),
        "-p", str(KATANA_PARALLELISM),
        "-rl", str(KATANA_RATE_LIMIT),
        "-timeout", "10",
        "-retry", "1",
        "-silent",
        "-jsonl",
    ]

    if KATANA_HEADLESS:
        cmd.extend(["-hl", "-nos"])             # headless for SPAs[reference:6]

    log.info(f"      katana  {len(hosts)} host(s)  "
             f"depth={KATANA_DEPTH}  js-crawl={KATANA_JS_CRAWL}  "
             f"headless={KATANA_HEADLESS}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=KATANA_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        source.error = f"timeout after {KATANA_TIMEOUT}s"
        source.duration = time.monotonic() - start
        return source
    except FileNotFoundError:
        source.error = "katana binary not found"
        source.duration = time.monotonic() - start
        return source

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Fallback: plain URL line
            url = _normalize_url(line)
            if url:
                source.urls.add(url)
            continue

        # Katana JSONL: {"timestamp":"...","url":"...","endpoint":"..."}
        raw_url = obj.get("url") or obj.get("endpoint") or ""
        url = _normalize_url(raw_url)
        if url:
            source.urls.add(url)

    if not source.urls and result.returncode != 0:
        source.error = result.stderr.strip()[:200] or "katana failed"

    source.duration = time.monotonic() - start
    return source


# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE 3 — JAVASCRIPT REFERENCES (SUBJS)
# ═════════════════════════════════════════════════════════════════════════════

def _run_subjs(hosts: list[str]) -> URLSource:
    """Use subjs to extract JavaScript URLs from the host list."""
    start = time.monotonic()
    source = URLSource(name="subjs")

    if not shutil.which("subjs"):
        source.error = "subjs not installed"
        source.duration = time.monotonic() - start
        return source

    input_data = "\n".join(hosts)
    try:
        result = subprocess.run(
            ["subjs"],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=SUBJS_TIMEOUT,
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
#  DEDUPLICATION (URO)
# ═════════════════════════════════════════════════════════════════════════════

def _run_uro(urls: list[str], workdir: Path) -> list[str]:
    """
    Pipe URLs through uro for semantic deduplication. Removes pagination
    variants, static assets, and URLs with the same path but different
    parameter values — all without making a single HTTP request[reference:7].
    """
    if not urls:
        return []

    if not shutil.which("uro"):
        log.info("      uro not installed — using basic Python deduplication")
        return _basic_dedupe(urls)

    input_file = workdir / "uro_input.txt"
    input_file.write_text("\n".join(urls) + "\n")

    cmd = [
        "uro",
        "-i", str(input_file),
        "--filters", "hasparams",  # keep all, but let uro handle noise
    ]

    log.info(f"      uro  {len(urls)} URL(s)")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=URO_TIMEOUT,
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
    """Fallback deduplication: normalize scheme/host, strip trailing slash."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        # Collapse parameter order and remove trailing slash
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)
        sorted_params = sorted(params)
        key = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            "",
            urllib.parse.urlencode(sorted_params),
            "",
        ))
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  LIVENESS VERIFICATION (HTTPX)
# ═════════════════════════════════════════════════════════════════════════════

def _verify_liveness(urls: list[str], workdir: Path) -> tuple[set[str], dict[str, dict]]:
    """
    Pipe URLs through httpx to confirm which actually respond.

    Returns:
      • live_urls: set of URLs that responded
      • metadata:  dict of url → {status, content_type}
    """
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
        "-ct",                                   # content-type
        "-threads", str(HTTPX_THREADS),
        "-rate-limit", str(HTTPX_RATE_LIMIT),
        "-timeout", "10",
        "-mc", HTTPX_STATUS_CODES,
        "-jsonl",
    ]

    log.info(f"      httpx  {len(urls)} URL(s)")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=HTTPX_TIMEOUT,
        )
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

        status = obj.get("status_code") or 0
        content_type = obj.get("content_type") or ""
        live_urls.add(url)
        metadata[url] = {
            "status": status,
            "content_type": content_type,
        }

    log.info(f"      httpx confirmed {len(live_urls)} / {len(urls)} live")
    return live_urls, metadata


# ═════════════════════════════════════════════════════════════════════════════
#  CLASSIFICATION & SPLITTING
# ═════════════════════════════════════════════════════════════════════════════

def _classify_urls(urls: list[str], metadata: dict[str, dict]) -> list[HarvestResult]:
    """Build HarvestResult records with classification flags."""
    results: list[HarvestResult] = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        r = HarvestResult(url=url)
        r.has_params = bool(parsed.query)
        r.is_js = path.endswith(".js")
        r.is_interesting = bool(INTERESTING_RE.search(url))

        meta = metadata.get(url, {})
        r.status = meta.get("status", 0)
        r.content_type = meta.get("content_type", "")
        r.alive = r.status > 0

        results.append(r)
    return results


def _write_split_outputs(results: list[HarvestResult], outdir: Path) -> dict[str, Path]:
    """Write URLs split by purpose."""
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
    max_hosts: int = MAX_HOSTS,
) -> Path:
    """
    Harvest every URL and endpoint from the hosts in `live_urls_file`.

    Returns the path to `url_harvest.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    hosts = _load_hosts(live_urls_file)
    if len(hosts) > max_hosts:
        log.warning(f"  Capping at {max_hosts} hosts (input had {len(hosts)})")
        hosts = hosts[:max_hosts]

    roots = _load_roots(wildcard_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "url_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(hosts)} host(s) from {live_urls_file.name}")
    log.info(f"  Roots  : {len(roots)} wildcard(s)")
    log.info("")

    if not hosts:
        log.warning("  No hosts to harvest — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Collect from all sources ────────────────────────────────────────────
    sources: list[URLSource] = []

    # Archives: gau and waybackurls per root domain
    if use_archives and roots:
        log.info("  Source 1 — Archives (gau + waybackurls)")
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
                sources.append(src)
                status = f"✓ {src.count:>5} URLs" if not src.error else f"✗ {src.error}"
                log.info(f"    {src_name:<14} {root:<24} {status}  ({src.duration:.1f}s)")
    else:
        log.info("  Source 1 — Archives skipped")

    # Live crawl: katana against all hosts
    if use_katana:
        log.info("")
        log.info("  Source 2 — Live crawl (katana)")
        katana_src = _run_katana(hosts, workdir)
        sources.append(katana_src)
        status = f"✓ {katana_src.count:>5} URLs" if not katana_src.error else f"✗ {katana_src.error}"
        log.info(f"    katana         {status}  ({katana_src.duration:.1f}s)")
    else:
        log.info("  Source 2 — katana skipped")

    # JS references: subjs
    if use_subjs:
        log.info("")
        log.info("  Source 3 — JavaScript references (subjs)")
        subjs_src = _run_subjs(hosts)
        sources.append(subjs_src)
        status = f"✓ {subjs_src.count:>5} JS files" if not subjs_src.error else f"✗ {subjs_src.error}"
        log.info(f"    subjs          {status}  ({subjs_src.duration:.1f}s)")
    else:
        log.info("  Source 3 — subjs skipped")

    # ── Merge all URLs ──────────────────────────────────────────────────────
    all_urls: set[str] = set()
    for src in sources:
        all_urls.update(src.urls)

    log.info("")
    log.info(f"  Merged : {len(all_urls)} unique URL(s) before filtering")

    # ── Filter to in-scope roots ────────────────────────────────────────────
    if roots:
        scoped_urls: set[str] = set()
        for url in all_urls:
            host = urllib.parse.urlparse(url).hostname or ""
            if any(host == r or host.endswith("." + r) for r in roots):
                scoped_urls.add(url)
        if len(scoped_urls) < len(all_urls):
            log.info(f"  Scope  : {len(all_urls)} → {len(scoped_urls)} "
                     f"(filtered {len(all_urls) - len(scoped_urls)} out-of-scope)")
        all_urls = scoped_urls

    # Cap total volume
    url_list = sorted(all_urls)
    if len(url_list) > MAX_URLS_PER_HOST * len(hosts):
        cap = MAX_URLS_PER_HOST * len(hosts)
        log.warning(f"  Capping at {cap} URLs (had {len(url_list)})")
        url_list = url_list[:cap]

    # ── Deduplicate with uro ────────────────────────────────────────────────
    log.info("")
    log.info("  Deduplication (uro)")
    deduped = _run_uro(url_list, workdir)

    # ── Verify liveness with httpx ──────────────────────────────────────────
    metadata: dict[str, dict] = {}
    if verify_liveness and deduped:
        log.info("")
        log.info("  Liveness verification (httpx)")
        live_set, metadata = _verify_liveness(deduped, workdir)
        if live_set:
            deduped = sorted(live_set)
        else:
            log.info("      (httpx unavailable — keeping unverified list)")

    # ── Classify and split ──────────────────────────────────────────────────
    results = _classify_urls(deduped, metadata)
    paths = _write_split_outputs(results, outdir)

    # ── Build report ────────────────────────────────────────────────────────
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

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "use_archives":     use_archives,
            "use_katana":       use_katana,
            "use_subjs":        use_subjs,
            "verify_liveness":  verify_liveness,
            "katana_depth":     KATANA_DEPTH,
            "katana_headless":  KATANA_HEADLESS,
            "gau_providers":    GAU_PROVIDERS,
        },
        "totals": {
            "hosts":            len(hosts),
            "raw_urls":         len(all_urls),
            "deduped_urls":     len(results),
            "with_params":      params_count,
            "js_files":         js_count,
            "interesting":      interesting_count,
            "alive":            sum(1 for r in results if r.alive),
        },
        "sources": by_source,
        "urls": [r.to_dict() for r in results],
    }

    json_path = outdir / "url_harvest.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup ─────────────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    all_urls.txt              {len(results):>6} URL(s)")
    log.info(f"    urls_with_params.txt      {params_count:>6} URL(s)")
    log.info(f"    urls_js_files.txt         {js_count:>6} JS file(s)")
    log.info(f"    urls_interesting.txt      {interesting_count:>6} URL(s)")

    log.info("")
    log.info(f"  Alive  : {sum(1 for r in results if r.alive)} / {len(results)} verified")

    if interesting_count:
        log.info("")
        log.info("  Interesting URLs (sample):")
        for r in [x for x in results if x.is_interesting][:10]:
            log.info(f"    {r.status:>3}  {r.url}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "hosts": 0, "raw_urls": 0, "deduped_urls": 0,
            "with_params": 0, "js_files": 0, "interesting": 0, "alive": 0,
        },
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
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    live = base / "output" / "live_urls.txt"
    wildcards = base / "wildcard.txt"
    out = base / "output"

    try:
        run_url_harvest(live, out, wildcards)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
