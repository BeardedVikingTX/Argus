#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/url_harvester.py — URL & Endpoint Harvesting
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/url_harvester.py
  Version   : 3.0.0 "HEIMDALL"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Turns live hosts into a comprehensive, deduplicated, verified inventory
  of every URL the target exposes.

  Two-traffic-mode module:
    · Archives (gau, waybackurls) — query third-party services. NO target
      traffic, NO platform headers.
    · Target (katana, subjs, httpx) — hit the target directly. Platform
      headers + request.txt auth applied. Rate limits honored.

  v2.0 → v3.0 (silent-failure fixes):
    [FIX]  MODULE_RATE_LIMITS["urls"] → fallback chain through "crawl"
           (katana) and "httpx_probe" (httpx). config.py has NO "urls" key —
           v2.0 was silently using 50 rps / 10 conc regardless of config.
    [FIX]  entry.get("rate_limit") → entry.get("rps"). config.py uses "rps".
    [FIX]  katana timeout partial-output recovery was BROKEN. `"result" in
           dir()` is False on TimeoutExpired — partial stdout was discarded
           every time. Now uses exc.stdout from the exception.
    [FIX]  _verify_liveness treats "httpx confirmed 0 live" the same as
           "httpx unavailable" — kept DEAD URLs as if they were live.
           Now returns httpx_ran flag; caller distinguishes.
    [FIX]  _self_sync sent up to 200K records in one API call → server
           rejects → silent failure. Now chunks in 5,000-record batches.
    [FIX]  _load_hosts / _load_roots missing BOM/CRLF/inline-comment safety.
    [FIX]  _write_empty_report didn't accept scan_id → empty-input path
           dropped DB sync.
    [FIX]  MAX_URLS_PER_HOST × hosts = OOM risk (50M URLs). Added
           MAX_ABSOLUTE_URLS = 500,000 hard cap.
    [FIX]  httpx IP extraction uses obj.get("host") — fragile. Now uses
           a/aaaa arrays explicitly.
    [FIX]  headers= kwarg silently lost via setdefault(). Now .update().
    [FIX]  KillSwitch missing — .ARGUS_STOP mid-crawl now cleanly unwinds.
    [FIX]  SIGINT/SIGTERM missing — Ctrl-C now writes partial report.

  v3.0 — NEW:
    [NEW]  24h archive cache (.state/url_harvest_cache.json). Second run
           of Phase 1 is <1s instead of 60s/root.
    [NEW]  --no-cache, --dry-run, --quiet, --verbose, --on-progress-ready.
    [NEW]  --max-urls, --katana-depth, --katana-headless CLI flags.
    [NEW]  --httpx-rate-limit, --httpx-concurrency separate from katana.
    [NEW]  Structured warnings[] array in report.
    [NEW]  schema_version + producer + input_hash + tool_versions in report.
    [NEW]  url_harvest_digest.md — sources, reasons, top-50 interesting URLs.
    [NEW]  Per-source 24h cache: gau + waybackurls keyed by root domain.
    [NEW]  Chunked DB sync (5,000-record batches).
    [NEW]  _run_subprocess_with_partial() helper — consistent partial-output
           recovery across ALL tool invocations.
    [NEW]  --selftest (60 checks) and --config-check.
    [NEW]  tool_versions captured in report (gau, waybackurls, katana,
           subjs, uro, httpx).

  Outputs:
    all_urls.txt                    — every verified URL
    urls_with_params.txt            — URLs containing query strings
    urls_js_files.txt               — JavaScript file URLs
    urls_interesting.txt            — URLs matching high-value patterns
    url_harvest.json                — full structured report
    url_harvest_digest.md           — top-50 markdown summary

  Usage:
    python3 url_harvester.py                    # full pipeline
    python3 url_harvester.py --passive          # archives only
    python3 url_harvester.py --dry-run          # preview, no subprocesses
    python3 url_harvester.py --no-cache         # force fresh archive queries
    python3 url_harvester.py --selftest
    python3 url_harvester.py --config-check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("argus.url_harvester")

# Defensive imports — not used by this module directly, but kept for
# compatibility with pipelines that disable SSL warnings globally.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _URLLIB3_AVAILABLE = True
except ImportError:
    _URLLIB3_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG INTEGRATION
# ═════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False

try:
    from db import DB  # type: ignore
    DB_AVAILABLE = True
except ImportError:
    DB = None  # type: ignore[assignment]
    DB_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _killswitch_check(label: str = "") -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


# v3.0: fallback chain through config's actual keys
def _katana_settings() -> dict:
    """
    v3.0: reads MODULE_RATE_LIMITS["crawl"] (config's canonical key for
    HTTP crawling) with legacy fallback to "urls". v2.0 used "urls" which
    does NOT exist in config.py → always defaulted to 50/10 regardless of
    user config.
    """
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = (all_limits.get("crawl")
             or all_limits.get("urls")
             or all_limits.get("httpx_probe")
             or {})
    rps = entry.get("rps", entry.get("rate_limit", 4))
    conc = entry.get("concurrency", 4)
    parallel = entry.get("parallelism", 5)
    if not isinstance(rps, int) or rps < 0:      rps = 4
    if not isinstance(conc, int) or conc < 1:    conc = 4
    if not isinstance(parallel, int) or parallel < 1: parallel = 5
    return {"rps": rps, "concurrency": conc, "parallelism": parallel}


def _httpx_settings() -> dict:
    """
    v3.0: reads MODULE_RATE_LIMITS["httpx_probe"] — the correct config key
    for httpx probing. Falls back to "urls" then default 10/10.
    """
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = (all_limits.get("httpx_probe")
             or all_limits.get("urls")
             or {})
    rps = entry.get("rps", entry.get("rate_limit", 10))
    conc = entry.get("concurrency", 10)
    if not isinstance(rps, int) or rps < 0:   rps = 10
    if not isinstance(conc, int) or conc < 1: conc = 10
    return {"rps": rps, "concurrency": conc}


def _target_headers(extra: Optional[dict] = None) -> dict[str, str]:
    """v3.0: caller-supplied headers OVERRIDE config (was setdefault → lost)."""
    h: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    if extra:
        h.update(extra)  # v3.0 fix — was setdefault in v2.0
    return h


def _auth_cookie_header() -> Optional[str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return None
    cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ═════════════════════════════════════════════════════════════════════════
#  THREAD LOCKS + SHARED STATE
# ═════════════════════════════════════════════════════════════════════════

_LOG_LOCK = threading.Lock()
_CACHE_LOCK = threading.Lock()
_SHARED = {"_quiet": False}


def _log_locked(level: str, msg: str) -> None:
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        getattr(log, level)(msg)


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

GAU_TIMEOUT             = 600
WAYBACKURLS_TIMEOUT     = 300
KATANA_TIMEOUT          = 900
SUBJS_TIMEOUT           = 180
URO_TIMEOUT             = 120
HTTPX_TIMEOUT           = 1800

MAX_HOSTS               = 1000
MAX_URLS_PER_HOST       = 50000
MAX_ABSOLUTE_URLS       = 500_000  # v3.0 hard cap — OOM safety
MAX_DB_URLS             = 200_000
DB_SYNC_CHUNK_SIZE      = 5000     # v3.0 — API batch size

# Katana defaults
KATANA_DEPTH            = 3
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

HTTPX_STATUS_CODES      = "200,201,204,301,302,307,308,401,403"

# v3.0 cache
CACHE_TTL_HOURS         = 24.0
CACHE_FILE              = "url_harvest_cache.json"

# ── Interesting patterns with labels ──────────────────────────────────────
INTERESTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("admin",      re.compile(r"/(admin|administrator|dashboard|console|management|panel|cp|control)(/|$|\?)", re.I)),
    ("login",      re.compile(r"/(login|signin|sign-in|logout|signout|register|signup|sign-up|auth|sso|oauth|saml|cas|ldap)(/|$|\?)", re.I)),
    ("api",        re.compile(r"/(api|rest|v\d+|graphql|graphiql)(/|$|\?|\.)", re.I)),
    ("internal",   re.compile(r"/(internal|private|backend|backoffice|intranet)(/|$|\?)", re.I)),
    ("debug",      re.compile(r"/(debug|test|dev|develop|staging|trace|actuator|metrics|health|status|info|env|config)(/|$|\?)", re.I)),
    ("docs",       re.compile(r"/(swagger|openapi|api-docs|docs|redoc|rapidoc)(/|$|\?)", re.I)),
    ("backup",     re.compile(r"(\.bak|\.backup|\.old|\.orig|\.swp|\.save|/backup|/backups)(/|$|\?)", re.I)),
    ("source_git", re.compile(r"(\.git|\.svn|\.hg|\.bzr)(/|$)", re.I)),
    ("secrets",    re.compile(r"(\.env|\.htaccess|\.DS_Store|wp-config|credentials|secrets)(/|$|\.)", re.I)),
    ("wp",         re.compile(r"/wp-(admin|content|includes|config|login)", re.I)),
    ("upload",     re.compile(r"/(upload|uploads|attachment|attachments|file|files|download|media)(/|$|\?)", re.I)),
    ("panel",      re.compile(r"/(jenkins|grafana|kibana|prometheus|consul|vault|jira|confluence|gitlab|phpmyadmin|webmin|cpanel|plesk)(/|$|\?)", re.I)),
    ("ssrf_param", re.compile(r"[?&](url|uri|redirect|next|return|dest|destination|target|callback|continue|goto|proxy|fetch|load)=", re.I)),
    ("file_param", re.compile(r"[?&](file|filename|path|filepath|doc|document|page|include|template)=", re.I)),
    ("inject_param", re.compile(r"[?&](cmd|exec|execute|command|run|shell|query|q|search|sql|select)=", re.I)),
]

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp4", ".webm", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
}


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class URLSource:
    name: str
    urls: set[str] = field(default_factory=set)
    error: str = ""
    duration: float = 0.0
    timed_out: bool = False
    from_cache: bool = False

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


# ═════════════════════════════════════════════════════════════════════════
#  HELPERS — v3.0 additions
# ═════════════════════════════════════════════════════════════════════════

def _input_hash(hosts: list[str]) -> str:
    """Stable hash of input hosts for reproducibility."""
    h = hashlib.sha256()
    for host in sorted(hosts):
        h.update(host.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:16]


def _chunk_list(items: list, size: int) -> list[list]:
    """Split a list into chunks of `size` for batched API calls."""
    if size <= 0:
        return [items]
    return [items[i:i + size] for i in range(0, len(items), size)]


def _get_tool_version(tool: str) -> str:
    """Get version string for a CLI tool. Best-effort."""
    try:
        if not shutil.which(tool):
            return "not-installed"
        # Different tools use different flags — try a few
        for flags in (["-version"], ["--version"], ["-v"], ["version"]):
            try:
                result = subprocess.run(
                    [tool] + flags,
                    capture_output=True, text=True, timeout=5,
                )
                text = (result.stdout or result.stderr or "").strip()
                m = re.search(r"v?\d+\.\d+(?:\.\d+)?", text)
                if m:
                    return m.group(0)
                if text:
                    return text.split("\n")[0][:40]
            except Exception:
                continue
        return "unknown"
    except Exception:
        return "unknown"


def _state_dir() -> Optional[Path]:
    sd = _cfg("STATE_DIR")
    return Path(sd) if sd is not None else None


def _cache_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / CACHE_FILE if sd else None


def _load_cache(path: Optional[Path],
                  ttl_hours: float = CACHE_TTL_HOURS) -> dict:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        now = time.time()
        fresh: dict = {}
        for key, entry in data.items():
            if not isinstance(entry, dict):
                continue
            age = (now - entry.get("_cached_at", 0)) / 3600
            if age <= ttl_hours:
                fresh[key] = entry
        return fresh
    except Exception:
        return {}


def _save_cache(path: Optional[Path], cache: dict) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_LOCK:
            path.write_text(json.dumps(cache, default=str), encoding="utf-8")
    except Exception:
        pass


def _looks_like_ip(s: str) -> bool:
    if not s:
        return False
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in s


def _normalize_url(url: str) -> Optional[str]:
    """Strip fragment, lowercase scheme+netloc, reject static extensions."""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if not parsed.hostname:
        return None
    path_lower = parsed.path.lower()
    for ext in STATIC_EXTENSIONS:
        if path_lower.endswith(ext):
            return None
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        "",  # v3.0: always strip fragment
    ))


def _classify_interesting(url: str) -> tuple[bool, list[str]]:
    """Return (is_interesting, reasons) with all matching pattern labels."""
    reasons: list[str] = []
    for label, pattern in INTERESTING_PATTERNS:
        if pattern.search(url):
            reasons.append(label)
    return (bool(reasons), reasons)


def _basic_dedupe(urls: list[str]) -> list[str]:
    """Python fallback for uro. Dedupe by (scheme, host, path, sorted query)."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            key = urllib.parse.urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/"),
                "",
                urllib.parse.urlencode(
                    sorted(urllib.parse.parse_qsl(parsed.query))),
                "",
            ))
        except Exception:
            key = url
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


# ═════════════════════════════════════════════════════════════════════════
#  INPUT (v3.0 — BOM/CRLF safe)
# ═════════════════════════════════════════════════════════════════════════

def _load_hosts(input_file: Path) -> list[str]:
    """v3.0: BOM/CRLF/inline-comment/trailing-dot safe."""
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    hosts: list[str] = []
    seen: set[str] = set()
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        try:
            parsed = urllib.parse.urlparse(token)
        except Exception:
            continue
        if not parsed.hostname:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if base not in seen:
            seen.add(base)
            hosts.append(base)
    return hosts


def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    """v3.0: BOM/CRLF/inline-comment safe."""
    if not wildcard_file or not wildcard_file.exists():
        return []
    roots: set[str] = set()
    raw = wildcard_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line and "." in line:
            roots.add(line.rstrip("."))
    return sorted(roots)


# ═════════════════════════════════════════════════════════════════════════
#  SUBPROCESS HELPER — v3.0 (fixed partial-output recovery)
# ═════════════════════════════════════════════════════════════════════════

def _run_subprocess_with_partial(
    cmd: list[str], timeout: int, label: str,
    input_data: Optional[str] = None,
) -> tuple[str, str, bool]:
    """
    v3.0: run subprocess, return (stdout, stderr, timed_out).
    On timeout, returns partial stdout/stderr from the exception.
    v2.0's `"result" in dir()` check returned "" always — partial output
    was lost on EVERY timeout.
    """
    _killswitch_check(label)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=input_data,
        )
        return result.stdout or "", result.stderr or "", False
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return stdout, stderr, True
    except FileNotFoundError:
        return "", f"{label} binary not found", False
    except Exception as e:
        return "", f"{label} failed: {type(e).__name__}: {e}", False


# ═════════════════════════════════════════════════════════════════════════
#  SOURCE 1 — ARCHIVES (no target traffic) with v3.0 cache
# ═════════════════════════════════════════════════════════════════════════

def _run_gau(domain: str, cache: Optional[dict] = None,
              cache_path: Optional[Path] = None) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="gau")

    # v3.0 cache lookup
    cache_key = f"gau|{domain}"
    if cache is not None and cache_key in cache:
        source.urls = set(cache[cache_key].get("urls", []))
        source.from_cache = True
        source.duration = time.monotonic() - start
        return source

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
    stdout, stderr, timed_out = _run_subprocess_with_partial(
        cmd, GAU_TIMEOUT, "gau")

    if timed_out:
        source.timed_out = True
        source.error = f"timeout after {GAU_TIMEOUT}s (partial output used)"

    for line in stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            source.urls.add(url)

    if not source.urls and not timed_out and stderr:
        source.error = stderr.strip()[:200]

    source.duration = time.monotonic() - start

    # v3.0: persist to cache
    if cache is not None and cache_path is not None and source.urls:
        cache[cache_key] = {
            "urls": list(source.urls),
            "_cached_at": time.time(),
        }
        _save_cache(cache_path, cache)

    return source


def _run_waybackurls(domain: str, cache: Optional[dict] = None,
                       cache_path: Optional[Path] = None) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="waybackurls")

    cache_key = f"waybackurls|{domain}"
    if cache is not None and cache_key in cache:
        source.urls = set(cache[cache_key].get("urls", []))
        source.from_cache = True
        source.duration = time.monotonic() - start
        return source

    if not shutil.which("waybackurls"):
        source.error = "waybackurls not installed"
        source.duration = time.monotonic() - start
        return source

    stdout, stderr, timed_out = _run_subprocess_with_partial(
        ["waybackurls", domain], WAYBACKURLS_TIMEOUT, "waybackurls")

    if timed_out:
        source.timed_out = True
        source.error = f"timeout after {WAYBACKURLS_TIMEOUT}s (partial used)"

    for line in stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            source.urls.add(url)

    source.duration = time.monotonic() - start

    if cache is not None and cache_path is not None and source.urls:
        cache[cache_key] = {
            "urls": list(source.urls),
            "_cached_at": time.time(),
        }
        _save_cache(cache_path, cache)

    return source


# ═════════════════════════════════════════════════════════════════════════
#  SOURCE 2 — KATANA (target traffic, v3.0 fixed partial output)
# ═════════════════════════════════════════════════════════════════════════

def _run_katana(
    hosts: list[str], workdir: Path,
    rate_limit: int, concurrency: int, parallelism: int,
    header_args: list[str], root_domains: list[str],
    depth: int = KATANA_DEPTH,
    headless: bool = KATANA_HEADLESS,
) -> tuple[URLSource, dict[str, dict]]:
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
        "-d", str(depth),
        "-kf", "all",
        "-c", str(concurrency),
        "-p", str(parallelism),
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
    if headless:
        cmd.extend(["-hl", "-nos"])
    if root_domains:
        cmd.extend(["-fs", "rdn"])
    for hdr in header_args:
        cmd.extend(["-H", hdr])

    _log_locked("info",
        f"      katana  {len(hosts)} host(s)  depth={depth}  "
        f"js={KATANA_JS_CRAWL}  xhr={KATANA_XHR_CRAWL}  "
        f"forms={KATANA_EXTRACT_FORMS}  headless={headless}  "
        f"rl={rate_limit}/s")

    stdout, stderr, timed_out = _run_subprocess_with_partial(
        cmd, KATANA_TIMEOUT, "katana")

    if timed_out:
        source.timed_out = True
        source.error = f"timeout after {KATANA_TIMEOUT}s (partial output used)"
        log.warning(f"      katana timeout — using {len(stdout.splitlines())} "
                    f"line(s) of partial output")

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
        for form in (obj.get("forms") or []):
            if isinstance(form, dict):
                action = form.get("action") or form.get("url")
                if action:
                    entry["form_actions"].append(str(action))

    if not source.urls and not timed_out and stderr:
        source.error = stderr.strip()[:200] or "katana failed"

    source.duration = time.monotonic() - start
    return source, metadata


# ═════════════════════════════════════════════════════════════════════════
#  SOURCE 3 — SUBJS (target traffic, no header support)
# ═════════════════════════════════════════════════════════════════════════

def _run_subjs(hosts: list[str]) -> URLSource:
    start = time.monotonic()
    source = URLSource(name="subjs")

    if not shutil.which("subjs"):
        source.error = "subjs not installed"
        source.duration = time.monotonic() - start
        return source

    stdout, stderr, timed_out = _run_subprocess_with_partial(
        ["subjs"], SUBJS_TIMEOUT, "subjs", input_data="\n".join(hosts))

    if timed_out:
        source.timed_out = True
        source.error = f"timeout after {SUBJS_TIMEOUT}s (partial output used)"

    for line in stdout.splitlines():
        url = _normalize_url(line.strip())
        if url and url.lower().split("?")[0].endswith(".js"):
            source.urls.add(url)

    source.duration = time.monotonic() - start
    return source


# ═════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION (uro)
# ═════════════════════════════════════════════════════════════════════════

def _run_uro(urls: list[str], workdir: Path) -> list[str]:
    if not urls:
        return []
    if not shutil.which("uro"):
        _log_locked("info", "      uro not installed — using Python dedupe")
        return _basic_dedupe(urls)

    input_file = workdir / "uro_input.txt"
    input_file.write_text("\n".join(urls) + "\n")

    stdout, stderr, timed_out = _run_subprocess_with_partial(
        ["uro", "-i", str(input_file)], URO_TIMEOUT, "uro")

    if timed_out:
        log.warning("      uro timeout — falling back to Python dedupe")
        return _basic_dedupe(urls)

    deduped: list[str] = []
    for line in stdout.splitlines():
        url = _normalize_url(line.strip())
        if url:
            deduped.append(url)
    if not deduped:
        return _basic_dedupe(urls)
    _log_locked("info", f"      uro reduced {len(urls)} → {len(deduped)} URL(s)")
    return deduped


# ═════════════════════════════════════════════════════════════════════════
#  LIVENESS VERIFICATION (httpx, v3.0 fixed 404 bug + a/aaaa extraction)
# ═════════════════════════════════════════════════════════════════════════

def _verify_liveness(
    urls: list[str], workdir: Path,
    rate_limit: int, concurrency: int,
    header_args: list[str], cookie_header: Optional[str],
) -> tuple[set[str], dict[str, dict], bool]:
    """
    v3.0: returns (live_urls, metadata, httpx_ran).
    httpx_ran distinguishes "httpx confirmed 0 live" (empty set + True)
    from "httpx unavailable" (input set + False) — v2.0 confused these.
    """
    if not urls:
        return set(), {}, False

    if not shutil.which("httpx"):
        log.warning("      httpx not installed — liveness unverified")
        return set(urls), {}, False

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

    _log_locked("info",
        f"      httpx  {len(urls)} URL(s)  rl={rate_limit}/s  "
        f"c={concurrency}  headers={len(header_args)}  "
        f"cookie={'yes' if cookie_header else 'no'}")

    stdout, stderr, timed_out = _run_subprocess_with_partial(
        cmd, HTTPX_TIMEOUT, "httpx")

    if timed_out:
        log.warning("      httpx timeout — partial results used")

    live_urls: set[str] = set()
    metadata: dict[str, dict] = {}

    for line in stdout.splitlines():
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

        # v3.0: use a/aaaa arrays explicitly instead of fragile obj.get("host")
        a_ips = obj.get("a") or []
        aaaa_ips = obj.get("aaaa") or []
        if isinstance(a_ips, str):
            a_ips = [a_ips]
        if isinstance(aaaa_ips, str):
            aaaa_ips = [aaaa_ips]
        resolved_ip = ""
        if a_ips:
            resolved_ip = str(a_ips[0])
        elif aaaa_ips:
            resolved_ip = str(aaaa_ips[0])
        elif obj.get("host") and _looks_like_ip(str(obj.get("host"))):
            resolved_ip = str(obj.get("host"))

        metadata[url] = {
            "status":          obj.get("status_code") or 0,
            "content_type":    obj.get("content_type") or "",
            "content_length":  obj.get("content_length"),
            "title":           obj.get("title") or "",
            "webserver":       obj.get("webserver") or "",
            "technologies":    obj.get("tech") or [],
            "final_url":       obj.get("final_url") or "",
            "redirect_chain":  obj.get("chain_status_codes") or [],
            "response_time":   str(obj.get("time") or ""),
            "resolved_ip":     resolved_ip,
            "cname":           obj.get("cname") or "",
        }

    _log_locked("info",
        f"      httpx confirmed {len(live_urls)} / {len(urls)} live")
    return live_urls, metadata, True


# ═════════════════════════════════════════════════════════════════════════
#  ASSEMBLY & CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════

def _build_results(
    urls: list[str],
    source_map: dict[str, set[str]],
    katana_meta: dict[str, dict],
    httpx_meta: dict[str, dict],
    auth_on: bool,
) -> list[HarvestResult]:
    now = datetime.now(timezone.utc).isoformat()
    results: list[HarvestResult] = []

    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            continue
        path_lower = parsed.path.lower()

        r = HarvestResult(
            url=url,
            sources=set(source_map.get(url, set())),
            auth_enabled=auth_on,
            first_seen=now,
        )
        r.has_params = bool(parsed.query)
        r.is_js = path_lower.endswith(".js")

        km = katana_meta.get(url, {})
        if km:
            r.methods = set(km.get("methods") or set())
            r.tags = set(km.get("tags") or set())
            r.attributes = set(km.get("attributes") or set())
            r.form_actions = list(km.get("form_actions") or [])[:50]
            r.is_form = "form" in r.tags or bool(r.form_actions)

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

        is_int, reasons = _classify_interesting(url)
        r.is_interesting = is_int
        r.interesting_reasons = reasons

        results.append(r)

    return results


def _write_split_outputs(results: list[HarvestResult],
                          outdir: Path) -> dict[str, Path]:
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


def _write_digest(results: list[HarvestResult], outdir: Path,
                    sources: list[URLSource]) -> None:
    """v3.0: human-readable markdown summary."""
    interesting = [r for r in results if r.is_interesting]

    reason_counts: dict[str, int] = {}
    for r in results:
        for reason in r.interesting_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    lines = [
        "# URL Harvest Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Total URLs:** {len(results)}  \n",
        f"**Interesting:** {len(interesting)}  \n",
        f"**With params:** {sum(1 for r in results if r.has_params)}  \n",
        f"**JS files:** {sum(1 for r in results if r.is_js)}  \n",
        f"**Forms:** {sum(1 for r in results if r.is_form)}  \n\n",
    ]

    if sources:
        lines.append("## Sources\n\n")
        lines.append("| Source | Count | Duration | Status |\n")
        lines.append("|--------|-------|----------|--------|\n")
        for src in sources:
            if src.error:
                status = "⚠ " + src.error[:60]
            elif src.from_cache:
                status = "cache"
            elif src.timed_out:
                status = "⚠ timeout"
            else:
                status = "✓"
            lines.append(
                f"| {src.name} | {src.count} | {src.duration:.1f}s | {status} |\n"
            )

    if reason_counts:
        lines.append("\n## Interesting reasons\n\n")
        lines.append("| Reason | Count |\n")
        lines.append("|--------|-------|\n")
        for label, count in sorted(reason_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {label} | {count} |\n")

    if interesting:
        lines.append("\n## Top interesting URLs\n\n")
        lines.append("| Status | Reasons | URL |\n")
        lines.append("|--------|---------|-----|\n")
        for r in interesting[:50]:
            url = r.url.replace("|", "\\|")[:90]
            reasons = ",".join(r.interesting_reasons[:3]).replace("|", "\\|")
            status = str(r.status) if r.status else "—"
            lines.append(f"| {status} | {reasons} | {url} |\n")

    (outdir / "url_harvest_digest.md").write_text(
        "".join(lines), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC (v3.0 — chunked)
# ═════════════════════════════════════════════════════════════════════════

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
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready")
        return

    if len(results) > MAX_DB_URLS:
        log.warning(f"  DB sync: capping at {MAX_DB_URLS} URLs (had {len(results)})")
        results = results[:MAX_DB_URLS]

    # v3.0: chunked sync — API batch limits respected
    total_upserted = 0
    for i, chunk in enumerate(_chunk_list(results, DB_SYNC_CHUNK_SIZE), 1):
        try:
            payloads = [r.to_dict() for r in chunk]
            result = DB.upsert_urls(scan_id, payloads)
            if result is None:
                log.warning(f"  DB sync: chunk {i} returned None")
                continue
            total_upserted += int(result) if isinstance(result, (int, float)) else 0
        except Exception as e:
            log.warning(f"  DB sync: chunk {i} exception — {e}")

    if total_upserted > 0:
        log.info(f"  DB sync: {total_upserted} URL(s) upserted "
                 f"({len(_chunk_list(results, DB_SYNC_CHUNK_SIZE))} batch(es))")


# ═════════════════════════════════════════════════════════════════════════
#  EMPTY REPORT (v3.0 — accepts scan_id + dry_run)
# ═════════════════════════════════════════════════════════════════════════

def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
    scan_id: Optional[int] = None,
    dry_run: bool = False,
    reason: str = "no_inputs",
) -> Path:
    report = {
        "schema_version":  3,
        "producer":        "url_harvester.py v3.0.0 'HEIMDALL'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "dry_run":         dry_run,
        "reason":          reason,
        "input_file":      str(input_file),
        "input_hash":      None,
        "auth_enabled":    bool(_cfg("AUTH_ENABLED", False)),
        "passive_only":    False,
        "config":          {},
        "tool_versions":   {},
        "warnings":        [],
        "totals": {
            "hosts": 0, "raw_urls": 0, "deduped_urls": 0,
            "with_params": 0, "js_files": 0, "forms": 0,
            "interesting": 0, "multi_source": 0, "alive": 0,
        },
        "interesting_reasons": {},
        "sources": {},
        "urls": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / "url_harvest.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("all_urls.txt", "urls_with_params.txt",
                 "urls_js_files.txt", "urls_interesting.txt"):
        (outdir / name).write_text("")
    (outdir / "url_harvest_digest.md").write_text(
        "# URL Harvest Digest\n\nNo URLs harvested.\n", encoding="utf-8")

    if scan_id is not None:
        _self_sync(scan_id, [])

    return path


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT (v3.0)
# ═════════════════════════════════════════════════════════════════════════

def run_url_harvest(
    live_urls_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    # v2 backward-compat
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
    # v3.0 additions
    dry_run: bool = False,
    quiet: bool = False,
    no_cache: bool = False,
    max_urls: int = MAX_ABSOLUTE_URLS,
    katana_depth: int = KATANA_DEPTH,
    katana_headless: bool = KATANA_HEADLESS,
    httpx_rate_limit: Optional[int] = None,
    httpx_concurrency: Optional[int] = None,
    on_progress: Optional[Callable[[str, dict], None]] = None,
) -> Path:
    """v3.0: full URL harvest with cache, chunked DB sync, partial output."""
    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    # ── SIGINT handler ──────────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — writing partial report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    try:
        # ── Settings ─────────────────────────────────────────────────────
        katana_cfg = _katana_settings()
        httpx_cfg = _httpx_settings()

        eff_katana_rate = (katana_rate_limit if katana_rate_limit is not None
                           else katana_cfg["rps"])
        eff_katana_conc = (katana_concurrency if katana_concurrency is not None
                           else katana_cfg["concurrency"])
        eff_katana_par  = katana_cfg["parallelism"]
        eff_httpx_rate = (httpx_rate_limit if httpx_rate_limit is not None
                          else httpx_cfg["rps"])
        eff_httpx_conc = (httpx_concurrency if httpx_concurrency is not None
                          else httpx_cfg["concurrency"])

        # ── Inputs ───────────────────────────────────────────────────────
        hosts = _load_hosts(live_urls_file)
        total_input = len(hosts)
        if len(hosts) > max_hosts:
            warnings.append(f"hosts-capped: {total_input} → {max_hosts}")
            log.warning(f"  Capping at {max_hosts} hosts (input had {total_input})")
            hosts = hosts[:max_hosts]

        roots = _load_roots(wildcard_file)
        outdir.mkdir(parents=True, exist_ok=True)
        workdir = outdir / "url_work"
        workdir.mkdir(parents=True, exist_ok=True)

        auth_on = bool(_cfg("AUTH_ENABLED", False))
        cfg_hdrs = _target_headers(headers)
        header_args = [f"{k}: {v}" for k, v in cfg_hdrs.items()]
        cookie_header = _auth_cookie_header()

        if not quiet:
            log.info(f"  Input  : {len(hosts)} host(s) from {live_urls_file.name}")
            log.info(f"  Roots  : {len(roots)} wildcard(s)")
            log.info(f"  Config : katana rl={eff_katana_rate}/s  "
                     f"c={eff_katana_conc}  p={eff_katana_par}  "
                     f"depth={katana_depth}  headless={katana_headless}")
            log.info(f"           httpx rl={eff_httpx_rate}/s  "
                     f"c={eff_httpx_conc}")
            log.info(f"           source=MODULE_RATE_LIMITS['crawl'/'httpx_probe']")
            if cfg_hdrs and not passive_only:
                log.info(f"  Headers: {len(cfg_hdrs)} → katana + httpx")
            if auth_on and not passive_only:
                log.info(f"  Auth   : ENABLED"
                         f"{' + cookies' if cookie_header else ''}")
            if passive_only:
                log.info(f"  Mode   : PASSIVE (archives only)")
            if dry_run:
                log.info(f"  Mode   : DRY-RUN (no subprocesses)")
            log.info("")

        if not hosts:
            log.warning("  No hosts — writing empty report")
            return _write_empty_report(
                outdir, live_urls_file, start,
                scan_id=scan_id, reason="empty_input")

        if dry_run:
            log.info(f"  DRY-RUN — would harvest from {len(hosts)} host(s)")
            for h in hosts[:10]:
                log.info(f"    {h}")
            if len(hosts) > 10:
                log.info(f"    … and {len(hosts) - 10} more")
            return _write_empty_report(
                outdir, live_urls_file, start,
                scan_id=scan_id, dry_run=True, reason="dry_run")

        # ── Cache ────────────────────────────────────────────────────────
        cache_path = _cache_path()
        cache = _load_cache(cache_path) if not no_cache else {}

        sources: list[URLSource] = []
        katana_meta: dict[str, dict] = {}
        source_map: dict[str, set[str]] = {}

        def _record_source(src: URLSource) -> None:
            sources.append(src)
            for url in src.urls:
                source_map.setdefault(url, set()).add(src.name)

        # ── Archives (v3.0 — with cache) ────────────────────────────────
        if use_archives and roots and not _sigint["flag"]:
            _progress("stage_start", {"stage": "archives", "roots": len(roots)})
            log.info("  Source 1 — Archives (no target traffic)")
            with ThreadPoolExecutor(max_workers=min(len(roots) * 2, 8)) as pool:
                futures = {}
                for root in roots:
                    futures[pool.submit(_run_gau, root, cache,
                                        cache_path)] = ("gau", root)
                    futures[pool.submit(_run_waybackurls, root, cache,
                                        cache_path)] = ("waybackurls", root)

                for fut in as_completed(futures):
                    src_name, root = futures[fut]
                    try:
                        src = fut.result()
                    except Exception as e:
                        src = URLSource(name=src_name, error=str(e))
                    _record_source(src)
                    tag = "[cache]" if src.from_cache else (
                        "[timeout]" if src.timed_out else "")
                    if src.error and not src.from_cache:
                        log.info(f"    {src_name:<14} {root:<24} "
                                 f"✗ {src.error}")
                        warnings.append(f"{src_name}/{root}: {src.error}")
                    else:
                        log.info(f"    {src_name:<14} {root:<24} "
                                 f"✓ {src.count:>5} URLs {tag}"
                                 f"  ({src.duration:.1f}s)")
            _progress("stage_end", {"stage": "archives",
                                      "urls": sum(s.count for s in sources)})
        else:
            log.info("  Source 1 — Archives skipped")

        # ── Katana ──────────────────────────────────────────────────────
        if use_katana and not passive_only and not _sigint["flag"]:
            _progress("stage_start", {"stage": "katana", "hosts": len(hosts)})
            log.info("")
            log.info("  Source 2 — Live crawl (katana, headers applied)")
            katana_src, katana_meta = _run_katana(
                hosts, workdir, eff_katana_rate, eff_katana_conc,
                eff_katana_par, header_args, roots,
                depth=katana_depth, headless=katana_headless,
            )
            _record_source(katana_src)
            if katana_src.error and not katana_src.urls:
                log.info(f"    katana         ✗ {katana_src.error}")
                warnings.append(f"katana: {katana_src.error}")
            else:
                log.info(f"    katana         ✓ {katana_src.count:>5} URLs"
                         f"  ({katana_src.duration:.1f}s)")
            _progress("stage_end", {"stage": "katana",
                                      "urls": katana_src.count})
        else:
            log.info("")
            log.info("  Source 2 — katana skipped"
                     + (" (passive)" if passive_only else ""))

        # ── subjs ───────────────────────────────────────────────────────
        if use_subjs and not passive_only and not _sigint["flag"]:
            _progress("stage_start", {"stage": "subjs"})
            log.info("")
            log.info("  Source 3 — JavaScript refs (subjs)")
            subjs_src = _run_subjs(hosts)
            _record_source(subjs_src)
            if subjs_src.error and not subjs_src.urls:
                log.info(f"    subjs          ✗ {subjs_src.error}")
                warnings.append(f"subjs: {subjs_src.error}")
            else:
                log.info(f"    subjs          ✓ {subjs_src.count:>5} JS files"
                         f"  ({subjs_src.duration:.1f}s)")
            _progress("stage_end", {"stage": "subjs",
                                      "urls": subjs_src.count})
        else:
            log.info("")
            log.info("  Source 3 — subjs skipped"
                     + (" (passive)" if passive_only else ""))

        # ── Merge ───────────────────────────────────────────────────────
        all_urls: set[str] = set()
        for src in sources:
            all_urls.update(src.urls)
        log.info("")
        log.info(f"  Merged : {len(all_urls)} unique URL(s) before filtering")

        # ── Scope filter ────────────────────────────────────────────────
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

        # v3.0: absolute cap (was MAX_URLS_PER_HOST * hosts = 50M potential)
        if len(url_list) > max_urls:
            warnings.append(f"urls-capped: {len(url_list)} → {max_urls}")
            log.warning(f"  Capping at {max_urls} URLs (had {len(url_list)})")
            url_list = url_list[:max_urls]

        # ── Dedupe ──────────────────────────────────────────────────────
        log.info("")
        log.info("  Deduplication (uro)")
        deduped = _run_uro(url_list, workdir)

        # ── Verify liveness ─────────────────────────────────────────────
        httpx_meta: dict[str, dict] = {}
        if verify_liveness and not passive_only and deduped and not _sigint["flag"]:
            _progress("stage_start", {"stage": "httpx",
                                        "urls": len(deduped)})
            log.info("")
            log.info("  Liveness verification (httpx, headers applied)")
            live_set, httpx_meta, httpx_ran = _verify_liveness(
                deduped, workdir, eff_httpx_rate, eff_httpx_conc,
                header_args, cookie_header,
            )
            if httpx_ran:
                # v3.0: httpx ran — trust its answer, even if it said "0 live"
                dead_count = len(deduped) - len(live_set)
                deduped = sorted(live_set)
                if not live_set:
                    warnings.append(
                        f"httpx confirmed 0 live URLs out of {len(deduped) + dead_count}")
            else:
                # httpx unavailable — keep unverified, but warn
                warnings.append("httpx unavailable — liveness unverified")
            _progress("stage_end", {"stage": "httpx", "live": len(live_set)})

        # ── Build results ───────────────────────────────────────────────
        results = _build_results(
            deduped, source_map, katana_meta, httpx_meta, auth_on,
        )
        paths = _write_split_outputs(results, outdir)

        # ── Digest ──────────────────────────────────────────────────────
        _write_digest(results, outdir, sources)

        # ── Tool versions ───────────────────────────────────────────────
        tool_versions = {
            "gau":         _get_tool_version("gau") if use_archives else "n/a",
            "waybackurls": _get_tool_version("waybackurls") if use_archives else "n/a",
            "katana":      _get_tool_version("katana") if (use_katana and not passive_only) else "n/a",
            "subjs":       _get_tool_version("subjs") if (use_subjs and not passive_only) else "n/a",
            "uro":         _get_tool_version("uro"),
            "httpx":       _get_tool_version("httpx") if (verify_liveness and not passive_only) else "n/a",
        }

        # ── Report ──────────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        by_source: dict[str, dict] = {}
        for src in sources:
            by_source[src.name] = {
                "count":      src.count,
                "error":      src.error,
                "duration":   round(src.duration, 2),
                "timed_out":  src.timed_out,
                "from_cache": src.from_cache,
            }

        params_count = sum(1 for r in results if r.has_params)
        js_count = sum(1 for r in results if r.is_js)
        interesting_count = sum(1 for r in results if r.is_interesting)
        forms_count = sum(1 for r in results if r.is_form)
        multi_source = sum(1 for r in results if len(r.sources) > 1)

        reason_counts: dict[str, int] = {}
        for r in results:
            for reason in r.interesting_reasons:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

        input_hash = _input_hash(hosts)

        report = {
            "schema_version":  3,
            "producer":        "url_harvester.py v3.0.0 'HEIMDALL'",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "input_file":      str(live_urls_file),
            "input_hash":      input_hash,
            "auth_enabled":    auth_on,
            "passive_only":    passive_only,
            "config": {
                "use_archives":      use_archives,
                "use_katana":        use_katana and not passive_only,
                "use_subjs":         use_subjs and not passive_only,
                "verify_liveness":   verify_liveness and not passive_only,
                "katana_rate":       eff_katana_rate,
                "katana_concurrency":eff_katana_conc,
                "katana_parallelism":eff_katana_par,
                "katana_depth":      katana_depth,
                "katana_headless":   katana_headless,
                "httpx_rate":        eff_httpx_rate,
                "httpx_concurrency": eff_httpx_conc,
                "headers_count":     len(cfg_hdrs),
                "cookie_set":        bool(cookie_header),
                "katana_xhr":        KATANA_XHR_CRAWL,
                "katana_forms":      KATANA_EXTRACT_FORMS,
                "gau_providers":     GAU_PROVIDERS,
                "max_urls":          max_urls,
            },
            "tool_versions":   tool_versions,
            "warnings":        warnings,
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
            "interesting_reasons": dict(
                sorted(reason_counts.items(), key=lambda kv: -kv[1])),
            "sources": by_source,
            "urls": [r.to_dict() for r in results],
        }

        json_path = outdir / "url_harvest.json"
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")

        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass

        if scan_id is not None:
            log.info("")
            log.info(f"  Syncing to remote database (scan_id={scan_id})...")
            _self_sync(scan_id, results)
        else:
            log.info("")
            log.info("  DB sync  : deferred to main.py (no scan_id passed)")

        # ── Console summary ─────────────────────────────────────────────
        if not quiet:
            log.info("")
            log.info("  Outputs :")
            log.info(f"    all_urls.txt              {len(results):>6} URL(s)")
            log.info(f"    urls_with_params.txt      {params_count:>6} URL(s)")
            log.info(f"    urls_js_files.txt         {js_count:>6} JS file(s)")
            log.info(f"    urls_interesting.txt      {interesting_count:>6} URL(s)")
            log.info(f"    url_harvest_digest.md")

            log.info("")
            log.info(f"  Alive  : {sum(1 for r in results if r.alive)} / "
                     f"{len(results)} verified")
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

            if warnings:
                log.info("")
                log.info("  Warnings:")
                for w in warnings[:8]:
                    log.warning(f"    {w}")

            log.info("")
            log.info(f"  Completed in {elapsed:.1f}s")

        return json_path

    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST (v3.0 — 60 checks)
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  url_harvester.py v3.0 'HEIMDALL' — selftest")
    print("═" * 70)

    import inspect
    import tempfile

    def _load_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example/x\r\n"
                     b"b.example/y  # inline\r\n"
                     b"\r\n"
                     b"# full-line\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_hosts(tmp)
            return loaded == ["https://a.example", "https://b.example"]
        finally:
            tmp.unlink(missing_ok=True)

    def _load_hosts_no_scheme() -> bool:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("example.com\nexample.org\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_hosts(tmp)
            return loaded == ["https://example.com", "https://example.org"]
        finally:
            tmp.unlink(missing_ok=True)

    def _load_roots_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfexample.com\r\nother.org  # inline\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_roots(tmp)
            return loaded == ["example.com", "other.org"]
        finally:
            tmp.unlink(missing_ok=True)

    def _normalize_strips_fragment() -> bool:
        return _normalize_url("https://x.com/a?id=1#frag") == \
               "https://x.com/a?id=1"

    def _normalize_lowercases_scheme() -> bool:
        return _normalize_url("HTTPS://X.com/a") == "https://x.com/a"

    def _normalize_preserves_port() -> bool:
        return _normalize_url("https://x.com:8443/a") == "https://x.com:8443/a"

    def _normalize_rejects_png() -> bool:
        return _normalize_url("https://x.com/img.png") is None

    def _normalize_rejects_css() -> bool:
        return _normalize_url("https://x.com/style.css") is None

    def _normalize_rejects_invalid() -> bool:
        return _normalize_url("not-a-url") is None

    def _normalize_rejects_relative() -> bool:
        return _normalize_url("/relative/path") is None

    def _normalize_empty() -> bool:
        return _normalize_url("") is None

    def _classify_admin() -> bool:
        return _classify_interesting("https://x.com/admin/")[0]

    def _classify_api() -> bool:
        return _classify_interesting("https://x.com/api/v1/")[0]

    def _classify_login() -> bool:
        return _classify_interesting("https://x.com/login")[0]

    def _classify_backup() -> bool:
        return _classify_interesting("https://x.com/db.sql.bak")[0]

    def _classify_source_git() -> bool:
        return _classify_interesting("https://x.com/.git/config")[0]

    def _classify_secrets() -> bool:
        return _classify_interesting("https://x.com/.env")[0]

    def _classify_ssrf_param() -> bool:
        return _classify_interesting("https://x.com/a?url=evil.com")[0]

    def _classify_inject_param() -> bool:
        return _classify_interesting("https://x.com/a?cmd=id")[0]

    def _classify_clean() -> bool:
        return not _classify_interesting("https://x.com/about")[0]

    def _classify_multiple() -> bool:
        _, reasons = _classify_interesting("https://x.com/admin?url=evil.com")
        return "admin" in reasons and "ssrf_param" in reasons

    def _looks_like_ip_v4() -> bool:
        return _looks_like_ip("1.2.3.4")

    def _looks_like_ip_v6() -> bool:
        return _looks_like_ip("::1")

    def _looks_like_ip_hostname() -> bool:
        return not _looks_like_ip("example.com")

    def _looks_like_ip_empty() -> bool:
        return not _looks_like_ip("")

    def _dedupe_keeps_distinct() -> bool:
        urls = ["https://x.com/a", "https://x.com/b"]
        return len(_basic_dedupe(urls)) == 2

    def _dedupe_reorders_query() -> bool:
        urls = ["https://x.com/a?b=2&a=1", "https://x.com/a?a=1&b=2"]
        return len(_basic_dedupe(urls)) == 1

    def _dedupe_slashes() -> bool:
        urls = ["https://x.com/a/", "https://x.com/a"]
        return len(_basic_dedupe(urls)) == 1

    def _build_results_sources() -> bool:
        results = _build_results(
            ["https://x.com/a"],
            {"https://x.com/a": {"katana", "gau"}},
            {}, {}, False,
        )
        return len(results) == 1 and results[0].sources == {"katana", "gau"}

    def _build_results_katana_meta() -> bool:
        results = _build_results(
            ["https://x.com/a"],
            {"https://x.com/a": {"katana"}},
            {"https://x.com/a": {
                "methods": {"GET", "POST"},
                "tags": {"form"},
                "attributes": {"action"},
                "form_actions": ["https://x.com/submit"],
            }},
            {}, False,
        )
        r = results[0]
        return r.is_form and "POST" in r.methods and r.form_actions

    def _build_results_httpx_meta() -> bool:
        results = _build_results(
            ["https://x.com/a"],
            {"https://x.com/a": {"httpx"}},
            {},
            {"https://x.com/a": {
                "status": 200,
                "title": "Home",
                "technologies": ["nginx", "jquery"],
                "resolved_ip": "1.2.3.4",
            }},
            False,
        )
        r = results[0]
        return (r.alive and r.title == "Home"
                and "nginx" in r.technologies
                and r.resolved_ip == "1.2.3.4")

    def _build_results_interesting() -> bool:
        results = _build_results(
            ["https://x.com/admin/"],
            {"https://x.com/admin/": {"katana"}}, {}, {}, False,
        )
        return results[0].is_interesting and "admin" in results[0].interesting_reasons

    def _build_results_has_params() -> bool:
        results = _build_results(
            ["https://x.com/a?id=1"], {}, {}, {}, False,
        )
        return results[0].has_params

    def _build_results_js() -> bool:
        results = _build_results(
            ["https://x.com/app.js"], {}, {}, {}, False,
        )
        return results[0].is_js

    def _chunk_list_basic() -> bool:
        return _chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]

    def _chunk_list_empty() -> bool:
        return _chunk_list([], 5) == [[]]

    def _chunk_list_single() -> bool:
        return _chunk_list([1], 100) == [[1]]

    def _input_hash_deterministic() -> bool:
        a = _input_hash(["https://a.example", "https://b.example"])
        b = _input_hash(["https://b.example", "https://a.example"])
        return a == b

    def _input_hash_distinct() -> bool:
        a = _input_hash(["https://a.example"])
        b = _input_hash(["https://b.example"])
        return a != b

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_url_harvest)
        return set(required).issubset(set(sig.parameters))

    def _empty_report_has_scan_id() -> bool:
        sig = inspect.signature(_write_empty_report)
        return "scan_id" in sig.parameters and "dry_run" in sig.parameters

    def _write_split_all() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            results = [
                HarvestResult(url="https://x.com/a"),
                HarvestResult(url="https://x.com/b?id=1"),
                HarvestResult(url="https://x.com/app.js"),
                HarvestResult(url="https://x.com/admin/"),
            ]
            # Set classification flags
            for r in results:
                r.has_params = "?" in r.url
                r.is_js = r.url.endswith(".js")
                r.is_interesting = "admin" in r.url
            paths = _write_split_outputs(results, out)
            all_ok = paths["all"].read_text().strip()
            return len(all_ok.splitlines()) == 4

    def _sig_has_dry_run() -> bool:
        return _sig_has("dry_run", "quiet", "no_cache", "max_urls",
                        "katana_depth", "katana_headless",
                        "httpx_rate_limit", "httpx_concurrency",
                        "on_progress")

    def _sig_has_v2_kwargs() -> bool:
        return _sig_has("use_archives", "use_katana", "use_subjs",
                        "verify_liveness", "passive_only", "max_hosts",
                        "katana_rate_limit", "katana_concurrency",
                        "headers", "scan_id")

    def _katana_settings_fallback() -> bool:
        s = _katana_settings()
        # config.py crawl = {rps: 4, conc: 4}; httpx_probe = {rps: 10, conc: 10}
        return s["rps"] == 4 and s["concurrency"] == 4

    def _httpx_settings_fallback() -> bool:
        s = _httpx_settings()
        return s["rps"] == 10 and s["concurrency"] == 10

    def _katana_settings_not_default_50() -> bool:
        # If v2.0 bug were still present, this would be 50/10
        return _katana_settings()["rps"] != 50

    def _state_dir_callable() -> bool:
        return callable(_state_dir)

    def _cache_path_callable() -> bool:
        return callable(_cache_path)

    def _killswitch_check_callable() -> bool:
        return callable(_killswitch_check)

    def _get_tool_version_callable() -> bool:
        return callable(_get_tool_version)

    def _subprocess_helper_callable() -> bool:
        return callable(_run_subprocess_with_partial)

    def _write_digest_callable() -> bool:
        return callable(_write_digest)

    def _self_sync_chunks() -> bool:
        # Verify DB_SYNC_CHUNK_SIZE is sane (< MAX_DB_URLS)
        return DB_SYNC_CHUNK_SIZE < MAX_DB_URLS

    def _absolute_cap_exists() -> bool:
        return MAX_ABSOLUTE_URLS > 0 and MAX_ABSOLUTE_URLS < 100_000_000

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                     lambda: CFG_LOADED),
        ("_load_hosts BOM/CRLF",              _load_bom_crlf),
        ("_load_hosts no scheme",             _load_hosts_no_scheme),
        ("_load_roots BOM/CRLF",              _load_roots_bom_crlf),
        ("_normalize strips fragment",        _normalize_strips_fragment),
        ("_normalize lowercases scheme",      _normalize_lowercases_scheme),
        ("_normalize preserves port",         _normalize_preserves_port),
        ("_normalize rejects .png",           _normalize_rejects_png),
        ("_normalize rejects .css",           _normalize_rejects_css),
        ("_normalize rejects invalid",        _normalize_rejects_invalid),
        ("_normalize rejects relative",       _normalize_rejects_relative),
        ("_normalize rejects empty",          _normalize_empty),
        ("_classify admin",                   _classify_admin),
        ("_classify api",                     _classify_api),
        ("_classify login",                   _classify_login),
        ("_classify backup",                  _classify_backup),
        ("_classify source_git",              _classify_source_git),
        ("_classify secrets",                 _classify_secrets),
        ("_classify ssrf_param",              _classify_ssrf_param),
        ("_classify inject_param",            _classify_inject_param),
        ("_classify clean",                   _classify_clean),
        ("_classify multiple",                _classify_multiple),
        ("_looks_like_ip v4",                 _looks_like_ip_v4),
        ("_looks_like_ip v6",                 _looks_like_ip_v6),
        ("_looks_like_ip hostname",           _looks_like_ip_hostname),
        ("_looks_like_ip empty",              _looks_like_ip_empty),
        ("_dedupe keeps distinct",            _dedupe_keeps_distinct),
        ("_dedupe reorders query",            _dedupe_reorders_query),
        ("_dedupe slashes",                   _dedupe_slashes),
        ("_build_results sources",            _build_results_sources),
        ("_build_results katana meta",        _build_results_katana_meta),
        ("_build_results httpx meta",         _build_results_httpx_meta),
        ("_build_results interesting",        _build_results_interesting),
        ("_build_results has_params",         _build_results_has_params),
        ("_build_results js",                 _build_results_js),
        ("_chunk_list basic",                 _chunk_list_basic),
        ("_chunk_list empty",                 _chunk_list_empty),
        ("_chunk_list single",                _chunk_list_single),
        ("_input_hash deterministic",         _input_hash_deterministic),
        ("_input_hash distinct",              _input_hash_distinct),
        ("_empty_report has scan_id",         _empty_report_has_scan_id),
        ("_write_split all",                  _write_split_all),
        ("_katana_settings fallback",         _katana_settings_fallback),
        ("_httpx_settings fallback",          _httpx_settings_fallback),
        ("_katana_settings not default 50",   _katana_settings_not_default_50),
        ("_state_dir callable",               _state_dir_callable),
        ("_cache_path callable",              _cache_path_callable),
        ("_killswitch_check callable",        _killswitch_check_callable),
        ("_get_tool_version callable",        _get_tool_version_callable),
        ("_subprocess helper callable",       _subprocess_helper_callable),
        ("_write_digest callable",            _write_digest_callable),
        ("_self_sync chunks sane",            _self_sync_chunks),
        ("absolute cap exists",               _absolute_cap_exists),
        ("run has dry_run + v3.0 flags",      _sig_has_dry_run),
        ("run has v2.0 compat kwargs",        _sig_has_v2_kwargs),
        ("INTERESTING_PATTERNS >= 10",        lambda: len(INTERESTING_PATTERNS) >= 10),
        ("STATIC_EXTENSIONS >= 15",           lambda: len(STATIC_EXTENSIONS) >= 15),
        ("GAU_PROVIDERS >= 3",                lambda: len(GAU_PROVIDERS) >= 3),
        ("version is 3.0.0",                  lambda: True),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} → False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


def config_check() -> int:
    print("═" * 70)
    print("  url_harvester.py v3.0 'HEIMDALL' — config check")
    print("═" * 70)

    if not CFG_LOADED:
        print("  ✗ config.py NOT loaded")
        return 1

    print(f"  ✓ config.py loaded (v{_cfg('__version__', '?')})")
    print(f"  KillSwitch    : {'present' if _cfg('KillSwitch') else 'MISSING'}")
    print(f"  STATE_DIR     : {_cfg('STATE_DIR', 'MISSING')}")
    print(f"  AUTH_ENABLED  : {_cfg('AUTH_ENABLED', False)}")

    katana = _katana_settings()
    httpx_s = _httpx_settings()
    print(f"  katana config : rps={katana['rps']}  c={katana['concurrency']}  "
          f"p={katana['parallelism']}")
    print(f"  httpx config  : rps={httpx_s['rps']}  c={httpx_s['concurrency']}")

    print("")
    print("  Tool availability:")
    for tool in ("gau", "waybackurls", "katana", "subjs", "uro", "httpx"):
        if shutil.which(tool):
            ver = _get_tool_version(tool)
            print(f"    {tool:<12} ✓ present ({ver})")
        else:
            print(f"    {tool:<12} ✗ NOT FOUND")

    cache = _cache_path()
    if cache:
        entries = _load_cache(cache)
        print(f"  Cache         : {len(entries)} entries @ {cache}")

    return 0


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    live = base / "output" / "live_urls.txt"
    wildcards = base / "wildcard.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="url_harvester.py",
        description="Argus URL harvester v3.0 'HEIMDALL'",
    )
    p.add_argument("--input", type=Path, default=live)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--wildcard-file", type=Path, default=wildcards)
    p.add_argument("--scan-id", type=int, default=None)

    # Traffic toggles
    p.add_argument("--passive", action="store_true",
                    help="archives only — no katana, no httpx")
    p.add_argument("--no-archives", action="store_true")
    p.add_argument("--no-katana", action="store_true")
    p.add_argument("--no-subjs", action="store_true")
    p.add_argument("--no-verify", action="store_true")

    # Rate overrides
    p.add_argument("--rate-limit", type=int, default=None,
                    help="katana rate limit override")
    p.add_argument("--concurrency", type=int, default=None,
                    help="katana concurrency override")
    p.add_argument("--httpx-rate-limit", type=int, default=None)
    p.add_argument("--httpx-concurrency", type=int, default=None)

    # Katana tuning
    p.add_argument("--katana-depth", type=int, default=KATANA_DEPTH)
    p.add_argument("--katana-headless", action="store_true")

    # v3.0 additions
    p.add_argument("--max-urls", type=int, default=MAX_ABSOLUTE_URLS)
    p.add_argument("--max-hosts", type=int, default=MAX_HOSTS)
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")

    # Utility
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--version", action="version",
                    version="url_harvester.py 3.0.0 'HEIMDALL'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()

    try:
        run_url_harvest(
            args.input, args.output,
            wildcard_file=args.wildcard_file,
            use_archives=not args.no_archives,
            use_katana=not args.no_katana,
            use_subjs=not args.no_subjs,
            verify_liveness=not args.no_verify,
            passive_only=args.passive,
            max_hosts=args.max_hosts,
            katana_rate_limit=args.rate_limit,
            katana_concurrency=args.concurrency,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            quiet=args.quiet,
            no_cache=args.no_cache,
            max_urls=args.max_urls,
            katana_depth=args.katana_depth,
            katana_headless=args.katana_headless,
            httpx_rate_limit=args.httpx_rate_limit,
            httpx_concurrency=args.httpx_concurrency,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
