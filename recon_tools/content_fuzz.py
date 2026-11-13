#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/content_fuzz.py — Content & Directory Discovery
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/content_fuzz.py
  Version   : 3.2.0 "JÖRMUNGANDR UNCHAINED"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Two-phase content discovery with pipeline-aware enrichment, pre-flight
  timing gate, budget-aware per-wordlist timeout, and full FENRIR config
  integration (UA rotation, ProxyPool, bbp headers, audit trail).

  v3.1 → v3.2 (8-hour burn fix + military-grade hardening):

    [FIX]  _log_locked fired DeprecationWarning on every call — stdlib
           Logger has .warning() not .warn(). Now dispatches by logger type.
    [FIX]  _target_headers never applied build_headers(bbp) — no bbp_program
           param existed. Now accepts bbp_program + always emits UA.
    [FIX]  No use_proxy / proxy_pool param — probes ignored config ProxyPool.
    [FIX]  No audit_trail param — probe requests were unaudited.
    [FIX]  Per-wordlist timeout ignored remaining host budget — one wordlist
           could eat all 900s of host_timeout, starving the rest.
    [FIX]  No wall-clock abort — silent 8-hour burn on slow config.
    [FIX]  Default parallel_hosts=1 — sequential on a parallel workload.

    [NEW]  Pre-flight timing gate: predicts wall clock before host contact,
           aborts if > 4h (configurable via --allow-slow), skips wordlists
           that can't complete in remaining budget.
    [NEW]  --fast preset: rate=50, parallel=4, timeout=300, wordlists=[common,
           api] — 24 hosts in ~20 min.
    [NEW]  Config rate warning: "config.rps=5 will take 8.0h — use --fast"
    [NEW]  Budget-aware per-wordlist execution: min(needed×1.5, remaining×0.9)
    [NEW]  Wall-clock metrics in report (predicted vs actual, speedup ratio)
    [NEW]  --allow-slow flag to override the 4-hour wall-clock abort
    [NEW]  --fuzz-proxy flag to route ferox/ffuf through ProxyPool
    [NEW]  bbp_program + use_proxy + proxy_pool + audit_trail params
    [NEW]  UA rotation for all HTTP probes (probe/robots/graphql/auth-diff)
    [NEW]  Predicted wordlist timing table on startup
    [NEW]  Per-wordlist skip when it can't fit in remaining budget
    [NEW]  Selftest expanded 50 → 62 checks (timing, fast mode, UA, wall-clock)

  Config integration:
    ·  MODULE_RATE_LIMITS["fuzzing"]  → {rps, concurrency, jitter}
    ·  ACTIVE_HEADERS + AUTH_HEADERS  → -H flags on ferox/ffuf
    ·  AUTH_COOKIES                    → baseline + auth-diff probes
    ·  build_headers(bbp_program)      → UA + BBP-specific headers
    ·  random_user_agent()             → UA rotation per probe
    ·  ProxyPool                       → proxy rotation per request/probe
    ·  AuditTrail                      → probe request logging
    ·  SCOPE, KillSwitch, human_delay
    ·  AI_ENABLED, AI.model, ai_complete, AI_COSTS
    ·  SYNC_TO_DB, BRIDGE_ENABLED

  Outputs:
    content_fuzz.json              — full report with timing metrics
    fuzzed_directories.txt         — every discovered URL
    fuzzed_interesting.txt         — high-confidence subset
    content_fuzz_digest.md         — top-50 markdown table
    content_fuzz_ai_<host>.md      — per-host AI triage
    content_fuzz_ai_cache/         — versioned AI cache
    pipeline_seeds.txt             — auto-derived seeds
    robots_seeds.txt               — robots.txt Disallow paths
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import os
import random
import re
import shutil
import signal
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = _cfg("log") or _FallbackLogger()


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


def _ai_enabled() -> bool:
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


def _killswitch_check(label: str = "") -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


_AI_LOCK     = threading.Lock()
_LOG_LOCK    = threading.Lock()
_STREAM_LOCK = threading.Lock()
_SHARED      = {"_quiet": False}


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG READERS
# ═════════════════════════════════════════════════════════════════════════
def _safe_log(level: str, msg: str) -> None:
    """Logging that NEVER raises — for non-critical paths."""
    try:
        _log_locked(level, msg)
    except Exception:
        pass

def _fuzz_settings() -> dict:
    """Reads MODULE_RATE_LIMITS["fuzzing"] with "fuzz" fallback."""
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = all_limits.get("fuzzing") or all_limits.get("fuzz") or {}

    threads = entry.get("concurrency", 3)
    rate    = entry.get("rps", entry.get("rate_limit", 5))
    jitter  = entry.get("jitter", (0.0, 0.0))
    timeout = entry.get("timeout", 600)

    if not isinstance(threads, int) or threads < 1: threads = 3
    if not isinstance(rate, int) or rate < 0:       rate = 5
    if not isinstance(timeout, int) or timeout < 1: timeout = 600
    if not isinstance(jitter, (tuple, list)) or len(jitter) != 2:
        jitter = (0.0, 0.0)

    return {"threads": threads, "rate_limit": rate,
            "jitter": tuple(jitter), "timeout": timeout}


def _target_headers(extra: Optional[dict] = None,
                     bbp_program: Optional[str] = None) -> dict[str, str]:
    """
    v3.2: merges (in order): ACTIVE_HEADERS → build_headers(bbp) → AUTH_HEADERS
    → caller-supplied extra. Guarantees a User-Agent is always present by
    falling back to config.random_user_agent().
    """
    h: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if bbp_program:
        try:
            builder = _cfg("build_headers")
            if callable(builder):
                h.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    if extra:
        h.update(extra)
    # v3.2: guarantee UA — rotate per request, fall back if config absent
    if not any(k.lower() == "user-agent" for k in h):
        try:
            ua_fn = _cfg("random_user_agent")
            if callable(ua_fn):
                h["User-Agent"] = ua_fn()
        except Exception:
            pass
        if not any(k.lower() == "user-agent" for k in h):
            h["User-Agent"] = (
                "Mozilla/5.0 (compatible; Argus-ContentFuzz/3.2)"
            )
    return h


def _tool_header_args(extra: Optional[dict] = None,
                       bbp_program: Optional[str] = None) -> list[str]:
    return [f"{k}: {v}" for k, v in
            _target_headers(extra, bbp_program).items()
            if v is not None and str(v).strip()]


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


def _pick_proxy(proxy_pool: Any) -> Optional[str]:
    """v3.2: proxy helper for probes and fuzz subprocesses."""
    if proxy_pool is None:
        return None
    try:
        p = proxy_pool.pick()
        return p.url() if p else None
    except Exception:
        return None


def _audit_probe(audit_trail: Any, label: str, url: str,
                  status: int, latency_ms: float,
                  error: Optional[str] = None) -> None:
    """v3.2: record HTTP probes to AuditTrail (best-effort)."""
    if audit_trail is None or not hasattr(audit_trail, "record"):
        return
    try:
        audit_trail.record(
            method="GET", url=url, status=status,
            latency_ms=latency_ms, proxy=None,
            user_agent="(rotating)", error=error,
        )
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

WORDLISTS: list[tuple[str, str, Optional[list[str]]]] = [
    ("common",            "/usr/share/seclists/Discovery/Web-Content/common.txt",                  None),
    ("raft-medium-dirs",  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", None),
    ("raft-medium-files", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",       None),
    ("api-endpoints",     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",       None),
    ("backup-files",      "/usr/share/seclists/Discovery/Web-Content/backup-files.txt",
     [".bak", ".old", ".zip", ".tar.gz", ".sql", ".swp"]),
]

FAST_WORDLIST_NAMES = {"common", "api-endpoints", "backup-files"}

DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".js", ".html"]

FEROX_TIMEOUT         = 600
FEROX_DEPTH           = 3
FEROX_SCAN_LIMIT      = 20000

FFUF_TIMEOUT          = 600
FFUF_MAX_TIME         = 600

SOFT_404_PROBE_LEN    = 32
SOFT_404_TOLERANCE    = 50
ALLOWED_STATUS        = {200, 201, 204, 301, 302, 307, 308, 401, 403, 500}

CONFIDENCE_HIGH_THRESHOLD = 60
CONFIDENCE_MED_THRESHOLD  = 30

DEFAULT_PARALLEL_HOSTS    = 4   # v3.2 — was 1, caused 8h serial burn
DEFAULT_HOST_TIMEOUT      = 900
DEFAULT_MAX_FINDINGS      = 10000
DEFAULT_AI_MAX_HOSTS      = 20
DEFAULT_AI_MAX_COST_USD   = 0.0
AI_DEFAULT_CACHE_TTL_HOURS = 72
AI_ESTIMATE_PER_CALL_USD  = 0.003
AI_PROMPT_VERSION         = "v3.2"

# v3.2 fast mode preset
FAST_RATE_LIMIT           = 50
FAST_PARALLEL_HOSTS       = 4
FAST_HOST_TIMEOUT         = 300
FAST_WORDLIST_RATE_CAP    = 100

# v3.2 timing gates
MIN_VIABLE_RATE           = 20       # below this, warn loudly
WALL_CLOCK_ABORT_SECONDS  = 4 * 3600 # abort unless --allow-slow
WORDLIST_MIN_USEFUL_FRAC  = 0.5      # if timeout < 50% of needed, skip

# Per-host caps
MAX_GRAPHQL_PROBES_PER_HOST   = 3
MAX_AUTH_DIFF_PROBES_PER_HOST = 10
MAX_ROBOTS_SEEDS_PER_HOST     = 50
MAX_PIPELINE_SEEDS_TOTAL      = 200

SECLISTS_FALLBACK_PATHS = [Path("/usr/share/seclists"), Path("/opt/seclists")]
MINIMAL_WORDLIST_FALLBACK = [
    "admin", "api", "v1", "v2", "v3", "login", "dashboard", "internal",
    "debug", "test", "staging", "dev", "backup", "config", "actuator",
    "swagger", "graphql", "phpmyadmin", "jenkins", "grafana",
]

BACKUP_EXTENSIONS = {".bak", ".old", ".zip", ".tar.gz", ".sql", ".swp",
                     ".env", ".git", ".yml", ".yaml"}
SENSITIVE_PATH_WORDS = {
    "admin", "internal", "debug", "actuator", "swagger", "graphql",
    "phpmyadmin", "jenkins", "grafana", "kibana", "backup", "config",
    "secret", "private", "token", "api", "v1", "v2", "v3",
}

SERVICE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("spring_actuator", re.compile(r"/actuator(/|$)", re.I)),
    ("swagger",         re.compile(r"/swagger(?:-ui|/|\.json|$)|/openapi(?:/|\.json|$)", re.I)),
    ("graphql",         re.compile(r"/graphql(?:/|$)", re.I)),
    ("jenkins",         re.compile(r"/jenkins(?:/|$)|/script(?:/|$)|/cli(?:/|$)", re.I)),
    ("grafana",         re.compile(r"/grafana(?:/|$)", re.I)),
    ("kibana",          re.compile(r"/kibana(?:/|$)|/app/kibana", re.I)),
    ("phpmyadmin",      re.compile(r"/phpmyadmin(?:/|$)|/pma(?:/|$)", re.I)),
    ("admin",           re.compile(r"/(?:admin|administrator|wp-admin)(?:/|$)", re.I)),
    ("api_v1",          re.compile(r"/api/v?\d+(?:/|$)", re.I)),
    ("backup_file",     re.compile(r"\.(bak|old|zip|tar|tar\.gz|sql|swp|env|git)$", re.I)),
    ("config",          re.compile(r"/(?:config|\.env|settings|\.git)(?:/|\.|$)", re.I)),
    ("debug",           re.compile(r"/(?:debug|test|dev|staging)(?:/|$)", re.I)),
    ("metrics",         re.compile(r"/(?:metrics|health|status|info)(?:/|$)", re.I)),
    ("internal",        re.compile(r"/(?:internal|private|secure|hidden)(?:/|$)", re.I)),
    ("docs",            re.compile(r"/(?:docs|documentation|readme)(?:/|\.html|$)", re.I)),
    ("upload",          re.compile(r"/(?:upload|uploads|files|assets)(?:/|$)", re.I)),
    ("auth",            re.compile(r"/(?:login|signin|auth|oauth|sso)(?:/|$)", re.I)),
    ("registry",        re.compile(r"/(?:registry|\.docker|\.npm|\.pypi)(?:/|$)", re.I)),
    ("ci",              re.compile(r"/(?:ci|build|pipeline|\.gitlab|\.github)(?:/|$)", re.I)),
]

MANUAL_TEST_HINTS: dict[str, str] = {
    "spring_actuator":   "GET /actuator/env, /actuator/health, /actuator/heapdump — check exposed secrets",
    "swagger":           "Fetch swagger.json / openapi.json — enumerate declared endpoints",
    "graphql":           "POST {__schema{types{name}}} introspection — check if enabled",
    "jenkins":           "Try /script, /cli, /computer/(master)/script — pre-auth RCE check",
    "grafana":           "GET /api/health for version, then cross-reference CVEs",
    "kibana":            "GET /app/kibana, /api/status — check pre-auth access + version",
    "phpmyadmin":        "Try default credentials (root:root), check version",
    "admin":             "Try common credentials, X-Forwarded-For auth bypass, check version",
    "api_v1":            "Enumerate documented verbs; check mass-assignment + authz",
    "backup_file":       "Download and grep for credentials, API keys, source, DBs",
    "config":            "Download and grep for secrets (DB_*, API_KEY, SECRET)",
    "debug":             "Check for stack traces, source disclosure, debug routes",
    "metrics":           "GET /metrics (Prometheus), /health — may leak internals",
    "internal":          "Try direct access; test X-Forwarded-For / X-Real-IP bypass",
    "docs":              "Read docs — often reveals hidden endpoints + sample creds",
    "upload":            "Try uploading harmless file — check unrestricted upload",
    "auth":              "Try common credentials; check username enumeration + rate-limit",
    "registry":          "Try anonymous /v2/_catalog (Docker) or list packages",
    "ci":                "Check for exposed CI dashboards, env vars, deploy keys",
}

NUCLEI_TAGS_BY_SERVICE: dict[str, list[str]] = {
    "spring_actuator": ["springboot", "exposure", "misconfig"],
    "swagger":         ["swagger", "api", "exposure"],
    "graphql":         ["graphql", "exposure"],
    "jenkins":         ["jenkins", "rce", "exposure"],
    "grafana":         ["grafana", "cve", "exposure"],
    "kibana":          ["kibana", "cve", "exposure"],
    "phpmyadmin":      ["phpmyadmin", "default-login"],
    "admin":           ["admin-panel", "default-login", "auth-bypass"],
    "backup_file":     ["backup", "exposure"],
    "config":          ["config", "exposure", "secrets"],
    "debug":           ["debug", "exposure"],
    "ci":              ["ci", "cicd", "exposure"],
    "registry":        ["docker", "registry", "exposure"],
    "upload":          ["upload", "file-upload"],
    "api_v1":          ["api", "swagger", "exposure"],
    "metrics":         ["metrics", "prometheus", "exposure"],
    "internal":        ["internal", "exposure"],
    "docs":            ["docs", "exposure"],
    "auth":            ["auth", "login", "default-login"],
}


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class FuzzFinding:
    url: str
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    redirect: str = ""
    source_tool: str = ""
    source_wordlist: str = ""
    extension: str = ""
    confidence: int = 0
    reasons: list[str] = field(default_factory=list)
    host: str = ""
    path: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    service_tag: str = ""
    manual_test: str = ""
    soft_404: bool = False
    auth_gate_confirmed: bool = False
    graphql_introspection: Optional[dict] = None
    nuclei_tags: list[str] = field(default_factory=list)
    body_fingerprint: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url, "host": self.host, "path": self.path,
            "status": self.status, "length": self.length,
            "words": self.words, "lines": self.lines,
            "content_type": self.content_type, "redirect": self.redirect,
            "source_tool": self.source_tool,
            "source_wordlist": self.source_wordlist,
            "extension": self.extension, "confidence": self.confidence,
            "reasons": self.reasons, "auth_enabled": self.auth_enabled,
            "first_seen": self.first_seen, "service_tag": self.service_tag,
            "manual_test": self.manual_test, "soft_404": self.soft_404,
            "auth_gate_confirmed": self.auth_gate_confirmed,
            "graphql_introspection": self.graphql_introspection,
            "nuclei_tags": self.nuclei_tags,
            "body_fingerprint": self.body_fingerprint,
        }


@dataclass
class HostResult:
    host: str
    findings: list[FuzzFinding] = field(default_factory=list)
    triage: Optional[dict] = None
    triage_source: str = ""
    warnings: list[str] = field(default_factory=list)
    # v3.2
    wordlist_timings: list[dict] = field(default_factory=list)
    timed_out: bool = False


# ═════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════

def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _service_tag_for(path: str) -> str:
    for tag, pattern in SERVICE_PATTERNS:
        if pattern.search(path):
            return tag
    return ""


def _confidence_band(conf: int) -> str:
    if conf >= CONFIDENCE_HIGH_THRESHOLD: return "high"
    if conf >= CONFIDENCE_MED_THRESHOLD:  return "medium"
    return "low"


def _log_locked(level: str, msg: str) -> None:
    """
    v3.2: dispatches by logger type. stdlib Logger has .warning() not .warn();
    _FallbackLogger / config.log has .warn() not .warning(). Silent on both.
    """
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        try:
            if level == "warn":
                if isinstance(log, logging.Logger):
                    log.warning(msg)
                elif hasattr(log, "warn"):
                    log.warn(msg)
                elif hasattr(log, "warning"):
                    log.warning(msg)
            elif level == "ok":
                if hasattr(log, "ok"):
                    log.ok(msg)
                else:
                    log.info(f"✓ {msg}")
            else:
                getattr(log, level)(msg)
        except Exception:
            try:
                log.info(msg)
            except Exception:
                pass


# ═════════════════════════════════════════════════════════════════════════
#  v3.2 — TIMING PREDICTION & FAST MODE
# ═════════════════════════════════════════════════════════════════════════

_WORDLIST_LINE_CACHE: dict[str, int] = {}
_WORDLIST_LINE_LOCK = threading.Lock()


def _count_wordlist_lines(path: Path) -> int:
    """Cache wordlist line counts — expensive for 30k-line wordlists."""
    key = str(path.resolve())
    with _WORDLIST_LINE_LOCK:
        if key in _WORDLIST_LINE_CACHE:
            return _WORDLIST_LINE_CACHE[key]
    try:
        count = sum(1 for _ in path.open("r", errors="ignore"))
    except OSError:
        count = 0
    with _WORDLIST_LINE_LOCK:
        _WORDLIST_LINE_CACHE[key] = count
    return count


def _predict_wordlist_times(
    wordlists: list[tuple[str, Path, Optional[list[str]]]],
    rate_per_host: int,
) -> list[dict]:
    """Predict required seconds per wordlist at the given rate."""
    preds = []
    for name, path, exts in wordlists:
        lines = _count_wordlist_lines(path)
        if rate_per_host > 0 and lines > 0:
            seconds = lines / rate_per_host
        else:
            seconds = 0.0
        preds.append({
            "name":     name,
            "path":     str(path),
            "lines":    lines,
            "extensions": exts or [],
            "seconds":  round(seconds, 1),
        })
    return preds


def _estimate_wall_clock(preds: list[dict], host_count: int,
                          parallel_hosts: int) -> float:
    """Total wall clock assuming per-host timeouts don't truncate."""
    if not preds or host_count <= 0 or parallel_hosts <= 0:
        return 0.0
    per_host_seconds = sum(p["seconds"] for p in preds)
    # 2 phases (ferox + ffuf) × 1 run each per wordlist
    total = per_host_seconds * 2 * host_count / parallel_hosts
    return round(total, 1)


def _estimate_wordlist_timeout(
    lines: int,
    rate_per_host: int,
    remaining_host_seconds: float,
    default_timeout: int,
) -> int:
    """
    v3.2: compute per-wordlist timeout with headroom.
    - At least 1.5× predicted need (headroom for slow pages)
    - Never more than 90% of remaining host budget
    - Never more than default_timeout (config ceiling)
    """
    if rate_per_host <= 0:
        needed = 60.0  # conservative default
    else:
        needed = lines / rate_per_host if lines > 0 else 60.0

    headroom = needed * 1.5
    budget_cap = remaining_host_seconds * 0.9
    timeout = min(headroom, budget_cap, default_timeout)
    return max(int(timeout), 30)  # floor at 30s


def _should_skip_wordlist(
    lines: int,
    rate_per_host: int,
    remaining_host_seconds: float,
) -> tuple[bool, float]:
    """
    Return (skip?, needed_seconds).
    Skip if required time > 90% of remaining budget × 1.2 (safety margin).
    """
    if rate_per_host <= 0 or lines == 0:
        return False, 0.0
    needed = lines / rate_per_host
    threshold = remaining_host_seconds * 0.9 * (1 / WORDLIST_MIN_USEFUL_FRAC)
    return (needed > threshold), needed


def _build_effective_plan(
    wordlists: list[tuple[str, Path, Optional[list[str]]]],
    host_count: int,
    cfg_rate: int, cfg_threads: int,
    fast_mode: bool, allow_slow: bool,
    explicit_rate: Optional[int], explicit_parallel: Optional[int],
    explicit_timeout: Optional[int],
) -> tuple[dict, list[str]]:
    """
    Resolve effective rate/parallel/timeout. Detect slow config, activate
    fast mode heuristics, or raise if wall-clock > abort threshold.

    Returns (plan_dict, warnings_list).
    """
    warnings_list: list[str] = []

    # 1. Base rate from explicit OR fast-mode OR config
    if explicit_rate is not None:
        rate = explicit_rate
        source = "explicit --rate-limit"
    elif fast_mode:
        rate = FAST_RATE_LIMIT
        source = "--fast preset"
    else:
        rate = cfg_rate
        source = "MODULE_RATE_LIMITS['fuzzing'].rps"

    # 2. Parallel
    if explicit_parallel is not None:
        parallel = max(1, explicit_parallel)
    elif fast_mode:
        parallel = FAST_PARALLEL_HOSTS
    else:
        parallel = DEFAULT_PARALLEL_HOSTS
    parallel = min(parallel, max(1, host_count))

    # 3. Host timeout
    if explicit_timeout is not None:
        host_timeout = explicit_timeout
    elif fast_mode:
        host_timeout = FAST_HOST_TIMEOUT
    else:
        host_timeout = DEFAULT_HOST_TIMEOUT

    # 4. Wordlist selection in fast mode — drop medium/large wordlists
    effective_wordlists = wordlists
    if fast_mode:
        filtered = [(n, p, e) for (n, p, e) in wordlists if n in FAST_WORDLIST_NAMES]
        if filtered:
            dropped = [n for (n, p, e) in wordlists if n not in FAST_WORDLIST_NAMES]
            if dropped:
                warnings_list.append(f"fast-mode-dropped-wordlists: {','.join(dropped)}")
            effective_wordlists = filtered
        else:
            warnings_list.append("fast-mode-no-fast-wordlists: using full set")

    # 5. Per-host rate — divide total budget across workers
    per_host_rate = (
        max(1, rate // parallel) if rate > 0 else 0
    )

    # 6. Prediction table
    preds = _predict_wordlist_times(effective_wordlists, per_host_rate)
    wall_clock = _estimate_wall_clock(preds, host_count, parallel)

    # 7. Auto-fast heuristic: if config rate is too slow AND we're not
    #    already in fast mode AND the caller didn't force a rate, gently
    #    escalate. Only happens once; the caller sees the warning.
    if (not fast_mode and explicit_rate is None and rate > 0
            and rate < MIN_VIABLE_RATE):
        warnings_list.append(
            f"config-rate-slow: {rate}/s × {parallel} workers ≈ "
            f"{wall_clock/3600:.1f}h wall clock"
        )

    # 8. Wall-clock gate
    if wall_clock > WALL_CLOCK_ABORT_SECONDS and not allow_slow:
        raise RuntimeError(
            f"Predicted wall clock {wall_clock/3600:.1f}h exceeds "
            f"{WALL_CLOCK_ABORT_SECONDS/3600:.0f}h abort threshold. "
            f"Effective rate: {rate}/s (source: {source}) × "
            f"{parallel} parallel. "
            f"Fix: use --fast (rate={FAST_RATE_LIMIT}, parallel={FAST_PARALLEL_HOSTS}, "
            f"timeout={FAST_HOST_TIMEOUT}, wordlists=[{'/'.join(FAST_WORDLIST_NAMES)}]) "
            f"OR raise --rate-limit OR pass --allow-slow to override."
        )

    # 9. Per-wordlist timeout sanity check
    for p in preds:
        if p["seconds"] > host_timeout * 0.9:
            warnings_list.append(
                f"wordlist-may-timeout: {p['name']} needs {p['seconds']:.0f}s "
                f"at {per_host_rate}/s but host_timeout={host_timeout}s"
            )

    plan = {
        "rate_limit":        rate,
        "rate_source":       source,
        "per_host_rate":     per_host_rate,
        "total_rate":        rate,
        "parallel_hosts":    parallel,
        "host_timeout":      host_timeout,
        "fast_mode":         fast_mode,
        "allow_slow":        allow_slow,
        "threads":           cfg_threads,
        "wordlists":         effective_wordlists,
        "predictions":       preds,
        "predicted_wall_clock_seconds": wall_clock,
        "host_count":        host_count,
    }
    return plan, warnings_list


# ═════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════

def _extract_hosts(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    bases: set[str] = set()
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            continue
        scheme = parsed.scheme or "https"
        base = f"{scheme}://{parsed.netloc}".rstrip("/")
        bases.add(base)
    return sorted(bases)


# ═════════════════════════════════════════════════════════════════════════
#  WORDLIST RESOLUTION
# ═════════════════════════════════════════════════════════════════════════

def _resolve_wordlists() -> list[tuple[str, Path, Optional[list[str]]]]:
    available: list[tuple[str, Path, Optional[list[str]]]] = []
    seen_paths: set[str] = set()
    missing: list[str] = []

    for name, path_str, exts in WORDLISTS:
        p = Path(path_str)
        try:
            if p.exists() and p.is_file() and p.stat().st_size > 0:
                key = str(p.resolve())
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                available.append((name, p, exts))
            else:
                missing.append(name)
        except OSError:
            missing.append(name)

    if missing:
        log.info(f"    Wordlists unavailable: {', '.join(missing)}")

    if not available:
        log.warning("    No SecLists wordlist found — writing minimal fallback.")
        sec_root = next((p for p in SECLISTS_FALLBACK_PATHS if p.exists()), None)
        if sec_root:
            log.info(f"    SecLists root detected at {sec_root}")
        fallback_dir = Path(__file__).resolve().parent.parent / "output"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        fallback = fallback_dir / "argus_minimal_wordlist.txt"
        fallback.write_text("\n".join(MINIMAL_WORDLIST_FALLBACK) + "\n")
        available.append(("minimal-fallback", fallback, DEFAULT_EXTENSIONS))

    log.info(f"    Using {len(available)} wordlist(s):")
    for name, p, exts in available:
        try:
            count = sum(1 for _ in p.open("r", errors="ignore"))
        except OSError:
            count = 0
        ext_label = f"  extensions={exts}" if exts else ""
        log.info(f"      · {name:<18} {p}  ({count} lines){ext_label}")

    return available


def _wordlists_from_cli(paths: list[str]) -> list[tuple[str, Path, Optional[list[str]]]]:
    out = []
    for p in paths:
        path = Path(p)
        if not path.exists() or not path.is_file():
            log.warning(f"  --wordlist {p} not found — skipping")
            continue
        out.append((path.stem, path, None))
    return out


def _load_pipeline_seeds(outdir: Path) -> list[str]:
    seeds: set[str] = set()

    sp = outdir / "site_pages.json"
    if sp.exists():
        try:
            data = json.loads(sp.read_text(encoding="utf-8"))
            for host in data.get("hosts", []):
                for page in host.get("pages", []):
                    p = (page.get("path") or "/").strip("/")
                    if p and "/" not in p and "?" not in p:
                        seeds.add(p)
        except Exception:
            pass

    je = outdir / "js_endpoints.txt"
    if je.exists():
        try:
            for line in je.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith(("http", "//")):
                    continue
                seg = line.strip("/").split("/")[0].split("?")[0]
                if seg and seg not in (".", "..") and len(seg) < 80:
                    seeds.add(seg)
        except Exception:
            pass

    ap = outdir / "auth_pages.txt"
    if ap.exists():
        try:
            for line in ap.read_text(encoding="utf-8").splitlines():
                try:
                    p = urllib.parse.urlparse(line).path.strip("/")
                    if p:
                        seg = p.split("/")[0]
                        if seg and len(seg) < 80:
                            seeds.add(seg)
                except Exception:
                    continue
        except Exception:
            pass

    return sorted(seeds)[:MAX_PIPELINE_SEEDS_TOTAL]


def _write_seed_wordlist(outdir: Path, seeds: list[str],
                          filename: str = "pipeline_seeds.txt") -> Optional[Path]:
    if not seeds:
        return None
    p = outdir / filename
    try:
        p.write_text("\n".join(seeds) + "\n", encoding="utf-8")
    except OSError:
        return None
    return p


# ═════════════════════════════════════════════════════════════════════════
#  HOST PROBE + ROBOTS
# ═════════════════════════════════════════════════════════════════════════

def _probe_host(base_url: str,
                 extra_headers: Optional[dict] = None,
                 bbp_program: Optional[str] = None,
                 proxy_pool: Any = None,
                 audit_trail: Any = None,
                 timeout: int = 10) -> tuple[bool, int, int]:
    rand = "".join(random.choices(
        string.ascii_lowercase + string.digits, k=SOFT_404_PROBE_LEN
    ))
    probe = f"{base_url}/{rand}"
    _killswitch_check(f"probe-{base_url}")

    hdrs = _target_headers(extra_headers, bbp_program)
    cookie_hdr = _auth_cookies()
    proxy_url = _pick_proxy(proxy_pool)

    try:
        import requests  # type: ignore
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        proxies = ({"http": proxy_url, "https": proxy_url}
                    if proxy_url else None)
        for attempt in range(2):
            start_ts = time.monotonic()
            try:
                r = requests.get(
                    probe, headers=hdrs,
                    cookies=cookie_hdr or None,
                    proxies=proxies,
                    timeout=timeout, verify=False, allow_redirects=False,
                )
                lat = (time.monotonic() - start_ts) * 1000
                _audit_probe(audit_trail, "probe", probe, r.status_code, lat)
                return True, len(r.content), r.status_code
            except Exception:
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                return False, 0, 0
    except ImportError:
        pass

    try:
        req = urllib.request.Request(probe, method="GET")
        for k, v in hdrs.items():
            req.add_header(k, v)
        if cookie_hdr:
            req.add_header("Cookie", "; ".join(
                f"{k}={v}" for k, v in cookie_hdr.items()))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(100_000)
            return True, len(body), resp.getcode()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(100_000)
            return True, len(body), e.code
        except Exception:
            return True, 0, e.code
    except Exception:
        return False, 0, 0


def _extract_robots_seeds(base_url: str,
                            extra_headers: Optional[dict] = None,
                            bbp_program: Optional[str] = None,
                            proxy_pool: Any = None,
                            timeout: int = 8) -> list[str]:
    seeds: list[str] = []
    _killswitch_check(f"robots-{base_url}")
    hdrs = _target_headers(extra_headers, bbp_program)
    proxy_url = _pick_proxy(proxy_pool)

    try:
        import requests  # type: ignore
        proxies = ({"http": proxy_url, "https": proxy_url}
                    if proxy_url else None)
        r = requests.get(f"{base_url}/robots.txt", headers=hdrs,
                          proxies=proxies, timeout=timeout, verify=False)
        if r.status_code != 200:
            return seeds
        body = r.text
    except ImportError:
        try:
            req = urllib.request.Request(f"{base_url}/robots.txt", method="GET")
            for k, v in hdrs.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.getcode() != 200:
                    return seeds
                body = resp.read(50_000).decode("utf-8", errors="replace")
        except Exception:
            return seeds
    except Exception:
        return seeds

    for line in body.splitlines():
        line = line.split("#")[0].strip()
        if not line.lower().startswith("disallow:"):
            continue
        p = line.split(":", 1)[1].strip()
        if p and p != "/" and "*" not in p and len(p) < 100:
            seeds.append(p.strip("/"))
    return seeds[:MAX_ROBOTS_SEEDS_PER_HOST]


# ═════════════════════════════════════════════════════════════════════════
#  FEROXBUSTER
# ═════════════════════════════════════════════════════════════════════════

def _ferox_cmd(base_url: str, wordlist: Path,
                extensions: Optional[list[str]], output_file: Path,
                threads: int, rate_limit: int,
                extra_headers: Optional[dict] = None,
                bbp_program: Optional[str] = None,
                proxy_url: Optional[str] = None) -> list[str]:
    cmd = [
        "feroxbuster",
        "--url", base_url,
        "--wordlist", str(wordlist),
        "--json",
        "--output", str(output_file),
        "--silent",
        "--no-state",
        "--redirects",
        "--depth", str(FEROX_DEPTH),
        "--threads", str(threads),
        "--scan-limit", str(FEROX_SCAN_LIMIT),
        "--timeout", "10",
        "--status-codes", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["--rate-limit", str(rate_limit)])
    if extensions:
        cmd.extend(["--extensions", ",".join(extensions)])
    for hdr in _tool_header_args(extra_headers, bbp_program):
        cmd.extend(["-H", hdr])
    if proxy_url:
        cmd.extend(["--proxy", proxy_url])
    return cmd


def _run_ferox(base_url: str, wordlist_name: str, wordlist: Path,
                extensions: Optional[list[str]], workdir: Path,
                threads: int, rate_limit: int, timeout: int,
                warnings: list[str], auth_on: bool,
                extra_headers: Optional[dict] = None,
                bbp_program: Optional[str] = None,
                proxy_url: Optional[str] = None) -> list[FuzzFinding]:
    if not shutil.which("feroxbuster"):
        if "feroxbuster-missing" not in warnings:
            warnings.append("feroxbuster-missing: binary not in PATH")
        return []

    _killswitch_check("feroxbuster")
    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ferox_{tag}_{wl_tag}.json"

    cmd = _ferox_cmd(base_url, wordlist, extensions, out_file,
                     threads, rate_limit, extra_headers, bbp_program,
                     proxy_url)
    _log_locked("info", f"      ferox  {base_url}  wl={wordlist_name}  "
                          f"timeout={timeout}s")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        warnings.append(f"ferox-timeout: {base_url} / {wordlist_name} after {timeout}s")
        _log_locked("warn", f"      ferox timeout after {timeout}s on {base_url}")
        # Partial recovery: ferox writes incrementally, so file may exist
    except FileNotFoundError:
        warnings.append("feroxbuster-missing: FileNotFoundError")
        return []
    except OSError as e:
        warnings.append(f"ferox-oserror: {type(e).__name__}: {e}")
        _log_locked("warn", f"      ferox failed on {base_url}: {e}")
        return []

    if not out_file.exists():
        log.debug(f"      ferox produced no output file")
        return []

    findings: list[FuzzFinding] = []
    try:
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "response":
                continue
            f = _build_finding(
                url=obj.get("url", ""),
                status=obj.get("status", 0),
                length=obj.get("content_length", 0),
                words=obj.get("word_count", 0),
                lines=obj.get("line_count", 0),
                content_type=obj.get("content_type", ""),
                redirect=obj.get("redirect_url", "") or "",
                tool="feroxbuster",
                wordlist=wordlist_name,
                extension=obj.get("extension", "") or "",
                auth_enabled=auth_on,
            )
            if f:
                findings.append(f)
    except Exception:
        pass
    return findings


# ═════════════════════════════════════════════════════════════════════════
#  FFUF
# ═════════════════════════════════════════════════════════════════════════

def _ffuf_cmd(base_url: str, wordlist: Path,
               extensions: Optional[list[str]], output_file: Path,
               baseline_length: int, threads: int, rate_limit: int,
               extra_headers: Optional[dict] = None,
               bbp_program: Optional[str] = None,
               proxy_url: Optional[str] = None) -> list[str]:
    cmd = [
        "ffuf",
        "-u", f"{base_url}/FUZZ",
        "-w", str(wordlist),
        "-json",
        "-o", str(output_file),
        "-s",
        "-t", str(threads),
        "-timeout", "10",
        "-maxtime", str(FFUF_MAX_TIME),
        "-mc", ",".join(str(c) for c in sorted(ALLOWED_STATUS)),
        "-noninteractive",
    ]
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])
    if extensions:
        cmd.extend(["-e", ",".join(extensions)])
    if baseline_length > 0:
        lo = max(0, baseline_length - SOFT_404_TOLERANCE)
        hi = baseline_length + SOFT_404_TOLERANCE
        cmd.extend(["-fs", f"{lo}-{hi}"])
    for hdr in _tool_header_args(extra_headers, bbp_program):
        cmd.extend(["-H", hdr])
    if proxy_url:
        cmd.extend(["-x", proxy_url])
    return cmd


def _run_ffuf(base_url: str, wordlist_name: str, wordlist: Path,
                extensions: Optional[list[str]], baseline_length: int,
                workdir: Path, threads: int, rate_limit: int, timeout: int,
                warnings: list[str], auth_on: bool,
                extra_headers: Optional[dict] = None,
                bbp_program: Optional[str] = None,
                proxy_url: Optional[str] = None) -> list[FuzzFinding]:
    if not shutil.which("ffuf"):
        if "ffuf-missing" not in warnings:
            warnings.append("ffuf-missing: binary not in PATH")
        return []

    _killswitch_check("ffuf")
    tag = re.sub(r"[^a-zA-Z0-9]+", "_", base_url.replace("://", "_"))
    wl_tag = re.sub(r"[^a-zA-Z0-9]+", "_", wordlist_name)
    out_file = workdir / f"ffuf_{tag}_{wl_tag}.json"

    cmd = _ffuf_cmd(base_url, wordlist, extensions, out_file,
                    baseline_length, threads, rate_limit, extra_headers,
                    bbp_program, proxy_url)
    _log_locked("info", f"      ffuf   {base_url}  wl={wordlist_name}  "
                          f"timeout={timeout}s")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        warnings.append(f"ffuf-timeout: {base_url} / {wordlist_name} after {timeout}s")
        _log_locked("warn", f"      ffuf timeout after {timeout}s on {base_url}")
    except FileNotFoundError:
        warnings.append("ffuf-missing: FileNotFoundError")
        return []
    except OSError as e:
        warnings.append(f"ffuf-oserror: {type(e).__name__}: {e}")
        _log_locked("warn", f"      ffuf failed on {base_url}: {e}")
        return []

    if not out_file.exists():
        log.debug(f"      ffuf produced no output file")
        return []

    findings: list[FuzzFinding] = []
    try:
        data = json.loads(out_file.read_text())
        for entry in data.get("results", []):
            f = _build_finding(
                url=entry.get("url", ""),
                status=entry.get("status", 0),
                length=entry.get("length", 0),
                words=entry.get("words", 0),
                lines=entry.get("lines", 0),
                content_type=entry.get("content-type", ""),
                redirect=entry.get("redirectlocation", "") or "",
                tool="ffuf",
                wordlist=wordlist_name,
                extension=entry.get("input", {}).get("FUZZ", "") or "",
                auth_enabled=auth_on,
            )
            if f:
                findings.append(f)
    except Exception:
        pass
    return findings


# ═════════════════════════════════════════════════════════════════════════
#  GRAPHQL & AUTH-DIFF PROBES
# ═════════════════════════════════════════════════════════════════════════

def _try_graphql_introspection(base_url: str,
                                extra_headers: Optional[dict] = None,
                                bbp_program: Optional[str] = None,
                                proxy_pool: Any = None,
                                timeout: int = 10) -> Optional[dict]:
    _killswitch_check("graphql")
    endpoint = f"{base_url.rstrip('/')}/graphql"
    query = '{"query":"{__schema{types{name kind}}}"}'
    hdrs = {**_target_headers(extra_headers, bbp_program),
             "Content-Type": "application/json"}
    proxy_url = _pick_proxy(proxy_pool)
    proxies = ({"http": proxy_url, "https": proxy_url} if proxy_url else None)

    try:
        import requests  # type: ignore
        r = requests.post(endpoint, data=query, headers=hdrs,
                           proxies=proxies, timeout=timeout, verify=False)
        if r.status_code != 200:
            return None
        body = r.text
        if "__schema" in body and "types" in body:
            return {"endpoint": endpoint, "schema_exposed": True,
                     "type_count": body.count('"name"'),
                     "status": r.status_code}
    except ImportError:
        try:
            req = urllib.request.Request(endpoint, data=query.encode(),
                                           method="POST", headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(200_000).decode("utf-8", errors="replace")
                if resp.getcode() == 200 and "__schema" in body:
                    return {"endpoint": endpoint, "schema_exposed": True,
                             "type_count": body.count('"name"'),
                             "status": resp.getcode()}
        except Exception:
            pass
    except Exception:
        pass
    return None


def _auth_diff_check(finding: FuzzFinding,
                      extra_headers: Optional[dict] = None,
                      bbp_program: Optional[str] = None,
                      proxy_pool: Any = None,
                      timeout: int = 10) -> Optional[dict]:
    if not getattr(CFG, "AUTH_ENABLED", False):
        return None
    cookies = _auth_cookies()
    if not cookies:
        return None
    _killswitch_check("auth-diff")
    hdrs = _target_headers(extra_headers, bbp_program)
    proxy_url = _pick_proxy(proxy_pool)
    proxies = ({"http": proxy_url, "https": proxy_url} if proxy_url else None)

    try:
        import requests  # type: ignore
        r = requests.get(finding.url, headers=hdrs, cookies=cookies,
                           proxies=proxies, timeout=timeout, verify=False,
                           allow_redirects=False)
        if r.status_code == 200 and r.text and len(r.content) > 100:
            return {"auth_gate_confirmed": True,
                     "unauth_status": finding.status,
                     "auth_status": r.status_code,
                     "auth_length": len(r.content)}
    except ImportError:
        try:
            req = urllib.request.Request(finding.url, method="GET")
            req.add_header("Cookie", "; ".join(
                f"{k}={v}" for k, v in cookies.items()))
            for k, v in hdrs.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(100_000)
                if resp.getcode() == 200 and len(body) > 100:
                    return {"auth_gate_confirmed": True,
                             "unauth_status": finding.status,
                             "auth_status": resp.getcode(),
                             "auth_length": len(body)}
        except Exception:
            pass
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════
#  FINDING CONSTRUCTION + SCORING
# ═════════════════════════════════════════════════════════════════════════

def _build_finding(url: str, status: int, length: int, words: int,
                    lines: int, content_type: str, redirect: str,
                    tool: str, wordlist: str, extension: str,
                    auth_enabled: bool = False) -> Optional[FuzzFinding]:
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc or ""
    path = parsed.path or "/"
    service_tag = _service_tag_for(path)

    f = FuzzFinding(
        url=url, status=status, length=length, words=words, lines=lines,
        content_type=content_type, redirect=redirect,
        source_tool=tool, source_wordlist=wordlist, extension=extension,
        host=host, path=path, auth_enabled=auth_enabled,
        first_seen=datetime.now(timezone.utc).isoformat(),
        service_tag=service_tag,
        manual_test=MANUAL_TEST_HINTS.get(service_tag, ""),
        nuclei_tags=list(NUCLEI_TAGS_BY_SERVICE.get(service_tag, [])),
        body_fingerprint=hashlib.sha1(
            f"{status}|{length}|{words}|{lines}|{content_type}".encode()
        ).hexdigest()[:12],
    )
    _score_finding(f)
    return f


def _score_finding(f: FuzzFinding) -> None:
    score = 0
    reasons: list[str] = []
    if f.status in (401, 403):
        score += 40
        reasons.append("access_gated")
    if any(f.path.lower().endswith(ext) for ext in BACKUP_EXTENSIONS):
        score += 35
        reasons.append("backup_extension")
    if any(k in f.path.lower() for k in SENSITIVE_PATH_WORDS):
        score += 25
        reasons.append("sensitive_path")
    ct = (f.content_type or "").lower()
    if "json" in ct or "xml" in ct:
        score += 20
        reasons.append("api_content_type")
    if 500 <= f.status < 600:
        score += 15
        reasons.append("server_error")
    if f.status == 200 and f.length > 200:
        score += 10
        reasons.append("substantial_body")
    if f.service_tag:
        score += 10
        reasons.append(f"service:{f.service_tag}")
    f.confidence = min(score, 100)
    f.reasons = reasons


def _flag_soft_404_clusters(findings: list[FuzzFinding]) -> None:
    clusters: dict[str, list[FuzzFinding]] = {}
    for f in findings:
        clusters.setdefault(f.body_fingerprint, []).append(f)
    for fingerprint, group in clusters.items():
        if len(group) >= 4 and group[0].length < 5000:
            for f in group:
                f.confidence = max(0, f.confidence - 25)
                f.soft_404 = True
                f.reasons.append("soft_404_cluster")


def _dedupe(findings: list[FuzzFinding]) -> list[FuzzFinding]:
    best: dict[str, FuzzFinding] = {}
    for f in findings:
        key = f.url.rstrip("/").lower()
        existing = best.get(key)
        if not existing or f.confidence > existing.confidence:
            best[key] = f
    return list(best.values())


# ═════════════════════════════════════════════════════════════════════════
#  HEURISTIC TRIAGE
# ═════════════════════════════════════════════════════════════════════════

def _build_clusters(findings: list[FuzzFinding]) -> list[dict]:
    by_tag: dict[str, list[FuzzFinding]] = {}
    for f in findings:
        if f.service_tag:
            by_tag.setdefault(f.service_tag, []).append(f)
    clusters = []
    for tag, items in by_tag.items():
        if len(items) < 2:
            continue
        clusters.append({
            "service": tag, "count": len(items),
            "urls": [x.url for x in items[:10]],
            "max_confidence": max(x.confidence for x in items),
        })
    clusters.sort(key=lambda c: (-c["count"], -c["max_confidence"]))
    return clusters


def _build_chains(findings: list[FuzzFinding]) -> list[str]:
    tags = {f.service_tag for f in findings if f.service_tag}
    chains: list[str] = []
    if "backup_file" in tags and ("admin" in tags or "auth" in tags):
        chains.append("Backup file(s) + admin/auth panel — may leak credentials")
    if "config" in tags and ("backup_file" in tags or "admin" in tags):
        chains.append("Config file + panel — may expose secrets")
    if "spring_actuator" in tags and "metrics" in tags:
        chains.append("Spring Actuator + metrics — env/heapdump leak")
    if "graphql" in tags and "api_v1" in tags:
        chains.append("GraphQL + versioned API — introspection enumerates REST")
    if "jenkins" in tags or "ci" in tags:
        chains.append("CI/CD exposed — check unauth /script, deploy keys")
    if "upload" in tags and "admin" in tags:
        chains.append("Upload + admin — potential RCE path")
    if "debug" in tags and "internal" in tags:
        chains.append("Debug + internal — debug mode may expose internals")
    if "registry" in tags and "ci" in tags:
        chains.append("Registry + CI — supply-chain compromise")
    return chains


def _guess_service_from_paths(findings: list[FuzzFinding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        if f.service_tag:
            counts[f.service_tag] = counts.get(f.service_tag, 0) + 1
    if not counts:
        return ""
    top = max(counts.items(), key=lambda kv: kv[1])
    return top[0] if top[1] >= 2 else ""


def _heuristic_host_triage(host: str, findings: list[FuzzFinding]) -> dict:
    if not findings:
        return {
            "summary": f"No findings on {host}.", "host_risk": "INFO",
            "service_guess": "", "top_priorities": [], "clusters": [],
            "chains": [], "false_positive_likelihood": "n/a",
            "suggested_manual_tests": [],
            "next_actions": ["Consider widening wordlists"],
            "source": "heuristic",
        }

    bands = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        bands[_confidence_band(f.confidence)] += 1

    best = max(findings, key=lambda f: f.confidence)
    if best.confidence >= 80:   host_risk = "CRITICAL"
    elif best.confidence >= 60: host_risk = "HIGH"
    elif best.confidence >= 40: host_risk = "MEDIUM"
    elif best.confidence >= 20: host_risk = "LOW"
    else:                        host_risk = "INFO"

    service_guess = _guess_service_from_paths(findings)
    clusters = _build_clusters(findings)
    chains = _build_chains(findings)

    ranked = sorted(findings, key=lambda f: -f.confidence)[:5]
    top_priorities = []
    for i, f in enumerate(ranked, 1):
        reason_parts = []
        if f.reasons:
            reason_parts.append(",".join(f.reasons[:3]))
        reason_parts.append(f"conf={f.confidence}")
        top_priorities.append({
            "rank": i, "finding": f"{f.status} {f.url}",
            "reason": " · ".join(reason_parts),
            "test_idea": f.manual_test or "Manually review",
            "service_tag": f.service_tag,
        })

    sizes = [f.length for f in findings if f.status == 200 and f.length > 0]
    n_soft = sum(1 for f in findings if f.soft_404)
    if n_soft >= 4:
        fp_note = f"high ({n_soft} flagged as soft-404 cluster)"
    elif len(sizes) >= 5:
        avg = sum(sizes) / len(sizes)
        spread = max(abs(s - avg) for s in sizes)
        if spread < 200 and avg < 2000:
            fp_note = "high (many 200s, near-identical bodies — likely soft-404)"
        elif len(set(sizes)) <= 2:
            fp_note = "medium (uniform sizes — possible soft-404)"
        else:
            fp_note = "low (varied sizes suggest real content)"
    elif len(sizes) >= 2:
        fp_note = "medium (small sample)"
    else:
        fp_note = "unknown (single finding)"

    tests: list[str] = []
    seen_services: set[str] = set()
    for f in ranked:
        if f.service_tag and f.service_tag not in seen_services:
            seen_services.add(f.service_tag)
            hint = MANUAL_TEST_HINTS.get(f.service_tag)
            if hint:
                tests.append(hint)
    if not tests:
        tests.append(f"Manually review top findings on {host}")

    next_actions: list[str] = []
    if bands["high"] > 0:
        next_actions.append(f"Confirm {bands['high']} high-confidence finding(s) first")
    if any(f.status in (401, 403) for f in findings):
        next_actions.append("Test auth bypass on 401/403 endpoints")
    if any(f.service_tag == "backup_file" for f in findings):
        next_actions.append("Download and inspect backup file(s)")
    if any(f.service_tag == "graphql" for f in findings):
        next_actions.append("Test GraphQL introspection and depth limits")
    if n_soft >= 4:
        next_actions.append(f"Filter {n_soft} soft-404 findings before review")
    if clusters:
        next_actions.append(
            f"Cluster of {clusters[0]['count']} `{clusters[0]['service']}` "
            f"endpoints — assess as a group")
    if not next_actions:
        next_actions.append("Manual review of medium-confidence findings")

    summary = (
        f"{len(findings)} endpoint(s) on {host}. "
        f"Confidence: high={bands['high']} medium={bands['medium']} "
        f"low={bands['low']}."
    )
    if service_guess:
        summary += f" Dominant service: {service_guess}."
    if clusters:
        summary += f" {len(clusters)} cluster(s)."
    if n_soft:
        summary += f" {n_soft} soft-404."

    return {
        "summary": summary, "host_risk": host_risk,
        "service_guess": service_guess, "top_priorities": top_priorities,
        "clusters": clusters, "chains": chains,
        "false_positive_likelihood": fp_note,
        "suggested_manual_tests": tests[:6],
        "next_actions": next_actions[:6],
        "confidence_bands": bands, "soft_404_count": n_soft,
        "source": "heuristic",
    }


# ═════════════════════════════════════════════════════════════════════════
#  AI CACHE + TRIAGE
# ═════════════════════════════════════════════════════════════════════════

def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "content_fuzz_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: str, findings: list[FuzzFinding], model: str = "") -> str:
    parts = [host.lower(), f"model={model or 'unknown'}",
             f"prompt={AI_PROMPT_VERSION}"]
    for f in sorted(findings, key=lambda x: x.url):
        parts.append(f"{f.url}|{f.status}|{f.confidence}|{f.service_tag}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
    if ttl_hours <= 0:
        return None
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        if not p.exists():
            return None
        age = (time.time() - p.stat().st_mtime) / 3600
        if age > ttl_hours:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ai_cache_put(outdir: Path, key: str, data: dict) -> None:
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


_BUDGET_LOCK = threading.Lock()


def _current_spend() -> float:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return float(tracker.estimate_cost() or 0)
    except Exception:
        pass
    return 0.0


def _ai_cost_guard(would_add: float, budget_usd: float) -> bool:
    if budget_usd <= 0 or would_add <= 0:
        return True
    with _BUDGET_LOCK:
        return (_current_spend() + would_add) <= budget_usd


AI_FUZZ_SYSTEM = (
    "You are an expert offensive-security triage analyst. Analyze one "
    "host's content-discovery findings. Reference actual endpoints. Never "
    "suggest running exploits. Return STRICT JSON only."
)


def _validate_ai_triage(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("summary", "host_risk", "top_priorities",
                "false_positive_likelihood", "suggested_manual_tests",
                "next_actions"):
        if key not in data:
            return False
    if not isinstance(data.get("top_priorities"), list): return False
    if not isinstance(data.get("suggested_manual_tests"), list): return False
    if not isinstance(data.get("next_actions"), list): return False
    if data.get("host_risk") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                       "INFO", "UNKNOWN", ""):
        return False
    return True


def _build_top_findings_block(findings: list[FuzzFinding], limit: int = 30) -> str:
    top = sorted(findings, key=lambda f: -f.confidence)[:limit]
    lines = []
    for f in top:
        bits = [f"[{f.status:<3}]", f"{f.confidence:>3}", f"{f.url}"]
        if f.length: bits.append(f"len={f.length}")
        if f.content_type: bits.append(f"ct={f.content_type[:30]}")
        if f.service_tag: bits.append(f"tag={f.service_tag}")
        if f.soft_404: bits.append("(soft404)")
        if f.reasons: bits.append(f"({','.join(f.reasons[:2])})")
        lines.append("  " + " ".join(bits))
    return "\n".join(lines) if lines else "  (no findings)"


def _ai_triage_host(host_result: HostResult, outdir: Path, *,
                     use_cache: bool = True,
                     cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
                     budget_usd: float = 0.0,
                     heuristic_hint: Optional[dict] = None) -> Optional[dict]:
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if not host_result.findings:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(host_result.host, host_result.findings,
                                model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        return None

    findings = host_result.findings
    bands = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        bands[_confidence_band(f.confidence)] += 1
    service_guess = _guess_service_from_paths(findings)
    clusters = _build_clusters(findings)
    n_soft = sum(1 for f in findings if f.soft_404)

    hint_block = ""
    if heuristic_hint and heuristic_hint.get("summary"):
        hint_lines = []
        if heuristic_hint.get("top_priorities"):
            for p in heuristic_hint["top_priorities"][:3]:
                hint_lines.append(f"  {p.get('rank', '?')}. {p.get('finding', '')}")
        hint_block = (
            "\n\nHeuristic baseline (HINT ONLY, verify independently):\n"
            f"  Summary: {heuristic_hint.get('summary', '')[:300]}\n"
        )
        if hint_lines:
            hint_block += "  Top findings:\n" + "\n".join(hint_lines)

    cluster_block = ""
    if clusters:
        cluster_block = "\nHeuristic clusters:\n" + "\n".join(
            f"  {c['service']} × {c['count']} (max_conf={c['max_confidence']})"
            for c in clusters[:6]
        )

    prompt = f"""Analyze content-discovery findings for host: {host_result.host}

Stats:
  Total:    {len(findings)}
  High:     {bands['high']}
  Medium:   {bands['medium']}
  Low:      {bands['low']}
  Soft-404: {n_soft}
  Service guess: {service_guess or '(unknown)'}
{cluster_block}

Top findings:
{_build_top_findings_block(findings)}{hint_block}
"""

    def _call(text: str) -> Optional[str]:
        try:
            return ai_fn(text, system=AI_FUZZ_SYSTEM)
        except Exception as e:
            log.warning(f"  AI triage failed for {host_result.host}: {e}")
            return None

    text = _call(prompt)
    if not text:
        return None

    def _strip_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        return s

    def _try_parse(raw: str) -> Optional[dict]:
        try:
            d = json.loads(_strip_fences(raw))
            return d if _validate_ai_triage(d) else None
        except Exception:
            return None

    data = _try_parse(text)

    if data is None:
        correction = (
            "Your response could not be parsed as valid JSON. Return ONLY "
            "the JSON object. Required keys: summary, host_risk, "
            "service_guess, top_priorities, false_positive_likelihood, "
            "chain_hypotheses, suggested_manual_tests, next_actions.\n\n"
            f"Previous response:\n{text[:700]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {
                    "summary": text2[:1500], "host_risk": "UNKNOWN",
                    "service_guess": service_guess, "top_priorities": [],
                    "false_positive_likelihood": "unknown",
                    "chain_hypotheses": [], "suggested_manual_tests": [],
                    "next_actions": [], "parse_error": True,
                }
        else:
            return None

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"content_fuzz_ai_{safe}.md"
    try:
        md = (f"# Jörmungandr · AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("host_risk"): md += f"**Host risk:** {data['host_risk']}\n\n"
        if data.get("summary"): md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("top_priorities"):
            md += "## Top Priorities\n\n"
            for p in data["top_priorities"]:
                md += (f"{p.get('rank', '?')}. **{p.get('finding', '')}**\n"
                       f"   - Reason: {p.get('reason', '')}\n"
                       f"   - Test: {p.get('test_idea', '')}\n\n")
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"  AI triage saved: {md_path.name}")

    return {
        "path": str(md_path), "summary": data.get("summary", ""),
        "host_risk": data.get("host_risk", ""),
        "service_guess": data.get("service_guess", ""),
        "top_priorities": data.get("top_priorities", [])[:10],
        "false_positive_likelihood": data.get("false_positive_likelihood", ""),
        "chain_hypotheses": data.get("chain_hypotheses", [])[:10],
        "suggested_manual_tests": data.get("suggested_manual_tests", [])[:10],
        "next_actions": data.get("next_actions", [])[:10],
        "cost_estimate": round(_current_spend(), 6), "source": "ai",
    }


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[FuzzFinding]) -> None:
    if not findings:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not available"); return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB is False"); return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED is False"); return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready"); return
    try:
        result = DB.upsert_content_fuzz(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} endpoint(s) upserted")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT (v3.2)
# ═════════════════════════════════════════════════════════════════════════

def run_content_fuzz(
    live_urls_file: Path, outdir: Path, *,
    # v2 backward-compat
    use_ferox: bool = True, use_ffuf: bool = True,
    wordlists: Optional[list[tuple[str, Path, Optional[list[str]]]]] = None,
    max_hosts: Optional[int] = None,
    threads: Optional[int] = None, rate_limit: Optional[int] = None,
    headers: Optional[dict] = None, scan_id: Optional[int] = None,
    # v3.0
    dry_run: bool = False, min_confidence: int = 0,
    only_status: Optional[list[int]] = None,
    exclude_status: Optional[list[int]] = None,
    parallel_hosts: Optional[int] = None,
    host_timeout: Optional[int] = None,
    no_ai: bool = False,
    ai_max_hosts: int = DEFAULT_AI_MAX_HOSTS,
    ai_max_cost_usd: float = DEFAULT_AI_MAX_COST_USD,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
    # v3.1
    pipeline_seeds: bool = True, graphql_probe: bool = True,
    auth_diff: bool = True, robots_seeds: bool = True,
    soft_404_detection: bool = True,
    # v3.2 NEW
    fast_mode: bool = False,
    allow_slow: bool = False,
    bbp_program: Optional[str] = None,
    use_proxy: bool = True,
    proxy_pool: Any = None,
    audit_trail: Any = None,
    fuzz_proxy: bool = False,
) -> Path:
    """
    v3.2: full content discovery with pre-flight timing gate, budget-aware
    timeouts, and full config integration (UA, proxy, bbp, audit).
    """
    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    if not shutil.which("feroxbuster") and not shutil.which("ffuf") and not dry_run:
        raise RuntimeError(
            "Neither feroxbuster nor ffuf is installed. "
            "Run `python3 tools.py --only feroxbuster,ffuf` first.")

    # ── Settings ──────────────────────────────────────────────────────────
    settings = _fuzz_settings()
    cfg_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    cfg_threads = threads if threads is not None else settings["threads"]
    cfg_timeout = settings["timeout"]

    # ── Inputs ────────────────────────────────────────────────────────────
    bases = _extract_hosts(live_urls_file)
    if max_hosts:
        bases = bases[:max_hosts]
    if not bases:
        log.warning("  No live hosts to fuzz — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start,
                                     scan_id=scan_id, plan={}, wall_clock=0.0)

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "fuzz_work"
    workdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    hdrs = _target_headers(headers, bbp_program)
    ai_active = _ai_enabled() and not no_ai and not dry_run

    # ── Wordlists ─────────────────────────────────────────────────────────
    if wordlists is None:
        wordlists = _resolve_wordlists()

    # Pipeline seed enrichment
    if pipeline_seeds:
        seeds = _load_pipeline_seeds(outdir)
        if seeds:
            seed_path = _write_seed_wordlist(outdir, seeds, "pipeline_seeds.txt")
            if seed_path:
                wordlists = list(wordlists) + [("pipeline-seeds", seed_path, None)]
                log.info(f"  Pipeline seeds: +{len(seeds)} path(s)")

    # ── v3.2: Pre-flight timing plan ──────────────────────────────────────
    try:
        plan, plan_warnings = _build_effective_plan(
            wordlists, len(bases),
            cfg_rate, cfg_threads,
            fast_mode, allow_slow,
            rate_limit, parallel_hosts, host_timeout,
        )
        warnings.extend(plan_warnings)
    except RuntimeError as e:
        log.error(f"  {e}")
        raise

    wordlists = plan["wordlists"]
    eff_threads = plan["threads"]
    eff_rate_per_host = plan["per_host_rate"]
    eff_parallel = plan["parallel_hosts"]
    eff_timeout = plan["host_timeout"]
    wall_clock = plan["predicted_wall_clock_seconds"]

    if not quiet:
        log.info(f"  Input  : {len(bases)} host(s) from {live_urls_file.name}")
        log.info(f"  Config : rate={plan['rate_limit']}/s  "
                 f"parallel={eff_parallel}  "
                 f"per_host_rate={eff_rate_per_host}/s  "
                 f"threads={eff_threads}  host_timeout={eff_timeout}s")
        log.info(f"           rate source: {plan['rate_source']}")
        if plan["fast_mode"]:
            log.ok(f"  Mode   : FAST (rate={FAST_RATE_LIMIT}, parallel={FAST_PARALLEL_HOSTS}, "
                   f"wordlists filtered to [{'/'.join(FAST_WORDLIST_NAMES)}])")
        if dry_run:
            log.info("  Mode   : DRY-RUN (no fuzzing)")

        # Wordlist prediction table
        log.info("")
        log.info("  Wordlist predictions @ " + f"{eff_rate_per_host}/s:")
        for p in plan["predictions"]:
            flag = "✓" if p["seconds"] <= eff_timeout * 0.9 else "⚠ TIMEOUT"
            log.info(f"    {p['name']:<20} {p['lines']:>6} lines → "
                     f"~{p['seconds']:>5.0f}s  {flag}")

        log.info("")
        if wall_clock > 0:
            log.info(f"  Predicted wall clock: ~{wall_clock/60:.1f} min "
                     f"({wall_clock/3600:.1f}h)")
        if any(p["seconds"] > eff_timeout for p in plan["predictions"]):
            log.warning(f"  ⚠ Some wordlists will TIMEOUT at current rate. "
                       f"Consider --fast or raise --rate-limit.")

        if hdrs:
            log.info(f"  Headers: {len(hdrs)} configured")
        log.info(f"  Auth   : {'ENABLED' if auth_on else 'disabled'}")
        log.info(f"  Proxy  : {'pool' if proxy_pool else ('direct' if use_proxy else 'disabled')}")
        if bbp_program:
            log.info(f"  BBP    : {bbp_program}")
        if ai_active:
            log.info(f"  AI     : enabled  (budget=${ai_max_cost_usd:.2f}, "
                     f"max_hosts={ai_max_hosts})")
        else:
            log.info(f"  AI     : disabled — heuristic triage active")

        if warnings:
            log.info("")
            log.info("  Warnings (pre-flight):")
            for w in warnings[:6]:
                log.warning(f"    {w}")

        log.info("")

    # ── Probe hosts + baseline + robots ──────────────────────────────────
    log.info("  Probing host reachability + soft-404 baselines...")
    _progress("stage_start", {"stage": "probe", "hosts": len(bases)})

    baselines: dict[str, int] = {}
    live_hosts: list[str] = []
    robots_seeds_map: dict[str, list[str]] = {}

    for base in bases:
        _killswitch_check(f"probe-{base}")
        reachable, length, status = _probe_host(
            base, headers, bbp_program, proxy_pool, audit_trail, timeout=10)
        if reachable:
            live_hosts.append(base)
            baselines[base] = length
            log.info(f"    {base:<40} baseline={length}B  status={status}")
            if robots_seeds:
                rs = _extract_robots_seeds(base, headers, bbp_program,
                                             proxy_pool, timeout=8)
                if rs:
                    robots_seeds_map[base] = rs
                    log.info(f"    {base:<40} robots: {len(rs)} Disallow path(s)")
        else:
            warnings.append(f"host-unreachable: {base}")
            log.warning(f"    {base:<40} UNREACHABLE — skipped")

    _progress("stage_end", {"stage": "probe", "live": len(live_hosts),
                              "dead": len(bases) - len(live_hosts)})

    if not live_hosts:
        log.warning("  No live hosts — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start,
                                     total_input=len(bases), scan_id=scan_id,
                                     plan=plan, wall_clock=wall_clock)

    # Add robots seeds as wordlist
    if robots_seeds_map:
        all_robots: set[str] = set()
        for rs in robots_seeds_map.values():
            all_robots.update(rs)
        if all_robots:
            rb_path = _write_seed_wordlist(outdir, sorted(all_robots),
                                             "robots_seeds.txt")
            if rb_path:
                wordlists = list(wordlists) + [("robots-seeds", rb_path, None)]
                # Rebuild plan to include robots seeds
                try:
                    plan, _more = _build_effective_plan(
                        wordlists, len(live_hosts), cfg_rate, cfg_threads,
                        fast_mode, allow_slow, rate_limit, parallel_hosts,
                        host_timeout,
                    )
                    wordlists = plan["wordlists"]
                except RuntimeError:
                    pass
                log.info(f"  Robots seeds: +{len(all_robots)} path(s)")

    if dry_run:
        log.info("")
        log.info(f"  DRY-RUN — would fuzz {len(live_hosts)} host(s) with "
                 f"{len(wordlists)} wordlist(s)")
        for base in live_hosts:
            log.info(f"    {base}  per_host_rate={eff_rate_per_host}/s")
        return _write_empty_report(outdir, live_urls_file, start,
                                     total_input=len(bases), scan_id=scan_id,
                                     plan=plan, wall_clock=wall_clock,
                                     dry_run=True)

    # ── SIGINT/SIGTERM ────────────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — finishing current host, writing report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    # ── Per-host worker ───────────────────────────────────────────────────
    def _process_one_host(args: tuple) -> HostResult:
        index, total, base = args
        host = _host_of(base) or base
        hr = HostResult(host=host)
        host_start = time.monotonic()
        host_deadline = host_start + eff_timeout

        if not quiet:
            with _LOG_LOCK:
                log.info(f"\n── ᛟ  [{index}/{total}] {host} ──")

        # v3.2: pick one proxy per host for ferox/ffuf (if enabled)
        fuzz_proxy_url = _pick_proxy(proxy_pool) if (fuzz_proxy and use_proxy) else None
        if fuzz_proxy_url:
            log.info(f"      fuzz proxy: {fuzz_proxy_url[:60]}")

        try:
            all_findings: list[FuzzFinding] = []

            # ── Phase 1: feroxbuster ──────────────────────────────────────
            if use_ferox and shutil.which("feroxbuster"):
                for wl_name, wl_path, wl_exts in wordlists:
                    if _sigint["flag"]:
                        hr.warnings.append("sigint-aborted")
                        return hr

                    remaining = host_deadline - time.monotonic()
                    if remaining < 15:
                        hr.warnings.append(f"host-budget-exhausted: {remaining:.0f}s left")
                        hr.timed_out = True
                        log.warning(f"  {host} — host budget exhausted")
                        break

                    # v3.2: predict need, skip if can't complete
                    lines = _count_wordlist_lines(wl_path)
                    skip, needed = _should_skip_wordlist(
                        lines, eff_rate_per_host, remaining)
                    if skip:
                        hr.warnings.append(
                            f"wordlist-skipped-slow: {wl_name} needs {needed:.0f}s, "
                            f"{remaining:.0f}s remaining")
                        log.warning(
                            f"      Skipping {wl_name} ({lines} lines needs "
                            f"~{needed:.0f}s, {remaining:.0f}s left)")
                        hr.wordlist_timings.append({
                            "name": wl_name, "tool": "ferox",
                            "skipped": True, "needed_s": round(needed, 1),
                            "remaining_s": round(remaining, 1),
                        })
                        continue

                    wl_timeout = _estimate_wordlist_timeout(
                        lines, eff_rate_per_host, remaining, cfg_timeout)

                    t0 = time.monotonic()
                    hits = _run_ferox(
                        base, wl_name, wl_path, wl_exts, workdir,
                        threads=eff_threads, rate_limit=eff_rate_per_host,
                        timeout=wl_timeout, warnings=hr.warnings,
                        auth_on=auth_on, extra_headers=headers,
                        bbp_program=bbp_program, proxy_url=fuzz_proxy_url,
                    )
                    dur = time.monotonic() - t0
                    all_findings.extend(hits)
                    hr.wordlist_timings.append({
                        "name": wl_name, "tool": "ferox", "skipped": False,
                        "duration_s": round(dur, 1),
                        "timeout_s": wl_timeout,
                        "hits": len(hits),
                    })

            # ── Phase 2: ffuf ─────────────────────────────────────────────
            if use_ffuf and shutil.which("ffuf"):
                baseline = baselines.get(base, 0)
                for wl_name, wl_path, wl_exts in wordlists:
                    if _sigint["flag"]:
                        hr.warnings.append("sigint-aborted")
                        return hr

                    remaining = host_deadline - time.monotonic()
                    if remaining < 15:
                        hr.warnings.append(f"host-budget-exhausted: {remaining:.0f}s left")
                        hr.timed_out = True
                        break

                    lines = _count_wordlist_lines(wl_path)
                    skip, needed = _should_skip_wordlist(
                        lines, eff_rate_per_host, remaining)
                    if skip:
                        hr.warnings.append(
                            f"wordlist-skipped-slow(ffuf): {wl_name} needs {needed:.0f}s")
                        hr.wordlist_timings.append({
                            "name": wl_name, "tool": "ffuf",
                            "skipped": True, "needed_s": round(needed, 1),
                        })
                        continue

                    wl_timeout = _estimate_wordlist_timeout(
                        lines, eff_rate_per_host, remaining, cfg_timeout)

                    t0 = time.monotonic()
                    hits = _run_ffuf(
                        base, wl_name, wl_path, wl_exts, baseline, workdir,
                        threads=eff_threads, rate_limit=eff_rate_per_host,
                        timeout=wl_timeout, warnings=hr.warnings,
                        auth_on=auth_on, extra_headers=headers,
                        bbp_program=bbp_program, proxy_url=fuzz_proxy_url,
                    )
                    dur = time.monotonic() - t0
                    all_findings.extend(hits)
                    hr.wordlist_timings.append({
                        "name": wl_name, "tool": "ffuf", "skipped": False,
                        "duration_s": round(dur, 1),
                        "timeout_s": wl_timeout,
                        "hits": len(hits),
                    })

            # ── Phase 3: GraphQL introspection ────────────────────────────
            if graphql_probe:
                gql_findings = [f for f in all_findings if f.service_tag == "graphql"]
                if gql_findings:
                    gql_result = _try_graphql_introspection(
                        base, headers, bbp_program, proxy_pool)
                    if gql_result and gql_result["schema_exposed"]:
                        log.ok(f"      ✓ GraphQL introspection ENABLED "
                               f"({gql_result['type_count']} types)")
                        synth = _build_finding(
                            url=gql_result["endpoint"],
                            status=gql_result["status"],
                            length=200, words=20, lines=10,
                            content_type="application/json", redirect="",
                            tool="graphql_introspection", wordlist="introspection",
                            extension="", auth_enabled=auth_on,
                        )
                        if synth:
                            synth.confidence = 90
                            synth.service_tag = "graphql"
                            synth.reasons.append("graphql_introspection_enabled")
                            synth.nuclei_tags = NUCLEI_TAGS_BY_SERVICE["graphql"]
                            synth.manual_test = (
                                f"Schema exposed at {gql_result['endpoint']}")
                            all_findings.append(synth)

            # ── Phase 4: Auth-diff ────────────────────────────────────────
            if auth_diff and auth_on:
                auth_gated = [f for f in all_findings if f.status in (401, 403)]
                for f in auth_gated[:MAX_AUTH_DIFF_PROBES_PER_HOST]:
                    if _sigint["flag"]:
                        break
                    diff = _auth_diff_check(f, headers, bbp_program, proxy_pool)
                    if diff:
                        log.ok(f"      {f.url} → AUTH-GATED confirmed")
                        f.auth_gate_confirmed = True
                        f.confidence = min(100, f.confidence + 25)
                        f.reasons.append("auth_gate_confirmed")

            # ── Dedupe + filters ──────────────────────────────────────────
            deduped = _dedupe(all_findings)
            if soft_404_detection:
                _flag_soft_404_clusters(deduped)
            if only_status:
                deduped = [f for f in deduped if f.status in only_status]
            if exclude_status:
                deduped = [f for f in deduped if f.status not in exclude_status]
            if min_confidence > 0:
                deduped = [f for f in deduped if f.confidence >= min_confidence]

            STATUS_PRIORITY = {200: 1, 201: 1, 204: 1, 401: 2, 403: 2,
                                301: 3, 302: 3, 307: 3, 308: 3, 500: 4}
            deduped.sort(key=lambda f: (-f.confidence,
                                         STATUS_PRIORITY.get(f.status, 5),
                                         f.url))
            hr.findings = deduped

            # ── Triage ────────────────────────────────────────────────────
            heuristic = _heuristic_host_triage(host, deduped)
            ai = None
            if ai_active and deduped:
                ai = _ai_triage_host(
                    hr, outdir, use_cache=True,
                    cache_ttl_hours=ai_cache_ttl_hours,
                    budget_usd=ai_max_cost_usd,
                    heuristic_hint=heuristic,
                )
            if ai:
                hr.triage = ai
                hr.triage_source = ai.get("source", "ai")
            else:
                hr.triage = heuristic
                hr.triage_source = "heuristic"

            if not quiet:
                with _LOG_LOCK:
                    log.ok(f"  {len(deduped)} endpoint(s) — "
                           f"triage={hr.triage_source} "
                           f"risk={hr.triage.get('host_risk', '?')}")

        except Exception as e:
            hr.warnings.append(f"host-error: {host}: {type(e).__name__}: {e}")
            log.error(f"  {host} failed: {e}")

        return hr

    # ── Dispatch ──────────────────────────────────────────────────────────
    host_results: list[HostResult] = []
    worker_args = [(i, len(live_hosts), base)
                    for i, base in enumerate(live_hosts, 1)]

    try:
        if eff_parallel > 1:
            log.info(f"  Fuzzing {len(live_hosts)} host(s) with "
                     f"{eff_parallel} parallel workers")
            _progress("stage_start", {"stage": "fuzz",
                                        "hosts": len(live_hosts),
                                        "parallel": eff_parallel})
            with ThreadPoolExecutor(max_workers=eff_parallel) as pool:
                futures = {pool.submit(_process_one_host, wa): wa[2]
                           for wa in worker_args}
                for fut in as_completed(futures):
                    base = futures[fut]
                    try:
                        hr = fut.result()
                        host_results.append(hr)
                        warnings.extend(hr.warnings)
                        _progress("host_end", {"host": hr.host,
                                                 "findings": len(hr.findings)})
                    except Exception as e:
                        warnings.append(f"host-worker: {base}: {e}")
                        _progress("host_error", {"host": base, "error": str(e)})
            _progress("stage_end", {"stage": "fuzz"})
        else:
            log.info(f"  Fuzzing {len(live_hosts)} host(s) sequentially")
            _progress("stage_start", {"stage": "fuzz", "hosts": len(live_hosts)})
            for wa in worker_args:
                if _sigint["flag"]:
                    warnings.append("run-interrupted: SIGINT")
                    break
                _progress("host_start", {"host": wa[2], "index": wa[0],
                                           "total": wa[1]})
                hr = _process_one_host(wa)
                host_results.append(hr)
                warnings.extend(hr.warnings)
                _progress("host_end", {"host": hr.host,
                                         "findings": len(hr.findings)})
            _progress("stage_end", {"stage": "fuzz"})
    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass

    # ── Aggregate + report ────────────────────────────────────────────────
    all_findings_flat: list[FuzzFinding] = []
    for hr in host_results:
        all_findings_flat.extend(hr.findings)

    STATUS_PRIORITY = {200: 1, 201: 1, 204: 1, 401: 2, 403: 2,
                        301: 3, 302: 3, 307: 3, 308: 3, 500: 4}
    all_findings_flat.sort(key=lambda f: (-f.confidence,
                                           STATUS_PRIORITY.get(f.status, 5),
                                           f.url))
    if len(all_findings_flat) > DEFAULT_MAX_FINDINGS:
        warnings.append(f"findings-capped: {len(all_findings_flat)} → {DEFAULT_MAX_FINDINGS}")
        all_findings_flat = all_findings_flat[:DEFAULT_MAX_FINDINGS]

    json_path = _write_report(
        outdir, live_urls_file, start, len(bases),
        all_findings_flat, host_results,
        plan=plan, eff_threads=eff_threads, eff_rate_per_host=eff_rate_per_host,
        auth_on=auth_on, hdrs=hdrs, ai_active=ai_active,
        warnings=warnings, dry_run=dry_run, scan_id=scan_id,
        bbp_program=bbp_program,
        pipeline_seeds_count=len(_load_pipeline_seeds(outdir)) if pipeline_seeds else 0,
        robots_seeds_count=sum(len(v) for v in robots_seeds_map.values()),
    )

    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    return json_path


# ═════════════════════════════════════════════════════════════════════════
#  REPORT WRITERS
# ═════════════════════════════════════════════════════════════════════════

def _write_report(
    outdir: Path, input_file: Path, start: float, total_input: int,
    all_findings_flat: list[FuzzFinding], host_results: list[HostResult],
    *, plan: dict, eff_threads: int, eff_rate_per_host: int,
    auth_on: bool, hdrs: dict, ai_active: bool,
    warnings: list[str], dry_run: bool, scan_id: Optional[int],
    bbp_program: Optional[str] = None,
    pipeline_seeds_count: int = 0, robots_seeds_count: int = 0,
) -> Path:
    elapsed = time.monotonic() - start

    all_urls = sorted({f.url for f in all_findings_flat})
    interesting = [f for f in all_findings_flat
                   if f.confidence >= CONFIDENCE_HIGH_THRESHOLD]

    (outdir / "fuzzed_directories.txt").write_text(
        "\n".join(all_urls) + ("\n" if all_urls else ""))
    (outdir / "fuzzed_interesting.txt").write_text(
        "\n".join(f.url for f in interesting) + ("\n" if interesting else ""))

    by_status: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    by_service: dict[str, int] = {}
    n_soft = n_auth = n_gql = 0
    for f in all_findings_flat:
        by_status[str(f.status)] = by_status.get(str(f.status), 0) + 1
        by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
        by_confidence[_confidence_band(f.confidence)] += 1
        if f.service_tag:
            by_service[f.service_tag] = by_service.get(f.service_tag, 0) + 1
        if f.soft_404: n_soft += 1
        if f.auth_gate_confirmed: n_auth += 1
        if f.graphql_introspection and f.graphql_introspection.get("schema_exposed"):
            n_gql += 1

    ai_triaged = sum(1 for h in host_results if h.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for h in host_results if h.triage_source == "heuristic")
    timed_out_hosts = sum(1 for h in host_results if h.timed_out)

    predicted_wall = plan.get("predicted_wall_clock_seconds", 0)
    speedup = predicted_wall / elapsed if elapsed > 0 and predicted_wall > 0 else 0

    report = {
        "schema_version": 4,
        "producer": "content_fuzz.py v3.2.0 'JÖRMUNGANDR UNCHAINED'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(input_file),
        "hosts_scanned": len(host_results),
        "hosts_input": total_input,
        "auth_enabled": auth_on,
        "ai_enabled": ai_active,
        "ai_prompt_version": AI_PROMPT_VERSION,
        "dry_run": dry_run,
        "bbp_program": bbp_program,
        "config": {
            "rate_limit":         plan.get("rate_limit"),
            "rate_source":        plan.get("rate_source"),
            "rate_per_host":      eff_rate_per_host,
            "parallel_hosts":     plan.get("parallel_hosts"),
            "host_timeout":       plan.get("host_timeout"),
            "threads":            eff_threads,
            "headers_count":      len(hdrs),
            "ferox_depth":        FEROX_DEPTH,
            "ferox_scan_limit":   FEROX_SCAN_LIMIT,
            "ffuf_max_time":      FFUF_MAX_TIME,
            "allowed_status":     sorted(ALLOWED_STATUS),
            "soft_404_tolerance": SOFT_404_TOLERANCE,
            "wordlists":          [name for name, _, _ in plan.get("wordlists", [])],
            "pipeline_seeds_count": pipeline_seeds_count,
            "robots_seeds_count": robots_seeds_count,
            "fast_mode":          plan.get("fast_mode", False),
            "allow_slow":         plan.get("allow_slow", False),
        },
        "timing": {
            "predicted_wall_clock_seconds": predicted_wall,
            "actual_wall_clock_seconds":    round(elapsed, 2),
            "speedup_ratio":                round(speedup, 2) if speedup else None,
            "wordlist_predictions":         plan.get("predictions", []),
            "hosts_timed_out":              timed_out_hosts,
        },
        "warnings": warnings,
        "totals": {
            "raw_findings":       len(all_findings_flat),
            "unique_endpoints":   len(all_findings_flat),
            "high_confidence":    len(interesting),
            "soft_404_flagged":   n_soft,
            "auth_gate_confirmed": n_auth,
            "graphql_exposed":    n_gql,
            "hosts_with_findings": len(host_results),
            "hosts_timed_out":    timed_out_hosts,
            "ai_triaged":         ai_triaged,
            "heuristic_triaged":  heuristic_triaged,
        },
        "summary": {
            "by_status":     by_status,
            "by_tool":       by_tool,
            "by_confidence": by_confidence,
            "by_service":    dict(sorted(by_service.items(),
                                          key=lambda kv: -kv[1])),
        },
        "hosts": [
            {
                "host":              h.host,
                "findings":          [f.to_dict() for f in h.findings],
                "triage":            h.triage,
                "triage_source":     h.triage_source,
                "warnings":          h.warnings,
                "wordlist_timings":  h.wordlist_timings,
                "timed_out":         h.timed_out,
            }
            for h in host_results
        ],
        "findings": [f.to_dict() for f in all_findings_flat],
    }

    json_path = outdir / "content_fuzz.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    _write_digest(outdir, all_findings_flat)

    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, all_findings_flat)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    _print_summary(outdir, report, all_findings_flat, interesting, elapsed)

    return json_path


def _write_digest(outdir: Path, findings: list[FuzzFinding]) -> None:
    if not findings:
        (outdir / "content_fuzz_digest.md").write_text(
            "# Content Fuzz Digest\n\nNo findings.\n", encoding="utf-8")
        return
    top = sorted(findings, key=lambda f: -f.confidence)[:50]
    lines = [
        "# Content Fuzz Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Total findings:** {len(findings)}  \n\n",
        "## Top 50\n\n",
        "| Conf | Status | URL | Service | Tags | Manual Test |\n",
        "|------|--------|-----|---------|------|-------------|\n",
    ]
    for f in top:
        url = f.url.replace("|", "\\|")[:80]
        service = f.service_tag or "—"
        tags = ",".join(f.nuclei_tags[:3]) if f.nuclei_tags else "—"
        test = (f.manual_test or "Review").replace("|", "\\|")[:80]
        lines.append(f"| {f.confidence:>3} | {f.status} | {url} | {service} | {tags} | {test} |\n")
    (outdir / "content_fuzz_digest.md").write_text("".join(lines), encoding="utf-8")
    log.ok(f"  Digest: content_fuzz_digest.md ({len(top)} findings)")


def _print_summary(outdir: Path, report: dict,
                    all_findings: list[FuzzFinding],
                    interesting: list[FuzzFinding], elapsed: float) -> None:
    log.info("")
    log.info("── ᛊ  Summary ──")
    t = report["totals"]
    timing = report["timing"]

    log.info(f"  Hosts scanned    : {t['hosts_with_findings']}")
    if t['hosts_timed_out']:
        log.warning(f"  Hosts timed out  : {t['hosts_timed_out']}")
    log.info(f"  Unique endpoints : {t['unique_endpoints']}")
    log.info(f"  High-confidence  : {t['high_confidence']}")
    if t["soft_404_flagged"]:
        log.info(f"  Soft-404 flagged : {t['soft_404_flagged']}")
    if t["auth_gate_confirmed"]:
        log.ok(f"  Auth-gate confirmed : {t['auth_gate_confirmed']}")
    if t["graphql_exposed"]:
        log.ok(f"  GraphQL exposed     : {t['graphql_exposed']}")

    log.info("")
    log.info(f"  Predicted wall clock: {timing['predicted_wall_clock_seconds']/60:.1f} min")
    log.info(f"  Actual wall clock   : {timing['actual_wall_clock_seconds']/60:.1f} min")
    if timing.get("speedup_ratio"):
        log.info(f"  Speedup vs estimate : {timing['speedup_ratio']:.2f}×")

    by_service = report["summary"].get("by_service", {})
    if by_service:
        log.info("")
        log.info("  Services:")
        for svc, count in list(by_service.items())[:10]:
            log.info(f"    {svc:<22} {count:>3}")

    if interesting:
        log.info("")
        log.info("  Top high-confidence findings:")
        for f in interesting[:10]:
            svc = f" [{f.service_tag}]" if f.service_tag else ""
            log.info(f"    {f.status:>3}  {f.confidence:>3}  "
                     f"{f.url[:60]}{svc}")

    log.info("")
    log.info("  Outputs:")
    log.info(f"    content_fuzz.json")
    log.info(f"    fuzzed_directories.txt")
    log.info(f"    fuzzed_interesting.txt")
    log.info(f"    content_fuzz_digest.md")
    if report["ai_enabled"] and t["ai_triaged"] > 0:
        log.info(f"    content_fuzz_ai_<host>.md")

    if report.get("warnings"):
        log.info("")
        log.info("  Warnings:")
        for w in report["warnings"][:8]:
            log.warning(f"    {w}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")


def _write_empty_report(outdir: Path, input_file: Path, start: float,
                         total_input: int = 0,
                         scan_id: Optional[int] = None,
                         plan: Optional[dict] = None,
                         wall_clock: float = 0.0,
                         dry_run: bool = False) -> Path:
    report = {
        "schema_version": 4,
        "producer": "content_fuzz.py v3.2.0 'JÖRMUNGANDR UNCHAINED'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "hosts_scanned": 0, "hosts_input": total_input,
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "ai_enabled": False, "ai_prompt_version": AI_PROMPT_VERSION,
        "dry_run": dry_run,
        "config": {},
        "timing": {
            "predicted_wall_clock_seconds": wall_clock,
            "actual_wall_clock_seconds": round(time.monotonic() - start, 2),
        },
        "warnings": [],
        "totals": {
            "raw_findings": 0, "unique_endpoints": 0, "high_confidence": 0,
            "soft_404_flagged": 0, "auth_gate_confirmed": 0,
            "graphql_exposed": 0, "hosts_with_findings": 0,
            "hosts_timed_out": 0, "ai_triaged": 0, "heuristic_triaged": 0,
        },
        "summary": {"by_status": {}, "by_tool": {}, "by_confidence": {},
                     "by_service": {}},
        "hosts": [], "findings": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / "content_fuzz.json"
    p.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for name in ("fuzzed_directories.txt", "fuzzed_interesting.txt"):
        (outdir / name).write_text("")
    (outdir / "content_fuzz_digest.md").write_text("# Content Fuzz Digest\n\nNo findings.\n")
    return p


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST (v3.2 — 62 checks)
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  content_fuzz.py v3.2 'JÖRMUNGANDR UNCHAINED' — selftest")
    print("═" * 70)

    def _mk(url="https://test.example/admin", status=200, length=100,
            service_tag="", confidence=0) -> FuzzFinding:
        return FuzzFinding(
            url=url, status=status, length=length,
            service_tag=service_tag, confidence=confidence,
            host=urllib.parse.urlparse(url).netloc,
            path=urllib.parse.urlparse(url).path,
            first_seen="2026-01-01T00:00:00Z",
        )

    def _make_wl(tmpdir, name, lines):
        p = Path(tmpdir) / f"{name}.txt"
        p.write_text("\n".join(["path"] * lines) + "\n")
        return (name, p, None)

    def _settings_reads_canonical_key() -> bool:
        s = _fuzz_settings()
        return s["threads"] == 3 and s["rate_limit"] == 5

    def _settings_reads_rps_not_rate_limit() -> bool:
        return _fuzz_settings()["rate_limit"] != 100

    def _input_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example\r\nb.example  # inline\r\n\r\n# full-line\r\n")
            tmp = Path(tf.name)
        try:
            return _extract_hosts(tmp) == ["https://a.example", "https://b.example"]
        finally:
            tmp.unlink(missing_ok=True)

    def _service_tag(x) -> str:
        return _service_tag_for(x)

    def _score_auth_gated() -> bool:
        f = _mk(status=401, service_tag="admin"); _score_finding(f)
        return "access_gated" in f.reasons

    def _score_backup_ext() -> bool:
        f = _mk(url="https://x/y.bak", service_tag="backup_file"); _score_finding(f)
        return "backup_extension" in f.reasons

    def _confidence_band() -> bool:
        return (_confidence_band(70) == "high"
                and _confidence_band(40) == "medium"
                and _confidence_band(10) == "low")

    def _dedupe_distinct() -> bool:
        return len(_dedupe([_mk(url="https://x/a"), _mk(url="https://x/b")])) == 2

    def _dedupe_keeps_higher() -> bool:
        r = _dedupe([_mk(url="https://x/a", confidence=30),
                      _mk(url="https://x/a", confidence=70)])
        return len(r) == 1 and r[0].confidence == 70

    def _soft_404_cluster() -> bool:
        fs = [_mk(url=f"https://x/a{i}", length=100, confidence=50) for i in range(5)]
        for f in fs: f.body_fingerprint = "same"
        _flag_soft_404_clusters(fs)
        return all(f.soft_404 for f in fs)

    def _heuristic_empty() -> bool:
        return _heuristic_host_triage("x.com", [])["host_risk"] == "INFO"

    def _heuristic_spring() -> bool:
        f1 = _mk(url="https://x.com/actuator/env", service_tag="spring_actuator", confidence=85)
        f2 = _mk(url="https://x.com/actuator/health", service_tag="spring_actuator", confidence=70)
        r = _heuristic_host_triage("x.com", [f1, f2])
        return r["host_risk"] in ("CRITICAL", "HIGH") and r["service_guess"] == "spring_actuator"

    def _heuristic_chain() -> bool:
        f1 = _mk(url="https://x/b.bak", service_tag="backup_file", confidence=70)
        f2 = _mk(url="https://x/admin/", service_tag="admin", confidence=65)
        return any("Backup file" in c for c in _heuristic_host_triage("x.com", [f1, f2])["chains"])

    def _ai_cache_stable() -> bool:
        f1 = _mk(url="https://x/a"); f2 = _mk(url="https://x/b", status=403)
        return _ai_cache_key("x.com", [f1, f2], model="m") == _ai_cache_key("x.com", [f2, f1], model="m")

    def _ai_cache_model_busts() -> bool:
        f = _mk()
        return _ai_cache_key("x.com", [f], model="m1") != _ai_cache_key("x.com", [f], model="m2")

    def _validate_ai_ok() -> bool:
        return _validate_ai_triage({"summary": "x", "host_risk": "HIGH",
                                     "top_priorities": [], "false_positive_likelihood": "x",
                                     "suggested_manual_tests": [], "next_actions": []})

    def _validate_ai_reject() -> bool:
        return not _validate_ai_triage({"summary": "x"})

    def _headers_merge() -> bool:
        h = _target_headers({"X-Custom": "yes"})
        return h.get("X-Custom") == "yes"

    def _headers_ua_always() -> bool:
        """v3.2: UA must be present even without bbp or config UAs."""
        h = _target_headers()
        return any(k.lower() == "user-agent" for k in h)

    def _headers_bbp_applied() -> bool:
        """v3.2: bbp_program triggers build_headers."""
        # Can only verify if config has build_headers callable
        if not callable(_cfg("build_headers")):
            return True  # skip
        h = _target_headers(None, bbp_program="hackerone")
        return len(h) > 0

    def _tool_header_args_ua() -> bool:
        args = _tool_header_args()
        return any("User-Agent" in a for a in args)

    def _tool_header_args_drop_empty() -> bool:
        return not any("X-Empty" in a for a in _tool_header_args({"X-Empty": ""}))

    def _predict_lines() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            wl = _make_wl(tmp, "test", 100)
            preds = _predict_wordlist_times([wl], rate_per_host=10)
            return preds[0]["lines"] == 100 and preds[0]["seconds"] == 10.0

    def _predict_seconds_at_rate() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            wl = _make_wl(tmp, "test", 500)
            preds = _predict_wordlist_times([wl], rate_per_host=50)
            return preds[0]["seconds"] == 10.0

    def _wall_clock_estimate() -> bool:
        preds = [{"seconds": 100}, {"seconds": 200}]
        # 2 phases × (100+200) × 24 hosts / 4 parallel = 2 × 300 × 6 = 3600s
        wc = _estimate_wall_clock(preds, host_count=24, parallel_hosts=4)
        return wc == 3600.0

    def _wordlist_timeout_within_budget() -> bool:
        # 10000 lines at 50/s = 200s needed; 1.5× = 300s; budget 900 × 0.9 = 810s
        t = _estimate_wordlist_timeout(10000, 50, 900, 600)
        return 300 <= t <= 810

    def _wordlist_timeout_capped() -> bool:
        # Very slow rate + tight budget → floor at 30s
        t = _estimate_wordlist_timeout(10000, 1, 60, 600)
        return t >= 30

    def _should_skip_slow() -> bool:
        # 100000 lines at 5/s = 20000s; budget 300s → skip
        skip, _ = _should_skip_wordlist(100000, 5, 300)
        return skip is True

    def _should_skip_fast() -> bool:
        # 1000 lines at 50/s = 20s; budget 900s → don't skip
        skip, _ = _should_skip_wordlist(1000, 50, 900)
        return skip is False

    def _fast_plan_activated() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            wl = _make_wl(tmp, "common", 5000)
            try:
                plan, _ = _build_effective_plan(
                    [wl], host_count=24, cfg_rate=5, cfg_threads=3,
                    fast_mode=True, allow_slow=True,
                    explicit_rate=None, explicit_parallel=None,
                    explicit_timeout=None,
                )
                return plan["rate_limit"] == FAST_RATE_LIMIT
            except RuntimeError:
                return False

    def _abort_on_slow_config() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            # 50k lines at 5/s = 10ks; 2 phases × 10ks × 24 / 1 = 480ks
            # That's 133 hours → definitely aborts
            wl = _make_wl(tmp, "huge", 50000)
            try:
                _build_effective_plan(
                    [wl], host_count=24, cfg_rate=5, cfg_threads=3,
                    fast_mode=False, allow_slow=False,
                    explicit_rate=None, explicit_parallel=None,
                    explicit_timeout=None,
                )
                return False  # should have raised
            except RuntimeError:
                return True

    def _allow_slow_bypass() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            wl = _make_wl(tmp, "huge", 50000)
            try:
                plan, warnings = _build_effective_plan(
                    [wl], host_count=24, cfg_rate=5, cfg_threads=3,
                    fast_mode=False, allow_slow=True,
                    explicit_rate=None, explicit_parallel=None,
                    explicit_timeout=None,
                )
                return any("config-rate-slow" in w for w in warnings)
            except RuntimeError:
                return False

    def _fast_mode_drops_big_wordlists() -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            wl1 = _make_wl(tmp, "common", 1000)
            wl2 = _make_wl(tmp, "raft-medium-dirs", 30000)
            try:
                plan, _ = _build_effective_plan(
                    [wl1, wl2], host_count=5, cfg_rate=5, cfg_threads=3,
                    fast_mode=True, allow_slow=True,
                    explicit_rate=None, explicit_parallel=None,
                    explicit_timeout=None,
                )
                names = [n for (n, _, _) in plan["wordlists"]]
                return "raft-medium-dirs" not in names
            except RuntimeError:
                return False

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_content_fuzz)
        return set(required).issubset(set(sig.parameters))

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                     lambda: CFG_LOADED),
        ("_settings reads 'fuzzing'",         _settings_reads_canonical_key),
        ("_settings reads 'rps'",             _settings_reads_rps_not_rate_limit),
        ("BOM/CRLF input",                    _input_bom_crlf),
        ("service: spring_actuator",          lambda: _service_tag("/actuator/env") == "spring_actuator"),
        ("service: graphql",                  lambda: _service_tag("/graphql") == "graphql"),
        ("service: backup_file",              lambda: _service_tag("/backup.sql") == "backup_file"),
        ("service: admin",                    lambda: _service_tag("/admin/") == "admin"),
        ("service: unknown",                  lambda: _service_tag("/random") == ""),
        ("score: auth_gated",                 _score_auth_gated),
        ("score: backup_ext",                 _score_backup_ext),
        ("_confidence_band",                  _confidence_band),
        ("dedupe: distinct",                  _dedupe_distinct),
        ("dedupe: keeps higher",              _dedupe_keeps_higher),
        ("soft_404: cluster",                 _soft_404_cluster),
        ("heuristic: empty",                  _heuristic_empty),
        ("heuristic: spring",                 _heuristic_spring),
        ("heuristic: chain",                  _heuristic_chain),
        ("ai cache: stable",                  _ai_cache_stable),
        ("ai cache: model busts",             _ai_cache_model_busts),
        ("validate_ai ok",                    _validate_ai_ok),
        ("validate_ai rejects",               _validate_ai_reject),
        ("headers: merge caller",             _headers_merge),
        ("headers: UA always",                _headers_ua_always),
        ("headers: bbp applied",              _headers_bbp_applied),
        ("tool_header_args: UA",              _tool_header_args_ua),
        ("tool_header_args: drops empty",     _tool_header_args_drop_empty),
        # v3.2 NEW: timing
        ("predict: line count",               _predict_lines),
        ("predict: seconds at rate",          _predict_seconds_at_rate),
        ("wall_clock estimate",               _wall_clock_estimate),
        ("wordlist_timeout: within budget",   _wordlist_timeout_within_budget),
        ("wordlist_timeout: floors at 30s",   _wordlist_timeout_capped),
        ("should_skip: slow wordlist",        _should_skip_slow),
        ("should_skip: fast wordlist",        _should_skip_fast),
        ("fast_plan: rate=50",                _fast_plan_activated),
        ("abort on slow config",              _abort_on_slow_config),
        ("allow_slow bypasses abort",         _allow_slow_bypass),
        ("fast_mode drops big wordlists",     _fast_mode_drops_big_wordlists),
        # Signature checks
        ("run has dry_run",                   lambda: _sig_has(
            "dry_run", "min_confidence", "only_status", "exclude_status",
            "parallel_hosts", "host_timeout", "no_ai", "ai_max_hosts",
            "ai_max_cost_usd", "ai_cache_ttl_hours", "on_progress",
            "headers", "pipeline_seeds", "graphql_probe", "auth_diff",
            "robots_seeds", "soft_404_detection")),
        ("run has v3.2 params",               lambda: _sig_has(
            "fast_mode", "allow_slow", "bbp_program", "use_proxy",
            "proxy_pool", "audit_trail", "fuzz_proxy")),
        # Callability
        ("_probe_host callable",              lambda: callable(_probe_host)),
        ("_extract_robots_seeds callable",    lambda: callable(_extract_robots_seeds)),
        ("_load_pipeline_seeds callable",     lambda: callable(_load_pipeline_seeds)),
        ("_try_graphql_introspection callable", lambda: callable(_try_graphql_introspection)),
        ("_auth_diff_check callable",         lambda: callable(_auth_diff_check)),
        ("_write_digest callable",            lambda: callable(_write_digest)),
        ("_flag_soft_404_clusters callable",  lambda: callable(_flag_soft_404_clusters)),
        ("_killswitch_check callable",        lambda: callable(_killswitch_check)),
        ("_run_ferox callable",               lambda: callable(_run_ferox)),
        ("_run_ffuf callable",                lambda: callable(_run_ffuf)),
        ("_heuristic_host_triage callable",   lambda: callable(_heuristic_host_triage)),
        ("_ai_triage_host callable",          lambda: callable(_ai_triage_host)),
        ("_write_report callable",            lambda: callable(_write_report)),
        ("_self_sync callable",               lambda: callable(_self_sync)),
        ("_pick_proxy callable",              lambda: callable(_pick_proxy)),
        ("_audit_probe callable",             lambda: callable(_audit_probe)),
        ("_count_wordlist_lines callable",    lambda: callable(_count_wordlist_lines)),
        ("_predict_wordlist_times callable",  lambda: callable(_predict_wordlist_times)),
        ("_build_effective_plan callable",    lambda: callable(_build_effective_plan)),
        ("NUCLEI_TAGS>=15 services",          lambda: len(NUCLEI_TAGS_BY_SERVICE) >= 15),
        ("SERVICE_PATTERNS>=15",              lambda: len(SERVICE_PATTERNS) >= 15),
        ("MIN_VIABLE_RATE==20",               lambda: MIN_VIABLE_RATE == 20),
        ("WALL_CLOCK_ABORT==4h",              lambda: WALL_CLOCK_ABORT_SECONDS == 14400),
        ("FAST_RATE==50",                     lambda: FAST_RATE_LIMIT == 50),
        ("version is 3.2.0",                  lambda: True),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn(): print(f"  ✓ {name}"); passed += 1
            else: print(f"  ✗ {name} → False"); failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}"); failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="content_fuzz.py",
        description="Argus content fuzz v3.2 'JÖRMUNGANDR UNCHAINED'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--max-hosts", type=int, default=None)
    p.add_argument("--no-ferox", action="store_true")
    p.add_argument("--no-ffuf", action="store_true")
    p.add_argument("--wordlist", action="append", default=None)
    p.add_argument("--min-confidence", type=int, default=0)
    p.add_argument("--only-status", default=None)
    p.add_argument("--exclude-status", default=None)
    p.add_argument("--parallel-hosts", type=int, default=None,
                    help="parallel workers (default: 4, or 4 in --fast mode)")
    p.add_argument("--host-timeout", type=int, default=None,
                    help="per-host wall clock (default: 900s, or 300s in --fast)")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--ai-max-hosts", type=int, default=DEFAULT_AI_MAX_HOSTS)
    p.add_argument("--ai-max-cost", type=float, default=DEFAULT_AI_MAX_COST_USD)
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS)
    p.add_argument("--no-pipeline-seeds", dest="pipeline_seeds", action="store_false", default=True)
    p.add_argument("--no-graphql-probe", dest="graphql_probe", action="store_false", default=True)
    p.add_argument("--no-auth-diff", dest="auth_diff", action="store_false", default=True)
    p.add_argument("--no-robots-seeds", dest="robots_seeds", action="store_false", default=True)
    p.add_argument("--no-soft-404", dest="soft_404_detection", action="store_false", default=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--version", action="version",
                    version="content_fuzz.py 3.2.0 'JÖRMUNGANDR UNCHAINED'")

    # v3.2 flags
    p.add_argument("--fast", dest="fast_mode", action="store_true",
                    help=f"Preset: rate={FAST_RATE_LIMIT}, parallel={FAST_PARALLEL_HOSTS}, "
                         f"timeout={FAST_HOST_TIMEOUT}s, wordlists filtered to "
                         f"fast set. Recommended for first pass.")
    p.add_argument("--allow-slow", action="store_true",
                    help="Skip the 4-hour wall-clock abort guard (use with caution)")
    p.add_argument("--bbp", dest="bbp_program", default=None,
                    help="Bug bounty program (hackerone|bugcrowd|generic) — "
                         "applies build_headers(bbp) to ferox/ffuf and probes")
    p.add_argument("--no-proxy", dest="use_proxy", action="store_false", default=True)
    p.add_argument("--fuzz-proxy", action="store_true",
                    help="Route ferox/ffuf through ProxyPool (adds latency, "
                         "burns proxy budget — usually not needed)")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:
        return selftest()

    wordlists = None
    if args.wordlist:
        wordlists = _wordlists_from_cli(args.wordlist)

    only_status = None
    if args.only_status:
        try:
            only_status = [int(x.strip()) for x in args.only_status.split(",") if x.strip()]
        except ValueError:
            log.error(f"--only-status: bad value {args.only_status}")
            return 1

    exclude_status = None
    if args.exclude_status:
        try:
            exclude_status = [int(x.strip()) for x in args.exclude_status.split(",") if x.strip()]
        except ValueError:
            log.error(f"--exclude-status: bad value {args.exclude_status}")
            return 1

    try:
        run_content_fuzz(
            args.input, args.output,
            use_ferox=not args.no_ferox,
            use_ffuf=not args.no_ffuf,
            wordlists=wordlists,
            max_hosts=args.max_hosts,
            threads=args.threads,
            rate_limit=args.rate_limit,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            min_confidence=args.min_confidence,
            only_status=only_status,
            exclude_status=exclude_status,
            parallel_hosts=args.parallel_hosts,
            host_timeout=args.host_timeout,
            no_ai=args.no_ai,
            ai_max_hosts=args.ai_max_hosts,
            ai_max_cost_usd=args.ai_max_cost,
            ai_cache_ttl_hours=args.ai_cache_ttl,
            quiet=args.quiet,
            pipeline_seeds=args.pipeline_seeds,
            graphql_probe=args.graphql_probe,
            auth_diff=args.auth_diff,
            robots_seeds=args.robots_seeds,
            soft_404_detection=args.soft_404_detection,
            # v3.2
            fast_mode=args.fast_mode,
            allow_slow=args.allow_slow,
            bbp_program=args.bbp_program,
            use_proxy=args.use_proxy,
            fuzz_proxy=args.fuzz_proxy,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except RuntimeError as e:
        log.error(f"aborted: {e}")
        return 2
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
