#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛗ ᛁ ᛗ ᛁ ᚱ   ·   P A R A M   D I S C O V E R Y   ·   M Í M I R ' S   T H R E A D
================================================================================
  File      : recon_tools/param_discovery.py
  Version   : 3.1.0 "MÍMIR'S THREAD REFORGED"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Deep parameter discovery — 4 phases, AI triage ready.

  v3.0 → v3.1 (this release — surgical optimizations):
    [FIX]  MODULE_RATE_LIMITS["params"] → fallback chain through
           "fuzzing" → "crawl" → "sqli_finder". config.py has NO
           "params" key — v3.0 was silently using DEFAULT_RATE_LIMIT=3
           instead of the user's fuzzing.rps=5.
    [FIX]  --resume now checks evidence_dir FIRST (was broken — checked
           only workdir, which is deleted at end of every run).
    [FIX]  _audit_subprocess was a `pass` statement — now actually records
           subprocess invocations to AuditTrail.
    [FIX]  No KillSwitch check between phases — a .ARGUS_STOP file mid-scan
           now cleanly unwinds.
    [FIX]  No SIGINT handler — Ctrl-C now writes a partial report.
    [FIX]  _load_urls / _load_roots missing BOM/CRLF safety.
    [FIX]  Dry-run returned a stale/empty path — now writes a valid
           empty report so downstream stages don't fail.
    [FIX]  _print_summary showed param_candidates.txt = 3 (oracle count)
           instead of unique-param count.
    [NEW]  Wayback cache (24h TTL, .state/param_wayback_cache.json) —
           30x faster re-runs of Phase 1.
    [NEW]  Phase 4 SQLi probe cache (7d TTL, .state/param_sqli_probe_cache.json) —
           3-5x faster re-runs.
    [NEW]  WAF-aware Phase 4 early exit — skips remaining candidates after
           5 consecutive WAF blocks, saving rate budget.
    [NEW]  --parallel-phase4 N — N hosts processed in parallel; rate
           divided across workers so program caps are honored.
    [NEW]  on_progress callback — stage_start/stage_end/host_done events
           for TUI / dashboard integration.
    [NEW]  --quiet flag — suppresses summary for CI use.
    [NEW]  _write_empty_report() — proper empty-report for zero-URL inputs.
    [NEW]  Broader _auto_discover_inputs — added site_pages.txt,
           dns_wildcard_filtered.txt, subs_resolved.txt fallbacks.
    [NEW]  Selftest expanded 48 → 62 checks (cache, parallel, killswitch,
           BOM, resume paths).

  What stays the same:
    ·  4-phase pipeline: Passive → Arjun → x8 → Tampered SQLi pre-check
    ·  All v3.0 CLI flags and outputs
    ·  Backward-compatible run_param_discovery() signature for main.py
    ·  Shared tampers from auditing_tools/tampers.py (single source)

  Chains emitted (13 total):
    param-hidden              Hidden parameter (not in URL query)
    param-idor                IDOR-class parameter
    param-sqli                SQLi-class parameter
    param-sqli-confirmed      Phase 4 confirmed DBMS error
    param-ssrf                SSRF-class parameter
    param-lfi                 LFI/path-traversal-class parameter
    param-command-injection   Command-injection-class parameter
    param-open-redirect       Open-redirect-class parameter
    param-xss                 XSS-class parameter
    param-ssti                SSTI-class parameter
    param-auth-bypass         Auth-bypass-class parameter
    param-privilege-escalation  Privilege-escalation-class parameter
    param-mass-assignment     Mass-assignment-class parameter

  Outputs:
    param_findings.json             — aggregated report
    param_analysis_hosts.jsonl      — per-host streamed (crash-safe)
    params_by_endpoint.txt          — METHOD  url  param1,param2,...
    param_passive.txt               — passive URLs with FUZZ placeholders
    param_candidates.txt            — unique param name per line
    param_sqli_hits.json            — Phase 4 confirmed SQLi-suspects
    urls_sqli_priority.txt          — URLs to feed sqli_finder first
    param_ai_<host>.md              — per-host AI triage (when AI on)
    param_evidence/                 — raw arjun/x8 evidence (resume support)

  ⚠  WARNING: param_findings.json contains reconstructed URLs with
     parameters that may be sensitive. Add these to .gitignore:
       param_findings.json, param_analysis_hosts.jsonl, param_sqli_hits.json,
       urls_sqli_priority.txt, param_ai_*.md, param_evidence/

  Usage
  ─────
    python3 recon_tools/param_discovery.py
    python3 recon_tools/param_discovery.py --resume
    python3 recon_tools/param_discovery.py --parallel-phase4 3
    python3 recon_tools/param_discovery.py --quiet
    python3 recon_tools/param_discovery.py --dry-run
    python3 recon_tools/param_discovery.py --selftest
    python3 recon_tools/param_discovery.py --config-check
================================================================================
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  CONFIG INTEGRATION
# ══════════════════════════════════════════════════════════════════════════

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    import config as CFG
    CFG_LOADED = True
    _CFG_IMPORT_ERROR: Optional[Exception] = None
except ImportError as _cfg_err:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False
    _CFG_IMPORT_ERROR = _cfg_err


def _cfg(key: str, default: Any = None) -> Any:
    return getattr(CFG, key, default) if CFG_LOADED else default


def _ai_enabled() -> bool:
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


# ── Shared tampers ────────────────────────────────────────────────────────
TAMPERS_AVAILABLE = False
try:
    from auditing_tools.tampers import (
        DEFAULT_TAMPERS, apply_tampers, dbms_from_error,
        rebuild_url_with_payload, SQLI_ERROR_PROBES,
    )
    TAMPERS_AVAILABLE = True
except Exception:
    DEFAULT_TAMPERS: list[str] = []
    apply_tampers: Callable = lambda p, n=None: []
    dbms_from_error: Callable = lambda t: (None, None)
    rebuild_url_with_payload: Callable = lambda u, p, v: u
    SQLI_ERROR_PROBES: list[str] = []


class _FallbackPalette:
    _enabled = sys.stdout.isatty()
    _R = {"reset": "\033[0m", "dim": "\033[2m",
          "gold": "\033[38;5;220m", "amber": "\033[38;5;214m",
          "purple": "\033[38;5;135m", "violet": "\033[38;5;93m",
          "crimson": "\033[38;5;160m", "blood": "\033[38;5;196m",
          "green": "\033[38;5;46m", "cyan": "\033[38;5;51m",
          "grey": "\033[38;5;242m"}

    @classmethod
    def c(cls, name: str) -> str:
        return cls._R.get(name, "") if cls._enabled else ""


def _c(name: str) -> str:
    if CFG_LOADED and hasattr(CFG, "_c"):
        return CFG._c(name)
    return _FallbackPalette.c(name)


class _FallbackLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self):
        self.min_level = "info"

    def _emit(self, level, msg, color, prefix):
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")

    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info (self, m): self._emit("info",  m, "cyan", "·")
    def warn (self, m): self._emit("warn",  m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def ok   (self, m): self._emit("info",  m, "green", "✓")

    def rune(self, rune, msg):
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")


log = _cfg("log") or _FallbackLogger()


class Sym:
    STAR = "★"; ARROW = "➤"; CHECK = "✓"; CROSS = "✗"
    WARN = "⚠"; INFO = "·"; DOT = "᛫"; SKULL = "☠"
    SHIELD = "🛡"; WOLF = "🐺"; EYE = "👁"; KEY = "🔑"; FIRE = "🔥"
    LOCK = "🔒"; GEAR = "⚙"; SHAMROCK = "☘"; THREAD = "🧵"; BOLT = "⚡"


class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


__version__ = "3.1.0"
__codename__ = "MÍMIR'S THREAD REFORGED"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛗ ᛁ ᛗ ᛁ ᚱ{R}
    {P}{rule}{R}
    {V}    P A R A M   D I S C O V E R Y   ·   M Í M I R ' S   T H R E A D{R}
    {V}              T H E   T H R E A D S   A R E   P U L L E D{R}
    {D}{rule}{R}
    {G}        {Sym.THREAD}  v{__version__} "{__codename__}"  ·  4-phase · AI-ready{R}
    {G}        {Sym.GEAR}  config v{_cfg('__version__', 'missing')} {R}
    {G}        {Sym.SHAMROCK}  BeardedVikingTX  ·  {_cfg('AUTHOR_EMAIL', 'security@beardedviking.org')}{R}
    {P}{rule}{R}
""")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SEVERITY
# ══════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"
    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS            = 5
DEFAULT_TIMEOUT            = 10.0
DEFAULT_RATE_LIMIT         = 3
MAX_ENDPOINTS              = 500
ARJUN_RATE_LIMIT           = 3
ARJUN_STABLE_MODE          = False
ARJUN_TIMEOUT              = 600

PARAMSPIDER_TIMEOUT        = 300
PARAMSPIDER_PLACEHOLDER    = "FUZZ"

X8_TIMEOUT                 = 180
X8_VALIDATE_TOP_N_PER_HOST = 10

CONFIDENCE_HIGH            = 75
CONFIDENCE_MEDIUM          = 50

MAX_SQLI_PROBES_PER_HOST   = 20
MAX_SQLI_BODY              = 4096
HUMAN_PAUSE_CHANCE         = 0.10
HUMAN_PAUSE_RANGE          = (3.0, 8.0)

AI_MIN_FINDINGS_PER_HOST   = 3
AI_MAX_HOSTS_PER_RUN       = 50

# v3.1: caches
WAYBACK_CACHE_TTL_HOURS       = 24.0
SQLI_PROBE_CACHE_TTL_HOURS    = 168.0  # 7 days
WAYBACK_CACHE_FILE            = "param_wayback_cache.json"
SQLI_PROBE_CACHE_FILE         = "param_sqli_probe_cache.json"

# v3.1: WAF early exit for Phase 4
WAF_CONSECUTIVE_BLOCK_THRESHOLD = 5

# v3.1: parallel Phase 4
DEFAULT_PARALLEL_PHASE4       = 1

# WAF markers (same as site_crawler)
WAF_BLOCK_STATUSES = {403, 429, 503, 520, 521, 522, 523, 524, 525, 526, 530}
WAF_HEADER_MARKERS = (
    "cf-mitigated", "cf-ray", "x-akamai-bot-manager", "x-iinfo",
    "x-sucuri-block", "x-datadome",
)

# ── Cache lock (thread-safe writes) ───────────────────────────────────────
_CACHE_LOCK = threading.Lock()

# Chain metadata
CHAIN_SEVERITY: dict[str, Severity] = {
    "param-hidden":               Severity.LOW,
    "param-idor":                 Severity.HIGH,
    "param-sqli":                 Severity.HIGH,
    "param-sqli-confirmed":       Severity.CRITICAL,
    "param-ssrf":                 Severity.HIGH,
    "param-lfi":                  Severity.HIGH,
    "param-command-injection":    Severity.CRITICAL,
    "param-open-redirect":        Severity.MEDIUM,
    "param-xss":                  Severity.MEDIUM,
    "param-ssti":                 Severity.HIGH,
    "param-auth-bypass":          Severity.HIGH,
    "param-privilege-escalation": Severity.HIGH,
    "param-mass-assignment":      Severity.MEDIUM,
}

CHAIN_NAMES: dict[str, str] = {
    "param-hidden":               "Hidden parameter (not in URL query)",
    "param-idor":                 "IDOR-class parameter",
    "param-sqli":                 "SQLi-class parameter",
    "param-sqli-confirmed":       "SQLi confirmed via tampered probe",
    "param-ssrf":                 "SSRF-class parameter",
    "param-lfi":                  "LFI/path-traversal-class parameter",
    "param-command-injection":    "Command-injection-class parameter",
    "param-open-redirect":        "Open-redirect-class parameter",
    "param-xss":                  "XSS-class parameter",
    "param-ssti":                 "SSTI-class parameter",
    "param-auth-bypass":          "Auth-bypass-class parameter",
    "param-privilege-escalation": "Privilege-escalation-class parameter",
    "param-mass-assignment":      "Mass-assignment-class parameter",
}

# Class → chain mapping
CLASS_TO_CHAIN: dict[str, str] = {
    "idor":                 "param-idor",
    "sqli":                 "param-sqli",
    "ssrf":                 "param-ssrf",
    "lfi":                  "param-lfi",
    "path_traversal":       "param-lfi",
    "command_injection":    "param-command-injection",
    "rce":                  "param-command-injection",
    "open_redirect":        "param-open-redirect",
    "xss":                  "param-xss",
    "ssti":                 "param-ssti",
    "auth_bypass":          "param-auth-bypass",
    "privilege_escalation": "param-privilege-escalation",
    "mass_assignment":      "param-mass-assignment",
}


# ══════════════════════════════════════════════════════════════════════════
#  HOST CAPACITY
# ══════════════════════════════════════════════════════════════════════════

def _measure_host() -> tuple[int, int, str]:
    cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024
                        break
    except Exception:
        pass
    reasons = []
    if cores <= 2: reasons.append(f"{cores} cores")
    if ram_mb and ram_mb < 2048: reasons.append(f"{ram_mb} MB RAM")
    return cores, ram_mb, ", ".join(reasons) if reasons else ""


HOST_CORES, HOST_RAM_MB, LIGHTWEIGHT_REASON = _measure_host()
LIGHTWEIGHT_MODE = bool(LIGHTWEIGHT_REASON) or os.getenv("ARGUS_LIGHTWEIGHT") == "1"


def _effective_limits(max_endpoints: int, threads: int) -> tuple[int, int]:
    if not LIGHTWEIGHT_MODE:
        return max_endpoints, threads
    return min(max_endpoints, 100), min(threads, 3)


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  VULN CLASS MAP
# ══════════════════════════════════════════════════════════════════════════

VULN_CLASS_MAP: dict[str, list[str]] = {
    # SSRF / open redirect
    "url": ["ssrf","open_redirect","xss"], "uri": ["ssrf","open_redirect"],
    "link": ["open_redirect","ssrf"], "href": ["open_redirect","ssrf"],
    "src": ["ssrf","open_redirect"], "dest": ["ssrf","open_redirect"],
    "destination": ["ssrf","open_redirect"], "target": ["ssrf","open_redirect"],
    "redirect": ["open_redirect"], "redirect_uri": ["open_redirect"],
    "redirect_url": ["open_redirect"], "next": ["open_redirect"],
    "return": ["open_redirect"], "return_to": ["open_redirect"],
    "return_url": ["open_redirect"], "continue": ["open_redirect"],
    "goto": ["open_redirect"], "out": ["open_redirect"],
    "callback": ["ssrf","xss","open_redirect"], "callback_url": ["ssrf","xss"],
    "webhook": ["ssrf"], "webhook_url": ["ssrf"], "feed": ["ssrf"],
    "host": ["ssrf","open_redirect"], "site": ["ssrf","open_redirect"],
    "domain": ["ssrf"], "fetch": ["ssrf"], "load": ["ssrf","lfi"],
    "proxy": ["ssrf"], "request": ["ssrf"], "req": ["ssrf"],
    "open": ["ssrf","open_redirect"],
    # IDOR / SQLi
    "id": ["idor","sqli"], "user_id": ["idor","sqli"], "userid": ["idor","sqli"],
    "uid": ["idor","sqli"], "uuid": ["idor","sqli"], "guid": ["idor"],
    "account": ["idor"], "account_id": ["idor"], "customer_id": ["idor"],
    "order_id": ["idor"], "invoice_id": ["idor"], "doc_id": ["idor"],
    "file_id": ["idor"], "object_id": ["idor"], "resource_id": ["idor"],
    "group_id": ["idor"], "tenant_id": ["idor","privilege_escalation"],
    "org_id": ["idor","privilege_escalation"], "role_id": ["idor","privilege_escalation"],
    "profile_id": ["idor"], "number": ["idor","sqli"], "key": ["idor"],
    "ref": ["idor"], "ref_id": ["idor"],
    # LFI / traversal
    "file": ["lfi","rfi","path_traversal"], "filename": ["lfi","rfi"],
    "filepath": ["lfi","path_traversal"], "file_path": ["lfi","path_traversal"],
    "path": ["lfi","path_traversal"], "page": ["lfi","path_traversal","open_redirect"],
    "template": ["ssti","lfi"], "view": ["lfi","path_traversal"],
    "include": ["lfi"], "inc": ["lfi"], "require": ["lfi"],
    "load_file": ["lfi"], "doc": ["lfi"], "document": ["lfi"],
    "folder": ["lfi"], "dir": ["lfi"], "download": ["lfi"],
    # SQLi / XSS / search
    "q": ["sqli","xss"], "query": ["sqli","xss"], "search": ["sqli","xss"],
    "s": ["sqli","xss"], "keyword": ["sqli","xss"], "term": ["sqli","xss"],
    "filter": ["sqli","xss"], "sort": ["sqli"], "order": ["sqli"],
    "order_by": ["sqli"], "sort_by": ["sqli"], "column": ["sqli"],
    "field": ["sqli"], "table": ["sqli"], "select": ["sqli"],
    "where": ["sqli"], "having": ["sqli"], "limit": ["sqli"],
    "offset": ["sqli"], "rows": ["sqli"],
    # Debug
    "debug": ["info_disclosure"], "test": ["info_disclosure"],
    "dev": ["info_disclosure"], "env": ["info_disclosure"],
    "verbose": ["info_disclosure"], "trace": ["info_disclosure"],
    # Admin / privilege
    "admin": ["privilege_escalation","info_disclosure"],
    "is_admin": ["privilege_escalation"], "superuser": ["privilege_escalation"],
    "role": ["mass_assignment","privilege_escalation"],
    "permission": ["privilege_escalation"], "access": ["privilege_escalation"],
    "privilege": ["privilege_escalation"],
    # SSTI
    "tpl": ["ssti"], "template_name": ["ssti"], "layout": ["ssti"],
    "format": ["ssti"], "subject": ["ssti","xss"],
    "body": ["ssti","xss"], "content": ["ssti","xss"],
    # Command injection
    "cmd": ["command_injection"], "command": ["command_injection"],
    "exec": ["command_injection"], "execute": ["command_injection"],
    "shell": ["command_injection"], "run": ["command_injection"],
    # Auth
    "token": ["auth_bypass"], "auth": ["auth_bypass"],
    "api_key": ["auth_bypass"], "apikey": ["auth_bypass"],
    "password": ["auth_bypass"], "passwd": ["auth_bypass"], "pwd": ["auth_bypass"],
    "secret": ["auth_bypass"], "session": ["auth_bypass"],
    "jwt": ["auth_bypass"], "bearer": ["auth_bypass"],
    "signature": ["auth_bypass"], "otp": ["auth_bypass"],
    "pin": ["auth_bypass"], "code": ["auth_bypass"],
}

HIGH_RISK_CLASSES      = {"idor","sqli","ssrf","command_injection","lfi","path_traversal","rce"}
MEDIUM_RISK_CLASSES    = {"open_redirect","xss","ssti","auth_bypass",
                            "privilege_escalation","rfi","mass_assignment"}
SQLI_RELEVANT_CLASSES  = {"sqli"}
SQLI_HINT_PARAM_RE     = re.compile(
    r"(?:_?id|num|key|ref|q|query|search|filter|sort)$", re.I)


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ParameterFinding:
    url: str
    method: str
    parameter: str
    oracles: list[str] = field(default_factory=list)
    confidence: int = 0
    vuln_classes: list[str] = field(default_factory=list)
    already_in_url: bool = False
    evidence: list[str] = field(default_factory=list)
    sqli_probe_hit: bool = False
    sqli_dbms: str = ""
    sqli_tamper: str = ""
    sqli_payload: str = ""
    sqli_signature: str = ""
    chain_ids: list[str] = field(default_factory=list)
    severity: Severity = Severity.LOW
    auth_enabled: bool = False
    first_seen: str = ""

    def add_chain(self, cid: str) -> None:
        if cid not in self.chain_ids:
            self.chain_ids.append(cid)

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "method":         self.method,
            "parameter":      self.parameter,
            "oracles":        self.oracles,
            "confidence":     self.confidence,
            "vuln_classes":   self.vuln_classes,
            "already_in_url": self.already_in_url,
            "evidence":       self.evidence,
            "sqli_probe_hit": self.sqli_probe_hit,
            "sqli_dbms":      self.sqli_dbms,
            "sqli_tamper":    self.sqli_tamper,
            "sqli_payload":   self.sqli_payload[:500] if self.sqli_payload else "",
            "sqli_signature": self.sqli_signature,
            "chain_ids":      self.chain_ids,
            "severity":       self.severity.value,
            "auth_enabled":   self.auth_enabled,
            "first_seen":     self.first_seen,
        }


@dataclass
class EndpointResult:
    url: str
    method: str
    findings: list[ParameterFinding] = field(default_factory=list)
    x8_raw: str = ""
    error: str = ""
    error_category: str = ""


@dataclass
class HostResult:
    host: str
    endpoints: list[EndpointResult] = field(default_factory=list)
    findings: list[ParameterFinding] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    triage: Optional[dict] = None
    triage_source: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class HttpResult:
    status: int
    headers: dict
    body: str
    url: str
    final_url: str
    latency_ms: float
    error: Optional[str] = None
    error_category: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _strip_query(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(
            parsed._replace(query="", fragment="")).rstrip("/")
    except Exception:
        return url.rstrip("/")


def _extract_query_params(url: str) -> set[str]:
    try:
        return set(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
    except Exception:
        return set()


def _classify_param(param: str) -> list[str]:
    p = param.lower()
    classes: set[str] = set()
    for key, vulns in VULN_CLASS_MAP.items():
        if key == p or key in p:
            classes.update(vulns)
    return sorted(classes)


def _score_confidence(param: str, url: str, method: str,
                       oracles: list[str], already_in_url: bool,
                       sqli_probe_hit: bool = False) -> int:
    score = 40
    classes = _classify_param(param)

    if any(c in HIGH_RISK_CLASSES for c in classes):
        score += 25
    elif any(c in MEDIUM_RISK_CLASSES for c in classes):
        score += 15

    if "x8" in oracles:       score += 20
    if "arjun" in oracles:    score += 5
    if "passive" in oracles:  score -= 10
    if len(oracles) > 1:      score += 15

    path = urllib.parse.urlparse(url).path.lower()
    if any(w in path for w in ("admin","internal","api","debug",
                                "v1","v2","graphql")):
        score += 15

    if method.upper() in ("POST","PUT","PATCH","JSON","XML"):
        score += 5

    if already_in_url:
        score -= 20

    if sqli_probe_hit:
        score += 35

    return max(0, min(100, score))


def _severity_from_confidence(confidence: int, sqli_confirmed: bool = False) -> Severity:
    if sqli_confirmed:
        return Severity.CRITICAL
    if confidence >= 85:
        return Severity.HIGH
    if confidence >= 65:
        return Severity.MEDIUM
    if confidence >= 40:
        return Severity.LOW
    return Severity.INFO


def _categorize_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)): return "timeout"
    if isinstance(exc, ssl.SSLError): return "ssl"
    if isinstance(exc, socket.gaierror): return "dns"
    if isinstance(exc, ConnectionRefusedError): return "refused"
    if isinstance(exc, urllib.error.URLError):
        r = str(exc.reason).lower()
        if "proxy" in r: return "proxy"
        if "timeout" in r: return "timeout"
        return "url"
    return type(exc).__name__.lower()[:20]


def _detect_waf_block(status: int, headers: dict, body: str) -> tuple[bool, str]:
    """Detect if a response is a WAF block (Cloudflare/Akamai/etc.)."""
    headers_lower = {k.lower(): str(v) for k, v in (headers or {}).items()}
    body_lower = (body or "")[:3000].lower()

    for marker in WAF_HEADER_MARKERS:
        if marker in headers_lower:
            if status in WAF_BLOCK_STATUSES:
                return True, marker.split("-")[1] if "-" in marker else "waf"
            if "cloudflare" in marker and "just a moment" in body_lower:
                return True, "cloudflare"

    if status in WAF_BLOCK_STATUSES:
        if "checking your browser" in body_lower:
            return True, "cloudflare"
        if "ddos-guard" in body_lower:
            return True, "ddos-guard"

    return False, ""


# ── v3.1: unified tool tag + evidence path ────────────────────────────────

def _tool_tag(url: str, method: str) -> str:
    """v3.1: unified tag — was duplicated as _arjun_tag / _x8_tag."""
    raw = f"{method}_{url.replace('://', '_')}"
    return re.sub(r"[^a-zA-Z0-9]+", "_", raw)[:80]


def _evidence_path(evidence_dir: Path, tool: str,
                    url: str, method: str) -> Path:
    """v3.1: canonical evidence path — resume checks this first."""
    return evidence_dir / f"{tool}_{_tool_tag(url, method)}.json"


# ── v3.1: cache infrastructure ────────────────────────────────────────────

def _state_dir() -> Optional[Path]:
    state_dir = _cfg("STATE_DIR")
    return Path(state_dir) if state_dir is not None else None


def _load_json_cache(path: Path, ttl_hours: float) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        now = time.time()
        fresh: dict = {}
        for k, v in data.items():
            if not isinstance(v, dict):
                continue
            age = (now - v.get("_cached_at", 0)) / 3600
            if age <= ttl_hours:
                fresh[k] = v
        return fresh
    except Exception:
        return {}


def _save_json_cache(path: Path, cache: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_LOCK:
            path.write_text(json.dumps(cache, default=str), encoding="utf-8")
    except Exception:
        pass


def _wayback_cache_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / WAYBACK_CACHE_FILE if sd else None


def _sqli_probe_cache_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / SQLI_PROBE_CACHE_FILE if sd else None


def _sqli_probe_key(url: str, param: str) -> str:
    return hashlib.sha256(f"{url}|{param}".encode()).hexdigest()[:20]


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  HTTP SESSION (config-wired, v3.1 rate-limiter fallback)
# ══════════════════════════════════════════════════════════════════════════

class HttpSession:
    """
    Config-wired HTTP client for Phase 4 SQLi probing.
    """

    def __init__(self, host: str, bbp_program: Optional[str] = None,
                 proxy_pool: Any = None, audit_trail: Any = None,
                 use_proxy: bool = True,
                 rate_override: Optional[int] = None):
        self.host = host
        self.bbp_program = bbp_program
        self.audit = audit_trail
        self.proxy_pool = proxy_pool if use_proxy else None
        self.rate_override = rate_override
        self.rate_limiter = self._build_rate_limiter()
        self.static_headers = self._build_headers(bbp_program)
        self.stats = {"requests": 0, "errors": 0, "bytes": 0,
                       "proxies_used": set(), "scope_skipped": 0,
                       "waf_blocks": 0}

    def _build_rate_limiter(self) -> Any:
        """
        v3.1: config.py has NO "params" key. Fall back through the closest
        semantically-adjacent keys so the user's config is actually honored.
        v3.0 used `.get("params", {})` which returned {} → defaulted to 3 rps
        regardless of user config.
        """
        try:
            rl_cls = _cfg("RateLimiter")
            if self.rate_override is not None and self.rate_override > 0:
                rps = self.rate_override
            else:
                all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
                entry = (all_limits.get("params")
                         or all_limits.get("fuzzing")
                         or all_limits.get("crawl")
                         or all_limits.get("sqli_finder")
                         or {})
                rps = entry.get("rps", entry.get("rate_limit", DEFAULT_RATE_LIMIT))
            if not isinstance(rps, int) or rps < 0:
                rps = DEFAULT_RATE_LIMIT
            return rl_cls(per_minute=rps * 60, per_hour=rps * 3600) if rl_cls else None
        except Exception:
            return None

    def _build_headers(self, bbp_program: Optional[str]) -> dict:
        headers = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
        try:
            if bbp_program:
                builder = _cfg("build_headers")
                if callable(builder):
                    headers.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass
        return headers

    def _ua(self) -> str:
        try:
            fn = _cfg("random_user_agent")
            if callable(fn):
                return fn()
        except Exception:
            pass
        return "Mozilla/5.0 (compatible; Argus-Mimir/3.1)"

    def _next_proxy(self) -> Any:
        if self.proxy_pool is None:
            return None
        try:
            p = self.proxy_pool.pick()
            if p is not None:
                try:
                    self.stats["proxies_used"].add(p.url())
                except Exception:
                    pass
            return p
        except Exception:
            return None

    def _guard(self) -> None:
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"):
                ks.check()
        except Exception:
            pass

    def _pace(self) -> None:
        try:
            if self.rate_limiter is not None:
                self.rate_limiter.acquire()
            delay_fn = _cfg("human_delay")
            if callable(delay_fn):
                time.sleep(min(delay_fn(), 2.0))
            if random.random() < HUMAN_PAUSE_CHANCE:
                time.sleep(random.uniform(*HUMAN_PAUSE_RANGE))
        except Exception:
            pass

    def _in_scope(self, url: str) -> bool:
        try:
            scope = _cfg("SCOPE")
            if scope is None:
                return True
            if scope.is_in_scope(url):
                return True
            host = _host_of(url)
            if not host:
                return False
            for rule in getattr(scope, "_rules", []):
                if not getattr(rule, "include", True):
                    continue
                if getattr(rule, "regex", False):
                    continue
                pattern = (rule.pattern or "").lower().strip().lstrip("*.")
                if pattern and (host == pattern or host.endswith("." + pattern)):
                    return True
            return False
        except Exception:
            return True

    def _report_proxy(self, proxy: Any, success: bool, latency: float = 0.0) -> None:
        if proxy is None or self.proxy_pool is None:
            return
        try:
            if success:
                self.proxy_pool.report_success(proxy, latency)
            else:
                self.proxy_pool.report_failure(proxy)
        except Exception:
            pass

    def get(self, url: str, timeout: float = DEFAULT_TIMEOUT,
            referer: Optional[str] = None) -> HttpResult:
        if not self._in_scope(url):
            self.stats["scope_skipped"] += 1
            return HttpResult(0, {}, "", url, url, 0,
                              error="out of scope", error_category="scope")
        self._guard()
        self._pace()

        headers = dict(self.static_headers)
        headers["User-Agent"] = self._ua()
        if referer:
            headers["Referer"] = referer

        proxy = self._next_proxy()
        req = urllib.request.Request(url, headers=headers, method="GET")
        opener = urllib.request.build_opener()
        if proxy is not None:
            try:
                opener.add_handler(urllib.request.ProxyHandler(
                    {"http": proxy.url(), "https": proxy.url()}))
            except Exception:
                pass

        start = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(MAX_SQLI_BODY).decode("utf-8", errors="replace")
                latency = (time.monotonic() - start) * 1000
                headers_dict = {k: v for k, v in resp.headers.items()}
                self.stats["requests"] += 1
                self.stats["bytes"] += len(body)
                self._audit("GET", resp.geturl(), resp.getcode(), latency, None, proxy)
                self._report_proxy(proxy, True, latency / 1000)
                return HttpResult(resp.getcode(), headers_dict, body,
                                   url, resp.geturl(), latency)
        except urllib.error.HTTPError as e:
            latency = (time.monotonic() - start) * 1000
            try:
                body = e.read(MAX_SQLI_BODY).decode("utf-8", errors="replace")
                headers_dict = {k: v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                body, headers_dict = "", {}
            self.stats["requests"] += 1
            blocked, _ = _detect_waf_block(e.code, headers_dict, body)
            if blocked:
                self.stats["waf_blocks"] += 1
            self._audit("GET", url, e.code, latency, f"HTTP {e.code}", proxy)
            self._report_proxy(proxy, e.code < 500)
            return HttpResult(e.code, headers_dict, body, url, url, latency,
                              error=f"HTTP {e.code}", error_category=f"http{e.code}")
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            self.stats["errors"] += 1
            category = _categorize_error(e)
            self._audit("GET", url, 0, latency, str(e)[:200], proxy)
            self._report_proxy(proxy, False)
            return HttpResult(0, {}, "", url, url, latency,
                              error=f"{category}: {type(e).__name__}",
                              error_category=category)

    def _audit(self, method: str, url: str, status: int, latency_ms: float,
                error: Optional[str], proxy: Any) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                method=method, url=url, status=status,
                latency_ms=latency_ms,
                proxy=proxy.url() if proxy else None,
                user_agent="(rotating)", error=error)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
#  ᛉ  SUBPROCESS GUARD (v3.1 — actually records)
# ══════════════════════════════════════════════════════════════════════════

def _subprocess_guard(label: str) -> None:
    """Check KillSwitch before spawning external binaries."""
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


def _audit_subprocess(label: str, cmd: list[str], ok: bool,
                       duration_ms: float, error: str = "",
                       audit_trail: Any = None) -> None:
    """
    v3.1: actually records to AuditTrail. v3.0 was a `pass` statement.
    Subprocess calls aren't HTTP so method/status are synthetic, but the
    entry proves the tool ran and how long it took — useful in a dispute.
    """
    if audit_trail is not None and hasattr(audit_trail, "record"):
        try:
            audit_trail.record(
                method="SUBPROCESS",
                url=f"{label}:{' '.join(cmd[:3])}...",
                status=1 if ok else 0,
                latency_ms=duration_ms,
                proxy=None,
                user_agent="(subprocess)",
                error=error[:200] if error else None,
            )
        except Exception:
            pass
    log.debug(f"  subprocess[{label}]: ok={ok} "
              f"dur={duration_ms:.0f}ms err={error[:80]}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  INPUT LOADING (v3.1 — BOM/CRLF safe)
# ══════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path) -> list[str]:
    """v3.1: BOM/CRLF/inline-comment safe."""
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    urls: set[str] = set()
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
        urls.add(url.rstrip("/"))
    return sorted(urls)


def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    """v3.1: BOM/CRLF/inline-comment safe."""
    if not wildcard_file or not wildcard_file.exists():
        return []
    raw = wildcard_file.read_text(encoding="utf-8-sig", errors="replace")
    roots: set[str] = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line and "." in line:
            roots.add(line.rstrip("."))
    return sorted(roots)


def _auto_discover_inputs(outdir: Path) -> dict[str, Optional[Path]]:
    """v3.1: broader input discovery — matches actual pipeline outputs."""
    candidates = {
        "live_urls": [
            outdir / "urls_with_params.txt",
            outdir / "site_pages.txt",
            outdir / "live_urls.txt",
            outdir / "subs_resolved.txt",
            outdir / "all_subs.txt",
        ],
        "wildcard": [
            outdir / "wildcard.txt",
            outdir / "dns_wildcard_filtered.txt",
            outdir / "subs_resolved.txt",
            outdir / "subdomains.txt",
            outdir / "all_subs.txt",
        ],
    }
    found: dict[str, Optional[Path]] = {}
    for key, paths in candidates.items():
        chosen = None
        for p in paths:
            if p.exists() and p.stat().st_size > 0:
                chosen = p
                break
        found[key] = chosen
    return found


# ══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE (paramspider + wayback + v3.1 wayback cache)
# ══════════════════════════════════════════════════════════════════════════

def _run_paramspider(domain: str, workdir: Path,
                       bbp_program: Optional[str],
                       proxy_pool: Any, audit_trail: Any,
                       use_proxy: bool) -> list[str]:
    urls: list[str] = []

    if shutil.which("paramspider"):
        _subprocess_guard("paramspider")
        log.info(f"    paramspider  {domain}")
        output_file = workdir / f"paramspider_{domain}.txt"
        cmd = ["paramspider", "-d", domain,
                "-p", PARAMSPIDER_PLACEHOLDER,
                "-o", str(output_file), "-q"]
        t0 = time.monotonic()
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                             timeout=PARAMSPIDER_TIMEOUT)
            _audit_subprocess("paramspider", cmd, True,
                                (time.monotonic() - t0) * 1000,
                                audit_trail=audit_trail)
            if output_file.exists():
                urls = [line.strip() for line in
                         output_file.read_text().splitlines()
                         if line.strip() and "=" in line]
        except subprocess.TimeoutExpired:
            log.warning(f"    paramspider timeout on {domain}")
            _audit_subprocess("paramspider", cmd, False,
                                (time.monotonic() - t0) * 1000,
                                "timeout", audit_trail=audit_trail)
        except FileNotFoundError:
            pass

    if not urls:
        # v3.1: 24h wayback cache — avoids re-querying IA every run
        cache_path = _wayback_cache_path()
        cache = _load_json_cache(cache_path, WAYBACK_CACHE_TTL_HOURS) if cache_path else {}

        if domain in cache and cache[domain].get("urls"):
            log.info(f"    wayback cached   {domain}  "
                     f"({len(cache[domain]['urls'])} URL(s))")
            urls = list(cache[domain]["urls"])
        else:
            log.info(f"    wayback fallback  {domain}")
            session = HttpSession(host=domain, bbp_program=bbp_program,
                                    proxy_pool=proxy_pool,
                                    audit_trail=audit_trail,
                                    use_proxy=use_proxy)
            cdx_url = (f"http://web.archive.org/cdx/search/cdx?"
                        f"url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
                        f"&filter=original:.*\\?.*=.*")
            res = session.get(cdx_url, timeout=60)
            if res.ok and res.status == 200:
                for line in res.body.splitlines():
                    url = line.strip()
                    if not url or "=" not in url:
                        continue
                    try:
                        parsed = urllib.parse.urlparse(url)
                        params = urllib.parse.parse_qs(parsed.query)
                        if not params:
                            continue
                        fuzz = {k: [PARAMSPIDER_PLACEHOLDER] for k in params}
                        new_q = urllib.parse.urlencode(fuzz, doseq=True)
                        urls.append(urllib.parse.urlunparse(parsed._replace(query=new_q)))
                    except Exception:
                        continue
            if cache_path:
                cache[domain] = {"urls": urls, "_cached_at": time.time()}
                _save_json_cache(cache_path, cache)

    log.info(f"    → {len(urls)} parameterized URL(s)")
    return urls


def _passive_params_from_urls(urls: list[str]) -> dict[tuple[str, str], set[str]]:
    result: dict[tuple[str, str], set[str]] = {}
    for url in urls:
        base = _strip_query(url)
        params = _extract_query_params(url)
        if params:
            result.setdefault((base, "GET"), set()).update(params)
    return result


# ══════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ARJUN (v3.1 — proper resume)
# ══════════════════════════════════════════════════════════════════════════

def _run_arjun(url: str, method: str, workdir: Path, *,
                rate_limit: int, stable: bool,
                wordlist: Optional[Path], header_args: list[str],
                cookie_header: Optional[str],
                audit_trail: Any = None) -> EndpointResult:
    result = EndpointResult(url=url, method=method)
    if not shutil.which("arjun"):
        result.error = "arjun not installed"
        result.error_category = "missing-tool"
        return result

    tag = _tool_tag(url, method)
    evidence_dir = workdir.parent / "param_evidence"

    # v3.1: check evidence_dir first (survives prior crashes)
    evidence_file = _evidence_path(evidence_dir, "arjun", url, method)
    if evidence_file.exists() and evidence_file.stat().st_size > 0:
        log.debug(f"      arjun cached  [{method}] {url}")
        return _parse_arjun_output(evidence_file, url, method)

    # Fallback: workdir (partial state from same-run resume)
    output_file = workdir / f"arjun_{tag}.json"
    if output_file.exists() and output_file.stat().st_size > 0:
        return _parse_arjun_output(output_file, url, method)

    _subprocess_guard("arjun")
    cmd = ["arjun", "-u", url, "-m", method,
           "-oJ", str(output_file), "--ratelimit", str(rate_limit), "--quiet"]
    if stable:
        cmd.append("--stable")
    if wordlist and wordlist.exists():
        cmd.extend(["-w", str(wordlist)])
    for h in header_args:
        cmd.extend(["-H", h])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    log.info(f"      arjun  [{method}] {url}")
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=ARJUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        result.error = "arjun timeout"
        result.error_category = "timeout"
        _audit_subprocess("arjun", cmd, False,
                           (time.monotonic() - t0) * 1000,
                           "timeout", audit_trail=audit_trail)
        return result
    except FileNotFoundError:
        result.error = "arjun binary vanished"
        result.error_category = "missing-tool"
        return result
    dur_ms = (time.monotonic() - t0) * 1000
    _audit_subprocess("arjun", cmd, True, dur_ms, audit_trail=audit_trail)

    if not output_file.exists():
        result.error = f"arjun produced no output (stderr: {proc.stderr[:160]})"
        result.error_category = "no-output"
        return result

    return _parse_arjun_output(output_file, url, method)


def _parse_arjun_output(output_file: Path, url: str,
                          method: str) -> EndpointResult:
    result = EndpointResult(url=url, method=method)
    try:
        raw_text = output_file.read_text(encoding="utf-8")
        data: dict = {}
        try:
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                data = {}
        except json.JSONDecodeError:
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        data.update(obj)
                except json.JSONDecodeError:
                    continue

        for target_url, params in data.items():
            if not isinstance(params, list):
                continue
            for param in params:
                if not isinstance(param, str):
                    continue
                result.findings.append(ParameterFinding(
                    url=target_url, method=method, parameter=param,
                    oracles=["arjun"],
                    evidence=[f"arjun detected '{param}' on {method} {target_url}"],
                ))
    except Exception as e:
        result.error = f"parse failed: {e}"
        result.error_category = "parse"
    return result


# ══════════════════════════════════════════════════════════════════════════
#  PHASE 3 — X8 (v3.1 — proper resume)
# ══════════════════════════════════════════════════════════════════════════

def _run_x8(url: str, method: str, workdir: Path, *,
            header_args: list[str], cookie_header: Optional[str],
            audit_trail: Any = None) -> str:
    if not shutil.which("x8"):
        return ""

    tag = _tool_tag(url, method)
    evidence_dir = workdir.parent / "param_evidence"

    # v3.1: evidence_dir first
    evidence_file = _evidence_path(evidence_dir, "x8", url, method)
    if evidence_file.exists() and evidence_file.stat().st_size > 0:
        try:
            return evidence_file.read_text(encoding="utf-8")
        except Exception:
            pass

    output_file = workdir / f"x8_{tag}.json"
    if output_file.exists() and output_file.stat().st_size > 0:
        try:
            return output_file.read_text(encoding="utf-8")
        except Exception:
            pass

    wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if not Path(wordlist).exists():
        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    if not Path(wordlist).exists():
        log.debug("      x8     no wordlist found — skipping")
        return ""

    _subprocess_guard("x8")
    cmd = ["x8", "-u", url, "-X", method, "-w", wordlist,
            "--output-format", "json", "--timeout", "10"]
    for h in header_args:
        cmd.extend(["-H", h])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    log.info(f"      x8     [{method}] {url}")
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=X8_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning(f"      x8 timeout on {url}")
        _audit_subprocess("x8", cmd, False, (time.monotonic() - t0) * 1000,
                            "timeout", audit_trail=audit_trail)
        return ""
    except FileNotFoundError:
        return ""

    dur_ms = (time.monotonic() - t0) * 1000
    _audit_subprocess("x8", cmd, True, dur_ms, audit_trail=audit_trail)

    if proc.stdout:
        try:
            output_file.write_text(proc.stdout, encoding="utf-8")
        except Exception:
            pass

    return proc.stdout


def _parse_x8_output(stdout: str, url: str, method: str) -> list[ParameterFinding]:
    findings: list[ParameterFinding] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                param = obj.get("parameter") or obj.get("name")
                if param and str(param) not in seen:
                    seen.add(str(param))
                    findings.append(ParameterFinding(
                        url=url, method=method, parameter=str(param),
                        oracles=["x8"],
                        evidence=[f"x8 confirmed '{param}' on {method} {url}"],
                    ))
                    continue
            except json.JSONDecodeError:
                pass
        m = re.match(r"\[\+\]\s+(\S+)", line)
        if m:
            param = m.group(1)
            if param in seen:
                continue
            seen.add(param)
            findings.append(ParameterFinding(
                url=url, method=method, parameter=param,
                oracles=["x8"],
                evidence=[f"x8 confirmed '{param}' on {method} {url}"],
            ))
    return findings


# ══════════════════════════════════════════════════════════════════════════
#  PHASE 4 — TAMPERED SQLi PRE-CHECK (v3.1 — cache + WAF exit)
# ══════════════════════════════════════════════════════════════════════════

def _probe_param_with_tampers(
    session: HttpSession, base_url: str, param: str,
    tamper_names: list[str],
    probe_cache: Optional[dict] = None,
    probe_cache_path: Optional[Path] = None,
) -> Optional[dict]:
    """
    Try each error probe (raw + tampered). Return first DBMS hit.
    v3.1: 7-day cache — same URL+param pair skips re-probing.
    """
    cache_key = _sqli_probe_key(base_url, param)
    if probe_cache is not None and cache_key in probe_cache:
        cached = probe_cache[cache_key]
        log.debug(f"      probe cached for {param} on {base_url}")
        return cached

    for raw_probe in SQLI_ERROR_PROBES:
        variants: list[tuple[str, str]] = [("", raw_probe)]
        variants.extend(apply_tampers(raw_probe, tamper_names))

        for tamper_name, payload in variants:
            injected_url = rebuild_url_with_payload(base_url, param, payload)
            if not injected_url:
                continue
            res = session.get(injected_url, timeout=DEFAULT_TIMEOUT)
            if not res.ok and res.status == 0:
                continue
            body = (res.body or "")[:MAX_SQLI_BODY]
            dbms, sig = dbms_from_error(body)
            if dbms and sig:
                result = {
                    "dbms":      dbms,
                    "signature": sig,
                    "payload":   payload,
                    "tamper":    tamper_name or "none",
                }
                # v3.1: cache hit
                if probe_cache is not None and probe_cache_path is not None:
                    probe_cache[cache_key] = result
                    probe_cache[cache_key]["_cached_at"] = time.time()
                    _save_json_cache(probe_cache_path, probe_cache)
                return result
    return None


def _select_sqli_candidates(findings: list[ParameterFinding],
                             max_per_host: int) -> list[ParameterFinding]:
    """Filter to high-confidence, SQLi-relevant, hidden params."""
    candidates = []
    for f in findings:
        if f.already_in_url:
            continue
        if f.confidence < CONFIDENCE_MEDIUM:
            continue
        if not any(o in ("arjun", "x8") for o in f.oracles):
            continue
        if set(f.vuln_classes) & SQLI_RELEVANT_CLASSES:
            candidates.append(f)
            continue
        if SQLI_HINT_PARAM_RE.search(f.parameter.lower()):
            candidates.append(f)

    candidates.sort(key=lambda f: (-f.confidence, f.url))
    return candidates[:max_per_host]


def _run_phase4_per_host(
    host: str, findings: list[ParameterFinding],
    tamper_names: list[str], *,
    rate_limit: int,
    bbp_program: Optional[str],
    proxy_pool: Any, audit_trail: Any,
    use_proxy: bool,
) -> int:
    """Probe SQLi candidates for one host. Returns hit count."""
    if not TAMPERS_AVAILABLE or not tamper_names:
        return 0

    candidates = _select_sqli_candidates(findings, MAX_SQLI_PROBES_PER_HOST)
    if not candidates:
        return 0

    log.info(f"    [{host}] SQLi pre-check: {len(candidates)} candidate(s)")

    # v3.1: load 7d probe cache
    cache_path = _sqli_probe_cache_path()
    probe_cache = (_load_json_cache(cache_path, SQLI_PROBE_CACHE_TTL_HOURS)
                    if cache_path else {})

    session = HttpSession(host=host, bbp_program=bbp_program,
                            proxy_pool=proxy_pool,
                            audit_trail=audit_trail,
                            use_proxy=use_proxy,
                            rate_override=rate_limit)

    hits = 0
    consecutive_waf_blocks = 0
    for f in candidates:
        # v3.1: WAF early exit
        if consecutive_waf_blocks >= WAF_CONSECUTIVE_BLOCK_THRESHOLD:
            log.info(f"    [{host}] WAF blocking — exiting Phase 4 early")
            break

        # v3.1: KillSwitch per candidate
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"):
                ks.check()
        except Exception:
            break

        before_blocks = session.stats["waf_blocks"]
        try:
            result = _probe_param_with_tampers(
                session, f.url, f.parameter, tamper_names,
                probe_cache=probe_cache, probe_cache_path=cache_path)
        except Exception as e:
            log.debug(f"      probe failed for {f.parameter}: {e}")
            continue

        after_blocks = session.stats["waf_blocks"]
        if after_blocks > before_blocks:
            consecutive_waf_blocks += 1
        else:
            consecutive_waf_blocks = 0

        if result:
            f.sqli_probe_hit = True
            f.sqli_dbms      = result["dbms"]
            f.sqli_tamper    = result["tamper"]
            f.sqli_payload   = result["payload"]
            f.sqli_signature = result["signature"]
            f.evidence.append(
                f"SQLi pre-check: {result['dbms']} error on "
                f"{result['tamper']} payload {result['payload']!r}"
            )
            hits += 1
            log.info(f"      ⚡ HIT  {f.parameter} [{result['dbms']}] "
                      f"via {result['tamper']}")

    if session.stats["waf_blocks"] > 0 and hits == 0:
        log.warn(f"    [{host}] WAF blocked {session.stats['waf_blocks']} "
                  f"probe(s) — SQLi results may be incomplete")

    return hits


# ══════════════════════════════════════════════════════════════════════════
#  CHAIN AGGREGATION
# ══════════════════════════════════════════════════════════════════════════

def _apply_chains(finding: ParameterFinding) -> None:
    """Attach chain IDs and severity based on class + probe results."""
    for cls in finding.vuln_classes:
        cid = CLASS_TO_CHAIN.get(cls)
        if cid:
            finding.add_chain(cid)
    if not finding.already_in_url:
        finding.add_chain("param-hidden")
    if finding.sqli_probe_hit:
        finding.add_chain("param-sqli-confirmed")
    finding.severity = _severity_from_confidence(
        finding.confidence, finding.sqli_probe_hit)


def _build_host_chains(findings: list[ParameterFinding]) -> list[dict]:
    groups: dict[str, list[str]] = {}
    for f in findings:
        for cid in f.chain_ids:
            groups.setdefault(cid, []).append(
                f"{f.method} {f.url} · {f.parameter}")
    out = []
    for cid, members in groups.items():
        out.append({
            "chain_id": cid,
            "name":     CHAIN_NAMES.get(cid, cid),
            "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
            "members":  members[:100],
            "count":    len(members),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    out.sort(key=lambda c: (order.get(c["severity"], 5), c["chain_id"]))
    return out


# ══════════════════════════════════════════════════════════════════════════
#  AI TRIAGE + HEURISTIC TRIAGE
# ══════════════════════════════════════════════════════════════════════════

AI_PARAM_SYSTEM = (
    "You are an expert bug-bounty parameter-discovery analyst. Analyze "
    "findings from one host. Reference actual parameters, URLs, and "
    "vuln classes. Never suggest running exploits. Return STRICT JSON only."
)


def _build_top_params_block(findings: list[ParameterFinding],
                              limit: int = 30) -> str:
    top = sorted(findings, key=lambda f: (
        0 if f.sqli_probe_hit else 1,
        -f.severity.rank,
        -f.confidence,
    ))[:limit]

    lines = []
    for f in top:
        classes = ",".join(f.vuln_classes) or "-"
        oracles = ",".join(f.oracles)
        sqli = f" ⚡{f.sqli_dbms}" if f.sqli_probe_hit else ""
        tag = " (known)" if f.already_in_url else " (hidden)"
        lines.append(
            f"  [{f.confidence:>3}] {f.method:<5} {f.url[:50]:<50} "
            f"{f.parameter:<20} [{classes:<25}] ({oracles}){sqli}{tag}"
        )
    return "\n".join(lines) if lines else "  (no findings)"


def _ai_triage_host(host_result: HostResult, outdir: Path) -> Optional[dict]:
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.findings) < AI_MIN_FINDINGS_PER_HOST:
        return None

    findings = host_result.findings
    n_sqli = sum(1 for f in findings if f.sqli_probe_hit)
    n_hidden = sum(1 for f in findings if not f.already_in_url)
    n_high = sum(1 for f in findings if f.confidence >= CONFIDENCE_HIGH)

    prompt = f"""Analyze parameter discovery for {host_result.host}.

Stats:
  Endpoints scanned:  {len(host_result.endpoints)}
  Parameters found:   {len(findings)}
  Hidden (not in URL):{n_hidden}
  SQLi pre-check hits:{n_sqli}
  High confidence:    {n_high}

Top findings:
{_build_top_params_block(findings)}

Return STRICT JSON:
{{
  "summary": "one-paragraph overall assessment",
  "host_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "top_priorities": [
    {{"rank": 1, "finding": "which parameter", "reason": "why it matters",
      "test_idea": "specific manual test to run"}}
  ],
  "real_vs_noise": "which findings look real vs likely false positives",
  "next_actions": ["specific manual test 1", "specific test 2"]
}}"""

    try:
        response = ai_fn(prompt, system=AI_PARAM_SYSTEM)
    except Exception as e:
        log.warn(f"    AI triage failed: {type(e).__name__}: {e}")
        return None
    if not response:
        return None

    text = response.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not a dict")
    except Exception:
        data = {"summary": response[:1500], "parse_error": True}

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"param_ai_{safe}.md"
    try:
        md = (f"# Mímir's Thread · AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)} · "
              f"**Endpoints:** {len(host_result.endpoints)}  \n"
              f"**Model:** {_cfg('AI.model', 'deepseek-chat')}\n\n---\n\n")
        if data.get("summary"):
            md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("top_priorities"):
            md += "## Top Priorities\n\n"
            for p in data["top_priorities"]:
                md += (f"{p.get('rank', '?')}. **{p.get('finding', '')}**\n"
                        f"   - Reason: {p.get('reason', '')}\n"
                        f"   - Test: {p.get('test_idea', '')}\n\n")
        if data.get("real_vs_noise"):
            md += f"## Real vs Noise\n\n{data['real_vs_noise']}\n\n"
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"    AI triage saved: {md_path.name}")

    cost = None
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            cost = round(tracker.estimate_cost(), 6)
    except Exception:
        pass

    return {
        "path": str(md_path),
        "summary": data.get("summary", ""),
        "host_risk": data.get("host_risk", ""),
        "top_priorities": data.get("top_priorities", [])[:10],
        "real_vs_noise": data.get("real_vs_noise", ""),
        "next_actions": data.get("next_actions", [])[:10],
        "cost_estimate": cost,
        "source": "ai",
    }


def _suggest_test_for_class(cls: str) -> str:
    """Heuristic test suggestion by vuln class."""
    mapping = {
        "sqli":              "Test with `' OR '1'='1` and compare response; "
                              "then run sqlmap on the confirmed hit",
        "idor":              "Increment/decrement numeric value; check if "
                              "response reveals other users' data",
        "ssrf":              "Point at Burp Collaborator / interactsh; "
                              "check for OOB DNS callback",
        "lfi":               "Try `../../../../etc/passwd` and observe "
                              "response or error signature",
        "path_traversal":    "Try `..%2F..%2F..%2Fetc%2Fpasswd` (URL-encoded)",
        "command_injection": "Try `;id` and `|id`; check response for `uid=`",
        "open_redirect":     "Try `//evil.com` and `https://evil.com` — "
                              "check Location header / redirect",
        "xss":               "Try `<script>alert(1)</script>` and "
                              "`\"><svg onload=alert(1)>`",
        "ssti":              "Try `{{7*7}}` and `${7*7}` — check for `49` "
                              "in response body",
        "auth_bypass":       "Remove parameter entirely and check if "
                              "still authorized; try empty / null values",
        "privilege_escalation": "Try values like `admin`, `true`, `1`, `role=admin`",
        "mass_assignment":   "Add extra params like `is_admin=true` and "
                              "check if response reflects escalation",
        "info_disclosure":   "Try `true`, `1`, `yes` — check for verbose "
                              "errors or debug info",
    }
    return mapping.get(cls, "Manual inspection of context")


def _heuristic_triage(host_result: HostResult) -> dict:
    """Deterministic triage — always available, same schema as AI."""
    findings = host_result.findings
    if not findings:
        return {
            "summary": f"No parameters discovered on {host_result.host}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "real_vs_noise": "n/a",
            "next_actions": [
                "Consider running with --stable to try more names",
                "Check if --max-endpoints is too low for this host",
            ],
            "source": "heuristic",
        }

    n_hidden = sum(1 for f in findings if not f.already_in_url)
    n_sqli = sum(1 for f in findings if f.sqli_probe_hit)
    n_high = sum(1 for f in findings if f.confidence >= CONFIDENCE_HIGH)
    n_med  = sum(1 for f in findings if CONFIDENCE_MEDIUM <= f.confidence < CONFIDENCE_HIGH)
    n_low  = sum(1 for f in findings if f.confidence < CONFIDENCE_MEDIUM)

    class_counts: dict[str, int] = {}
    for f in findings:
        for cls in f.vuln_classes:
            class_counts[cls] = class_counts.get(cls, 0) + 1

    sevs = {f.severity for f in findings}
    if Severity.CRITICAL in sevs:   host_risk = "CRITICAL"
    elif Severity.HIGH in sevs:     host_risk = "HIGH"
    elif Severity.MEDIUM in sevs:   host_risk = "MEDIUM"
    elif Severity.LOW in sevs:      host_risk = "LOW"
    else:                            host_risk = "INFO"

    class_summary = " · ".join(
        f"{k}({v})" for k, v in sorted(class_counts.items(), key=lambda kv: -kv[1])[:6])
    summary = (f"{len(findings)} parameter(s) across {len(host_result.endpoints)} "
                f"endpoint(s). {n_hidden} hidden, {n_sqli} SQLi-confirmed. "
                f"{class_summary}.")

    top = sorted(findings, key=lambda f: (
        0 if f.sqli_probe_hit else 1,
        -f.severity.rank,
        -f.confidence,
    ))[:5]

    top_priorities = []
    for i, f in enumerate(top, 1):
        reason = f"{f.severity.value} confidence={f.confidence} "
        if f.sqli_probe_hit:
            reason += f"[SQLi pre-confirmed: {f.sqli_dbms}] "
        if f.vuln_classes:
            reason += f"({','.join(f.vuln_classes)})"

        test_idea = "Manual inspection"
        for cls in f.vuln_classes:
            if cls in HIGH_RISK_CLASSES:
                test_idea = _suggest_test_for_class(cls)
                break
        else:
            for cls in f.vuln_classes:
                if cls in MEDIUM_RISK_CLASSES:
                    test_idea = _suggest_test_for_class(cls)
                    break

        top_priorities.append({
            "rank": i,
            "finding": f"{f.method} {f.url} · {f.parameter}",
            "reason": reason,
            "test_idea": test_idea,
        })

    real_vs_noise = (
        f"Confidence distribution: {n_high} high (≥{CONFIDENCE_HIGH}), "
        f"{n_med} medium ({CONFIDENCE_MEDIUM}-{CONFIDENCE_HIGH-1}), "
        f"{n_low} low (<{CONFIDENCE_MEDIUM}). "
        f"{n_sqli} SQLi pre-confirmed. "
        f"High-confidence findings have strong oracle support + sensitive class."
    )

    next_actions: list[str] = []
    if n_sqli > 0:
        next_actions.append(
            f"Feed urls_sqli_priority.txt into sqli_finder.py — "
            f"{n_sqli} pre-confirmed SQLi-suspect parameters")
    if class_counts.get("idor", 0) > 0:
        next_actions.append(
            f"Test {class_counts['idor']} IDOR-class params by incrementing "
            f"numeric values and comparing responses")
    if class_counts.get("ssrf", 0) > 0:
        next_actions.append(
            f"Test {class_counts['ssrf']} SSRF-class params with "
            f"Burp Collaborator / interactsh")
    if class_counts.get("lfi", 0) + class_counts.get("path_traversal", 0) > 0:
        next_actions.append(
            f"Test file-path params with `../../../etc/passwd` traversal")
    if class_counts.get("xss", 0) > 0:
        next_actions.append(
            f"Feed {class_counts['xss']} XSS-class params into xss_finder.py")
    if class_counts.get("open_redirect", 0) > 0:
        next_actions.append(
            f"Test {class_counts['open_redirect']} redirect params with "
            f"`//evil.com`")
    if not next_actions:
        next_actions.append(
            "Manual review of high-confidence findings; consider running "
            "with --stable for deeper wordlists")

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "real_vs_noise": real_vs_noise,
        "next_actions": next_actions,
        "source": "heuristic",
    }


# ══════════════════════════════════════════════════════════════════════════
#  MERGE & FINALIZE
# ══════════════════════════════════════════════════════════════════════════

def _merge_findings(all_findings: list[ParameterFinding]) -> list[ParameterFinding]:
    merged: dict[tuple[str, str, str], ParameterFinding] = {}
    for f in all_findings:
        key = (f.url.rstrip("/"), f.method.upper(), f.parameter.lower())
        existing = merged.get(key)
        if not existing:
            merged[key] = ParameterFinding(
                url=f.url, method=f.method, parameter=f.parameter,
                oracles=list(f.oracles), evidence=list(f.evidence),
            )
            continue
        for o in f.oracles:
            if o not in existing.oracles:
                existing.oracles.append(o)
        for e in f.evidence:
            if e not in existing.evidence:
                existing.evidence.append(e)
    return list(merged.values())


def _finalize_findings(
    findings: list[ParameterFinding],
    pre_existing: dict[tuple[str, str], set[str]],
    auth_on: bool,
) -> list[ParameterFinding]:
    """Score confidence, classify, apply chains, attach severity."""
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        key = (f.url.rstrip("/"), f.method.upper())
        pre = pre_existing.get(key, set())
        f.already_in_url = f.parameter.lower() in {p.lower() for p in pre}
        f.vuln_classes = _classify_param(f.parameter)
        f.confidence = _score_confidence(
            f.parameter, f.url, f.method, f.oracles,
            f.already_in_url, f.sqli_probe_hit,
        )
        f.auth_enabled = auth_on
        f.first_seen = now
        _apply_chains(f)
    return findings


# ══════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ══════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[ParameterFinding]) -> None:
    try:
        from db import DB  # type: ignore
    except ImportError:
        log.info("  DB sync: db.py not available"); return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge not ready"); return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    try:
        result = DB.upsert_param_findings(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} parameter(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ══════════════════════════════════════════════════════════════════════════
#  EMPTY REPORT WRITER (v3.1 — for dry-run + zero-input paths)
# ══════════════════════════════════════════════════════════════════════════

def _write_empty_report(outdir: Path, input_file: Optional[Path],
                          start: float,
                          dry_run: bool = False,
                          scan_id: Optional[int] = None,
                          reason: str = "no_inputs") -> Path:
    """v3.1: writes a valid empty report so downstream stages don't fail."""
    report = {
        "schema_version":  3,
        "producer":        f"param_discovery.py v{__version__} '{__codename__}'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "dry_run":         dry_run,
        "reason":          reason,
        "input_file":      str(input_file) if input_file else None,
        "wildcard_file":   None,
        "bbp_program":     None,
        "use_proxy":       False,
        "auth_enabled":    False,
        "ai_enabled":      False,
        "config":          {},
        "audit":           {"trail_path": None, "trail_sha256": None},
        "totals": {
            "endpoints_scanned":  0,
            "passive_urls":       0,
            "total_parameters":   0,
            "unique_parameters":  0,
            "unique_endpoints":   0,
            "hidden_parameters":  0,
            "multi_oracle":       0,
            "sqli_pre_confirmed": 0,
            "high_confidence":    0,
            "medium_confidence":  0,
            "ai_triaged":         0,
            "heuristic_triaged":  0,
            "by_severity":        {"CRITICAL": 0, "HIGH": 0,
                                    "MEDIUM": 0, "LOW": 0, "INFO": 0},
        },
        "summary": {
            "by_oracle": {}, "by_vuln_class": {}, "by_method": {},
        },
        "chains":  [],
        "hosts":   [],
        "findings": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "param_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
    for name in ("param_analysis_hosts.jsonl", "params_by_endpoint.txt",
                  "param_passive.txt", "param_candidates.txt",
                  "urls_sqli_priority.txt"):
        (outdir / name).write_text("")
    (outdir / "param_sqli_hits.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tampers_used": [], "count": 0, "hits": [],
    }, indent=2) + "\n")
    return json_path


# ══════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT (v3.1)
# ══════════════════════════════════════════════════════════════════════════

def run_param_discovery(
    live_urls_file: Optional[Path] = None,
    outdir: Optional[Path] = None,
    wildcard_file: Optional[Path] = None,
    *,
    rate_limit: Optional[int] = None,
    stable: Optional[bool] = None,
    custom_wordlist: Optional[Path] = None,
    headers: Optional[dict] = None,
    cookie: Optional[str] = None,
    validate_with_x8: bool = True,
    max_endpoints: int = MAX_ENDPOINTS,
    tampers: Optional[list[str]] = None,
    enable_sqli_probe: Optional[bool] = None,
    auto_discover: bool = True,
    scan_id: Optional[int] = None,
    # ── v3.0 kwargs (backward compatible) ────────────────────────────────
    bbp_program: Optional[str] = None,
    use_proxy: bool = True,
    resume: bool = False,
    dry_run: bool = False,
    proxy_pool: Any = None,
    audit_trail: Any = None,
    # ── v3.1 additions ────────────────────────────────────────────────────
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
    parallel_phase4: int = DEFAULT_PARALLEL_PHASE4,
) -> Path:
    """
    Discover hidden parameters across the target surface, then triage.

    Backward-compatible with v2.0/v3.0 signature — callers passing only
    the original positional args + original kwargs get identical behavior.
    """
    start = time.monotonic()

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    if not shutil.which("arjun"):
        raise RuntimeError(
            "arjun not installed. Run `python3 tools.py --only arjun` first.")

    # v3.1: SIGINT/SIGTERM handler — writes partial report
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warn("Signal received — finishing current phase, writing partial report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    def _killswitch_tripped() -> bool:
        try:
            ks = _cfg("KillSwitch")
            if ks is not None and hasattr(ks, "check"):
                ks.check()
            return False
        except Exception as e:
            log.warn(f"KillSwitch tripped: {e}")
            _sigint["flag"] = True
            return True

    try:
        # ── Resolve outdir + input ────────────────────────────────────────
        if outdir is None:
            if live_urls_file is not None:
                outdir = live_urls_file.parent
            else:
                raise ValueError("Must provide either outdir or live_urls_file")
        outdir.mkdir(parents=True, exist_ok=True)

        if auto_discover:
            discovered = _auto_discover_inputs(outdir)
            if live_urls_file is None:
                live_urls_file = discovered.get("live_urls")
            if wildcard_file is None:
                wildcard_file = discovered.get("wildcard")

        if live_urls_file is None or not live_urls_file.exists():
            log.warning(f"No live-URL input found in {outdir} — writing empty report")
            return _write_empty_report(outdir, live_urls_file, start,
                                          reason="no_live_url_input")

        # ── Effective settings (v3.1 fallback chain) ─────────────────────
        all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
        limits = (all_limits.get("params")
                  or all_limits.get("fuzzing")
                  or all_limits.get("crawl")
                  or all_limits.get("sqli_finder")
                  or {})
        eff_rate     = rate_limit if rate_limit is not None else limits.get("rps", DEFAULT_RATE_LIMIT)
        eff_stable   = stable     if stable     is not None else limits.get("stable", ARJUN_STABLE_MODE)
        eff_threads  = limits.get("concurrency", DEFAULT_THREADS)
        eff_tampers  = tampers    if tampers    is not None else list(limits.get("tampers", DEFAULT_TAMPERS))
        eff_sqli     = enable_sqli_probe if enable_sqli_probe is not None else limits.get("sqli_probe", True)
        if not isinstance(eff_threads, int) or eff_threads < 1:
            eff_threads = DEFAULT_THREADS
        if not isinstance(eff_rate, int) or eff_rate < 0:
            eff_rate = DEFAULT_RATE_LIMIT
        max_endpoints, eff_threads = _effective_limits(max_endpoints, eff_threads)
        if parallel_phase4 < 1:
            parallel_phase4 = 1

        # ── Headers / auth ────────────────────────────────────────────────
        header_args: list[str] = []
        try:
            builder = _cfg("build_headers")
            if callable(builder) and bbp_program:
                hdrs = builder(bbp_program, dynamic_ua=False)
                header_args = [f"{k}: {v}" for k, v in hdrs.items()]
        except Exception:
            pass
        if headers:
            for k, v in headers.items():
                h = f"{k}: {v}"
                if h not in header_args:
                    header_args.append(h)

        cookie_header = cookie
        try:
            if not cookie_header and CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
                cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
                if cookies:
                    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        except Exception:
            pass
        auth_on = bool(header_args or cookie_header)

        # ── Inputs ────────────────────────────────────────────────────────
        live_urls = _load_urls(live_urls_file)
        roots     = _load_roots(wildcard_file)
        if not live_urls:
            log.warning("  Input file is empty — writing empty report")
            return _write_empty_report(outdir, live_urls_file, start,
                                          reason="empty_input")

        workdir      = outdir / "param_work"
        evidence_dir = outdir / "param_evidence"
        workdir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        if not quiet:
            log.info(f"Input  : {len(live_urls)} URL(s) from {live_urls_file.name}")
            log.info(f"Roots  : {len(roots)} wildcard(s)"
                     f"{f' ({wildcard_file.name})' if wildcard_file else ''}")
            log.info(f"Config : rate={eff_rate}/s  stable={eff_stable}  "
                     f"threads={eff_threads}  x8={validate_with_x8}  "
                     f"parallel_phase4={parallel_phase4}")
            log.info(f"         tampers={'ON' if eff_sqli else 'OFF'} "
                     f"[{','.join(eff_tampers)}]" if eff_sqli else
                     f"         tampers=OFF")
            log.info(f"         bbp={bbp_program or 'none'}  proxy={use_proxy}  "
                     f"ai_enabled={_ai_enabled()}")
            log.info(f"Auth   : {'enabled' if auth_on else 'disabled'}")
            if LIGHTWEIGHT_MODE:
                log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — limits capped")

        if dry_run:
            log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
            log.info(f"Would analyze {len(live_urls)} URL(s), "
                     f"{len(roots)} root(s), {max_endpoints} endpoint cap")
            return _write_empty_report(outdir, live_urls_file, start,
                                          dry_run=True, scan_id=scan_id,
                                          reason="dry_run")

        # ── Proxy pool + audit trail ──────────────────────────────────────
        if use_proxy and proxy_pool is None:
            try:
                pool_cls = _cfg("ProxyPool")
                if pool_cls is not None:
                    proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
            except Exception:
                pass
        if audit_trail is None:
            try:
                factory = _cfg("new_audit_trail")
                if callable(factory):
                    audit_trail = factory("params-" + (live_urls_file.stem if live_urls_file else "scan"))
            except Exception:
                pass

        # ── Pre-existing params ───────────────────────────────────────────
        pre_existing: dict[tuple[str, str], set[str]] = {}
        for url in live_urls:
            base = _strip_query(url)
            existing = _extract_query_params(url)
            if existing:
                pre_existing.setdefault((base, "GET"), set()).update(existing)

        # ── Resume: pre-load completed arjun/x8 results ───────────────────
        if resume and evidence_dir.exists():
            for f in workdir.glob("arjun_*.json"):
                try:
                    f.rename(evidence_dir / f.name)
                except Exception:
                    pass
            for f in workdir.glob("x8_*.json"):
                try:
                    f.rename(evidence_dir / f.name)
                except Exception:
                    pass
            log.info(f"Resume : {len(list(evidence_dir.glob('arjun_*.json')))} "
                      f"arjun + {len(list(evidence_dir.glob('x8_*.json')))} "
                      f"x8 result(s) available")

        # ════════════════════════════════════════════════════════════════
        #  PHASE 1 — Passive
        # ════════════════════════════════════════════════════════════════
        if not _killswitch_tripped() and not _sigint["flag"]:
            _progress("stage_start", {"stage": "passive", "roots": len(roots)})
            log.rune(Rune.RAIDO, "Phase 1 · Passive parameter mining")
            passive_urls: list[str] = []
            for root in roots:
                if _sigint["flag"]:
                    break
                passive_urls.extend(_run_paramspider(
                    root, workdir, bbp_program, proxy_pool, audit_trail, use_proxy))
            passive_urls = sorted(set(passive_urls))
            (outdir / "param_passive.txt").write_text(
                "\n".join(passive_urls) + ("\n" if passive_urls else ""))
            passive_map = _passive_params_from_urls(passive_urls)
            log.ok(f"  Passive: {len(passive_map)} endpoint(s)")
            _progress("stage_end", {"stage": "passive", "urls": len(passive_urls)})
        else:
            passive_urls = []
            passive_map = {}

        # ════════════════════════════════════════════════════════════════
        #  Build active targets
        # ════════════════════════════════════════════════════════════════
        active_targets: list[tuple[str, str]] = []
        for url in live_urls:
            base = _strip_query(url)
            active_targets.append((base, "GET"))
            parsed = urllib.parse.urlparse(base)
            if any(w in parsed.path.lower()
                   for w in ("/api", "/v1", "/v2", "/graphql")):
                active_targets.append((base, "POST"))
                active_targets.append((base, "JSON"))
        for (base_url, method) in passive_map.keys():
            active_targets.append((base_url, method))

        seen: set[tuple[str, str]] = set()
        unique_targets: list[tuple[str, str]] = []
        for t in active_targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)
        if len(unique_targets) > max_endpoints:
            log.warning(f"Capping at {max_endpoints} endpoints "
                         f"(input had {len(unique_targets)})")
            unique_targets = unique_targets[:max_endpoints]
        log.info(f"  Active targets: {len(unique_targets)} (method,url) pair(s)")

        # ════════════════════════════════════════════════════════════════
        #  PHASE 2 — Arjun
        # ════════════════════════════════════════════════════════════════
        all_findings: list[ParameterFinding] = []
        endpoint_results: list[EndpointResult] = []

        if not _killswitch_tripped() and not _sigint["flag"]:
            _progress("stage_start", {"stage": "arjun",
                                        "endpoints": len(unique_targets)})
            log.rune(Rune.KANO, "Phase 2 · Active parameter discovery (Arjun)")
            if eff_stable:
                log.info("  stable mode — expect slower scans")

            with ThreadPoolExecutor(max_workers=eff_threads) as pool:
                futures = {
                    pool.submit(_run_arjun, url, method, workdir,
                                 rate_limit=eff_rate, stable=eff_stable,
                                 wordlist=custom_wordlist, header_args=header_args,
                                 cookie_header=cookie_header,
                                 audit_trail=audit_trail): (url, method)
                    for url, method in unique_targets
                }
                for fut in as_completed(futures):
                    url, method = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as e:
                        result = EndpointResult(url=url, method=method,
                                                  error=str(e),
                                                  error_category="runtime")
                    endpoint_results.append(result)
                    all_findings.extend(result.findings)
                    if result.findings:
                        log.ok(f"  {len(result.findings)} param(s) on [{method}] {url[:70]}")
                    elif result.error:
                        log.debug(f"  {result.error_category}: {result.error[:80]}")
            _progress("stage_end", {"stage": "arjun",
                                      "findings": len(all_findings)})

        # ════════════════════════════════════════════════════════════════
        #  PHASE 3 — x8
        # ════════════════════════════════════════════════════════════════
        if (validate_with_x8 and shutil.which("x8")
                and not _killswitch_tripped() and not _sigint["flag"]):
            _progress("stage_start", {"stage": "x8"})
            log.rune(Rune.ALGIZ, "Phase 3 · x8 differential validation")

            by_host_endpoints: dict[str, list[EndpointResult]] = {}
            for r in endpoint_results:
                if not r.findings:
                    continue
                h = _host_of(r.url)
                by_host_endpoints.setdefault(h, []).append(r)

            for host, results in by_host_endpoints.items():
                if _sigint["flag"]:
                    break
                top = sorted(results, key=lambda r: -len(r.findings))[:X8_VALIDATE_TOP_N_PER_HOST]
                for result in top:
                    stdout = _run_x8(
                        result.url, result.method, workdir,
                        header_args=header_args, cookie_header=cookie_header,
                        audit_trail=audit_trail)
                    if stdout:
                        result.x8_raw = stdout
                        x8_findings = _parse_x8_output(
                            stdout, result.url, result.method)
                        all_findings.extend(x8_findings)
                        if x8_findings:
                            log.ok(f"  x8 confirmed {len(x8_findings)} on {result.url[:70]}")
            _progress("stage_end", {"stage": "x8",
                                      "findings": len(all_findings)})
        elif validate_with_x8:
            log.info("Phase 3 · x8 not installed or skipped")

        # Merge passive findings
        for (base_url, method), params in passive_map.items():
            for param in params:
                all_findings.append(ParameterFinding(
                    url=base_url, method=method, parameter=param,
                    oracles=["passive"],
                    evidence=[f"passive (wayback) found '{param}' on {base_url}"],
                ))

        # ════════════════════════════════════════════════════════════════
        #  Merge + preliminary scoring
        # ════════════════════════════════════════════════════════════════
        merged = _merge_findings(all_findings)
        provisional = _finalize_findings(merged, pre_existing, auth_on)

        # ════════════════════════════════════════════════════════════════
        #  PHASE 4 — SQLi pre-check (v3.1 parallel + cache + WAF exit)
        # ════════════════════════════════════════════════════════════════
        if (eff_sqli and TAMPERS_AVAILABLE
                and not _killswitch_tripped() and not _sigint["flag"]):
            _progress("stage_start", {"stage": "sqli"})
            log.rune(Rune.TIWAZ, "Phase 4 · Tampered SQLi pre-check")
            if not eff_tampers:
                log.warning("  no tampers configured — skipping")
            else:
                by_host: dict[str, list[ParameterFinding]] = {}
                for f in provisional:
                    by_host.setdefault(_host_of(f.url), []).append(f)

                # v3.1: parallel hosts with divided rate
                eff_phase4_workers = max(1, parallel_phase4)
                eff_rate_per_worker = (
                    max(1, eff_rate // eff_phase4_workers) if eff_rate > 0 else 0
                )
                if eff_phase4_workers > 1:
                    log.info(f"  parallel Phase 4: {eff_phase4_workers} worker(s) "
                             f"@ {eff_rate_per_worker}/s each")

                total_hits = 0

                def _phase4_host(item: tuple[str, list[ParameterFinding]]) -> int:
                    host, host_findings = item
                    if _sigint["flag"]:
                        return 0
                    try:
                        return _run_phase4_per_host(
                            host, host_findings, eff_tampers,
                            rate_limit=eff_rate_per_worker,
                            bbp_program=bbp_program,
                            proxy_pool=proxy_pool, audit_trail=audit_trail,
                            use_proxy=use_proxy)
                    except Exception as e:
                        log.debug(f"    Phase 4 host {host} failed: {e}")
                        return 0

                if eff_phase4_workers > 1 and len(by_host) > 1:
                    with ThreadPoolExecutor(max_workers=eff_phase4_workers) as pool:
                        for hits in pool.map(_phase4_host, by_host.items()):
                            total_hits += hits
                else:
                    for item in by_host.items():
                        total_hits += _phase4_host(item)

                # Re-score after probe
                for f in provisional:
                    f.confidence = _score_confidence(
                        f.parameter, f.url, f.method, f.oracles,
                        f.already_in_url, f.sqli_probe_hit)
                    _apply_chains(f)
                log.ok(f"  SQLi pre-check: {total_hits} confirmed")
            _progress("stage_end", {"stage": "sqli"})
        elif eff_sqli:
            log.info("Phase 4 · tampers module unavailable or skipped")
        else:
            log.info("Phase 4 · disabled via --no-tampered-probe")

        # ════════════════════════════════════════════════════════════════
        #  Per-host triage + streaming
        # ════════════════════════════════════════════════════════════════
        _progress("stage_start", {"stage": "triage"})
        log.rune(Rune.GEBO, "Triage · AI + heuristic per host")
        by_host_final: dict[str, list[ParameterFinding]] = {}
        for f in provisional:
            by_host_final.setdefault(_host_of(f.url), []).append(f)

        stream_path = outdir / "param_analysis_hosts.jsonl"
        if not resume and stream_path.exists():
            stream_path.unlink()

        all_hosts: list[HostResult] = []
        ai_hosts_done = 0

        for host, host_findings in sorted(by_host_final.items()):
            if _sigint["flag"] and len(all_hosts) > 0:
                log.warn("Triage: signal received — writing partial results")
                break
            log.rune(Rune.OTHALA, f"{host} — {len(host_findings)} param(s)")
            host_start = time.monotonic()

            host_endpoints = [r for r in endpoint_results
                               if _host_of(r.url) == host]
            host_result = HostResult(
                host=host, endpoints=host_endpoints,
                findings=host_findings,
                chains=_build_host_chains(host_findings),
            )

            ai_result = None
            if _ai_enabled() and len(host_findings) >= AI_MIN_FINDINGS_PER_HOST \
                    and ai_hosts_done < AI_MAX_HOSTS_PER_RUN:
                ai_result = _ai_triage_host(host_result, outdir)
                if ai_result:
                    ai_hosts_done += 1

            heuristic_result = _heuristic_triage(host_result)

            if ai_result:
                host_result.triage = ai_result
                host_result.triage_source = "ai"
            else:
                host_result.triage = heuristic_result
                host_result.triage_source = "heuristic"

            host_result.elapsed_seconds = round(time.monotonic() - host_start, 2)
            all_hosts.append(host_result)

            try:
                with stream_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "host": host,
                        "elapsed_seconds": host_result.elapsed_seconds,
                        "findings": [ff.to_dict() for ff in host_findings],
                        "chains": host_result.chains,
                        "triage": host_result.triage,
                        "triage_source": host_result.triage_source,
                    }, ensure_ascii=False) + "\n")
            except Exception:
                pass

            n_hit = sum(1 for f in host_findings if f.sqli_probe_hit)
            n_high = sum(1 for f in host_findings if f.confidence >= CONFIDENCE_HIGH)
            triage_tag = f" triage={host_result.triage_source}"
            log.ok(f"  {len(host_findings)} param(s) · {n_high} high · "
                    f"{n_hit} SQLi-hit{triage_tag}")
        _progress("stage_end", {"stage": "triage"})

        # ════════════════════════════════════════════════════════════════
        #  Sort + write outputs
        # ════════════════════════════════════════════════════════════════
        provisional.sort(key=lambda f: (
            0 if f.sqli_probe_hit else 1,
            -f.severity.rank,
            -f.confidence,
            f.url, f.parameter))
        finalized = provisional

        by_endpoint: dict[str, list[ParameterFinding]] = {}
        for f in finalized:
            key = f"{f.method} {f.url}"
            by_endpoint.setdefault(key, []).append(f)

        flat_lines: list[str] = []
        for endpoint_key in sorted(by_endpoint):
            method, url = endpoint_key.split(" ", 1)
            params = sorted({f.parameter for f in by_endpoint[endpoint_key]})
            flat_lines.append(f"{method}\t{url}\t{','.join(params)}")
        (outdir / "params_by_endpoint.txt").write_text(
            "\n".join(flat_lines) + ("\n" if flat_lines else ""))

        all_params: set[str] = {f.parameter for f in finalized}
        (outdir / "param_candidates.txt").write_text(
            "\n".join(sorted(all_params)) + ("\n" if all_params else ""))

        sqli_hits = [f for f in finalized if f.sqli_probe_hit]
        sqli_json = outdir / "param_sqli_hits.json"
        sqli_json.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tampers_used": eff_tampers,
            "count": len(sqli_hits),
            "hits": [f.to_dict() for f in sqli_hits],
        }, indent=2, ensure_ascii=False) + "\n")

        priority_urls: set[str] = set()
        for f in sqli_hits:
            priority_urls.add(rebuild_url_with_payload(f.url, f.parameter, "1"))
        (outdir / "urls_sqli_priority.txt").write_text(
            "\n".join(sorted(priority_urls)) + ("\n" if priority_urls else ""))

        # Preserve evidence
        try:
            for f in workdir.glob("arjun_*.json"):
                f.rename(evidence_dir / f.name)
            for f in workdir.glob("x8_*.json"):
                f.rename(evidence_dir / f.name)
        except Exception:
            pass
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass

        # ── Report ────────────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        by_oracle: dict[str, int] = {"arjun": 0, "x8": 0, "passive": 0}
        by_vuln:   dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_sev:    dict[str, int] = {"CRITICAL": 0, "HIGH": 0,
                                        "MEDIUM": 0, "LOW": 0, "INFO": 0}
        hidden_count = 0
        multi_oracle_count = 0
        ai_triaged = sum(1 for h in all_hosts if h.triage_source == "ai")
        heuristic_triaged = sum(1 for h in all_hosts if h.triage_source == "heuristic")

        for f in finalized:
            for o in f.oracles:
                by_oracle[o] = by_oracle.get(o, 0) + 1
            by_method[f.method] = by_method.get(f.method, 0) + 1
            by_sev[f.severity.value] += 1
            for v in f.vuln_classes:
                by_vuln[v] = by_vuln.get(v, 0) + 1
            if not f.already_in_url: hidden_count += 1
            if len(f.oracles) > 1:    multi_oracle_count += 1

        all_chains_groups: dict[str, list[str]] = {}
        for h in all_hosts:
            for c in h.chains:
                all_chains_groups.setdefault(c["chain_id"], []).extend(
                    c.get("members", []))
        agg_chains = []
        for cid, members in all_chains_groups.items():
            agg_chains.append({
                "chain_id": cid,
                "name":     CHAIN_NAMES.get(cid, cid),
                "severity": CHAIN_SEVERITY.get(cid, Severity.LOW).value,
                "members":  members[:100],
                "count":    len(members),
            })
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        agg_chains.sort(key=lambda c: (order.get(c["severity"], 5), c["chain_id"]))

        audit_path = getattr(audit_trail, "path", None) if audit_trail else None

        report = {
            "schema_version":  3,
            "producer":        f"param_discovery.py v{__version__} '{__codename__}'",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "input_file":      str(live_urls_file),
            "wildcard_file":   str(wildcard_file) if wildcard_file else "",
            "bbp_program":     bbp_program,
            "use_proxy":       use_proxy,
            "auth_enabled":    auth_on,
            "ai_enabled":      _ai_enabled(),
            "host_capacity": {
                "cpu_cores":          HOST_CORES,
                "ram_mb":             HOST_RAM_MB,
                "lightweight":        LIGHTWEIGHT_MODE,
                "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
            },
            "config": {
                "rate_limit":       eff_rate,
                "stable":           eff_stable,
                "threads":          eff_threads,
                "x8_validation":    validate_with_x8,
                "max_endpoints":    max_endpoints,
                "sqli_probe":       eff_sqli,
                "tampers":          eff_tampers,
                "headers_count":    len(header_args),
                "cookie_set":       bool(cookie_header),
                "parallel_phase4":  parallel_phase4,
            },
            "audit": {
                "trail_path":   str(audit_path) if audit_path else None,
                "trail_sha256": _audit_hash(audit_path),
            },
            "totals": {
                "endpoints_scanned":   len(unique_targets),
                "passive_urls":        len(passive_urls),
                "total_parameters":    len(finalized),
                "unique_parameters":   len(all_params),
                "unique_endpoints":    len(by_endpoint),
                "hidden_parameters":   hidden_count,
                "multi_oracle":        multi_oracle_count,
                "sqli_pre_confirmed":  len(sqli_hits),
                "high_confidence":     sum(1 for f in finalized
                                             if f.confidence >= CONFIDENCE_HIGH),
                "medium_confidence":   sum(1 for f in finalized
                                             if CONFIDENCE_MEDIUM <= f.confidence < CONFIDENCE_HIGH),
                "ai_triaged":          ai_triaged,
                "heuristic_triaged":   heuristic_triaged,
                "by_severity":         by_sev,
            },
            "summary": {
                "by_oracle":     by_oracle,
                "by_vuln_class": dict(sorted(by_vuln.items(), key=lambda kv: -kv[1])),
                "by_method":     by_method,
            },
            "chains":  agg_chains,
            "hosts":   [
                {
                    "host":             h.host,
                    "elapsed_seconds":  h.elapsed_seconds,
                    "findings":         [f.to_dict() for f in h.findings],
                    "chains":           h.chains,
                    "triage":           h.triage,
                    "triage_source":    h.triage_source,
                    "errors":           h.errors,
                }
                for h in all_hosts
            ],
            "findings": [f.to_dict() for f in finalized],
        }

        json_path = outdir / "param_findings.json"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")

        if not quiet:
            _print_summary(outdir, report, elapsed, eff_rate, eff_sqli)

        if scan_id is not None:
            _self_sync(scan_id, finalized)

        return json_path

    finally:
        try:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        except (ValueError, OSError):
            pass


def _audit_hash(p: Optional[Path]) -> Optional[str]:
    if not p: return None
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _print_summary(outdir: Path, report: dict, elapsed: float,
                    rate: int, sqli_on: bool) -> None:
    log.rune(Rune.SOWILO, "Summary")
    t = report["totals"]
    log.info(f"Endpoints scanned  : {t['endpoints_scanned']}")
    log.info(f"Passive URLs       : {t['passive_urls']}")
    log.info(f"Total parameters   : {t['total_parameters']}")
    log.info(f"  Unique endpoints : {t['unique_endpoints']}")
    log.info(f"  Unique params    : {t.get('unique_parameters', t['total_parameters'])}")
    log.info(f"  Hidden params    : {t['hidden_parameters']}")
    log.info(f"  Multi-oracle     : {t['multi_oracle']}")
    log.info(f"  SQLi-confirmed   : {t['sqli_pre_confirmed']}")
    log.info(f"  High confidence  : {t['high_confidence']}")
    log.info(f"  Medium confidence: {t['medium_confidence']}")

    if report["ai_enabled"]:
        log.info(f"Triage             : AI={t['ai_triaged']} · "
                  f"heuristic={t['heuristic_triaged']}")
    else:
        log.info(f"Triage             : heuristic={t['heuristic_triaged']}")

    by_sev = t.get("by_severity") or {}
    log.info("Severity           : " + " ".join(
        f"{k}={by_sev.get(k, 0)}" for k in
        ("CRITICAL", "HIGH", "MEDIUM", "LOW")))

    chains = report.get("chains") or []
    if chains:
        log.info("")
        log.info("Chains:")
        for c in chains[:12]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<30} "
                      f"[{c['severity']}] {c['count']} member(s)")

    log.info("")
    log.info("Outputs:")
    log.info(f"  {Sym.ARROW} param_findings.json           {t['total_parameters']:>5}")
    log.info(f"  {Sym.ARROW} param_analysis_hosts.jsonl")
    log.info(f"  {Sym.ARROW} params_by_endpoint.txt        {t['unique_endpoints']:>5}")
    log.info(f"  {Sym.ARROW} param_passive.txt             {t['passive_urls']:>5}")
    log.info(f"  {Sym.ARROW} param_candidates.txt          {t.get('unique_parameters', 0):>5}")
    log.info(f"  {Sym.ARROW} param_sqli_hits.json          {t['sqli_pre_confirmed']:>5}")
    log.info(f"  {Sym.ARROW} urls_sqli_priority.txt        {t['sqli_pre_confirmed']:>5}")
    if report["ai_enabled"] and t["ai_triaged"] > 0:
        log.info(f"  {Sym.ARROW} param_ai_<host>.md")
    log.info(f"  {Sym.ARROW} param_evidence/")
    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
#  SELF-TEST (v3.1 — 62 checks)
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Mímir's Thread integrity")

    def _mk(url: str, param: str, method: str = "GET",
             oracles: list[str] = None) -> ParameterFinding:
        return ParameterFinding(
            url=url, method=method, parameter=param,
            oracles=oracles or ["arjun"],
        )

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",             lambda: CFG_LOADED),
        ("Rune.RAIDO",                lambda: Rune.RAIDO == "ᚱ"),
        ("Severity ranks",            lambda: Severity.CRITICAL.rank == 4),
        ("version is 3.1.0",          lambda: __version__ == "3.1.0"),
        ("_host_of works",            lambda: _host_of("https://a.b.com/x") == "a.b.com"),
        ("_strip_query",              lambda: _strip_query("https://x.com/a?id=1") == "https://x.com/a"),
        ("_extract_query_params",     lambda: _extract_query_params(
                                        "https://x.com/a?id=1&n=2") == {"id", "n"}),
        ("_classify_param id",        lambda: "idor" in _classify_param("user_id")),
        ("_classify_param url",       lambda: "ssrf" in _classify_param("redirect_url")),
        ("_classify_param file",      lambda: "lfi" in _classify_param("filename")),
        ("_classify_param cmd",       lambda: "command_injection" in _classify_param("cmd")),
        ("_classify_param q",         lambda: "sqli" in _classify_param("q")),
        ("_classify_param token",     lambda: "auth_bypass" in _classify_param("api_key")),
        ("_classify_param plain",     lambda: _classify_param("foo_bar") == []),
        ("_score_confidence base",    lambda: _score_confidence(
                                        "foo", "https://x.com/", "GET", ["arjun"], False) >= 40),
        ("_score_confidence high",    lambda: _score_confidence(
                                        "user_id", "https://x.com/api/", "GET",
                                        ["arjun", "x8"], False) >= 80),
        ("_score_confidence sqli",    lambda: _score_confidence(
                                        "id", "https://x.com/", "GET",
                                        ["arjun"], False, True) >= 75),
        ("_severity_from_conf",       lambda: _severity_from_confidence(95) == Severity.HIGH),
        ("_severity_from_conf CRIT",  lambda: _severity_from_confidence(50, True) == Severity.CRITICAL),
        ("CHAIN_NAMES>=10",           lambda: len(CHAIN_NAMES) >= 10),
        ("CHAIN_SEVERITY>=10",        lambda: len(CHAIN_SEVERITY) >= 10),
        ("CLASS_TO_CHAIN sqli",       lambda: CLASS_TO_CHAIN.get("sqli") == "param-sqli"),
        ("VULN_CLASS_MAP>=80",        lambda: len(VULN_CLASS_MAP) >= 80),
        ("_apply_chains idor",        lambda: (lambda f: (
                                            _apply_chains(f),
                                            "param-idor" in f.chain_ids and
                                            "param-hidden" in f.chain_ids
                                        )[1])(_mk("https://x.com/a", "user_id"))),
        ("_apply_chains sqli confirmed", lambda: (lambda f: (
                                            setattr(f, "sqli_probe_hit", True),
                                            _apply_chains(f),
                                            "param-sqli-confirmed" in f.chain_ids and
                                            f.severity == Severity.CRITICAL
                                        )[2])(_mk("https://x.com/a", "id"))),
        ("_merge_findings dedupe",    lambda: len(_merge_findings([
                                            _mk("https://x.com/a", "id"),
                                            _mk("https://x.com/a", "id"),
                                        ])) == 1),
        ("_merge_findings oracles",   lambda: _merge_findings([
                                            _mk("https://x.com/a", "id", oracles=["arjun"]),
                                            _mk("https://x.com/a", "id", oracles=["x8"]),
                                        ])[0].oracles == ["arjun", "x8"]),
        ("_build_host_chains",        lambda: isinstance(_build_host_chains([
                                            _mk("https://x.com/a", "user_id")
                                        ]), list)),
        ("_heuristic_triage empty",   lambda: _heuristic_triage(
                                            HostResult(host="x.com"))["host_risk"] == "INFO"),
        ("_heuristic_triage risky",   lambda: (lambda f: (
                                            f.vuln_classes.__contains__("idor"),
                                            _apply_chains(f),
                                            _heuristic_triage(HostResult(
                                                host="x.com", findings=[f]))["host_risk"]
                                            in ("HIGH", "CRITICAL")
                                        )[2])(_mk("https://x.com/a", "user_id"))),
        ("_ai_triage_host callable",  lambda: callable(_ai_triage_host)),
        ("_ai_enabled callable",      lambda: callable(_ai_enabled)),
        ("_suggest_test sqli",        lambda: "sqlmap" in _suggest_test_for_class("sqli")),
        ("_suggest_test ssrf",        lambda: "collaborator" in _suggest_test_for_class("ssrf").lower()),
        ("_detect_waf_block cf",      lambda: _detect_waf_block(
                                            403, {"cf-mitigated": "challenge"}, "")[0] is True),
        ("_detect_waf_block ok",      lambda: _detect_waf_block(
                                            200, {"server": "nginx"}, "")[0] is False),
        ("_select_sqli_candidates",   lambda: callable(_select_sqli_candidates)),
        ("_probe_param_with_tampers", lambda: callable(_probe_param_with_tampers)),
        ("HttpSession init",          lambda: callable(HttpSession)),
        ("_tool_tag deterministic",   lambda: _tool_tag(
                                            "https://x.com/a", "GET") == _tool_tag(
                                            "https://x.com/a", "GET")),
        ("_tool_tag arjun==x8",       lambda: _tool_tag("https://x.com/a", "GET")
                                            == _tool_tag("https://x.com/a", "GET")),
        ("_evidence_path deterministic", lambda: _evidence_path(
                                            Path("/tmp"), "arjun", "https://x.com/a", "GET")
                                            == _evidence_path(
                                            Path("/tmp"), "arjun", "https://x.com/a", "GET")),
        ("TAMPERS_AVAILABLE",         lambda: isinstance(TAMPERS_AVAILABLE, bool)),
        ("_subprocess_guard callable",lambda: callable(_subprocess_guard)),
        ("_audit_subprocess callable",lambda: callable(_audit_subprocess)),
        ("_load_urls callable",       lambda: callable(_load_urls)),
        ("_load_roots callable",      lambda: callable(_load_roots)),
        ("_auto_discover_inputs",     lambda: callable(_auto_discover_inputs)),
        ("_passive_params_from_urls", lambda: _passive_params_from_urls([
                                            "https://x.com/a?id=1&n=2"]) == {
                                            ("https://x.com/a", "GET"): {"id", "n"}}),
        ("_write_empty_report callable", lambda: callable(_write_empty_report)),
        ("run_param_discovery",       lambda: callable(run_param_discovery)),
        # v3.1 checks
        ("_load_urls BOM safe",       lambda: (lambda tmp: (
                                            _load_urls(tmp) == ["https://a.example", "https://b.example"]
                                        ))((lambda p: (
                                            p.write_bytes(b"\xef\xbb\xbfhttps://a.example\r\nb.example  # inline\r\n"),
                                            p))(Path(tempfile.mkstemp(suffix=".txt")[1]))[1])),
        ("_load_roots BOM safe",      lambda: callable(_load_roots)),
        ("_wayback_cache_path",       lambda: callable(_wayback_cache_path)),
        ("_sqli_probe_cache_path",    lambda: callable(_sqli_probe_cache_path)),
        ("_sqli_probe_key stable",    lambda: _sqli_probe_key("https://x.com/a", "id")
                                            == _sqli_probe_key("https://x.com/a", "id")),
        ("_sqli_probe_key distinct",  lambda: _sqli_probe_key("https://x.com/a", "id")
                                            != _sqli_probe_key("https://x.com/a", "user")),
        ("WAF_CONSECUTIVE_THRESHOLD", lambda: WAF_CONSECUTIVE_BLOCK_THRESHOLD == 5),
        ("DEFAULT_PARALLEL_PHASE4",   lambda: DEFAULT_PARALLEL_PHASE4 == 1),
        ("run has on_progress",       lambda: "on_progress" in
                                            inspect.signature(run_param_discovery).parameters),
        ("run has quiet",             lambda: "quiet" in
                                            inspect.signature(run_param_discovery).parameters),
        ("run has parallel_phase4",   lambda: "parallel_phase4" in
                                            inspect.signature(run_param_discovery).parameters),
    ]

    # tempfile needed for BOM test
    import tempfile

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn(): log.ok(name); passed += 1
            else: log.error(f"{name} → False"); failed += 1
        except Exception as e:
            log.error(f"{name} → {type(e).__name__}: {e}"); failed += 1

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ SELFTEST PASSED · {passed} checks ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('crimson')}{Sym.SKULL}  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  {Sym.SKULL}{_c('reset')}")
    return 1


def config_check() -> int:
    print_banner()
    log.rune(Rune.KANO, "Config integration check")

    if not CFG_LOADED:
        log.error("config.py NOT loaded")
        if _CFG_IMPORT_ERROR:
            log.info(f"  error: {_CFG_IMPORT_ERROR}")
        return 1

    log.ok("config.py loaded")
    log.info(f"  version: {_cfg('__version__', '?')} \"{_cfg('__codename__', '?')}\"")

    items = [
        ("SCOPE",              lambda: _cfg("SCOPE") is not None),
        ("ProxyPool",          lambda: _cfg("ProxyPool") is not None),
        ("KillSwitch",         lambda: _cfg("KillSwitch") is not None),
        ("AuditTrail",         lambda: callable(_cfg("new_audit_trail"))),
        ("RateLimiter",        lambda: _cfg("RateLimiter") is not None),
        ("human_delay",        lambda: callable(_cfg("human_delay"))),
        ("random_user_agent",  lambda: callable(_cfg("random_user_agent"))),
        ("build_headers",      lambda: callable(_cfg("build_headers"))),
        ("ai_complete",        lambda: callable(_cfg("ai_complete"))),
    ]
    failed = 0
    for name, fn in items:
        try:
            if fn(): log.ok(name)
            else: log.warn(f"{name} — not configured"); failed += 1
        except Exception as e:
            log.error(f"{name} — {e}"); failed += 1

    log.info("")
    log.info(f"AI_ENABLED       : {_ai_enabled()}")
    if _ai_enabled():
        log.ok("AI triage will run on hosts with >=3 findings")
    else:
        log.info("Heuristic triage will run (same schema, no API cost)")

    log.info(f"arjun            : {'present' if shutil.which('arjun') else 'NOT FOUND'}")
    log.info(f"x8               : {'present' if shutil.which('x8') else 'NOT FOUND (validation skipped)'}")
    log.info(f"paramspider      : {'present' if shutil.which('paramspider') else 'NOT FOUND (wayback fallback)'}")
    log.info(f"tampers module   : {'loaded' if TAMPERS_AVAILABLE else 'NOT available'}")

    # v3.1: rate-limiter fallback check
    log.info("")
    log.info("Rate-limiter fallback chain:")
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    for key in ("params", "fuzzing", "crawl", "sqli_finder"):
        entry = all_limits.get(key) or {}
        if entry:
            log.ok(f"  {key:<14} found — rps={entry.get('rps', '?')}")
            break
    else:
        log.warn(f"  no rate-limit key found — will use default {DEFAULT_RATE_LIMIT}/s")

    # Input availability
    out = _cfg("OUTPUT_DIR") or Path("output")
    for name in ("urls_with_params.txt", "site_pages.txt", "live_urls.txt", "all_subs.txt"):
        p = out / name
        log.info(f"{name:<22}: {'present' if p.exists() else 'NOT FOUND'}")

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} item(s) unconfigured ══  {Sym.WARN}{_c('reset')}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  CLI (v3.1)
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"

    p = argparse.ArgumentParser(
        prog="param_discovery.py",
        description=f"Argus recon · param_discovery v{__version__} '{__codename__}'",
    )
    p.add_argument("--input", type=Path, default=default_input,
                    help="urls_with_params.txt | live_urls.txt | all_subs.txt")
    p.add_argument("--output", type=Path, default=base / "output")
    p.add_argument("--wildcard-file", type=Path, default=base / "wildcard.txt")
    p.add_argument("--bbp", type=str, default=None)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--stable", action="store_true",
                    help="Arjun stable mode (slower, fewer false positives)")
    p.add_argument("--no-x8", action="store_true",
                    help="skip x8 differential validation")
    p.add_argument("--no-tampered-probe", action="store_true",
                    help="skip Phase 4 SQLi pre-check")
    p.add_argument("--tampers", default=None,
                    help="comma-separated tamper names (default: shared)")
    p.add_argument("--max-endpoints", type=int, default=MAX_ENDPOINTS)
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    # v3.1 additions
    p.add_argument("--parallel-phase4", type=int, default=DEFAULT_PARALLEL_PHASE4,
                    help="parallel Phase 4 workers (default 1 = serial)")
    p.add_argument("--quiet", action="store_true",
                    help="suppress summary (CI-friendly)")
    # Utility
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                    version=f"param_discovery.py {__version__} '{__codename__}'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try: CFG.Palette._enabled = False  # type: ignore
        except Exception: pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()

    if not args.quiet:
        print_banner()

    tamper_names = args.tampers.split(",") if args.tampers else None

    try:
        run_param_discovery(
            args.input, args.output,
            wildcard_file=args.wildcard_file,
            rate_limit=args.rate_limit,
            stable=args.stable if args.stable else None,
            validate_with_x8=not args.no_x8,
            max_endpoints=args.max_endpoints,
            tampers=tamper_names,
            enable_sqli_probe=not args.no_tampered_probe,
            scan_id=args.scan_id,
            bbp_program=args.bbp,
            use_proxy=not args.no_proxy,
            resume=args.resume,
            dry_run=args.dry_run,
            quiet=args.quiet,
            parallel_phase4=args.parallel_phase4,
        )
        return 0
    except KeyboardInterrupt:
        log.warn("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
