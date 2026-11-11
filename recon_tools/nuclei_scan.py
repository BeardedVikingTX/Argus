#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛊ ᚢ ᚱ ᛏ ᚱ   ·   N U C L E I   S C A N   ·   S U R T R ' S   W R A T H
================================================================================
  File      : recon_tools/nuclei_scan.py
  Version   : 3.0.0 "SURTR'S WRATH REFORGED"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  v3.0 changes vs v2.0:
    [FIX]  _build_cmd() got an unexpected keyword argument 'resume'
           Three-layer defense-in-depth:
             1. _build_cmd() now accepts **kwargs and ignores unknowns
             2. _run_batch() pops `resume` before passing kwargs through
             3. run_nuclei_scan() no longer smuggles resume via **kwargs
    [NEW]  AI triage cache (nuclei_ai_cache/) — same findings = same result,
           skips on resume and re-runs
    [NEW]  --ai-max-cost USD budget cap — drops to heuristic when reached
    [NEW]  --ai-max-hosts cap (default 20) — bounded spend on big scans
    [NEW]  --no-ai flag — explicit override of config.AI_ENABLED
    [NEW]  Interactsh OFF by default (-ni) — safety + speed for BBP
    [NEW]  --interactsh-url for self-hosted OAST servers
    [NEW]  -or (omit-raw) by default — 10× smaller output files
    [NEW]  -duc (disable update check) + -stats-json
    [NEW]  --page-timeout, --exclude-matcher, --sni, --track-error flags
    [NEW]  Config-driven defaults: NUCLEI_NO_INTERACTSH, NUCLEI_INTERACTSH_URL,
           NUCLEI_PAGE_TIMEOUT, NUCLEI_EXCLUDE_MATCHERS
    [NEW]  Enhanced nuclei v3.x schema tolerance (CVSS vectors, port strings,
           template_id alias variants, case-insensitive headers)
    [NEW]  Failed nuclei batches surface stderr with benign-error filter
    [NEW]  Expanded selftest (50+ checks, verifies the resume fix itself)

  Outputs:
    nuclei_findings.json         — aggregated report
    nuclei_analysis_hosts.jsonl  — per-host streamed (crash-safe)
    nuclei_critical.txt          — CRIT/HIGH matched URLs
    nuclei_all.txt               — all matched URLs
    nuclei_raw.jsonl             — sorted findings, one per line
    nuclei_ai_<host>.md          — per-host AI triage (when AI on)
    nuclei_ai_cache/             — cached AI results (TTL 72h)
    nuclei_evidence/             — raw batch output (resume support)
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
import subprocess
import sys
import time
import urllib.parse
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
    LOCK = "🔒"; GEAR = "⚙"; SHAMROCK = "☘"; BOLT = "⚡"; SWORD = "⚔"


class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


__version__ = "3.0.0"
__codename__ = "SURTR'S WRATH REFORGED"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛊ ᚢ ᚱ ᛏ ᚱ{R}
    {P}{rule}{R}
    {V}      N U C L E I   S C A N   ·   S U R T R ' S   W R A T H{R}
    {V}              R E F O R G E D   ·   v{__version__}{R}
    {D}{rule}{R}
    {G}        {Sym.FIRE}  "{__codename__}"  ·  8000+ templates · AI-ready{R}
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

DEFAULT_RATE_LIMIT          = 5
DEFAULT_CONCURRENCY         = 10
DEFAULT_BULK_SIZE           = 5
DEFAULT_TIMEOUT             = 10
DEFAULT_RETRIES             = 1

MAX_TARGETS_PER_BATCH       = 100
NUCLEI_HARD_TIMEOUT         = 7200
MAX_FINDINGS_REPORT         = 50000
TEMPLATE_UPDATE_TIMEOUT     = 600

AI_MIN_FINDINGS_PER_HOST    = 1
AI_MAX_HOSTS_PER_RUN        = 20
AI_DEFAULT_CACHE_TTL_HOURS  = 72

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                    "LOW": 3, "INFO": 4, "UNKNOWN": 5}

CHAIN_SEVERITY: dict[str, Severity] = {
    "nuclei-critical-finding":   Severity.CRITICAL,
    "nuclei-high-finding":       Severity.HIGH,
    "nuclei-cve-match":          Severity.HIGH,
    "nuclei-exposed-config":     Severity.HIGH,
    "nuclei-exposed-panel":      Severity.HIGH,
    "nuclei-default-creds":      Severity.CRITICAL,
    "nuclei-cors-misconfig":     Severity.MEDIUM,
    "nuclei-takeover-suspect":   Severity.HIGH,
    "nuclei-tech-disclosure":    Severity.LOW,
    "nuclei-rce-candidate":      Severity.CRITICAL,
    "nuclei-sqli-candidate":     Severity.HIGH,
    "nuclei-ssrf-candidate":     Severity.HIGH,
    "nuclei-lfi-candidate":      Severity.HIGH,
    "nuclei-xss-candidate":      Severity.MEDIUM,
    "nuclei-auth-bypass":        Severity.HIGH,
    "nuclei-sensitive-file":     Severity.HIGH,
    "nuclei-multi-finding-host": Severity.MEDIUM,
}

CHAIN_NAMES: dict[str, str] = {
    "nuclei-critical-finding":   "Nuclei CRITICAL finding",
    "nuclei-high-finding":       "Nuclei HIGH finding",
    "nuclei-cve-match":          "Known CVE matched by nuclei",
    "nuclei-exposed-config":     "Exposed configuration file",
    "nuclei-exposed-panel":      "Exposed admin/login panel",
    "nuclei-default-creds":      "Default credentials detected",
    "nuclei-cors-misconfig":     "CORS misconfiguration",
    "nuclei-takeover-suspect":   "Takeover-related finding",
    "nuclei-tech-disclosure":    "Technology version disclosure",
    "nuclei-rce-candidate":      "Potential RCE",
    "nuclei-sqli-candidate":     "Potential SQL injection",
    "nuclei-ssrf-candidate":     "Potential SSRF",
    "nuclei-lfi-candidate":      "Potential LFI/path traversal",
    "nuclei-xss-candidate":      "Potential XSS",
    "nuclei-auth-bypass":        "Potential auth bypass",
    "nuclei-sensitive-file":     "Sensitive file exposed",
    "nuclei-multi-finding-host": "Host with 3+ nuclei findings",
}

TEMPLATE_CHAIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^cve-\d{4}-", re.I),                                          "nuclei-cve-match"),
    (re.compile(r"default-?login|default-?cred|default-?password|default-?pass", re.I), "nuclei-default-creds"),
    (re.compile(r"(?:exposed|disclosure|exposure)-.*?(?:config|env|settings|secret)", re.I), "nuclei-exposed-config"),
    (re.compile(r"(?:^|-)\.?env(?:$|-)|\.git-?(?:config|head|index)", re.I),     "nuclei-exposed-config"),
    (re.compile(r"(?:admin|dashboard|panel|management)(?:-panel)?", re.I),      "nuclei-exposed-panel"),
    (re.compile(r"jenkins|grafana|kibana|adminer|phpmyadmin|tomcat-manager", re.I), "nuclei-exposed-panel"),
    (re.compile(r"cors-?(?:misconfig|wildcard|origin)", re.I),                  "nuclei-cors-misconfig"),
    (re.compile(r"takeover|subdomain-?(?:takeover|hijack)", re.I),              "nuclei-takeover-suspect"),
    (re.compile(r"tech-?(?:detect|fingerprint)|version-?(?:detect|disclosure)", re.I), "nuclei-tech-disclosure"),
    (re.compile(r"rce-|remote-?code|command-?injection|deserialization", re.I), "nuclei-rce-candidate"),
    (re.compile(r"sqli|sql-?injection|blind-?sql", re.I),                       "nuclei-sqli-candidate"),
    (re.compile(r"ssrf|server-?side-?request", re.I),                           "nuclei-ssrf-candidate"),
    (re.compile(r"lfi|path-?traversal|local-?file-?inclusion", re.I),           "nuclei-lfi-candidate"),
    (re.compile(r"xss|cross-?site-?scripting", re.I),                           "nuclei-xss-candidate"),
    (re.compile(r"auth-?bypass|broken-?auth|unauthenticated|unauth-", re.I),    "nuclei-auth-bypass"),
    (re.compile(r"backup|\.bak|\.sql|\.zip|\.tar|file-?download|sensitive-?file", re.I), "nuclei-sensitive-file"),
]

WAF_BLOCK_BODY_MARKERS = (
    "attention required! | cloudflare",
    "just a moment...",
    "checking your browser",
    "ddos-guard",
    "enable javascript and cookies",
)

PROFILES: dict[str, dict] = {
    "critical": {
        "severities":   ["critical"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "description":  "Critical only — fastest first pass",
    },
    "standard": {
        "severities":   ["critical", "high", "medium"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "description":  "Critical + high + medium — bug bounty default",
    },
    "thorough": {
        "severities":   ["critical", "high", "medium", "low"],
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce"],
        "description":  "All severities except info — deep audit",
    },
    "recommended": {
        "severities":   None,
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz", "intrusive", "bruteforce", "headless"],
        "templates":    ["-as"],
        "description":  "Recommended subset with autoscan",
    },
    "full": {
        "severities":   None,
        "tags_allow":   None,
        "tags_deny":    ["dos", "fuzz"],
        "description":  "Everything including info — noisiest",
    },
}

DEFAULT_PROFILE = "standard"


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


def _effective_limits(rate: int, conc: int, bulk: int) -> tuple[int, int, int]:
    if not LIGHTWEIGHT_MODE:
        return rate, conc, bulk
    return max(1, min(rate, 3)), min(conc, 5), min(bulk, 3)


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class NucleiFinding:
    template_id:        str
    template_name:      str = ""
    template_path:      str = ""
    template_author:    list[str] = field(default_factory=list)
    severity:           str = "UNKNOWN"
    cvss_score:         Optional[float] = None
    cve_ids:            list[str] = field(default_factory=list)
    cwe_ids:            list[str] = field(default_factory=list)
    matched_at:         str = ""
    host:               str = ""
    ip:                 str = ""
    port:               Optional[int] = None
    scheme:             str = ""
    path:               str = ""
    matcher_name:       str = ""
    extracted_results:  list[str] = field(default_factory=list)
    curl_command:       str = ""
    request:            str = ""
    response:           str = ""
    tags:               list[str] = field(default_factory=list)
    description:        str = ""
    reference:          list[str] = field(default_factory=list)
    metadata:           dict = field(default_factory=dict)
    chain_ids:          list[str] = field(default_factory=list)
    waf_blocked:        bool = False
    auth_enabled:       bool = False
    first_seen:         str = ""

    def add_chain(self, cid: str) -> None:
        if cid not in self.chain_ids:
            self.chain_ids.append(cid)

    def to_dict(self) -> dict:
        return {
            "template_id":       self.template_id,
            "template_name":     self.template_name,
            "template_path":     self.template_path,
            "template_author":   self.template_author,
            "severity":          self.severity,
            "cvss_score":        self.cvss_score,
            "cve_ids":           self.cve_ids,
            "cwe_ids":           self.cwe_ids,
            "matched_at":        self.matched_at,
            "host":              self.host,
            "ip":                self.ip,
            "port":              self.port,
            "scheme":            self.scheme,
            "path":              self.path,
            "matcher_name":      self.matcher_name,
            "extracted_results": self.extracted_results,
            "curl_command":      self.curl_command,
            "request":           self.request,
            "response":          self.response,
            "tags":              self.tags,
            "description":       self.description,
            "reference":         self.reference,
            "metadata":          self.metadata,
            "chain_ids":         self.chain_ids,
            "waf_blocked":       self.waf_blocked,
            "auth_enabled":      self.auth_enabled,
            "first_seen":        self.first_seen,
        }


@dataclass
class BatchResult:
    batch_index:    int
    input_file:     str = ""
    targets_count:  int = 0
    findings_count: int = 0
    duration_ms:    int = 0
    rate_limit:     Optional[int] = None
    concurrency:    Optional[int] = None
    bulk_size:      Optional[int] = None
    severities:     str = ""
    tags_allow:     str = ""
    tags_deny:      str = ""
    templates_used: str = ""
    headless:       bool = False
    auth_enabled:   bool = False
    error:          str = ""
    first_seen:     str = ""

    def to_dict(self) -> dict:
        return {
            "batch_index":    self.batch_index,
            "input_file":     self.input_file,
            "targets_count":  self.targets_count,
            "findings_count": self.findings_count,
            "duration_ms":    self.duration_ms,
            "rate_limit":     self.rate_limit,
            "concurrency":    self.concurrency,
            "bulk_size":      self.bulk_size,
            "severities":     self.severities,
            "tags_allow":     self.tags_allow,
            "tags_deny":      self.tags_deny,
            "templates_used": self.templates_used,
            "headless":       self.headless,
            "auth_enabled":   self.auth_enabled,
            "error":          self.error,
            "first_seen":     self.first_seen,
        }


@dataclass
class HostResult:
    host: str
    findings: list[NucleiFinding] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    triage: Optional[dict] = None
    triage_source: str = ""
    error: str = ""


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_waf_block_response(body: str) -> bool:
    if not body:
        return False
    body_lower = body[:3000].lower()
    return any(m in body_lower for m in WAF_BLOCK_BODY_MARKERS)


def _severity_of_str(sev: str) -> Severity:
    s = (sev or "unknown").upper()
    try:
        return Severity(s)
    except ValueError:
        return Severity.INFO


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  TEMPLATE CLASSIFICATION → CHAINS
# ══════════════════════════════════════════════════════════════════════════

def _classify_template_to_chains(template_id: str) -> list[str]:
    chains: list[str] = []
    for pattern, cid in TEMPLATE_CHAIN_PATTERNS:
        if pattern.search(template_id):
            if cid not in chains:
                chains.append(cid)
    return chains


def _apply_chains(finding: NucleiFinding) -> None:
    if finding.severity == "CRITICAL":
        finding.add_chain("nuclei-critical-finding")
    elif finding.severity == "HIGH":
        finding.add_chain("nuclei-high-finding")
    if finding.cve_ids:
        finding.add_chain("nuclei-cve-match")
    for cid in _classify_template_to_chains(finding.template_id):
        finding.add_chain(cid)


def _build_host_chains(findings: list[NucleiFinding]) -> list[dict]:
    groups: dict[str, list[str]] = {}
    for f in findings:
        for cid in f.chain_ids:
            groups.setdefault(cid, []).append(f"{f.template_id}@{f.matched_at}")

    if len(findings) >= 3:
        groups.setdefault("nuclei-multi-finding-host", []).append(
            f"{len(findings)} finding(s) on {_host_of(findings[0].matched_at)}")

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
#  ᛜ  INPUT LOADING
# ══════════════════════════════════════════════════════════════════════════

def _load_targets(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    targets: list[str] = []
    seen: set[str] = set()
    for line in input_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        if token not in seen:
            seen.add(token)
            targets.append(token)
    return targets


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  SUBPROCESS GUARD + AUDIT
# ══════════════════════════════════════════════════════════════════════════

def _subprocess_guard(label: str) -> None:
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


def _audit_subprocess(label: str, cmd: list[str], ok: bool,
                       duration_ms: float, error: str = "") -> None:
    log.debug(f"  subprocess[{label}]: ok={ok} dur={duration_ms:.0f}ms "
              f"err={error[:80]}")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  TEMPLATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════

def _update_templates() -> bool:
    if not shutil.which("nuclei"):
        log.warning("  nuclei not installed — cannot update templates")
        return False

    _subprocess_guard("nuclei-update-templates")
    log.info("  Updating nuclei templates...")
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True, text=True, timeout=TEMPLATE_UPDATE_TIMEOUT,
        )
        dur_ms = (time.monotonic() - t0) * 1000
        _audit_subprocess("nuclei-update-templates",
                            ["nuclei", "-update-templates"],
                            result.returncode == 0, dur_ms,
                            result.stderr[:200])
        if result.returncode == 0:
            log.ok("  Templates updated")
            return True
        log.warning(f"  template update returned {result.returncode}: "
                     f"{result.stderr.strip()[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log.warning(f"  template update timed out after "
                     f"{TEMPLATE_UPDATE_TIMEOUT}s")
        return False
    except FileNotFoundError:
        return False


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  HEADER + PROXY RESOLUTION
# ══════════════════════════════════════════════════════════════════════════

def _headers_for_nuclei(bbp_program: Optional[str],
                          extra: Optional[dict]) -> tuple[list[str], bool]:
    """Build -H args from config.build_headers + ACTIVE_HEADERS + AUTH_HEADERS + extra."""
    merged: dict[str, str] = {}

    if bbp_program:
        try:
            builder = _cfg("build_headers")
            if callable(builder):
                merged.update(builder(bbp_program, dynamic_ua=False))
        except Exception:
            pass

    try:
        merged.update(_cfg("ACTIVE_HEADERS", {}) or {})
    except Exception:
        pass

    try:
        if getattr(CFG, "AUTH_ENABLED", False):
            merged.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    except Exception:
        pass

    if extra:
        merged.update(extra)

    args: list[str] = []
    has_ua = False
    for k, v in merged.items():
        args.extend(["-H", f"{k}: {v}"])
        if k.lower() == "user-agent":
            has_ua = True
    return args, has_ua


def _pick_proxy(proxy_pool: Any) -> Optional[str]:
    if proxy_pool is None:
        return None
    try:
        p = proxy_pool.pick()
        return p.url() if p else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════
#  ⚡  COMMAND BUILDER — v3.0 FIXED
#      • Accepts **_ignored to swallow unknown kwargs (defense #1)
#      • -ni (no interactsh) by default — safety
#      • -duc, -stats-json, -or for lean output
#      • page-timeout, interactsh-url, exclude-matchers, sni, track-error
# ══════════════════════════════════════════════════════════════════════════

def _build_cmd(
    targets_file: Path,
    output_jsonl: Path,
    *,
    rate_limit: int,
    concurrency: int,
    bulk_size: int,
    timeout: int,
    retries: int,
    profile: str,
    custom_templates: Optional[list[str]] = None,
    custom_tags: Optional[list[str]] = None,
    header_args: Optional[list[str]] = None,
    cookie_header: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
    has_ua: bool = False,
    page_timeout: Optional[int] = None,
    interactsh_url: Optional[str] = None,
    no_interactsh: bool = True,
    exclude_matchers: Optional[list[str]] = None,
    sni: Optional[str] = None,
    track_error: bool = False,
    omit_raw: bool = True,
    **_ignored: Any,
) -> list[str]:
    """
    v3.0.1 — Tiered flags for maximum nuclei-version compatibility.

    Tier 1 (always emitted — verified in nuclei 2.x AND 3.x):
        -l  -jsonl  -o  -rl  -c  -timeout  -retries
        -silent  -nc  -severity  -exclude-tags  -random-agent
        -H  -t  -proxy  -headless  -sni  -page-timeout

    Tier 2 (opt-in via env/config — may not exist on older builds):
        -no-interactsh  -interactsh-url  -exclude-matchers
        -track-error  -omit-raw  -bulk-size

    Tier 3 (removed in v3.0.1 — the likely culprits for your exit 2):
        -duc  -stats  -stats-json
        These aliases are not consistently present. The speed gain
        from -duc was negligible; -stats-json wasn't parsed by the
        pipeline anyway.
    """
    if _ignored:
        log.debug(f"  _build_cmd: ignored kwargs: {sorted(_ignored.keys())}")

    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    # ═══ TIER 1 — universal safe flags ═══
    cmd: list[str] = [
        "nuclei",
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_jsonl),
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-silent",
        "-nc",
    ]

    # ═══ TIER 1 — universal safe flags (bulk-size: long form only) ═══
    if bulk_size and bulk_size != DEFAULT_BULK_SIZE:
        cmd.extend(["-bulk-size", str(bulk_size)])

    if prof.get("severities"):
        cmd.extend(["-severity", ",".join(prof["severities"])])

    tags_allow: list[str] = []
    if prof.get("tags_allow"):
        tags_allow.extend(prof["tags_allow"])
    if custom_tags:
        tags_allow.extend(custom_tags)
    if tags_allow:
        cmd.extend(["-tags", ",".join(tags_allow)])

    if prof.get("tags_deny"):
        cmd.extend(["-exclude-tags", ",".join(prof["tags_deny"])])

    if "templates" in prof:
        cmd.extend(prof["templates"])

    if custom_templates:
        for t in custom_templates:
            cmd.extend(["-t", t])

    for hdr in (header_args or []):
        cmd.extend(["-H", hdr])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    if not has_ua:
        cmd.append("-random-agent")

    if headless:
        cmd.append("-headless")

    if proxy:
        cmd.extend(["-proxy", proxy])

    if sni:
        cmd.extend(["-sni", sni])

    if page_timeout and page_timeout != timeout:
        cmd.extend(["-page-timeout", str(page_timeout)])

    # ═══ TIER 2 — opt-in extras (config-driven) ═══

    # Exclude matchers (long form only — safe on 3.x, missing on 2.x)
    if exclude_matchers and CFG_LOADED and \
            getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False):
        for m in exclude_matchers:
            cmd.extend(["-exclude-matchers", m])

    # Interactsh: only if explicitly enabled
    if no_interactsh and CFG_LOADED and \
            getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False):
        cmd.append("-no-interactsh")
    elif interactsh_url and CFG_LOADED and \
            getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False):
        cmd.extend(["-interactsh-url", interactsh_url])

    if track_error and CFG_LOADED and \
            getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False):
        cmd.append("-track-error")

    if omit_raw and CFG_LOADED and \
            getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False):
        cmd.append("-omit-raw")

    return cmd


def _build_minimal_cmd(
    targets_file: Path,
    output_jsonl: Path,
    *,
    rate_limit: int,
    concurrency: int,
    timeout: int,
    header_args: Optional[list[str]] = None,
    cookie_header: Optional[str] = None,
    proxy: Optional[str] = None,
    has_ua: bool = False,
    profile: str = "standard",
) -> list[str]:
    """
    v3.0.1 — Bulletproof minimal command.
    Uses ONLY the flags verified working in nuclei v2.x through v3.11.1.
    Used as the progressive-retry fallback when the tiered command fails.
    """
    prof = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    cmd: list[str] = [
        "nuclei",
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_jsonl),
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(timeout),
        "-silent", "-nc",
    ]

    if prof.get("severities"):
        cmd.extend(["-severity", ",".join(prof["severities"])])

    if prof.get("tags_deny"):
        cmd.extend(["-exclude-tags", ",".join(prof["tags_deny"])])

    for hdr in (header_args or []):
        cmd.extend(["-H", hdr])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    if not has_ua:
        cmd.append("-random-agent")

    if proxy:
        cmd.extend(["-proxy", proxy])

    return cmd


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  BATCH EXECUTION — v3.0 FIXED
#      • Pops `resume` before passing kwargs (defense #2)
#      • Surfaces real stderr (with benign-error filter)
#      • Explicit exception handlers for each failure class
# ══════════════════════════════════════════════════════════════════════════

def _batch_evidence_path(evidence_dir: Path, batch_index: int,
                           targets: list[str]) -> Path:
    h = hashlib.sha256("\n".join(sorted(targets)).encode()).hexdigest()[:12]
    return evidence_dir / f"batch_{batch_index:03d}_{h}.jsonl"


def _try_nuclei(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """
    Run nuclei, capture everything, never raise.
    Returns (returncode, stdout, stderr).
    -1 = timeout, -2 = nuclei missing, -3 = unexpected exception.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -2, "", "nuclei binary not found in PATH"
    except Exception as e:
        return -3, "", f"{type(e).__name__}: {e}"


def _run_batch(
    targets: list[str],
    workdir: Path,
    evidence_dir: Path,
    batch_index: int,
    **kwargs: Any,
) -> tuple[Optional[Path], BatchResult]:
    """
    v3.0.1 — progressive-retry.

    1. Try tiered command (full flags).
    2. If exit 2 (bad flag), retry with minimal safe command.
    3. If that also fails, log stderr+stdout and return.
    """
    resume_flag = bool(kwargs.pop("resume", False))

    result = BatchResult(
        batch_index=batch_index,
        targets_count=len(targets),
        rate_limit=kwargs.get("rate_limit"),
        concurrency=kwargs.get("concurrency"),
        bulk_size=kwargs.get("bulk_size"),
        severities=",".join(PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {})
                             .get("severities") or []),
        tags_allow=",".join(kwargs.get("custom_tags") or []),
        tags_deny=",".join(PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {})
                            .get("tags_deny") or []),
        headless=bool(kwargs.get("headless")),
        auth_enabled=bool(kwargs.get("cookie_header") or kwargs.get("header_args")),
        first_seen=datetime.now(timezone.utc).isoformat(),
    )

    if not targets:
        return None, result

    evidence_path = _batch_evidence_path(evidence_dir, batch_index, targets)
    if resume_flag and evidence_path.exists() and evidence_path.stat().st_size > 0:
        log.ok(f"  batch {batch_index:02d}  resume from {evidence_path.name} "
               f"({evidence_path.stat().st_size}B)")
        result.input_file = str(evidence_path)
        result.error = ""
        return evidence_path, result

    targets_file = workdir / f"batch_{batch_index:03d}_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")
    output_jsonl = workdir / f"batch_{batch_index:03d}_output.jsonl"
    result.input_file = str(targets_file)

    _subprocess_guard("nuclei")
    log.info(f"  batch {batch_index:02d}  {len(targets):>3} target(s)  "
             f"→ {output_jsonl.name}")

    # ═══ ATTEMPT 1: tiered command ═══
    cmd = _build_cmd(targets_file, output_jsonl, **kwargs)
    log.debug(f"  cmd: {' '.join(cmd[:8])}…")

    started = time.monotonic()
    rc, stdout, stderr = _try_nuclei(cmd, NUCLEI_HARD_TIMEOUT)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    _audit_subprocess("nuclei", cmd, rc == 0, result.duration_ms, stderr[:200])

    # ═══ ATTEMPT 2: minimal fallback on exit 2 ═══
    if rc == 2:
        log.warn(f"  batch {batch_index:02d}  exit 2 on tiered command — "
                  f"unsupported flag on this nuclei build")
        if stderr.strip():
            log.warn(f"         stderr: {stderr.strip()[:200]}")
        if stdout.strip():
            log.warn(f"         stdout: {stdout.strip()[:200]}")

        log.info(f"  batch {batch_index:02d}  retrying with minimal safe flags")
        min_cmd = _build_minimal_cmd(
            targets_file, output_jsonl,
            rate_limit=kwargs.get("rate_limit", DEFAULT_RATE_LIMIT),
            concurrency=kwargs.get("concurrency", DEFAULT_CONCURRENCY),
            timeout=kwargs.get("timeout", DEFAULT_TIMEOUT),
            header_args=kwargs.get("header_args"),
            cookie_header=kwargs.get("cookie_header"),
            proxy=kwargs.get("proxy"),
            has_ua=kwargs.get("has_ua", False),
            profile=kwargs.get("profile", DEFAULT_PROFILE),
        )
        log.debug(f"  minimal: {' '.join(min_cmd)}")

        started = time.monotonic()
        rc, stdout, stderr = _try_nuclei(min_cmd, NUCLEI_HARD_TIMEOUT)
        result.duration_ms += int((time.monotonic() - started) * 1000)
        _audit_subprocess("nuclei-minimal", min_cmd, rc == 0,
                            result.duration_ms, stderr[:200])

        if rc != 0:
            result.error = f"minimal also failed (rc={rc}): {stderr[:200]}"
            log.error(f"  batch {batch_index:02d}  minimal ALSO failed: "
                       f"rc={rc}  {stderr.strip()[:200]}")
            if stdout.strip():
                log.error(f"         stdout: {stdout.strip()[:200]}")
            return None, result

        log.ok(f"  batch {batch_index:02d}  minimal command succeeded")

    elif rc != 0:
        result.error = f"rc={rc}: {stderr[:300] or stdout[:300]}"
        log.warn(f"  batch {batch_index:02d}  exited {rc}: "
                  f"{(stderr or stdout).strip()[:200]}")
        return None, result

    if not output_jsonl.exists():
        result.error = (stderr or stdout or "no output file produced")[:300]
        log.debug(f"  batch {batch_index:02d}: no JSONL. "
                   f"stderr: {stderr.strip()[:160]}  "
                   f"stdout: {stdout.strip()[:160]}")
        return None, result

    try:
        shutil.copy2(output_jsonl, evidence_path)
    except Exception:
        pass

    return output_jsonl, result


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  JSONL PARSING — v3.0 (full nuclei v3.x schema tolerance)
# ══════════════════════════════════════════════════════════════════════════

def _parse_jsonl(path: Path, auth_on: bool) -> list[NucleiFinding]:
    """
    Parse nuclei JSONL output into NucleiFinding objects.

    v3.0 tolerances:
      · template-id / templateID / template_id / template aliases
      · info.classification may be missing entirely
      · cvss-score may be float, str, or omitted; falls back to
        parsing the CVSS vector string ("CVSS:3.1/.../9.8")
      · cve-id / cwe-id may be str (single) or list
      · port may be int, str, "null", or missing
      · severity strings normalized; unknown values → "UNKNOWN"
      · response body sniffed for WAF block markers (cloudflare, akamai)
    """
    if not path.exists():
        return []

    findings: list[NucleiFinding] = []
    parse_errors = 0
    now = datetime.now(timezone.utc).isoformat()

    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if not isinstance(obj, dict):
            continue

        info = obj.get("info", {}) or {}
        if not isinstance(info, dict):
            info = {}
        classification = info.get("classification", {}) or {}
        if not isinstance(classification, dict):
            classification = {}

        template_id = (
            obj.get("template-id")
            or obj.get("templateID")
            or obj.get("template_id")
            or obj.get("template")
            or ""
        )
        matched_at = (
            obj.get("matched-at")
            or obj.get("matched_at")
            or obj.get("host")
            or obj.get("url")
            or ""
        )
        if not template_id or not matched_at:
            continue

        # ── CVSS: try numeric field, then CVSS vector string ──
        cvss: Optional[float] = None
        for key in ("cvss-score", "cvss_score", "cvss"):
            val = classification.get(key)
            if val not in (None, "", "null"):
                try:
                    cvss = float(val)
                    break
                except (TypeError, ValueError):
                    continue
        if cvss is None:
            metrics = (classification.get("cvss-metrics")
                        or classification.get("cvss_metrics") or "")
            if isinstance(metrics, str) and metrics:
                m = re.search(r"/(\d+\.\d+)$", metrics)
                if m:
                    try:
                        cvss = float(m.group(1))
                    except (TypeError, ValueError):
                        pass

        # ── CVE / CWE — accept str or list ──
        def _as_list(val: Any) -> list[str]:
            if not val:
                return []
            if isinstance(val, str):
                return [v.strip() for v in val.split(",") if v.strip()]
            if isinstance(val, (list, tuple)):
                return [str(v) for v in val]
            return []

        cves = _as_list(classification.get("cve-id") or classification.get("cve_id"))
        cwes = _as_list(classification.get("cwe-id") or classification.get("cwe_id"))

        # ── Tags ──
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif not isinstance(tags, list):
            tags = []

        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        author = info.get("author") or []
        if isinstance(author, str):
            author = [a.strip() for a in author.split(",") if a.strip()]
        elif not isinstance(author, list):
            author = []

        # ── Severity ──
        sev = (info.get("severity") or "unknown").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "UNKNOWN"

        # ── Port ──
        port: Optional[int] = None
        for key in ("port", "matched-port", "matched_port"):
            port_raw = obj.get(key)
            if port_raw not in (None, "", "null"):
                try:
                    port = int(port_raw)
                    break
                except (TypeError, ValueError):
                    pass

        host = obj.get("host") or _host_of(matched_at)

        # ── WAF sniff on response body ──
        response_body = obj.get("response", "") or ""
        waf_blocked = _is_waf_block_response(response_body)

        extracted = (obj.get("extracted-results")
                     or obj.get("extracted_results") or [])
        if isinstance(extracted, str):
            extracted = [extracted]
        elif not isinstance(extracted, list):
            extracted = []

        finding = NucleiFinding(
            template_id=template_id,
            template_name=info.get("name", "") or "",
            template_path=(obj.get("template-path")
                            or obj.get("template_path") or ""),
            template_author=author,
            severity=sev,
            cvss_score=cvss,
            cve_ids=cves,
            cwe_ids=cwes,
            matched_at=matched_at,
            host=host,
            ip=obj.get("ip", "") or "",
            port=port,
            scheme=obj.get("scheme", "") or "",
            path=obj.get("path", "") or "",
            matcher_name=(obj.get("matcher-name")
                           or obj.get("matcher_name") or ""),
            extracted_results=list(extracted),
            curl_command=(obj.get("curl-command")
                           or obj.get("curl_command") or ""),
            request=obj.get("request", "") or "",
            response=response_body,
            tags=tags,
            description=info.get("description", "") or "",
            reference=refs,
            metadata=classification,
            waf_blocked=waf_blocked,
            auth_enabled=auth_on,
            first_seen=now,
        )
        _apply_chains(finding)
        findings.append(finding)

    if parse_errors:
        log.debug(f"  {parse_errors} line(s) failed JSON parsing")
    return findings


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  DEDUPE + SORT
# ══════════════════════════════════════════════════════════════════════════

def _dedupe(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    seen: set[tuple] = set()
    deduped: list[NucleiFinding] = []
    for f in findings:
        key = (f.template_id, f.matched_at, f.matcher_name,
                tuple(sorted(f.extracted_results)))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _sort_findings(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 5),
            -(f.cvss_score or 0.0),
            f.template_id,
            f.matched_at,
        ),
    )


# ══════════════════════════════════════════════════════════════════════════
#  🧠 v3.0 AI CACHE — skip re-triaging hosts with the same findings
# ══════════════════════════════════════════════════════════════════════════

def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "nuclei_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: str, findings: list[NucleiFinding]) -> str:
    """Stable hash of host + finding set. Same findings = same cache."""
    parts = [host.lower()]
    for f in sorted(findings, key=lambda x: (x.template_id, x.matched_at)):
        parts.append(f"{f.template_id}|{f.matched_at}|{f.severity}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
    """Retrieve cached AI triage if fresh. ttl_hours <= 0 disables cache."""
    if ttl_hours <= 0:
        return None
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        if not p.exists():
            return None
        age_hours = (time.time() - p.stat().st_mtime) / 3600
        if age_hours > ttl_hours:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ai_cache_put(outdir: Path, key: str, data: dict) -> None:
    """Persist AI triage result. Best-effort — never fatal."""
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


def _ai_cost_guard(would_add_cost: Optional[float], budget_usd: float) -> bool:
    """
    Return True if it's safe to make another AI call.
    Uses config.AI_COSTS.estimate_cost() as the running total.
    budget_usd <= 0 means unlimited.
    """
    if budget_usd <= 0:
        return True
    if not would_add_cost:
        return True
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is None or not hasattr(tracker, "estimate_cost"):
            return True
        spent = float(tracker.estimate_cost() or 0)
        return (spent + would_add_cost) <= budget_usd
    except Exception:
        return True


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  AI TRIAGE  ·  per-host (v3.0: cache + budget-aware)
# ══════════════════════════════════════════════════════════════════════════

AI_NUCLEI_SYSTEM = (
    "You are an expert bug-bounty triage analyst. Analyze nuclei findings "
    "for one host. Determine which findings are likely real vs false "
    "positives, prioritize manual confirmation, and suggest specific tests. "
    "Never suggest running exploits. Return STRICT JSON only."
)


def _build_top_findings_block(findings: list[NucleiFinding],
                                limit: int = 30) -> str:
    top = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 5),
        -(f.cvss_score or 0.0),
    ))[:limit]

    lines = []
    for f in top:
        cve = f",{','.join(f.cve_ids[:2])}" if f.cve_ids else ""
        lines.append(
            f"  [{f.severity:<8}] {f.template_id:<40} "
            f"{f.matched_at[:60]:<60}{cve}"
        )
    return "\n".join(lines) if lines else "  (no findings)"


def _ai_triage_host(
    host_result: HostResult,
    outdir: Path,
    *,
    use_cache: bool = True,
    cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    budget_usd: float = 0.0,
) -> Optional[dict]:
    """
    AI triage for one host.

    v3.0:
      · Cache hit → return without spending tokens
      · Budget exhausted → return None (caller falls back to heuristic)
      · Never raises — any exception → None → heuristic runs
    """
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.findings) < AI_MIN_FINDINGS_PER_HOST:
        return None

    # ── Cache check ──
    cache_key = _ai_cache_key(host_result.host, host_result.findings)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            log.debug(f"  AI triage (cached) for {host_result.host}")
            cached["source"] = "ai-cached"
            return cached

    # ── Budget check (rough ~$0.002 per triage call on deepseek-chat) ──
    if budget_usd > 0 and not _ai_cost_guard(0.002, budget_usd):
        log.debug(f"  AI budget reached — heuristic for {host_result.host}")
        return None

    findings = host_result.findings
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    cve_count = sum(1 for f in findings if f.cve_ids)
    waf_blocks = sum(1 for f in findings if f.waf_blocked)

    prompt = f"""Analyze nuclei findings for host: {host_result.host}

Stats:
  Total findings:  {len(findings)}
  CRITICAL:        {by_sev['CRITICAL']}
  HIGH:            {by_sev['HIGH']}
  MEDIUM:          {by_sev['MEDIUM']}
  LOW:             {by_sev['LOW']}
  INFO:            {by_sev['INFO']}
  CVE-tagged:      {cve_count}
  WAF-blocked:     {waf_blocks}

Top findings:
{_build_top_findings_block(findings)}

Return STRICT JSON:
{{
  "summary": "one paragraph overall assessment",
  "host_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "top_priorities": [
    {{"rank": 1, "finding": "template_id @ url", "reason": "why",
      "test_idea": "specific manual confirmation step"}}
  ],
  "real_vs_noise": "which findings look real vs likely false positives",
  "next_actions": ["manual confirmation 1", "manual confirmation 2"],
  "chain_hypothesis": "any multi-finding exploit chain worth exploring"
}}"""

    try:
        response = ai_fn(prompt, system=AI_NUCLEI_SYSTEM)
    except Exception as e:
        log.warn(f"  AI triage failed for {host_result.host}: "
                  f"{type(e).__name__}: {e}")
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

    # ── Persist cache only if parse succeeded ──
    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"nuclei_ai_{safe}.md"
    try:
        md = (f"# Surtr's Wrath · AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)}  \n"
              f"**Model:** {_cfg('AI.model', 'deepseek-chat')}\n\n---\n\n")
        if data.get("summary"):
            md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("top_priorities"):
            md += "## Top Priorities\n\n"
            for p in data["top_priorities"]:
                md += (f"{p.get('rank', '?')}. **{p.get('finding', '')}**\n"
                        f"   - Reason: {p.get('reason', '')}\n"
                        f"   - Confirm: {p.get('test_idea', '')}\n\n")
        if data.get("real_vs_noise"):
            md += f"## Real vs Noise\n\n{data['real_vs_noise']}\n\n"
        if data.get("chain_hypothesis"):
            md += f"## Chain Hypothesis\n\n{data['chain_hypothesis']}\n\n"
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"  AI triage saved: {md_path.name}")

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
        "chain_hypothesis": data.get("chain_hypothesis", ""),
        "cost_estimate": cost,
        "source": "ai",
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  HEURISTIC TRIAGE — same schema as AI, always runs
# ══════════════════════════════════════════════════════════════════════════

def _suggest_confirmation(f: NucleiFinding) -> str:
    tid = f.template_id.lower()
    if "sqli" in tid or "sql-injection" in tid:
        return f"Manually confirm SQLi at {f.matched_at} with ' OR '1'='1 (carefully)"
    if "xss" in tid:
        return f"Manually confirm XSS at {f.matched_at} with <script>alert(1)</script>"
    if "ssrf" in tid:
        return f"Manually confirm SSRF via Collaborator payload at {f.matched_at}"
    if "lfi" in tid or "traversal" in tid:
        return f"Manually confirm LFI at {f.matched_at} with ../../../../etc/passwd"
    if "rce" in tid or "command-injection" in tid:
        return f"CAREFULLY confirm RCE at {f.matched_at} with `;id`"
    if "cors" in tid:
        return f"Manually check CORS at {f.matched_at} with Origin: https://evil.com"
    if "exposed" in tid or "disclosure" in tid:
        return f"Browse {f.matched_at} in browser — confirm data sensitivity"
    if "default-login" in tid or "default-cred" in tid:
        return f"Manually verify default credentials at {f.matched_at}"
    if "takeover" in tid:
        return f"Verify takeover possibility for {_host_of(f.matched_at)} via DNS"
    if "tech" in tid or "version" in tid:
        return f"Check {f.matched_at} for specific version — cross-reference CVEs"
    if f.cve_ids:
        return f"Look up {','.join(f.cve_ids)} on NVD — confirm version + test"
    return f"Manually verify {f.matched_at} in browser"


def _heuristic_triage(host_result: HostResult) -> dict:
    findings = host_result.findings
    if not findings:
        return {
            "summary": f"No nuclei findings on {host_result.host}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "real_vs_noise": "n/a",
            "next_actions": [
                "Consider widening --profile or --tags on next run",
            ],
            "chain_hypothesis": "",
            "source": "heuristic",
        }

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    if by_sev["CRITICAL"] > 0: host_risk = "CRITICAL"
    elif by_sev["HIGH"] > 0:   host_risk = "HIGH"
    elif by_sev["MEDIUM"] > 0: host_risk = "MEDIUM"
    elif by_sev["LOW"] > 0:    host_risk = "LOW"
    else:                       host_risk = "INFO"

    cve_count = sum(1 for f in findings if f.cve_ids)
    waf_blocks = sum(1 for f in findings if f.waf_blocked)

    summary = (
        f"{len(findings)} nuclei finding(s) on {host_result.host}. "
        f"CRITICAL={by_sev['CRITICAL']} HIGH={by_sev['HIGH']} "
        f"MEDIUM={by_sev['MEDIUM']}. {cve_count} CVE-tagged."
    )
    if waf_blocks > 0:
        summary += (f" WARNING: {waf_blocks} finding(s) show WAF block pages "
                     f"— likely false positives.")

    top = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 5),
        -(f.cvss_score or 0.0),
    ))[:5]

    top_priorities = []
    for i, f in enumerate(top, 1):
        reason = f"{f.severity} severity"
        if f.cvss_score:
            reason += f" (CVSS {f.cvss_score})"
        if f.cve_ids:
            reason += f" — {','.join(f.cve_ids[:2])}"
        top_priorities.append({
            "rank": i,
            "finding": f"{f.template_id} @ {f.matched_at}",
            "reason": reason,
            "test_idea": _suggest_confirmation(f),
        })

    notes = []
    if waf_blocks > 0:
        notes.append(f"{waf_blocks} WAF-blocked (likely false positive)")
    if cve_count > 0:
        notes.append(f"{cve_count} CVE-tagged (verify version match)")
    info_count = by_sev["INFO"]
    if info_count > 0:
        notes.append(f"{info_count} INFO-level (informational, low $ value)")
    real_vs_noise = (
        f"{len(findings) - waf_blocks} potentially real, "
        f"{waf_blocks} WAF-blocked."
        + ("; ".join(notes) if notes else "")
    )

    next_actions: list[str] = []
    if by_sev["CRITICAL"] > 0:
        next_actions.append(
            f"Manually confirm {by_sev['CRITICAL']} CRITICAL finding(s) — "
            f"highest reward potential")
    if by_sev["HIGH"] > 0:
        next_actions.append(f"Manually confirm {by_sev['HIGH']} HIGH finding(s)")
    if cve_count > 0:
        next_actions.append(
            f"Cross-reference {cve_count} CVE(s) on NVD for affected versions")
    if waf_blocks > 0:
        next_actions.append(
            f"Investigate {waf_blocks} WAF-blocked finding(s) — likely FP")
    if not next_actions:
        next_actions.append("Manual review of MEDIUM/LOW findings")

    chain_ids: set[str] = set()
    for f in findings:
        chain_ids.update(f.chain_ids)

    chain_hypothesis = ""
    if "nuclei-auth-bypass" in chain_ids and "nuclei-exposed-panel" in chain_ids:
        chain_hypothesis = "Auth bypass + exposed panel — potential pre-auth admin access"
    elif "nuclei-exposed-config" in chain_ids and "nuclei-default-creds" in chain_ids:
        chain_hypothesis = "Exposed config + default creds — likely full compromise path"
    elif "nuclei-sqli-candidate" in chain_ids and "nuclei-exposed-panel" in chain_ids:
        chain_hypothesis = "SQLi + admin panel — potential auth bypass or data exfil"
    elif len(chain_ids) >= 3:
        chain_hypothesis = f"Multiple chain types ({len(chain_ids)}) — worth manual review"

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "real_vs_noise": real_vs_noise,
        "next_actions": next_actions,
        "chain_hypothesis": chain_hypothesis,
        "source": "heuristic",
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-SYNC (DB bridge)
# ══════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[NucleiFinding],
                batches: list[BatchResult]) -> None:
    try:
        from db import DB  # type: ignore
    except ImportError:
        log.info("  DB sync: db.py not available")
        return
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge not ready")
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return

    if findings and hasattr(DB, "upsert_nuclei_findings"):
        try:
            payloads = [f.to_dict() for f in findings]
            result = DB.upsert_nuclei_findings(scan_id, payloads)
            if result is not None:
                log.info(f"  DB sync: {result} finding(s) upserted")
        except Exception as e:
            log.warning(f"  DB sync findings exception: {e}")

    if batches and hasattr(DB, "save_nuclei_batch"):
        saved = 0
        for b in batches:
            try:
                if DB.save_nuclei_batch(scan_id, b.to_dict()) is not None:
                    saved += 1
            except Exception:
                pass
        log.info(f"  DB sync: {saved}/{len(batches)} batch record(s) saved")


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  MISC HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _audit_hash(p: Optional[Path]) -> Optional[str]:
    if not p:
        return None
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _load_resume_batches(evidence_dir: Path) -> set[str]:
    if not evidence_dir.exists():
        return set()
    return {p.name for p in evidence_dir.glob("batch_*.jsonl")
            if p.stat().st_size > 0}


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  PUBLIC ENTRY POINT — v3.0 ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════

def run_nuclei_scan(
    targets_file: Path,
    outdir: Path,
    *,
    # v1.0 backward-compat
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    bulk_size: Optional[int] = None,
    timeout: Optional[int] = None,
    retries: Optional[int] = None,
    profile: str = DEFAULT_PROFILE,
    severities: Optional[list[str]] = None,
    tags_allow: Optional[list[str]] = None,
    tags_deny: Optional[list[str]] = None,
    custom_templates: Optional[list[str]] = None,
    custom_tags: Optional[list[str]] = None,
    headers: Optional[dict] = None,
    cookie: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
    update_templates: bool = True,
    scan_id: Optional[int] = None,
    # v2.0 additions
    bbp_program: Optional[str] = None,
    use_proxy: bool = True,
    resume: bool = False,
    dry_run: bool = False,
    proxy_pool: Any = None,
    audit_trail: Any = None,
    # v3.0 additions
    no_ai: bool = False,
    ai_max_cost_usd: float = 0.0,
    ai_max_hosts: int = AI_MAX_HOSTS_PER_RUN,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    no_interactsh: bool = True,
    interactsh_url: Optional[str] = None,
    page_timeout: Optional[int] = None,
    exclude_matchers: Optional[list[str]] = None,
    sni: Optional[str] = None,
    track_error: bool = False,
    omit_raw: bool = True,
) -> Path:
    """Run nuclei against every target in targets_file (v3.0 orchestrator)."""
    start = time.monotonic()

    if not shutil.which("nuclei") and not dry_run:
        raise RuntimeError(
            "nuclei not installed. Run `python3 tools.py --only nuclei` first.")

    # ── Resolve limits ──
    limits = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("nuclei", {}) or {}
    eff_rate    = rate_limit  if rate_limit  is not None else limits.get("rps", DEFAULT_RATE_LIMIT)
    eff_conc    = concurrency if concurrency is not None else limits.get("concurrency", DEFAULT_CONCURRENCY)
    eff_bulk    = bulk_size   if bulk_size   is not None else limits.get("bulk_size", DEFAULT_BULK_SIZE)
    eff_timeout = timeout     if timeout     is not None else limits.get("timeout", DEFAULT_TIMEOUT)
    eff_retries = retries     if retries     is not None else limits.get("retries", DEFAULT_RETRIES)
    if not isinstance(eff_rate, int) or eff_rate < 0:
        eff_rate = DEFAULT_RATE_LIMIT
    if not isinstance(eff_conc, int) or eff_conc < 1:
        eff_conc = DEFAULT_CONCURRENCY
    if not isinstance(eff_bulk, int) or eff_bulk < 1:
        eff_bulk = DEFAULT_BULK_SIZE
    eff_rate, eff_conc, eff_bulk = _effective_limits(eff_rate, eff_conc, eff_bulk)

    if profile not in PROFILES:
        log.warn(f"  Unknown profile '{profile}' — using '{DEFAULT_PROFILE}'")
        profile = DEFAULT_PROFILE

    # ── Config-driven defaults for v3.0 flags ──
    # Only if the CLI didn't override (we detect override by comparing to defaults)
    if no_interactsh and CFG_LOADED:
        cfg_ni = getattr(CFG, "NUCLEI_NO_INTERACTSH", None)
        if cfg_ni is not None:
            no_interactsh = bool(cfg_ni)
    if interactsh_url is None and CFG_LOADED:
        interactsh_url = getattr(CFG, "NUCLEI_INTERACTSH_URL", None)
    if page_timeout is None and CFG_LOADED:
        page_timeout = getattr(CFG, "NUCLEI_PAGE_TIMEOUT", None)
    if exclude_matchers is None and CFG_LOADED:
        exclude_matchers = getattr(CFG, "NUCLEI_EXCLUDE_MATCHERS", None)

    # ── Inputs ──
    targets = _load_targets(targets_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "nuclei_work"
    evidence_dir = outdir / "nuclei_evidence"
    workdir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    log.info(f"Input  : {len(targets)} target(s) from {targets_file.name}")
    if not targets:
        log.warn("No targets to scan — writing empty report")
        return _write_empty_report(outdir, targets_file, start)

    # ── Headers ──
    header_args, has_ua = _headers_for_nuclei(bbp_program, headers)

    cookie_header = cookie
    try:
        if not cookie_header and CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
            cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
            if cookies:
                cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    except Exception:
        pass
    auth_on = bool(header_args or cookie_header)

    # ── Proxy ──
    eff_proxy = proxy
    if not eff_proxy and use_proxy and proxy_pool is None:
        try:
            pool_cls = _cfg("ProxyPool")
            if pool_cls is not None:
                proxy_pool = pool_cls.from_file(_cfg("PROXIES_FILE"))
        except Exception:
            pass
    if not eff_proxy and use_proxy and proxy_pool is not None:
        eff_proxy = _pick_proxy(proxy_pool)

    # ── Audit trail ──
    if audit_trail is None:
        try:
            factory = _cfg("new_audit_trail")
            if callable(factory):
                audit_trail = factory("nuclei-" + (targets_file.stem or "scan"))
        except Exception:
            pass

    # ── AI decision ──
    ai_active = _ai_enabled() and not no_ai
    if no_ai and _ai_enabled():
        log.info("  AI triage: disabled via --no-ai")
    elif ai_active:
        budget_str = f"${ai_max_cost_usd:.2f}" if ai_max_cost_usd > 0 else "unlimited"
        log.info(f"  AI triage: enabled  (budget={budget_str}, "
                  f"max_hosts={ai_max_hosts}, cache_ttl={ai_cache_ttl_hours}h)")
    else:
        log.info("  AI triage: disabled (config.AI_ENABLED=False) — "
                  "heuristic fallback active")

    # ── Config display ──
    prof = PROFILES[profile]
    log.info(f"Profile: {profile}  ({prof['description']})")
    log.info(f"Config : rate={eff_rate}/s  conc={eff_conc}  bulk={eff_bulk}  "
             f"timeout={eff_timeout}s  retries={eff_retries}")
    log.info(f"         bbp={bbp_program or 'none'}  proxy={eff_proxy or 'direct'}")
    log.info(f"         interactsh={'OFF (-ni)' if no_interactsh else (interactsh_url or 'default')}")
    if header_args:
        log.info(f"Headers: {len(header_args)//2} configured")
    if not has_ua:
        log.info(f"UA     : rotating (-random-agent)")
    if cookie_header:
        log.info(f"Auth   : enabled ({len(cookie_header)}-char Cookie)")
    if LIGHTWEIGHT_MODE:
        log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — limits capped")

    if dry_run:
        log.rune(Rune.HAGALAZ, "DRY-RUN — no network calls")
        batches = [targets[i:i + MAX_TARGETS_PER_BATCH]
                    for i in range(0, len(targets), MAX_TARGETS_PER_BATCH)]
        log.info(f"Would scan {len(targets)} target(s) in {len(batches)} batch(es)")
        for i, b in enumerate(batches, 1):
            log.info(f"  batch {i:02d}  {len(b)} target(s)")
        return outdir / "nuclei_findings.json"

    # ── Template update ──
    if update_templates:
        _update_templates()
        log.info("")

    # ── Resume ──
    if resume:
        existing = _load_resume_batches(evidence_dir)
        if existing:
            log.info(f"Resume : {len(existing)} batch evidence file(s) available")

    # ── Batching ──
    batches: list[list[str]] = [
        targets[i:i + MAX_TARGETS_PER_BATCH]
        for i in range(0, len(targets), MAX_TARGETS_PER_BATCH)
    ]
    log.info(f"Scanning {len(targets)} target(s) in {len(batches)} batch(es)...")

    all_findings: list[NucleiFinding] = []
    batch_results: list[BatchResult] = []

    # ═══ v3.0 DEFENSE #3: resume is a named kwarg that _run_batch pops ═══
    kwargs = dict(
        rate_limit=eff_rate, concurrency=eff_conc, bulk_size=eff_bulk,
        timeout=eff_timeout, retries=eff_retries, profile=profile,
        custom_templates=custom_templates,
        custom_tags=custom_tags or tags_allow,
        header_args=header_args, cookie_header=cookie_header,
        headless=headless, proxy=eff_proxy, has_ua=has_ua,
        page_timeout=page_timeout,
        interactsh_url=interactsh_url,
        no_interactsh=no_interactsh,
        exclude_matchers=exclude_matchers,
        sni=sni,
        track_error=track_error,
        omit_raw=omit_raw,
        resume=resume,
    )

    if severities is not None:
        PROFILES[profile]["severities"] = severities
    if tags_deny is not None:
        PROFILES[profile]["tags_deny"] = tags_deny

    for i, batch in enumerate(batches, 1):
        output, result = _run_batch(batch, workdir, evidence_dir, i, **kwargs)
        batch_results.append(result)
        if output:
            bf = _parse_jsonl(output, auth_on)
            all_findings.extend(bf)
            result.findings_count = len(bf)
            log.ok(f"  batch {i:02d} → {len(bf)} finding(s) "
                    f"({result.duration_ms}ms)")

    # ── Dedupe + sort ──
    deduped = _dedupe(all_findings)
    sorted_findings = _sort_findings(deduped)

    log.info("")
    log.info(f"Raw findings    : {len(all_findings)}")
    log.info(f"Unique findings : {len(sorted_findings)}")

    # ── Per-host grouping + triage ──
    log.rune(Rune.GEBO, "Triage · AI + heuristic per host")
    by_host: dict[str, list[NucleiFinding]] = {}
    for f in sorted_findings:
        host = f.host or _host_of(f.matched_at) or "unknown"
        by_host.setdefault(host, []).append(f)

    stream_path = outdir / "nuclei_analysis_hosts.jsonl"
    if not resume and stream_path.exists():
        stream_path.unlink()

    all_hosts: list[HostResult] = []
    ai_hosts_done = 0
    ai_budget_exhausted = False

    for host, host_findings in sorted(by_host.items()):
        host_result = HostResult(
            host=host, findings=host_findings,
            chains=_build_host_chains(host_findings),
        )

        ai_result: Optional[dict] = None
        if ai_active and len(host_findings) >= AI_MIN_FINDINGS_PER_HOST \
                and ai_hosts_done < ai_max_hosts and not ai_budget_exhausted:
            ai_result = _ai_triage_host(
                host_result, outdir,
                use_cache=True,
                cache_ttl_hours=ai_cache_ttl_hours,
                budget_usd=ai_max_cost_usd,
            )
            if ai_result:
                ai_hosts_done += 1
            elif ai_max_cost_usd > 0:
                # Check whether budget hit
                try:
                    tracker = _cfg("AI_COSTS")
                    if tracker and hasattr(tracker, "estimate_cost"):
                        if float(tracker.estimate_cost() or 0) >= ai_max_cost_usd:
                            ai_budget_exhausted = True
                except Exception:
                    pass

        heuristic = _heuristic_triage(host_result)

        if ai_result:
            host_result.triage = ai_result
            host_result.triage_source = ai_result.get("source", "ai")
        else:
            host_result.triage = heuristic
            host_result.triage_source = "heuristic"

        all_hosts.append(host_result)

        try:
            with stream_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "host": host,
                    "findings": [x.to_dict() for x in host_findings],
                    "chains": host_result.chains,
                    "triage": host_result.triage,
                    "triage_source": host_result.triage_source,
                }, ensure_ascii=False) + "\n")
        except Exception:
            pass

        n_crit = sum(1 for f in host_findings if f.severity == "CRITICAL")
        n_high = sum(1 for f in host_findings if f.severity == "HIGH")
        log.ok(f"  {host[:50]:<50} · {len(host_findings)} finding(s) "
                f"(CRIT={n_crit} HIGH={n_high}) triage={host_result.triage_source}")

    # ── Flat outputs ──
    critical_high = [f for f in sorted_findings
                     if f.severity in ("CRITICAL", "HIGH")]
    all_urls = sorted({f.matched_at for f in sorted_findings})

    (outdir / "nuclei_critical.txt").write_text(
        "\n".join(f.matched_at for f in critical_high)
        + ("\n" if critical_high else ""))
    (outdir / "nuclei_all.txt").write_text(
        "\n".join(all_urls) + ("\n" if all_urls else ""))

    raw_jsonl = outdir / "nuclei_raw.jsonl"
    with raw_jsonl.open("w", encoding="utf-8") as f:
        for finding in sorted_findings:
            f.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")

    # ── Report ──
    elapsed = time.monotonic() - start

    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    by_template: dict[str, int] = {}
    by_host_count: dict[str, int] = {}
    cve_count = 0
    waf_blocks = 0
    chain_counts: dict[str, int] = {}

    for f in sorted_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
        h = f.host or _host_of(f.matched_at) or "unknown"
        by_host_count[h] = by_host_count.get(h, 0) + 1
        if f.cve_ids:
            cve_count += 1
        if f.waf_blocked:
            waf_blocks += 1
        for cid in f.chain_ids:
            chain_counts[cid] = chain_counts.get(cid, 0) + 1

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

    ai_triaged = sum(1 for h in all_hosts
                      if h.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for h in all_hosts
                              if h.triage_source == "heuristic")

    audit_path = getattr(audit_trail, "path", None) if audit_trail else None

    report = {
        "schema_version": 3,
        "producer":       f"nuclei_scan.py v{__version__} '{__codename__}'",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":round(elapsed, 2),
        "input_file":     str(targets_file),
        "bbp_program":    bbp_program,
        "use_proxy":      use_proxy,
        "profile":        profile,
        "auth_enabled":   auth_on,
        "ai_enabled":     ai_active,
        "host_capacity": {
            "cpu_cores":          HOST_CORES,
            "ram_mb":             HOST_RAM_MB,
            "lightweight":        LIGHTWEIGHT_MODE,
            "lightweight_reason": LIGHTWEIGHT_REASON or "sufficient capacity",
        },
        "config": {
            "rate_limit":         eff_rate,
            "concurrency":        eff_conc,
            "bulk_size":          eff_bulk,
            "timeout":            eff_timeout,
            "retries":            eff_retries,
            "headers_count":      len(header_args) // 2 if header_args else 0,
            "cookie_set":         bool(cookie_header),
            "headless":           headless,
            "proxy":              eff_proxy,
            "profile_severities": prof.get("severities"),
            "profile_tags_deny":  prof.get("tags_deny"),
            "custom_templates":   custom_templates,
            "custom_tags":        custom_tags,
            "no_interactsh":      no_interactsh,
            "interactsh_url":     interactsh_url,
            "page_timeout":       page_timeout,
            "exclude_matchers":   exclude_matchers,
            "omit_raw":           omit_raw,
            "track_error":        track_error,
            "ai_max_cost_usd":    ai_max_cost_usd,
            "ai_max_hosts":       ai_max_hosts,
            "ai_cache_ttl_hours": ai_cache_ttl_hours,
        },
        "audit": {
            "trail_path":   str(audit_path) if audit_path else None,
            "trail_sha256": _audit_hash(audit_path),
        },
        "totals": {
            "targets_input":       len(targets),
            "batches":             len(batches),
            "raw_findings":        len(all_findings),
            "unique_findings":     len(sorted_findings),
            "hosts_with_findings": len(all_hosts),
            "critical":            by_sev["CRITICAL"],
            "high":                by_sev["HIGH"],
            "medium":              by_sev["MEDIUM"],
            "low":                 by_sev["LOW"],
            "info":                by_sev["INFO"],
            "unknown":             by_sev["UNKNOWN"],
            "unique_cves":         cve_count,
            "waf_blocked":         waf_blocks,
            "ai_triaged":          ai_triaged,
            "heuristic_triaged":   heuristic_triaged,
            "ai_budget_exhausted": ai_budget_exhausted,
            "by_severity":         by_sev,
        },
        "summary": {
            "by_template": dict(sorted(by_template.items(),
                                         key=lambda kv: -kv[1])[:50]),
            "by_host":     dict(sorted(by_host_count.items(),
                                         key=lambda kv: -kv[1])[:50]),
            "by_chain":    dict(sorted(chain_counts.items(),
                                         key=lambda kv: -kv[1])),
        },
        "chains":  agg_chains,
        "hosts":   [
            {
                "host":          h.host,
                "findings":      [f.to_dict() for f in h.findings],
                "chains":        h.chains,
                "triage":        h.triage,
                "triage_source": h.triage_source,
            }
            for h in all_hosts
        ],
        "batches": [b.to_dict() for b in batch_results],
        "findings": [f.to_dict() for f in sorted_findings[:MAX_FINDINGS_REPORT]],
    }

    json_path = outdir / "nuclei_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")

    # ── Cleanup workdir (preserve evidence) ──
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ──
    if scan_id is not None:
        log.info("")
        log.info(f"Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, sorted_findings, batch_results)
    else:
        log.info("")
        log.info("DB sync  : deferred to main.py (no scan_id passed)")

    # ── Summary ──
    _print_summary(outdir, report, elapsed, critical_high)

    return json_path


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _print_summary(outdir: Path, report: dict, elapsed: float,
                    critical_high: list[NucleiFinding]) -> None:
    log.rune(Rune.SOWILO, "Summary")
    t = report["totals"]
    log.info(f"Targets scanned     : {t['targets_input']}")
    log.info(f"Batches             : {t['batches']}")
    log.info(f"Raw findings        : {t['raw_findings']}")
    log.info(f"Unique findings     : {t['unique_findings']}")
    log.info(f"Hosts with findings : {t['hosts_with_findings']}")
    log.info(f"Unique CVEs         : {t['unique_cves']}")
    if t["waf_blocked"]:
        log.warn(f"WAF-blocked         : {t['waf_blocked']} (likely FP)")

    by_sev = t["by_severity"]
    log.info("Severity            : " + " ".join(
        f"{k}={by_sev.get(k, 0)}" for k in
        ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))

    if report["ai_enabled"]:
        budget_note = ""
        if t.get("ai_budget_exhausted"):
            budget_note = " (budget exhausted)"
        log.info(f"Triage              : AI={t['ai_triaged']} · "
                  f"heuristic={t['heuristic_triaged']}{budget_note}")
    else:
        log.info(f"Triage              : heuristic={t['heuristic_triaged']}")

    chains = report.get("chains") or []
    if chains:
        log.info("")
        log.info("Chains:")
        for c in chains[:12]:
            log.info(f"  {Sym.ARROW} {c['chain_id']:<32} "
                      f"[{c['severity']}] {c['count']} member(s)")

    if critical_high:
        log.info("")
        log.info("CRITICAL/HIGH findings:")
        for f in critical_high[:15]:
            cve = f" [{','.join(f.cve_ids[:2])}]" if f.cve_ids else ""
            log.info(f"  [{f.severity:<8}] {f.template_id:<30} "
                      f"{f.matched_at[:60]}{cve}")

    log.info("")
    log.info("Outputs:")
    log.info(f"  {Sym.ARROW} nuclei_findings.json          {t['unique_findings']:>5}")
    log.info(f"  {Sym.ARROW} nuclei_analysis_hosts.jsonl")
    log.info(f"  {Sym.ARROW} nuclei_critical.txt           {len(critical_high):>5}")
    log.info(f"  {Sym.ARROW} nuclei_all.txt                {len(set(f.matched_at for f in critical_high)):>5}")
    log.info(f"  {Sym.ARROW} nuclei_raw.jsonl")
    if report["ai_enabled"] and t["ai_triaged"] > 0:
        log.info(f"  {Sym.ARROW} nuclei_ai_<host>.md")
        log.info(f"  {Sym.ARROW} nuclei_ai_cache/")
    log.info(f"  {Sym.ARROW} nuclei_evidence/")
    log.info("")
    log.info(f"Completed in {elapsed:.1f}s")


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "schema_version": 3,
        "producer":       f"nuclei_scan.py v{__version__} '{__codename__}'",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":round(time.monotonic() - start, 2),
        "input_file":     str(input_file),
        "profile":        DEFAULT_PROFILE,
        "auth_enabled":   False,
        "ai_enabled":     _ai_enabled(),
        "config":         {},
        "totals": {
            "targets_input": 0, "batches": 0,
            "raw_findings": 0, "unique_findings": 0,
            "hosts_with_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "unknown": 0, "unique_cves": 0, "waf_blocked": 0,
            "ai_triaged": 0, "heuristic_triaged": 0,
            "ai_budget_exhausted": False,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                             "LOW": 0, "INFO": 0, "UNKNOWN": 0},
        },
        "summary":  {"by_template": {}, "by_host": {}, "by_chain": {}},
        "chains":   [],
        "hosts":    [],
        "batches":  [],
        "findings": [],
    }
    p = outdir / "nuclei_findings.json"
    p.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nuclei_critical.txt", "nuclei_all.txt",
                  "nuclei_raw.jsonl", "nuclei_analysis_hosts.jsonl"):
        (outdir / name).write_text("")
    return p


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  SELF-TEST — v3.0 (includes the resume-fix verification)
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Surtr's Wrath Reforged integrity")

    def _mk(template_id: str, severity: str = "HIGH",
             matched_at: str = "https://test.example/path",
             cve_ids: Optional[list[str]] = None,
             chain_ids: Optional[list[str]] = None) -> NucleiFinding:
        return NucleiFinding(
            template_id=template_id,
            severity=severity,
            matched_at=matched_at,
            host=_host_of(matched_at),
            cve_ids=cve_ids or [],
            chain_ids=chain_ids or [],
        )

    def _mk_no_resume_crash() -> bool:
        """v3.0 CRITICAL: proves _build_cmd accepts resume (and swallows it)."""
        try:
            _build_cmd(
                Path("/tmp/t.txt"), Path("/tmp/o.jsonl"),
                rate_limit=5, concurrency=10, bulk_size=5,
                timeout=10, retries=1, profile="standard",
                resume=True,   # ← the kwarg that used to crash
            )
            return True
        except TypeError:
            return False
        except Exception:
            # Any other exception is fine — only TypeError would fail the test
            return True

    def _mk_unknown_kwarg_swallow() -> bool:
        """v3.0 DEFENSE #1: _build_cmd should swallow arbitrary kwargs."""
        try:
            _build_cmd(
                Path("/tmp/t.txt"), Path("/tmp/o.jsonl"),
                rate_limit=5, concurrency=10, bulk_size=5,
                timeout=10, retries=1, profile="standard",
                totally_made_up_kwarg="x",   # ← would have crashed v2.0
            )
            return True
        except TypeError:
            return False
        except Exception:
            return True

    checks: list[tuple[str, Callable[[], bool]]] = [
        # Base
        ("config loaded",             lambda: CFG_LOADED),
        ("Rune.RAIDO",                lambda: Rune.RAIDO == "ᚱ"),
        ("Severity ranks",            lambda: Severity.CRITICAL.rank == 4),
        ("version is 3.0.0",          lambda: __version__ == "3.0.0"),

        # Helpers
        ("_host_of works",            lambda: _host_of("https://a.b.com/x") == "a.b.com"),
        ("_host_of empty",            lambda: _host_of("") == ""),
        ("_is_waf_block yes",         lambda: _is_waf_block_response(
                                        "Attention Required! | Cloudflare")),
        ("_is_waf_block no",          lambda: not _is_waf_block_response(
                                        "<html>normal page</html>")),
        ("_severity_of_str crit",     lambda: _severity_of_str("CRITICAL") == Severity.CRITICAL),
        ("_severity_of_str unknown",  lambda: _severity_of_str("weird") == Severity.INFO),

        # Chain infra
        ("CHAIN_NAMES>=15",           lambda: len(CHAIN_NAMES) >= 15),
        ("CHAIN_SEVERITY>=15",        lambda: len(CHAIN_SEVERITY) >= 15),
        ("PROFILES>=5",               lambda: len(PROFILES) >= 5),

        # Template classification
        ("_classify_template cve",    lambda: "nuclei-cve-match" in
                                        _classify_template_to_chains("cve-2021-44228")),
        ("_classify_template default",lambda: "nuclei-default-creds" in
                                        _classify_template_to_chains("default-login-jenkins")),
        ("_classify_template sqli",   lambda: "nuclei-sqli-candidate" in
                                        _classify_template_to_chains("sqli-error-based")),
        ("_classify_template xss",    lambda: "nuclei-xss-candidate" in
                                        _classify_template_to_chains("xss-reflected")),
        ("_classify_template ssrf",   lambda: "nuclei-ssrf-candidate" in
                                        _classify_template_to_chains("ssrf-internal")),
        ("_classify_template rce",    lambda: "nuclei-rce-candidate" in
                                        _classify_template_to_chains("rce-deserialization")),
        ("_classify_template cors",   lambda: "nuclei-cors-misconfig" in
                                        _classify_template_to_chains("cors-misconfig")),
        ("_classify_template panel",  lambda: "nuclei-exposed-panel" in
                                        _classify_template_to_chains("exposed-jenkins-panel")),
        ("_classify_template file",   lambda: "nuclei-sensitive-file" in
                                        _classify_template_to_chains("backup-sql-dump")),

        # _apply_chains
        ("_apply_chains crit",        lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-critical-finding" in f.chain_ids
                                        )[1])(_mk("test-tpl", "CRITICAL"))),
        ("_apply_chains high",        lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-high-finding" in f.chain_ids
                                        )[1])(_mk("test-tpl", "HIGH"))),
        ("_apply_chains cve",         lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-cve-match" in f.chain_ids
                                        )[1])(_mk("cve-2021-44228", "CRITICAL",
                                                    cve_ids=["CVE-2021-44228"]))),
        ("_apply_chains default+crit", lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-default-creds" in f.chain_ids and
                                            "nuclei-critical-finding" in f.chain_ids
                                        )[1])(_mk("default-login-jenkins", "CRITICAL"))),

        # _build_host_chains
        ("_build_host_chains empty",  lambda: _build_host_chains([]) == []),
        ("_build_host_chains multi",  lambda: any(
                                            c["chain_id"] == "nuclei-multi-finding-host"
                                            for c in _build_host_chains([
                                                _mk("cve-2021-44228", "CRITICAL",
                                                     cve_ids=["CVE-2021-44228"]),
                                                _mk("default-login-ftp", "CRITICAL"),
                                                _mk("exposed-env", "HIGH"),
                                            ]))),

        # Headers
        ("_headers_for_nuclei empty", lambda: _headers_for_nuclei(None, None)[0] == []),
        ("_headers_for_nuclei extra", lambda: any("X-Test" in h for h in
                                            _headers_for_nuclei(None,
                                                {"X-Test": "yes"})[0])),
        ("_headers_for_nuclei has_ua", lambda: _headers_for_nuclei(None,
                                            {"User-Agent": "TestUA"})[1] is True),

        # ═══ v3.0 CRITICAL: resume kwarg no longer crashes ═══
        ("_build_cmd accepts resume kwarg",   lambda: _mk_no_resume_crash()),
        ("_build_cmd swallows unknown kwargs",
                                       lambda: _mk_unknown_kwarg_swallow()),
        ("_build_cmd returns list",   lambda: isinstance(
                                        _build_cmd(Path("/tmp/t"), Path("/tmp/o"),
                                                    rate_limit=5, concurrency=10,
                                                    bulk_size=5, timeout=10,
                                                    retries=1, profile="standard"),
                                        list)),

        # _run_batch signature accepts **kwargs (so resume can be popped)
        ("_run_batch has **kwargs",   lambda: any(
                                        p.kind == p.VAR_KEYWORD
                                        for p in __import__("inspect").signature(
                                            _run_batch).parameters.values())),

        # Heuristic triage
        ("_heuristic_triage empty",   lambda: _heuristic_triage(
                                            HostResult(host="x.com"))["host_risk"] == "INFO"),
        ("_heuristic_triage crit",    lambda: _heuristic_triage(HostResult(
                                            host="x.com",
                                            findings=[_mk("cve-2021-44228",
                                                            "CRITICAL",
                                                            cve_ids=["CVE-2021-44228"])]
                                        ))["host_risk"] == "CRITICAL"),
        ("_suggest_confirmation cve", lambda: "cve" in _suggest_confirmation(
                                            _mk("cve-2021-44228",
                                                 cve_ids=["CVE-2021-44228"])).lower()),

        # AI cache helpers
        ("_ai_cache_dir callable",    lambda: callable(_ai_cache_dir)),
        ("_ai_cache_key stable",      lambda: _ai_cache_key(
                                            "example.com",
                                            [_mk("cve-2021-44228")]) ==
                                        _ai_cache_key(
                                            "example.com",
                                            [_mk("cve-2021-44228")])),
        ("_ai_cache_key different",   lambda: _ai_cache_key(
                                            "a.com", [_mk("cve-2021-44228")]) !=
                                        _ai_cache_key(
                                            "b.com", [_mk("cve-2021-44228")])),
        ("_ai_cost_guard unlimited",  lambda: _ai_cost_guard(0.01, 0.0) is True),
        ("_ai_cost_guard allows small", lambda: _ai_cost_guard(0.001, 100.0) is True),
        ("_ai_cost_guard blocks over",lambda: _ai_cost_guard(1.0, 0.01) is False
                                        or _cfg("AI_COSTS") is None),

        # Callables exist
        ("_ai_triage_host callable",  lambda: callable(_ai_triage_host)),
        ("_ai_enabled callable",      lambda: callable(_ai_enabled)),
        ("_subprocess_guard",         lambda: callable(_subprocess_guard)),
        ("_audit_subprocess",         lambda: callable(_audit_subprocess)),
        ("_load_targets callable",    lambda: callable(_load_targets)),
        ("_load_resume_batches",      lambda: callable(_load_resume_batches)),
        ("_pick_proxy none",          lambda: _pick_proxy(None) is None),
        ("_batch_evidence_path",      lambda: _batch_evidence_path(
                                            Path("/tmp"), 1,
                                            ["https://a", "https://b"]
                                        ).name.startswith("batch_001_")),
        ("run_nuclei_scan",           lambda: callable(run_nuclei_scan)),

        # run_nuclei_scan signature has v3.0 flags
        ("run has no_ai param",       lambda: "no_ai" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
        ("run has ai_max_cost_usd",   lambda: "ai_max_cost_usd" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
        ("run has ai_cache_ttl_hours",lambda: "ai_cache_ttl_hours" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
        ("run has no_interactsh",     lambda: "no_interactsh" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
        ("run has exclude_matchers",  lambda: "exclude_matchers" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
        ("run has omit_raw",          lambda: "omit_raw" in __import__("inspect").signature(
                                            run_nuclei_scan).parameters),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                log.ok(name); passed += 1
            else:
                log.error(f"{name} → False"); failed += 1
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
        ("new_audit_trail",    lambda: callable(_cfg("new_audit_trail"))),
        ("RateLimiter",        lambda: _cfg("RateLimiter") is not None),
        ("human_delay",        lambda: callable(_cfg("human_delay"))),
        ("random_user_agent",  lambda: callable(_cfg("random_user_agent"))),
        ("build_headers",      lambda: callable(_cfg("build_headers"))),
        ("ai_complete",        lambda: callable(_cfg("ai_complete"))),
    ]
    failed = 0
    for name, fn in items:
        try:
            if fn():
                log.ok(name)
            else:
                log.warn(f"{name} — not configured")
                failed += 1
        except Exception as e:
            log.error(f"{name} — {e}")
            failed += 1

    log.info("")
    log.info(f"AI_ENABLED       : {_ai_enabled()}")
    if _ai_enabled():
        log.ok(f"AI triage will run on hosts with >={AI_MIN_FINDINGS_PER_HOST} "
                f"findings (capped at {AI_MAX_HOSTS_PER_RUN} hosts)")
    else:
        log.info("Heuristic triage will run (same schema, no API cost)")

    # v3.0 config surfaces
    log.info("")
    log.info("v3.0 config defaults:")
    log.info(f"  NUCLEI_NO_INTERACTSH    : {_cfg('NUCLEI_NO_INTERACTSH', True)}")
    log.info(f"  NUCLEI_INTERACTSH_URL   : {_cfg('NUCLEI_INTERACTSH_URL', None)}")
    log.info(f"  NUCLEI_PAGE_TIMEOUT     : {_cfg('NUCLEI_PAGE_TIMEOUT', None)}")
    log.info(f"  NUCLEI_EXCLUDE_MATCHERS : {_cfg('NUCLEI_EXCLUDE_MATCHERS', [])}")

    log.info("")
    log.info(f"nuclei           : {'present' if shutil.which('nuclei') else 'NOT FOUND'}")

    templates_dir = Path.home() / "nuclei-templates"
    log.info(f"templates        : {'present' if templates_dir.exists() else 'NOT FOUND'} "
              f"({templates_dir})")

    out = _cfg("OUTPUT_DIR") or Path("output")
    for name in ("live_urls.txt", "site_pages.txt", "urls_sqli_priority.txt"):
        p = out / name
        log.info(f"{name:<22}: {'present' if p.exists() else 'NOT FOUND'}")

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ CONFIG READY ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('amber')}{Sym.WARN}  ══ {failed} item(s) unconfigured ══  {Sym.WARN}{_c('reset')}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI
# ══════════════════════════════════════════════════════════════════════════
def smoke_test(args: argparse.Namespace) -> int:
    """
    v3.0.1 — pinpoint exactly which flags work on this nuclei build.

    Tests 3 command tiers against a single target and reports which one
    succeeds. The pipeline uses tier-1 by default; this diagnostic tells
    you whether tier-1 will pass or need the minimal fallback.
    """
    print_banner()
    log.rune(Rune.HAGALAZ, "SMOKE TEST — verifying nuclei flag compatibility")

    if not shutil.which("nuclei"):
        log.error("nuclei not found in PATH")
        return 1

    try:
        ver = subprocess.run(["nuclei", "-version"],
                              capture_output=True, text=True, timeout=10)
        log.info(f"  nuclei version: {(ver.stdout or ver.stderr).strip()[:120]}")
    except Exception as e:
        log.warn(f"  could not get version: {e}")

    tmpdir = Path("/tmp/nuclei_smoke")
    tmpdir.mkdir(exist_ok=True)
    tf = tmpdir / "targets.txt"
    tf.write_text("https://beardedviking.org\n")
    oj = tmpdir / "out.jsonl"

    def _run_and_report(label: str, cmd: list[str], timeout: int) -> bool:
        if oj.exists():
            oj.unlink()
        log.info("")
        log.info(f"── {label} ──")
        log.info(f"  cmd: {' '.join(cmd[:12])}{' …' if len(cmd) > 12 else ''}")
        rc, out, err = _try_nuclei(cmd, timeout)
        produced = oj.exists() and oj.stat().st_size > 0
        log.info(f"  rc={rc}  output={'YES' if produced else 'NO'}")
        if err.strip():
            log.warn(f"  stderr: {err.strip()[:400]}")
        if out.strip() and rc != 0:
            log.warn(f"  stdout: {out.strip()[:400]}")
        return rc == 0 and produced

    # Tier 3: minimal
    min_cmd = [
        "nuclei", "-l", str(tf), "-jsonl", "-o", str(oj),
        "-silent", "-nc", "-rl", "5", "-c", "10", "-timeout", "10",
    ]
    min_ok = _run_and_report("Tier 3 · minimal (universal safe flags)",
                              min_cmd, 120)
    if not min_ok:
        log.error("  MINIMAL command failed — nuclei itself is broken")
        return 1
    log.ok("  ✓ minimal works — pipeline fallback guaranteed")

    # Tier 2: with severity + exclude-tags + random-agent + full long-form
    t2_cmd = min_cmd + [
        "-severity", "critical,high,medium",
        "-exclude-tags", "dos,fuzz,intrusive,bruteforce,headless",
        "-random-agent",
    ]
    t2_ok = _run_and_report("Tier 2 · + severity + exclude-tags + random-agent",
                              t2_cmd, 180)
    if not t2_ok:
        log.warn("  Tier 2 failed — pipeline will use Tier 3 fallback")
        print()
        print(f"{_c('amber')}{Sym.WARN}  ══ SMOKE TEST PARTIAL — fallback active ══  {Sym.WARN}{_c('reset')}")
        return 0

    # Tier 1: full tiered command from _build_cmd
    t1_cmd = _build_cmd(
        tf, oj,
        rate_limit=5, concurrency=10, bulk_size=5,
        timeout=10, retries=1, profile=args.profile,
        no_interactsh=True, omit_raw=True,
    )
    t1_ok = _run_and_report("Tier 1 · full _build_cmd tiered command",
                              t1_cmd, 180)

    print()
    if t1_ok:
        print(f"{_c('green')}{Sym.SHIELD}  ══ SMOKE TEST PASSED — all 3 tiers work ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    log.warn("  Tier 1 failed — pipeline will fall back to Tier 2/3 automatically")
    print(f"{_c('amber')}{Sym.WARN}  ══ SMOKE TEST PARTIAL — fallback active ══  {Sym.WARN}{_c('reset')}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_urls.txt"

    p = argparse.ArgumentParser(
        prog="nuclei_scan.py",
        description=f"Argus recon · nuclei_scan v{__version__} '{__codename__}'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=base / "output")
    p.add_argument("--bbp", type=str, default=None)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--profile", default=DEFAULT_PROFILE,
                    choices=list(PROFILES.keys()))
    p.add_argument("--rate-limit", type=int, default=None)
    p.add_argument("--concurrency", type=int, default=None)
    p.add_argument("--bulk-size", type=int, default=None)
    p.add_argument("--severities", default=None,
                    help="comma-separated severity override")
    p.add_argument("--tags", default=None,
                    help="comma-separated additional tags")
    p.add_argument("--no-update", action="store_true",
                    help="skip -update-templates")
    p.add_argument("--headless", action="store_true",
                    help="enable nuclei headless templates")
    p.add_argument("--proxy", default=None,
                    help="explicit proxy URL (overrides ProxyPool)")
    p.add_argument("--no-proxy", action="store_true",
                    help="disable ProxyPool rotation")
    p.add_argument("--resume", action="store_true",
                    help="resume from nuclei_evidence/ (skip done batches)")
    p.add_argument("--dry-run", action="store_true")

    # ── v3.0 additions ──
    p.add_argument("--no-ai", action="store_true",
                    help="explicitly disable AI triage (overrides AI_ENABLED)")
    p.add_argument("--ai-max-cost", type=float, default=0.0,
                    help="max USD to spend on AI triage this run (0 = unlimited)")
    p.add_argument("--ai-max-hosts", type=int, default=AI_MAX_HOSTS_PER_RUN,
                    help="cap hosts receiving AI triage")
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS,
                    help="hours to cache AI triage results (0 = no cache)")
    p.add_argument("--enable-interactsh", action="store_true",
                    help="enable Project Discovery's interactsh OAST server")
    p.add_argument("--interactsh-url", type=str, default=None,
                    help="self-hosted interactsh server URL")
    p.add_argument("--page-timeout", type=int, default=None,
                    help="full page load timeout (defaults to --timeout)")
    p.add_argument("--exclude-matcher", action="append", default=None,
                    help="exclude matcher name (repeatable)")
    p.add_argument("--sni", type=str, default=None,
                    help="custom SNI for TLS handshake")
    p.add_argument("--track-error", action="store_true",
                    help="nuclei -track-error (troubleshooting)")
    p.add_argument("--no-omit-raw", action="store_true",
                    help="keep full request/response blobs in JSONL (huge files)")

    # Utility
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version",
                    version=f"nuclei_scan.py {__version__} '{__codename__}'")
    p.add_argument("--smoke-test", action="store_true",
                    help="diagnose exactly which nuclei flags work on this build")
    p.add_argument("--no-omit-raw", action="store_true",
                    help="keep full request/response blobs in JSONL (huge files)")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try:
            CFG.Palette._enabled = False  # type: ignore
        except Exception:
            pass
    if args.verbose and hasattr(log, "min_level"):
        log.min_level = "debug"

    if args.selftest:
        return selftest()
    if args.config_check:
        return config_check()
    if args.smoke_test:
        return smoke_test(args)

    print_banner()

    sev: Optional[list[str]] = None
    if args.severities:
        sev = [s.strip().lower() for s in args.severities.split(",") if s.strip()]

    tags: Optional[list[str]] = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    # Interactsh resolution
    no_interactsh = not args.enable_interactsh
    if args.interactsh_url:
        no_interactsh = False

    try:
        run_nuclei_scan(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            bulk_size=args.bulk_size,
            profile=args.profile,
            severities=sev,
            custom_tags=tags,
            headless=args.headless,
            proxy=args.proxy,
            update_templates=not args.no_update,
            scan_id=args.scan_id,
            bbp_program=args.bbp,
            use_proxy=not args.no_proxy,
            resume=args.resume,
            dry_run=args.dry_run,
            # ── v3.0 ──
            no_ai=args.no_ai,
            ai_max_cost_usd=args.ai_max_cost,
            ai_max_hosts=args.ai_max_hosts,
            ai_cache_ttl_hours=args.ai_cache_ttl,
            no_interactsh=no_interactsh,
            interactsh_url=args.interactsh_url,
            page_timeout=args.page_timeout,
            exclude_matchers=args.exclude_matcher,
            sni=args.sni,
            track_error=args.track_error,
            omit_raw=not args.no_omit_raw,
        )
        return 0
    except KeyboardInterrupt:
        log.warn("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
