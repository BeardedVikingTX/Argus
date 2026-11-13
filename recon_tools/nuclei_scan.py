#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛊ ᚢ ᚱ ᛏ ᚱ   ·   N U C L E I   S C A N   ·   S U R T R ' S   W R A T H
================================================================================
  File      : recon_tools/nuclei_scan.py
  Version   : 3.1.0 "SURTR'S WRATH · MASTERWORK"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  v3.1 — MASTERWORK (this release):
    [FIX]  Duplicate --no-omit-raw argparse declaration (CLI startup crash).
    [FIX]  PROFILES[profile] global mutation removed — per-run effective profile.
    [FIX]  Interactsh config override no longer clobbers explicit user intent.
    [FIX]  _load_targets: BOM strip + CRLF normalize + inline comment strip.
    [FIX]  _dedupe: now keys on path + response hash for fuzz findings.
    [FIX]  _build_minimal_cmd: honors user --severities / --tags override.
    [FIX]  WAF-blocked findings no longer inflate host_risk.
    [FIX]  UNKNOWN severity now inferred from CVSS score when missing.
    [FIX]  Header values with empty strings are dropped before nuclei sees them.
    [NEW]  --min-severity / --max-severity filtering.
    [NEW]  --batch-timeout (per-batch); default derives from hard timeout / batch count.
    [NEW]  Per-finding confidence score (high/medium/low) in heuristic triage.
    [NEW]  WAF-aware effective severity + real-vs-noise breakdown.
    [NEW]  AI cache versioned by model + prompt hash — model swap busts cache.
    [NEW]  AI prompt now includes chains, WAF flags, CVSS, extracted results,
           and top-3 heuristic rankings as a soft hint.
    [NEW]  AI response schema validation + one corrective retry on parse failure.
    [NEW]  AI cost tracking from actual usage when ai_complete returns (text, usage).
    [NEW]  Optional parallel AI triage (--ai-parallel) with budget lock.
    [NEW]  Structured `warnings` array in report JSON.
    [NEW]  nuclei version captured into report.
    [NEW]  on_progress callback for TUI / dashboard integration.
    [NEW]  SIGINT handler — finish current batch, write partial report.
    [NEW]  Selftest: 50 → 74 checks (parse-path, WAF downgrade, cache stability).
    [NEW]  _build_cmd kwargs whitelist: known-compat kwargs silently dropped,
           truly unknown ones warn loudly so real typos are caught.

  Pipeline preserves all v3.0 file outputs. Schema is additive only.
================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures as _fut
import hashlib
import json
import logging
import math
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
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
    import config as CFG  # type: ignore
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
        return CFG._c(name)  # type: ignore[attr-defined]
    return _FallbackPalette.c(name)


class _FallbackLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self) -> None:
        self.min_level = "info"

    def _emit(self, level: str, msg: str, color: str, prefix: str) -> None:
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")

    def debug(self, m): self._emit("debug", m, "grey", "·")
    def info (self, m): self._emit("info",  m, "cyan", "·")
    def warn (self, m): self._emit("warn",  m, "amber", "⚠")
    def error(self, m): self._emit("error", m, "crimson", "✗")
    def ok   (self, m): self._emit("info",  m, "green", "✓")

    def rune(self, rune: str, msg: str) -> None:
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


__version__ = "3.2.0"
__codename__ = "SURTR'S WRATH · HOTFORGED"


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛊ ᚢ ᚱ ᛏ ᚱ{R}
    {P}{rule}{R}
    {V}      N U C L E I   S C A N   ·   S U R T R ' S   W R A T H{R}
    {V}              M A S T E R W O R K   ·   v{__version__}{R}
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

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        return [cls.INFO, cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL][max(0, min(4, rank))]


def _downgrade_severity(sev: str) -> str:
    """One-step severity downgrade — used for WAF-blocked findings."""
    return {
        "CRITICAL": "MEDIUM", "HIGH": "MEDIUM", "MEDIUM": "LOW",
        "LOW": "INFO", "INFO": "INFO", "UNKNOWN": "INFO",
    }.get(sev.upper(), "INFO")


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "INFO"


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
DEFAULT_BATCH_TIMEOUT       = 900

AI_MIN_FINDINGS_PER_HOST    = 1
AI_MAX_HOSTS_PER_RUN        = 20
AI_DEFAULT_CACHE_TTL_HOURS  = 72
AI_DEFAULT_MAX_WORKERS      = 4
AI_ESTIMATE_PER_CALL_USD    = 0.002
AI_PROMPT_VERSION           = "v3.1"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                    "LOW": 3, "INFO": 4, "UNKNOWN": 5}

# Kwargs that may appear but must be silently dropped (documented in v3.0 changelog)
_COMPAT_KWARGS_SILENT = {"resume"}

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
    "nuclei-ssti-candidate":     Severity.HIGH,
    "nuclei-xxe-candidate":      Severity.HIGH,
    "nuclei-open-redirect":      Severity.LOW,
    "nuclei-crlf-injection":     Severity.MEDIUM,
    "nuclei-auth-bypass":        Severity.HIGH,
    "nuclei-sensitive-file":     Severity.HIGH,
    "nuclei-misconfig":          Severity.MEDIUM,
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
    "nuclei-ssti-candidate":     "Potential server-side template injection",
    "nuclei-xxe-candidate":      "Potential XML external entity",
    "nuclei-open-redirect":      "Open redirect",
    "nuclei-crlf-injection":     "CRLF / header injection",
    "nuclei-auth-bypass":        "Potential auth bypass",
    "nuclei-sensitive-file":     "Sensitive file exposed",
    "nuclei-misconfig":          "Misconfiguration flagged",
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
    (re.compile(r"(?<![a-z])xss|cross-?site-?scripting", re.I),                 "nuclei-xss-candidate"),
    (re.compile(r"ssti|template-?injection", re.I),                              "nuclei-ssti-candidate"),
    (re.compile(r"xxe|xml-?external", re.I),                                     "nuclei-xxe-candidate"),
    (re.compile(r"open-?redirect|url-?redirect", re.I),                          "nuclei-open-redirect"),
    (re.compile(r"crlf|header-?injection|response-?splitting", re.I),            "nuclei-crlf-injection"),
    (re.compile(r"auth-?bypass|broken-?auth|unauthenticated|unauth-", re.I),    "nuclei-auth-bypass"),
    (re.compile(r"backup|\.bak|\.sql|\.zip|\.tar|file-?download|sensitive-?file", re.I), "nuclei-sensitive-file"),
    (re.compile(r"misconfig|configuration-?issue|insecure-?setting", re.I),     "nuclei-misconfig"),
]

WAF_BLOCK_BODY_MARKERS = (
    "attention required! | cloudflare",
    "just a moment...",
    "checking your browser",
    "ddos-guard",
    "enable javascript and cookies",
    "request blocked",
    "access denied",
    "captcha",
    "incapsula incident id",
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
    confidence:         str = "medium"      # v3.1: high / medium / low
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
            "confidence":        self.confidence,
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
    # Wider window than v3.0 — CDN pages can be long.
    body_lower = body[:8000].lower()
    return any(m in body_lower for m in WAF_BLOCK_BODY_MARKERS)


def _severity_of_str(sev: str) -> Severity:
    s = (sev or "unknown").upper()
    try:
        return Severity(s)
    except ValueError:
        return Severity.INFO


def _dedupe_key(f: NucleiFinding) -> tuple:
    # v3.1: include path + response hash so fuzz findings with distinct
    # payloads but same template + URL survive the dedupe pass.
    resp_hash = hashlib.sha1((f.response or "")[:4096].encode()).hexdigest()[:12]
    return (
        f.template_id,
        f.matched_at,
        f.matcher_name,
        tuple(sorted(f.extracted_results)),
        f.path,
        resp_hash,
    )


def _confidence_of(f: NucleiFinding) -> str:
    """v3.1 heuristic confidence scoring for a single finding."""
    if f.waf_blocked:
        return "low"
    if f.severity in ("INFO", "UNKNOWN"):
        return "low"
    if f.cve_ids and not f.waf_blocked:
        return "high"
    if f.template_id.startswith(("cve-", "CVE-")):
        return "high"
    if any(c in ("nuclei-rce-candidate", "nuclei-auth-bypass",
                  "nuclei-exposed-config", "nuclei-default-creds")
           for c in f.chain_ids):
        return "high" if f.extracted_results else "medium"
    if f.extracted_results:
        return "high"
    return "medium"


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  TEMPLATE CLASSIFICATION → CHAINS
# ══════════════════════════════════════════════════════════════════════════

def _classify_template_to_chains(template_id: str) -> list[str]:
    chains: list[str] = []
    for pattern, cid in TEMPLATE_CHAIN_PATTERNS:
        if pattern.search(template_id) and cid not in chains:
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
    finding.confidence = _confidence_of(finding)


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
#  ᛜ  INPUT LOADING — v3.1 BOM + CRLF safe
# ══════════════════════════════════════════════════════════════════════════

def _load_targets(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    targets: list[str] = []
    seen: set[str] = set()
    # v3.1: utf-8-sig strips BOM automatically.
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments only when preceded by whitespace
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
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


def _nuclei_version() -> str:
    """v3.1: capture version for report provenance."""
    try:
        r = subprocess.run(["nuclei", "-version"],
                            capture_output=True, text=True, timeout=10)
        text = (r.stdout or r.stderr or "").strip()
        m = re.search(r"v?\d+\.\d+\.\d+", text)
        return m.group(0) if m else text[:40]
    except Exception:
        return "unknown"


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  HEADER + PROXY RESOLUTION
# ══════════════════════════════════════════════════════════════════════════

def _headers_for_nuclei(bbp_program: Optional[str],
                          extra: Optional[dict]) -> tuple[list[str], bool]:
    """
    Build -H args from config.build_headers + ACTIVE_HEADERS + AUTH_HEADERS + extra.

    v3.2: if no User-Agent was contributed by any source, emit one from the
    config UA corpus via -H. This replaces the old `-random-agent` flag —
    which is NOT supported on all nuclei builds. `has_ua` is now always True
    after this function returns.
    """
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
        if v is None or (isinstance(v, str) and not v.strip()):
            continue
        args.extend(["-H", f"{k}: {v}"])
        if k.lower() == "user-agent":
            has_ua = True

    # v3.2 — always emit a UA. Universal — works on every nuclei build.
    if not has_ua:
        ua = ""
        try:
            ua_fn = _cfg("random_user_agent")
            if callable(ua_fn):
                ua = str(ua_fn())
        except Exception:
            ua = ""
        if not ua:
            ua = (f"Mozilla/5.0 (compatible; Argus/{__version__} "
                  f"nuclei_scan; +https://beardedviking.org)")
        args.extend(["-H", f"User-Agent: {ua}"])
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
#  ⚡  COMMAND BUILDER — v3.1
#      · Explicit kwargs whitelist — only truly unknown kwargs warn
#      · Tiered flag emission for maximum nuclei version compatibility
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
    effective_profile: Optional[dict] = None,
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
    **extra: Any,
) -> list[str]:
    """
    v3.1 — same tiered strategy as v3.0.1, with an explicit kwargs whitelist.
    Only `resume` is silently tolerated (documented compat); any other
    unknown kwarg warns so real typos are caught instead of silently swallowed.
    """
    for k in extra:
        if k in _COMPAT_KWARGS_SILENT:
            log.debug(f"  _build_cmd: compat kwarg '{k}' silently dropped")
        else:
            log.warning(f"  _build_cmd: unexpected kwarg '{k}' dropped — "
                        f"investigate caller")

    prof = effective_profile if effective_profile is not None \
        else PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

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

    if headless:
        cmd.append("-headless")

    if proxy:
        cmd.extend(["-proxy", proxy])

    if sni:
        cmd.extend(["-sni", sni])

    if page_timeout and page_timeout != timeout:
        cmd.extend(["-page-timeout", str(page_timeout)])

    # ═══ TIER 2 — opt-in extras (config-gated for older nuclei) ═══
    tier2_ok = CFG_LOADED and getattr(CFG, "NUCLEI_USE_TIER2_FLAGS", False)

    if exclude_matchers and tier2_ok:
        for m in exclude_matchers:
            cmd.extend(["-exclude-matchers", m])

    if no_interactsh and tier2_ok:
        cmd.append("-no-interactsh")
    elif interactsh_url and tier2_ok:
        cmd.extend(["-interactsh-url", interactsh_url])

    if track_error and tier2_ok:
        cmd.append("-track-error")

    if omit_raw and tier2_ok:
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
    effective_profile: Optional[dict] = None,
) -> list[str]:
    """
    v3.1 — bulletproof minimal command. Now honors the effective profile
    (including any user-supplied --severities / --tags-* overrides) so the
    fallback run does not silently scan wider than the primary run.
    """
    prof = effective_profile if effective_profile is not None \
        else PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

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

    if proxy:
        cmd.extend(["-proxy", proxy])

    return cmd


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  BATCH EXECUTION — v3.1
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

# Flags that take a value (used for progressive elimination)
_FLAGS_TAKING_VALUE: frozenset[str] = frozenset({
    "H", "l", "t", "o", "rl", "c", "timeout", "retries",
    "severity", "tags", "exclude-tags", "bulk-size",
    "proxy", "sni", "page-timeout", "interactsh-url",
    "exclude-matchers", "stats-json", "stats-interval",
    "target", "dut", "field", "template",
})


def _strip_flag_from_cmd(cmd: list[str], flag: str) -> list[str]:
    """
    v3.2: remove `flag` (and its value if it takes one) from a nuclei command.
    `flag` may be passed with or without leading dash ("-random-agent" or
    "random-agent"). Preserves the binary at index 0.
    """
    target = flag.lstrip("-")
    out: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-") and tok.lstrip("-") == target:
            if target in _FLAGS_TAKING_VALUE:
                skip_next = True
            continue
        out.append(tok)
    return out

def _run_batch(
    targets: list[str],
    workdir: Path,
    evidence_dir: Path,
    batch_index: int,
    batch_timeout: Optional[int] = None,
    **kwargs: Any,
) -> tuple[Optional[Path], BatchResult]:
    """
    v3.2 — progressive flag elimination.

    On rc==2, parses "flag provided but not defined: -X" from output, strips
    `-X` (and its value if applicable), retries. Repeats up to MAX_STRIP passes.
    If a flag can't be parsed, falls back to the minimal-safe command.
    """
    resume_flag = bool(kwargs.pop("resume", False))
    eff_profile = kwargs.pop("effective_profile", None)
    eff_timeout = batch_timeout or NUCLEI_HARD_TIMEOUT

    result = BatchResult(
        batch_index=batch_index,
        targets_count=len(targets),
        rate_limit=kwargs.get("rate_limit"),
        concurrency=kwargs.get("concurrency"),
        bulk_size=kwargs.get("bulk_size"),
        severities=",".join(
            (eff_profile or PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {}))
            .get("severities") or []),
        tags_allow=",".join(kwargs.get("custom_tags") or []),
        tags_deny=",".join(
            (eff_profile or PROFILES.get(kwargs.get("profile", DEFAULT_PROFILE), {}))
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
        return evidence_path, result

    targets_file = workdir / f"batch_{batch_index:03d}_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")
    output_jsonl = workdir / f"batch_{batch_index:03d}_output.jsonl"
    result.input_file = str(targets_file)

    _subprocess_guard("nuclei")
    log.info(f"  batch {batch_index:02d}  {len(targets):>3} target(s)  "
             f"→ {output_jsonl.name}")

    cmd = _build_cmd(targets_file, output_jsonl,
                      effective_profile=eff_profile, **kwargs)

    # ═══ ATTEMPT LOOP — progressive flag elimination ═══
    MAX_STRIPS = 8
    tried_flags: set[str] = set()
    rc, stdout, stderr = 0, "", ""

    for attempt in range(MAX_STRIPS + 1):
        log.debug(f"  cmd (attempt {attempt+1}, {len(cmd)} tokens): "
                  f"{' '.join(cmd[:10])}…")
        started = time.monotonic()
        rc, stdout, stderr = _try_nuclei(cmd, eff_timeout)
        result.duration_ms += int((time.monotonic() - started) * 1000)
        _audit_subprocess("nuclei", cmd, rc == 0,
                          result.duration_ms, stderr[:200])

        if rc == 0:
            break

        # Non-flag error → no point in further flag elimination
        if rc != 2:
            result.error = (f"rc={rc}: "
                            f"{(stderr or stdout).strip()[:500]}")
            log.warn(f"  batch {batch_index:02d}  exited {rc}: "
                     f"{(stderr or stdout).strip()[:200]}")
            return None, result

        # rc == 2 — try to parse the rejected flag
        combined = f"{stderr}\n{stdout}"
        m = re.search(r"flag provided but not defined:\s*-([\w\-]+)",
                       combined)
        if not m:
            # Can't parse — fall through to minimal
            log.warn(f"  batch {batch_index:02d}  exit 2 with unparseable flag "
                     f"error — falling back to minimal command")
            log.debug(f"         raw: {(combined.strip()[:300])}")
            break

        bad_flag = m.group(1).strip()
        if bad_flag in tried_flags:
            log.error(f"  batch {batch_index:02d}  loop on flag -{bad_flag} — "
                     f"giving up")
            result.error = f"flag loop on -{bad_flag}"
            return None, result

        tried_flags.add(bad_flag)
        log.warn(f"  batch {batch_index:02d}  nuclei rejected "
                 f"-{bad_flag} — stripping and retrying "
                 f"({len(tried_flags)}/{MAX_STRIPS})")

        new_cmd = _strip_flag_from_cmd(cmd, bad_flag)
        if len(new_cmd) < 3:
            result.error = f"cannot strip -{bad_flag} — command too short"
            log.error(f"  batch {batch_index:02d}  {result.error}")
            return None, result
        if new_cmd == cmd:
            result.error = f"strip on -{bad_flag} made no change"
            log.error(f"  batch {batch_index:02d}  {result.error}")
            return None, result
        cmd = new_cmd
        continue
    else:
        # Loop exhausted without success — try minimal
        log.warn(f"  batch {batch_index:02d}  exhausted {MAX_STRIPS} strip "
                 f"attempts — falling back to minimal command")
        cmd = []  # force minimal fallback below

    # ═══ If still failing or fell through → minimal fallback ═══
    if rc != 0:
        log.info(f"  batch {batch_index:02d}  retrying with minimal-safe flags")
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
            effective_profile=eff_profile,
        )
        log.debug(f"  minimal: {' '.join(min_cmd)}")

        # Also strip-eliminate on minimal
        for attempt in range(MAX_STRIPS):
            started = time.monotonic()
            rc, stdout, stderr = _try_nuclei(min_cmd, eff_timeout)
            result.duration_ms += int((time.monotonic() - started) * 1000)
            if rc == 0:
                break
            if rc != 2:
                break
            combined = f"{stderr}\n{stdout}"
            m = re.search(r"flag provided but not defined:\s*-([\w\-]+)",
                           combined)
            if not m:
                break
            bad_flag = m.group(1).strip()
            log.warn(f"  batch {batch_index:02d}  minimal rejected "
                     f"-{bad_flag} — stripping")
            new_min = _strip_flag_from_cmd(min_cmd, bad_flag)
            if new_min == min_cmd or len(new_min) < 3:
                break
            min_cmd = new_min

        if rc != 0:
            result.error = (f"minimal also failed (rc={rc}): "
                            f"{(stderr or stdout).strip()[:500]}")
            log.error(f"  batch {batch_index:02d}  minimal ALSO failed: "
                       f"rc={rc}")
            log.error(f"         stdout: {stdout.strip()[:200]}")
            log.error(f"         stderr: {stderr.strip()[:200]}")
            return None, result

        log.ok(f"  batch {batch_index:02d}  minimal command succeeded")

    if not output_jsonl.exists():
        result.error = (stderr or stdout or "no output file produced")[:500]
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
#  ᛊ  JSONL PARSING — v3.1 (schema tolerance preserved, CVSS-severity
#      upgrade added)
# ══════════════════════════════════════════════════════════════════════════

def _parse_jsonl(path: Path, auth_on: bool) -> list[NucleiFinding]:
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

        # ── CVSS: try numeric fields, then the CVSS vector string ──
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

        # ── Severity, with CVSS upgrade for UNKNOWN (v3.1) ──
        sev = (info.get("severity") or "unknown").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if cvss is not None and cvss > 0:
                sev = _severity_from_cvss(cvss)
            else:
                sev = "UNKNOWN"

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
        k = _dedupe_key(f)
        if k in seen:
            continue
        seen.add(k)
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
#  🧠 v3.1 AI CACHE — versioned by model + prompt hash
# ══════════════════════════════════════════════════════════════════════════

def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "nuclei_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: str, findings: list[NucleiFinding],
                    model: str = "", prompt_version: str = AI_PROMPT_VERSION) -> str:
    """
    Stable hash of host + finding set + model + prompt version.
    Same inputs → same cache key; model swap or prompt revision busts cache.
    """
    parts = [host.lower(), f"model={model or 'unknown'}",
             f"prompt={prompt_version}"]
    for f in sorted(findings, key=lambda x: (x.template_id, x.matched_at)):
        parts.append(f"{f.template_id}|{f.matched_at}|{f.severity}|{f.waf_blocked}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
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
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
#  💰 v3.1 COST TRACKING
# ══════════════════════════════════════════════════════════════════════════

_BUDGET_LOCK = threading.Lock()


def _current_spend() -> float:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return float(tracker.estimate_cost() or 0)
    except Exception:
        pass
    return 0.0


def _ai_cost_guard(would_add_cost: float, budget_usd: float) -> bool:
    """
    Return True if it's safe to make another AI call.
    Lock-protected so parallel callers can't both see "just under budget".
    """
    if budget_usd <= 0:
        return True
    if would_add_cost <= 0:
        return True
    with _BUDGET_LOCK:
        return (_current_spend() + would_add_cost) <= budget_usd


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  AI TRIAGE  ·  per-host (v3.1: enriched prompt + validation + retry)
# ══════════════════════════════════════════════════════════════════════════

AI_NUCLEI_SYSTEM = (
    "You are an expert bug-bounty triage analyst. You will receive nuclei "
    "findings for ONE host, along with that host's chain classification, WAF "
    "status per finding, CVSS scores, extracted results, and a heuristic "
    "baseline ranking you may use as a soft hint but MUST NOT trust blindly. "
    "\n\n"
    "Your job:\n"
    "  1. Rank findings by likely real-world impact (not just severity label).\n"
    "  2. Distinguish likely-real from likely-false-positive with reasoning.\n"
    "  3. Propose a multi-finding chain hypothesis if any is plausible.\n"
    "  4. Suggest concrete MANUAL confirmation steps — never exploits.\n"
    "  5. Downgrade findings whose response body looks like a WAF block page.\n"
    "\n"
    "Return STRICT JSON only. No markdown fences, no preamble. "
    "Required schema:\n"
    "{\n"
    '  "summary": "<one paragraph>",\n'
    '  "host_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
    '  "top_priorities": [{"rank":1,"finding":"tpl @ url","reason":"…",'
    '"test_idea":"…","confidence":"high|medium|low"}],\n'
    '  "real_vs_noise": "<specific narrative>",\n'
    '  "next_actions": ["…","…"],\n'
    '  "chain_hypothesis": "<one-liner or empty>"\n'
    "}"
)


def _build_top_findings_block(findings: list[NucleiFinding],
                                limit: int = 30) -> str:
    top = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 5),
        -(f.cvss_score or 0.0),
    ))[:limit]

    lines = []
    for f in top:
        bits = [f"[{f.severity:<8}]", f"{f.template_id:<38}"]
        bits.append(f"{f.matched_at[:70]}")
        if f.cvss_score:
            bits.append(f"cvss={f.cvss_score:.1f}")
        if f.waf_blocked:
            bits.append("WAF-BLOCKED")
        if f.extracted_results:
            sample = ",".join(str(x)[:40] for x in f.extracted_results[:2])
            bits.append(f"extracted=[{sample}]")
        if f.cve_ids:
            bits.append(",".join(f.cve_ids[:2]))
        lines.append("  " + " ".join(bits))
    return "\n".join(lines) if lines else "  (no findings)"


def _build_chains_block(host_result: HostResult) -> str:
    if not host_result.chains:
        return "  (no chains)"
    lines = []
    for c in host_result.chains[:12]:
        lines.append(f"  [{c['severity']:<8}] {c['chain_id']:<32} "
                     f"x{c['count']}")
    return "\n".join(lines)


def _validate_ai_triage(data: Any) -> bool:
    """v3.1: light schema validation — must be dict with required keys."""
    if not isinstance(data, dict):
        return False
    for key in ("summary", "host_risk", "real_vs_noise", "next_actions"):
        if key not in data:
            return False
    if not isinstance(data.get("next_actions"), list):
        return False
    if data.get("host_risk") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                       "INFO", "UNKNOWN", ""):
        return False
    if "top_priorities" in data and not isinstance(data["top_priorities"], list):
        return False
    return True


def _ai_triage_host(
    host_result: HostResult,
    outdir: Path,
    *,
    use_cache: bool = True,
    cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    budget_usd: float = 0.0,
    heuristic_hint: Optional[dict] = None,
) -> Optional[dict]:
    """
    AI triage for one host. Never raises — any failure → None → heuristic runs.
    """
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if len(host_result.findings) < AI_MIN_FINDINGS_PER_HOST:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(host_result.host, host_result.findings,
                                model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            log.debug(f"  AI triage (cached) for {host_result.host}")
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        log.debug(f"  AI budget reached — heuristic for {host_result.host}")
        return None

    findings = host_result.findings
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
                "UNKNOWN": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    cve_count = sum(1 for f in findings if f.cve_ids)
    waf_blocks = sum(1 for f in findings if f.waf_blocked)
    high_conf = sum(1 for f in findings if f.confidence == "high")

    hint_block = ""
    if heuristic_hint and heuristic_hint.get("top_priorities"):
        hint_lines = []
        for p in heuristic_hint["top_priorities"][:3]:
            hint_lines.append(f"  {p.get('rank', '?')}. {p.get('finding', '')} "
                              f"({p.get('reason', '')})")
        hint_block = (
            "\n\nHeuristic baseline ranking (HINT ONLY, verify independently):\n"
            + "\n".join(hint_lines)
        )

    prompt = f"""Analyze nuclei findings for host: {host_result.host}

Statistics:
  Total:        {len(findings)}
  CRITICAL:     {by_sev['CRITICAL']}
  HIGH:         {by_sev['HIGH']}
  MEDIUM:       {by_sev['MEDIUM']}
  LOW:          {by_sev['LOW']}
  INFO:         {by_sev['INFO']}
  UNKNOWN:      {by_sev['UNKNOWN']}
  CVE-tagged:   {cve_count}
  WAF-blocked:  {waf_blocks}
  High-conf:    {high_conf}

Chain classification:
{_build_chains_block(host_result)}

Top findings:
{_build_top_findings_block(findings)}{hint_block}
"""

    def _call(prompt_text: str) -> Optional[str]:
        try:
            return ai_fn(prompt_text, system=AI_NUCLEI_SYSTEM)
        except Exception as e:
            log.warn(f"  AI call failed for {host_result.host}: "
                      f"{type(e).__name__}: {e}")
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

    # v3.1: one corrective retry on parse/validate failure
    if data is None:
        log.debug(f"  AI parse/validate failed for {host_result.host} — "
                  f"retrying once with correction")
        correction = (
            "Your previous response could not be parsed as valid JSON matching "
            "the required schema. Return ONLY the JSON object, no fences, no "
            "preamble. All required keys must be present.\n\n"
            f"Previous response was:\n{text[:800]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {"summary": text2[:1500], "parse_error": True,
                        "host_risk": "UNKNOWN", "real_vs_noise": "unknown",
                        "next_actions": [], "top_priorities": []}
        else:
            data = {"summary": text[:1500], "parse_error": True,
                    "host_risk": "UNKNOWN", "real_vs_noise": "unknown",
                    "next_actions": [], "top_priorities": []}

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host_result.host)[:60]
    md_path = outdir / f"nuclei_ai_{safe}.md"
    try:
        md = (f"# Surtr's Wrath · AI Triage — {host_result.host}\n\n"
              f"**Findings:** {len(findings)}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("host_risk"):
            md += f"**Host risk:** {data['host_risk']}\n\n"
        if data.get("summary"):
            md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("top_priorities"):
            md += "## Top Priorities\n\n"
            for p in data["top_priorities"]:
                md += (f"{p.get('rank', '?')}. **{p.get('finding', '')}** "
                       f"_(conf={p.get('confidence', '?')})_\n"
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

    return {
        "path": str(md_path),
        "summary": data.get("summary", ""),
        "host_risk": data.get("host_risk", ""),
        "top_priorities": data.get("top_priorities", [])[:10],
        "real_vs_noise": data.get("real_vs_noise", ""),
        "next_actions": data.get("next_actions", [])[:10],
        "chain_hypothesis": data.get("chain_hypothesis", ""),
        "cost_estimate": round(_current_spend(), 6),
        "source": "ai",
    }


# ══════════════════════════════════════════════════════════════════════════
#  ᚹ  HEURISTIC TRIAGE — v3.1 (WAF-aware, confidence, cross-correlation)
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
    if "ssti" in tid or "template-injection" in tid:
        return f"Manually confirm SSTI at {f.matched_at} with {{{{7*7}}}}"
    if "xxe" in tid or "xml-external" in tid:
        return f"Manually confirm XXE at {f.matched_at} with an out-of-band DOCTYPE payload"
    if "open-redirect" in tid or "url-redirect" in tid:
        return f"Manually confirm redirect at {f.matched_at} with ?next=https://evil.test"
    if "crlf" in tid or "header-injection" in tid:
        return f"Manually confirm CRLF at {f.matched_at} with %0d%0aX-Injected:1"
    if "cors" in tid:
        return f"Manually check CORS at {f.matched_at} with Origin: https://evil.test"
    if "exposed" in tid or "disclosure" in tid:
        return f"Browse {f.matched_at} in browser — confirm data sensitivity"
    if "default-login" in tid or "default-cred" in tid:
        return f"Manually verify default credentials at {f.matched_at}"
    if "takeover" in tid:
        return f"Verify takeover possibility for {_host_of(f.matched_at)} via DNS"
    if "backup" in tid or ".bak" in tid or ".sql" in tid:
        return f"Download and inspect {f.matched_at} — confirm data contents"
    if "tech" in tid or "version" in tid:
        return f"Check {f.matched_at} for specific version — cross-reference CVEs"
    if "misconfig" in tid:
        return f"Review {f.matched_at} for exploitable misconfiguration"
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
            "next_actions": ["Consider widening --profile or --tags on next run"],
            "chain_hypothesis": "",
            "source": "heuristic",
        }

    # Raw + WAF-adjusted severity breakdown
    by_sev_raw: dict[str, int] = {}
    by_sev_eff: dict[str, int] = {}
    n_waf = 0
    for f in findings:
        by_sev_raw[f.severity] = by_sev_raw.get(f.severity, 0) + 1
        if f.waf_blocked:
            n_waf += 1
            eff = _downgrade_severity(f.severity)
        else:
            eff = f.severity
        by_sev_eff[eff] = by_sev_eff.get(eff, 0) + 1

    # Host risk driven by EFFECTIVE severity (WAF-aware)
    if by_sev_eff.get("CRITICAL", 0) > 0: host_risk = "CRITICAL"
    elif by_sev_eff.get("HIGH", 0) > 0:   host_risk = "HIGH"
    elif by_sev_eff.get("MEDIUM", 0) > 0: host_risk = "MEDIUM"
    elif by_sev_eff.get("LOW", 0) > 0:    host_risk = "LOW"
    else:                                   host_risk = "INFO"

    cve_count = sum(1 for f in findings if f.cve_ids)
    high_conf = sum(1 for f in findings if f.confidence == "high")
    low_conf = sum(1 for f in findings if f.confidence == "low")

    n_total = len(findings)
    n_effective = n_total - n_waf

    summary = (
        f"{n_total} finding(s) on {host_result.host}. "
        f"Raw: CRIT={by_sev_raw.get('CRITICAL', 0)} "
        f"HIGH={by_sev_raw.get('HIGH', 0)} "
        f"MED={by_sev_raw.get('MEDIUM', 0)}. "
        f"Effective (WAF-adjusted): CRIT={by_sev_eff.get('CRITICAL', 0)} "
        f"HIGH={by_sev_eff.get('HIGH', 0)}. "
        f"{cve_count} CVE-tagged, {high_conf} high-confidence."
    )
    if n_waf:
        summary += (f" WARNING: {n_waf} finding(s) show WAF block pages — "
                     f"effective severity downgraded by one rank.")

    # Rank by effective severity, WAF state, CVSS, confidence
    rank_confidence = {"high": 0, "medium": 1, "low": 2}
    top = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(
            _downgrade_severity(f.severity) if f.waf_blocked else f.severity, 5),
        f.waf_blocked,
        rank_confidence.get(f.confidence, 3),
        -(f.cvss_score or 0.0),
    ))[:5]

    top_priorities = []
    for i, f in enumerate(top, 1):
        eff_sev = _downgrade_severity(f.severity) if f.waf_blocked else f.severity
        reason_parts = [f"effective {eff_sev}"]
        if f.waf_blocked:
            reason_parts.append(f"WAF-blocked (raw {f.severity})")
        if f.cvss_score:
            reason_parts.append(f"CVSS {f.cvss_score:.1f}")
        if f.cve_ids:
            reason_parts.append(",".join(f.cve_ids[:2]))
        reason_parts.append(f"conf={f.confidence}")
        top_priorities.append({
            "rank": i,
            "finding": f"{f.template_id} @ {f.matched_at}",
            "reason": " · ".join(reason_parts),
            "test_idea": _suggest_confirmation(f),
            "confidence": f.confidence,
        })

    # Real-vs-noise breakdown
    noise_bits = []
    if n_waf:
        noise_bits.append(f"{n_waf} WAF-blocked")
    if by_sev_raw.get("INFO", 0):
        noise_bits.append(f"{by_sev_raw['INFO']} INFO-level")
    if low_conf:
        noise_bits.append(f"{low_conf} low-confidence")
    signal_bits = []
    if high_conf:
        signal_bits.append(f"{high_conf} high-confidence")
    if cve_count:
        signal_bits.append(f"{cve_count} CVE-tagged")
    real_vs_noise = (
        f"{n_effective} potentially real"
        + (f" ({', '.join(signal_bits)})" if signal_bits else "")
        + (f"; {', '.join(noise_bits)} likely noise" if noise_bits else "")
    )

    # Next actions
    next_actions: list[str] = []
    if by_sev_eff.get("CRITICAL", 0):
        next_actions.append(
            f"Confirm {by_sev_eff['CRITICAL']} effective-CRITICAL finding(s) "
            f"first — highest reward")
    if by_sev_eff.get("HIGH", 0):
        next_actions.append(f"Confirm {by_sev_eff['HIGH']} effective-HIGH finding(s)")
    if cve_count:
        next_actions.append(
            f"Cross-reference {cve_count} CVE(s) on NVD for affected versions")
    if high_conf >= 2:
        next_actions.append(
            f"Manually review the {high_conf} high-confidence finding(s) as a cluster")
    if n_waf:
        next_actions.append(
            f"Re-run {n_waf} WAF-blocked target(s) with --random-agent and slower --rate-limit")
    if not next_actions:
        next_actions.append("Manual review of MEDIUM/LOW findings")

    # Cross-finding chain hypothesis
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
    elif "nuclei-cve-match" in chain_ids and "nuclei-rce-candidate" in chain_ids:
        chain_hypothesis = "Known CVE + RCE surface — prioritize version verification"
    elif "nuclei-ssti-candidate" in chain_ids or "nuclei-rce-candidate" in chain_ids:
        chain_hypothesis = "Template-injection-class finding — assess execution context"
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
        "waf_blocked_count": n_waf,
        "effective_severity": by_sev_eff,
        "raw_severity": by_sev_raw,
        "high_confidence_count": high_conf,
        "low_confidence_count": low_conf,
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
#  ᛊ  PUBLIC ENTRY POINT — v3.1 ORCHESTRATOR
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
    # v3.1 additions
    batch_timeout: Optional[int] = None,
    min_severity: Optional[str] = None,
    max_severity: Optional[str] = None,
    ai_parallel: bool = False,
    ai_max_workers: int = AI_DEFAULT_MAX_WORKERS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
) -> Path:
    """Run nuclei against every target in targets_file (v3.1 orchestrator)."""
    start = time.monotonic()
    warnings: list[str] = []

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

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
    if not isinstance(eff_rate, int) or eff_rate < 0:   eff_rate = DEFAULT_RATE_LIMIT
    if not isinstance(eff_conc, int) or eff_conc < 1:   eff_conc = DEFAULT_CONCURRENCY
    if not isinstance(eff_bulk, int) or eff_bulk < 1:   eff_bulk = DEFAULT_BULK_SIZE
    eff_rate, eff_conc, eff_bulk = _effective_limits(eff_rate, eff_conc, eff_bulk)

    if profile not in PROFILES:
        warnings.append(f"Unknown profile '{profile}' — fell back to '{DEFAULT_PROFILE}'")
        log.warn(warnings[-1])
        profile = DEFAULT_PROFILE

    # ═══ v3.1: effective profile — never mutate PROFILES ═══
    effective_profile = dict(PROFILES[profile])
    if severities is not None:
        effective_profile["severities"] = severities
    if tags_deny is not None:
        effective_profile["tags_deny"] = tags_deny

    # ═══ v3.1: config-driven defaults — respect explicit user intent ═══
    # no_interactsh and page_timeout can come from config ONLY when the
    # caller passed the sentinel default values; not when explicitly overridden.
    if no_interactsh is True:  # sentinel = "not explicitly set"
        cfg_ni = _cfg("NUCLEI_NO_INTERACTSH", None) if CFG_LOADED else None
        if cfg_ni is not None and cfg_ni is not True:
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

    if not quiet:
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
    if not quiet:
        if no_ai and _ai_enabled():
            log.info("  AI triage: disabled via --no-ai")
        elif ai_active:
            budget_str = f"${ai_max_cost_usd:.2f}" if ai_max_cost_usd > 0 else "unlimited"
            par = f" parallel(max={ai_max_workers})" if ai_parallel else ""
            log.info(f"  AI triage: enabled  (budget={budget_str}, "
                      f"max_hosts={ai_max_hosts}, cache_ttl={ai_cache_ttl_hours}h, "
                      f"prompt={AI_PROMPT_VERSION}{par})")
        else:
            log.info("  AI triage: disabled (config.AI_ENABLED=False) — "
                      "heuristic fallback active")

    # ── Config display ──
    if not quiet:
        log.info(f"Profile: {profile}  ({effective_profile.get('description', '')})")
        log.info(f"Config : rate={eff_rate}/s  conc={eff_conc}  bulk={eff_bulk}  "
                 f"timeout={eff_timeout}s  retries={eff_retries}")
        log.info(f"         bbp={bbp_program or 'none'}  proxy={eff_proxy or 'direct'}")
        log.info(f"         interactsh={'OFF (-ni)' if no_interactsh else (interactsh_url or 'default')}")
        if header_args:
            log.info(f"Headers: {len(header_args)//2} configured")
        if not has_ua:
            log.info("UA     : rotating (-random-agent)")
        if cookie_header:
            log.info(f"Auth   : enabled ({len(cookie_header)}-char Cookie)")
        if LIGHTWEIGHT_MODE:
            log.warn(f"lightweight host ({LIGHTWEIGHT_REASON}) — limits capped")
        if min_severity or max_severity:
            log.info(f"Filter : min_severity={min_severity or 'any'} "
                      f"max_severity={max_severity or 'any'}")

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
        if not quiet:
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
    if not quiet:
        log.info(f"Scanning {len(targets)} target(s) in {len(batches)} batch(es)...")

    # v3.1: derive per-batch timeout
    eff_batch_timeout = batch_timeout
    if eff_batch_timeout is None:
        # Divide the hard timeout across batches, floor at DEFAULT_BATCH_TIMEOUT
        eff_batch_timeout = max(DEFAULT_BATCH_TIMEOUT,
                                 NUCLEI_HARD_TIMEOUT // max(1, len(batches)))

    all_findings: list[NucleiFinding] = []
    batch_results: list[BatchResult] = []

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
        effective_profile=effective_profile,
    )

    # SIGINT handler — let current batch finish, then write partial report
    _sigint_received = {"flag": False}

    def _on_sigint(signum, frame):  # noqa: ARG001
        if not _sigint_received["flag"]:
            log.warn("SIGINT — finishing current batch then writing report")
            _sigint_received["flag"] = True

    prev_sigint = signal.signal(signal.SIGINT, _on_sigint)

    try:
        for i, batch in enumerate(batches, 1):
            if _sigint_received["flag"]:
                log.warn("Aborting remaining batches — writing partial report")
                warnings.append("Run interrupted via SIGINT — partial results")
                break
            _progress("batch_start", {"index": i, "total": len(batches),
                                        "targets": len(batch)})
            output, result = _run_batch(batch, workdir, evidence_dir, i,
                                          batch_timeout=eff_batch_timeout,
                                          **kwargs)
            batch_results.append(result)
            if output:
                bf = _parse_jsonl(output, auth_on)
                all_findings.extend(bf)
                result.findings_count = len(bf)
                log.ok(f"  batch {i:02d} → {len(bf)} finding(s) "
                        f"({result.duration_ms}ms)")
            _progress("batch_end", {"index": i, "findings": result.findings_count,
                                      "duration_ms": result.duration_ms})
    finally:
        signal.signal(signal.SIGINT, prev_sigint)

    # ── Dedupe + sort ──
    deduped = _dedupe(all_findings)
    sorted_findings = _sort_findings(deduped)

    # ── v3.1: severity filtering ──
    if min_severity or max_severity:
        min_rank = (Severity(min_severity.upper()).rank if min_severity else 0)
        max_rank = (Severity(max_severity.upper()).rank if max_severity else 4)
        before_filter = len(sorted_findings)
        sorted_findings = [
            f for f in sorted_findings
            if min_rank <= Severity(_severity_of_str(f.severity).value).rank <= max_rank
            or f.severity == "UNKNOWN"
        ]
        dropped = before_filter - len(sorted_findings)
        if dropped:
            log.info(f"Filter : dropped {dropped} finding(s) outside "
                      f"[{min_severity or 'INFO'}, {max_severity or 'CRITICAL'}]")

    if not quiet:
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

    sorted_hosts = sorted(by_host.items())
    total_hosts = len(sorted_hosts)

    for idx, (host, host_findings) in enumerate(sorted_hosts, 1):
        host_result = HostResult(
            host=host, findings=host_findings,
            chains=_build_host_chains(host_findings),
        )

        # Always compute heuristic (cheap, useful as hint + fallback)
        heuristic = _heuristic_triage(host_result)

        ai_result: Optional[dict] = None
        if (ai_active
                and len(host_findings) >= AI_MIN_FINDINGS_PER_HOST
                and ai_hosts_done < ai_max_hosts
                and not ai_budget_exhausted):
            ai_result = _ai_triage_host(
                host_result, outdir,
                use_cache=True,
                cache_ttl_hours=ai_cache_ttl_hours,
                budget_usd=ai_max_cost_usd,
                heuristic_hint=heuristic,   # v3.1
            )
            if ai_result:
                ai_hosts_done += 1
            elif ai_max_cost_usd > 0 and _current_spend() >= ai_max_cost_usd:
                ai_budget_exhausted = True

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
        log.ok(f"  [{idx}/{total_hosts}] {host[:48]:<48} · "
                f"{len(host_findings)} finding(s) "
                f"(CRIT={n_crit} HIGH={n_high}) triage={host_result.triage_source}")

        _progress("host_triaged", {"host": host, "index": idx,
                                     "total": total_hosts,
                                     "source": host_result.triage_source})

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
    by_sev_eff: dict[str, int] = {}
    by_template: dict[str, int] = {}
    by_host_count: dict[str, int] = {}
    cve_count = 0
    waf_blocks = 0
    high_conf = 0
    chain_counts: dict[str, int] = {}

    for f in sorted_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        eff = _downgrade_severity(f.severity) if f.waf_blocked else f.severity
        by_sev_eff[eff] = by_sev_eff.get(eff, 0) + 1
        by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
        h = f.host or _host_of(f.matched_at) or "unknown"
        by_host_count[h] = by_host_count.get(h, 0) + 1
        if f.cve_ids: cve_count += 1
        if f.waf_blocked: waf_blocks += 1
        if f.confidence == "high": high_conf += 1
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

    ai_triaged = sum(1 for h in all_hosts if h.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for h in all_hosts if h.triage_source == "heuristic")

    audit_path = getattr(audit_trail, "path", None) if audit_trail else None

    # Collect any per-batch warnings
    for b in batch_results:
        if b.error:
            warnings.append(f"batch {b.batch_index}: {b.error[:200]}")
    if ai_budget_exhausted:
        warnings.append(f"AI budget reached (${ai_max_cost_usd:.2f}) — "
                         f"{heuristic_triaged - (len(all_hosts) - ai_triaged)} host(s) "
                         f"fell back to heuristic")

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
        "ai_prompt_version": AI_PROMPT_VERSION,
        "nuclei_version": _nuclei_version(),
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
            "batch_timeout":      eff_batch_timeout,
            "headers_count":      len(header_args) // 2 if header_args else 0,
            "cookie_set":         bool(cookie_header),
            "headless":           headless,
            "proxy":              eff_proxy,
            "profile_severities": effective_profile.get("severities"),
            "profile_tags_deny":  effective_profile.get("tags_deny"),
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
            "min_severity":       min_severity,
            "max_severity":       max_severity,
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
            "effective_critical":  by_sev_eff.get("CRITICAL", 0),
            "effective_high":      by_sev_eff.get("HIGH", 0),
            "unique_cves":         cve_count,
            "waf_blocked":         waf_blocks,
            "high_confidence":     high_conf,
            "ai_triaged":          ai_triaged,
            "heuristic_triaged":   heuristic_triaged,
            "ai_budget_exhausted": ai_budget_exhausted,
            "by_severity":         by_sev,
            "by_effective_severity": by_sev_eff,
        },
        "warnings": warnings,
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
    log.info(f"High-confidence     : {t.get('high_confidence', 0)}")
    if t["waf_blocked"]:
        log.warn(f"WAF-blocked         : {t['waf_blocked']} (likely FP)")

    by_sev = t["by_severity"]
    log.info("Raw severity        : " + " ".join(
        f"{k}={by_sev.get(k, 0)}" for k in
        ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    by_eff = t.get("by_effective_severity") or {}
    if t["waf_blocked"]:
        log.info("Effective severity  : " + " ".join(
            f"{k}={by_eff.get(k, 0)}" for k in
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

    if report.get("warnings"):
        log.info("")
        log.info("Warnings:")
        for w in report["warnings"][:8]:
            log.warn(f"  {w}")

    if critical_high:
        log.info("")
        log.info("CRITICAL/HIGH findings:")
        for f in critical_high[:15]:
            cve = f" [{','.join(f.cve_ids[:2])}]" if f.cve_ids else ""
            waf = " WAF" if f.waf_blocked else ""
            log.info(f"  [{f.severity:<8}]{waf} {f.template_id:<30} "
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
        "ai_prompt_version": AI_PROMPT_VERSION,
        "config":         {},
        "totals": {
            "targets_input": 0, "batches": 0,
            "raw_findings": 0, "unique_findings": 0,
            "hosts_with_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "unknown": 0, "effective_critical": 0, "effective_high": 0,
            "unique_cves": 0, "waf_blocked": 0, "high_confidence": 0,
            "ai_triaged": 0, "heuristic_triaged": 0,
            "ai_budget_exhausted": False,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                             "LOW": 0, "INFO": 0, "UNKNOWN": 0},
            "by_effective_severity": {},
        },
        "warnings": [],
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
#  ᛊ  SELF-TEST — v3.1 (74 checks incl. parse-path, WAF downgrade, cache)
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    import inspect
    import tempfile

    print_banner()
    log.rune(Rune.ALGIZ, "Self-test · Surtr's Wrath Masterwork integrity")

    def _mk(template_id: str, severity: str = "HIGH",
             matched_at: str = "https://test.example/path",
             cve_ids: Optional[list[str]] = None,
             chain_ids: Optional[list[str]] = None,
             waf_blocked: bool = False) -> NucleiFinding:
        f = NucleiFinding(
            template_id=template_id,
            severity=severity,
            matched_at=matched_at,
            host=_host_of(matched_at),
            cve_ids=cve_ids or [],
            chain_ids=chain_ids or [],
            waf_blocked=waf_blocked,
        )
        return f

    def _mk_no_resume_crash() -> bool:
        try:
            _build_cmd(
                Path("/tmp/t.txt"), Path("/tmp/o.jsonl"),
                rate_limit=5, concurrency=10, bulk_size=5,
                timeout=10, retries=1, profile="standard",
                resume=True,
            )
            return True
        except TypeError:
            return False
        except Exception:
            return True

    def _mk_unknown_kwarg_silenced() -> bool:
        try:
            _build_cmd(
                Path("/tmp/t.txt"), Path("/tmp/o.jsonl"),
                rate_limit=5, concurrency=10, bulk_size=5,
                timeout=10, retries=1, profile="standard",
                totally_made_up_kwarg="x",
            )
            return True
        except TypeError:
            return False
        except Exception:
            return True

    def _mk_end_to_end_parse() -> bool:
        """v3.1: actual parse-path integration through a temp JSONL."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                            delete=False) as tf:
            tf.write(json.dumps({
                "template-id": "cve-2021-44228",
                "info": {
                    "name": "Log4Shell",
                    "severity": "critical",
                    "classification": {
                        "cve-id": ["CVE-2021-44228"],
                        "cvss-score": 10.0,
                    },
                },
                "matched-at": "https://test.example/x",
                "host": "test.example",
            }) + "\n")
            tmp = Path(tf.name)
        try:
            parsed = _parse_jsonl(tmp, auth_on=False)
            return (len(parsed) == 1
                    and parsed[0].severity == "CRITICAL"
                    and "nuclei-cve-match" in parsed[0].chain_ids
                    and "nuclei-critical-finding" in parsed[0].chain_ids
                    and parsed[0].confidence == "high")
        finally:
            tmp.unlink(missing_ok=True)

    def _mk_cvss_severity_inference() -> bool:
        """v3.1: UNKNOWN severity + CVSS ≥ 9 → CRITICAL."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                            delete=False) as tf:
            tf.write(json.dumps({
                "template-id": "custom-novel",
                "info": {
                    "name": "Novel",
                    "severity": "unknown",
                    "classification": {"cvss-score": 9.8},
                },
                "matched-at": "https://test.example/y",
            }) + "\n")
            tmp = Path(tf.name)
        try:
            parsed = _parse_jsonl(tmp, auth_on=False)
            return len(parsed) == 1 and parsed[0].severity == "CRITICAL"
        finally:
            tmp.unlink(missing_ok=True)

    def _mk_waf_downgrade() -> bool:
        """v3.1: heuristic host_risk downgrades WAF-blocked CRITICALs."""
        h = HostResult(
            host="x.com",
            findings=[_mk("cve-2021-44228", "CRITICAL",
                            cve_ids=["CVE-2021-44228"],
                            waf_blocked=True)],
        )
        result = _heuristic_triage(h)
        return result["host_risk"] in ("MEDIUM", "LOW", "INFO")

    def _mk_cache_stability() -> bool:
        f1 = _mk("cve-2021-44228", "CRITICAL")
        f2 = _mk("exposed-env", "HIGH")
        a = _ai_cache_key("x.com", [f1, f2], model="m")
        b = _ai_cache_key("x.com", [f2, f1], model="m")  # reordered
        return a == b

    def _mk_cache_model_busts() -> bool:
        f = _mk("cve-2021-44228", "CRITICAL")
        a = _ai_cache_key("x.com", [f], model="model-a")
        b = _ai_cache_key("x.com", [f], model="model-b")
        return a != b

    def _mk_dedupe_distinct_paths() -> bool:
        f1 = _mk("xss-reflected", "MEDIUM", matched_at="https://x.com/a")
        f1.path = "/a"
        f1.response = "<html>1</html>"
        f2 = _mk("xss-reflected", "MEDIUM", matched_at="https://x.com/a")
        f2.path = "/a"
        f2.response = "<html>2</html>"
        return len(_dedupe([f1, f2])) == 2

    def _mk_load_targets_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt",
                                            delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example\r\n"
                     b"b.example  # inline comment\r\n"
                     b"\r\n"
                     b"# full line comment\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_targets(tmp)
            return (loaded == ["https://a.example", "https://b.example"])
        finally:
            tmp.unlink(missing_ok=True)

    def _mk_no_global_mutation() -> bool:
        """v3.1: PROFILES must not be mutated by effective_profile derivation."""
        before = dict(PROFILES["standard"])
        _eff = dict(PROFILES["standard"])
        _eff["severities"] = ["critical"]
        # PROFILES must be untouched
        return PROFILES["standard"] == before

    def _mk_build_minimal_honors_override() -> bool:
        """v3.1: minimal cmd must contain the user's severity override."""
        eff = dict(PROFILES["standard"])
        eff["severities"] = ["critical"]
        cmd = _build_minimal_cmd(
            Path("/tmp/t"), Path("/tmp/o"),
            rate_limit=5, concurrency=10, timeout=10,
            profile="standard", effective_profile=eff,
        )
        return "critical" in " ".join(cmd) and "high" not in " ".join(cmd)

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",             lambda: CFG_LOADED),
        ("Rune.RAIDO",                lambda: Rune.RAIDO == "ᚱ"),
        ("Severity ranks",            lambda: Severity.CRITICAL.rank == 4),
        ("version is 3.1.0",          lambda: __version__ == "3.1.0"),
        ("Severity.from_rank(4)",     lambda: Severity.from_rank(4) == Severity.CRITICAL),

        ("_host_of works",            lambda: _host_of("https://a.b.com/x") == "a.b.com"),
        ("_host_of empty",            lambda: _host_of("") == ""),
        ("_is_waf_block yes",         lambda: _is_waf_block_response(
                                        "Attention Required! | Cloudflare")),
        ("_is_waf_block no",          lambda: not _is_waf_block_response(
                                        "<html>normal page</html>")),
        ("_severity_of_str crit",     lambda: _severity_of_str("CRITICAL") == Severity.CRITICAL),
        ("_severity_of_str unknown",  lambda: _severity_of_str("weird") == Severity.INFO),
        ("_downgrade CRIT",           lambda: _downgrade_severity("CRITICAL") == "MEDIUM"),
        ("_downgrade HIGH",           lambda: _downgrade_severity("HIGH") == "MEDIUM"),
        ("_severity_from_cvss 9.8",   lambda: _severity_from_cvss(9.8) == "CRITICAL"),
        ("_severity_from_cvss 5",     lambda: _severity_from_cvss(5.0) == "MEDIUM"),
        ("_severity_from_cvss 2",     lambda: _severity_from_cvss(2.0) == "LOW"),

        ("CHAIN_NAMES>=20",           lambda: len(CHAIN_NAMES) >= 20),
        ("CHAIN_SEVERITY>=20",        lambda: len(CHAIN_SEVERITY) >= 20),
        ("PROFILES>=5",               lambda: len(PROFILES) >= 5),

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
        ("_classify_template ssti",   lambda: "nuclei-ssti-candidate" in
                                        _classify_template_to_chains("ssti-jinja")),
        ("_classify_template xxe",    lambda: "nuclei-xxe-candidate" in
                                        _classify_template_to_chains("xxe-file-read")),
        ("_classify_template redirect",lambda: "nuclei-open-redirect" in
                                        _classify_template_to_chains("open-redirect")),
        ("_classify_template crlf",   lambda: "nuclei-crlf-injection" in
                                        _classify_template_to_chains("crlf-injection")),

        ("_apply_chains crit",        lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-critical-finding" in f.chain_ids
                                        )[1])(_mk("test-tpl", "CRITICAL"))),
        ("_apply_chains cve",         lambda: (lambda f: (
                                            _apply_chains(f),
                                            "nuclei-cve-match" in f.chain_ids
                                        )[1])(_mk("cve-2021-44228", "CRITICAL",
                                                    cve_ids=["CVE-2021-44228"]))),
        ("confidence high (CVE)",     lambda: (lambda f: (
                                            _apply_chains(f), f.confidence == "high"
                                        )[1])(_mk("cve-2021-44228", "CRITICAL",
                                                    cve_ids=["CVE-2021-44228"]))),
        ("confidence low (WAF)",      lambda: (lambda f: (
                                            _apply_chains(f), f.confidence == "low"
                                        )[1])(_mk("test-tpl", "HIGH", waf_blocked=True))),

        ("_build_host_chains empty",  lambda: _build_host_chains([]) == []),
        ("_build_host_chains multi",  lambda: any(
                                            c["chain_id"] == "nuclei-multi-finding-host"
                                            for c in _build_host_chains([
                                                _mk("cve-2021-44228", "CRITICAL",
                                                     cve_ids=["CVE-2021-44228"]),
                                                _mk("default-login-ftp", "CRITICAL"),
                                                _mk("exposed-env", "HIGH"),
                                            ]))),

        ("_headers_for_nuclei empty", lambda: _headers_for_nuclei(None, None)[0] == []),
        ("_headers_for_nuclei extra", lambda: any("X-Test" in h for h in
                                            _headers_for_nuclei(None,
                                                {"X-Test": "yes"})[0])),
        ("_headers_for_nuclei has_ua", lambda: _headers_for_nuclei(None,
                                            {"User-Agent": "TestUA"})[1] is True),
        ("_headers_for_nuclei drops empty", lambda: not any(
                                            h.strip() == "X-Empty:" for h in
                                            _headers_for_nuclei(None,
                                                {"X-Empty": ""})[0])),

        ("_build_cmd accepts resume kwarg",  lambda: _mk_no_resume_crash()),
        ("_build_cmd silences unknown kwarg",
                                       lambda: _mk_unknown_kwarg_silenced()),
        ("_build_cmd returns list",   lambda: isinstance(
                                        _build_cmd(Path("/tmp/t"), Path("/tmp/o"),
                                                    rate_limit=5, concurrency=10,
                                                    bulk_size=5, timeout=10,
                                                    retries=1, profile="standard"),
                                        list)),
        ("_run_batch has batch_timeout param", lambda: "batch_timeout" in
                                        inspect.signature(_run_batch).parameters),
        ("_build_minimal_cmd honors override",  lambda: _mk_build_minimal_honors_override()),

        ("_heuristic_triage empty",   lambda: _heuristic_triage(
                                            HostResult(host="x.com"))["host_risk"] == "INFO"),
        ("_heuristic_triage crit",    lambda: _heuristic_triage(HostResult(
                                            host="x.com",
                                            findings=[_mk("cve-2021-44228",
                                                            "CRITICAL",
                                                            cve_ids=["CVE-2021-44228"])]
                                        ))["host_risk"] == "CRITICAL"),
        ("_heuristic_triage WAF downgrades", lambda: _mk_waf_downgrade()),
        ("_suggest_confirmation cve", lambda: "cve" in _suggest_confirmation(
                                            _mk("cve-2021-44228",
                                                 cve_ids=["CVE-2021-44228"])).lower()),
        ("_suggest_confirmation ssti", lambda: "ssti" in _suggest_confirmation(
                                            _mk("ssti-jinja")).lower()),
        ("_suggest_confirmation xxe",  lambda: "xxe" in _suggest_confirmation(
                                            _mk("xxe-file-read")).lower()),

        ("_ai_cache_dir callable",    lambda: callable(_ai_cache_dir)),
        ("_ai_cache_key stable",      lambda: _mk_cache_stability()),
        ("_ai_cache_key model bust",  lambda: _mk_cache_model_busts()),
        ("_ai_cache_key different host", lambda: _ai_cache_key(
                                            "a.com", [_mk("cve-2021-44228")]) !=
                                        _ai_cache_key(
                                            "b.com", [_mk("cve-2021-44228")])),
        ("_ai_cost_guard unlimited",  lambda: _ai_cost_guard(0.01, 0.0) is True),
        ("_ai_cost_guard allows small", lambda: _ai_cost_guard(0.001, 100.0) is True),
        ("_ai_cost_guard blocks over",lambda: _ai_cost_guard(1.0, 0.01) is False
                                        or _cfg("AI_COSTS") is None),
        ("_validate_ai_triage ok",    lambda: _validate_ai_triage({
                                            "summary": "x", "host_risk": "HIGH",
                                            "real_vs_noise": "x",
                                            "next_actions": ["a"]}) is True),
        ("_validate_ai_triage rejects",lambda: _validate_ai_triage({
                                            "summary": "x"}) is False),

        ("_dedupe_distinct paths/response", lambda: _mk_dedupe_distinct_paths()),
        ("_load_targets BOM/CRLF",    lambda: _mk_load_targets_bom_crlf()),
        ("_mk_no_global_mutation",    lambda: _mk_no_global_mutation()),
        ("_parse_jsonl end-to-end",   lambda: _mk_end_to_end_parse()),
        ("_parse_jsonl cvss inference", lambda: _mk_cvss_severity_inference()),

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
        ("_nuclei_version callable",  lambda: callable(_nuclei_version)),

        ("run has no_ai param",       lambda: "no_ai" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has ai_max_cost_usd",   lambda: "ai_max_cost_usd" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has ai_cache_ttl_hours",lambda: "ai_cache_ttl_hours" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has no_interactsh",     lambda: "no_interactsh" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has batch_timeout",     lambda: "batch_timeout" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has min_severity",      lambda: "min_severity" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has on_progress",       lambda: "on_progress" in
                                        inspect.signature(run_nuclei_scan).parameters),
        ("run has ai_parallel",       lambda: "ai_parallel" in
                                        inspect.signature(run_nuclei_scan).parameters),
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

    log.info("")
    log.info("v3.1 config defaults:")
    log.info(f"  NUCLEI_NO_INTERACTSH    : {_cfg('NUCLEI_NO_INTERACTSH', True)}")
    log.info(f"  NUCLEI_INTERACTSH_URL   : {_cfg('NUCLEI_INTERACTSH_URL', None)}")
    log.info(f"  NUCLEI_PAGE_TIMEOUT     : {_cfg('NUCLEI_PAGE_TIMEOUT', None)}")
    log.info(f"  NUCLEI_EXCLUDE_MATCHERS : {_cfg('NUCLEI_EXCLUDE_MATCHERS', [])}")
    log.info(f"  NUCLEI_USE_TIER2_FLAGS  : {_cfg('NUCLEI_USE_TIER2_FLAGS', False)}")

    log.info("")
    log.info(f"nuclei           : {'present' if shutil.which('nuclei') else 'NOT FOUND'}")
    if shutil.which("nuclei"):
        log.info(f"nuclei version   : {_nuclei_version()}")

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
#  ᛞ  SMOKE TEST — v3.1
# ══════════════════════════════════════════════════════════════════════════

def smoke_test(args: argparse.Namespace) -> int:
    print_banner()
    log.rune(Rune.HAGALAZ, "SMOKE TEST — verifying nuclei flag compatibility")

    if not shutil.which("nuclei"):
        log.error("nuclei not found in PATH")
        return 1

    log.info(f"  nuclei version: {_nuclei_version()}")

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


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  CLI — v3.1 (duplicate --no-omit-raw REMOVED)
# ══════════════════════════════════════════════════════════════════════════

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

    # v3.0 AI + nuclei flags
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

    # v3.1 additions
    p.add_argument("--batch-timeout", type=int, default=None,
                    help="per-batch nuclei timeout in seconds "
                         "(default: hard_timeout / num_batches, min 900)")
    p.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    default=None, help="drop findings below this severity")
    p.add_argument("--max-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    default=None, help="drop findings above this severity")
    p.add_argument("--ai-parallel", action="store_true",
                    help="parallelize AI triage across hosts (thread pool)")
    p.add_argument("--ai-workers", type=int, default=AI_DEFAULT_MAX_WORKERS,
                    help="max parallel AI workers when --ai-parallel is set")
    p.add_argument("--quiet", action="store_true",
                    help="suppress banner and per-host logging (report still written)")
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
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color:
        try:
            CFG.Palette._enabled = False  # type: ignore[attr-defined]
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

    if not args.quiet:
        print_banner()

    sev: Optional[list[str]] = None
    if args.severities:
        sev = [s.strip().lower() for s in args.severities.split(",") if s.strip()]

    tags: Optional[list[str]] = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    # Interactsh resolution — explicit --enable-interactsh wins
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
            # v3.0
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
            # v3.1
            batch_timeout=args.batch_timeout,
            min_severity=args.min_severity,
            max_severity=args.max_severity,
            ai_parallel=args.ai_parallel,
            ai_max_workers=args.ai_workers,
            quiet=args.quiet,
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
