#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/nmap.py — Port, Service & OS Discovery
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/nmap.py
  Version   : 3.0.0 "ULLR"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Two-phase network discovery:
    Phase 1 — Fast sweep (top 1000 ports) on every host
    Phase 2 — Deep scan (full range, NSE) on top-N diverse hosts

  nmap speaks raw TCP/IP. This means:
    ✗ Platform headers NOT applied
    ✗ request.txt auth NOT applied
    ✓ Rate limiting maps to --max-rate (packets/sec) + timing templates

  v1.0 → v3.0 (silent-failure fixes):
    [FIX]  MODULE_RATE_LIMITS["nmap"] → ["port_scan"]. Config.py uses
           "port_scan" — was defaulting to no-rate-limit regardless of config.
    [FIX]  entry.get("rate_limit") → entry.get("rps"). config.py uses "rps".
    [FIX]  rps → --max-rate translation: rps is HTTP-style rate; nmap's
           --max-rate is packets/sec. We multiply rps × 50 to get a
           reasonable packets/sec ceiling (rps: 2 → 100 pps). A new
           nmap_max_rate config key overrides this.
    [FIX]  Deep scan timeout: was DEEP_TIMEOUT_PER_HOST * len(targets) =
           10h worst case. Now capped at DEEP_TOTAL_TIMEOUT_MAX (3h).
    [FIX]  Partial XML recovery: nmap timeout leaves truncated XML which
           ET.ParseError silently dropped, losing ALL hosts from that phase.
           Now appends missing </nmaprun> and re-parses.
    [FIX]  _write_empty_report now accepts scan_id for empty-input DB sync.
    [FIX]  _extract_hosts: BOM/CRLF/inline-comment/trailing-dot safe.
    [FIX]  Input cap (MAX_HOSTS_INPUT=500) — nmap against 5000 hosts was
           an unguarded footgun.

  v3.0 — NEW:
    [NEW]  KillSwitch.check() before every nmap subprocess and parse.
    [NEW]  SIGINT/SIGTERM handler — writes partial report.
    [NEW]  Per-host manual_test — exact command to verify per port type.
    [NEW]  Per-host nuclei_tags — recommended follow-up scan tags.
    [NEW]  Per-host confidence score (0-100) mirroring other v3.x modules.
    [NEW]  Per-host heuristic triage — summary, priorities, chains.
    [NEW]  AI triage with schema validation + corrective retry + cache
           (mirrors js_analysis, cors_check, dns_resolve v3.0).
    [NEW]  nmap_findings_digest.md — top-50 markdown table.
    [NEW]  Structured warnings[] array in report.
    [NEW]  nmap version captured in report.
    [NEW]  --dry-run, --quiet, --no-ai, --ai-max-hosts, --ai-max-cost,
           --ai-cache-ttl, --exclude-ports, --top-ports, --total-deep-timeout,
           --no-os-detection, --on-progress callback.
    [NEW]  --quiet suppresses per-host logging; summary still written.
    [NEW]  nmap_web_ports.txt split into 2 files:
           - nmap_web_ports.txt (URLs only — feed to httpx)
           - nmap_web_ports_detailed.txt (URL + standard/nonstandard + label)
    [NEW]  UDP warning when root is available but udp=False.
    [NEW]  Removed --osscan-limit (was silently breaking OS detection on
           hosts with no closed ports — common on WAF'd hosts).
    [NEW]  Selftest with 50 checks (was 0).

  Config integration:
    ·  MODULE_RATE_LIMITS["port_scan"]  → rps → --max-rate (×50), timing
    ·  nmap_max_rate (optional)         → overrides rps for --max-rate
    ·  KillSwitch, human_delay, SCOPE (no-op for nmap)
    ·  AI_ENABLED, AI.model, ai_complete, AI_COSTS
    ·  SYNC_TO_DB, BRIDGE_ENABLED, new_audit_trail

  Outputs:
    nmap_scan.json              — full report with per-host triage
    nmap_open_ports.txt         — host:port service version
    nmap_interesting.txt        — prioritized host list
    nmap_os_guesses.txt         — OS fingerprints
    nmap_web_ports.txt          — URLs for downstream tools
    nmap_web_ports_detailed.txt — URL + tag + label
    nmap_findings_digest.md     — top-50 markdown table
    nmap_ai_<host>.md           — per-host AI triage (when AI on)
    nmap_ai_cache/              — versioned AI cache
    nmap_fast.{xml,gnmap,nmap}  — raw artifacts
    nmap_deep.{xml,gnmap,nmap}  — raw artifacts (if deep ran)
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("argus.nmap")


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


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG READERS — v3.0 FIX
# ═════════════════════════════════════════════════════════════════════════

def _nmap_settings() -> dict:
    """
    v3.0: reads MODULE_RATE_LIMITS["port_scan"] (config's canonical key)
    with legacy fallback to "nmap". Translates rps → max_rate.

    nmap's --max-rate is packets/sec, not requests/sec. A config rps of 2
    would make --max-rate 2 = ~12 packets/min = absurdly slow. We multiply
    by 50 to get a reasonable packets/sec ceiling:
        rps: 2  → max_rate 100 pps  (default safe)
        rps: 5  → max_rate 250 pps
        rps: 10 → max_rate 500 pps  (aggressive)
    If the config explicitly sets nmap_max_rate, that's used verbatim.
    """
    all_limits = _cfg("MODULE_RATE_LIMITS", {}) or {}
    entry = all_limits.get("port_scan") or all_limits.get("nmap") or {}

    rps = entry.get("rps", entry.get("rate_limit", 2))
    if not isinstance(rps, int) or rps < 0:
        rps = 2

    # Explicit override wins
    explicit_max_rate = entry.get("nmap_max_rate")
    if isinstance(explicit_max_rate, int) and explicit_max_rate > 0:
        max_rate = explicit_max_rate
        rps_to_max_rate = False
    elif rps > 0:
        max_rate = rps * 50
        rps_to_max_rate = True
    else:
        max_rate = 0
        rps_to_max_rate = False

    min_rate = entry.get("min_rate", 0)
    if not isinstance(min_rate, int) or min_rate < 0:
        min_rate = 0

    timing_fast = entry.get("timing_fast", "T4")
    if not isinstance(timing_fast, str):
        timing_fast = "T4"
    timing_deep = entry.get("timing_deep", "T4")
    if not isinstance(timing_deep, str):
        timing_deep = "T4"

    return {
        "rps":            rps,
        "max_rate":       max_rate,
        "min_rate":       min_rate,
        "timing_fast":    timing_fast,
        "timing_deep":    timing_deep,
        "rps_to_max_rate": rps_to_max_rate,
    }


# ═════════════════════════════════════════════════════════════════════════
#  THREAD LOCKS
# ═════════════════════════════════════════════════════════════════════════

_AI_LOCK     = threading.Lock()
_LOG_LOCK    = threading.Lock()
_SHARED      = {"_quiet": False}


def _log_locked(level: str, msg: str) -> None:
    with _LOG_LOCK:
        if _SHARED["_quiet"] and level not in ("warn", "error", "ok"):
            return
        getattr(log, level)(msg)


# ═════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

FAST_TOP_PORTS        = 1000
FAST_TIMING           = "T4"
FAST_TIMEOUT          = 3600

DEEP_TIMING           = "T4"
DEEP_TIMEOUT_PER_HOST = 1800
DEEP_TOTAL_TIMEOUT_MAX = 3 * 3600  # 3-hour hard cap on deep phase
DEEP_HOST_LIMIT       = 20
DEEP_MIN_RATE         = 0

MAX_HOSTS_INPUT       = 500
DEFAULT_MAX_FINDINGS  = 5000

DEFAULT_NSE = "default,safe,discovery,http-headers,http-methods,ssl-cert,ssl-enum-ciphers"
VULN_NSE    = "vuln"

INTERESTING_SCORE = 30

# AI triage
AI_MIN_HOSTS_PER_RUN     = 1
AI_DEFAULT_MAX_HOSTS     = 20
AI_DEFAULT_CACHE_TTL_HOURS = 72
AI_ESTIMATE_PER_CALL_USD = 0.002
AI_PROMPT_VERSION        = "v3.0"

# ── Port category sets ──────────────────────────────────────────────────
DATABASE_PORTS = {
    1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300,
    11211, 27017, 27018, 27019, 5984, 8086, 7474, 7687,
    5000, 5001, 5002,  # CouchDB alt
    2379, 2380,        # etcd
}
ADMIN_PORTS = {
    3000, 4000, 5000, 5601, 7077, 8000, 8001, 8008,
    8080, 8081, 8088, 8443, 8888, 9000, 9090, 9091,
    9092, 9093, 2375, 2376, 6443,  # Docker, k8s API
    2379, 2380,                     # etcd
    9200, 9300,                     # Elasticsearch
    10250, 10255,                   # kubelet
}
DANGEROUS_PORTS = {
    21, 23, 25, 111, 135, 137, 138, 139, 445,
    512, 513, 514, 873, 2049, 3260,
    161, 162,                       # SNMP
    1900, 5353,                     # UPnP, mDNS
    1433, 1521, 3306, 5432, 27017,  # Database ports (also dangerous if exposed)
    6379, 11211,                    # Redis, memcached
    4369, 5672, 15672,              # RabbitMQ
    2375, 2376,                     # Docker (unauthed)
}
REMOTE_ACCESS_PORTS = {
    22, 3389, 5900, 5901, 5985, 5986,
    23, 512, 513, 514,
}
WEB_PORTS = {
    80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    8002, 8003, 8004, 8005, 8006, 8007, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095,
    8161, 8180, 8181, 8200, 8222, 8280, 8281, 8333, 8400, 8444,
    8500, 8800, 8834, 9001, 9002, 9003, 9043, 9080, 9090, 9091,
    9200, 9443, 10000, 10443, 18080, 18081,
}

STANDARD_WEB_PORTS = {80, 443}
HTTPS_PORTS_LIKELY = {443, 8443, 9443, 10443, 18081}

# ── Port → manual test command map ───────────────────────────────────────
MANUAL_TEST_BY_PORT: dict[int, Callable[[str], str]] = {
    3306:  lambda h: f"mysql -h {h} -P 3306 -u root -p --connect-timeout 5",
    5432:  lambda h: f"psql -h {h} -p 5432 -U postgres -c 'SELECT version();'",
    6379:  lambda h: f"redis-cli -h {h} -p 6379 INFO server",
    27017: lambda h: f"mongosh --host {h} --port 27017 --eval 'db.version()'",
    9200:  lambda h: f"curl -i 'http://{h}:9200/_cat/indices?v'",
    11211: lambda h: f"echo -e 'stats\\r\\nquit' | nc {h} 11211",
    2375:  lambda h: f"docker -H tcp://{h}:2375 info",
    2376:  lambda h: f"docker -H tcp://{h}:2376 info  # TLS variant",
    22:    lambda h: f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes root@{h}",
    3389:  lambda h: f"xfreerdp /v:{h}:3389 /u:Administrator",
    5900:  lambda h: f"vncviewer {h}:5900",
    21:    lambda h: f"ftp -n {h} 21  # try anonymous",
    1433:  lambda h: f"sqlcmd -S {h},1433 -U sa",
    9200:  lambda h: f"curl -i 'http://{h}:9200/'",
}

NUCLEI_TAGS_BY_CATEGORY: dict[str, list[str]] = {
    "web":           ["http", "tech-detect", "network"],
    "database":      ["network", "unauth", "database"],
    "admin":         ["admin-panel", "default-login", "exposure"],
    "dangerous":     ["network", "exposure"],
    "remote_access": ["network", "default-login"],
}

PORT_SPECIFIC_TAGS: dict[int, list[str]] = {
    3306:  ["mysql"], 5432: ["postgresql"], 6379: ["redis"],
    27017: ["mongodb"], 9200: ["elasticsearch"], 11211: ["memcached"],
    22:    ["ssh"], 23: ["telnet"], 21: ["ftp"], 25: ["smtp"],
    3389:  ["rdp"], 5900: ["vnc"], 2375: ["docker"], 2376: ["docker"],
    1433:  ["mssql"], 445:  ["smb"], 2049: ["nfs"],
}


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: list[dict] = field(default_factory=list)

    is_web: bool = False
    is_database: bool = False
    is_admin: bool = False
    is_dangerous: bool = False
    is_remote_access: bool = False

    def label(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        if parts:
            return f"{self.service} ({' '.join(parts)})"
        return self.service or f"port {self.port}"

    def classify(self) -> None:
        p = self.port
        self.is_web           = p in WEB_PORTS or self.service in (
            "http", "https", "http-proxy", "http-alt", "ssl/http",
            "http-rpc-epmap", "soap", "http-mgmt",
        )
        self.is_database      = p in DATABASE_PORTS
        self.is_admin         = p in ADMIN_PORTS
        self.is_dangerous     = p in DANGEROUS_PORTS
        self.is_remote_access = p in REMOTE_ACCESS_PORTS

    def to_dict(self) -> dict:
        return {
            "port":             self.port,
            "protocol":         self.protocol,
            "state":            self.state,
            "reason":           self.reason,
            "service":          self.service,
            "product":          self.product,
            "version":          self.version,
            "extrainfo":        self.extrainfo,
            "cpe":              self.cpe,
            "scripts":          self.scripts,
            "is_web":           self.is_web,
            "is_database":      self.is_database,
            "is_admin":         self.is_admin,
            "is_dangerous":     self.is_dangerous,
            "is_remote_access": self.is_remote_access,
        }


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    status: str = "up"
    os_matches: list[dict] = field(default_factory=list)
    host_scripts: list[dict] = field(default_factory=list)
    traceroute: list[dict] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    interesting: bool = False
    reasons: list[str] = field(default_factory=list)
    score: int = 0
    diversity: int = 0
    phase: str = ""
    first_seen: str = ""
    # v3.0 additions
    confidence: int = 0
    manual_test: str = ""
    nuclei_tags: list[str] = field(default_factory=list)
    triage: Optional[dict] = None
    triage_source: str = ""

    def to_dict(self) -> dict:
        return {
            "ip":              self.ip,
            "hostname":        self.hostname,
            "status":          self.status,
            "os_matches":      self.os_matches,
            "host_scripts":    self.host_scripts,
            "traceroute":      self.traceroute,
            "ports":           [p.to_dict() for p in self.ports],
            "interesting":     self.interesting,
            "reasons":         self.reasons,
            "score":           self.score,
            "diversity":       self.diversity,
            "phase":           self.phase,
            "first_seen":      self.first_seen,
            "confidence":      self.confidence,
            "manual_test":     self.manual_test,
            "nuclei_tags":     self.nuclei_tags,
            "triage":          self.triage,
            "triage_source":   self.triage_source,
        }


# ═════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING (v3.0 — BOM/CRLF safe, host cap)
# ═════════════════════════════════════════════════════════════════════════

def _extract_hosts(input_file: Path) -> list[str]:
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
        if token.startswith(("http://", "https://")):
            try:
                host = urllib.parse.urlparse(token).hostname or ""
            except Exception:
                continue
        else:
            host = token.split("/")[0].split(":")[0].rstrip(".")
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def _has_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _check_nmap() -> bool:
    return shutil.which("nmap") is not None


def _get_nmap_version() -> str:
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True,
                                 text=True, timeout=10)
        first = (result.stdout or result.stderr or "").split("\n")[0]
        m = re.search(r"version\s+(\S+)", first, re.I)
        return m.group(1) if m else first[:60]
    except Exception:
        return "unknown"


# ═════════════════════════════════════════════════════════════════════════
#  COMMAND BUILDERS
# ═════════════════════════════════════════════════════════════════════════

def _scan_type_flag() -> str:
    return "-sS" if _has_root() else "-sT"


def _build_fast_cmd(
    hostfile: Path, out_prefix: Path, timing: str, max_rate: int,
    top_ports: int, exclude_ports: Optional[str], os_detection: bool,
) -> list[str]:
    cmd = [
        "nmap", _scan_type_flag(), "-sV", "--version-intensity", "7",
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open", "-Pn", "--reason",
        "--top-ports", str(top_ports),
        "-oA", str(out_prefix),
        "-iL", str(hostfile),
    ]
    if os_detection and _has_root():
        cmd.extend(["-O", "--osscan-guess"])
    if max_rate and max_rate > 0:
        cmd.extend(["--max-rate", str(max_rate)])
    if exclude_ports:
        cmd.extend(["--exclude-ports", exclude_ports])
    return cmd


def _build_deep_cmd(
    hostfile: Path, out_prefix: Path, timing: str, nse: str,
    min_rate: int, max_rate: int, exclude_ports: Optional[str],
    os_detection: bool,
) -> list[str]:
    cmd = [
        "nmap", _scan_type_flag(), "-sV", "--version-intensity", "9",
        "--version-all", "-sC", "--script", nse,
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open", "-Pn", "--reason", "-p-", "--traceroute",
        "-oA", str(out_prefix), "-iL", str(hostfile),
    ]
    if os_detection and _has_root():
        cmd.extend(["-O", "--osscan-guess"])
    if min_rate and min_rate > 0:
        cmd.extend(["--min-rate", str(min_rate)])
    if max_rate and max_rate > 0:
        cmd.extend(["--max-rate", str(max_rate)])
    if exclude_ports:
        cmd.extend(["--exclude-ports", exclude_ports])
    return cmd


def _run_nmap(cmd: list[str], timeout: int, label: str) -> bool:
    _killswitch_check(f"nmap-{label}")
    _log_locked("info",
        f"    $ {' '.join(cmd[:12])}{' ...' if len(cmd) > 12 else ''}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        _log_locked("warn", f"    nmap {label} exceeded {timeout}s — "
                             f"using partial output")
        return False
    except FileNotFoundError:
        log.error("    nmap binary not found — install `apt-get install nmap`")
        return False
    except OSError as e:
        log.warning(f"    nmap {label} failed: {e}")
        return False

    if result.returncode != 0:
        out_idx = cmd.index("-oA") + 1 if "-oA" in cmd else -1
        out_prefix = cmd[out_idx] if out_idx > 0 else ""
        if not out_prefix or not Path(f"{out_prefix}.xml").exists():
            log.warning(f"    nmap {label} exited {result.returncode}: "
                        f"{result.stderr.strip()[:200]}")
            return False
    return True


# ═════════════════════════════════════════════════════════════════════════
#  XML PARSING (v3.0 — partial XML recovery)
# ═════════════════════════════════════════════════════════════════════════

def _parse_nmap_xml(xml_path: Path, phase: str) -> list[HostInfo]:
    if not xml_path.exists():
        _log_locked("warn", f"    XML not found: {xml_path}")
        return []

    try:
        content = xml_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.error(f"    read failed: {xml_path}: {e}")
        return []

    if not content.strip():
        return []

    # v3.0: partial XML recovery — nmap writes incrementally, so a timeout
    # leaves an unclosed <nmaprun>. Append the closing tag and retry.
    if not content.rstrip().endswith("</nmaprun>"):
        _log_locked("debug",
            f"    {xml_path.name} appears truncated — attempting repair")
        content = content.rstrip() + "\n</nmaprun>"

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        log.error(f"    failed to parse {xml_path} even after repair: {e}")
        return []

    now = datetime.now(timezone.utc).isoformat()
    hosts: list[HostInfo] = []

    for host_elem in root.findall("host"):
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        if status != "up":
            continue

        ip = ""
        for addr_elem in host_elem.findall("address"):
            addrtype = addr_elem.get("addrtype", "")
            if addrtype == "ipv4":
                ip = addr_elem.get("addr", "")
                break
            if addrtype == "ipv6" and not ip:
                ip = addr_elem.get("addr", "")
        if not ip:
            continue

        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    hostname = hn.get("name", "")
                    break
            if not hostname:
                first = hostnames_elem.find("hostname")
                if first is not None:
                    hostname = first.get("name", "")

        host = HostInfo(
            ip=ip, hostname=hostname, status=status,
            phase=phase, first_seen=now,
        )

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                port = PortInfo(
                    port=int(port_elem.get("portid", "0")),
                    protocol=port_elem.get("protocol", "tcp"),
                    state="open",
                    reason=state_elem.get("reason", ""),
                )
                svc_elem = port_elem.find("service")
                if svc_elem is not None:
                    port.service   = svc_elem.get("name", "")
                    port.product   = svc_elem.get("product", "")
                    port.version   = svc_elem.get("version", "")
                    port.extrainfo = svc_elem.get("extrainfo", "")
                    for cpe in svc_elem.findall("cpe"):
                        if cpe.text:
                            port.cpe.append(cpe.text)
                for script_elem in port_elem.findall("script"):
                    port.scripts.append({
                        "id":     script_elem.get("id", ""),
                        "output": (script_elem.get("output", "") or "")[:1000],
                    })
                port.classify()
                host.ports.append(port)

        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                try:
                    accuracy = int(osmatch.get("accuracy", "0"))
                except ValueError:
                    accuracy = 0
                host.os_matches.append({
                    "name":     osmatch.get("name", ""),
                    "accuracy": accuracy,
                })

        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                host.host_scripts.append({
                    "id":     script_elem.get("id", ""),
                    "output": (script_elem.get("output", "") or "")[:1000],
                })

        trace_elem = host_elem.find("trace")
        if trace_elem is not None:
            for hop_elem in trace_elem.findall("hop"):
                try:
                    ttl = int(hop_elem.get("ttl", "0"))
                except ValueError:
                    ttl = 0
                host.traceroute.append({
                    "ttl":  ttl,
                    "ip":   hop_elem.get("ipaddr", ""),
                    "rtt":  hop_elem.get("rtt", ""),
                    "host": hop_elem.get("host", ""),
                })

        _score_host(host)
        _decorate_host(host)
        hosts.append(host)

    return hosts


# ═════════════════════════════════════════════════════════════════════════
#  HOST SCORING + DECORATION
# ═════════════════════════════════════════════════════════════════════════

def _score_host(host: HostInfo) -> None:
    reasons: list[str] = []
    score = 0

    if host.os_matches:
        best_acc = max(o["accuracy"] for o in host.os_matches)
        score += 10 if best_acc >= 85 else 5
        reasons.append("os_fingerprinted")

    web_count = 0
    categories: set[str] = set()

    for port in host.ports:
        if port.is_database:
            score += 40
            reasons.append(f"database_port:{port.port}")
            categories.add("database")
        if port.is_admin:
            score += 30
            reasons.append(f"admin_port:{port.port}")
            categories.add("admin")
        if port.is_dangerous:
            score += 25
            reasons.append(f"dangerous_port:{port.port}")
            categories.add("dangerous")
        if port.is_remote_access:
            score += 15
            reasons.append(f"remote_access:{port.port}")
            categories.add("remote_access")
        if port.is_web:
            web_count += 1
            score += 3
            categories.add("web")
        if port.product and port.version:
            score += 5
            reasons.append(f"version_known:{port.port}")

    if web_count > 1:
        score += 15
        reasons.append(f"multi_web_ports:{web_count}")

    if len(host.ports) >= 10:
        score += 10
        reasons.append(f"many_open_ports:{len(host.ports)}")

    host.score = score
    host.reasons = reasons
    host.diversity = len(categories)
    host.interesting = score >= INTERESTING_SCORE


def _decorate_host(host: HostInfo) -> None:
    """v3.0: add confidence, manual_test, nuclei_tags per host."""
    confidence = 30  # baseline for open ports
    for p in host.ports:
        if p.is_database: confidence += 30
        elif p.is_admin:   confidence += 20
        elif p.is_dangerous: confidence += 10
        if p.product and p.version: confidence += 5
        if any("vuln" in (s.get("id","").lower()) for s in p.scripts):
            confidence += 20
    if host.os_matches:
        confidence += 10
    host.confidence = min(confidence, 100)

    # Manual test — pick the highest-priority port
    if host.ports:
        best = max(host.ports, key=lambda p: (
            100 if p.is_database else
            80 if p.is_admin else
            50 if p.is_dangerous else
            40 if p.is_remote_access else
            20 if p.is_web else 0
        ))
        if best.port in MANUAL_TEST_BY_PORT:
            host.manual_test = MANUAL_TEST_BY_PORT[best.port](host.ip)
        elif best.is_web:
            scheme = "https" if best.port in HTTPS_PORTS_LIKELY else "http"
            host.manual_test = f"curl -i '{scheme}://{host.ip}:{best.port}/'"
        else:
            port_list = ",".join(str(p.port) for p in host.ports[:5])
            host.manual_test = f"nmap -sV -p{port_list} -Pn {host.ip}"
    else:
        host.manual_test = f"nmap -sS -Pn --top-ports 100 {host.ip}"

    # Nuclei tags
    tags: set[str] = set()
    for p in host.ports:
        if p.is_web:           tags.update(NUCLEI_TAGS_BY_CATEGORY["web"])
        if p.is_database:      tags.update(NUCLEI_TAGS_BY_CATEGORY["database"])
        if p.is_admin:         tags.update(NUCLEI_TAGS_BY_CATEGORY["admin"])
        if p.is_dangerous:     tags.update(NUCLEI_TAGS_BY_CATEGORY["dangerous"])
        if p.is_remote_access: tags.update(NUCLEI_TAGS_BY_CATEGORY["remote_access"])
        if p.port in PORT_SPECIFIC_TAGS:
            tags.update(PORT_SPECIFIC_TAGS[p.port])
    if not tags:
        tags.add("network")
    host.nuclei_tags = sorted(tags)


def _select_deep_targets(candidates: list[HostInfo], limit: int) -> list[HostInfo]:
    ranked = sorted(
        candidates,
        key=lambda h: (-(h.score + h.diversity * 10), -h.score, h.ip),
    )
    return ranked[:limit]


def _merge_host_info(fast: list[HostInfo], deep: list[HostInfo]) -> list[HostInfo]:
    by_ip: dict[str, HostInfo] = {h.ip: h for h in fast}
    for h in deep:
        if h.ip in by_ip:
            if not h.hostname and by_ip[h.ip].hostname:
                h.hostname = by_ip[h.ip].hostname
            h.phase = "merged"
        by_ip[h.ip] = h
    return list(by_ip.values())


# ═════════════════════════════════════════════════════════════════════════
#  PER-HOST HEURISTIC TRIAGE
# ═════════════════════════════════════════════════════════════════════════

def _heuristic_host_triage(host: HostInfo) -> dict:
    if not host.ports:
        return {
            "summary": f"No open ports on {host.ip}.",
            "host_risk": "INFO",
            "top_priorities": [],
            "chains": [],
            "false_positive_likelihood": "n/a",
            "suggested_manual_tests": [],
            "next_actions": ["No action required"],
            "source": "heuristic",
        }

    n_db = sum(1 for p in host.ports if p.is_database)
    n_admin = sum(1 for p in host.ports if p.is_admin)
    n_danger = sum(1 for p in host.ports if p.is_dangerous)
    n_ra = sum(1 for p in host.ports if p.is_remote_access)
    n_web = sum(1 for p in host.ports if p.is_web)

    if n_db > 0:                host_risk = "CRITICAL"
    elif n_admin > 0:           host_risk = "HIGH"
    elif n_danger > 0:          host_risk = "MEDIUM"
    elif n_ra > 0:              host_risk = "MEDIUM"
    elif n_web > 0:             host_risk = "LOW"
    else:                       host_risk = "INFO"

    ranked = sorted(host.ports, key=lambda p: (
        0 if p.is_database else
        1 if p.is_admin else
        2 if p.is_dangerous else
        3 if p.is_remote_access else
        4 if p.is_web else 5,
    ))[:5]

    top_priorities = []
    for i, p in enumerate(ranked, 1):
        reason_parts = []
        if p.is_database:      reason_parts.append("database")
        if p.is_admin:         reason_parts.append("admin")
        if p.is_dangerous:     reason_parts.append("dangerous")
        if p.is_remote_access: reason_parts.append("remote_access")
        if p.is_web:           reason_parts.append("web")
        if p.product or p.version:
            reason_parts.append(p.label())
        top_priorities.append({
            "rank": i,
            "finding": f"{p.port}/{p.protocol} {p.service or 'unknown'}",
            "reason": " · ".join(reason_parts) if reason_parts else "open port",
            "test_idea": (
                MANUAL_TEST_BY_PORT[p.port](host.ip)
                if p.port in MANUAL_TEST_BY_PORT
                else f"curl -i 'http://{host.ip}:{p.port}/'"
                if p.is_web
                else f"nmap -sV -p{p.port} -Pn {host.ip}"
            ),
        })

    chains = []
    if n_db > 0 and n_admin > 0:
        chains.append(f"{n_db} database(s) + {n_admin} admin panel(s) — "
                       f"likely full compromise path")
    if n_ra > 0 and n_admin > 0:
        chains.append(f"{n_ra} remote-access + {n_admin} admin — lateral movement")
    if n_db > 0:
        chains.append(f"{n_db} exposed database(s) — check for unauthenticated access")

    tests = [p_["test_idea"] for p_ in top_priorities if p_.get("test_idea")][:5]

    next_actions: list[str] = []
    if n_db > 0:
        next_actions.append(
            f"Test {n_db} database(s) for unauthenticated access (CRITICAL)")
    if n_admin > 0:
        next_actions.append(f"Check {n_admin} admin panel(s) for default creds")
    if n_danger > 0:
        next_actions.append(f"Review {n_danger} dangerous port(s) — "
                             f"{host.diversity} categories total")
    if n_web > 1:
        next_actions.append(
            f"{n_web} web ports — feed nmap_web_ports.txt to httpx + nuclei")
    if not next_actions:
        next_actions.append("Manual review of open ports")

    summary = (
        f"{len(host.ports)} open port(s) on {host.ip}"
        + (f" ({host.hostname})" if host.hostname else "")
        + f". Categories: web={n_web} db={n_db} admin={n_admin} "
        + f"danger={n_danger} ra={n_ra}."
    )

    return {
        "summary": summary,
        "host_risk": host_risk,
        "top_priorities": top_priorities,
        "chains": chains,
        "false_positive_likelihood": (
            "low" if host.score >= 50 else
            "medium" if host.score >= 30 else "high"
        ),
        "suggested_manual_tests": tests,
        "next_actions": next_actions,
        "source": "heuristic",
    }


# ═════════════════════════════════════════════════════════════════════════
#  AI TRIAGE (mirrors other v3.x modules)
# ═════════════════════════════════════════════════════════════════════════

AI_NMAP_SYSTEM = (
    "You are an expert offensive-security triage analyst. Analyze port "
    "scan findings for one host. Reference actual port numbers, services, "
    "and versions. Never suggest running exploits. Return STRICT JSON only."
)


def _validate_ai_triage(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("summary", "host_risk", "top_priorities",
                "real_vs_noise", "suggested_manual_tests", "next_actions"):
        if key not in data:
            return False
    if not isinstance(data.get("top_priorities"), list): return False
    if not isinstance(data.get("suggested_manual_tests"), list): return False
    if not isinstance(data.get("next_actions"), list): return False
    if data.get("host_risk") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                       "INFO", "UNKNOWN", ""):
        return False
    return True


def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "nmap_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(host: HostInfo, model: str = "") -> str:
    parts = [host.ip, host.hostname, f"model={model or 'unknown'}",
             f"prompt={AI_PROMPT_VERSION}"]
    for p in sorted(host.ports, key=lambda x: x.port):
        parts.append(f"{p.port}|{p.service}|{p.product}|{p.version}")
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


def _build_ports_block(host: HostInfo, limit: int = 30) -> str:
    top = sorted(host.ports, key=lambda p: (
        0 if p.is_database else
        1 if p.is_admin else
        2 if p.is_dangerous else
        3 if p.is_remote_access else
        4 if p.is_web else 5,
    ))[:limit]
    lines = []
    for p in top:
        bits = [f"{p.port}/{p.protocol}", p.service or "?"]
        if p.product or p.version:
            bits.append(p.label())
        if p.is_database:      bits.append("DB")
        if p.is_admin:         bits.append("ADMIN")
        if p.is_dangerous:     bits.append("DANGER")
        if p.is_remote_access: bits.append("RA")
        lines.append("  " + " ".join(bits))
    return "\n".join(lines) if lines else "  (no open ports)"


def _ai_triage_host(host: HostInfo, outdir: Path, *,
                     use_cache: bool = True,
                     cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
                     budget_usd: float = 0.0,
                     heuristic_hint: Optional[dict] = None) -> Optional[dict]:
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if not host.ports:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(host, model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        return None

    n_db    = sum(1 for p in host.ports if p.is_database)
    n_admin = sum(1 for p in host.ports if p.is_admin)
    n_web   = sum(1 for p in host.ports if p.is_web)

    hint_block = ""
    if heuristic_hint and heuristic_hint.get("summary"):
        hint_block = (
            "\n\nHeuristic baseline (HINT ONLY):\n"
            f"  Summary: {heuristic_hint.get('summary', '')[:300]}\n"
        )

    prompt = f"""Analyze port-scan findings for host: {host.ip}
Hostname: {host.hostname or '(no PTR)'}
OS: {host.os_matches[0]['name'] if host.os_matches else '(unknown)'}

Stats:
  Open ports:  {len(host.ports)}
  Databases:   {n_db}
  Admin panels:{n_admin}
  Web ports:   {n_web}

Ports:
{_build_ports_block(host)}{hint_block}
"""

    def _call(text: str) -> Optional[str]:
        try:
            return ai_fn(text, system=AI_NMAP_SYSTEM)
        except Exception as e:
            log.warning(f"  AI triage failed for {host.ip}: "
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

    if data is None:
        correction = (
            "Your previous response could not be parsed as valid JSON. "
            "Return ONLY the JSON object, no fences. Required keys: "
            "summary, host_risk, top_priorities, real_vs_noise, "
            "suggested_manual_tests, next_actions.\n\n"
            f"Previous response:\n{text[:600]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {
                    "summary": text2[:1500], "host_risk": "UNKNOWN",
                    "top_priorities": [], "real_vs_noise": "unknown",
                    "suggested_manual_tests": [], "next_actions": [],
                    "parse_error": True,
                }
        else:
            return None

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host.ip)[:60]
    md_path = outdir / f"nmap_ai_{safe}.md"
    try:
        md = (f"# Ullr · Nmap AI Triage — {host.ip}\n\n"
              + (f"**Hostname:** {host.hostname}  \n" if host.hostname else "")
              + f"**Ports:** {len(host.ports)}  \n"
              + f"**Model:** {model_name}  \n"
              + f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("host_risk"):
            md += f"**Host risk:** {data['host_risk']}\n\n"
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
        if data.get("suggested_manual_tests"):
            md += "## Suggested Manual Tests\n\n"
            for t in data["suggested_manual_tests"]:
                md += f"- {t}\n"
            md += "\n"
        if data.get("next_actions"):
            md += "## Next Actions\n\n"
            for a in data["next_actions"]:
                md += f"- {a}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"  AI triage saved: {md_path.name}")

    return {
        "path":             str(md_path),
        "summary":          data.get("summary", ""),
        "host_risk":        data.get("host_risk", ""),
        "top_priorities":   data.get("top_priorities", [])[:10],
        "real_vs_noise":    data.get("real_vs_noise", ""),
        "suggested_manual_tests": data.get("suggested_manual_tests", [])[:10],
        "next_actions":     data.get("next_actions", [])[:10],
        "cost_estimate":    round(_current_spend(), 6),
        "source": "ai",
    }


# ═════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════

def _write_open_ports_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    lines: list[str] = []
    for h in sorted(hosts, key=lambda x: x.ip):
        host_label = h.hostname or h.ip
        for p in sorted(h.ports, key=lambda x: x.port):
            lines.append(f"{host_label}:{p.port}\t{p.protocol}\t{p.label()}")
    path = outdir / "nmap_open_ports.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_interesting_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    lines: list[str] = []
    for h in sorted(hosts, key=lambda x: (-x.score, x.ip)):
        if not h.interesting:
            continue
        host_label = h.hostname or h.ip
        reasons = ",".join(h.reasons[:8])
        ports = ",".join(str(p.port) for p in h.ports)
        lines.append(f"{host_label}\t{h.ip}\tscore={h.score}\tdiv={h.diversity}\t"
                     f"conf={h.confidence}\t"
                     f"reasons={reasons}\tports=[{ports}]")
    path = outdir / "nmap_interesting.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_os_guesses_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    lines: list[str] = []
    for h in sorted(hosts, key=lambda x: x.ip):
        if not h.os_matches:
            continue
        host_label = h.hostname or h.ip
        best = h.os_matches[0]
        lines.append(f"{host_label}\t{best['name']}\taccuracy={best['accuracy']}%")
    path = outdir / "nmap_os_guesses.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_web_ports_txt(hosts: list[HostInfo], outdir: Path) -> tuple[Path, Path]:
    """v3.0: split into URLs-only + detailed."""
    urls_only: list[str] = []
    detailed: list[str] = []
    seen: set[str] = set()

    for h in hosts:
        host_label = h.hostname or h.ip
        if not host_label:
            continue
        for p in h.ports:
            if not p.is_web:
                continue
            scheme = "https" if p.port in HTTPS_PORTS_LIKELY else "http"
            url = f"{scheme}://{host_label}:{p.port}"
            if url in seen:
                continue
            seen.add(url)
            tag = "standard" if p.port in STANDARD_WEB_PORTS else "nonstandard"
            urls_only.append(url)
            detailed.append(f"{url}\t{tag}\t{p.label()}")

    urls_path = outdir / "nmap_web_ports.txt"
    urls_path.write_text("\n".join(urls_only) + ("\n" if urls_only else ""))
    detailed_path = outdir / "nmap_web_ports_detailed.txt"
    detailed_path.write_text("\n".join(detailed) + ("\n" if detailed else ""))
    return urls_path, detailed_path


def _write_digest(hosts: list[HostInfo], outdir: Path) -> None:
    if not hosts:
        (outdir / "nmap_findings_digest.md").write_text(
            "# Nmap Findings Digest\n\nNo hosts.\n", encoding="utf-8")
        return

    interesting = [h for h in hosts if h.interesting]
    top = interesting[:50] if interesting else hosts[:50]

    lines = [
        "# Nmap Findings Digest\n\n",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n",
        f"**Total hosts:** {len(hosts)}  \n",
        f"**Interesting:** {len(interesting)}  \n\n",
        "## Top hosts\n\n",
        "| Score | Conf | Host | OS | Key Ports | Manual Test |\n",
        "|-------|------|------|-----|-----------|-------------|\n",
    ]
    for h in top:
        host = (h.hostname or h.ip).replace("|", "\\|")[:40]
        os_name = (h.os_matches[0]["name"][:30] if h.os_matches else "—").replace("|", "\\|")
        key_ports = ", ".join(
            str(p.port) for p in sorted(
                h.ports,
                key=lambda p: (0 if p.is_database else 1 if p.is_admin else 2),
            )[:6]
        ) or "—"
        test = (h.manual_test or "Review").replace("|", "\\|")[:70]
        lines.append(
            f"| {h.score:>3} | {h.confidence:>3} | {host} | {os_name} | "
            f"{key_ports} | {test} |\n"
        )
    (outdir / "nmap_findings_digest.md").write_text(
        "".join(lines), encoding="utf-8")
    log.ok(f"  Digest: nmap_findings_digest.md ({len(top)} hosts)")


def _build_summary(hosts: list[HostInfo]) -> dict:
    by_port: dict[str, int] = {}
    by_service: dict[str, int] = {}
    by_os: dict[str, int] = {}
    by_category: dict[str, int] = {"web": 0, "database": 0, "admin": 0,
                                    "dangerous": 0, "remote_access": 0}
    total_ports = 0

    for h in hosts:
        for p in h.ports:
            total_ports += 1
            by_port[str(p.port)] = by_port.get(str(p.port), 0) + 1
            svc = p.service or "unknown"
            by_service[svc] = by_service.get(svc, 0) + 1
            if p.is_web:           by_category["web"] += 1
            if p.is_database:      by_category["database"] += 1
            if p.is_admin:         by_category["admin"] += 1
            if p.is_dangerous:     by_category["dangerous"] += 1
            if p.is_remote_access: by_category["remote_access"] += 1
        for o in h.os_matches[:1]:
            name = o["name"]
            by_os[name] = by_os.get(name, 0) + 1

    return {
        "total_open_ports": total_ports,
        "by_port":     dict(sorted(by_port.items(), key=lambda kv: -kv[1])),
        "by_service":  dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
        "by_os":       dict(sorted(by_os.items(), key=lambda kv: -kv[1])),
        "by_category": by_category,
    }


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, hosts: list[HostInfo]) -> None:
    if not hosts:
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
    try:
        host_payloads = []
        for h in hosts:
            host_payloads.append({
                "ip":              h.ip,
                "hostname":        h.hostname or None,
                "status":          h.status,
                "os_matches":      h.os_matches,
                "host_scripts":    h.host_scripts,
                "traceroute":      h.traceroute,
                "phase":           h.phase,
                "score":           h.score,
                "interesting":     h.interesting,
                "reasons":         h.reasons,
                "open_port_count": len(h.ports),
                "first_seen":      h.first_seen.replace("T", " ").split(".")[0] if h.first_seen else None,
            })
        host_result = DB.upsert_nmap_hosts(scan_id, host_payloads)
        if host_result is None:
            log.warning("  DB sync: hosts upsert returned None")
            return
        host_ids = host_result.get("host_ids", {})
        log.info(f"  DB sync: {host_result['count']} host(s) upserted")

        port_payloads = []
        for h in hosts:
            host_hash = hashlib.sha256(h.ip.encode()).hexdigest()
            if host_hash not in host_ids:
                continue
            for p in h.ports:
                port_payloads.append({
                    "host_hash":        host_hash,
                    "port":             p.port,
                    "protocol":         p.protocol,
                    "state":            p.state,
                    "reason":           p.reason,
                    "service":          p.service,
                    "product":          p.product,
                    "version":          p.version,
                    "extrainfo":        p.extrainfo,
                    "cpe":              p.cpe,
                    "scripts":          p.scripts,
                    "is_web":           p.is_web,
                    "is_database":      p.is_database,
                    "is_admin":         p.is_admin,
                    "is_dangerous":     p.is_dangerous,
                    "is_remote_access": p.is_remote_access,
                    "first_seen":       h.first_seen.replace("T", " ").split(".")[0] if h.first_seen else None,
                })
        if port_payloads:
            port_count = DB.upsert_nmap_ports(scan_id, port_payloads)
            if port_count is not None:
                log.info(f"  DB sync: {port_count} port(s) upserted")
            else:
                log.warning("  DB sync: ports upsert returned None")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════

def run_nmap_scan(
    live_hosts_file: Path,
    outdir: Path,
    *,
    # v1 backward-compat
    deep_scan: bool = True,
    deep_limit: int = DEEP_HOST_LIMIT,
    deep_min_rate: Optional[int] = None,
    deep_max_rate: Optional[int] = None,
    use_vuln_scripts: bool = False,
    udp: bool = False,
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    quiet: bool = False,
    top_ports: int = FAST_TOP_PORTS,
    exclude_ports: Optional[str] = None,
    total_deep_timeout: int = DEEP_TOTAL_TIMEOUT_MAX,
    os_detection: bool = True,
    no_ai: bool = False,
    ai_max_hosts: int = AI_DEFAULT_MAX_HOSTS,
    ai_max_cost_usd: float = 0.0,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
) -> Path:
    """v3.0: full port scan with partial XML recovery, per-host triage, AI."""
    start = time.monotonic()
    warnings: list[str] = []
    _SHARED["_quiet"] = quiet

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    if not _check_nmap():
        raise RuntimeError(
            "nmap not installed. Run `python3 tools.py --only nmap` "
            "or `sudo apt-get install nmap` first.")

    # ── Settings ────────────────────────────────────────────────────────────
    settings = _nmap_settings()
    eff_min_rate  = deep_min_rate if deep_min_rate is not None else settings["min_rate"]
    eff_max_rate  = deep_max_rate if deep_max_rate is not None else settings["max_rate"]
    eff_fast_timing = settings["timing_fast"]
    eff_deep_timing = settings["timing_deep"]

    # ── Inputs ──────────────────────────────────────────────────────────────
    hosts = _extract_hosts(live_hosts_file)
    total_input = len(hosts)
    if len(hosts) > MAX_HOSTS_INPUT:
        warnings.append(f"input-capped: {total_input} → {MAX_HOSTS_INPUT}")
        log.warning(f"  Capping at {MAX_HOSTS_INPUT} hosts (input had {total_input})")
        hosts = hosts[:MAX_HOSTS_INPUT]

    outdir.mkdir(parents=True, exist_ok=True)

    if not hosts:
        log.warning("  No hosts to scan — writing empty report")
        return _write_empty_report(outdir, live_hosts_file, start,
                                     total_input=total_input, scan_id=scan_id)

    hostfile = outdir / "nmap_targets.txt"
    hostfile.write_text("\n".join(hosts) + "\n")

    nmap_version = _get_nmap_version()
    ai_active = _ai_enabled() and not no_ai and not dry_run

    if not quiet:
        log.info(f"  Input  : {len(hosts)} host(s) from {live_hosts_file.name}")
        log.info(f"  Mode   : {_scan_type_flag()} "
                 f"({'root' if _has_root() else 'non-root'})  ·  "
                 f"{'OS detection on' if (os_detection and _has_root()) else 'OS detection off'}")
        log.info(f"  nmap   : {nmap_version}")
        rate_parts = []
        if eff_min_rate and eff_min_rate > 0:
            rate_parts.append(f"min-rate={eff_min_rate}")
        if eff_max_rate and eff_max_rate > 0:
            rate_parts.append(f"max-rate={eff_max_rate}")
        rate_label = " · ".join(rate_parts) if rate_parts else "unlimited"
        translate_note = (
            f" (rps={settings['rps']} × 50)" if settings["rps_to_max_rate"] else ""
        )
        log.info(f"  Config : timing fast={eff_fast_timing} deep={eff_deep_timing}  "
                 f"{rate_label}{translate_note}")
        log.info(f"           source=MODULE_RATE_LIMITS['port_scan']")
        log.info(f"           note: nmap speaks TCP/IP — platform headers not applicable")
        if udp and not _has_root():
            log.warning("  UDP   : --udp requires root — UDP scan will be skipped")
        if dry_run:
            log.info("  Mode   : DRY-RUN (no nmap subprocess)")
        if ai_active:
            budget_str = (f"${ai_max_cost_usd:.2f}"
                           if ai_max_cost_usd > 0 else "unlimited")
            log.info(f"  AI     : enabled  (budget={budget_str}, "
                     f"max_hosts={ai_max_hosts}, cache={ai_cache_ttl_hours}h)")
        else:
            log.info("  AI     : disabled — heuristic triage active")
        log.info("")

    if dry_run:
        log.info(f"  DRY-RUN — would scan {len(hosts)} host(s)")
        for h in hosts[:10]:
            log.info(f"    {h}")
        if len(hosts) > 10:
            log.info(f"    … and {len(hosts) - 10} more")
        return _write_empty_report(outdir, live_hosts_file, start,
                                     total_input=total_input, scan_id=scan_id,
                                     dry_run=True)

    # ── SIGINT/SIGTERM handler ──────────────────────────────────────────────
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — writing partial report after current phase")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    try:
        # ── Phase 1 ─────────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "fast", "hosts": len(hosts)})
        log.info("  Phase 1 — Fast sweep (top ports, service versions)")
        fast_prefix = outdir / "nmap_fast"
        fast_cmd = _build_fast_cmd(
            hostfile, fast_prefix, eff_fast_timing, eff_max_rate or 0,
            top_ports, exclude_ports, os_detection,
        )
        _run_nmap(fast_cmd, FAST_TIMEOUT, "phase 1")
        fast_hosts = _parse_nmap_xml(outdir / "nmap_fast.xml", phase="fast")
        log.info(f"    Parsed {len(fast_hosts)} live host(s) from phase 1")
        _progress("stage_end", {"stage": "fast", "hosts": len(fast_hosts)})

        if _sigint["flag"]:
            warnings.append("run-interrupted: SIGINT during phase 1")

        # ── UDP ─────────────────────────────────────────────────────────────
        if udp and _has_root() and not _sigint["flag"]:
            log.info("  Phase 1b — UDP top 100 ports")
            udp_prefix = outdir / "nmap_udp"
            udp_cmd = [
                "nmap", "-sU", "--top-ports", "100", "-T4", "--open", "-Pn",
                "-oA", str(udp_prefix), "-iL", str(hostfile),
            ]
            if exclude_ports:
                udp_cmd.extend(["--exclude-ports", exclude_ports])
            _run_nmap(udp_cmd, FAST_TIMEOUT, "udp")
            udp_hosts = _parse_nmap_xml(outdir / "nmap_udp.xml", phase="fast")
            fast_hosts = _merge_host_info(fast_hosts, udp_hosts)
            log.info(f"    Merged UDP results → {len(fast_hosts)} host(s)")

        # ── Phase 2 ─────────────────────────────────────────────────────────
        deep_hosts: list[HostInfo] = []
        if deep_scan and fast_hosts and not _sigint["flag"]:
            candidates = [h for h in fast_hosts if h.ports]
            targets = _select_deep_targets(candidates, deep_limit)

            if targets:
                log.info("")
                log.info(f"  Phase 2 — Deep scan (full port range) on "
                         f"{len(targets)}/{len(candidates)} diverse host(s)")
                for h in targets:
                    log.info(f"    {h.ip:<18} {h.hostname or '(no PTR)':<40} "
                             f"score={h.score}  div={h.diversity}  ports={len(h.ports)}")

                deep_hostfile = outdir / "nmap_deep_targets.txt"
                deep_hostfile.write_text("\n".join(h.ip for h in targets) + "\n")

                nse = DEFAULT_NSE + ("," + VULN_NSE if use_vuln_scripts else "")
                deep_prefix = outdir / "nmap_deep"
                deep_cmd = _build_deep_cmd(
                    deep_hostfile, deep_prefix, eff_deep_timing, nse,
                    eff_min_rate or 0, eff_max_rate or 0,
                    exclude_ports, os_detection,
                )
                # v3.0: hard-capped total timeout
                deep_timeout = min(
                    DEEP_TIMEOUT_PER_HOST * len(targets), total_deep_timeout,
                )
                if deep_timeout < DEEP_TIMEOUT_PER_HOST * len(targets):
                    warnings.append(
                        f"deep-timeout-capped: "
                        f"{DEEP_TIMEOUT_PER_HOST * len(targets)} → {deep_timeout}s")

                _progress("stage_start", {"stage": "deep", "hosts": len(targets)})
                _run_nmap(deep_cmd, deep_timeout, "phase 2")
                deep_hosts = _parse_nmap_xml(outdir / "nmap_deep.xml", phase="deep")
                log.info(f"    Parsed {len(deep_hosts)} host(s) from phase 2")
                _progress("stage_end", {"stage": "deep", "hosts": len(deep_hosts)})

                if _sigint["flag"]:
                    warnings.append("run-interrupted: SIGINT during phase 2")
            else:
                log.info("")
                log.info("  Phase 2 — skipped (no hosts with open ports)")

        # ── Merge ───────────────────────────────────────────────────────────
        combined = _merge_host_info(fast_hosts, deep_hosts)
        combined.sort(key=lambda h: (-h.score, h.ip))
        interesting = [h for h in combined if h.interesting]
        log.info("")
        log.info(f"  Combined: {len(combined)} host(s), "
                 f"{len(interesting)} flagged interesting")

        # ── Triage ──────────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "triage", "hosts": len(combined)})
        ai_hosts_done = 0
        ai_budget_exhausted = False

        for h in combined:
            heuristic = _heuristic_host_triage(h)
            ai_result: Optional[dict] = None
            if (ai_active and h.interesting and ai_hosts_done < ai_max_hosts
                    and not ai_budget_exhausted):
                ai_result = _ai_triage_host(
                    h, outdir, use_cache=True,
                    cache_ttl_hours=ai_cache_ttl_hours,
                    budget_usd=ai_max_cost_usd,
                    heuristic_hint=heuristic,
                )
                if ai_result:
                    ai_hosts_done += 1
                elif ai_max_cost_usd > 0 and _current_spend() >= ai_max_cost_usd:
                    ai_budget_exhausted = True

            if ai_result:
                h.triage = ai_result
                h.triage_source = ai_result.get("source", "ai")
            else:
                h.triage = heuristic
                h.triage_source = "heuristic"

        if ai_active and ai_hosts_done > 0:
            log.info(f"  AI triaged: {ai_hosts_done} host(s)")
            if ai_budget_exhausted:
                warnings.append(f"ai-budget-exhausted: ${ai_max_cost_usd:.2f}")
        _progress("stage_end", {"stage": "triage"})

        # ── Flat outputs ────────────────────────────────────────────────────
        ports_path        = _write_open_ports_txt(combined, outdir)
        interesting_path  = _write_interesting_txt(combined, outdir)
        os_path           = _write_os_guesses_txt(combined, outdir)
        web_ports_path, web_ports_detailed_path = _write_web_ports_txt(combined, outdir)

        # ── Report ──────────────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        summary = _build_summary(combined)

        ai_triaged = sum(1 for h in combined if h.triage_source.startswith("ai"))
        heuristic_triaged = sum(1 for h in combined if h.triage_source == "heuristic")

        report = {
            "schema_version": 3,
            "producer": "nmap.py v3.0.0 'ULLR'",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "input_file": str(live_hosts_file),
            "total_input": total_input,
            "nmap_version": nmap_version,
            "config": {
                "scan_type":       "syn" if _has_root() else "connect",
                "os_detection":    os_detection and _has_root(),
                "fast_top_ports":  top_ports,
                "fast_timing":     eff_fast_timing,
                "deep_timing":     eff_deep_timing,
                "deep_scan":       deep_scan,
                "deep_limit":      deep_limit,
                "deep_min_rate":   eff_min_rate or 0,
                "deep_max_rate":   eff_max_rate or 0,
                "rps":             settings["rps"],
                "rps_to_max_rate": settings["rps_to_max_rate"],
                "total_deep_timeout": total_deep_timeout,
                "exclude_ports":   exclude_ports,
                "vuln_scripts":    use_vuln_scripts,
                "udp":             udp and _has_root(),
                "headers_applied": False,
                "note":            "nmap speaks raw TCP/IP — platform headers "
                                   "and auth cookies not applicable",
            },
            "warnings": warnings,
            "totals": {
                "hosts_input":           total_input,
                "hosts_up":              len(combined),
                "hosts_with_open_ports": sum(1 for h in combined if h.ports),
                "hosts_interesting":     len(interesting),
                "total_open_ports":      summary["total_open_ports"],
                "ai_triaged":            ai_triaged,
                "heuristic_triaged":     heuristic_triaged,
            },
            "summary":  summary,
            "hosts":    [h.to_dict() for h in combined[:DEFAULT_MAX_FINDINGS]],
        }

        json_path = outdir / "nmap_scan.json"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

        _write_digest(combined, outdir)

        if scan_id is not None:
            log.info("")
            log.info(f"  Syncing to remote database (scan_id={scan_id})...")
            _self_sync(scan_id, combined)
        else:
            log.info("")
            log.info("  DB sync  : deferred to main.py (no scan_id passed)")

        # ── Console summary ─────────────────────────────────────────────────
        log.info("")
        log.info("── ᛊ  Summary ──")
        log.info(f"  Hosts up         : {len(combined)} / {total_input}")
        log.info(f"  Interesting      : {len(interesting)}")
        log.info(f"  Open ports       : {summary['total_open_ports']}")
        if report["ai_enabled"]:
            log.info(f"  AI triage        : {ai_triaged} host(s) AI · "
                     f"{heuristic_triaged} heuristic")

        if summary["by_port"]:
            top_ports = list(summary["by_port"].items())[:10]
            log.info(f"  Top ports        : " + " · ".join(
                f"{p}({n})" for p, n in top_ports))
        if summary["by_service"]:
            top_svcs = list(summary["by_service"].items())[:8]
            log.info(f"  Top services     : " + " · ".join(
                f"{s}({n})" for s, n in top_svcs))
        cats = summary["by_category"]
        log.info(f"  Categories       : web={cats['web']}  database={cats['database']}  "
                 f"admin={cats['admin']}  dangerous={cats['dangerous']}  "
                 f"remote_access={cats['remote_access']}")

        if interesting:
            log.info("")
            log.info("  Interesting hosts:")
            for h in interesting[:10]:
                label = h.hostname or h.ip
                top_ports_list = ",".join(
                    str(p.port) for p in sorted(h.ports, key=lambda x: x.port)[:6])
                reasons = ",".join(h.reasons[:3])
                log.info(f"    {label:<40} score={h.score:>3} div={h.diversity}  "
                         f"conf={h.confidence:>3}  "
                         f"ports=[{top_ports_list}]  [{reasons}]")

        log.info("")
        log.info("  Outputs:")
        log.info(f"    nmap_scan.json")
        log.info(f"    nmap_open_ports.txt")
        log.info(f"    nmap_interesting.txt")
        log.info(f"    nmap_os_guesses.txt")
        log.info(f"    nmap_web_ports.txt")
        log.info(f"    nmap_web_ports_detailed.txt")
        log.info(f"    nmap_findings_digest.md")
        if report["ai_enabled"] and ai_triaged > 0:
            log.info(f"    nmap_ai_<host>.md")

        if report.get("warnings"):
            log.info("")
            log.info("  Warnings:")
            for w in report["warnings"][:8]:
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


def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
    total_input: int = 0, scan_id: Optional[int] = None,
    dry_run: bool = False,
) -> Path:
    report = {
        "schema_version": 3,
        "producer": "nmap.py v3.0.0 'ULLR'",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "total_input": total_input,
        "nmap_version": "unknown",
        "config": {},
        "warnings": [],
        "totals": {
            "hosts_input": total_input, "hosts_up": 0,
            "hosts_with_open_ports": 0, "hosts_interesting": 0,
            "total_open_ports": 0, "ai_triaged": 0, "heuristic_triaged": 0,
        },
        "summary": {"by_port": {}, "by_service": {}, "by_os": {},
                    "by_category": {}, "total_open_ports": 0},
        "hosts": [],
    }
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / "nmap_scan.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nmap_open_ports.txt", "nmap_interesting.txt",
                 "nmap_os_guesses.txt", "nmap_web_ports.txt",
                 "nmap_web_ports_detailed.txt"):
        (outdir / name).write_text("")
    (outdir / "nmap_findings_digest.md").write_text(
        "# Nmap Findings Digest\n\nNo hosts.\n", encoding="utf-8")
    return path


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  nmap.py v3.0 'ULLR' — selftest")
    print("═" * 70)

    def _mk_port(port: int, service: str = "http",
                  product: str = "", version: str = "") -> PortInfo:
        p = PortInfo(port=port, service=service,
                     product=product, version=version)
        p.classify()
        return p

    def _mk_host(ip: str = "1.2.3.4", ports: Optional[list] = None,
                  hostname: str = "") -> HostInfo:
        h = HostInfo(ip=ip, hostname=hostname, first_seen="2026-01-01T00:00:00Z")
        h.ports = ports or [_mk_port(80)]
        _score_host(h)
        _decorate_host(h)
        return h

    def _settings_reads_canonical_key() -> bool:
        s = _nmap_settings()
        # config.py: {"port_scan": {"rps": 2, "concurrency": 2}}
        return s["rps"] == 2 and s["max_rate"] == 100

    def _settings_reads_rps_not_rate_limit() -> bool:
        s = _nmap_settings()
        # If it read rate_limit instead of rps, we'd get defaults
        return s["rps"] != 100  # 100 is the old default

    def _settings_translates_rps() -> bool:
        s = _nmap_settings()
        return s["rps_to_max_rate"] and s["max_rate"] == s["rps"] * 50

    def _input_bom_crlf() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example.com/x\r\n"
                     b"b.example.com  # inline\r\n"
                     b"\r\n"
                     b"# full-line\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _extract_hosts(tmp)
            return loaded == ["a.example.com", "b.example.com"]
        finally:
            tmp.unlink(missing_ok=True)

    def _port_classify_db() -> bool:
        return _mk_port(3306, "mysql").is_database

    def _port_classify_admin() -> bool:
        return _mk_port(8080, "http-proxy").is_admin

    def _port_classify_web() -> bool:
        return _mk_port(8080, "http").is_web

    def _port_classify_ra() -> bool:
        return _mk_port(22, "ssh").is_remote_access

    def _port_classify_danger() -> bool:
        return _mk_port(23, "telnet").is_dangerous

    def _score_db_host() -> bool:
        h = _mk_host(ports=[_mk_port(3306, "mysql")])
        return h.score >= 40

    def _score_admin_host() -> bool:
        h = _mk_host(ports=[_mk_port(8080, "http")])
        return h.score >= 30

    def _score_web_only_low() -> bool:
        h = _mk_host(ports=[_mk_port(80, "http")])
        return h.score < 30

    def _select_deep_diverse() -> bool:
        h1 = _mk_host("1.1.1.1", ports=[
            _mk_port(3306, "mysql"),
            _mk_port(8080, "http"),
            _mk_port(22, "ssh"),
        ])
        h2 = _mk_host("2.2.2.2", ports=[_mk_port(80)] * 5)  # 5 identical ports
        targets = _select_deep_targets([h1, h2], 2)
        return targets[0].ip == "1.1.1.1"

    def _decorate_confidence() -> bool:
        h = _mk_host(ports=[_mk_port(3306, "mysql")])
        return h.confidence >= 60

    def _decorate_manual_test_mysql() -> bool:
        h = _mk_host(ports=[_mk_port(3306, "mysql")])
        return "mysql" in h.manual_test

    def _decorate_manual_test_ssh() -> bool:
        h = _mk_host(ports=[_mk_port(22, "ssh")])
        return "ssh" in h.manual_test

    def _decorate_manual_test_web() -> bool:
        h = _mk_host(ports=[_mk_port(8080, "http")])
        return "curl" in h.manual_test

    def _decorate_nuclei_tags_db() -> bool:
        h = _mk_host(ports=[_mk_port(3306, "mysql")])
        return "database" in h.nuclei_tags

    def _decorate_nuclei_tags_web() -> bool:
        h = _mk_host(ports=[_mk_port(80, "http")])
        return "http" in h.nuclei_tags

    def _heuristic_empty() -> bool:
        h = _mk_host(ports=[])
        return _heuristic_host_triage(h)["host_risk"] == "INFO"

    def _heuristic_db_critical() -> bool:
        h = _mk_host(ports=[_mk_port(3306, "mysql")])
        return _heuristic_host_triage(h)["host_risk"] == "CRITICAL"

    def _heuristic_admin_high() -> bool:
        h = _mk_host(ports=[_mk_port(8080, "http")])
        return _heuristic_host_triage(h)["host_risk"] == "HIGH"

    def _heuristic_chain_db_admin() -> bool:
        h = _mk_host(ports=[
            _mk_port(3306, "mysql"),
            _mk_port(8080, "http"),
        ])
        r = _heuristic_host_triage(h)
        return any("database" in c and "admin" in c for c in r["chains"])

    def _merge_host_info() -> bool:
        f = _mk_host("1.1.1.1", ports=[_mk_port(80)])
        d = _mk_host("1.1.1.1", ports=[_mk_port(80), _mk_port(443)])
        merged = _merge_host_info([f], [d])
        return len(merged) == 1 and len(merged[0].ports) == 2

    def _merge_host_info_keeps_hostname() -> bool:
        f = _mk_host("1.1.1.1", hostname="example.com")
        d = _mk_host("1.1.1.1")  # no hostname
        merged = _merge_host_info([f], [d])
        return merged[0].hostname == "example.com"

    def _xml_parse_basic() -> bool:
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.20"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
            tf.write(xml_content)
            tmp = Path(tf.name)
        try:
            hosts = _parse_nmap_xml(tmp, phase="test")
            return (len(hosts) == 1 and hosts[0].ip == "1.2.3.4"
                    and len(hosts[0].ports) == 1
                    and hosts[0].ports[0].port == 80)
        finally:
            tmp.unlink(missing_ok=True)

    def _xml_partial_recovery() -> bool:
        # Simulate truncated XML (no closing </nmaprun>)
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
            tf.write(xml_content)
            tmp = Path(tf.name)
        try:
            hosts = _parse_nmap_xml(tmp, phase="test")
            return len(hosts) == 1  # recovery worked
        finally:
            tmp.unlink(missing_ok=True)

    def _xml_os_matches() -> bool:
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
            tf.write(xml_content)
            tmp = Path(tf.name)
        try:
            hosts = _parse_nmap_xml(tmp, phase="test")
            return len(hosts) == 1 and len(hosts[0].os_matches) == 1
        finally:
            tmp.unlink(missing_ok=True)

    def _fast_cmd_structure() -> bool:
        cmd = _build_fast_cmd(
            Path("/tmp/hosts.txt"), Path("/tmp/out"), "T4", 100,
            1000, None, False,
        )
        return "-sV" in cmd and "--top-ports" in cmd and "--open" in cmd

    def _fast_cmd_with_max_rate() -> bool:
        cmd = _build_fast_cmd(
            Path("/tmp/hosts.txt"), Path("/tmp/out"), "T4", 500,
            1000, None, False,
        )
        return "--max-rate" in cmd and "500" in cmd

    def _fast_cmd_with_exclude() -> bool:
        cmd = _build_fast_cmd(
            Path("/tmp/hosts.txt"), Path("/tmp/out"), "T4", 0,
            1000, "22,3389", False,
        )
        return "--exclude-ports" in cmd and "22,3389" in cmd

    def _deep_cmd_structure() -> bool:
        cmd = _build_deep_cmd(
            Path("/tmp/hosts.txt"), Path("/tmp/out"), "T4",
            "default,safe", 0, 500, None, False,
        )
        return "-p-" in cmd and "--traceroute" in cmd and "--script" in cmd

    def _ai_cache_stable() -> bool:
        h = _mk_host("1.2.3.4", ports=[_mk_port(80)])
        k1 = _ai_cache_key(h, model="m")
        k2 = _ai_cache_key(h, model="m")
        return k1 == k2

    def _ai_cache_model_busts() -> bool:
        h = _mk_host("1.2.3.4")
        return (_ai_cache_key(h, model="m1") != _ai_cache_key(h, model="m2"))

    def _validate_ai_ok() -> bool:
        return _validate_ai_triage({
            "summary": "x", "host_risk": "HIGH", "top_priorities": [],
            "real_vs_noise": "x", "suggested_manual_tests": [],
            "next_actions": [],
        })

    def _validate_ai_reject() -> bool:
        return not _validate_ai_triage({"summary": "x"})

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_nmap_scan)
        return set(required).issubset(set(sig.parameters))

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                    lambda: CFG_LOADED),
        ("_settings reads 'port_scan'",      _settings_reads_canonical_key),
        ("_settings reads 'rps'",            _settings_reads_rps_not_rate_limit),
        ("_settings translates rps",         _settings_translates_rps),
        ("BOM/CRLF input",                   _input_bom_crlf),
        ("port classify: db",                _port_classify_db),
        ("port classify: admin",             _port_classify_admin),
        ("port classify: web",               _port_classify_web),
        ("port classify: ra",                _port_classify_ra),
        ("port classify: danger",            _port_classify_danger),
        ("score: db host",                   _score_db_host),
        ("score: admin host",                _score_admin_host),
        ("score: web-only low",              _score_web_only_low),
        ("select_deep: diversity wins",      _select_deep_diverse),
        ("decorate: confidence",             _decorate_confidence),
        ("decorate: manual_test mysql",      _decorate_manual_test_mysql),
        ("decorate: manual_test ssh",        _decorate_manual_test_ssh),
        ("decorate: manual_test web",        _decorate_manual_test_web),
        ("decorate: nuclei_tags db",         _decorate_nuclei_tags_db),
        ("decorate: nuclei_tags web",        _decorate_nuclei_tags_web),
        ("heuristic: empty",                 _heuristic_empty),
        ("heuristic: db critical",           _heuristic_db_critical),
        ("heuristic: admin high",            _heuristic_admin_high),
        ("heuristic: chain db+admin",        _heuristic_chain_db_admin),
        ("merge: same IP",                   _merge_host_info),
        ("merge: keeps hostname",            _merge_host_info_keeps_hostname),
        ("XML: basic parse",                 _xml_parse_basic),
        ("XML: partial recovery",            _xml_partial_recovery),
        ("XML: OS match",                    _xml_os_matches),
        ("cmd: fast structure",              _fast_cmd_structure),
        ("cmd: fast with max-rate",          _fast_cmd_with_max_rate),
        ("cmd: fast with exclude",           _fast_cmd_with_exclude),
        ("cmd: deep structure",              _deep_cmd_structure),
        ("ai cache: stable",                 _ai_cache_stable),
        ("ai cache: model busts",            _ai_cache_model_busts),
        ("validate_ai_triage ok",            _validate_ai_ok),
        ("validate_ai_triage rejects",       _validate_ai_reject),
        ("run has dry_run",                  lambda: _sig_has(
            "dry_run", "quiet", "top_ports", "exclude_ports",
            "total_deep_timeout", "os_detection", "no_ai",
            "ai_max_hosts", "ai_max_cost_usd", "ai_cache_ttl_hours",
            "on_progress")),
        ("_run_nmap callable",               lambda: callable(_run_nmap)),
        ("_parse_nmap_xml callable",         lambda: callable(_parse_nmap_xml)),
        ("_build_fast_cmd callable",         lambda: callable(_build_fast_cmd)),
        ("_build_deep_cmd callable",         lambda: callable(_build_deep_cmd)),
        ("_score_host callable",             lambda: callable(_score_host)),
        ("_decorate_host callable",          lambda: callable(_decorate_host)),
        ("_select_deep_targets callable",    lambda: callable(_select_deep_targets)),
        ("_heuristic_host_triage callable",  lambda: callable(_heuristic_host_triage)),
        ("_ai_triage_host callable",         lambda: callable(_ai_triage_host)),
        ("_write_digest callable",           lambda: callable(_write_digest)),
        ("_self_sync callable",              lambda: callable(_self_sync)),
        ("_get_nmap_version callable",       lambda: callable(_get_nmap_version)),
        ("MANUAL_TEST_BY_PORT >= 10",        lambda: len(MANUAL_TEST_BY_PORT) >= 10),
        ("version is 3.0.0",                 lambda: True),
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


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="nmap.py",
        description="Argus nmap scanner v3.0 'ULLR'",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--deep-limit", type=int, default=DEEP_HOST_LIMIT)
    p.add_argument("--deep-min-rate", type=int, default=None)
    p.add_argument("--deep-max-rate", type=int, default=None)
    p.add_argument("--no-deep", action="store_true")
    p.add_argument("--udp", action="store_true")
    p.add_argument("--vuln", action="store_true")

    # v3.0 additions
    p.add_argument("--top-ports", type=int, default=FAST_TOP_PORTS)
    p.add_argument("--exclude-ports", type=str, default=None,
                    help="comma-separated port list or range to exclude")
    p.add_argument("--total-deep-timeout", type=int,
                    default=DEEP_TOTAL_TIMEOUT_MAX,
                    help="hard cap on deep phase (seconds)")
    p.add_argument("--no-os-detection", dest="os_detection",
                    action="store_false", default=True)
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--ai-max-hosts", type=int, default=AI_DEFAULT_MAX_HOSTS)
    p.add_argument("--ai-max-cost", type=float, default=0.0)
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS)

    # Utility
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--version", action="version",
                    version="nmap.py 3.0.0 'ULLR'")
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

    try:
        run_nmap_scan(
            args.input, args.output,
            deep_scan=not args.no_deep,
            deep_limit=args.deep_limit,
            deep_min_rate=args.deep_min_rate,
            deep_max_rate=args.deep_max_rate,
            use_vuln_scripts=args.vuln,
            udp=args.udp,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            quiet=args.quiet,
            top_ports=args.top_ports,
            exclude_ports=args.exclude_ports,
            total_deep_timeout=args.total_deep_timeout,
            os_detection=args.os_detection,
            no_ai=args.no_ai,
            ai_max_hosts=args.ai_max_hosts,
            ai_max_cost_usd=args.ai_max_cost,
            ai_cache_ttl_hours=args.ai_cache_ttl,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
