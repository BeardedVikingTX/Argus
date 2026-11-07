#!/usr/bin/env python3
"""
recon_tools/nmap.py — Port, Service & OS Discovery
═══════════════════════════════════════════════════════════════════════════════

The network discovery stage for Argus. Two-phase strategy:

  Phase 1 — Fast sweep (every host)
      -sS -sV --top-ports 1000 --open -Pn --reason
      Fast, covers 99% of bug bounty findings.

  Phase 2 — Deep scan (top-N diverse hosts)
      -sS -sV -sC -p- -O --version-all --traceroute
      Full port range, NSE scripts, OS detection on high-value targets.

WHY NMAP IS DIFFERENT FROM HTTP STAGES
──────────────────────────────────────
nmap speaks TCP/IP directly — no HTTP layer. That means:
  ✗ Platform headers (ACTIVE_HEADERS) are NOT applied
  ✗ request.txt auth (AUTH_HEADERS, AUTH_COOKIES) is NOT applied
  ✓ Rate limiting maps to nmap's --min-rate / --max-rate + timing templates

Privilege awareness:
  • Root   → -sS (SYN scan) + -O (OS detection) + -sU (UDP)
  • Non-root → -sT (TCP connect) + no OS detection

Config integration (config.py):
  • MODULE_RATE_LIMITS["nmap"]["rate_limit"]   → --max-rate (ceiling)
  • MODULE_RATE_LIMITS["nmap"]["timing"]       → -T0 through -T5
  • SYNC_TO_DB, BRIDGE_*                       → remote database sync

Outputs (into `outdir`):
  • nmap_scan.json          — full structured report (primary)
  • nmap_open_ports.txt     — host:port service version
  • nmap_interesting.txt    — prioritized host list
  • nmap_os_guesses.txt     — OS fingerprints
  • nmap_web_ports.txt      — NEW: non-standard web ports for downstream tools
  • nmap_fast.nmap/.xml/.gnmap  — raw artifacts
  • nmap_deep.nmap/.xml/.gnmap  — raw artifacts (if deep ran)

Remote DB (if scan_id is provided):
  • nmap_hosts table        — one row per host
  • nmap_ports table        — one row per open port (queryable by port/service)

Integration:
  main.py → run_one("nmap") → run_nmap_scan(live_hosts_file, outdir)
  main.py syncs via _sync_stage_artifacts()
  Standalone: run_nmap_scan(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.nmap")

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


def _nmap_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("nmap", {})
    return {
        "max_rate":    entry.get("rate_limit", 0),      # 0 = unset (no --max-rate)
        "min_rate":    entry.get("min_rate", 0),        # 0 = unset (no --min-rate)
        "timing_fast": entry.get("timing_fast", "T4"),
        "timing_deep": entry.get("timing_deep", "T4"),
    }


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

FAST_TOP_PORTS        = 1000
FAST_TIMING           = "T4"
FAST_TIMEOUT          = 3600

DEEP_TIMING           = "T4"
DEEP_TIMEOUT_PER_HOST = 1800
DEEP_HOST_LIMIT       = 20
DEEP_MIN_RATE         = 0

DEFAULT_NSE   = "default,safe,discovery,http-headers,http-methods,ssl-cert,ssl-enum-ciphers"
VULN_NSE      = "vuln"

INTERESTING_SCORE = 30

# ── Port category sets ──────────────────────────────────────────────────────
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
    1433, 1521, 3306, 5432, 27017,  # Database ports are also "dangerous" if exposed
    6379, 11211,                    # Redis, memcached
    4369, 5672, 15672,              # RabbitMQ
    2375, 2376,                     # Docker (unauthed)
}
REMOTE_ACCESS_PORTS = {
    22, 3389, 5900, 5901, 5985, 5986,
    23, 512, 513, 514,              # rlogin, rsh, rexec
}
WEB_PORTS = {
    80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    8002, 8003, 8004, 8005, 8006, 8007, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095,
    8161, 8180, 8181, 8200, 8222, 8280, 8281, 8333, 8400, 8444,
    8500, 8800, 8834, 9001, 9002, 9003, 9043, 9080, 9090, 9091,
    9200, 9443, 10000, 10443, 18080, 18081,
}

# Common web ports for URL generation in nmap_web_ports.txt
STANDARD_WEB_PORTS = {80, 443}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

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

    # Category flags — computed once, used for scoring and sync
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
        """Populate the category flags from the port number."""
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
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_hosts(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    hosts: list[str] = []
    seen: set[str] = set()

    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if token.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(token)
            host = parsed.hostname or ""
        else:
            host = token.split("/")[0].split(":")[0]

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


# ═════════════════════════════════════════════════════════════════════════════
#  NMAP COMMAND BUILDING
# ═════════════════════════════════════════════════════════════════════════════

def _scan_type_flag() -> str:
    return "-sS" if _has_root() else "-sT"


def _build_fast_cmd(
    hostfile: Path,
    out_prefix: Path,
    timing: str,
    max_rate: int,
) -> list[str]:
    cmd = [
        "nmap",
        _scan_type_flag(),
        "-sV",
        "--version-intensity", "7",
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open",
        "-Pn",
        "--reason",
        "--top-ports", str(FAST_TOP_PORTS),
        "-oA", str(out_prefix),
        "-iL", str(hostfile),
    ]
    if _has_root():
        cmd.extend(["-O", "--osscan-guess", "--osscan-limit"])
    if max_rate and max_rate > 0:
        cmd.extend(["--max-rate", str(max_rate)])
    return cmd


def _build_deep_cmd(
    hostfile: Path,
    out_prefix: Path,
    timing: str,
    nse: str,
    min_rate: int,
    max_rate: int,
) -> list[str]:
    cmd = [
        "nmap",
        _scan_type_flag(),
        "-sV",
        "--version-intensity", "9",
        "--version-all",
        "-sC",
        "--script", nse,
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open",
        "-Pn",
        "--reason",
        "-p-",
        "--traceroute",
        "-oA", str(out_prefix),
        "-iL", str(hostfile),
    ]
    if _has_root():
        cmd.extend(["-O", "--osscan-guess"])
    if min_rate and min_rate > 0:
        cmd.extend(["--min-rate", str(min_rate)])
    if max_rate and max_rate > 0:
        cmd.extend(["--max-rate", str(max_rate)])
    return cmd


def _run_nmap(cmd: list[str], timeout: int, label: str) -> bool:
    log.info(f"    $ {' '.join(cmd[:12])}{' ...' if len(cmd) > 12 else ''}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"    nmap {label} exceeded {timeout}s — using partial output")
        return False
    except FileNotFoundError:
        log.error("    nmap binary not found — install with `apt-get install nmap`")
        return False

    if result.returncode != 0:
        if not Path(cmd[cmd.index("-oA") + 1] + ".xml").exists():
            log.warning(f"    nmap {label} exited {result.returncode}: "
                        f"{result.stderr.strip()[:200]}")
            return False
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  XML PARSING (enhanced)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_nmap_xml(xml_path: Path, phase: str) -> list[HostInfo]:
    if not xml_path.exists():
        log.warning(f"    XML not found: {xml_path}")
        return []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        log.error(f"    failed to parse {xml_path}: {e}")
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
            ip=ip,
            hostname=hostname,
            status=status,
            phase=phase,
            first_seen=now,
        )

        # ── Ports ──────────────────────────────────────────────────────────
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

        # ── OS matches ─────────────────────────────────────────────────────
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host.os_matches.append({
                    "name":     osmatch.get("name", ""),
                    "accuracy": int(osmatch.get("accuracy", "0")),
                })

        # ── Host scripts ───────────────────────────────────────────────────
        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                host.host_scripts.append({
                    "id":     script_elem.get("id", ""),
                    "output": (script_elem.get("output", "") or "")[:1000],
                })

        # ── Traceroute ─────────────────────────────────────────────────────
        trace_elem = host_elem.find("trace")
        if trace_elem is not None:
            for hop_elem in trace_elem.findall("hop"):
                host.traceroute.append({
                    "ttl":  int(hop_elem.get("ttl", "0")),
                    "ip":   hop_elem.get("ipaddr", ""),
                    "rtt":  hop_elem.get("rtt", ""),
                    "host": hop_elem.get("host", ""),
                })

        _score_host(host)
        hosts.append(host)

    return hosts


# ═════════════════════════════════════════════════════════════════════════════
#  HOST SCORING (with diversity)
# ═════════════════════════════════════════════════════════════════════════════

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


def _select_deep_targets(candidates: list[HostInfo], limit: int) -> list[HostInfo]:
    """
    Pick deep-scan targets.

    Score by (score + diversity * 10) so a host with 1 DB port, 2 web ports,
    and an exposed RDP all on the same box outranks a single 30-port web host
    that only varies by port count. Diversity of service categories is a
    stronger signal than raw port count.
    """
    ranked = sorted(
        candidates,
        key=lambda h: (-(h.score + h.diversity * 10), -h.score, h.ip),
    )
    return ranked[:limit]


# ═════════════════════════════════════════════════════════════════════════════
#  MERGE
# ═════════════════════════════════════════════════════════════════════════════

def _merge_host_info(fast: list[HostInfo], deep: list[HostInfo]) -> list[HostInfo]:
    by_ip: dict[str, HostInfo] = {h.ip: h for h in fast}
    for h in deep:
        if h.ip in by_ip:
            if not h.hostname and by_ip[h.ip].hostname:
                h.hostname = by_ip[h.ip].hostname
            h.phase = "merged"
        by_ip[h.ip] = h
    return list(by_ip.values())


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

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


def _write_web_ports_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    """
    Emit URLs for every web port nmap found. Non-standard ports (not 80/443)
    are the useful part — downstream tools (httpx, nuclei, crawlers) can
    rescan these to find surfaces the initial live_hosts.txt feed missed.
    """
    urls: list[str] = []
    seen: set[str] = set()

    for h in hosts:
        host_label = h.hostname or h.ip
        if not host_label:
            continue
        for p in h.ports:
            if not p.is_web:
                continue
            # Decide scheme by port number
            if p.port in (443, 8443, 9443, 10443):
                scheme = "https"
            elif p.port in (80, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 9000, 9090):
                scheme = "http"
            else:
                # Fallback: try http first for unknown web ports
                scheme = "http"
            url = f"{scheme}://{host_label}:{p.port}"
            if url in seen:
                continue
            seen.add(url)
            tag = "standard" if p.port in STANDARD_WEB_PORTS else "nonstandard"
            urls.append(f"{url}\t{tag}\t{p.label()}")

    path = outdir / "nmap_web_ports.txt"
    path.write_text("\n".join(urls) + ("\n" if urls else ""))
    return path


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


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

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
    if not DB.available:
        log.warning("  DB sync: bridge client not ready")
        return

    try:
        # ── Step 1: hosts ──────────────────────────────────────────────────
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

        # ── Step 2: ports ──────────────────────────────────────────────────
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


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(
    live_hosts_file: Path,
    outdir: Path,
    *,
    deep_scan: bool = True,
    deep_limit: int = DEEP_HOST_LIMIT,
    deep_min_rate: Optional[int] = None,
    deep_max_rate: Optional[int] = None,
    use_vuln_scripts: bool = False,
    udp: bool = False,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Scan every host in `live_hosts_file` for open ports, services, and OS.
    """
    start = time.monotonic()

    if not _check_nmap():
        raise RuntimeError(
            "nmap not installed. Run `python3 tools.py --only nmap` "
            "or `sudo apt-get install nmap` first."
        )

    settings = _nmap_settings()
    eff_min_rate = deep_min_rate if deep_min_rate is not None else settings["min_rate"]
    eff_max_rate = deep_max_rate if deep_max_rate is not None else settings["max_rate"]
    eff_fast_timing = settings["timing_fast"]
    eff_deep_timing = settings["timing_deep"]

    hosts = _extract_hosts(live_hosts_file)
    outdir.mkdir(parents=True, exist_ok=True)

    if not hosts:
        log.warning("  No hosts to scan — writing empty report")
        return _write_empty_report(outdir, live_hosts_file, start)

    hostfile = outdir / "nmap_targets.txt"
    hostfile.write_text("\n".join(hosts) + "\n")

    log.info(f"  Input  : {len(hosts)} host(s) from {live_hosts_file.name}")
    log.info(f"  Mode   : {_scan_type_flag()} "
             f"({'root' if _has_root() else 'non-root'})  ·  "
             f"{'OS detection on' if _has_root() else 'OS detection off (needs root)'}")

    # Rate + timing config
    rate_parts = []
    if eff_min_rate and eff_min_rate > 0:
        rate_parts.append(f"min-rate={eff_min_rate}")
    if eff_max_rate and eff_max_rate > 0:
        rate_parts.append(f"max-rate={eff_max_rate}")
    rate_label = " · ".join(rate_parts) if rate_parts else "unlimited (nmap default)"
    log.info(f"  Config : timing fast={eff_fast_timing}  deep={eff_deep_timing}  "
             f"{rate_label}")
    log.info(f"           source: MODULE_RATE_LIMITS['nmap']")
    log.info(f"           note: nmap speaks TCP/IP directly — "
             f"platform headers and auth cookies are NOT applicable")
    log.info("")

    # ── Phase 1 ─────────────────────────────────────────────────────────────
    log.info("  Phase 1 — Fast sweep (top 1000 ports, service versions)")
    fast_prefix = outdir / "nmap_fast"
    fast_cmd = _build_fast_cmd(hostfile, fast_prefix, eff_fast_timing, eff_max_rate or 0)
    _run_nmap(fast_cmd, FAST_TIMEOUT, "phase 1")
    fast_hosts = _parse_nmap_xml(outdir / "nmap_fast.xml", phase="fast")
    log.info(f"    Parsed {len(fast_hosts)} live host(s) from phase 1")

    # Optional UDP
    if udp and _has_root():
        log.info("  Phase 1b — UDP top 100 ports")
        udp_prefix = outdir / "nmap_udp"
        udp_cmd = [
            "nmap", "-sU", "--top-ports", "100", "-T4", "--open", "-Pn",
            "-oA", str(udp_prefix), "-iL", str(hostfile),
        ]
        _run_nmap(udp_cmd, FAST_TIMEOUT, "udp")
        udp_hosts = _parse_nmap_xml(outdir / "nmap_udp.xml", phase="fast")
        fast_hosts = _merge_host_info(fast_hosts, udp_hosts)
        log.info(f"    Merged UDP results → {len(fast_hosts)} host(s)")
    elif udp:
        log.info("  Phase 1b — UDP skipped (needs root)")

    # ── Phase 2 ─────────────────────────────────────────────────────────────
    deep_hosts: list[HostInfo] = []
    if deep_scan and fast_hosts:
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
            )
            _run_nmap(deep_cmd, DEEP_TIMEOUT_PER_HOST * len(targets), "phase 2")
            deep_hosts = _parse_nmap_xml(outdir / "nmap_deep.xml", phase="deep")
            log.info(f"    Parsed {len(deep_hosts)} host(s) from phase 2")
        else:
            log.info("")
            log.info("  Phase 2 — skipped (no hosts with open ports)")
    elif deep_scan:
        log.info("")
        log.info("  Phase 2 — skipped (phase 1 returned no live hosts)")

    # ── Merge ───────────────────────────────────────────────────────────────
    combined = _merge_host_info(fast_hosts, deep_hosts)
    combined.sort(key=lambda h: (-h.score, h.ip))

    interesting = [h for h in combined if h.interesting]
    log.info("")
    log.info(f"  Combined: {len(combined)} host(s), "
             f"{len(interesting)} flagged interesting")

    # ── Flat outputs ────────────────────────────────────────────────────────
    ports_path        = _write_open_ports_txt(combined, outdir)
    interesting_path  = _write_interesting_txt(combined, outdir)
    os_path           = _write_os_guesses_txt(combined, outdir)
    web_ports_path    = _write_web_ports_txt(combined, outdir)

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    summary = _build_summary(combined)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_hosts_file),
        "config": {
            "scan_type":       "syn" if _has_root() else "connect",
            "os_detection":    _has_root(),
            "fast_top_ports":  FAST_TOP_PORTS,
            "fast_timing":     eff_fast_timing,
            "deep_timing":     eff_deep_timing,
            "deep_scan":       deep_scan,
            "deep_limit":      deep_limit,
            "deep_min_rate":   eff_min_rate or 0,
            "deep_max_rate":   eff_max_rate or 0,
            "vuln_scripts":    use_vuln_scripts,
            "udp":             udp,
            "headers_applied": False,
            "note":            "nmap speaks raw TCP/IP — platform headers and "
                               "auth cookies do not apply to this stage",
        },
        "totals": {
            "hosts_input":           len(hosts),
            "hosts_up":              len(combined),
            "hosts_with_open_ports": sum(1 for h in combined if h.ports),
            "hosts_interesting":     len(interesting),
            "total_open_ports":      summary["total_open_ports"],
        },
        "summary":  summary,
        "hosts":    [h.to_dict() for h in combined],
    }

    json_path = outdir / "nmap_scan.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, combined)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(combined):>5} host(s)")
    log.info(f"    {ports_path.name:<24} {summary['total_open_ports']:>5} port(s)")
    log.info(f"    {interesting_path.name:<24} {len(interesting):>5} interesting host(s)")
    log.info(f"    {os_path.name:<24} {sum(1 for h in combined if h.os_matches):>5} OS fingerprint(s)")
    log.info(f"    {web_ports_path.name:<24} "
             f"{sum(1 for _ in web_ports_path.read_text().splitlines()) if web_ports_path.exists() else 0:>5} web URL(s)")

    if summary["by_port"]:
        top_ports = list(summary["by_port"].items())[:10]
        log.info("")
        log.info("  Top ports      : " + " · ".join(f"{p}({n})" for p, n in top_ports))
    if summary["by_service"]:
        top_svcs = list(summary["by_service"].items())[:8]
        log.info("  Top services   : " + " · ".join(f"{s}({n})" for s, n in top_svcs))
    if summary["by_category"]:
        cats = summary["by_category"]
        log.info(f"  Categories     : web={cats['web']}  database={cats['database']}  "
                 f"admin={cats['admin']}  dangerous={cats['dangerous']}  "
                 f"remote_access={cats['remote_access']}")

    if interesting:
        log.info("")
        log.info("  Interesting hosts:")
        for h in interesting[:10]:
            label = h.hostname or h.ip
            top_ports = ",".join(str(p.port) for p in sorted(h.ports, key=lambda x: x.port)[:6])
            reasons = ",".join(h.reasons[:3])
            log.info(f"    {label:<40} score={h.score:>3} div={h.diversity}  "
                     f"ports=[{top_ports}]  [{reasons}]")

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
            "hosts_input": 0, "hosts_up": 0, "hosts_with_open_ports": 0,
            "hosts_interesting": 0, "total_open_ports": 0,
        },
        "summary": {"by_port": {}, "by_service": {}, "by_os": {},
                    "by_category": {}, "total_open_ports": 0},
        "hosts": [],
    }
    path = outdir / "nmap_scan.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nmap_open_ports.txt", "nmap_interesting.txt",
                 "nmap_os_guesses.txt", "nmap_web_ports.txt"):
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
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus nmap scanner (standalone)")
    parser.add_argument("--input", type=Path, default=live)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--deep-limit", type=int, default=DEEP_HOST_LIMIT)
    parser.add_argument("--deep-min-rate", type=int, default=None)
    parser.add_argument("--deep-max-rate", type=int, default=None)
    parser.add_argument("--no-deep", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--vuln", action="store_true")
    args = parser.parse_args()

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
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
