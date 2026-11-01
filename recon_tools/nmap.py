#!/usr/bin/env python3
"""
recon_tools/nmap.py — Port, Service & OS Discovery
═══════════════════════════════════════════════════════════════════════════════

The network discovery stage for Argus. Two-phase strategy:

  Phase 1 — Fast sweep (every host)
      `-sS -sV --top-ports 1000 --open`
      Fast, covers the ports where 99% of bug bounty findings live.

  Phase 2 — Deep scan (top-N interesting hosts)
      `-sS -sV -sC -p- -O` on hosts with high-interest services
      (databases, admin panels, dangerous protocols, multi-web-port hosts).

Privilege awareness:
  • Running as root  → SYN scan (-sS) + OS detection (-O)
  • Running as user  → TCP connect scan (-sT), no OS detection
  Both paths are transparent to the caller.

Outputs (into `outdir`):
  • nmap_fast.nmap / .xml / .gnmap     — raw phase-1 scan artifacts
  • nmap_deep.nmap / .xml / .gnmap     — raw phase-2 scan artifacts (if run)
  • nmap_scan.json                     — combined structured report
  • nmap_open_ports.txt                — flat "host:port service version" list
  • nmap_interesting.txt               — interesting hosts only
  • nmap_os_guesses.txt                — OS fingerprints

Integration:
  main.py → run_one("nmap") → run_nmap_scan(live_hosts_file, outdir)
"""

from __future__ import annotations

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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

FAST_TOP_PORTS        = 1000
FAST_TIMING           = "T4"
FAST_TIMEOUT          = 3600     # 60 min overall ceiling

DEEP_TIMING           = "T4"
DEEP_TIMEOUT_PER_HOST = 1800     # 30 min per host
DEEP_HOST_LIMIT       = 20
DEEP_MIN_RATE         = 0        # 0 = unset; set to e.g. 1000 for aggressive

# NSE script sets
DEFAULT_NSE   = "default,safe,discovery,http-headers,http-methods,ssl-cert,ssl-enum-ciphers"
VULN_NSE      = "vuln"

# Interesting-host score threshold
INTERESTING_SCORE = 30

# ── Port category sets ──────────────────────────────────────────────────────
# These drive the interesting-host scoring.
DATABASE_PORTS = {
    1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300,
    11211, 27017, 27018, 27019, 5984, 8086, 7474, 7687,
}
ADMIN_PORTS = {
    3000, 4000, 5000, 5601, 7077, 8000, 8001, 8008,
    8080, 8081, 8088, 8443, 8888, 9000, 9090, 9091,
    9092, 9093,
}
DANGEROUS_PORTS = {
    21, 23, 25, 111, 135, 137, 138, 139, 445,
    512, 513, 514, 873, 2049, 3260,
}
REMOTE_ACCESS_PORTS = {
    22, 3389, 5900, 5901, 5985, 5986,
}
WEB_PORTS = {
    80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: list[dict] = field(default_factory=list)

    def label(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        if parts:
            return f"{self.service} ({' '.join(parts)})"
        return self.service or f"port {self.port}"

    def to_dict(self) -> dict:
        return {
            "port":       self.port,
            "protocol":   self.protocol,
            "state":      self.state,
            "service":    self.service,
            "product":    self.product,
            "version":    self.version,
            "extrainfo":  self.extrainfo,
            "cpe":        self.cpe,
            "scripts":    self.scripts,
        }


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    status: str = "up"
    os_matches: list[dict] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    interesting: bool = False
    reasons: list[str] = field(default_factory=list)
    score: int = 0
    phase: str = ""          # "fast" | "deep" | "merged"

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "hostname":    self.hostname,
            "status":      self.status,
            "os_matches":  self.os_matches,
            "ports":       [p.to_dict() for p in self.ports],
            "interesting": self.interesting,
            "reasons":     self.reasons,
            "score":       self.score,
            "phase":       self.phase,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _extract_hosts(input_file: Path) -> list[str]:
    """
    Accept live_hosts.txt ('URL [status] [title] [tech]') or live_urls.txt
    (bare URLs). Return a deduplicated list of hostnames (no scheme/path/port).
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
    """Return -sS if we have root, -sT otherwise."""
    return "-sS" if _has_root() else "-sT"


def _build_fast_cmd(hostfile: Path, out_prefix: Path, timing: str) -> list[str]:
    cmd = [
        "nmap",
        _scan_type_flag(),
        "-sV",
        "--version-intensity", "7",
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open",
        "-Pn",
        "--top-ports", str(FAST_TOP_PORTS),
        "-oA", str(out_prefix),
        "-iL", str(hostfile),
    ]
    if _has_root():
        cmd.extend(["-O", "--osscan-guess"])
    return cmd


def _build_deep_cmd(hostfile: Path, out_prefix: Path, timing: str,
                    nse: str, min_rate: int) -> list[str]:
    cmd = [
        "nmap",
        _scan_type_flag(),
        "-sV",
        "--version-intensity", "9",
        "-sC",
        "--script", nse,
        f"-{timing}" if not timing.startswith("-") else timing,
        "--open",
        "-Pn",
        "-p-",
        "-oA", str(out_prefix),
        "-iL", str(hostfile),
    ]
    if _has_root():
        cmd.extend(["-O", "--osscan-guess"])
    if min_rate > 0:
        cmd.extend(["--min-rate", str(min_rate)])
    return cmd


def _run_nmap(cmd: list[str], timeout: int, label: str) -> bool:
    """Run nmap. Returns True on successful completion (even with 0 findings)."""
    log.info(f"    $ {' '.join(cmd[:10])}{' ...' if len(cmd) > 10 else ''}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"    nmap {label} exceeded {timeout}s — using partial output")
        return False
    except FileNotFoundError:
        log.error("    nmap binary not found — install with `apt-get install nmap`")
        return False

    if result.returncode != 0:
        # nmap returns non-zero on some non-fatal conditions; check for output
        if not Path(cmd[cmd.index("-oA") + 1] + ".xml").exists():
            log.warning(f"    nmap {label} exited {result.returncode}: "
                        f"{result.stderr.strip()[:200]}")
            return False
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  XML PARSING
# ═════════════════════════════════════════════════════════════════════════════

def _parse_nmap_xml(xml_path: Path, phase: str) -> list[HostInfo]:
    """Parse nmap's XML output into HostInfo records."""
    if not xml_path.exists():
        log.warning(f"    XML not found: {xml_path}")
        return []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        log.error(f"    failed to parse {xml_path}: {e}")
        return []

    hosts: list[HostInfo] = []

    for host_elem in root.findall("host"):
        # Status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        if status != "up":
            continue

        # IP address (prefer ipv4, then ipv6)
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

        # Hostname (PTR from nmap)
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

        host = HostInfo(ip=ip, hostname=hostname, status=status, phase=phase)

        # Ports
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
                        "output": (script_elem.get("output", "") or "")[:500],
                    })

                host.ports.append(port)

        # OS matches
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host.os_matches.append({
                    "name":     osmatch.get("name", ""),
                    "accuracy": int(osmatch.get("accuracy", "0")),
                })

        _score_host(host)
        hosts.append(host)

    return hosts


# ═════════════════════════════════════════════════════════════════════════════
#  HOST SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _score_host(host: HostInfo) -> None:
    """Score a host for bug bounty relevance. Higher = more interesting."""
    reasons: list[str] = []
    score = 0

    if host.os_matches:
        best_acc = max(o["accuracy"] for o in host.os_matches)
        score += 10 if best_acc >= 85 else 5
        reasons.append("os_fingerprinted")

    web_port_count = 0
    for port in host.ports:
        p = port.port

        if p in DATABASE_PORTS:
            score += 40
            reasons.append(f"database_port:{p}")

        if p in ADMIN_PORTS:
            score += 30
            reasons.append(f"admin_port:{p}")

        if p in DANGEROUS_PORTS:
            score += 25
            reasons.append(f"dangerous_port:{p}")

        if p in REMOTE_ACCESS_PORTS:
            score += 15
            reasons.append(f"remote_access:{p}")

        if p in WEB_PORTS or port.service in (
            "http", "https", "http-proxy", "http-alt", "ssl/http"
        ):
            web_port_count += 1
            score += 3

        if port.product and port.version:
            score += 5
            reasons.append(f"version_known:{p}")

    if web_port_count > 1:
        score += 15
        reasons.append(f"multi_web_ports:{web_port_count}")

    if len(host.ports) >= 10:
        score += 10
        reasons.append(f"many_open_ports:{len(host.ports)}")

    host.score = score
    host.reasons = reasons
    host.interesting = score >= INTERESTING_SCORE


# ═════════════════════════════════════════════════════════════════════════════
#  MERGE & DEDUPLICATE
# ═════════════════════════════════════════════════════════════════════════════

def _merge_host_info(fast: list[HostInfo], deep: list[HostInfo]) -> list[HostInfo]:
    """Merge phase-1 and phase-2 results. Deep phase wins when both exist."""
    by_ip: dict[str, HostInfo] = {h.ip: h for h in fast}
    for h in deep:
        if h.ip in by_ip:
            # Preserve phase-1 hostname if phase-2 has none
            if not h.hostname and by_ip[h.ip].hostname:
                h.hostname = by_ip[h.ip].hostname
            h.phase = "merged"
        by_ip[h.ip] = h
    return list(by_ip.values())


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_open_ports_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    """Flat list: 'host port/service version' one per line."""
    lines: list[str] = []
    for h in sorted(hosts, key=lambda x: x.ip):
        host_label = h.hostname or h.ip
        for p in sorted(h.ports, key=lambda x: x.port):
            detail = p.label()
            lines.append(f"{host_label}:{p.port}\t{p.protocol}\t{detail}")
    path = outdir / "nmap_open_ports.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_interesting_txt(hosts: list[HostInfo], outdir: Path) -> Path:
    lines: list[str] = []
    for h in sorted(hosts, key=lambda x: (-x.score, x.ip)):
        if not h.interesting:
            continue
        host_label = h.hostname or h.ip
        reasons = ",".join(h.reasons)
        ports = ",".join(str(p.port) for p in h.ports)
        lines.append(f"{host_label}\t{h.ip}\tscore={h.score}\t{reasons}\tports=[{ports}]")
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


def _build_summary(hosts: list[HostInfo]) -> dict:
    by_port: dict[str, int] = {}
    by_service: dict[str, int] = {}
    by_os: dict[str, int] = {}
    total_ports = 0

    for h in hosts:
        for p in h.ports:
            total_ports += 1
            by_port[str(p.port)] = by_port.get(str(p.port), 0) + 1
            svc = p.service or "unknown"
            by_service[svc] = by_service.get(svc, 0) + 1

        for o in h.os_matches[:1]:
            name = o["name"]
            by_os[name] = by_os.get(name, 0) + 1

    return {
        "total_open_ports": total_ports,
        "by_port":    dict(sorted(by_port.items(), key=lambda kv: -kv[1])),
        "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
        "by_os":      dict(sorted(by_os.items(), key=lambda kv: -kv[1])),
    }


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(
    live_hosts_file: Path,
    outdir: Path,
    *,
    deep_scan: bool = True,
    deep_limit: int = DEEP_HOST_LIMIT,
    deep_min_rate: int = DEEP_MIN_RATE,
    use_vuln_scripts: bool = False,
    udp: bool = False,
) -> Path:
    """
    Scan every host in `live_hosts_file` for open ports, services, and OS.

    Returns the path to `nmap_scan.json`.
    """
    start = time.monotonic()

    if not _check_nmap():
        raise RuntimeError(
            "nmap not installed. Run `python3 tools.py --only nmap` or "
            "`sudo apt-get install nmap` first."
        )

    # ── Inputs ──────────────────────────────────────────────────────────────
    hosts = _extract_hosts(live_hosts_file)
    outdir.mkdir(parents=True, exist_ok=True)

    if not hosts:
        log.warning("  No hosts to scan — writing empty report")
        return _write_empty_report(outdir, live_hosts_file, start)

    # Write the canonical host list nmap will read from
    hostfile = outdir / "nmap_targets.txt"
    hostfile.write_text("\n".join(hosts) + "\n")

    log.info(f"  Input  : {len(hosts)} host(s) from {live_hosts_file.name}")
    log.info(f"  Mode   : {_scan_type_flag()} "
             f"({'root' if _has_root() else 'non-root'})  ·  "
             f"{'OS detection on' if _has_root() else 'OS detection off (needs root)'}")
    log.info("")

    # ── Phase 1: Fast sweep ─────────────────────────────────────────────────
    log.info("  Phase 1 — Fast sweep (top 1000 ports, service versions)")
    fast_prefix = outdir / "nmap_fast"
    fast_cmd = _build_fast_cmd(hostfile, fast_prefix, FAST_TIMING)
    _run_nmap(fast_cmd, FAST_TIMEOUT, "phase 1")
    fast_hosts = _parse_nmap_xml(outdir / "nmap_fast.xml", phase="fast")
    log.info(f"    Parsed {len(fast_hosts)} live host(s) from phase 1")

    # Optional UDP pass (small, fast, but noisy)
    if udp:
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

    # ── Phase 2: Deep scan (top-N interesting hosts) ────────────────────────
    deep_hosts: list[HostInfo] = []
    if deep_scan and fast_hosts:
        # Select hosts with open ports, sorted by score
        candidates = [h for h in fast_hosts if h.ports]
        candidates.sort(key=lambda h: -h.score)
        targets = candidates[:deep_limit]

        if targets:
            log.info("")
            log.info(f"  Phase 2 — Deep scan (full port range) on "
                     f"{len(targets)}/{len(candidates)} interesting host(s)")
            for h in targets:
                log.info(f"    {h.ip:<18} {h.hostname or '(no PTR)':<40} "
                         f"score={h.score}  ports={len(h.ports)}")

            deep_hostfile = outdir / "nmap_deep_targets.txt"
            deep_hostfile.write_text("\n".join(h.ip for h in targets) + "\n")

            nse = DEFAULT_NSE + ("," + VULN_NSE if use_vuln_scripts else "")
            deep_prefix = outdir / "nmap_deep"
            deep_cmd = _build_deep_cmd(
                deep_hostfile, deep_prefix, DEEP_TIMING, nse, deep_min_rate
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

    # ── Write flat text outputs ─────────────────────────────────────────────
    ports_path = _write_open_ports_txt(combined, outdir)
    interesting_path = _write_interesting_txt(combined, outdir)
    os_path = _write_os_guesses_txt(combined, outdir)

    # ── Build JSON report ──────────────────────────────────────────────────
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
            "fast_timing":     FAST_TIMING,
            "deep_scan":       deep_scan,
            "deep_limit":      deep_limit,
            "deep_min_rate":   deep_min_rate,
            "vuln_scripts":    use_vuln_scripts,
            "udp":             udp,
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

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(combined):>5} host(s)")
    log.info(f"    {ports_path.name:<24} {summary['total_open_ports']:>5} port(s)")
    log.info(f"    {interesting_path.name:<24} {len(interesting):>5} interesting host(s)")
    log.info(f"    {os_path.name:<24} {sum(1 for h in combined if h.os_matches):>5} OS fingerprint(s)")

    if summary["by_port"]:
        top_ports = list(summary["by_port"].items())[:10]
        log.info("")
        log.info("  Top open ports : " + " · ".join(f"{p}({n})" for p, n in top_ports))
    if summary["by_service"]:
        top_svcs = list(summary["by_service"].items())[:8]
        log.info("  Top services   : " + " · ".join(f"{s}({n})" for s, n in top_svcs))

    if interesting:
        log.info("")
        log.info("  Interesting hosts:")
        for h in interesting[:10]:
            label = h.hostname or h.ip
            top_ports = ",".join(str(p.port) for p in sorted(h.ports, key=lambda x: x.port)[:5])
            reasons = ",".join(h.reasons[:3])
            log.info(f"    {label:<40} score={h.score:>3}  ports=[{top_ports}]  [{reasons}]")

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
        "summary": {"by_port": {}, "by_service": {}, "by_os": {}, "total_open_ports": 0},
        "hosts": [],
    }
    path = outdir / "nmap_scan.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nmap_open_ports.txt", "nmap_interesting.txt", "nmap_os_guesses.txt"):
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
    out = base / "output"
    try:
        run_nmap_scan(live, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
