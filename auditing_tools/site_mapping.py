#!/usr/bin/env python3
"""
auditing_tools/site_mapping.py — Master Site Map Consolidator
═══════════════════════════════════════════════════════════════════════════════

The master index for the entire Argus pipeline. Reads every artifact from
`output/`, cross-references findings to their endpoints, and produces a
single hierarchical site map that represents the complete attack surface.

Why this module exists:

  Without site_mapping.py:
    Each finder reads its own artifact. Endpoints, parameters, findings,
    and hosts are scattered across 20+ files. There is no single truth.

  With site_mapping.py:
    One file — `site_map.json` — tells you every host, every endpoint,
    every parameter, every finding, and how they relate.

The map is hierarchical:

  Scope (wildcard roots)
    └── Hosts (live hosts, IPs, technologies, ports)
          └── Endpoints (URLs, methods, parameters)
                └── Findings (SQLi, XSS, SSRF, IDOR, CORS, etc.)

Cross-referencing:
  A finding is attached to its endpoint when:
    • The finding's `target` matches the endpoint URL exactly, OR
    • The finding's `target` host matches the endpoint host, OR
    • The finding's `details` references the endpoint URL.

Outputs (into `outdir`):
  • site_map.json             — full hierarchical map (primary output)
  • site_map.md               — human-readable navigable map
  • site_map_hosts.txt        — flat host list with metadata
  • site_map_endpoints.txt    — flat endpoint list with methods
  • site_map_parameters.txt   — flat endpoint → parameters mapping
  • site_map_findings.txt     — flat finding list with severity

Integration:
  main.py → run_one("mapping") → run_site_mapping(live_urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("argus.site_mapping")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

MAX_ENDPOINTS_PER_HOST = 5000
MAX_FINDINGS_PER_ENDPOINT = 100

# Artifact files the consolidator reads — each is optional
ARTIFACT_FILES = {
    "wildcards":        "wildcard.txt",
    "subdomains":       "all_subs.txt",
    "dns_resolved":     "dns_wildcard_filtered.txt",
    "dns_records":      "dns_resolve.json",
    "takeover":         "takeover_findings.json",
    "live_hosts":       "live_hosts.json",
    "nmap":             "nmap_scan.json",
    "all_urls":         "all_urls.txt",
    "urls_with_params": "urls_with_params.txt",
    "urls_js":          "urls_js_files.txt",
    "urls_interesting": "urls_interesting.txt",
    "js_findings":      "js_findings.json",
    "param_findings":   "param_findings.json",
    "params_by_endpoint": "params_by_endpoint.txt",
    "content_fuzz":     "content_fuzz.json",
    "nuclei":           "nuclei_findings.json",
    "cors":             "cors_findings.json",
    "auth":             "auth_findings.json",
    "cache":            "cache_findings.json",
    "graphql":          "graphql_findings.json",
    "idor":             "idor_findings.json",
    "open_redirect":    "open_redirect_findings.json",
    "race":             "race_findings.json",
    "sqli":             "sqli_candidates.txt",
    "xss":              "xss_candidates.txt",
    "ssrf":             "ssrf_candidates.txt",
    "url_categorize":   "url_categorize.json",
    "triage":           "triage_report.json",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointNode:
    """A single URL endpoint in the site map."""
    url: str
    method: str = "GET"
    host: str = ""
    path: str = ""
    parameters: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)   # gf categories
    findings: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url":          self.url,
            "method":       self.method,
            "host":         self.host,
            "path":         self.path,
            "parameters":   sorted(set(self.parameters)),
            "categories":   sorted(set(self.categories)),
            "technologies": sorted(set(self.technologies)),
            "findings":     self.findings[:MAX_FINDINGS_PER_ENDPOINT],
            "finding_count": len(self.findings),
        }


@dataclass
class HostNode:
    """A single host in the site map."""
    hostname: str
    ip: str = ""
    status_code: int = 0
    technologies: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)
    cname: str = ""
    cdn: str = ""
    geo: list[dict] = field(default_factory=list)
    endpoints: dict[str, EndpointNode] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)   # host-level findings
    auth_surface: list[dict] = field(default_factory=list)
    graphql_endpoints: list[dict] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    takeover: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "hostname":     self.hostname,
            "ip":           self.ip,
            "status_code":  self.status_code,
            "technologies": sorted(set(self.technologies)),
            "ports":        self.ports,
            "cname":        self.cname,
            "cdn":          self.cdn,
            "geo":          self.geo,
            "dns_records":  self.dns_records,
            "takeover":     self.takeover,
            "auth_surface": self.auth_surface,
            "graphql_endpoints": self.graphql_endpoints,
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in list(self.endpoints.values())[:MAX_ENDPOINTS_PER_HOST]],
            "host_findings": self.findings,
            "host_finding_count": len(self.findings),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as e:
        log.debug(f"    failed to load {path.name}: {e}")
        return None


def _load_txt(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception:
        return []


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urllib.parse.urlparse(url).hostname or ""


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        "",
        parsed.query,
        "",
    ))


def _extract_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return sorted(params.keys())


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        (s or "").upper(), 5
    )


# ═════════════════════════════════════════════════════════════════════════════
#  LOADERS — one per artifact type
# ═════════════════════════════════════════════════════════════════════════════

def _load_scope(outdir: Path) -> list[str]:
    wildcards_path = outdir.parent / "wildcard.txt"
    if wildcards_path.exists():
        return [
            line.strip().lower()
            for line in wildcards_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    return []


def _load_live_hosts(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Load live_hosts.json — the primary host enrichment source."""
    data = _load_json(outdir / "live_hosts.json")
    if not data:
        return 0

    count = 0
    for h in data.get("hosts", []):
        hostname = h.get("subdomain") or _host_from_url(h.get("url", ""))
        if not hostname:
            continue

        node = hosts.get(hostname) or HostNode(hostname=hostname)
        node.status_code = h.get("status_code") or 0
        node.technologies = list(h.get("technologies") or [])
        node.cname = h.get("cname") or ""
        node.cdn = h.get("cdn") or ""
        node.geo = list(h.get("geo") or [])

        ips = h.get("ip")
        if isinstance(ips, list) and ips:
            node.ip = ips[0]
        elif isinstance(ips, str):
            node.ip = ips

        hosts[hostname] = node
        count += 1

    return count


def _load_nmap(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach nmap port data to hosts."""
    data = _load_json(outdir / "nmap_scan.json")
    if not data:
        return 0

    count = 0
    for h in data.get("hosts", []):
        hostname = h.get("hostname") or h.get("ip", "")
        if not hostname:
            continue

        node = hosts.get(hostname)
        if not node:
            node = HostNode(hostname=hostname, ip=h.get("ip", ""))
            hosts[hostname] = node

        node.ports = h.get("ports", [])
        if not node.ip:
            node.ip = h.get("ip", "")
        count += 1

    return count


def _load_dns(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach DNS records and takeover data to hosts."""
    data = _load_json(outdir / "dns_resolve.json")
    if not data:
        return 0

    count = 0
    for r in data.get("records", []):
        host = r.get("host", "")
        if not host:
            continue
        node = hosts.get(host)
        if not node:
            node = HostNode(hostname=host)
            hosts[host] = node
        node.dns_records = {
            "a":     r.get("a", []),
            "aaaa":  r.get("aaaa", []),
            "cname": r.get("cname", []),
            "mx":    r.get("mx", []),
            "ns":    r.get("ns", []),
            "txt":   r.get("txt", []),
        }
        count += 1

    return count


def _load_takeover(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach takeover findings to hosts."""
    data = _load_json(outdir / "takeover_findings.json")
    if not data:
        return 0

    count = 0
    for f in data.get("findings", []):
        subdomain = f.get("subdomain", "")
        if not subdomain:
            continue
        node = hosts.get(subdomain)
        if not node:
            node = HostNode(hostname=subdomain)
            hosts[subdomain] = node
        node.takeover = {
            "status":    f.get("status", ""),
            "service":   f.get("service", ""),
            "cvss":      f.get("cvss", 0),
            "evidence":  f.get("fingerprint", ""),
        }
        node.findings.append({
            "type":     "takeover",
            "severity": "CRITICAL" if f.get("status") == "VULNERABLE" else "HIGH",
            "source":   "takeover_check",
            "evidence": f.get("notes", "")[:300],
        })
        count += 1

    return count


def _load_urls(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Populate endpoint nodes from all URLs (union of all URL lists)."""
    url_sources = [
        outdir / "all_urls.txt",
        outdir / "urls_with_params.txt",
        outdir / "urls_js_files.txt",
        outdir / "urls_interesting.txt",
    ]
    seen_endpoints: set[str] = set()

    for src in url_sources:
        for line in _load_txt(src):
            url = line.split()[0] if line else ""
            norm = _normalize_url(url)
            if not norm or norm in seen_endpoints:
                continue
            seen_endpoints.add(norm)

            hostname = _host_from_url(norm)
            if not hostname:
                continue

            node = hosts.get(hostname)
            if not node:
                node = HostNode(hostname=hostname)
                hosts[hostname] = node

            parsed = urllib.parse.urlparse(norm)
            endpoint = EndpointNode(
                url=norm,
                method="GET",
                host=hostname,
                path=parsed.path or "/",
                parameters=_extract_params(norm),
            )
            node.endpoints[norm] = endpoint

    return len(seen_endpoints)


def _load_params_by_endpoint(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach discovered parameters from params_by_endpoint.txt."""
    lines = _load_txt(outdir / "params_by_endpoint.txt")
    if not lines:
        return 0

    count = 0
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        method, url, params_str = parts[0], parts[1], parts[2]
        norm = _normalize_url(url)
        hostname = _host_from_url(norm)
        if not hostname:
            continue

        node = hosts.get(hostname)
        if not node:
            node = HostNode(hostname=hostname)
            hosts[hostname] = node

        endpoint = node.endpoints.get(norm)
        if not endpoint:
            endpoint = EndpointNode(
                url=norm,
                method=method,
                host=hostname,
                path=urllib.parse.urlparse(norm).path or "/",
            )
            node.endpoints[norm] = endpoint

        discovered = [p.strip() for p in params_str.split(",") if p.strip()]
        endpoint.parameters = sorted(set(endpoint.parameters + discovered))
        count += 1

    return count


def _load_url_categorize(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach gf categories to endpoints."""
    data = _load_json(outdir / "url_categorize.json")
    if not data:
        return 0

    count = 0
    for cat in data.get("categories", []):
        cat_name = cat.get("name", "")
        for url in cat.get("urls", []):
            norm = _normalize_url(url)
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.categories.append(cat_name)
                count += 1

    return count


def _load_findings(outdir: Path, hosts: dict[str, HostNode]) -> dict[str, int]:
    """Attach findings from every JSON finder to their endpoints/hosts."""
    stats = {
        "nuclei": 0, "cors": 0, "auth": 0, "cache": 0,
        "graphql": 0, "idor": 0, "redirect": 0, "race": 0,
        "js": 0, "sqli": 0, "xss": 0, "ssrf": 0, "param": 0,
    }

    # ── Nuclei ──────────────────────────────────────────────────────────────
    data = _load_json(outdir / "nuclei_findings.json")
    if data:
        for f in data.get("findings", []):
            target = f.get("matched_at") or f.get("host", "")
            norm = _normalize_url(target)
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "nuclei",
                "subtype":  f.get("template_id", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "nuclei",
                "evidence": (f.get("template_name", "") or "")[:200],
                "details": {
                    "cve_ids":     f.get("cve_ids", []),
                    "cvss_score":  f.get("cvss_score", 0),
                },
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["nuclei"] += 1

    # ── CORS ────────────────────────────────────────────────────────────────
    data = _load_json(outdir / "cors_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("url", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "cors",
                "subtype":  f.get("probe", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "cors_check",
                "evidence": (f.get("reasons") or []) and ", ".join(f.get("reasons", [])[:4]),
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["cors"] += 1

    # ── Auth ────────────────────────────────────────────────────────────────
    data = _load_json(outdir / "auth_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "auth",
                "subtype":  f.get("vuln_type", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "auth_tester",
                "evidence": (f.get("evidence", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            # Also attach to auth surface
            node.auth_surface.append(finding)
            stats["auth"] += 1

    # ── Cache ───────────────────────────────────────────────────────────────
    data = _load_json(outdir / "cache_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "cache",
                "subtype":  f.get("vuln_type", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "cache_poisoning",
                "evidence": (f.get("evidence", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["cache"] += 1

    # ── GraphQL ─────────────────────────────────────────────────────────────
    data = _load_json(outdir / "graphql_findings.json")
    if data:
        for ep in data.get("endpoints", []):
            norm = _normalize_url(ep.get("url", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            node.graphql_endpoints.append({
                "url":          norm,
                "engine":       ep.get("engine", ""),
                "introspectable": ep.get("introspectable", False),
            })
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "graphql",
                "subtype":  f.get("vuln_type", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "graphql_finder",
                "evidence": (f.get("evidence", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["graphql"] += 1

    # ── IDOR ────────────────────────────────────────────────────────────────
    data = _load_json(outdir / "idor_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "idor",
                "subtype":  f.get("vuln_type", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "idor_finder",
                "evidence": (f.get("evidence", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["idor"] += 1

    # ── Redirect ────────────────────────────────────────────────────────────
    data = _load_json(outdir / "open_redirect_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "open_redirect",
                "subtype":  f.get("vector", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "open_redirect_finder",
                "evidence": (f.get("evidence", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["redirect"] += 1

    # ── Race ────────────────────────────────────────────────────────────────
    data = _load_json(outdir / "race_findings.json")
    if data:
        for c in data.get("candidates", []):
            norm = _normalize_url(c.get("target", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     "race_condition",
                "subtype":  c.get("race_class", ""),
                "severity": (c.get("severity") or "MEDIUM").upper(),
                "source":   "race_condition",
                "evidence": (c.get("description", "") or "")[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["race"] += 1

    # ── JS findings ─────────────────────────────────────────────────────────
    data = _load_json(outdir / "js_findings.json")
    if data:
        for f in data.get("findings", []):
            if f.get("kind") == "secret":
                norm = _normalize_url(f.get("file_url", ""))
            else:
                norm = _normalize_url(f.get("value", "")) if f.get("kind") == "endpoint" else ""
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     f"js_{f.get('kind', '')}",
                "subtype":  f.get("subtype", ""),
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "source":   "js_analysis",
                "evidence": (f.get("redacted") or f.get("value", ""))[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats["js"] += 1

    # ── Parameter findings ──────────────────────────────────────────────────
    data = _load_json(outdir / "param_findings.json")
    if data:
        for f in data.get("findings", []):
            norm = _normalize_url(f.get("url", ""))
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            endpoint = node.endpoints.get(norm)
            if endpoint:
                param = f.get("parameter", "")
                if param and param not in endpoint.parameters:
                    endpoint.parameters.append(param)
            stats["param"] += 1

    # ── Flat candidate files (sqli / xss / ssrf) ────────────────────────────
    flat_sources = [
        ("sqli_candidates.txt", "sqli", "sqli_finder", "sqli"),
        ("xss_candidates.txt",  "xss",  "xss_finder",  "xss"),
        ("ssrf_candidates.txt", "ssrf", "ssrf_finder", "ssrf"),
    ]
    for filename, stat_key, source, ftype in flat_sources:
        for line in _load_txt(outdir / filename):
            parts = line.split("\t")
            target = parts[0] if parts else ""
            norm = _normalize_url(target)
            hostname = _host_from_url(norm)
            if not hostname:
                continue
            node = hosts.get(hostname)
            if not node:
                continue
            finding = {
                "type":     ftype,
                "subtype":  "candidate",
                "severity": "MEDIUM",
                "source":   source,
                "evidence": line[:200],
            }
            endpoint = node.endpoints.get(norm)
            if endpoint:
                endpoint.findings.append(finding)
            else:
                node.findings.append(finding)
            stats[stat_key] += 1

    return stats


# ═════════════════════════════════════════════════════════════════════════════
#  ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _compute_host_score(node: HostNode) -> int:
    """Score a host by the total severity of its findings."""
    score = 0
    sev_points = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}

    for f in node.findings:
        score += sev_points.get(f.get("severity", "INFO"), 0)
    for ep in node.endpoints.values():
        for f in ep.findings:
            score += sev_points.get(f.get("severity", "INFO"), 0)

    # Bonus signals
    if node.ports:
        score += len(node.ports) * 2
    if node.takeover and node.takeover.get("status") == "VULNERABLE":
        score += 50
    if node.graphql_endpoints:
        score += 10
    if node.auth_surface:
        score += 15

    return score


def _build_summary(hosts: dict[str, HostNode]) -> dict:
    total_endpoints = sum(len(h.endpoints) for h in hosts.values())
    total_findings = sum(len(h.findings) for h in hosts.values()) + sum(
        len(e.findings) for h in hosts.values() for e in h.endpoints.values()
    )

    by_severity: dict[str, int] = defaultdict(int)
    by_finding_type: dict[str, int] = defaultdict(int)

    for h in hosts.values():
        for f in h.findings:
            by_severity[f.get("severity", "INFO")] += 1
            by_finding_type[f.get("type", "unknown")] += 1
        for e in h.endpoints.values():
            for f in e.findings:
                by_severity[f.get("severity", "INFO")] += 1
                by_finding_type[f.get("type", "unknown")] += 1

    top_hosts = sorted(
        hosts.values(),
        key=lambda h: (-_compute_host_score(h), h.hostname),
    )[:20]

    return {
        "hosts":         len(hosts),
        "endpoints":     total_endpoints,
        "findings":      total_findings,
        "by_severity":   dict(by_severity),
        "by_finding_type": dict(sorted(by_finding_type.items(), key=lambda kv: -kv[1])),
        "top_hosts":     [
            {
                "hostname":    h.hostname,
                "score":       _compute_host_score(h),
                "endpoints":   len(h.endpoints),
                "findings":    len(h.findings) + sum(len(e.findings) for e in h.endpoints.values()),
            }
            for h in top_hosts
        ],
    }


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_json_map(
    scope: list[str], hosts: dict[str, HostNode],
    stats: dict, elapsed: float, outdir: Path,
) -> Path:
    """Write the full hierarchical site map."""
    summary = _build_summary(hosts)

    sorted_hosts = sorted(hosts.values(), key=lambda h: (-_compute_host_score(h), h.hostname))

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "scope":           scope,
        "summary":         summary,
        "load_stats":      stats,
        "hosts":           [h.to_dict() for h in sorted_hosts],
    }

    path = outdir / "site_map.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return path


def _write_hosts_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    """Flat host list with metadata."""
    lines = []
    for h in sorted(hosts.values(), key=lambda x: (-_compute_host_score(x), x.hostname)):
        ports = ",".join(str(p.get("port", "")) for p in h.ports[:10])
        tech = ",".join(h.technologies[:5])
        finding_count = len(h.findings) + sum(len(e.findings) for e in h.endpoints.values())
        lines.append(
            f"{h.hostname}\t{h.ip}\tstatus={h.status_code}\t"
            f"endpoints={len(h.endpoints)}\tfindings={finding_count}\t"
            f"ports=[{ports}]\ttech=[{tech}]"
        )
    path = outdir / "site_map_hosts.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_endpoints_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    """Flat endpoint list with methods and finding counts."""
    lines = []
    for h in hosts.values():
        for ep in h.endpoints.values():
            lines.append(
                f"{ep.method}\t{ep.url}\t"
                f"params={len(ep.parameters)}\t"
                f"categories={','.join(ep.categories)}\t"
                f"findings={len(ep.findings)}"
            )
    lines.sort()
    path = outdir / "site_map_endpoints.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_parameters_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    """Flat endpoint → parameters mapping."""
    lines = []
    for h in hosts.values():
        for ep in h.endpoints.values():
            if not ep.parameters:
                continue
            lines.append(f"{ep.url}\t{','.join(sorted(ep.parameters))}")
    lines.sort()
    path = outdir / "site_map_parameters.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_findings_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    """Flat finding list with severity and target."""
    rows = []
    for h in hosts.values():
        for f in h.findings:
            rows.append((_severity_rank(f.get("severity", "INFO")), h.hostname, f))
        for ep in h.endpoints.values():
            for f in ep.findings:
                rows.append((_severity_rank(f.get("severity", "INFO")), ep.url, f))
    rows.sort(key=lambda r: (r[0], r[1]))

    lines = [
        f"[{f.get('severity', 'INFO'):<8}] {f.get('type', ''):<20} {f.get('source', ''):<20} {target}"
        for _, target, f in rows
    ]
    path = outdir / "site_map_findings.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_markdown(hosts: dict[str, HostNode], outdir: Path, scope: list[str]) -> Path:
    """Human-readable navigable map."""
    lines: list[str] = []
    summary = _build_summary(hosts)

    lines.append("# Argus Site Map")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if scope:
        lines.append("## Scope")
        lines.append("")
        for root in scope:
            lines.append(f"- `{root}`")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Hosts:** {summary['hosts']}")
    lines.append(f"- **Endpoints:** {summary['endpoints']}")
    lines.append(f"- **Findings:** {summary['findings']}")
    lines.append("")
    lines.append("**By severity:**")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = summary["by_severity"].get(sev, 0)
        if count:
            lines.append(f"- {sev}: {count}")
    lines.append("")

    # Top hosts
    lines.append("## Top hosts by risk score")
    lines.append("")
    lines.append("| Host | Score | Endpoints | Findings |")
    lines.append("|------|-------|-----------|----------|")
    for h in summary["top_hosts"][:20]:
        lines.append(f"| `{h['hostname']}` | {h['score']} | {h['endpoints']} | {h['findings']} |")
    lines.append("")

    # Per-host detail
    lines.append("## Host details")
    lines.append("")
    sorted_hosts = sorted(hosts.values(), key=lambda h: (-_compute_host_score(h), h.hostname))
    for h in sorted_hosts[:30]:
        score = _compute_host_score(h)
        lines.append(f"### `{h.hostname}` (score: {score})")
        lines.append("")

        meta = []
        if h.ip:
            meta.append(f"IP: `{h.ip}`")
        if h.status_code:
            meta.append(f"Status: {h.status_code}")
        if h.technologies:
            meta.append(f"Tech: {', '.join(h.technologies[:5])}")
        if h.ports:
            port_list = ", ".join(str(p.get("port", "")) for p in h.ports[:10])
            meta.append(f"Ports: {port_list}")
        if h.cdn:
            meta.append(f"CDN: {h.cdn}")
        if h.takeover:
            meta.append(f"⚠ **Takeover: {h.takeover.get('status', '')}**")
        if meta:
            lines.append(" · ".join(meta))
            lines.append("")

        # Host-level findings
        if h.findings:
            lines.append("**Host findings:**")
            for f in sorted(h.findings, key=lambda x: _severity_rank(x.get("severity", "INFO")))[:10]:
                lines.append(f"- [{f.get('severity', 'INFO')}] {f.get('type', '')}: {f.get('evidence', '')[:120]}")
            lines.append("")

        # Endpoints with findings
        endpoints_with_findings = [
            (e, [f for f in e.findings]) for e in h.endpoints.values()
            if e.findings
        ]
        if endpoints_with_findings:
            lines.append(f"**Endpoints with findings ({len(endpoints_with_findings)}):**")
            for ep, findings in sorted(
                endpoints_with_findings,
                key=lambda x: min(_severity_rank(f.get("severity", "INFO")) for f in x[1]),
            )[:15]:
                max_sev = min(findings, key=lambda f: _severity_rank(f.get("severity", "INFO"))).get("severity", "INFO")
                lines.append(f"- [{max_sev}] `{ep.url}` ({len(findings)} finding(s))")
            lines.append("")

        # Endpoints with parameters
        param_endpoints = [e for e in h.endpoints.values() if e.parameters and not e.findings]
        if param_endpoints:
            lines.append(f"**Parameterised endpoints ({len(param_endpoints)}):**")
            for ep in param_endpoints[:10]:
                lines.append(f"- `{ep.url}` — params: `{', '.join(ep.parameters[:8])}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    path = outdir / "site_map.md"
    path.write_text("\n".join(lines) + "\n")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_site_mapping(
    live_urls_file: Path,
    outdir: Path,
    *,
    wildcard_file: Optional[Path] = None,
) -> Path:
    """
    Consolidate every artifact in `outdir` into a single site map.

    The `live_urls_file` argument is accepted for pipeline compatibility
    with main.py, but the module reads from the full artifact set regardless.

    Returns the path to `site_map.json`.
    """
    start = time.monotonic()
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Output dir : {outdir}")
    log.info("")

    # ── Load scope ──────────────────────────────────────────────────────────
    scope = _load_scope(wildcard_file or outdir)
    log.info(f"  Scope      : {len(scope)} wildcard(s)")

    # ── Initialize host map ─────────────────────────────────────────────────
    hosts: dict[str, HostNode] = {}
    stats: dict[str, int] = {}

    # ── Load every artifact defensively ─────────────────────────────────────
    log.info("  Loading artifacts...")
    loaders = [
        ("live_hosts",       lambda: _load_live_hosts(outdir, hosts)),
        ("nmap",             lambda: _load_nmap(outdir, hosts)),
        ("dns",              lambda: _load_dns(outdir, hosts)),
        ("takeover",         lambda: _load_takeover(outdir, hosts)),
        ("urls",             lambda: _load_urls(outdir, hosts)),
        ("params",           lambda: _load_params_by_endpoint(outdir, hosts)),
        ("categorize",       lambda: _load_url_categorize(outdir, hosts)),
    ]

    for name, loader in loaders:
        try:
            count = loader()
            stats[name] = count
            status = f"✓ {count:>5}" if count else "—"
            log.info(f"    {name:<16} {status}")
        except Exception as e:
            log.warning(f"    {name:<16} error: {e}")
            stats[name] = 0

    # ── Load findings from every finder ─────────────────────────────────────
    log.info("  Attaching findings...")
    try:
        finding_stats = _load_findings(outdir, hosts)
        stats.update(finding_stats)
        for ftype, count in finding_stats.items():
            if count:
                log.info(f"    {ftype:<16} ✓ {count:>5}")
    except Exception as e:
        log.warning(f"    findings loader error: {e}")

    # ── Build summary ───────────────────────────────────────────────────────
    summary = _build_summary(hosts)
    log.info("")
    log.info(f"  Hosts      : {summary['hosts']}")
    log.info(f"  Endpoints  : {summary['endpoints']}")
    log.info(f"  Findings   : {summary['findings']}")
    log.info("")

    by_sev = summary["by_severity"]
    log.info(
        f"  Severity   : "
        f"CRITICAL={by_sev.get('CRITICAL', 0)}  "
        f"HIGH={by_sev.get('HIGH', 0)}  "
        f"MEDIUM={by_sev.get('MEDIUM', 0)}  "
        f"LOW={by_sev.get('LOW', 0)}"
    )

    if not hosts:
        log.warning("  No hosts found in any artifact — writing empty map")

    # ── Write outputs ───────────────────────────────────────────────────────
    elapsed = time.monotonic() - start

    json_path = _write_json_map(scope, hosts, stats, elapsed, outdir)
    hosts_path = _write_hosts_txt(hosts, outdir)
    endpoints_path = _write_endpoints_txt(hosts, outdir)
    params_path = _write_parameters_txt(hosts, outdir)
    findings_path = _write_findings_txt(hosts, outdir)
    md_path = _write_markdown(hosts, outdir, scope)

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} full hierarchical map")
    log.info(f"    {md_path.name:<28} navigable Markdown map")
    log.info(f"    {hosts_path.name:<28} {summary['hosts']:>5} host(s)")
    log.info(f"    {endpoints_path.name:<28} {summary['endpoints']:>5} endpoint(s)")
    log.info(f"    {params_path.name:<28} parameterised endpoints")
    log.info(f"    {findings_path.name:<28} {summary['findings']:>5} finding(s)")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


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
        run_site_mapping(live, out, wildcard_file=wildcards)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
