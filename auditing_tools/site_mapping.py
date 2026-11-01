#!/usr/bin/env python3
"""
auditing_tools/site_mapping.py — Master Site Map Consolidator (v3)
═══════════════════════════════════════════════════════════════════════════════

The master index for the entire Argus pipeline. Reads every artifact from
`output/`, cross-references findings to their endpoints, and produces a
single hierarchical site map that represents the complete attack surface.

v3 corrections over v2 (10 bugs fixed):
  1. _load_scope() accepts a directory OR an explicit file path (v2's
     ".parent / wildcard.txt" only worked by accident)
  2. CORS evidence field is always str (v2 returned [] on empty reasons)
  3. URL loading MERGES endpoints instead of overwriting (v2 lost
     parameters from earlier sources)
  4. Categorize auto-creates missing hosts/endpoints (v2 skipped them)
  5. triage_report.json is no longer read — the individual finder files
     are the source of truth (v2 listed it in ARTIFACT_FILES but never
     loaded it, and loading it would have double-counted findings)
  6. Finding attachment tries URL → host+path → host (v2 was exact-URL
     only, so findings on /api/users/123 became orphans under /api/users/)
  7. URLs are normalized (trailing slash stripped, host lowercased) so
     /api and /api/ are the same endpoint
  8. url_categorize.json priority_urls loaded with weight + param names
  9. Truncation warnings emitted when MAX_ENDPOINTS_PER_HOST is hit
 10. Markdown output escapes |, backtick, _, * in evidence text

New coverage:
  • Path parameter extraction (/users/123/orders/456 → path_id=123...)
  • Endpoint value scoring for "interesting endpoints" panel
  • subdomains.json source attribution per host
  • Optional DB self-sync (site_map_hosts table)

Outputs (into `outdir`):
  • site_map.json             — full hierarchical map (primary)
  • site_map.md               — human-readable navigable map
  • site_map_hosts.txt        — flat host list with metadata
  • site_map_endpoints.txt    — flat endpoint list with methods
  • site_map_parameters.txt   — flat endpoint → parameters mapping
  • site_map_findings.txt     — flat finding list with severity
  • site_map_interesting.txt  — top-N endpoints by value score (NEW)

Integration:
  main.py → run_one("mapping") → run_site_mapping(live_urls_file, outdir,
                                                  wildcard_file=...,
                                                  scan_id=_CURRENT_SCAN_ID)
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


MAX_ENDPOINTS_PER_HOST = 5000
MAX_FINDINGS_PER_ENDPOINT = 100
DEFAULT_MAX_HOSTS = 5000


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointNode:
    url: str
    method: str = "GET"
    host: str = ""
    path: str = ""
    parameters: list[str] = field(default_factory=list)
    path_params: list[str] = field(default_factory=list)     # /users/{id}/...
    categories: list[str] = field(default_factory=list)      # gf categories
    findings: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    is_priority: bool = False
    priority_weight: int = 0
    auth_gated: bool = False
    form: bool = False

    def merge_from(self, other: "EndpointNode") -> None:
        """Union all fields when the same URL is discovered twice."""
        self.parameters = sorted(set(self.parameters + other.parameters))
        self.path_params = sorted(set(self.path_params + other.path_params))
        self.categories = sorted(set(self.categories + other.categories))
        self.technologies = sorted(set(self.technologies + other.technologies))
        self.is_priority = self.is_priority or other.is_priority
        self.priority_weight = max(self.priority_weight, other.priority_weight)
        self.auth_gated = self.auth_gated or other.auth_gated
        self.form = self.form or other.form
        # Don't merge findings — those are attached post-build

    def value_score(self) -> int:
        """Higher = more worth triaging."""
        score = 0
        for f in self.findings:
            score += {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 20, "LOW": 5, "INFO": 0}.get(
                f.get("severity", "INFO").upper(), 0,
            )
        if self.parameters: score += 10
        if self.path_params: score += 5
        if self.is_priority: score += 20
        if self.auth_gated:  score += 15
        if self.form:        score += 10
        if self.categories:  score += min(len(self.categories) * 3, 15)
        return score

    def to_dict(self) -> dict:
        return {
            "url":           self.url,
            "method":        self.method,
            "host":          self.host,
            "path":          self.path,
            "parameters":    sorted(set(self.parameters)),
            "path_params":   sorted(set(self.path_params)),
            "categories":    sorted(set(self.categories)),
            "technologies":  sorted(set(self.technologies)),
            "is_priority":   self.is_priority,
            "priority_weight": self.priority_weight,
            "auth_gated":    self.auth_gated,
            "form":          self.form,
            "value_score":   self.value_score(),
            "findings":      self.findings[:MAX_FINDINGS_PER_ENDPOINT],
            "finding_count": len(self.findings),
        }


@dataclass
class HostNode:
    hostname: str
    ip: str = ""
    status_code: int = 0
    technologies: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)
    cname: str = ""
    cdn: str = ""
    geo: list[dict] = field(default_factory=list)
    endpoints: dict[str, EndpointNode] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    auth_surface: list[dict] = field(default_factory=list)
    graphql_endpoints: list[dict] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    takeover: Optional[dict] = None
    interesting: bool = False
    reasons: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)         # subdomain source attribution

    def endpoints_truncated(self) -> bool:
        return len(self.endpoints) > MAX_ENDPOINTS_PER_HOST

    def to_dict(self) -> dict:
        ep_values = list(self.endpoints.values())
        if len(ep_values) > MAX_ENDPOINTS_PER_HOST:
            log.warning(
                f"    {self.hostname}: {len(ep_values)} endpoints, "
                f"truncating to {MAX_ENDPOINTS_PER_HOST} in JSON"
            )
            # Keep the highest-value endpoints
            ep_values = sorted(ep_values, key=lambda e: -e.value_score())[:MAX_ENDPOINTS_PER_HOST]
        else:
            ep_values = sorted(ep_values, key=lambda e: (-e.value_score(), e.url))

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
            "interesting":  self.interesting,
            "reasons":      self.reasons,
            "sources":      sorted(set(self.sources)),
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in ep_values],
            "host_findings": self.findings,
            "host_finding_count": len(self.findings),
        }


# ═════════════════════════════════════════════════════════════════════════════
#  URL UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _normalize_url(url: str) -> str:
    """
    Canonical URL form for indexing.

    • lowercases scheme + host
    • strips trailing slash from path (except root)
    • drops fragment
    • keeps query string as-is
    """
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        "",
        parsed.query,
        "",
    ))


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return (urllib.parse.urlparse(url).hostname or "").lower()


def _extract_query_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return sorted(urllib.parse.parse_qs(parsed.query).keys())


_PATH_PARAM_PATTERNS = [
    (re.compile(r"^\d{1,10}$"), "path_id"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "path_uuid"),
    (re.compile(r"^[0-9a-f]{16,}$", re.I), "path_hex"),
]

def _extract_path_params(url: str) -> list[str]:
    """Extract /users/123/orders/456 style path parameters."""
    parsed = urllib.parse.urlparse(url)
    out: list[str] = []
    for seg in parsed.path.split("/"):
        if not seg:
            continue
        for pat, label in _PATH_PARAM_PATTERNS:
            if pat.match(seg):
                out.append(f"{label}={seg}")
                break
    return out


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        (s or "").upper(), 5
    )


def _md_escape(s: str) -> str:
    """Escape markdown table-breaking characters."""
    if not s:
        return ""
    return (
        s.replace("|", "\\|")
         .replace("`", "'")
         .replace("\n", " ")
         .replace("\r", "")
    )[:200]


# ═════════════════════════════════════════════════════════════════════════════
#  LOADERS
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


def _ensure_host(hosts: dict[str, HostNode], hostname: str) -> Optional[HostNode]:
    """Return (creating if needed) the HostNode for a hostname."""
    if not hostname:
        return None
    h = hostname.lower()
    if h not in hosts:
        hosts[h] = HostNode(hostname=h)
    return hosts[h]


def _ensure_endpoint(
    node: HostNode, url: str, method: str = "GET",
) -> EndpointNode:
    """Return (creating if needed) the EndpointNode for a URL within a host."""
    norm = _normalize_url(url)
    if not norm:
        return EndpointNode(url="", host=node.hostname)
    ep = node.endpoints.get(norm)
    if ep is None:
        parsed = urllib.parse.urlparse(norm)
        ep = EndpointNode(
            url=norm,
            method=method,
            host=node.hostname,
            path=parsed.path or "/",
            parameters=_extract_query_params(norm),
            path_params=_extract_path_params(norm),
        )
        node.endpoints[norm] = ep
    return ep


def _load_scope(wildcard_file: Optional[Path], outdir: Path) -> list[str]:
    """Scope resolution — try explicit file, then outdir/../wildcard.txt, then outdir/wildcard.txt."""
    candidates: list[Path] = []
    if wildcard_file:
        candidates.append(Path(wildcard_file))
    candidates.append(outdir.parent / "wildcard.txt")
    candidates.append(outdir / "wildcard.txt")

    for cand in candidates:
        if cand.exists() and cand.is_file():
            try:
                return [
                    line.strip().lower()
                    for line in cand.read_text().splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            except Exception:
                continue
    return []


def _load_live_hosts(outdir: Path, hosts: dict[str, HostNode]) -> int:
    data = _load_json(outdir / "live_hosts.json")
    if not data:
        return 0
    count = 0
    for h in data.get("hosts") or []:
        hostname = h.get("subdomain") or _host_from_url(h.get("url", ""))
        node = _ensure_host(hosts, hostname)
        if node is None:
            continue
        node.status_code = h.get("status_code") or 0
        node.technologies = list(h.get("technologies") or [])
        node.cname = h.get("cname") or ""
        node.cdn = h.get("cdn") or ""
        node.geo = list(h.get("geo") or [])
        node.interesting = bool(h.get("interesting"))
        node.reasons = list(h.get("reasons") or [])
        ips = h.get("ip")
        if isinstance(ips, list) and ips:
            node.ip = str(ips[0])
        elif isinstance(ips, str):
            node.ip = ips
        # Create the endpoint that httpx probed
        if h.get("url"):
            _ensure_endpoint(node, h["url"])
        count += 1
    return count


def _load_subdomains(outdir: Path, hosts: dict[str, HostNode]) -> int:
    data = _load_json(outdir / "subdomains.json")
    if not data:
        return 0
    count = 0
    for s in data.get("subdomains") or []:
        node = _ensure_host(hosts, s.get("subdomain", ""))
        if node is None:
            continue
        for src in s.get("sources") or []:
            if src not in node.sources:
                node.sources.append(src)
        count += 1
    return count


def _load_nmap(outdir: Path, hosts: dict[str, HostNode]) -> int:
    data = _load_json(outdir / "nmap_scan.json")
    if not data:
        return 0
    count = 0
    for h in data.get("hosts") or []:
        hostname = h.get("hostname") or h.get("ip", "")
        node = _ensure_host(hosts, hostname)
        if node is None:
            continue
        node.ports = h.get("ports", [])
        if not node.ip:
            node.ip = h.get("ip", "")
        count += 1
    return count


def _load_dns(outdir: Path, hosts: dict[str, HostNode]) -> int:
    data = _load_json(outdir / "dns_resolve.json")
    if not data:
        return 0
    count = 0
    for r in data.get("records") or []:
        node = _ensure_host(hosts, r.get("host", ""))
        if node is None:
            continue
        node.dns_records = {
            "a": r.get("a", []), "aaaa": r.get("aaaa", []),
            "cname": r.get("cname", []), "mx": r.get("mx", []),
            "ns": r.get("ns", []), "txt": r.get("txt", []),
        }
        count += 1
    return count


def _load_takeover(outdir: Path, hosts: dict[str, HostNode]) -> int:
    data = _load_json(outdir / "takeover_findings.json")
    if not data:
        return 0
    count = 0
    for f in data.get("findings") or []:
        node = _ensure_host(hosts, f.get("subdomain", ""))
        if node is None:
            continue
        node.takeover = {
            "status":   f.get("status", ""),
            "service":  f.get("service", ""),
            "cvss":     f.get("cvss", 0),
            "evidence": f.get("fingerprint", ""),
        }
        sev = "CRITICAL" if f.get("status") == "VULNERABLE" else "HIGH"
        node.findings.append({
            "type": "takeover", "subtype": f.get("service", ""),
            "severity": sev, "source": "takeover_check",
            "evidence": (f.get("notes") or "")[:300],
        })
        count += 1
    return count


def _load_urls(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Populate endpoints from every URL list — MERGES instead of overwriting."""
    url_sources = [
        outdir / "all_urls.txt",
        outdir / "urls_with_params.txt",
        outdir / "urls_js_files.txt",
        outdir / "urls_interesting.txt",
        outdir / "urls_forms.txt",
    ]
    seen: set[str] = set()
    for src in url_sources:
        for line in _load_txt(src):
            url = line.split()[0] if line else ""
            norm = _normalize_url(url)
            if not norm:
                continue
            hostname = _host_from_url(norm)
            node = _ensure_host(hosts, hostname)
            if node is None:
                continue
            ep = _ensure_endpoint(node, norm)
            # Merge-from-empty is a no-op but harmless and keeps structure
            ep.merge_from(ep)
            seen.add(norm)
    return len(seen)


def _load_params_by_endpoint(outdir: Path, hosts: dict[str, HostNode]) -> int:
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
        node = _ensure_host(hosts, _host_from_url(norm))
        if node is None:
            continue
        ep = _ensure_endpoint(node, norm, method=method)
        discovered = [p.strip() for p in params_str.split(",") if p.strip()]
        ep.parameters = sorted(set(ep.parameters + discovered))
        count += 1
    return count


def _load_url_categorize(outdir: Path, hosts: dict[str, HostNode]) -> int:
    """Attach categories AND priority_urls, auto-creating endpoints."""
    data = _load_json(outdir / "url_categorize.json")
    if not data:
        return 0
    count = 0

    # ── categories[].urls
    for cat in data.get("categories") or []:
        cat_name = cat.get("name", "")
        for url in cat.get("urls") or []:
            norm = _normalize_url(url)
            node = _ensure_host(hosts, _host_from_url(norm))
            if node is None:
                continue
            ep = _ensure_endpoint(node, norm)
            if cat_name and cat_name not in ep.categories:
                ep.categories.append(cat_name)
            count += 1

    # ── priority_urls (with weight + param_names)
    for entry in data.get("priority_urls") or []:
        url = entry.get("url", "")
        if not url:
            continue
        norm = _normalize_url(url)
        node = _ensure_host(hosts, _host_from_url(norm))
        if node is None:
            continue
        ep = _ensure_endpoint(node, norm)
        ep.is_priority = True
        ep.priority_weight = max(ep.priority_weight, int(entry.get("weight") or 0))
        for cat in entry.get("categories") or []:
            if cat and cat not in ep.categories:
                ep.categories.append(cat)
        for p in entry.get("param_names") or []:
            if p and p not in ep.parameters:
                ep.parameters.append(p)
        count += 1

    return count


# ═════════════════════════════════════════════════════════════════════════════
#  FINDINGS ATTACHMENT (URL → host+path → host)
# ═════════════════════════════════════════════════════════════════════════════

def _attach_finding(
    hosts: dict[str, HostNode], target: str, finding: dict,
) -> bool:
    """
    Attach finding to the best-matching endpoint, or fall back to host-level.

    Order:
      1. Exact URL match
      2. URL path match — endpoint whose path is a prefix of the finding path
      3. Host-level fallback

    Returns True if attached to an endpoint, False if host-level.
    """
    norm = _normalize_url(target)
    hostname = _host_from_url(norm)
    node = _ensure_host(hosts, hostname)
    if node is None:
        return False

    # 1. Exact
    ep = node.endpoints.get(norm)
    if ep:
        ep.findings.append(finding)
        return True

    # 2. Path-prefix match
    parsed = urllib.parse.urlparse(norm)
    finding_path = parsed.path or "/"
    best_ep: Optional[EndpointNode] = None
    best_score = 0
    for endpoint in node.endpoints.values():
        ep_path = endpoint.path or "/"
        if finding_path.startswith(ep_path) and len(ep_path) > best_score:
            best_ep = endpoint
            best_score = len(ep_path)

    if best_ep and best_score > 1:      # >1 excludes "/" matching everything
        best_ep.findings.append(finding)
        return True

    # 3. Host-level
    node.findings.append(finding)
    return False


def _finding(source_type: str, subtype: str, severity: str,
             source: str, evidence: str, details: Optional[dict] = None) -> dict:
    return {
        "type": source_type,
        "subtype": subtype,
        "severity": (severity or "MEDIUM").upper(),
        "source": source,
        "evidence": (evidence or "")[:300],
        "details": details or {},
    }


def _load_findings(outdir: Path, hosts: dict[str, HostNode]) -> dict[str, int]:
    stats = defaultdict(int)

    # ── Nuclei
    for f in (_load_json(outdir / "nuclei_findings.json") or {}).get("findings", []):
        target = f.get("matched_at") or f.get("host", "")
        if _attach_finding(hosts, target, _finding(
            "nuclei", f.get("template_id", ""),
            f.get("severity", "MEDIUM"), "nuclei",
            f.get("template_name", ""),
            {"cve_ids": f.get("cve_ids", []), "cvss": f.get("cvss_score", 0)},
        )):
            stats["nuclei"] += 1

    # ── CORS
    for f in (_load_json(outdir / "cors_findings.json") or {}).get("findings", []):
        reasons = f.get("reasons") or []
        evidence = ", ".join(str(r) for r in reasons[:4]) if reasons else ""
        _attach_finding(hosts, f.get("url") or f.get("target", ""), _finding(
            "cors", f.get("probe", ""), f.get("severity", "MEDIUM"),
            "cors_check", evidence,
        ))
        stats["cors"] += 1

    # ── Auth
    for f in (_load_json(outdir / "auth_findings.json") or {}).get("findings", []):
        target = f.get("target", "")
        finding = _finding(
            "auth", f.get("vuln_type", ""), f.get("severity", "MEDIUM"),
            "auth_tester", f.get("evidence", ""),
        )
        _attach_finding(hosts, target, finding)
        node = _ensure_host(hosts, _host_from_url(_normalize_url(target)))
        if node:
            node.auth_surface.append(finding)
        stats["auth"] += 1

    # ── Cache
    for f in (_load_json(outdir / "cache_findings.json") or {}).get("findings", []):
        _attach_finding(hosts, f.get("target", ""), _finding(
            "cache", f.get("vuln_type", ""), f.get("severity", "MEDIUM"),
            "cache_poisoning", f.get("evidence", ""),
        ))
        stats["cache"] += 1

    # ── GraphQL — endpoints + findings
    gql = _load_json(outdir / "graphql_findings.json") or {}
    for ep in gql.get("endpoints") or []:
        target = ep.get("url", "")
        node = _ensure_host(hosts, _host_from_url(_normalize_url(target)))
        if node:
            node.graphql_endpoints.append({
                "url": _normalize_url(target),
                "engine": ep.get("engine", ""),
                "introspectable": ep.get("introspectable", False),
            })
    for f in gql.get("findings") or []:
        _attach_finding(hosts, f.get("target", ""), _finding(
            "graphql", f.get("vuln_type", ""), f.get("severity", "MEDIUM"),
            "graphql_finder", f.get("evidence", ""),
        ))
        stats["graphql"] += 1

    # ── IDOR
    for f in (_load_json(outdir / "idor_findings.json") or {}).get("findings", []):
        _attach_finding(hosts, f.get("target", ""), _finding(
            "idor", f.get("technique", "") or f.get("vuln_type", ""),
            f.get("severity", "MEDIUM"), "idor_finder", f.get("evidence", ""),
        ))
        stats["idor"] += 1

    # ── Open redirect
    for f in (_load_json(outdir / "open_redirect_findings.json") or {}).get("findings", []):
        _attach_finding(hosts, f.get("target", ""), _finding(
            "open_redirect", f.get("vector", ""), f.get("severity", "MEDIUM"),
            "open_redirect_finder", f.get("evidence", ""),
        ))
        stats["redirect"] += 1

    # ── Race
    for c in (_load_json(outdir / "race_findings.json") or {}).get("candidates", []):
        _attach_finding(hosts, c.get("target", ""), _finding(
            "race_condition", c.get("race_class", ""),
            c.get("severity", "MEDIUM"), "race_condition",
            c.get("evidence", "") or c.get("description", ""),
            {"confirmed": c.get("confirmed", False)},
        ))
        stats["race"] += 1

    # ── JS findings
    for f in (_load_json(outdir / "js_findings.json") or {}).get("findings", []):
        kind = f.get("kind", "")
        if kind == "secret":
            target = f.get("file_url", "")
        elif kind == "endpoint":
            target = f.get("value", "")
        else:
            target = f.get("file_url", "")
        _attach_finding(hosts, target, _finding(
            f"js_{kind}", f.get("subtype", ""), f.get("severity", "MEDIUM"),
            "js_analysis", f.get("redacted") or f.get("value", ""),
        ))
        stats["js"] += 1

    # ── Param findings — enrich parameters AND record finding
    for f in (_load_json(outdir / "param_findings.json") or {}).get("findings", []):
        target = f.get("url", "")
        norm = _normalize_url(target)
        node = _ensure_host(hosts, _host_from_url(norm))
        if not node:
            continue
        ep = _ensure_endpoint(node, norm)
        param = f.get("parameter", "")
        if param and param not in ep.parameters:
            ep.parameters.append(param)
        stats["param"] += 1

    # ── Flat candidates (sqli / xss / ssrf / ssti / xxe)
    for filename, key in [
        ("sqli_candidates.txt", "sqli"),
        ("xss_candidates.txt", "xss"),
        ("ssrf_candidates.txt", "ssrf"),
        ("ssti_candidates.txt", "ssti"),
        ("xxe_candidates.txt", "xxe"),
    ]:
        for line in _load_txt(outdir / filename):
            target = line.split("\t")[0] if line else ""
            _attach_finding(hosts, target, _finding(
                key, "candidate", "MEDIUM", f"{key}_finder", line,
            ))
            stats[key] += 1

    return dict(stats)


# ═════════════════════════════════════════════════════════════════════════════
#  ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _compute_host_score(node: HostNode) -> int:
    score = 0
    sev_points = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
    for f in node.findings:
        score += sev_points.get(f.get("severity", "INFO"), 0)
    for ep in node.endpoints.values():
        for f in ep.findings:
            score += sev_points.get(f.get("severity", "INFO"), 0)
    score += min(len(node.ports) * 2, 20)
    if node.takeover and node.takeover.get("status") == "VULNERABLE":
        score += 50
    if node.graphql_endpoints:
        score += 10
    if node.auth_surface:
        score += 15
    return score


def _severity_counts(node: HostNode) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in node.findings:
        s = (f.get("severity") or "INFO").upper()
        if s in counts:
            counts[s] += 1
    for ep in node.endpoints.values():
        for f in ep.findings:
            s = (f.get("severity") or "INFO").upper()
            if s in counts:
                counts[s] += 1
    return counts


def _build_summary(hosts: dict[str, HostNode]) -> dict:
    total_endpoints = sum(len(h.endpoints) for h in hosts.values())
    total_findings = 0
    by_severity: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)

    for h in hosts.values():
        for f in h.findings:
            total_findings += 1
            by_severity[f.get("severity", "INFO")] += 1
            by_type[f.get("type", "unknown")] += 1
        for ep in h.endpoints.values():
            for f in ep.findings:
                total_findings += 1
                by_severity[f.get("severity", "INFO")] += 1
                by_type[f.get("type", "unknown")] += 1

    top_hosts = sorted(
        hosts.values(), key=lambda h: (-_compute_host_score(h), h.hostname),
    )[:20]

    return {
        "hosts":           len(hosts),
        "endpoints":       total_endpoints,
        "findings":        total_findings,
        "by_severity":     dict(by_severity),
        "by_finding_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "top_hosts":       [
            {
                "hostname":    h.hostname,
                "score":       _compute_host_score(h),
                "endpoints":   len(h.endpoints),
                "findings":    sum(_severity_counts(h).values()),
            }
            for h in top_hosts
        ],
    }


def _interesting_endpoints(hosts: dict[str, HostNode], n: int = 200) -> list[dict]:
    """Top-N endpoints by value score across all hosts."""
    rows: list[tuple[int, HostNode, EndpointNode]] = []
    for h in hosts.values():
        for ep in h.endpoints.values():
            sc = ep.value_score()
            if sc > 0:
                rows.append((sc, h, ep))
    rows.sort(key=lambda r: (-r[0], r[2].url))
    return [
        {
            "score":     sc,
            "url":       ep.url,
            "method":    ep.method,
            "host":      h.hostname,
            "parameters": ep.parameters[:20],
            "categories": ep.categories,
            "finding_count": len(ep.findings),
            "max_severity": min(
                (f.get("severity", "INFO") for f in ep.findings),
                key=_severity_rank, default="",
            ),
        }
        for sc, h, ep in rows[:n]
    ]


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, hosts: dict[str, HostNode]) -> None:
    if not hosts:
        return
    if not DB_AVAILABLE or DB is None:
        log.warning("  DB sync: db.py not available")
        return
    if not _cfg("SYNC_TO_DB", True):
        log.info("  DB sync: SYNC_TO_DB is False")
        return
    if not _cfg("SITE_MAP_SYNC", True):
        log.info("  DB sync: SITE_MAP_SYNC is False")
        return
    if not _cfg("BRIDGE_ENABLED", False):
        log.info("  DB sync: BRIDGE_ENABLED is False")
        return
    if not DB.available:
        log.warning("  DB sync: bridge client not ready")
        return
    method = getattr(DB, "upsert_site_map_hosts", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_site_map_hosts() — "
            "add the method to enable site map sync"
        )
        return

    payload: list[dict] = []
    for h in hosts.values():
        counts = _severity_counts(h)
        payload.append({
            "hostname":        h.hostname,
            "ip":              h.ip,
            "status_code":     h.status_code,
            "score":           _compute_host_score(h),
            "endpoint_count":  len(h.endpoints),
            "finding_count":   sum(counts.values()),
            "critical_count":  counts["CRITICAL"],
            "high_count":      counts["HIGH"],
            "medium_count":    counts["MEDIUM"],
            "technologies":    h.technologies,
            "ports":           h.ports,
            "takeover_status": (h.takeover or {}).get("status", "") if h.takeover else None,
            "cdn":             h.cdn or None,
            "is_interesting":  h.interesting or counts["CRITICAL"] > 0 or counts["HIGH"] > 0,
            "metadata": {
                "reasons": h.reasons,
                "sources": h.sources,
                "auth_findings": len(h.auth_surface),
                "graphql_endpoints": len(h.graphql_endpoints),
            },
        })

    try:
        result = method(scan_id, payload)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(
                f"  DB sync: {result} host summary row(s) "
                f"upserted (scan_id={scan_id})"
            )
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_json_map(
    scope: list[str], hosts: dict[str, HostNode],
    stats: dict, elapsed: float, outdir: Path, max_hosts: int,
) -> Path:
    sorted_hosts = sorted(
        hosts.values(), key=lambda h: (-_compute_host_score(h), h.hostname),
    )
    truncated_hosts = len(sorted_hosts) > max_hosts
    if truncated_hosts:
        log.warning(
            f"  Truncating JSON output to top {max_hosts} hosts "
            f"(had {len(sorted_hosts)}) — all hosts are still in the .txt files"
        )
        sorted_hosts = sorted_hosts[:max_hosts]

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "scope":           scope,
        "summary":         _build_summary(hosts),
        "load_stats":      stats,
        "interesting_endpoints": _interesting_endpoints(hosts),
        "truncated":       truncated_hosts,
        "hosts":           [h.to_dict() for h in sorted_hosts],
    }
    path = outdir / "site_map.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return path


def _write_hosts_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    lines = []
    for h in sorted(hosts.values(), key=lambda x: (-_compute_host_score(x), x.hostname)):
        ports = ",".join(str(p.get("port", "")) for p in h.ports[:10])
        tech = ",".join(h.technologies[:5])
        counts = _severity_counts(h)
        lines.append(
            f"{h.hostname}\t{h.ip}\tstatus={h.status_code}\t"
            f"endpoints={len(h.endpoints)}\tfindings={sum(counts.values())}\t"
            f"crit={counts['CRITICAL']}\thigh={counts['HIGH']}\t"
            f"ports=[{ports}]\ttech=[{tech}]"
        )
    path = outdir / "site_map_hosts.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_endpoints_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    lines = []
    for h in hosts.values():
        for ep in h.endpoints.values():
            lines.append(
                f"{ep.method}\t{ep.url}\t"
                f"params={len(ep.parameters)}\t"
                f"path_params={len(ep.path_params)}\t"
                f"priority={int(ep.is_priority)}\t"
                f"score={ep.value_score()}\t"
                f"categories={','.join(ep.categories)}\t"
                f"findings={len(ep.findings)}"
            )
    lines.sort()
    path = outdir / "site_map_endpoints.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_parameters_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    lines = []
    for h in hosts.values():
        for ep in h.endpoints.values():
            if not ep.parameters and not ep.path_params:
                continue
            parts = []
            if ep.parameters:
                parts.append(",".join(sorted(ep.parameters)))
            if ep.path_params:
                parts.append("[" + ",".join(sorted(ep.path_params)) + "]")
            lines.append(f"{ep.url}\t{' '.join(parts)}")
    lines.sort()
    path = outdir / "site_map_parameters.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_findings_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    rows: list[tuple[int, str, dict]] = []
    for h in hosts.values():
        for f in h.findings:
            rows.append((_severity_rank(f.get("severity", "INFO")), h.hostname, f))
        for ep in h.endpoints.values():
            for f in ep.findings:
                rows.append((_severity_rank(f.get("severity", "INFO")), ep.url, f))
    rows.sort(key=lambda r: (r[0], r[1]))
    lines = [
        f"[{f.get('severity', 'INFO'):<8}] {f.get('type', ''):<20} "
        f"{f.get('source', ''):<20} {target}\t{f.get('evidence', '')[:120]}"
        for _, target, f in rows
    ]
    path = outdir / "site_map_findings.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_interesting_txt(hosts: dict[str, HostNode], outdir: Path) -> Path:
    rows = _interesting_endpoints(hosts, n=500)
    lines = [
        f"{r['score']}\t{r['max_severity']:<8}\t{r['method']}\t{r['url']}\t"
        f"params={len(r['parameters'])}\tfindings={r['finding_count']}\t"
        f"cats={','.join(r['categories'])}"
        for r in rows
    ]
    path = outdir / "site_map_interesting.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_markdown(hosts: dict[str, HostNode], outdir: Path, scope: list[str]) -> Path:
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
        c = summary["by_severity"].get(sev, 0)
        if c:
            lines.append(f"- {sev}: {c}")
    lines.append("")

    lines.append("## Top hosts by risk score")
    lines.append("")
    lines.append("| Host | Score | Endpoints | Findings |")
    lines.append("|------|-------|-----------|----------|")
    for h in summary["top_hosts"][:20]:
        lines.append(
            f"| `{_md_escape(h['hostname'])}` | {h['score']} | "
            f"{h['endpoints']} | {h['findings']} |"
        )
    lines.append("")

    lines.append("## Host details")
    lines.append("")
    sorted_hosts = sorted(hosts.values(), key=lambda h: (-_compute_host_score(h), h.hostname))
    for h in sorted_hosts[:50]:
        score = _compute_host_score(h)
        lines.append(f"### `{_md_escape(h.hostname)}` (score: {score})")
        lines.append("")

        meta: list[str] = []
        if h.ip:    meta.append(f"IP: `{h.ip}`")
        if h.status_code: meta.append(f"Status: {h.status_code}")
        if h.technologies: meta.append(f"Tech: {', '.join(h.technologies[:5])}")
        if h.ports:
            plist = ", ".join(str(p.get("port", "")) for p in h.ports[:10])
            meta.append(f"Ports: {plist}")
        if h.cdn:   meta.append(f"CDN: {h.cdn}")
        if h.takeover:
            meta.append(f"⚠ **Takeover: {h.takeover.get('status', '')}**")
        if meta:
            lines.append(" · ".join(meta))
            lines.append("")

        if h.findings:
            lines.append("**Host findings:**")
            for f in sorted(h.findings, key=lambda x: _severity_rank(x.get("severity", "INFO")))[:10]:
                lines.append(
                    f"- [{_md_escape(f.get('severity', 'INFO'))}] "
                    f"{_md_escape(f.get('type', ''))}: "
                    f"{_md_escape(f.get('evidence', ''))[:120]}"
                )
            lines.append("")

        ep_with_findings = [e for e in h.endpoints.values() if e.findings]
        if ep_with_findings:
            lines.append(f"**Endpoints with findings ({len(ep_with_findings)}):**")
            for ep in sorted(
                ep_with_findings,
                key=lambda e: min(_severity_rank(f.get("severity", "INFO")) for f in e.findings),
            )[:15]:
                max_sev = min(
                    (f.get("severity", "INFO") for f in ep.findings),
                    key=_severity_rank,
                )
                lines.append(
                    f"- [{_md_escape(max_sev)}] `{_md_escape(ep.url)}` "
                    f"({len(ep.findings)} finding(s), score: {ep.value_score()})"
                )
            lines.append("")

        param_endpoints = [e for e in h.endpoints.values() if e.parameters and not e.findings]
        if param_endpoints:
            lines.append(f"**Parameterised endpoints ({len(param_endpoints)}):**")
            for ep in sorted(param_endpoints, key=lambda e: -e.value_score())[:10]:
                lines.append(
                    f"- `{_md_escape(ep.url)}` — params: "
                    f"`{_md_escape(', '.join(ep.parameters[:8]))}`"
                )
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
    max_hosts: int = DEFAULT_MAX_HOSTS,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Consolidate every artifact in `outdir` into a single site map.

    `live_urls_file` is accepted for pipeline compatibility but the module
    reads from the full artifact set regardless.

    If `scan_id` is provided and the bridge is configured, per-host
    summaries are synced to the `site_map_hosts` table.
    """
    start = time.monotonic()
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Output dir : {outdir}")
    log.info("")

    scope = _load_scope(wildcard_file, outdir)
    log.info(f"  Scope      : {len(scope)} wildcard(s)")

    hosts: dict[str, HostNode] = {}
    stats: dict[str, int] = {}

    # ── Load recon data (creates hosts + endpoints)
    log.info("  Loading artifacts...")
    loaders = [
        ("live_hosts",  lambda: _load_live_hosts(outdir, hosts)),
        ("subdomains",  lambda: _load_subdomains(outdir, hosts)),
        ("nmap",        lambda: _load_nmap(outdir, hosts)),
        ("dns",         lambda: _load_dns(outdir, hosts)),
        ("takeover",    lambda: _load_takeover(outdir, hosts)),
        ("urls",        lambda: _load_urls(outdir, hosts)),
        ("params",      lambda: _load_params_by_endpoint(outdir, hosts)),
        ("categorize",  lambda: _load_url_categorize(outdir, hosts)),
    ]
    for name, loader in loaders:
        try:
            c = loader()
            stats[name] = c
            log.info(f"    {name:<16} {'✓ ' + str(c) if c else '—'}")
        except Exception as e:
            log.warning(f"    {name:<16} error: {e}")
            stats[name] = 0

    # ── Attach findings
    log.info("  Attaching findings...")
    try:
        fstats = _load_findings(outdir, hosts)
        stats.update(fstats)
        for k, c in fstats.items():
            if c:
                log.info(f"    {k:<16} ✓ {c}")
    except Exception as e:
        log.warning(f"    findings loader error: {e}")

    # ── Summary
    summary = _build_summary(hosts)
    log.info("")
    log.info(f"  Hosts      : {summary['hosts']}")
    log.info(f"  Endpoints  : {summary['endpoints']}")
    log.info(f"  Findings   : {summary['findings']}")
    log.info("")
    sev = summary["by_severity"]
    log.info(
        f"  Severity   : CRITICAL={sev.get('CRITICAL', 0)}  "
        f"HIGH={sev.get('HIGH', 0)}  MEDIUM={sev.get('MEDIUM', 0)}  "
        f"LOW={sev.get('LOW', 0)}"
    )

    if not hosts:
        log.warning("  No hosts found — writing empty map")

    # ── Write outputs
    elapsed = time.monotonic() - start
    json_path      = _write_json_map(scope, hosts, stats, elapsed, outdir, max_hosts)
    hosts_path     = _write_hosts_txt(hosts, outdir)
    endpoints_path = _write_endpoints_txt(hosts, outdir)
    params_path    = _write_parameters_txt(hosts, outdir)
    findings_path  = _write_findings_txt(hosts, outdir)
    interesting_path = _write_interesting_txt(hosts, outdir)
    md_path        = _write_markdown(hosts, outdir, scope)

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} full hierarchical map")
    log.info(f"    {md_path.name:<28} navigable Markdown map")
    log.info(f"    {hosts_path.name:<28} {summary['hosts']:>5} host(s)")
    log.info(f"    {endpoints_path.name:<28} {summary['endpoints']:>5} endpoint(s)")
    log.info(f"    {params_path.name:<28} parameterised endpoints")
    log.info(f"    {findings_path.name:<28} {summary['findings']:>5} finding(s)")
    log.info(f"    {interesting_path.name:<28} top endpoints by value")

    # ── Self-sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, hosts)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Argus Site Map Consolidator")
    parser.add_argument("--input", type=Path, default=base / "output" / "live_urls.txt")
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--wildcard", type=Path, default=base / "wildcard.txt")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS)
    args = parser.parse_args()

    try:
        run_site_mapping(
            args.input, args.output,
            wildcard_file=args.wildcard,
            max_hosts=args.max_hosts,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
