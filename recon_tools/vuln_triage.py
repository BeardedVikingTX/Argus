#!/usr/bin/env python3
"""
recon_tools/vuln_triage.py — Finding Aggregation & Prioritization
═══════════════════════════════════════════════════════════════════════════════

The final triage stage for Argus. Reads every finding from every module,
normalizes them into a universal Finding shape, cross-references targets
across modules, scores each one by correlation strength, and produces a
ranked, prioritized report.

Why this exists:

  Without triage, you have 15 JSON files scattered across `output/` and no
  idea which 5 findings deserve your attention first. Every module speaks
  its own dialect, uses its own severity scale, and has no awareness of what
  the other modules found.

  With triage, you get one report, one priority list, one truth:
    • "SQLi candidate on /api/user?id=123 that ALSO appears in gf_sqli.txt
       AND has a nuclei template match" → CRITICAL, test first
    • "Nuclei medium-severity XSS template on /search" → MEDIUM, test later

Cross-correlation signals:

  Each finding gets a base score from its source module. Then it's boosted
  when the SAME TARGET is flagged by multiple modules:
    +25 per additional source beyond the first
    +15 if target is in url_categorize_priority.txt
    +10 if target is a live host (from live_hosts.json)
    +10 if the target appears in gf_*.txt category files

Sources ingested (each optional — missing files are logged and skipped):
  • nmap_scan.json               — port/service discovery
  • subdomains.json              — subdomain attribution
  • dns_resolve.json             — DNS records, wildcard, takeover candidates
  • live_hosts.json              — HTTPX liveness + tech
  • takeover_findings.json       — subdomain takeover
  • js_findings.json             — JS secrets and endpoints
  • param_findings.json          — discovered parameters
  • content_fuzz.json            — content discovery
  • nuclei_findings.json         — template matches
  • cors_findings.json           — CORS misconfigurations
  • url_categorize.json          — category attribution + priority
  • sqli_candidates.txt/json     — SQLi flags (from sqli_finder)
  • xss_candidates.txt/json      — XSS flags (from xss_finder)
  • ssrf_candidates.txt/json     — SSRF flags (from ssrf_finder)
  • gf_*.txt                     — raw category files
  • dns_takeover_candidates.txt  — takeover candidates from dns stage

Outputs (into `outdir`):
  • triage_report.json           — full structured report
  • triage_priority.md           — human-readable top findings, ready to work from
  • triage_next_steps.txt        — flat list of targets to test, in priority order
  • triage_by_category.txt       — grouped by vuln class for batch manual testing

Integration:
  main.py → run_one("triage") → run_vuln_triage(outdir)
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

log = logging.getLogger("argus.vuln_triage")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# Base severity scoring
SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH":     75,
    "MEDIUM":   50,
    "LOW":      25,
    "INFO":     5,
    "unknown":  20,
}

# Correlation bonuses
CORRELATION_BONUS_PER_SOURCE = 25
CONTEXT_BONUS_LIVE_HOST      = 10
CONTEXT_BONUS_PRIORITY_URL   = 15
CONTEXT_BONUS_GF_CATEGORY    = 10

# Report caps
MAX_FINDINGS_IN_JSON    = 5000
MAX_FINDINGS_IN_MARKDOWN = 100
MAX_EVIDENCE_PER_FINDING = 5


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """A normalized finding from any source module."""
    target: str                     # URL, host, or subdomain
    kind: str                       # vuln class: "sql_injection", "cors_misconfig", etc.
    source: str                     # module name: "nuclei", "cors_check", etc.
    severity: str = "unknown"
    confidence: int = 0             # 0-100
    details: dict = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    cross_refs: set[str] = field(default_factory=set)
    score: float = 0.0
    rank: int = 0

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "kind":       self.kind,
            "source":     self.source,
            "severity":   self.severity,
            "confidence": self.confidence,
            "score":      round(self.score, 1),
            "rank":       self.rank,
            "cross_refs": sorted(self.cross_refs),
            "details":    self.details,
            "evidence":   self.evidence[:MAX_EVIDENCE_PER_FINDING],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _safe_load_json(path: Path) -> Optional[dict]:
    """Load JSON, returning None on any error."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as e:
        log.debug(f"    failed to load {path.name}: {e}")
        return None


def _safe_load_txt(path: Path) -> list[str]:
    """Load text file, return lines. Empty list if missing."""
    if not path.exists():
        return []
    try:
        return [
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception:
        return []


def _normalize_target(target: str) -> str:
    """
    Normalize a target for cross-referencing. Hosts and URLs should collapse
    to a canonical form so 'https://A.example.com/x' and 'a.example.com'
    don't get treated as different targets.

    Preserves query strings but lowercases scheme/host.
    """
    if not target:
        return ""

    t = target.strip()

    # If it's a bare hostname, normalize it
    if not t.startswith(("http://", "https://")):
        # If it looks like a URL without scheme, add https
        if "." in t and " " not in t:
            t = "https://" + t
        else:
            return t.lower().rstrip(".")

    try:
        parsed = urllib.parse.urlparse(t)
        # Normalize to just host + path + query
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}" + (
            f"?{parsed.query}" if parsed.query else ""
        )
    except Exception:
        return t.lower()


def _target_host(target: str) -> str:
    """Extract just the hostname from a target (URL or host)."""
    if not target:
        return ""
    if target.startswith(("http://", "https://")):
        try:
            return urllib.parse.urlparse(target).hostname or ""
        except Exception:
            return ""
    # Bare hostname or host:port
    return target.split(":")[0].split("/")[0].lower()


def _severity_normalize(s: str) -> str:
    """Normalize severity strings to canonical uppercase form."""
    if not s:
        return "unknown"
    s = s.strip().upper()
    if s in ("CRITICAL", "CRIT", "P1"):
        return "CRITICAL"
    if s in ("HIGH", "P2"):
        return "HIGH"
    if s in ("MEDIUM", "MED", "MODERATE", "P3"):
        return "MEDIUM"
    if s in ("LOW", "P4"):
        return "LOW"
    if s in ("INFO", "INFORMATIONAL", "P5"):
        return "INFO"
    return "unknown"


def _short_url(url: str, max_len: int = 80) -> str:
    if len(url) <= max_len:
        return url
    return url[:max_len - 3] + "..."


# ═════════════════════════════════════════════════════════════════════════════
#  INGESTORS — one per source module
# ═════════════════════════════════════════════════════════════════════════════

def _ingest_nuclei(outdir: Path) -> list[Finding]:
    data = _safe_load_json(outdir / "nuclei_findings.json")
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        target = f.get("matched_at") or f.get("host") or ""
        if not target:
            continue
        severity = _severity_normalize(f.get("severity", "unknown"))
        template = f.get("template_id", "")
        evidence = []
        if f.get("extracted_results"):
            evidence.append(f"extracted: {', '.join(str(x) for x in f['extracted_results'][:3])}")
        if f.get("cve_ids"):
            evidence.append(f"CVEs: {', '.join(f['cve_ids'][:3])}")
        if f.get("curl_command"):
            evidence.append(f"curl: {f['curl_command'][:200]}")
        findings.append(Finding(
            target=_normalize_target(target),
            kind=_nuclei_kind(template, f.get("tags") or []),
            source="nuclei",
            severity=severity,
            confidence=90 if severity == "CRITICAL" else 80 if severity == "HIGH" else 60,
            details={
                "template_id":     template,
                "template_name":   f.get("template_name", ""),
                "cvss_score":      f.get("cvss_score", 0),
                "cve_ids":         f.get("cve_ids", []),
                "matcher_name":    f.get("matcher_name", ""),
                "description":     (f.get("description", "") or "")[:300],
            },
            evidence=evidence,
        ))
    return findings


def _nuclei_kind(template_id: str, tags: list) -> str:
    """Infer vuln class from nuclei template ID and tags."""
    tid = (template_id or "").lower()
    tags_lower = [str(t).lower() for t in tags]
    combined = tid + " " + " ".join(tags_lower)

    if "cve" in combined or any("cve" in str(t) for t in tags_lower):
        if "rce" in combined or "code" in combined or "execution" in combined:
            return "rce"
        if "sqli" in combined or "sql" in combined:
            return "sql_injection"
        if "xss" in combined:
            return "xss"
        if "ssrf" in combined:
            return "ssrf"
        if "lfi" in combined:
            return "lfi"
        return "cve_match"
    if "takeover" in combined:
        return "takeover"
    if "exposure" in combined:
        return "exposure"
    if "misconfig" in combined:
        return "misconfiguration"
    if "default" in combined and "login" in combined:
        return "default_credentials"
    if "cors" in combined:
        return "cors_misconfig"
    if "graphql" in combined:
        return "graphql_issue"
    return "generic_vuln"


def _ingest_cors(outdir: Path) -> list[Finding]:
    data = _safe_load_json(outdir / "cors_findings.json")
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        target = f.get("url") or ""
        if not target:
            continue
        severity = _severity_normalize(f.get("severity", "unknown"))
        if severity in ("INFO",):
            continue  # Skip wildcard-without-credentials — not a finding
        evidence = []
        if f.get("sent_origin"):
            evidence.append(f"sent origin: {f['sent_origin']}")
        if f.get("access_control_allow_origin"):
            evidence.append(f"ACAO: {f['access_control_allow_origin']}")
        if f.get("access_control_allow_credentials"):
            evidence.append("ACAC: true")
        if f.get("response_snippet"):
            evidence.append(f"body: {f['response_snippet'][:200]}")
        findings.append(Finding(
            target=_normalize_target(target),
            kind="cors_misconfig",
            source="cors_check",
            severity=severity,
            confidence=f.get("score", 50),
            details={
                "probe":    f.get("probe", ""),
                "reasons":  f.get("reasons", []),
                "acao":     f.get("access_control_allow_origin", ""),
                "acac":     f.get("access_control_allow_credentials", False),
            },
            evidence=evidence,
        ))
    return findings


def _ingest_takeover(outdir: Path) -> list[Finding]:
    findings = []
    # Structured source
    data = _safe_load_json(outdir / "takeover_findings.json")
    if data:
        for f in data.get("findings", []):
            subdomain = f.get("subdomain") or ""
            if not subdomain:
                continue
            status = f.get("status", "")
            if status not in ("VULNERABLE", "POTENTIAL"):
                continue
            severity = "CRITICAL" if status == "VULNERABLE" else "HIGH"
            evidence = [f"CNAME chain: {' → '.join(f.get('cname_chain', []))}"]
            if f.get("fingerprint"):
                evidence.append(f"fingerprint: {f['fingerprint']}")
            findings.append(Finding(
                target=_normalize_target(subdomain),
                kind="takeover",
                source="takeover_check",
                severity=severity,
                confidence=95 if status == "VULNERABLE" else 60,
                details={
                    "status":   status,
                    "service":  f.get("service", ""),
                    "cvss":     f.get("cvss", 0),
                    "notes":    f.get("notes", ""),
                },
                evidence=evidence,
            ))

    # Flat fallback: dns_takeover_candidates.txt
    flat = _safe_load_txt(outdir / "dns_takeover_candidates.txt")
    for sub in flat:
        findings.append(Finding(
            target=_normalize_target(sub),
            kind="takeover",
            source="dns_resolve",
            severity="MEDIUM",
            confidence=50,
            details={"source_note": "flagged by dns_resolve (no HTTP confirmation)"},
            evidence=["CNAME points to vulnerable service (unconfirmed)"],
        ))

    # Confirmed vulnerable only
    vuln_flat = _safe_load_txt(outdir / "takeover_vulnerable.txt")
    for sub in vuln_flat:
        findings.append(Finding(
            target=_normalize_target(sub),
            kind="takeover",
            source="takeover_confirmed",
            severity="CRITICAL",
            confidence=95,
            details={"source_note": "confirmed vulnerable by takeover_check"},
            evidence=["HTTP fingerprint confirmed unclaimed state"],
        ))

    return findings


def _ingest_js_findings(outdir: Path) -> list[Finding]:
    data = _safe_load_json(outdir / "js_findings.json")
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        kind = f.get("kind", "")
        subtype = f.get("subtype", "")
        value = f.get("value", "")
        file_url = f.get("file_url", "")
        if not value:
            continue

        if kind == "secret":
            severity = _severity_normalize(f.get("severity", "MEDIUM"))
            target = file_url or "js_scan"
            findings.append(Finding(
                target=_normalize_target(target),
                kind=f"js_secret_{subtype}",
                source="js_analysis",
                severity=severity,
                confidence=f.get("confidence", 50),
                details={
                    "subtype":     subtype,
                    "redacted":    f.get("redacted", ""),
                    "line_number": f.get("line_number", 0),
                    "reasons":     f.get("reasons", []),
                },
                evidence=[f"context: {f.get('context', '')[:200]}"],
            ))
        elif kind == "endpoint":
            # Only interesting endpoints get promoted
            if f.get("confidence", 0) < 60:
                continue
            findings.append(Finding(
                target=_normalize_target(file_url or ""),
                kind="js_endpoint",
                source="js_analysis",
                severity="LOW",
                confidence=f.get("confidence", 50),
                details={
                    "endpoint":   value,
                    "subtype":    subtype,
                    "line_number": f.get("line_number", 0),
                },
                evidence=[f"endpoint: {value}"],
            ))
        elif kind == "sourcemap":
            findings.append(Finding(
                target=_normalize_target(f.get("value", "")),
                kind="source_map_exposed",
                source="js_analysis",
                severity="MEDIUM",
                confidence=80,
                details={"source": file_url},
                evidence=[f"source map URL: {value}"],
            ))
    return findings


def _ingest_params(outdir: Path) -> list[Finding]:
    data = _safe_load_json(outdir / "param_findings.json")
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        target = f.get("url", "")
        param = f.get("parameter", "")
        if not target or not param:
            continue
        vuln_classes = f.get("vuln_classes", [])
        confidence = f.get("confidence", 50)

        # Promote high-confidence parameter findings to vuln candidates
        for vclass in vuln_classes:
            findings.append(Finding(
                target=_normalize_target(target),
                kind=f"param_for_{vclass}",
                source="param_discovery",
                severity="MEDIUM" if confidence >= 75 else "LOW",
                confidence=confidence,
                details={
                    "parameter":     param,
                    "method":        f.get("method", "GET"),
                    "oracle":        f.get("oracle", ""),
                    "vuln_classes":  vuln_classes,
                },
                evidence=[f"parameter '{param}' discovered via {f.get('oracle', 'unknown')}"],
            ))
    return findings


def _ingest_content_fuzz(outdir: Path) -> list[Finding]:
    data = _safe_load_json(outdir / "content_fuzz.json")
    if not data:
        return []
    findings = []
    for f in data.get("findings", []):
        target = f.get("url", "")
        if not target:
            continue
        confidence = f.get("confidence", 0)
        if confidence < 60:
            continue
        findings.append(Finding(
            target=_normalize_target(target),
            kind="interesting_endpoint",
            source="content_fuzz",
            severity="LOW" if confidence < 75 else "MEDIUM",
            confidence=confidence,
            details={
                "status":       f.get("status", 0),
                "content_type": f.get("content_type", ""),
                "reasons":      f.get("reasons", []),
            },
            evidence=[f"status {f.get('status')} on {_short_url(target)}"],
        ))
    return findings


def _ingest_live_hosts(outdir: Path) -> list[Finding]:
    """Interesting live hosts feed the priority stack."""
    data = _safe_load_json(outdir / "live_hosts.json")
    if not data:
        return []
    findings = []
    for h in data.get("hosts", []):
        if not h.get("interesting"):
            continue
        url = h.get("url") or f"https://{h.get('subdomain', '')}"
        if not url:
            continue
        findings.append(Finding(
            target=_normalize_target(url),
            kind="interesting_host",
            source="live_discovery",
            severity="LOW",
            confidence=h.get("score", 50),
            details={
                "status":       h.get("status_code", 0),
                "technologies": h.get("technologies", []),
                "reasons":      h.get("reasons", []),
            },
            evidence=[f"flagged: {','.join(h.get('reasons', []))}"],
        ))
    return findings


def _ingest_nmap(outdir: Path) -> list[Finding]:
    """Exposed database/admin ports are directly reportable."""
    data = _safe_load_json(outdir / "nmap_scan.json")
    if not data:
        return []
    findings = []
    DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017}
    ADMIN_PORTS = {2375, 2376, 5000, 8080, 8081, 9090, 5601}
    for h in data.get("hosts", []):
        hostname = h.get("hostname") or h.get("ip", "")
        if not hostname:
            continue
        for port in h.get("ports", []):
            pnum = port.get("port", 0)
            service = port.get("service", "")
            if pnum in DATABASE_PORTS:
                findings.append(Finding(
                    target=hostname,
                    kind="exposed_database",
                    source="nmap",
                    severity="HIGH",
                    confidence=75,
                    details={
                        "port":    pnum,
                        "service": service,
                        "product": port.get("product", ""),
                        "version": port.get("version", ""),
                    },
                    evidence=[f"{service} exposed on {hostname}:{pnum}"],
                ))
            elif pnum in ADMIN_PORTS:
                findings.append(Finding(
                    target=hostname,
                    kind="exposed_admin_service",
                    source="nmap",
                    severity="MEDIUM",
                    confidence=60,
                    details={"port": pnum, "service": service},
                    evidence=[f"admin-like service on {hostname}:{pnum}"],
                ))
    return findings


def _ingest_candidate_txt(outdir: Path, filename: str, kind: str,
                          source: str, severity: str = "MEDIUM") -> list[Finding]:
    """Ingest a candidate list from a .txt file (sqli_candidates.txt, etc.)."""
    lines = _safe_load_txt(outdir / filename)
    findings = []
    for line in lines:
        target = line.split()[0] if line else ""
        if not target:
            continue
        findings.append(Finding(
            target=_normalize_target(target),
            kind=kind,
            source=source,
            severity=severity,
            confidence=55,
            details={"raw": line[:300]},
            evidence=[f"candidate from {filename}"],
        ))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  CROSS-REFERENCE ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def _load_context(outdir: Path) -> dict:
    """
    Load auxiliary context used for scoring bonuses:
      • live_hosts      — set of live hostnames
      • priority_urls   — set of URLs from url_categorize_priority.txt
      • gf_categories   — dict of URL → set of categories
    """
    context: dict[str, Any] = {
        "live_hosts":    set(),
        "priority_urls": set(),
        "gf_categories": defaultdict(set),
    }

    # Live hosts
    live_data = _safe_load_json(outdir / "live_hosts.json")
    if live_data:
        for h in live_data.get("hosts", []):
            sub = h.get("subdomain", "")
            if sub:
                context["live_hosts"].add(sub.lower())

    # Priority URLs from url_categorize
    for url in _safe_load_txt(outdir / "url_categorize_priority.txt"):
        context["priority_urls"].add(_normalize_target(url))

    # Category files
    for f in outdir.glob("gf_*.txt"):
        category = f.stem[3:]  # strip "gf_"
        for url in _safe_load_txt(f):
            context["gf_categories"][_normalize_target(url)].add(category)

    return context


def _apply_correlation_and_score(findings: list[Finding], context: dict) -> None:
    """
    First pass: build cross-reference map.
    Second pass: apply correlation and context bonuses.
    """
    # Build target → sources map
    target_sources: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        target_sources[f.target].add(f.source)

    # Build target → number of distinct kinds
    target_kinds: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        target_kinds[f.target].add(f.kind)

    # Apply scores
    for f in findings:
        base = SEVERITY_BASE.get(f.severity, SEVERITY_BASE["unknown"])

        # Confidence scaling (0-100 confidence → 0.5x to 1.0x base)
        conf_factor = 0.5 + (f.confidence / 200.0)
        score = base * conf_factor

        # Correlation bonus
        other_sources = target_sources[f.target] - {f.source}
        score += len(other_sources) * CORRELATION_BONUS_PER_SOURCE
        f.cross_refs = other_sources

        # Cross-kind bonus (SQLi + nuclei CVE on same URL)
        other_kinds = target_kinds[f.target] - {f.kind}
        score += len(other_kinds) * 5

        # Context bonuses
        host = _target_host(f.target)
        if host and host.lower() in context["live_hosts"]:
            score += CONTEXT_BONUS_LIVE_HOST

        if f.target in context["priority_urls"]:
            score += CONTEXT_BONUS_PRIORITY_URL

        if f.target in context["gf_categories"]:
            score += CONTEXT_BONUS_GF_CATEGORY

        f.score = min(score, 150.0)  # Cap at 150

    # Sort by score descending and assign ranks
    findings.sort(key=lambda x: (-x.score, x.target))
    for i, f in enumerate(findings, 1):
        f.rank = i


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_json(findings: list[Finding], outdir: Path,
                source_status: dict[str, str], start: float) -> Path:
    """Write the full structured JSON report."""
    elapsed = time.monotonic() - start

    by_severity: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)

    for f in findings:
        by_severity[f.severity] += 1
        by_kind[f.kind] += 1
        by_source[f.source] += 1

    report = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            "total_findings": len(findings),
            "unique_targets":  len({f.target for f in findings}),
            "unique_kinds":    len({f.kind for f in findings}),
            **{f"severity_{k.lower()}": v for k, v in by_severity.items()},
        },
        "summary": {
            "by_severity": dict(by_severity),
            "by_kind":     dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
            "by_source":   dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
        },
        "source_status": source_status,
        "findings": [f.to_dict() for f in findings[:MAX_FINDINGS_IN_JSON]],
    }

    path = outdir / "triage_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return path


def _write_markdown(findings: list[Finding], outdir: Path,
                    source_status: dict[str, str]) -> Path:
    """Write the human-readable Markdown triage report."""
    lines: list[str] = []

    # Header
    lines.append("# Argus Triage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Executive summary
    by_severity: dict[str, int] = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append(f"- **Unique targets:** {len({f.target for f in findings})}")
    lines.append(f"- 🔴 **CRITICAL:** {by_severity.get('CRITICAL', 0)}")
    lines.append(f"- 🟠 **HIGH:**     {by_severity.get('HIGH', 0)}")
    lines.append(f"- 🟡 **MEDIUM:**   {by_severity.get('MEDIUM', 0)}")
    lines.append(f"- 🔵 **LOW:**      {by_severity.get('LOW', 0)}")
    lines.append(f"- ⚪ **INFO:**     {by_severity.get('INFO', 0)}")
    lines.append("")

    # Top priority findings
    lines.append("---")
    lines.append("")
    lines.append("## Top Priority Findings")
    lines.append("")
    lines.append("Ranked by combined severity, confidence, and cross-module correlation.")
    lines.append("")

    top = findings[:MAX_FINDINGS_IN_MARKDOWN]
    for f in top:
        sev_icon = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🔵",
            "INFO":     "⚪",
        }.get(f.severity, "⚪")

        lines.append(f"### {f.rank}. {sev_icon} [{f.severity}] {f.kind}")
        lines.append("")
        lines.append(f"**Target:** `{f.target}`  ")
        lines.append(f"**Source:** `{f.source}`  ")
        lines.append(f"**Score:** {f.score:.1f} (confidence: {f.confidence})")

        if f.cross_refs:
            lines.append(f"**Cross-referenced by:** {', '.join(f'`{s}`' for s in sorted(f.cross_refs))}")

        lines.append("")
        lines.append("**Details:**")
        for k, v in f.details.items():
            if v in (None, "", [], {}):
                continue
            v_str = str(v)[:200]
            lines.append(f"- `{k}`: {v_str}")

        if f.evidence:
            lines.append("")
            lines.append("**Evidence:**")
            for ev in f.evidence[:MAX_EVIDENCE_PER_FINDING]:
                lines.append(f"- {ev[:250]}")

        lines.append("")

    # Source status appendix
    lines.append("---")
    lines.append("")
    lines.append("## Source Status")
    lines.append("")
    lines.append("| Module | Status |")
    lines.append("|--------|--------|")
    for source, status in sorted(source_status.items()):
        icon = "✓" if status == "loaded" else "—"
        lines.append(f"| {source} | {icon} {status} |")
    lines.append("")

    path = outdir / "triage_priority.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def _write_next_steps(findings: list[Finding], outdir: Path) -> Path:
    """Flat list of targets to test, in priority order."""
    lines = []
    seen: set[tuple] = set()

    for f in findings:
        key = (f.target, f.kind)
        if key in seen:
            continue
        seen.add(key)

        # Only include HIGH/MEDIUM/CRITICAL, skip low-noise
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            lines.append(f"[{f.severity:<8}] {f.kind:<24}  {f.target}")

    path = outdir / "triage_next_steps.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_by_category(findings: list[Finding], outdir: Path) -> Path:
    """Group findings by vuln class for batch manual testing."""
    by_kind: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_kind[f.kind].append(f)

    lines = []
    for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
        kind_findings = by_kind[kind]
        lines.append(f"=== {kind} ({len(kind_findings)} finding(s)) ===")
        lines.append("")
        for f in kind_findings[:50]:
            lines.append(f"  [{f.severity:<8}] {f.target}")
        if len(kind_findings) > 50:
            lines.append(f"  ... and {len(kind_findings) - 50} more")
        lines.append("")

    path = outdir / "triage_by_category.txt"
    path.write_text("\n".join(lines) + "\n")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_vuln_triage(outdir: Path) -> Path:
    """
    Aggregate every finding from every module, cross-reference, score, and
    write the triage report.

    Returns the path to `triage_report.json`.
    """
    start = time.monotonic()

    if not outdir.exists():
        raise FileNotFoundError(f"output directory not found: {outdir}")

    log.info(f"  Output : {outdir}")
    log.info("")

    # ── Ingest all sources ──────────────────────────────────────────────────
    log.info("  Ingesting module outputs...")

    ingestors = [
        ("nuclei",        _ingest_nuclei),
        ("cors",          _ingest_cors),
        ("takeover",      _ingest_takeover),
        ("js_analysis",   _ingest_js_findings),
        ("params",        _ingest_params),
        ("content_fuzz",  _ingest_content_fuzz),
        ("live_hosts",    _ingest_live_hosts),
        ("nmap",          _ingest_nmap),
    ]

    all_findings: list[Finding] = []
    source_status: dict[str, str] = {}

    for name, fn in ingestors:
        try:
            batch = fn(outdir)
        except Exception as e:
            log.warning(f"    {name:<16} ingest error: {e}")
            source_status[name] = "error"
            continue

        all_findings.extend(batch)
        if batch:
            source_status[name] = "loaded"
            log.info(f"    {name:<16} ✓ {len(batch):>4} finding(s)")
        else:
            source_status[name] = "empty"
            log.info(f"    {name:<16} — (no data)")

    # Flat-file candidate sources (may or may not exist)
    flat_sources = [
        ("sqli_candidates.txt",  "sql_injection",   "sqli_finder",   "MEDIUM"),
        ("xss_candidates.txt",   "xss",             "xss_finder",    "MEDIUM"),
        ("ssrf_candidates.txt",  "ssrf",            "ssrf_finder",   "MEDIUM"),
        ("nuclei_critical.txt",  "nuclei_flag",     "nuclei",        "HIGH"),
    ]
    for filename, kind, source, severity in flat_sources:
        batch = _ingest_candidate_txt(
            outdir, filename, kind, source, severity,
        )
        if batch:
            all_findings.extend(batch)
            source_status[source] = source_status.get(source, "") + f" +{filename}"
            log.info(f"    {filename:<24} ✓ {len(batch):>4} candidate(s)")

    log.info("")
    log.info(f"  Total ingested : {len(all_findings)} finding(s)")

    if not all_findings:
        log.warning("  No findings to triage — writing empty report")
        return _write_empty_report(outdir, start, source_status)

    # ── Load context ────────────────────────────────────────────────────────
    log.info("  Loading cross-reference context...")
    context = _load_context(outdir)
    log.info(f"    Live hosts     : {len(context['live_hosts'])}")
    log.info(f"    Priority URLs  : {len(context['priority_urls'])}")
    log.info(f"    GF categories  : {len(context['gf_categories'])} URL(s)")

    # ── Deduplicate ─────────────────────────────────────────────────────────
    dedup_map: dict[tuple, Finding] = {}
    for f in all_findings:
        key = (f.target, f.kind, f.source)
        existing = dedup_map.get(key)
        if not existing or f.confidence > existing.confidence:
            dedup_map[key] = f

    deduped = list(dedup_map.values())
    if len(deduped) < len(all_findings):
        log.info(f"  Dedupe         : {len(all_findings)} → {len(deduped)} finding(s)")

    # ── Correlate & score ───────────────────────────────────────────────────
    log.info("  Correlating and scoring...")
    _apply_correlation_and_score(deduped, context)

    # ── Write outputs ───────────────────────────────────────────────────────
    json_path  = _write_json(deduped, outdir, source_status, start)
    md_path    = _write_markdown(deduped, outdir, source_status)
    steps_path = _write_next_steps(deduped, outdir)
    cat_path   = _write_by_category(deduped, outdir)

    elapsed = time.monotonic() - start

    # ── Console summary ─────────────────────────────────────────────────────
    by_severity: dict[str, int] = defaultdict(int)
    for f in deduped:
        by_severity[f.severity] += 1

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    {md_path.name:<28} {min(len(deduped), MAX_FINDINGS_IN_MARKDOWN):>5} entry(ies)")
    log.info(f"    {steps_path.name:<28} {sum(1 for f in deduped if f.severity in ('CRITICAL','HIGH','MEDIUM')):>5} target(s)")
    log.info(f"    {cat_path.name:<28} {len({f.kind for f in deduped}):>5} category(ies)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity.get('CRITICAL', 0)}  "
        f"HIGH={by_severity.get('HIGH', 0)}  "
        f"MEDIUM={by_severity.get('MEDIUM', 0)}  "
        f"LOW={by_severity.get('LOW', 0)}"
    )

    # Top 10 by score
    log.info("")
    log.info("  Top 10 findings by priority score:")
    for f in deduped[:10]:
        cross = f" [+{len(f.cross_refs)} sources]" if f.cross_refs else ""
        log.info(f"    #{f.rank:<3} [{f.severity:<8}] score={f.score:>5.1f}  "
                 f"{f.kind:<24} {_short_url(f.target, 55)}{cross}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, start: float, source_status: dict[str, str],
) -> Path:
    """Write empty report when no findings are ingested."""
    elapsed = time.monotonic() - start
    report = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            "total_findings": 0, "unique_targets": 0, "unique_kinds": 0,
        },
        "summary": {"by_severity": {}, "by_kind": {}, "by_source": {}},
        "source_status": source_status,
        "findings": [],
    }
    json_path = outdir / "triage_report.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")

    (outdir / "triage_priority.md").write_text(
        "# Argus Triage Report\n\nNo findings were ingested from any module.\n\n"
        "Check the `source_status` field in `triage_report.json` to see what was "
        "expected vs. what was present.\n"
    )
    (outdir / "triage_next_steps.txt").write_text("")
    (outdir / "triage_by_category.txt").write_text("")
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
    out = base / "output"

    try:
        run_vuln_triage(out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
