#!/usr/bin/env python3
"""
recon_tools/vuln_triage.py — Finding Aggregation & Prioritization
═══════════════════════════════════════════════════════════════════════════════

The final recon stage. Reads every finding from every module, normalizes them
into a universal Finding shape, cross-references targets across modules and
across historical scans, scores each one by correlation strength, and produces
a ranked, prioritized report.

LOCAL-ONLY STAGE — no HTTP requests, no headers, no auth.

What makes this triage "accurate"
──────────────────────────────────
  1. Cross-source merging — a target flagged by nuclei AND cors AND js_analysis
     is CRITICAL regardless of any individual module's base severity.
  2. Param-tier awareness — URLs with CRITICAL-tier params (from
     param_findings) receive +20 score.
  3. URL-category awareness — URLs with weight ≥ 6 (from url_categorize)
     receive +15 score.
  4. CVSS weighting — a CRITICAL with CVSS 9.8 outranks a CRITICAL with CVSS
     6.0 by up to +20 score.
  5. Cross-scan stability — a finding that has appeared in 3+ prior scans
     (same target+kind) is marked "stable" — either a confirmed bug or
     persistent noise. Either way, worth extra attention.
  6. Host-correlation boost — a host flagged by 3+ modules receives +10
     per additional module on top of URL-level correlation.

What makes this triage "precise" (false-positive reduction)
───────────────────────────────────────────────────────────
  • Nuclei UNKNOWN-severity findings are dropped (they're errors, not findings)
  • dns_resolve takeover fallback is dropped (redundant with takeover_check)
  • Param findings with confidence < 50 are dropped
  • Content-fuzz findings with confidence < 70 are dropped
  • Live-host flags with status not in (200-499) are dropped
  • Deduplication merges by (target, kind) — not (target, kind, source) — so a
    target+kind is one finding with all source attributions merged, not three
    separate rows

Remote DB (if scan_id is provided):
  • triage_findings table   — one row per (scan_id, finding_hash), with
                              cross-scan stability status and full attribution

Outputs (into `outdir`):
  • triage_report.json          — full structured report
  • triage_priority.md          — human-readable top findings
  • triage_next_steps.txt       — flat prioritized target list
  • triage_by_category.txt      — grouped by vuln class

Integration:
  main.py → run_one("triage") → run_vuln_triage(outdir)
  Standalone: run_vuln_triage(outdir, scan_id=42) → self-syncs
"""

from __future__ import annotations

import hashlib
import json
import logging
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


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH":     75,
    "MEDIUM":   50,
    "LOW":      25,
    "INFO":     5,
    "unknown":  20,
}

# Correlation and context bonuses
CORRELATION_BONUS_PER_SOURCE     = 25
CONTEXT_BONUS_LIVE_HOST          = 10
CONTEXT_BONUS_PRIORITY_URL       = 15
CONTEXT_BONUS_GF_CATEGORY        = 10
CONTEXT_BONUS_PARAM_CRITICAL     = 20
CONTEXT_BONUS_PARAM_HIGH         = 10
CONTEXT_BONUS_URL_CATEGORY_HIGH  = 15
HOST_CORRELATION_BONUS_PER_MOD   = 10

# Severity from CVSS (for nuclei findings)
def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "unknown"


# Report caps
MAX_FINDINGS_IN_JSON     = 5000
MAX_FINDINGS_IN_MARKDOWN = 100
MAX_EVIDENCE_PER_FINDING = 5

# Cross-scan stability threshold
STABLE_TIMES_SEEN = 3

# High-risk categories for scoring
HIGH_RISK_CATEGORIES = {
    "sqli", "ssrf", "rce", "lfi", "ssti", "idor", "xss",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    target: str
    kind: str
    source: str
    severity: str = "unknown"
    confidence: int = 0
    details: dict = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    # Populated during scoring
    source_modules: set[str] = field(default_factory=set)
    cross_refs: set[str] = field(default_factory=set)
    param_tier: str = ""
    url_categories: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    finding_status: str = "new"
    times_seen: int = 1
    score: float = 0.0
    rank: int = 0
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(
            f"{self.target}|{self.kind}".encode()
        ).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "target_host":      _target_host(self.target),
            "kind":             self.kind,
            "severity":         self.severity,
            "base_confidence":  self.confidence,
            "source_modules":   sorted(self.source_modules),
            "source_count":     len(self.source_modules),
            "cross_refs":       sorted(self.cross_refs),
            "cross_ref_count":  len(self.cross_refs),
            "param_tier":       self.param_tier,
            "url_categories":   self.url_categories,
            "cvss_score":       self.cvss_score,
            "finding_status":   self.finding_status,
            "times_seen":       self.times_seen,
            "final_score":      round(self.score, 1),
            "rank":             self.rank,
            "finding_hash":     self.finding_hash,
            "details":          self.details,
            "evidence":         self.evidence[:MAX_EVIDENCE_PER_FINDING],
            "first_seen":       self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _safe_load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as e:
        log.debug(f"    failed to load {path.name}: {e}")
        return None


def _safe_load_txt(path: Path) -> list[str]:
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
    if not target:
        return ""
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        if "." in t and " " not in t:
            t = "https://" + t
        else:
            return t.lower().rstrip(".")
    try:
        parsed = urllib.parse.urlparse(t)
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}" + (
            f"?{parsed.query}" if parsed.query else ""
        )
    except Exception:
        return t.lower()


def _target_host(target: str) -> str:
    if not target:
        return ""
    if target.startswith(("http://", "https://")):
        try:
            return urllib.parse.urlparse(target).hostname or ""
        except Exception:
            return ""
    return target.split(":")[0].split("/")[0].lower()


def _severity_normalize(s: str) -> str:
    if not s:
        return "unknown"
    s = s.strip().upper()
    if s in ("CRITICAL", "CRIT"):
        return "CRITICAL"
    if s in ("HIGH", "P2"):
        return "HIGH"
    if s in ("MEDIUM", "MED", "MODERATE"):
        return "MEDIUM"
    if s in ("LOW", "P4"):
        return "LOW"
    if s in ("INFO", "INFORMATIONAL"):
        return "INFO"
    return "unknown"


def _short_url(url: str, max_len: int = 80) -> str:
    if len(url) <= max_len:
        return url
    return url[:max_len - 3] + "..."


# ═════════════════════════════════════════════════════════════════════════════
#  INGESTORS — one per source module (with FP filtering)
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

        raw_sev = f.get("severity", "unknown")
        severity = _severity_normalize(raw_sev)

        # FP filter: drop nuclei UNKNOWN-severity (parse errors, not findings)
        if severity == "unknown":
            continue

        cvss = None
        raw_cvss = f.get("cvss_score")
        if raw_cvss not in (None, "", 0, 0.0, "0"):
            try:
                cvss = float(raw_cvss)
            except (TypeError, ValueError):
                cvss = None

        template = f.get("template_id", "")
        evidence = []
        if f.get("extracted_results"):
            evidence.append(f"extracted: {', '.join(str(x) for x in f['extracted_results'][:3])}")
        if f.get("cve_ids"):
            evidence.append(f"CVEs: {', '.join(f['cve_ids'][:3])}")
        if f.get("curl_command"):
            evidence.append(f"curl: {f['curl_command'][:200]}")

        confidence = 90 if severity == "CRITICAL" else 80 if severity == "HIGH" else 60
        # Confidence boost if CVSS is high
        if cvss and cvss >= 9.0:
            confidence = min(100, confidence + 5)

        findings.append(Finding(
            target=_normalize_target(target),
            kind=_nuclei_kind(template, f.get("tags") or []),
            source="nuclei",
            severity=severity,
            confidence=confidence,
            cvss_score=cvss,
            details={
                "template_id":  template,
                "template_name": f.get("template_name", ""),
                "cvss_score":   cvss or 0,
                "cve_ids":      f.get("cve_ids", []),
                "matcher_name": f.get("matcher_name", ""),
                "description":  (f.get("description", "") or "")[:300],
            },
            evidence=evidence,
        ))
    return findings


def _nuclei_kind(template_id: str, tags: list) -> str:
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
        if severity == "INFO":
            continue  # wildcard-without-credentials isn't a finding

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
                "probe":   f.get("probe", ""),
                "reasons": f.get("reasons", []),
                "acao":    f.get("access_control_allow_origin", ""),
                "acac":    f.get("access_control_allow_credentials", False),
            },
            evidence=evidence,
        ))
    return findings


def _ingest_takeover(outdir: Path) -> list[Finding]:
    """
    Read takeover findings from the structured report only.

    The dns_resolve takeover_candidates.txt fallback is intentionally NOT read
    here — it produces many false positives (the CNAME points to a vulnerable
    service but the resource is claimed). Only takeover_check's confirmed and
    potential findings enter triage.
    """
    findings = []
    data = _safe_load_json(outdir / "takeover_findings.json")
    if not data:
        return findings

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
        if f.get("dangling"):
            evidence.append("DNS dangling — terminal CNAME has no A record")
        if f.get("shared_cname"):
            evidence.append("Shared terminal CNAME with other subdomains")

        confidence = 95 if status == "VULNERABLE" else 60
        # Dangling is a strong signal — boost potential confidence
        if f.get("dangling") and status == "POTENTIAL":
            confidence = min(85, confidence + 15)

        findings.append(Finding(
            target=_normalize_target(subdomain),
            kind="takeover",
            source="takeover_check",
            severity=severity,
            confidence=confidence,
            details={
                "status":       status,
                "service":      f.get("service", ""),
                "cvss":         f.get("cvss", 0),
                "dangling":     bool(f.get("dangling")),
                "shared_cname": bool(f.get("shared_cname")),
                "notes":        f.get("notes", ""),
            },
            evidence=evidence,
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
            findings.append(Finding(
                target=_normalize_target(file_url or "js_scan"),
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
            if f.get("confidence", 0) < 60:
                continue
            findings.append(Finding(
                target=_normalize_target(file_url or ""),
                kind="js_endpoint",
                source="js_analysis",
                severity="LOW",
                confidence=f.get("confidence", 50),
                details={
                    "endpoint":    value,
                    "subtype":     subtype,
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
        confidence = f.get("confidence", 50)
        if confidence < 50:
            continue

        vuln_classes = f.get("vuln_classes", [])
        # Skip broad_surface — too generic
        vuln_classes = [v for v in vuln_classes if v != "broad_surface"]
        if not vuln_classes:
            continue

        for vclass in vuln_classes:
            findings.append(Finding(
                target=_normalize_target(target),
                kind=f"param_for_{vclass}",
                source="param_discovery",
                severity="MEDIUM" if confidence >= 75 else "LOW",
                confidence=confidence,
                details={
                    "parameter":    param,
                    "method":       f.get("method", "GET"),
                    "oracle":       f.get("oracles", []),
                    "vuln_classes": vuln_classes,
                },
                evidence=[f"parameter '{param}' discovered via {','.join(f.get('oracles', ['?']))}"],
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
        if confidence < 70:  # raised from 60 — reduce noise
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
        status = h.get("status_code") or 0
        # FP filter: only 200-499 are meaningful live hosts
        if not (200 <= status < 500):
            continue
        findings.append(Finding(
            target=_normalize_target(url),
            kind="interesting_host",
            source="live_discovery",
            severity="LOW",
            confidence=h.get("score", 50),
            details={
                "status":       status,
                "technologies": h.get("technologies", []),
                "reasons":      h.get("reasons", []),
            },
            evidence=[f"flagged: {','.join(h.get('reasons', []))}"],
        ))
    return findings


def _ingest_nmap(outdir: Path) -> list[Finding]:
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


def _ingest_candidate_txt(
    outdir: Path, filename: str, kind: str, source: str, severity: str = "MEDIUM",
) -> list[Finding]:
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
#  CONTEXT LOADING (multi-source)
# ═════════════════════════════════════════════════════════════════════════════

def _load_context(outdir: Path) -> dict:
    """
    Load auxiliary context used for scoring bonuses.

    Keys:
      • live_hosts      — set of live hostnames
      • priority_urls   — set of URLs from url_categorize_priority.txt
      • gf_categories   — dict of URL → set of categories
      • url_weights     — dict of URL → weight (from url_categorize.json)
      • param_tiers     — dict of URL → tier (best param tier on that URL)
      • high_risk_urls  — set of URLs matching ≥ 2 high-risk categories
    """
    context: dict[str, Any] = {
        "live_hosts":     set(),
        "priority_urls":  set(),
        "gf_categories":  defaultdict(set),
        "url_weights":    {},
        "param_tiers":    {},
        "high_risk_urls": set(),
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
        category = f.stem[3:]
        for url in _safe_load_txt(f):
            context["gf_categories"][_normalize_target(url)].add(category)

    # URL weights from url_categorize.json
    cat_data = _safe_load_json(outdir / "url_categorize.json")
    if cat_data:
        for p in cat_data.get("priority_urls") or []:
            url = _normalize_target(p.get("url", ""))
            weight = int(p.get("weight") or 0)
            if url and weight:
                context["url_weights"][url] = weight
                cats = set(p.get("categories") or [])
                if len(cats & HIGH_RISK_CATEGORIES) >= 2:
                    context["high_risk_urls"].add(url)

    # Param tiers from param_findings.json
    # Map URL → best tier (CRITICAL > HIGH > MEDIUM > LOW)
    param_data = _safe_load_json(outdir / "param_findings.json")
    if param_data:
        tier_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "": -1}
        for p in param_data.get("findings", []):
            url = _normalize_target(p.get("url", ""))
            if not url:
                continue
            classes = set(p.get("vuln_classes") or [])
            confidence = p.get("confidence", 0)

            # Derive tier from param's vuln classes + confidence
            if len(classes & HIGH_RISK_CATEGORIES) >= 2 and confidence >= 75:
                tier = "CRITICAL"
            elif len(classes & HIGH_RISK_CATEGORIES) >= 1 and confidence >= 70:
                tier = "HIGH"
            elif classes and confidence >= 60:
                tier = "MEDIUM"
            elif classes:
                tier = "LOW"
            else:
                tier = ""

            existing = context["param_tiers"].get(url, "")
            if tier_rank.get(tier, -1) > tier_rank.get(existing, -1):
                context["param_tiers"][url] = tier

    return context


# ═════════════════════════════════════════════════════════════════════════════
#  CROSS-SCAN HISTORY (best-effort, requires DB)
# ═════════════════════════════════════════════════════════════════════════════

def _load_cross_scan_history(scan_id: Optional[int]) -> dict[str, int]:
    """
    Return {finding_hash: times_seen_across_prior_scans}.

    Queries the triage_findings table for all previous scans with the same
    wildcard scope. If the DB is unavailable, returns an empty dict — no
    cross-scan status tracking, everything stays "new".

    This is a best-effort enrichment. It doesn't block triage if the DB is
    down or the table doesn't exist yet.
    """
    if not scan_id:
        return {}
    if not DB_AVAILABLE or DB is None:
        return {}
    if not DB.available:
        return {}

    # Fetch prior scans' hash counts — one API call, one aggregate
    try:
        r = DB._call("query.triage_history_aggregate", {
            "current_scan_id": scan_id,
        })
        if r and r.get("ok") and isinstance(r.get("history"), dict):
            return {str(k): int(v) for k, v in r["history"].items()}
    except Exception as e:
        log.debug(f"  cross-scan history unavailable: {e}")
    return {}


# ═════════════════════════════════════════════════════════════════════════════
#  MERGE, SCORE, FINALIZE
# ═════════════════════════════════════════════════════════════════════════════

def _merge_findings(all_findings: list[Finding]) -> list[Finding]:
    """
    Merge by (target, kind). A target+kind flagged by multiple sources becomes
    one finding with all source attributions merged. Preserves the highest
    base severity and confidence, merges details + evidence, unions source
    modules.
    """
    by_key: dict[tuple[str, str], Finding] = {}

    for f in all_findings:
        key = (f.target, f.kind)
        existing = by_key.get(key)

        if not existing:
            # Fresh row — copy source modules
            f.source_modules = {f.source}
            by_key[key] = f
            continue

        # Merge into existing
        existing.source_modules.add(f.source)

        # Keep higher severity
        existing_sev_rank = SEVERITY_BASE.get(existing.severity, 0)
        incoming_sev_rank = SEVERITY_BASE.get(f.severity, 0)
        if incoming_sev_rank > existing_sev_rank:
            existing.severity = f.severity

        # Keep higher confidence
        if f.confidence > existing.confidence:
            existing.confidence = f.confidence

        # Merge details (don't overwrite keys — first writer wins per key,
        # but merge nested dicts by union)
        for k, v in f.details.items():
            if k not in existing.details or existing.details[k] in (None, "", [], {}):
                existing.details[k] = v

        # Merge evidence (dedupe by string)
        for ev in f.evidence:
            if ev and ev not in existing.evidence and len(existing.evidence) < 20:
                existing.evidence.append(ev)

        # Keep higher CVSS
        if f.cvss_score is not None:
            if existing.cvss_score is None or f.cvss_score > existing.cvss_score:
                existing.cvss_score = f.cvss_score

    return list(by_key.values())


def _apply_correlation_and_score(
    findings: list[Finding],
    context: dict,
    history: dict[str, int],
) -> None:
    """
    Score each finding based on:
      • Base severity + confidence
      • Multi-source confirmation
      • Param-tier of the URL
      • URL category weight
      • Live-host context
      • GF category presence
      • Nuclei CVSS
      • Cross-scan stability
      • Host-level multi-module correlation
    """
    # Build target → sources map (for cross-reference)
    target_sources: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        target_sources[f.target].update(f.source_modules)

    # Build target → kinds map
    target_kinds: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        target_kinds[f.target].add(f.kind)

    # Build host → modules map (for host-level correlation)
    host_modules: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        host = _target_host(f.target)
        if host:
            host_modules[host].update(f.source_modules)

    now = datetime.now(timezone.utc).isoformat()

    for f in findings:
        base = SEVERITY_BASE.get(f.severity, SEVERITY_BASE["unknown"])
        conf_factor = 0.5 + (f.confidence / 200.0)
        score = base * conf_factor

        # Multi-source bonus — this kind is the core signal
        f.cross_refs = set(target_sources[f.target]) - f.source_modules
        score += len(f.cross_refs) * CORRELATION_BONUS_PER_SOURCE

        # Cross-kind bonus
        other_kinds = target_kinds[f.target] - {f.kind}
        score += len(other_kinds) * 5

        # Host-level correlation
        host = _target_host(f.target)
        if host:
            host_mod_count = len(host_modules.get(host, set()))
            if host_mod_count >= 3:
                score += (host_mod_count - 2) * HOST_CORRELATION_BONUS_PER_MOD

        # Live host context
        if host and host.lower() in context["live_hosts"]:
            score += CONTEXT_BONUS_LIVE_HOST

        # Priority URL context
        if f.target in context["priority_urls"]:
            score += CONTEXT_BONUS_PRIORITY_URL

        # GF category context
        if f.target in context["gf_categories"]:
            score += CONTEXT_BONUS_GF_CATEGORY

        # URL weight context
        weight = context["url_weights"].get(f.target, 0)
        if weight >= 6:
            score += CONTEXT_BONUS_URL_CATEGORY_HIGH

        # Param tier context
        tier = context["param_tiers"].get(f.target, "")
        f.param_tier = tier
        if tier == "CRITICAL":
            score += CONTEXT_BONUS_PARAM_CRITICAL
        elif tier == "HIGH":
            score += CONTEXT_BONUS_PARAM_HIGH

        # URL categories context
        cats = context["gf_categories"].get(f.target, set())
        f.url_categories = sorted(cats)
        if f.target in context["high_risk_urls"]:
            score += 5   # already counted via param_tier HIGH, but worth a small extra

        # Nuclei CVSS — direct weight
        if f.cvss_score:
            score += int(f.cvss_score * 2)

        # Cross-scan stability
        f.times_seen = 1 + history.get(f.finding_hash, 0)
        if f.times_seen >= STABLE_TIMES_SEEN:
            f.finding_status = "stable"
            score += 10   # confirmed or persistent noise — worth attention
        elif f.times_seen >= 2:
            f.finding_status = "known"
        else:
            f.finding_status = "new"

        f.score = min(score, 200.0)
        f.first_seen = now

    # Sort by score descending
    findings.sort(key=lambda x: (-x.score, x.target))
    for i, f in enumerate(findings, 1):
        f.rank = i


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_json(
    findings: list[Finding], outdir: Path,
    source_status: dict[str, str], start: float,
    context_stats: dict,
) -> Path:
    elapsed = time.monotonic() - start

    by_severity: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    by_tier: dict[str, int] = defaultdict(int)

    for f in findings:
        by_severity[f.severity] += 1
        by_kind[f.kind] += 1
        by_source[f.source] += 1
        by_status[f.finding_status] += 1
        if f.param_tier:
            by_tier[f.param_tier] += 1

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            "total_findings":    len(findings),
            "unique_targets":    len({f.target for f in findings}),
            "unique_kinds":      len({f.kind for f in findings}),
            "unique_hosts":      len({_target_host(f.target) for f in findings if _target_host(f.target)}),
            "multi_source":      sum(1 for f in findings if len(f.source_modules) > 1),
            "stable_findings":   sum(1 for f in findings if f.finding_status == "stable"),
            "critical_or_high":  sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH")),
            **{f"severity_{k.lower()}": v for k, v in by_severity.items()},
        },
        "summary": {
            "by_severity":       dict(by_severity),
            "by_kind":           dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
            "by_source":         dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
            "by_finding_status": dict(by_status),
            "by_param_tier":     dict(by_tier),
        },
        "context": context_stats,
        "source_status": source_status,
        "findings": [f.to_dict() for f in findings[:MAX_FINDINGS_IN_JSON]],
    }

    path = outdir / "triage_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return path


def _write_markdown(
    findings: list[Finding], outdir: Path,
    source_status: dict[str, str],
) -> Path:
    lines: list[str] = []

    lines.append("# Argus Triage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    by_severity: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1
        by_status[f.finding_status] += 1

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append(f"- **Unique targets:** {len({f.target for f in findings})}")
    lines.append(f"- **Multi-source confirmed:** {sum(1 for f in findings if len(f.source_modules) > 1)}")
    lines.append(f"- **Stable (seen 3+ scans):** {by_status.get('stable', 0)}")
    lines.append("")
    lines.append(f"- 🔴 **CRITICAL:** {by_severity.get('CRITICAL', 0)}")
    lines.append(f"- 🟠 **HIGH:**     {by_severity.get('HIGH', 0)}")
    lines.append(f"- 🟡 **MEDIUM:**   {by_severity.get('MEDIUM', 0)}")
    lines.append(f"- 🔵 **LOW:**      {by_severity.get('LOW', 0)}")
    lines.append(f"- ⚪ **INFO:**     {by_severity.get('INFO', 0)}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Top Priority Findings")
    lines.append("")
    lines.append("Ranked by combined severity, confidence, cross-module correlation,")
    lines.append("param tier, and cross-scan stability.")
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

        status_badge = {
            "stable": " 🏛️ STABLE",
            "known":  " 🔁 KNOWN",
            "new":    "",
        }.get(f.finding_status, "")

        lines.append(f"### {f.rank}. {sev_icon} [{f.severity}] {f.kind}{status_badge}")
        lines.append("")
        lines.append(f"**Target:** `{f.target}`  ")
        lines.append(f"**Sources:** `{', '.join(sorted(f.source_modules))}`  ")
        lines.append(f"**Score:** {f.score:.1f} (confidence: {f.confidence})")

        if f.cross_refs:
            lines.append(f"**Cross-referenced by:** {', '.join(f'`{s}`' for s in sorted(f.cross_refs))}")
        if f.param_tier:
            lines.append(f"**Param tier:** {f.param_tier}")
        if f.url_categories:
            lines.append(f"**URL categories:** {', '.join(f.url_categories)}")
        if f.cvss_score:
            lines.append(f"**CVSS:** {f.cvss_score}")
        if f.times_seen > 1:
            lines.append(f"**Times seen:** {f.times_seen} scan(s)")

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
    lines = []
    seen: set[tuple] = set()
    for f in findings:
        key = (f.target, f.kind)
        if key in seen:
            continue
        seen.add(key)
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            stable_tag = " [stable]" if f.finding_status == "stable" else ""
            lines.append(
                f"[{f.severity:<8}] {f.kind:<24}  {f.target}{stable_tag}"
            )
    path = outdir / "triage_next_steps.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_by_category(findings: list[Finding], outdir: Path) -> Path:
    by_kind: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_kind[f.kind].append(f)

    lines = []
    for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
        kind_findings = by_kind[kind]
        lines.append(f"=== {kind} ({len(kind_findings)} finding(s)) ===")
        lines.append("")
        for f in kind_findings[:50]:
            stable = " *" if f.finding_status == "stable" else ""
            lines.append(f"  [{f.severity:<8}] score={f.score:>5.1f}  {f.target}{stable}")
        if len(kind_findings) > 50:
            lines.append(f"  ... and {len(kind_findings) - 50} more")
        lines.append("")

    path = outdir / "triage_by_category.txt"
    path.write_text("\n".join(lines) + "\n")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[Finding]) -> None:
    if not findings:
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
        payloads = [f.to_dict() for f in findings]
        result = DB.upsert_triage_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} triage finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_vuln_triage(
    outdir: Path,
    *,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Aggregate, correlate, score, and rank all findings in `outdir`.

    If scan_id is provided AND the DB is available, the triaged findings
    are upserted to the triage_findings table, and cross-scan history is
    loaded to mark findings as new/known/stable.
    """
    start = time.monotonic()

    if not outdir.exists():
        raise FileNotFoundError(f"output directory not found: {outdir}")

    log.info(f"  Output : {outdir}")
    log.info(f"  Note   : local-only stage — no HTTP, no headers, no auth")
    log.info("")

    # ── Ingest ──────────────────────────────────────────────────────────────
    log.info("  Ingesting module outputs...")

    ingestors = [
        ("nuclei",       _ingest_nuclei),
        ("cors",         _ingest_cors),
        ("takeover",     _ingest_takeover),
        ("js_analysis",  _ingest_js_findings),
        ("params",       _ingest_params),
        ("content_fuzz", _ingest_content_fuzz),
        ("live_hosts",   _ingest_live_hosts),
        ("nmap",         _ingest_nmap),
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

    # Flat-file candidate sources
    flat_sources = [
        ("sqli_candidates.txt",  "sql_injection", "sqli_finder", "MEDIUM"),
        ("xss_candidates.txt",   "xss",           "xss_finder",  "MEDIUM"),
        ("ssrf_candidates.txt",  "ssrf",          "ssrf_finder", "MEDIUM"),
        ("nuclei_critical.txt",  "nuclei_flag",   "nuclei",      "HIGH"),
    ]
    for filename, kind, source, severity in flat_sources:
        batch = _ingest_candidate_txt(outdir, filename, kind, source, severity)
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
    context_stats = {
        "live_hosts":     len(context["live_hosts"]),
        "priority_urls":  len(context["priority_urls"]),
        "gf_categories":  len(context["gf_categories"]),
        "url_weights":    len(context["url_weights"]),
        "param_tiers":    len(context["param_tiers"]),
        "high_risk_urls": len(context["high_risk_urls"]),
    }
    log.info(f"    Live hosts     : {context_stats['live_hosts']}")
    log.info(f"    Priority URLs  : {context_stats['priority_urls']}")
    log.info(f"    GF categories  : {context_stats['gf_categories']} URL(s)")
    log.info(f"    Param tiers    : {context_stats['param_tiers']} URL(s)")
    log.info(f"    High-risk URLs : {context_stats['high_risk_urls']}")

    # ── Cross-scan history ──────────────────────────────────────────────────
    history: dict[str, int] = {}
    if scan_id:
        log.info("  Loading cross-scan history...")
        try:
            history = _load_cross_scan_history(scan_id)
            if history:
                log.info(f"    {len(history)} prior finding hash(es) across previous scans")
            else:
                log.info(f"    (no prior history — all findings will be 'new')")
        except Exception as e:
            log.info(f"    history unavailable ({e}) — all findings will be 'new'")
    else:
        log.info("  Cross-scan history: disabled (no scan_id passed)")

    # ── Merge across sources ────────────────────────────────────────────────
    log.info("  Merging across sources...")
    merged = _merge_findings(all_findings)
    if len(merged) < len(all_findings):
        log.info(f"    {len(all_findings)} → {len(merged)} after cross-source merge")

    # ── Correlate + score ───────────────────────────────────────────────────
    log.info("  Correlating and scoring...")
    _apply_correlation_and_score(merged, context, history)

    # ── Write outputs ───────────────────────────────────────────────────────
    json_path  = _write_json(merged, outdir, source_status, start, context_stats)
    md_path    = _write_markdown(merged, outdir, source_status)
    steps_path = _write_next_steps(merged, outdir)
    cat_path   = _write_by_category(merged, outdir)

    elapsed = time.monotonic() - start

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, merged)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    by_severity: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    for f in merged:
        by_severity[f.severity] += 1
        by_status[f.finding_status] += 1

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(merged):>5} finding(s)")
    log.info(f"    {md_path.name:<28} {min(len(merged), MAX_FINDINGS_IN_MARKDOWN):>5} entry(ies)")
    log.info(f"    {steps_path.name:<28} {sum(1 for f in merged if f.severity in ('CRITICAL','HIGH','MEDIUM')):>5} target(s)")
    log.info(f"    {cat_path.name:<28} {len({f.kind for f in merged}):>5} category(ies)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity.get('CRITICAL', 0)}  "
        f"HIGH={by_severity.get('HIGH', 0)}  "
        f"MEDIUM={by_severity.get('MEDIUM', 0)}  "
        f"LOW={by_severity.get('LOW', 0)}"
    )
    log.info(
        f"  Status   : "
        f"new={by_status.get('new', 0)}  "
        f"known={by_status.get('known', 0)}  "
        f"stable={by_status.get('stable', 0)}"
    )

    log.info("")
    log.info("  Top 10 findings by priority score:")
    for f in merged[:10]:
        cross = f" [+{len(f.cross_refs)}]" if f.cross_refs else ""
        stable = " 🏛️" if f.finding_status == "stable" else ""
        log.info(f"    #{f.rank:<3} [{f.severity:<8}] score={f.score:>5.1f}  "
                 f"{f.kind:<24} {_short_url(f.target, 50)}{cross}{stable}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, start: float, source_status: dict[str, str],
) -> Path:
    elapsed = time.monotonic() - start
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            "total_findings": 0, "unique_targets": 0, "unique_kinds": 0,
        },
        "summary":       {"by_severity": {}, "by_kind": {}, "by_source": {}},
        "context":       {},
        "source_status": source_status,
        "findings":      [],
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
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus vuln triage (standalone)")
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    args = parser.parse_args()

    try:
        run_vuln_triage(args.output, scan_id=args.scan_id)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
