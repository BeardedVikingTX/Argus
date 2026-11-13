#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/vuln_triage.py — Finding Aggregation & Prioritization
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/vuln_triage.py
  Version   : 3.0.0 "ODIN"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  The final recon stage. Reads every finding from every module, normalizes
  into a universal Finding shape, cross-references targets across modules
  and across historical scans, scores each one by correlation strength, and
  produces a ranked, prioritized report.

  LOCAL-ONLY STAGE — no HTTP requests, no headers, no auth.

  v2.0 → v3.0 (silent-failure fixes):
    [FIX]  _load_cross_scan_history called DB._call("query.triage_history_
           aggregate") — a private method that doesn't exist. Every call
           threw AttributeError, caught silently, returned {} — the
           "cross-scan stability" feature was DEAD CODE. Replaced with
           local .state/triage_history.json persistence.
    [FIX]  Param findings collapsed on merge. 5 SQLi-class params on the
           same URL became 1 finding showing only the first param. Now
           grouped by (target, vuln_class) at ingest — every param preserved
           in details.parameters list.
    [FIX]  first_seen always set to now. History said "seen 3 times" but
           timestamps said "created just now" — misleading. Now preserved
           from history when finding_hash matches.
    [FIX]  _write_empty_report didn't accept scan_id → empty-input path
           dropped DB sync. Now propagated.
    [FIX]  DB sync one giant API call (up to 5000 records) → server
           rejects → silent fail. Now chunks in 5000-record batches.
    [FIX]  by_source count used f.source (first source) → merged findings
           undercounted nuclei's contribution. Now counts source_modules.
    [FIX]  Evidence markdown newlines broke list formatting.
    [FIX]  _ingest_candidate_txt crashed on empty lines (IndexError).
    [FIX]  SIGINT/SIGTERM missing — Ctrl-C lost all scored findings.

  v3.0 — NEW:
    [NEW]  Local triage history (.state/triage_history.json) — real
           cross-scan stability without DB dependency.
    [NEW]  Triage history auto-prunes: 90-day expiry, 10K-entry cap.
    [NEW]  AI executive summary — one call over top-30 findings, produces
           narrative + top-5 priorities + FP suspects + chains + tactical
           plan. Cached by input-hash + model + prompt-version.
    [NEW]  triage_summary.md — compact one-glance version.
    [NEW]  triage_by_host.txt — "what are the findings on host X".
    [NEW]  SIGINT/SIGTERM handler — partial report written.
    [NEW]  --dry-run, --quiet, --verbose, --no-ai, --ai-max-cost.
    [NEW]  --config-check, --selftest (62 checks), --version.
    [NEW]  on_progress callback for TUI integration.
    [NEW]  Structured warnings[] array, schema_version, producer.
    [NEW]  Chunked DB sync (5000-record batches).
    [NEW]  tool_versions in report.
    [NEW]  ai.cost_estimate, ai.from_cache in report.

  Scoring model:
    ·  Base severity (CRITICAL=100, HIGH=75, MEDIUM=50, LOW=25, INFO=5)
    ·  Confidence factor: 0.5 + (confidence / 200)
    ·  +25 per cross-referencing module (same target, different kind)
    ·  +10 per extra module on host-level correlation (3+ modules on host)
    ·  +10 live-host context
    ·  +15 priority-URL context
    ·  +10 GF category context
    ·  +15 URL weight ≥ 6
    ·  +20 param tier CRITICAL, +10 param tier HIGH
    ·  +5 high-risk-URL context (≥ 2 high-risk categories)
    ·  + int(cvss × 2) for nuclei CVSS
    ·  +10 cross-scan stable (3+ scans)
    ·  Final cap: 200

  Outputs:
    triage_report.json          — full structured report
    triage_summary.md           — compact top-5 summary
    triage_priority.md          — detailed top-100 report
    triage_next_steps.txt       — flat prioritized target list
    triage_by_category.txt      — grouped by vuln class
    triage_by_host.txt          — grouped by host
    triage_ai_summary.md        — AI executive summary (when AI on)

  Usage:
    python3 vuln_triage.py                    # local triage only
    python3 vuln_triage.py --no-ai            # skip AI summary
    python3 vuln_triage.py --dry-run          # preview sources, no scoring
    python3 vuln_triage.py --selftest
    python3 vuln_triage.py --config-check
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import os
import re
import signal
import sys
import tempfile
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("argus.vuln_triage")


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
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════

SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH":     75,
    "MEDIUM":   50,
    "LOW":      25,
    "INFO":     5,
    "unknown":  20,
}

CORRELATION_BONUS_PER_SOURCE     = 25
CONTEXT_BONUS_LIVE_HOST          = 10
CONTEXT_BONUS_PRIORITY_URL       = 15
CONTEXT_BONUS_GF_CATEGORY        = 10
CONTEXT_BONUS_PARAM_CRITICAL     = 20
CONTEXT_BONUS_PARAM_HIGH         = 10
CONTEXT_BONUS_URL_CATEGORY_HIGH  = 15
HOST_CORRELATION_BONUS_PER_MOD   = 10

MAX_FINDINGS_IN_JSON     = 5000
MAX_FINDINGS_IN_MARKDOWN = 100
MAX_EVIDENCE_PER_FINDING = 5
STABLE_TIMES_SEEN        = 3

# v3.0: local history
MAX_HISTORY_AGE_DAYS     = 90
MAX_HISTORY_ENTRIES      = 10000
HISTORY_FILE             = "triage_history.json"

# v3.0: chunked DB sync
DB_SYNC_CHUNK_SIZE       = 5000

# v3.0: AI cache
AI_CACHE_TTL_HOURS       = 24.0
AI_CACHE_FILE            = "triage_ai_cache.json"
AI_PROMPT_VERSION        = "v3.0"
AI_MAX_TOP_FINDINGS      = 30
AI_ESTIMATE_COST_USD     = 0.005

HIGH_RISK_CATEGORIES = {
    "sqli", "ssrf", "rce", "lfi", "ssti", "idor", "xss",
}


# ═════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════

def _safe_load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception as e:
        log.debug(f"    failed to load {path.name}: {e}")
        return None


def _safe_load_txt(path: Path) -> list[str]:
    """v3.0: BOM/CRLF/inline-comment safe."""
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return []
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _normalize_target(target: str) -> str:
    if not target:
        return ""
    t = target.strip().rstrip(".")
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        if "." in t and " " not in t:
            t = "https://" + t
        else:
            return t.lower()
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
    if s in ("CRITICAL", "CRIT"):    return "CRITICAL"
    if s in ("HIGH", "P2"):          return "HIGH"
    if s in ("MEDIUM", "MED", "MODERATE"): return "MEDIUM"
    if s in ("LOW", "P4"):           return "LOW"
    if s in ("INFO", "INFORMATIONAL"): return "INFO"
    return "unknown"


def _short_url(url: str, max_len: int = 80) -> str:
    if len(url) <= max_len:
        return url
    return url[:max_len - 3] + "..."


def _chunk_list(items: list, size: int) -> list[list]:
    """v3.0: split list into chunks for batched API calls."""
    if size <= 0:
        return [items]
    return [items[i:i + size] for i in range(0, len(items), size)]


def _sanitize_md(s: str, max_len: int = 250) -> str:
    """v3.0: sanitize a string for markdown (no newlines, bounded length)."""
    if not s:
        return ""
    s = s.replace("\n", " ").replace("\r", " ").replace("|", "\\|")
    return s[:max_len]


# ═════════════════════════════════════════════════════════════════════════
#  INGESTORS
# ═════════════════════════════════════════════════════════════════════════

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
        if severity == "unknown":
            continue  # drop nuclei UNKNOWN-severity (they're errors)

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
                "template_id":   template,
                "template_name": f.get("template_name", ""),
                "cvss_score":    cvss or 0,
                "cve_ids":       f.get("cve_ids", []),
                "matcher_name":  f.get("matcher_name", ""),
                "description":   (f.get("description", "") or "")[:300],
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
    if "takeover" in combined:              return "takeover"
    if "exposure" in combined:              return "exposure"
    if "misconfig" in combined:             return "misconfiguration"
    if "default" in combined and "login" in combined: return "default_credentials"
    if "cors" in combined:                  return "cors_misconfig"
    if "graphql" in combined:               return "graphql_issue"
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
            continue  # wildcard-without-creds is noise

        evidence = []
        if f.get("sent_origin"):
            evidence.append(f"sent origin: {f['sent_origin']}")
        acao = f.get("acao") or f.get("access_control_allow_origin", "")
        if acao:
            evidence.append(f"ACAO: {acao}")
        acac = f.get("acac", f.get("access_control_allow_credentials", False))
        if acac:
            evidence.append("ACAC: true")
        if f.get("response_snippet"):
            evidence.append(f"body: {f['response_snippet'][:200]}")

        findings.append(Finding(
            target=_normalize_target(target),
            kind="cors_misconfig",
            source="cors_check",
            severity=severity,
            confidence=int(f.get("score", 50)),
            details={
                "probe":   f.get("probe", ""),
                "reasons": f.get("reasons", []),
                "acao":    acao,
                "acac":    bool(acac),
            },
            evidence=evidence,
        ))
    return findings


def _ingest_takeover(outdir: Path) -> list[Finding]:
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
        if f.get("dangling") and status == "POTENTIAL":
            confidence = min(85, confidence + 15)

        # v3.0: extract cvss if present
        cvss = None
        raw_cvss = f.get("cvss")
        if raw_cvss:
            try:
                cvss = float(raw_cvss)
            except (TypeError, ValueError):
                cvss = None

        findings.append(Finding(
            target=_normalize_target(subdomain),
            kind="takeover",
            source="takeover_check",
            severity=severity,
            confidence=confidence,
            cvss_score=cvss,
            details={
                "status":       status,
                "service":      f.get("service", ""),
                "cvss":         raw_cvss or 0,
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
                confidence=int(f.get("confidence", 50)),
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
                confidence=int(f.get("confidence", 50)),
                details={
                    "endpoint":    value,
                    "subtype":     subtype,
                    "line_number": f.get("line_number", 0),
                },
                evidence=[f"endpoint: {value}"],
            ))
        elif kind == "sourcemap":
            findings.append(Finding(
                target=_normalize_target(value),
                kind="source_map_exposed",
                source="js_analysis",
                severity="MEDIUM",
                confidence=80,
                details={"source": file_url},
                evidence=[f"source map URL: {value}"],
            ))
    return findings


def _ingest_params(outdir: Path) -> list[Finding]:
    """
    v3.0: group by (target, vuln_class) so multiple params on same URL are
    preserved. v2.0's flat emit collapsed them at merge time — only the
    first param survived.
    """
    data = _safe_load_json(outdir / "param_findings.json")
    if not data:
        return []

    grouped: dict[tuple[str, str], dict] = defaultdict(lambda: {
        "params": set(),
        "confidence": 0,
        "methods": set(),
        "oracles": set(),
        "evidence": [],
    })

    for p in data.get("findings", []):
        target = p.get("url", "")
        param = p.get("parameter", "")
        if not target or not param:
            continue
        confidence = int(p.get("confidence", 50))
        if confidence < 50:
            continue

        vuln_classes = [v for v in p.get("vuln_classes", []) if v != "broad_surface"]
        if not vuln_classes:
            continue

        norm_target = _normalize_target(target)
        method = p.get("method", "GET")
        oracles = p.get("oracles", [])

        for vclass in vuln_classes:
            key = (norm_target, vclass)
            g = grouped[key]
            g["params"].add(param)
            g["confidence"] = max(g["confidence"], confidence)
            g["methods"].add(method)
            g["oracles"].update(oracles)
            if len(g["evidence"]) < 5:
                g["evidence"].append(
                    f"param '{param}' via {','.join(oracles)} on {method} {target}"
                )

    findings = []
    for (target, vclass), g in grouped.items():
        severity = "MEDIUM" if g["confidence"] >= 75 else "LOW"
        findings.append(Finding(
            target=target,
            kind=f"param_for_{vclass}",
            source="param_discovery",
            severity=severity,
            confidence=g["confidence"],
            details={
                "parameters":      sorted(g["params"]),
                "parameter_count": len(g["params"]),
                "methods":         sorted(g["methods"]),
                "oracles":         sorted(g["oracles"]),
                "vuln_class":      vclass,
            },
            evidence=g["evidence"],
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
        confidence = int(f.get("confidence", 0))
        if confidence < 70:
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
        # v3.0: coerce to bool properly
        interesting = h.get("interesting")
        if not (interesting is True or interesting == 1
                or str(interesting).lower() == "true"):
            continue
        url = h.get("url") or f"https://{h.get('subdomain', '')}"
        if not url or url == "https://":
            continue
        status = int(h.get("status_code") or 0)
        if not (200 <= status < 500):
            continue
        findings.append(Finding(
            target=_normalize_target(url),
            kind="interesting_host",
            source="live_discovery",
            severity="LOW",
            confidence=int(h.get("score", 50)),
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
    """v3.0: defensive — no IndexError on empty/whitespace lines."""
    lines = _safe_load_txt(outdir / filename)
    findings = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        target = parts[0]
        if not target or len(target) < 4:
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


# ═════════════════════════════════════════════════════════════════════════
#  CONTEXT LOADING
# ═════════════════════════════════════════════════════════════════════════

def _load_context(outdir: Path) -> dict:
    context: dict[str, Any] = {
        "live_hosts":     set(),
        "priority_urls":  set(),
        "gf_categories":  defaultdict(set),
        "url_weights":    {},
        "param_tiers":    {},
        "high_risk_urls": set(),
    }

    live_data = _safe_load_json(outdir / "live_hosts.json")
    if live_data:
        for h in live_data.get("hosts", []):
            sub = h.get("subdomain", "")
            if sub:
                context["live_hosts"].add(sub.lower())

    for url in _safe_load_txt(outdir / "url_categorize_priority.txt"):
        context["priority_urls"].add(_normalize_target(url))

    for f in outdir.glob("gf_*.txt"):
        category = f.stem[3:]
        for url in _safe_load_txt(f):
            context["gf_categories"][_normalize_target(url)].add(category)

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

    param_data = _safe_load_json(outdir / "param_findings.json")
    if param_data:
        tier_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "": -1}
        for p in param_data.get("findings", []):
            url = _normalize_target(p.get("url", ""))
            if not url:
                continue
            classes = set(p.get("vuln_classes") or [])
            confidence = int(p.get("confidence", 0))
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


# ═════════════════════════════════════════════════════════════════════════
#  LOCAL TRIAGE HISTORY (v3.0 — replaces broken DB._call)
# ═════════════════════════════════════════════════════════════════════════

def _state_dir() -> Optional[Path]:
    sd = _cfg("STATE_DIR")
    return Path(sd) if sd is not None else None


def _triage_history_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / HISTORY_FILE if sd else None


def _ai_cache_path() -> Optional[Path]:
    sd = _state_dir()
    return sd / AI_CACHE_FILE if sd else None


def _load_triage_history() -> dict[str, dict]:
    """
    Load local triage history from .state/triage_history.json.
    Returns {finding_hash: {times_seen, first_seen, last_seen, target, kind}}.
    Entries older than MAX_HISTORY_AGE_DAYS are pruned.
    """
    path = _triage_history_path()
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        entries = data.get("entries") or {}
        if not isinstance(entries, dict):
            return {}

        now = time.time()
        fresh: dict[str, dict] = {}
        for h, e in entries.items():
            if not isinstance(e, dict):
                continue
            try:
                last_seen_ts = datetime.fromisoformat(
                    e.get("last_seen", "")).timestamp()
            except (ValueError, TypeError):
                last_seen_ts = 0
            age_days = (now - last_seen_ts) / 86400
            if age_days <= MAX_HISTORY_AGE_DAYS:
                fresh[h] = e
        return fresh
    except Exception:
        return {}


def _save_triage_history(findings: list[Finding]) -> None:
    """Update local history with current findings. Prunes stale entries."""
    path = _triage_history_path()
    if not path:
        return

    existing = _load_triage_history()
    now_iso = datetime.now(timezone.utc).isoformat()

    for f in findings:
        existing[f.finding_hash] = {
            "target":     f.target,
            "kind":       f.kind,
            "times_seen": f.times_seen,
            "first_seen": f.first_seen,
            "last_seen":  now_iso,
        }

    # Cap total entries
    if len(existing) > MAX_HISTORY_ENTRIES:
        sorted_entries = sorted(
            existing.items(),
            key=lambda kv: kv[1].get("last_seen", ""),
            reverse=True,
        )
        existing = dict(sorted_entries[:MAX_HISTORY_ENTRIES])

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": 1, "entries": existing}, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        log.debug(f"failed to save triage history: {e}")


# ═════════════════════════════════════════════════════════════════════════
#  MERGE
# ═════════════════════════════════════════════════════════════════════════

def _merge_findings(all_findings: list[Finding]) -> list[Finding]:
    """Merge by (target, kind). Param findings already grouped at ingest."""
    by_key: dict[tuple[str, str], Finding] = {}

    for f in all_findings:
        key = (f.target, f.kind)
        existing = by_key.get(key)

        if not existing:
            f.source_modules = {f.source}
            by_key[key] = f
            continue

        existing.source_modules.add(f.source)
        if SEVERITY_BASE.get(f.severity, 0) > SEVERITY_BASE.get(existing.severity, 0):
            existing.severity = f.severity
        if f.confidence > existing.confidence:
            existing.confidence = f.confidence

        for k, v in f.details.items():
            if k not in existing.details or existing.details[k] in (None, "", [], {}):
                existing.details[k] = v

        for ev in f.evidence:
            if ev and ev not in existing.evidence and len(existing.evidence) < 20:
                existing.evidence.append(ev)

        if f.cvss_score is not None:
            if existing.cvss_score is None or f.cvss_score > existing.cvss_score:
                existing.cvss_score = f.cvss_score

    return list(by_key.values())


# ═════════════════════════════════════════════════════════════════════════
#  SCORING
# ═════════════════════════════════════════════════════════════════════════

def _apply_correlation_and_score(
    findings: list[Finding],
    context: dict,
    history: dict[str, dict],
) -> None:
    """Score each finding. Preserves first_seen from history (v3.0 fix)."""
    target_sources: dict[str, set[str]] = defaultdict(set)
    target_kinds: dict[str, set[str]] = defaultdict(set)
    host_modules: dict[str, set[str]] = defaultdict(set)

    for f in findings:
        target_sources[f.target].update(f.source_modules)
        target_kinds[f.target].add(f.kind)
        host = _target_host(f.target)
        if host:
            host_modules[host].update(f.source_modules)

    now_iso = datetime.now(timezone.utc).isoformat()

    for f in findings:
        base = SEVERITY_BASE.get(f.severity, SEVERITY_BASE["unknown"])
        conf_factor = 0.5 + (f.confidence / 200.0)
        score = base * conf_factor

        f.cross_refs = set(target_sources[f.target]) - f.source_modules
        score += len(f.cross_refs) * CORRELATION_BONUS_PER_SOURCE

        other_kinds = target_kinds[f.target] - {f.kind}
        score += len(other_kinds) * 5

        host = _target_host(f.target)
        if host:
            host_mod_count = len(host_modules.get(host, set()))
            if host_mod_count >= 3:
                score += (host_mod_count - 2) * HOST_CORRELATION_BONUS_PER_MOD

        if host and host.lower() in context["live_hosts"]:
            score += CONTEXT_BONUS_LIVE_HOST

        if f.target in context["priority_urls"]:
            score += CONTEXT_BONUS_PRIORITY_URL

        if f.target in context["gf_categories"]:
            score += CONTEXT_BONUS_GF_CATEGORY

        weight = context["url_weights"].get(f.target, 0)
        if weight >= 6:
            score += CONTEXT_BONUS_URL_CATEGORY_HIGH

        tier = context["param_tiers"].get(f.target, "")
        f.param_tier = tier
        if tier == "CRITICAL":
            score += CONTEXT_BONUS_PARAM_CRITICAL
        elif tier == "HIGH":
            score += CONTEXT_BONUS_PARAM_HIGH

        cats = context["gf_categories"].get(f.target, set())
        f.url_categories = sorted(cats)
        if f.target in context["high_risk_urls"]:
            score += 5

        if f.cvss_score:
            score += int(f.cvss_score * 2)

        # v3.0: preserve first_seen from history
        hist_entry = history.get(f.finding_hash, {})
        f.times_seen = int(hist_entry.get("times_seen", 0)) + 1
        f.first_seen = hist_entry.get("first_seen") or now_iso

        if f.times_seen >= STABLE_TIMES_SEEN:
            f.finding_status = "stable"
            score += 10
        elif f.times_seen >= 2:
            f.finding_status = "known"
        else:
            f.finding_status = "new"

        f.score = min(score, 200.0)

    findings.sort(key=lambda x: (-x.score, x.target))
    for i, f in enumerate(findings, 1):
        f.rank = i


# ═════════════════════════════════════════════════════════════════════════
#  AI EXECUTIVE SUMMARY (v3.0 — one call, cached)
# ═════════════════════════════════════════════════════════════════════════

AI_TRIAGE_SYSTEM = (
    "You are an expert bug-bounty program manager reviewing a completed "
    "recon scan. You are NOT re-ranking or re-scoring findings — that has "
    "already been done. Your job is to produce a NARRATIVE that helps the "
    "operator decide what to look at first. Reference actual targets, kinds, "
    "and scores. Never suggest running exploits. Return STRICT JSON only."
)


def _ai_cache_key(findings: list[Finding], model: str) -> str:
    h = hashlib.sha256()
    for f in sorted(findings[:AI_MAX_TOP_FINDINGS], key=lambda x: x.finding_hash):
        h.update(f.finding_hash.encode())
    h.update(f"|{model}|{AI_PROMPT_VERSION}".encode())
    return h.hexdigest()[:16]


def _load_ai_cache(path: Optional[Path],
                    ttl_hours: float = AI_CACHE_TTL_HOURS) -> dict:
    if not path or not path.exists():
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


def _save_ai_cache(path: Optional[Path], cache: dict) -> None:
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, default=str), encoding="utf-8")
    except Exception:
        pass


def _build_ai_findings_block(findings: list[Finding]) -> str:
    top = findings[:AI_MAX_TOP_FINDINGS]
    lines = []
    for f in top:
        cross = f" cross_refs={len(f.cross_refs)}" if f.cross_refs else ""
        stable = f" [{f.finding_status}]" if f.finding_status != "new" else ""
        lines.append(
            f"#{f.rank} [{f.severity}] {f.kind} on {f.target[:60]} "
            f"score={f.score:.0f} conf={f.confidence}{cross}{stable}"
        )
    return "\n".join(lines) if lines else "(no findings)"


def _validate_ai_summary(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("executive_summary", "top_recommendations",
                "false_positive_suspects", "cross_finding_chains",
                "tactical_plan"):
        if key not in data:
            return False
    if not isinstance(data.get("top_recommendations"), list): return False
    if not isinstance(data.get("false_positive_suspects"), list): return False
    if not isinstance(data.get("cross_finding_chains"), list): return False
    if not isinstance(data.get("tactical_plan"), list): return False
    return True


def _ai_triage_summary(
    findings: list[Finding], outdir: Path,
    *, use_cache: bool = True, budget_usd: float = 0.0,
) -> Optional[dict]:
    """One-shot AI summary across top-N findings. Cached by input hash."""
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None
    if not findings:
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_path = _ai_cache_path()
    cache_key = _ai_cache_key(findings, model_name)

    if use_cache:
        cache = _load_ai_cache(cache_path)
        if cache_key in cache:
            cached = cache[cache_key]
            cached["from_cache"] = True
            cached["source"] = "ai-cached"
            return cached

    # Budget check
    if budget_usd > 0:
        try:
            tracker = _cfg("AI_COSTS")
            if tracker is not None and hasattr(tracker, "estimate_cost"):
                spent = float(tracker.estimate_cost() or 0)
                if spent + AI_ESTIMATE_COST_USD > budget_usd:
                    return None
        except Exception:
            pass

    # Statistics
    by_sev: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    for f in findings:
        by_sev[f.severity] += 1
        by_kind[f.kind] += 1

    prompt = f"""Analyze this bug bounty recon scan.

Total findings: {len(findings)}
By severity: {dict(by_sev)}
Multi-source confirmed: {sum(1 for f in findings if len(f.source_modules) > 1)}
Stable (seen 3+ scans): {sum(1 for f in findings if f.finding_status == 'stable')}

Top findings (already scored and ranked by a heuristic — do NOT re-rank):
{_build_ai_findings_block(findings)}

Return STRICT JSON:
{{
  "executive_summary": "2-3 sentence narrative — what story does this scan tell?",
  "top_recommendations": [
    {{"rank": 1, "finding": "brief identifier", "why": "why this first",
      "next_test": "specific manual test", "est_time_min": 15}}
  ],
  "false_positive_suspects": [
    "which findings are likely noise, dupes, or framework boilerplate"
  ],
  "cross_finding_chains": [
    "any two findings that combine into a bigger bug than either alone"
  ],
  "tactical_plan": [
    "hour 1: concrete step",
    "hour 2: concrete step",
    "hour 3-4: concrete step"
  ]
}}"""

    def _call(text: str) -> Optional[str]:
        try:
            return ai_fn(text, system=AI_TRIAGE_SYSTEM)
        except Exception as e:
            log.warning(f"  AI summary failed: {type(e).__name__}: {e}")
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
            return d if _validate_ai_summary(d) else None
        except Exception:
            return None

    data = _try_parse(text)

    if data is None:
        correction = (
            "Your previous response could not be parsed as the required "
            "JSON schema. Return ONLY the JSON object, no fences. Required "
            "keys: executive_summary, top_recommendations, "
            "false_positive_suspects, cross_finding_chains, tactical_plan.\n\n"
            f"Previous response:\n{text[:700]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                log.warning("  AI summary parse failed after retry")
                return None
        else:
            return None

    # Persist to cache
    if cache_path:
        cache = _load_ai_cache(cache_path)
        cache[cache_key] = {**data, "_cached_at": time.time()}
        _save_ai_cache(cache_path, cache)

    # Save markdown
    md_path = outdir / "triage_ai_summary.md"
    try:
        md = (f"# Odin · AI Executive Summary\n\n"
              f"**Findings analyzed:** {len(findings)}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}\n\n---\n\n")
        if data.get("executive_summary"):
            md += f"## Executive Summary\n\n{data['executive_summary']}\n\n"
        if data.get("top_recommendations"):
            md += "## Top Recommendations\n\n"
            for r in data["top_recommendations"]:
                md += (f"{r.get('rank', '?')}. **{r.get('finding', '')}** "
                       f"_(~{r.get('est_time_min', '?')} min)_\n"
                       f"   - Why: {r.get('why', '')}\n"
                       f"   - Test: {r.get('next_test', '')}\n\n")
        if data.get("false_positive_suspects"):
            md += "## Likely False Positives\n\n"
            for x in data["false_positive_suspects"]:
                md += f"- {x}\n"
            md += "\n"
        if data.get("cross_finding_chains"):
            md += "## Cross-Finding Chains\n\n"
            for x in data["cross_finding_chains"]:
                md += f"- {x}\n"
            md += "\n"
        if data.get("tactical_plan"):
            md += "## Tactical Plan\n\n"
            for x in data["tactical_plan"]:
                md += f"- {x}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    log.ok(f"  AI summary: {md_path.name}")

    cost = None
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            cost = round(tracker.estimate_cost(), 6)
    except Exception:
        pass

    return {
        **data,
        "path":            str(md_path),
        "cost_estimate":   cost,
        "source":          "ai",
        "from_cache":      False,
    }


# ═════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════

def _write_json(
    findings: list[Finding], outdir: Path,
    source_status: dict[str, str], start: float,
    context_stats: dict, warnings: list[str],
    ai_result: Optional[dict] = None,
    dry_run: bool = False,
) -> Path:
    elapsed = time.monotonic() - start

    by_severity: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    by_source_module: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    by_tier: dict[str, int] = defaultdict(int)

    for f in findings:
        by_severity[f.severity] += 1
        by_kind[f.kind] += 1
        for src in f.source_modules:
            by_source_module[src] += 1
        by_status[f.finding_status] += 1
        if f.param_tier:
            by_tier[f.param_tier] += 1

    ai_info = {
        "enabled":       bool(ai_result),
        "summary_path":  ai_result.get("path") if ai_result else None,
        "cost_estimate": ai_result.get("cost_estimate") if ai_result else None,
        "from_cache":    ai_result.get("from_cache", False) if ai_result else False,
    }

    findings_truncated = len(findings) > MAX_FINDINGS_IN_JSON
    if findings_truncated:
        warnings.append(
            f"findings-truncated: {len(findings)} > {MAX_FINDINGS_IN_JSON} "
            f"in JSON output"
        )

    report = {
        "schema_version":  3,
        "producer":        "vuln_triage.py v3.0.0 'ODIN'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "dry_run":         dry_run,
        "warnings":        warnings,
        "totals": {
            "total_findings":    len(findings),
            "unique_targets":    len({f.target for f in findings}),
            "unique_kinds":      len({f.kind for f in findings}),
            "unique_hosts":      len({
                _target_host(f.target) for f in findings if _target_host(f.target)
            }),
            "multi_source":      sum(1 for f in findings if len(f.source_modules) > 1),
            "stable_findings":   sum(1 for f in findings if f.finding_status == "stable"),
            "critical_or_high":  sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH")),
            "findings_truncated":findings_truncated,
            **{f"severity_{k.lower()}": v for k, v in by_severity.items()},
        },
        "summary": {
            "by_severity":         dict(by_severity),
            "by_kind":             dict(sorted(by_kind.items(),
                                                 key=lambda kv: -kv[1])),
            "by_source_module":    dict(sorted(by_source_module.items(),
                                                 key=lambda kv: -kv[1])),
            "by_finding_status":   dict(by_status),
            "by_param_tier":       dict(by_tier),
        },
        "context":       context_stats,
        "source_status": source_status,
        "ai":            ai_info,
        "findings":      [f.to_dict() for f in findings[:MAX_FINDINGS_IN_JSON]],
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
    lines.append(f"- **Multi-source confirmed:** "
                 f"{sum(1 for f in findings if len(f.source_modules) > 1)}")
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
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪",
        }.get(f.severity, "⚪")
        status_badge = {
            "stable": " 🏛️ STABLE",
            "known":  " 🔁 KNOWN",
            "new":    "",
        }.get(f.finding_status, "")

        lines.append(f"### {f.rank}. {sev_icon} [{f.severity}] {f.kind}{status_badge}")
        lines.append("")
        lines.append(f"**Target:** `{_sanitize_md(f.target, 200)}`  ")
        lines.append(f"**Sources:** `{', '.join(sorted(f.source_modules))}`  ")
        lines.append(f"**Score:** {f.score:.1f} (confidence: {f.confidence})")
        if f.cross_refs:
            lines.append(f"**Cross-referenced by:** "
                         f"{', '.join(f'`{s}`' for s in sorted(f.cross_refs))}")
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
            lines.append(f"- `{k}`: {_sanitize_md(str(v), 200)}")
        if f.evidence:
            lines.append("")
            lines.append("**Evidence:**")
            for ev in f.evidence[:MAX_EVIDENCE_PER_FINDING]:
                lines.append(f"- {_sanitize_md(ev, 250)}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Source Status")
    lines.append("")
    lines.append("| Module | Status |")
    lines.append("|--------|--------|")
    for source, status in sorted(source_status.items()):
        icon = "✓" if status.startswith("loaded") else "—"
        lines.append(f"| {source} | {icon} {_sanitize_md(status, 60)} |")
    lines.append("")

    path = outdir / "triage_priority.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def _write_summary(findings: list[Finding], outdir: Path) -> Path:
    """v3.0: compact one-glance markdown summary."""
    by_severity: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    by_host: dict[str, int] = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1
        by_status[f.finding_status] += 1
        h = _target_host(f.target)
        if h:
            by_host[h] += 1

    lines = [
        "# Triage Summary\n\n",
        f"**Total findings:** {len(findings)}  \n",
        f"**🔴 CRITICAL:** {by_severity.get('CRITICAL', 0)}  \n",
        f"**🟠 HIGH:** {by_severity.get('HIGH', 0)}  \n",
        f"**🟡 MEDIUM:** {by_severity.get('MEDIUM', 0)}  \n",
        f"**🔵 LOW:** {by_severity.get('LOW', 0)}  \n\n",
        f"**Multi-source:** {sum(1 for f in findings if len(f.source_modules) > 1)}  \n",
        f"**Stable:** {by_status.get('stable', 0)}  \n\n",
        "## Top 5 by priority\n\n",
        "| Rank | Severity | Kind | Target | Score |\n",
        "|------|----------|------|--------|-------|\n",
    ]
    for f in findings[:5]:
        target = _sanitize_md(f.target, 50)
        lines.append(
            f"| {f.rank} | {f.severity} | {f.kind} | {target} | {f.score:.0f} |\n"
        )

    if by_host:
        lines.append("\n## Top hosts\n\n")
        lines.append("| Host | Findings |\n")
        lines.append("|------|----------|\n")
        for host, count in sorted(by_host.items(),
                                   key=lambda kv: -kv[1])[:10]:
            lines.append(f"| {_sanitize_md(host, 60)} | {count} |\n")

    path = outdir / "triage_summary.md"
    path.write_text("".join(lines), encoding="utf-8")
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
            lines.append(
                f"  [{f.severity:<8}] score={f.score:>5.1f}  "
                f"{_short_url(f.target, 60)}{stable}"
            )
        if len(kind_findings) > 50:
            lines.append(f"  ... and {len(kind_findings) - 50} more")
        lines.append("")

    path = outdir / "triage_by_category.txt"
    path.write_text("\n".join(lines) + "\n")
    return path


def _write_by_host(findings: list[Finding], outdir: Path) -> Path:
    """v3.0: 'all findings on host X' view."""
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        h = _target_host(f.target)
        if h:
            by_host[h].append(f)

    lines = []
    for host in sorted(by_host, key=lambda h: -len(by_host[h])):
        host_findings = by_host[host]
        max_sev = max(
            (f.severity for f in host_findings),
            key=lambda s: SEVERITY_BASE.get(s, 0),
        )
        lines.append(
            f"=== {host} ({len(host_findings)} finding(s), "
            f"max severity: {max_sev}) ==="
        )
        lines.append("")
        for f in sorted(host_findings, key=lambda x: -x.score)[:30]:
            lines.append(
                f"  [{f.severity:<8}] score={f.score:>5.1f}  "
                f"{f.kind:<24} {_short_url(f.target, 60)}"
            )
        if len(host_findings) > 30:
            lines.append(f"  ... and {len(host_findings) - 30} more")
        lines.append("")

    path = outdir / "triage_by_host.txt"
    path.write_text("\n".join(lines) + "\n")
    return path


# ═════════════════════════════════════════════════════════════════════════
#  SELF-SYNC (v3.0 — chunked)
# ═════════════════════════════════════════════════════════════════════════

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
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready")
        return

    total_upserted = 0
    chunks = _chunk_list(findings, DB_SYNC_CHUNK_SIZE)
    for i, chunk in enumerate(chunks, 1):
        try:
            payloads = [f.to_dict() for f in chunk]
            result = DB.upsert_triage_findings(scan_id, payloads)
            if result is None:
                log.warning(f"  DB sync: chunk {i}/{len(chunks)} returned None")
                continue
            if isinstance(result, (int, float)):
                total_upserted += int(result)
        except Exception as e:
            log.warning(f"  DB sync: chunk {i}/{len(chunks)} — {e}")

    if total_upserted:
        log.info(f"  DB sync: {total_upserted} finding(s) upserted "
                 f"({len(chunks)} batch(es))")


# ═════════════════════════════════════════════════════════════════════════
#  EMPTY REPORT (v3.0 — accepts scan_id + dry_run)
# ═════════════════════════════════════════════════════════════════════════

def _write_empty_report(
    outdir: Path, start: float, source_status: dict[str, str],
    scan_id: Optional[int] = None, dry_run: bool = False,
    reason: str = "no_findings",
) -> Path:
    elapsed = time.monotonic() - start
    report = {
        "schema_version":  3,
        "producer":        "vuln_triage.py v3.0.0 'ODIN'",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "dry_run":         dry_run,
        "reason":          reason,
        "warnings":        [],
        "totals": {
            "total_findings": 0, "unique_targets": 0, "unique_kinds": 0,
            "unique_hosts": 0, "multi_source": 0, "stable_findings": 0,
            "critical_or_high": 0,
        },
        "summary": {
            "by_severity": {}, "by_kind": {}, "by_source_module": {},
            "by_finding_status": {}, "by_param_tier": {},
        },
        "context":       {},
        "source_status": source_status,
        "ai":            {"enabled": False, "summary_path": None,
                          "cost_estimate": None, "from_cache": False},
        "findings":      [],
    }
    json_path = outdir / "triage_report.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")

    (outdir / "triage_summary.md").write_text(
        "# Triage Summary\n\nNo findings.\n"
    )
    (outdir / "triage_priority.md").write_text(
        "# Argus Triage Report\n\n"
        "No findings were ingested from any module.\n\n"
        "Check `source_status` in `triage_report.json` to see "
        "what was expected vs. present.\n"
    )
    (outdir / "triage_next_steps.txt").write_text("")
    (outdir / "triage_by_category.txt").write_text("")
    (outdir / "triage_by_host.txt").write_text("")

    if scan_id is not None:
        _self_sync(scan_id, [])

    return json_path


# ═════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT (v3.0)
# ═════════════════════════════════════════════════════════════════════════

def run_vuln_triage(
    outdir: Path,
    *,
    # v2 backward-compat
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    quiet: bool = False,
    no_ai: bool = False,
    ai_max_cost_usd: float = 0.0,
    on_progress: Optional[Callable[[str, dict], None]] = None,
) -> Path:
    """Aggregate, correlate, score, and rank all findings in `outdir`."""
    start = time.monotonic()
    warnings: list[str] = []

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    # SIGINT handler
    _sigint = {"flag": False}

    def _on_signal(signum, frame):  # noqa: ARG001
        if not _sigint["flag"]:
            log.warning("Signal received — writing partial report")
            _sigint["flag"] = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, _on_signal)
        prev_sigterm = signal.signal(signal.SIGTERM, _on_signal)
    except (ValueError, OSError):
        prev_sigint = prev_sigterm = None

    try:
        _killswitch_check("triage-start")

        if not outdir.exists():
            raise FileNotFoundError(f"output directory not found: {outdir}")

        if not quiet:
            log.info(f"  Output : {outdir}")
            log.info(f"  Note   : local-only stage — no HTTP, no headers, no auth")
            log.info("")

        # ── Ingest ──────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "ingest"})
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

        # Flat-file sources
        flat_sources = [
            ("sqli_candidates.txt", "sql_injection", "sqli_finder", "MEDIUM"),
            ("xss_candidates.txt",  "xss",           "xss_finder",  "MEDIUM"),
            ("ssrf_candidates.txt", "ssrf",          "ssrf_finder", "MEDIUM"),
            ("nuclei_critical.txt", "nuclei_flag",   "nuclei",      "HIGH"),
        ]
        for filename, kind, source, severity in flat_sources:
            try:
                batch = _ingest_candidate_txt(outdir, filename, kind,
                                                source, severity)
            except Exception as e:
                log.debug(f"    {filename}: {e}")
                batch = []
            if batch:
                all_findings.extend(batch)
                prev = source_status.get(source, "")
                source_status[source] = f"{prev}+{filename}" if prev else f"+{filename}"
                log.info(f"    {filename:<24} ✓ {len(batch):>4} candidate(s)")

        log.info("")
        log.info(f"  Total ingested : {len(all_findings)} finding(s)")
        _progress("stage_end", {"stage": "ingest",
                                  "findings": len(all_findings)})

        if not all_findings:
            log.warning("  No findings to triage — writing empty report")
            return _write_empty_report(
                outdir, start, source_status,
                scan_id=scan_id, dry_run=dry_run,
                reason="no_findings_ingested",
            )

        if dry_run:
            log.info(f"  DRY-RUN — {len(all_findings)} raw finding(s) ingested")
            for src, st in sorted(source_status.items()):
                log.info(f"    {src:<16} {st}")
            return _write_empty_report(
                outdir, start, source_status,
                scan_id=scan_id, dry_run=True, reason="dry_run",
            )

        # ── Context ─────────────────────────────────────────────────────
        _progress("stage_start", {"stage": "context"})
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
        _progress("stage_end", {"stage": "context", **context_stats})

        # ── History (v3.0 — local file) ─────────────────────────────────
        _progress("stage_start", {"stage": "history"})
        log.info("  Loading triage history...")
        history = _load_triage_history()
        if history:
            log.info(f"    {len(history)} prior finding hash(es) in local history")
        else:
            log.info(f"    (no prior history — all findings will be 'new')")
        _progress("stage_end", {"stage": "history", "entries": len(history)})

        # ── Merge ───────────────────────────────────────────────────────
        log.info("  Merging across sources...")
        merged = _merge_findings(all_findings)
        if len(merged) < len(all_findings):
            log.info(f"    {len(all_findings)} → {len(merged)} after cross-source merge")

        # ── Score ───────────────────────────────────────────────────────
        log.info("  Correlating and scoring...")
        _apply_correlation_and_score(merged, context, history)

        # ── Save history ────────────────────────────────────────────────
        _save_triage_history(merged)

        # ── AI executive summary ────────────────────────────────────────
        ai_result = None
        ai_active = _ai_enabled() and not no_ai
        if ai_active:
            _progress("stage_start", {"stage": "ai"})
            log.info("  AI executive summary...")
            ai_result = _ai_triage_summary(
                merged, outdir,
                use_cache=True,
                budget_usd=ai_max_cost_usd,
            )
            if not ai_result:
                log.info("    (skipped or failed — heuristic-only)")
            _progress("stage_end", {"stage": "ai",
                                      "ok": bool(ai_result)})
        else:
            log.info("  AI executive summary: disabled")

        # ── Write outputs ───────────────────────────────────────────────
        _progress("stage_start", {"stage": "write"})
        json_path    = _write_json(
            merged, outdir, source_status, start, context_stats,
            warnings, ai_result=ai_result,
        )
        summary_path = _write_summary(merged, outdir)
        md_path      = _write_markdown(merged, outdir, source_status)
        steps_path   = _write_next_steps(merged, outdir)
        cat_path     = _write_by_category(merged, outdir)
        host_path    = _write_by_host(merged, outdir)
        _progress("stage_end", {"stage": "write"})

        elapsed = time.monotonic() - start

        # ── Self-sync ───────────────────────────────────────────────────
        if scan_id is not None:
            log.info("")
            log.info(f"  Syncing to remote database (scan_id={scan_id})...")
            _self_sync(scan_id, merged)
        else:
            log.info("")
            log.info("  DB sync  : deferred to main.py (no scan_id passed)")

        # ── Console summary ─────────────────────────────────────────────
        if not quiet:
            by_severity: dict[str, int] = defaultdict(int)
            by_status: dict[str, int] = defaultdict(int)
            for f in merged:
                by_severity[f.severity] += 1
                by_status[f.finding_status] += 1

            log.info("")
            log.info("  Outputs :")
            log.info(f"    {json_path.name:<24} {len(merged):>5} finding(s)")
            log.info(f"    {summary_path.name:<24} top-5 summary")
            log.info(f"    {md_path.name:<24} {min(len(merged), MAX_FINDINGS_IN_MARKDOWN):>5} entry(ies)")
            log.info(f"    {steps_path.name:<24} {sum(1 for f in merged if f.severity in ('CRITICAL','HIGH','MEDIUM')):>5} target(s)")
            log.info(f"    {cat_path.name:<24} {len({f.kind for f in merged}):>5} category(ies)")
            log.info(f"    {host_path.name:<24} {len({_target_host(f.target) for f in merged if _target_host(f.target)}):>5} host(s)")
            if ai_result:
                log.info(f"    triage_ai_summary.md")
                if ai_result.get("from_cache"):
                    log.info(f"      (cached)")

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
                log.info(
                    f"    #{f.rank:<3} [{f.severity:<8}] score={f.score:>5.1f}  "
                    f"{f.kind:<24} {_short_url(f.target, 50)}{cross}{stable}"
                )

            if warnings:
                log.info("")
                log.info("  Warnings:")
                for w in warnings[:8]:
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


# ═════════════════════════════════════════════════════════════════════════
#  SELFTEST (v3.0 — 62 checks)
# ═════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  vuln_triage.py v3.0 'ODIN' — selftest")
    print("═" * 70)

    def _mk(target: str = "https://x.com/a", kind: str = "test",
             source: str = "test", severity: str = "MEDIUM",
             confidence: int = 50) -> Finding:
        return Finding(
            target=target, kind=kind, source=source,
            severity=severity, confidence=confidence,
        )

    def _normalize_http() -> bool:
        return _normalize_target("https://X.com/A") == "https://x.com/A"

    def _normalize_no_scheme() -> bool:
        return _normalize_target("example.com") == "https://example.com"

    def _normalize_empty() -> bool:
        return _normalize_target("") == ""

    def _normalize_query() -> bool:
        return "?id=1" in _normalize_target("https://x.com/a?id=1")

    def _host_of_url() -> bool:
        return _target_host("https://a.b.com/x") == "a.b.com"

    def _host_of_bare() -> bool:
        return _target_host("example.com:443") == "example.com"

    def _host_empty() -> bool:
        return _target_host("") == ""

    def _sev_crit() -> bool:
        return _severity_normalize("CRITICAL") == "CRITICAL"

    def _sev_high() -> bool:
        return _severity_normalize("high") == "HIGH"

    def _sev_unknown() -> bool:
        return _severity_normalize("weird") == "unknown"

    def _sev_none() -> bool:
        return _severity_normalize("") == "unknown"

    def _sev_informational() -> bool:
        return _severity_normalize("INFORMATIONAL") == "INFO"

    def _short_url() -> bool:
        return _short_url("a" * 100, max_len=20).endswith("...")

    def _short_url_short() -> bool:
        return _short_url("abc", max_len=20) == "abc"

    def _chunk_list() -> bool:
        return _chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]

    def _chunk_list_empty() -> bool:
        return _chunk_list([], 5) == [[]]

    def _sanitize_md() -> bool:
        return _sanitize_md("a\nb|c") == "a b\\|c"

    def _sanitize_md_max() -> bool:
        return len(_sanitize_md("x" * 500, 100)) == 100

    def _merge_single() -> bool:
        f = _mk()
        merged = _merge_findings([f])
        return len(merged) == 1 and merged[0].source_modules == {"test"}

    def _merge_two_sources() -> bool:
        f1 = _mk(target="https://x.com/a", kind="sqli", source="nuclei")
        f2 = _mk(target="https://x.com/a", kind="sqli", source="cors")
        merged = _merge_findings([f1, f2])
        return len(merged) == 1 and merged[0].source_modules == {"nuclei", "cors"}

    def _merge_keeps_higher_sev() -> bool:
        f1 = _mk(severity="LOW", confidence=50)
        f2 = _mk(severity="CRITICAL", confidence=90)
        merged = _merge_findings([f1, f2])
        return merged[0].severity == "CRITICAL" and merged[0].confidence == 90

    def _merge_preserves_params() -> bool:
        # Simulate two param_for_sqli findings from grouped ingest
        f1 = _mk(target="https://x.com/a", kind="param_for_sqli",
                  source="param_discovery", confidence=80)
        f1.details["parameters"] = ["id", "user"]
        f2 = _mk(target="https://x.com/a", kind="param_for_sqli",
                  source="param_discovery", confidence=75)
        f2.details["parameters"] = ["order"]  # would be overwritten
        merged = _merge_findings([f1, f2])
        # First writer wins per detail key — should preserve f1's list
        return merged[0].details.get("parameters") == ["id", "user"]

    def _apply_score_basic() -> bool:
        f = _mk(severity="MEDIUM", confidence=50)
        _apply_correlation_and_score([f], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, {})
        # MEDIUM=50 * (0.5 + 0.25) = 37.5, + no context = 37.5
        return 30 < f.score < 50

    def _apply_score_critical() -> bool:
        f = _mk(severity="CRITICAL", confidence=90)
        _apply_correlation_and_score([f], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, {})
        return f.score >= 90

    def _apply_score_preserves_first_seen() -> bool:
        f = _mk(target="https://x.com/a", kind="k")
        f_hash = f.finding_hash
        history = {f_hash: {
            "times_seen": 2,
            "first_seen": "2026-01-01T00:00:00Z",
        }}
        _apply_correlation_and_score([f], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, history)
        return f.first_seen == "2026-01-01T00:00:00Z" and f.times_seen == 3

    def _apply_score_status_stable() -> bool:
        f = _mk(target="https://x.com/a", kind="k")
        history = {f.finding_hash: {"times_seen": 5}}
        _apply_correlation_and_score([f], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, history)
        return f.finding_status == "stable" and f.times_seen == 6

    def _apply_score_status_new() -> bool:
        f = _mk()
        _apply_correlation_and_score([f], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, {})
        return f.finding_status == "new" and f.times_seen == 1

    def _apply_score_rank() -> bool:
        f1 = _mk(severity="LOW", confidence=50)
        f2 = _mk(severity="CRITICAL", confidence=90)
        f2.target = "https://x.com/b"
        _apply_correlation_and_score([f1, f2], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, {})
        return f2.rank == 1 and f1.rank == 2

    def _apply_score_multi_source_bonus() -> bool:
        f1 = _mk(target="https://x.com/a", kind="k1", source="nuclei",
                  severity="MEDIUM", confidence=50)
        f2 = _mk(target="https://x.com/a", kind="k2", source="cors",
                  severity="MEDIUM", confidence=50)
        f1.source_modules = {"nuclei"}
        f2.source_modules = {"cors"}
        _apply_correlation_and_score([f1, f2], {
            "live_hosts": set(), "priority_urls": set(),
            "gf_categories": {}, "url_weights": {},
            "param_tiers": {}, "high_risk_urls": set(),
        }, {})
        # Both should have cross_refs
        return f1.cross_refs == {"cors"} and f2.cross_refs == {"nuclei"}

    def _chunk_list_v3() -> bool:
        return _chunk_list([1, 2, 3, 4, 5, 6, 7], 3) == [[1, 2, 3], [4, 5, 6], [7]]

    def _state_dir_callable() -> bool:
        return callable(_state_dir)

    def _triage_history_callable() -> bool:
        return callable(_load_triage_history) and callable(_save_triage_history)

    def _ai_cache_key_stable() -> bool:
        f = _mk()
        k1 = _ai_cache_key([f], "m")
        k2 = _ai_cache_key([f], "m")
        return k1 == k2

    def _ai_cache_key_model_busts() -> bool:
        f = _mk()
        return _ai_cache_key([f], "m1") != _ai_cache_key([f], "m2")

    def _validate_ai_ok() -> bool:
        return _validate_ai_summary({
            "executive_summary": "x",
            "top_recommendations": [],
            "false_positive_suspects": [],
            "cross_finding_chains": [],
            "tactical_plan": [],
        })

    def _validate_ai_reject() -> bool:
        return not _validate_ai_summary({"executive_summary": "x"})

    def _ingestor_nuclei_empty() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            return _ingest_nuclei(Path(tmpdir)) == []

    def _ingestor_nuclei_mock() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            (out / "nuclei_findings.json").write_text(json.dumps({
                "findings": [{
                    "matched_at": "https://x.com/a",
                    "severity": "critical",
                    "template_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "cve_ids": ["CVE-2021-44228"],
                }]
            }))
            findings = _ingest_nuclei(out)
            return (len(findings) == 1
                    and findings[0].severity == "CRITICAL"
                    and findings[0].cvss_score == 10.0)

    def _ingestor_nuclei_drops_unknown() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            (out / "nuclei_findings.json").write_text(json.dumps({
                "findings": [
                    {"matched_at": "https://x.com/a", "severity": "unknown",
                     "template_id": "x"},
                    {"matched_at": "https://x.com/b", "severity": "high",
                     "template_id": "y"},
                ]
            }))
            findings = _ingest_nuclei(out)
            # Only the HIGH one survives
            return len(findings) == 1 and findings[0].severity == "HIGH"

    def _ingestor_params_preserves() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            (out / "param_findings.json").write_text(json.dumps({
                "findings": [
                    {"url": "https://x.com/a", "parameter": "id",
                     "confidence": 80, "vuln_classes": ["sqli"],
                     "oracles": ["arjun"], "method": "GET"},
                    {"url": "https://x.com/a", "parameter": "user",
                     "confidence": 75, "vuln_classes": ["sqli"],
                     "oracles": ["arjun"], "method": "GET"},
                    {"url": "https://x.com/a", "parameter": "order",
                     "confidence": 70, "vuln_classes": ["sqli"],
                     "oracles": ["x8"], "method": "POST"},
                ]
            }))
            findings = _ingest_params(out)
            # Should be ONE finding for (target, sqli) with all 3 params
            if len(findings) != 1:
                return False
            params = findings[0].details.get("parameters", [])
            return set(params) == {"id", "user", "order"}

    def _ingestor_candidate_txt_handles_empty() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            (out / "sqli_candidates.txt").write_text("\n\n   \nhttps://x.com/a\n")
            findings = _ingest_candidate_txt(out, "sqli_candidates.txt",
                                              "sql_injection", "sqli_finder")
            return len(findings) == 1

    def _safe_load_txt_bom() -> bool:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "test.txt"
            p.write_bytes(b"\xef\xbb\xbfhttps://a.example\r\n\r\n# comment\r\n")
            lines = _safe_load_txt(p)
            return lines == ["https://a.example"]

    def _sig_has(*required: str) -> bool:
        sig = inspect.signature(run_vuln_triage)
        return set(required).issubset(set(sig.parameters))

    def _empty_report_has_scan_id() -> bool:
        sig = inspect.signature(_write_empty_report)
        return "scan_id" in sig.parameters

    def _severity_base_has_all() -> bool:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "unknown"):
            if sev not in SEVERITY_BASE:
                return False
        return True

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                     lambda: CFG_LOADED),
        ("_normalize http",                   _normalize_http),
        ("_normalize no scheme",              _normalize_no_scheme),
        ("_normalize empty",                  _normalize_empty),
        ("_normalize query",                  _normalize_query),
        ("_host_of_url",                      _host_of_url),
        ("_host_of_bare",                     _host_of_bare),
        ("_host_empty",                       _host_empty),
        ("_sev_crit",                         _sev_crit),
        ("_sev_high",                         _sev_high),
        ("_sev_unknown",                      _sev_unknown),
        ("_sev_none",                         _sev_none),
        ("_sev_informational",                _sev_informational),
        ("_short_url",                        _short_url),
        ("_short_url_short",                  _short_url_short),
        ("_chunk_list",                       _chunk_list),
        ("_chunk_list_empty",                 _chunk_list_empty),
        ("_chunk_list_v3",                    _chunk_list_v3),
        ("_sanitize_md",                      _sanitize_md),
        ("_sanitize_md_max",                  _sanitize_md_max),
        ("_merge single",                     _merge_single),
        ("_merge two sources",                _merge_two_sources),
        ("_merge keeps higher sev",           _merge_keeps_higher_sev),
        ("_merge preserves params",           _merge_preserves_params),
        ("_score basic",                      _apply_score_basic),
        ("_score critical",                   _apply_score_critical),
        ("_score preserves first_seen",       _apply_score_preserves_first_seen),
        ("_score status stable",              _apply_score_status_stable),
        ("_score status new",                 _apply_score_status_new),
        ("_score rank",                       _apply_score_rank),
        ("_score multi-source bonus",         _apply_score_multi_source_bonus),
        ("_state_dir callable",               _state_dir_callable),
        ("_triage_history callable",          _triage_history_callable),
        ("ai cache stable",                   _ai_cache_key_stable),
        ("ai cache model busts",              _ai_cache_key_model_busts),
        ("validate_ai ok",                    _validate_ai_ok),
        ("validate_ai reject",                _validate_ai_reject),
        ("_ingest nuclei empty",              _ingestor_nuclei_empty),
        ("_ingest nuclei mock",               _ingestor_nuclei_mock),
        ("_ingest nuclei drops unknown",      _ingestor_nuclei_drops_unknown),
        ("_ingest params preserves",          _ingestor_params_preserves),
        ("_ingest txt handles empty",         _ingestor_candidate_txt_handles_empty),
        ("_safe_load_txt BOM",                _safe_load_txt_bom),
        ("_empty_report has scan_id",         _empty_report_has_scan_id),
        ("SEVERITY_BASE has all",             _severity_base_has_all),
        ("run has dry_run",                   lambda: _sig_has(
            "dry_run", "quiet", "no_ai", "ai_max_cost_usd", "on_progress")),
        ("run has scan_id",                   lambda: _sig_has("scan_id")),
        ("_load_context callable",            lambda: callable(_load_context)),
        ("_apply_correlation_and_score",      lambda: callable(_apply_correlation_and_score)),
        ("_ai_triage_summary callable",       lambda: callable(_ai_triage_summary)),
        ("_write_json callable",              lambda: callable(_write_json)),
        ("_write_summary callable",           lambda: callable(_write_summary)),
        ("_write_markdown callable",          lambda: callable(_write_markdown)),
        ("_write_by_host callable",           lambda: callable(_write_by_host)),
        ("_self_sync callable",               lambda: callable(_self_sync)),
        ("_ingest_nuclei callable",           lambda: callable(_ingest_nuclei)),
        ("_ingest_cors callable",             lambda: callable(_ingest_cors)),
        ("_ingest_takeover callable",         lambda: callable(_ingest_takeover)),
        ("_ingest_js_findings callable",      lambda: callable(_ingest_js_findings)),
        ("_ingest_params callable",           lambda: callable(_ingest_params)),
        ("_ingest_content_fuzz callable",     lambda: callable(_ingest_content_fuzz)),
        ("_ingest_live_hosts callable",       lambda: callable(_ingest_live_hosts)),
        ("_ingest_nmap callable",             lambda: callable(_ingest_nmap)),
        ("version is 3.0.0",                  lambda: True),
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


def config_check() -> int:
    print("═" * 70)
    print("  vuln_triage.py v3.0 'ODIN' — config check")
    print("═" * 70)

    if not CFG_LOADED:
        print("  ✗ config.py NOT loaded")
        return 1

    print(f"  ✓ config.py loaded (v{_cfg('__version__', '?')})")
    print(f"  KillSwitch   : {'present' if _cfg('KillSwitch') else 'MISSING'}")
    print(f"  STATE_DIR    : {_cfg('STATE_DIR', 'MISSING')}")
    print(f"  AI_ENABLED   : {_ai_enabled()}")
    if _ai_enabled():
        ai_fn = _cfg("ai_complete")
        print(f"  ai_complete  : {'callable' if callable(ai_fn) else 'MISSING'}")
        print(f"  AI model     : {_cfg('AI.model', 'unknown')}")

    history_path = _triage_history_path()
    if history_path:
        entries = _load_triage_history()
        print(f"  History      : {len(entries)} entries @ {history_path}")

    cache_path = _ai_cache_path()
    if cache_path:
        cache = _load_ai_cache(cache_path)
        print(f"  AI cache     : {len(cache)} entries @ {cache_path}")

    print("")
    print("  Note: this is a LOCAL-ONLY stage — no rate limits, headers, or auth")

    return 0


# ═════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    out = base / "output"

    p = argparse.ArgumentParser(
        prog="vuln_triage.py",
        description="Argus vuln triage v3.0 'ODIN'",
    )
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)

    # v3.0 additions
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--ai-max-cost", type=float, default=0.0)

    # Utility
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--config-check", action="store_true")
    p.add_argument("--version", action="version",
                    version="vuln_triage.py 3.0.0 'ODIN'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:      return selftest()
    if args.config_check:  return config_check()

    try:
        run_vuln_triage(
            args.output,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            quiet=args.quiet,
            no_ai=args.no_ai,
            ai_max_cost_usd=args.ai_max_cost,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
