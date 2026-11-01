#!/usr/bin/env python3
"""
recon_tools/nuclei_scan.py — Template-Driven Vulnerability Scanning
═══════════════════════════════════════════════════════════════════════════════

The vulnerability scanning stage for Argus. Wraps ProjectDiscovery's Nuclei
with safety rails and structured output.

Design priorities:
  • Bug-bounty-safe defaults — conservative rate limiting, no intrusive tags.
  • Scope enforcement — only in-scope URLs reach the nuclei command line.
  • Template management — auto-update, severity filtering, tag allow/deny.
  • Multi-target batching — split large input into manageable chunks.
  • Structured JSON — parse nuclei's JSONL output into a scored report.

Safety defaults:
  • Rate limit: 5 req/s per target (adjustable).
  • Concurrency: 10.
  • Bulk size: 1 (prevent burst concurrency).
  • Deny-list tags: dos, fuzz, intrusive, bruteforce.
  • Timeout: 10s per request, 1 retry.

Outputs (into `outdir`):
  • nuclei_findings.json       — full structured report, primary output
  • nuclei_critical.txt        — CRITICAL + HIGH findings, one URL per line
  • nuclei_all.txt             — every finding URL
  • nuclei_raw.jsonl           — raw nuclei JSONL (for debugging / reprocessing)

Integration:
  main.py → run_one("nuclei") → run_nuclei_scan(targets_file, outdir)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.nuclei")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# ── Safety defaults (bug-bounty tuned) ──────────────────────────────────────
DEFAULT_RATE_LIMIT      = 5          # requests/second per target
DEFAULT_CONCURRENCY    = 10         # parallel template executions
DEFAULT_BULK_SIZE      = 1          # hosts per template — keep at 1 for safety
DEFAULT_TIMEOUT        = 10         # seconds per request
DEFAULT_RETRIES        = 1

# ── Template selection ──────────────────────────────────────────────────────
DEFAULT_SEVERITIES     = ["critical", "high", "medium"]
DEFAULT_TAGS_ALLOW     = ["cve", "misconfig", "exposure", "takeover", "default-login"]
DEFAULT_TAGS_DENY      = ["dos", "fuzz", "intrusive", "bruteforce", "headless"]

# ── Execution limits ────────────────────────────────────────────────────────
MAX_TARGETS_PER_BATCH  = 100        # split large inputs into batches
NUCLEI_HARD_TIMEOUT    = 7200       # 2-hour wall-clock ceiling per batch
MAX_FINDINGS_REPORT    = 5000       # cap JSON report size

# ── Template management ─────────────────────────────────────────────────────
TEMPLATE_UPDATE_TIMEOUT = 600       # 10 minutes for `nuclei -update-templates`

# ── Output ──────────────────────────────────────────────────────────────────
USER_AGENT = "Argus-Nuclei/1.0"


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class NucleiFinding:
    template_id: str
    template_name: str
    severity: str
    matched_at: str
    host: str
    ip: str = ""
    port: str = ""
    scheme: str = ""
    path: str = ""
    matcher_name: str = ""
    extracted_results: list[str] = field(default_factory=list)
    curl_command: str = ""
    timestamp: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    tags: list[str] = field(default_factory=list)
    description: str = ""
    reference: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "template_id":        self.template_id,
            "template_name":      self.template_name,
            "severity":           self.severity,
            "matched_at":         self.matched_at,
            "host":               self.host,
            "ip":                 self.ip,
            "port":               self.port,
            "scheme":             self.scheme,
            "path":               self.path,
            "matcher_name":       self.matcher_name,
            "extracted_results":  self.extracted_results,
            "curl_command":       self.curl_command,
            "timestamp":          self.timestamp,
            "cve_ids":            self.cve_ids,
            "cvss_score":         self.cvss_score,
            "tags":               self.tags,
            "description":        self.description,
            "reference":          self.reference,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def _load_targets(input_file: Path) -> list[str]:
    """
    Load target URLs from a file. Accepts:
      • Bare URLs (https://host/path)
      • httpx format ('URL [status] [title] [tech]')
      • Bare hostnames (auto-prefixed with https://)
    """
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")

    targets: list[str] = []
    seen: set[str] = set()

    for line in input_file.read_text().splitlines():
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


def _extract_host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _check_nuclei() -> bool:
    return shutil.which("nuclei") is not None


# ═════════════════════════════════════════════════════════════════════════════
#  TEMPLATE MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

def _update_templates() -> bool:
    """Run `nuclei -update-templates` and return success."""
    if not _check_nuclei():
        log.warning("    nuclei not installed — cannot update templates")
        return False

    log.info("    Updating nuclei templates...")
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=TEMPLATE_UPDATE_TIMEOUT,
        )
        if result.returncode == 0:
            log.info("    Templates updated successfully")
            return True
        log.warning(f"    template update returned {result.returncode}: "
                    f"{result.stderr.strip()[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log.warning(f"    template update timed out after {TEMPLATE_UPDATE_TIMEOUT}s")
        return False
    except FileNotFoundError:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  COMMAND BUILDING
# ═════════════════════════════════════════════════════════════════════════════

def _build_nuclei_cmd(
    targets_file: Path,
    output_jsonl: Path,
    *,
    rate_limit: int,
    concurrency: int,
    bulk_size: int,
    timeout: int,
    retries: int,
    severities: list[str],
    tags_allow: list[str],
    tags_deny: list[str],
    templates: Optional[list[str]] = None,
    headers: Optional[list[str]] = None,
    cookie: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
) -> list[str]:
    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-jsonl",
        "-o", str(output_jsonl),
        "-rate-limit", str(rate_limit),
        "-concurrency", str(concurrency),
        "-bulk-size", str(bulk_size),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-severity", ",".join(severities),
        "-silent",
        "-no-color",
    ]

    # Tag filtering
    if tags_allow:
        cmd.extend(["-tags", ",".join(tags_allow)])
    if tags_deny:
        cmd.extend(["-exclude-tags", ",".join(tags_deny)])

    # Custom template paths (if provided, overrides default template set)
    if templates:
        for t in templates:
            cmd.extend(["-t", t])

    # Authenticated / header injection
    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    # Headless mode (browser-based templates)
    if headless:
        cmd.append("-headless")

    # Proxy
    if proxy:
        cmd.extend(["-proxy", proxy])

    return cmd


# ═════════════════════════════════════════════════════════════════════════════
#  EXECUTION
# ═════════════════════════════════════════════════════════════════════════════

def _run_nuclei_batch(
    targets: list[str],
    workdir: Path,
    batch_index: int,
    **kwargs,
) -> Optional[Path]:
    """Run nuclei against one batch of targets. Returns the JSONL output path."""
    if not targets:
        return None

    targets_file = workdir / f"batch_{batch_index:03d}_targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")
    output_jsonl = workdir / f"batch_{batch_index:03d}_output.jsonl"

    cmd = _build_nuclei_cmd(targets_file, output_jsonl, **kwargs)
    log.info(f"    batch {batch_index:02d}  {len(targets):>3} target(s)  "
             f"→ {output_jsonl.name}")
    log.debug(f"    $ {' '.join(cmd[:12])}...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"    batch {batch_index} exceeded {NUCLEI_HARD_TIMEOUT}s")
    except FileNotFoundError:
        log.error("    nuclei binary vanished mid-run")
        return None

    if not output_jsonl.exists():
        log.debug(f"    batch {batch_index} produced no JSONL "
                  f"(stderr: {result.stderr.strip()[:160] if 'result' in dir() else 'n/a'})")
        return None

    return output_jsonl


def _parse_nuclei_jsonl(path: Path) -> list[NucleiFinding]:
    """Parse nuclei JSONL output into NucleiFinding records."""
    if not path.exists():
        return []

    findings: list[NucleiFinding] = []
    parse_errors = 0

    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        # Required fields
        template_id = obj.get("template-id") or obj.get("templateID") or ""
        template_name = obj.get("info", {}).get("name", "")
        severity = (obj.get("info", {}).get("severity") or "unknown").lower()
        matched_at = obj.get("matched-at") or obj.get("host") or ""
        host = obj.get("host") or ""

        if not matched_at or not template_id:
            continue

        # Optional enrichment
        info = obj.get("info", {})
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cvss_score = classification.get("cvss-score") or 0.0
        try:
            cvss_score = float(cvss_score)
        except (TypeError, ValueError):
            cvss_score = 0.0

        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        reference = info.get("reference") or []
        if isinstance(reference, str):
            reference = [reference]

        finding = NucleiFinding(
            template_id=template_id,
            template_name=template_name,
            severity=severity,
            matched_at=matched_at,
            host=host,
            ip=obj.get("ip", ""),
            port=str(obj.get("port", "")),
            scheme=obj.get("scheme", ""),
            path=obj.get("path", ""),
            matcher_name=obj.get("matcher-name", ""),
            extracted_results=obj.get("extracted-results") or [],
            curl_command=obj.get("curl-command", ""),
            timestamp=obj.get("timestamp", ""),
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            tags=tags,
            description=info.get("description", ""),
            reference=reference,
            raw=obj,
        )
        findings.append(finding)

    if parse_errors:
        log.debug(f"    {parse_errors} line(s) failed JSON parsing")

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION & SCORING
# ═════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedupe_findings(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    """Deduplicate by (template_id, matched_at, matcher_name)."""
    seen: set[tuple] = set()
    deduped: list[NucleiFinding] = []
    for f in findings:
        key = (f.template_id, f.matched_at, f.matcher_name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _sort_findings(findings: list[NucleiFinding]) -> list[NucleiFinding]:
    """Sort by severity (critical first), then by CVSS score descending."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 5),
            -f.cvss_score,
            f.template_id,
        ),
    )


def _build_summary(findings: list[NucleiFinding]) -> dict:
    by_severity: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    by_template: dict[str, int] = {}
    by_host: dict[str, int] = {}
    cve_count = 0

    for f in findings:
        sev = f.severity if f.severity in by_severity else "info"
        by_severity[sev] += 1
        by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
        host = f.host or _extract_host(f.matched_at)
        if host:
            by_host[host] = by_host.get(host, 0) + 1
        if f.cve_ids:
            cve_count += 1

    return {
        "by_severity": by_severity,
        "by_template": dict(sorted(by_template.items(), key=lambda kv: -kv[1])),
        "by_host": dict(sorted(by_host.items(), key=lambda kv: -kv[1])),
        "unique_cves": cve_count,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_nuclei_scan(
    targets_file: Path,
    outdir: Path,
    *,
    rate_limit: int = DEFAULT_RATE_LIMIT,
    concurrency: int = DEFAULT_CONCURRENCY,
    bulk_size: int = DEFAULT_BULK_SIZE,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    severities: Optional[list[str]] = None,
    tags_allow: Optional[list[str]] = None,
    tags_deny: Optional[list[str]] = None,
    templates: Optional[list[str]] = None,
    headers: Optional[list[str]] = None,
    cookie: Optional[str] = None,
    headless: bool = False,
    proxy: Optional[str] = None,
    update_templates: bool = True,
) -> Path:
    """
    Run nuclei against every target in `targets_file`.

    Returns the path to `nuclei_findings.json`.
    """
    start = time.monotonic()

    if not _check_nuclei():
        raise RuntimeError(
            "nuclei not installed. Run `python3 tools.py --only nuclei` first."
        )

    # ── Defaults ────────────────────────────────────────────────────────────
    severities = severities or DEFAULT_SEVERITIES
    tags_allow = tags_allow if tags_allow is not None else DEFAULT_TAGS_ALLOW
    tags_deny = tags_deny or DEFAULT_TAGS_DENY

    # ── Inputs ──────────────────────────────────────────────────────────────
    targets = _load_targets(targets_file)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "nuclei_work"
    workdir.mkdir(parents=True, exist_ok=True)

    if not targets:
        log.warning("  No targets to scan — writing empty report")
        return _write_empty_report(outdir, targets_file, start)

    log.info(f"  Input  : {len(targets)} target(s) from {targets_file.name}")
    log.info(f"  Config : rate-limit={rate_limit}/s  concurrency={concurrency}  "
             f"bulk-size={bulk_size}")
    log.info(f"  Severities : {', '.join(severities)}")
    log.info(f"  Tags allow : {', '.join(tags_allow) if tags_allow else '(none)'}")
    log.info(f"  Tags deny  : {', '.join(tags_deny)}")
    log.info("")

    # ── Template management ─────────────────────────────────────────────────
    if update_templates:
        log.info("  Template management")
        _update_templates()
        log.info("")

    # ── Batch execution ─────────────────────────────────────────────────────
    batches = [
        targets[i:i + MAX_TARGETS_PER_BATCH]
        for i in range(0, len(targets), MAX_TARGETS_PER_BATCH)
    ]
    log.info(f"  Scanning {len(targets)} target(s) in {len(batches)} batch(es)...")

    all_findings: list[NucleiFinding] = []
    batch_kwargs = dict(
        rate_limit=rate_limit,
        concurrency=concurrency,
        bulk_size=bulk_size,
        timeout=timeout,
        retries=retries,
        severities=severities,
        tags_allow=tags_allow,
        tags_deny=tags_deny,
        templates=templates,
        headers=headers,
        cookie=cookie,
        headless=headless,
        proxy=proxy,
    )

    for i, batch in enumerate(batches, 1):
        output = _run_nuclei_batch(batch, workdir, i, **batch_kwargs)
        if output:
            batch_findings = _parse_nuclei_jsonl(output)
            all_findings.extend(batch_findings)
            log.info(f"      → {len(batch_findings)} finding(s)")

    # ── Deduplicate & sort ──────────────────────────────────────────────────
    deduped = _dedupe_findings(all_findings)
    sorted_findings = _sort_findings(deduped)

    log.info("")
    log.info(f"  Raw findings      : {len(all_findings)}")
    log.info(f"  Unique findings   : {len(sorted_findings)}")

    # ── Write outputs ───────────────────────────────────────────────────────
    critical_high = [
        f for f in sorted_findings
        if f.severity in ("critical", "high")
    ]
    all_urls = sorted({f.matched_at for f in sorted_findings})

    critical_path = outdir / "nuclei_critical.txt"
    critical_path.write_text(
        "\n".join(f.matched_at for f in critical_high) + ("\n" if critical_high else "")
    )

    all_path = outdir / "nuclei_all.txt"
    all_path.write_text("\n".join(all_urls) + ("\n" if all_urls else ""))

    # Combined raw JSONL for debugging
    raw_jsonl = outdir / "nuclei_raw.jsonl"
    with raw_jsonl.open("w") as f:
        for finding in sorted_findings:
            f.write(json.dumps(finding.raw) + "\n")

    # ── Build report ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    summary = _build_summary(sorted_findings)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(targets_file),
        "config": {
            "rate_limit": rate_limit,
            "concurrency": concurrency,
            "bulk_size": bulk_size,
            "timeout": timeout,
            "retries": retries,
            "severities": severities,
            "tags_allow": tags_allow,
            "tags_deny": tags_deny,
            "templates": templates,
            "headless": headless,
            "authenticated": cookie is not None or headers is not None,
        },
        "totals": {
            "targets_input": len(targets),
            "raw_findings": len(all_findings),
            "unique_findings": len(sorted_findings),
            "critical": summary["by_severity"]["critical"],
            "high": summary["by_severity"]["high"],
            "medium": summary["by_severity"]["medium"],
            "low": summary["by_severity"]["low"],
            "info": summary["by_severity"]["info"],
            "unique_cves": summary["unique_cves"],
        },
        "summary": summary,
        "findings": [f.to_dict() for f in sorted_findings[:MAX_FINDINGS_REPORT]],
    }

    json_path = outdir / "nuclei_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup ─────────────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(sorted_findings):>5} finding(s)")
    log.info(f"    {critical_path.name:<24} {len(critical_high):>5} critical/high URL(s)")
    log.info(f"    {all_path.name:<24} {len(all_urls):>5} total URL(s)")
    log.info(f"    {raw_jsonl.name:<24} {len(sorted_findings):>5} raw line(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={summary['by_severity']['critical']}  "
        f"HIGH={summary['by_severity']['high']}  "
        f"MEDIUM={summary['by_severity']['medium']}  "
        f"LOW={summary['by_severity']['low']}  "
        f"INFO={summary['by_severity']['info']}"
    )

    if critical_high:
        log.info("")
        log.info("  Critical / high findings:")
        for f in critical_high[:15]:
            cve = f" [{','.join(f.cve_ids)}]" if f.cve_ids else ""
            log.info(f"    [{f.severity.upper():<8}] {f.template_id:<30} "
                     f"{f.matched_at:<60}{cve}")

    if summary["by_template"]:
        log.info("")
        log.info("  Top templates:")
        for tid, count in list(summary["by_template"].items())[:8]:
            log.info(f"    {tid:<40} {count:>4}")

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
            "targets_input": 0, "raw_findings": 0, "unique_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "unique_cves": 0,
        },
        "summary": {},
        "findings": [],
    }
    path = outdir / "nuclei_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("nuclei_critical.txt", "nuclei_all.txt", "nuclei_raw.jsonl"):
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
    targets = base / "output" / "live_urls.txt"
    out = base / "output"

    try:
        run_nuclei_scan(targets, out)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
