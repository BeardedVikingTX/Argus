#!/usr/bin/env python3
"""
recon_tools/param_discovery.py — Hidden Parameter Discovery
═══════════════════════════════════════════════════════════════════════════════

The parameter discovery stage for Argus. Finds parameters that the server
accepts but the UI never exposes.

Three-phase strategy:

  Phase 1 — Passive mining (zero target traffic)
      ParamSpider queries the Wayback CDX API for historical URLs with query
      strings, replacing values with a FUZZ placeholder. Zero traffic to the
      target, maximum historical coverage.

  Phase 2 — Active brute-forcing (Arjun)
      Arjun's curated ~26,000-name wordlist, batched intelligently. Supports
      GET, POST, JSON, and XML methods. The --stable flag is exposed for
      WAF-protected or rate-limited targets.

  Phase 3 — Validation (x8, optional)
      x8 uses line-by-line differential analysis, catching subtle parameter
      acceptance that Arjun's hash-based comparison might miss. Used as a
      second-opinion pass on high-value endpoints.

Every finding is scored by oracle strength (reflection > status change > length
diff), mapped to likely vulnerability classes, and written to a structured
report. Downstream modules (sqli_finder, xss_finder, ssrf_finder) consume the
flat `params_by_endpoint.txt` file.

Outputs (into `outdir`):
  • param_findings.json         — full structured report, primary output
  • params_by_endpoint.txt      — flat 'METHOD URL param1,param2,...' format
  • param_passive.txt           — ParamSpider discovered URLs (FUZZ placeholders)
  • param_candidates.txt        — merged candidate parameter list

Integration:
  main.py → run_one("params") → run_param_discovery(live_urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import random
import re
import shutil
import string
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.param_discovery")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# ── Execution ───────────────────────────────────────────────────────────────
DEFAULT_THREADS           = 5
DEFAULT_TIMEOUT           = 10
MAX_ENDPOINTS             = 500
ARJUN_RATE_LIMIT          = 3          # requests/second
ARJUN_STABLE_MODE         = False      # True = 1 thread + 6-12s delay

# ── ParamSpider ─────────────────────────────────────────────────────────────
PARAMSPIDER_TIMEOUT       = 300
PARAMSPIDER_PLACEHOLDER   = "FUZZ"

# ── x8 validation ───────────────────────────────────────────────────────────
X8_TIMEOUT                = 180
X8_VALIDATE_TOP_N         = 20         # validate only top N endpoints with x8

# ── Scoring ─────────────────────────────────────────────────────────────────
CONFIDENCE_HIGH           = 75
CONFIDENCE_MEDIUM         = 50

# ── Parameter → vulnerability class mapping ─────────────────────────────────
VULN_CLASS_MAP: dict[str, list[str]] = {
    "url":       ["ssrf", "open_redirect", "xss"],
    "uri":       ["ssrf", "open_redirect"],
    "redirect":  ["open_redirect"],
    "next":      ["open_redirect"],
    "return":    ["open_redirect"],
    "dest":      ["ssrf", "open_redirect"],
    "callback":  ["ssrf", "xss"],
    "webhook":   ["ssrf"],
    "id":        ["idor", "sqli"],
    "user_id":   ["idor", "sqli"],
    "account":   ["idor"],
    "file":      ["lfi", "rfi"],
    "path":      ["lfi", "path_traversal"],
    "template":  ["ssti", "lfi"],
    "q":         ["sqli", "xss"],
    "query":     ["sqli", "xss"],
    "search":    ["sqli", "xss"],
    "debug":     ["info_disclosure"],
    "test":      ["info_disclosure"],
    "admin":     ["privilege_escalation"],
    "role":      ["mass_assignment"],
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ParameterFinding:
    url: str
    method: str
    parameter: str
    oracle: str              # "arjun" | "x8" | "passive"
    confidence: int
    vuln_classes: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "method":         self.method,
            "parameter":      self.parameter,
            "oracle":         self.oracle,
            "confidence":     self.confidence,
            "vuln_classes":   self.vuln_classes,
            "evidence":       self.evidence,
        }


@dataclass
class EndpointResult:
    url: str
    method: str
    parameters: list[ParameterFinding] = field(default_factory=list)
    arjun_raw: dict = field(default_factory=dict)
    x8_raw: str = ""
    error: str = ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE MINING (ParamSpider)
# ═════════════════════════════════════════════════════════════════════════════

def _run_paramspider(domain: str, workdir: Path) -> list[str]:
    """
    Run ParamSpider against a domain. Returns URLs with FUZZ placeholders.
    Falls back to direct Wayback CDX query if ParamSpider is not installed.
    """
    urls: list[str] = []

    if shutil.which("paramspider"):
        log.info(f"    paramspider  {domain}")
        output_file = workdir / f"paramspider_{domain}.txt"
        cmd = [
            "paramspider",
            "-d", domain,
            "-p", PARAMSPIDER_PLACEHOLDER,
            "-o", str(output_file),
            "-q",  # quiet
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=PARAMSPIDER_TIMEOUT,
            )
            if output_file.exists():
                urls = [
                    line.strip()
                    for line in output_file.read_text().splitlines()
                    if line.strip() and "=" in line
                ]
        except subprocess.TimeoutExpired:
            log.warning(f"    paramspider timeout on {domain}")

    # Fallback: direct Wayback CDX query
    if not urls:
        log.info(f"    wayback fallback  {domain}")
        try:
            cdx_url = (
                f"http://web.archive.org/cdx/search/cdx?"
                f"url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
                f"&filter=original:.*\\?.*=.*"
            )
            resp = requests.get(cdx_url, timeout=60)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    url = line.strip()
                    if not url or "=" not in url:
                        continue
                    # Replace every value with FUZZ
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    if not params:
                        continue
                    fuzz_params = {k: [PARAMSPIDER_PLACEHOLDER] for k in params}
                    new_query = urllib.parse.urlencode(fuzz_params, doseq=True)
                    fuzz_url = urllib.parse.urlunparse(
                        parsed._replace(query=new_query)
                    )
                    urls.append(fuzz_url)
        except Exception as e:
            log.debug(f"    wayback fallback failed: {e}")

    log.info(f"    → {len(urls)} parameterized URL(s)")
    return urls


def _extract_endpoints_from_passive(urls: list[str], roots: list[str]) -> list[tuple[str, str]]:
    """
    Extract unique (url_without_query, method) endpoint bases from passive URLs.
    """
    endpoints: set[tuple[str, str]] = set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base = urllib.parse.urlunparse(
            parsed._replace(query="", fragment="")
        )
        # Only keep endpoints matching our roots
        host = parsed.hostname or ""
        if not any(host == r or host.endswith("." + r) for r in roots):
            continue
        endpoints.add((base.rstrip("/"), "GET"))
    return sorted(endpoints)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ACTIVE BRUTE-FORCING (Arjun)
# ═════════════════════════════════════════════════════════════════════════════

def _build_arjun_cmd(
    url: str,
    method: str,
    output_file: Path,
    *,
    rate_limit: int = ARJUN_RATE_LIMIT,
    stable: bool = ARJUN_STABLE_MODE,
    wordlist: Optional[Path] = None,
    headers: Optional[list[str]] = None,
    cookie: Optional[str] = None,
) -> list[str]:
    """
    Build the Arjun command line.

    Arjun flags (from manpages):
      -u URL            target
      -m METHOD         GET, POST, JSON, XML
      -oJ FILE          JSON output path
      --stable          stability over speed (1 thread, 6-12s delays)
      --ratelimit N     requests/second
      -w WORDLIST       custom wordlist
      -H HEADER         custom header
    """
    cmd = [
        "arjun",
        "-u", url,
        "-m", method,
        "-oJ", str(output_file),
        "--ratelimit", str(rate_limit),
    ]

    if stable:
        cmd.append("--stable")

    if wordlist and wordlist.exists():
        cmd.extend(["-w", str(wordlist)])

    if headers:
        for h in headers:
            cmd.extend(["-H", h])

    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    return cmd


def _run_arjun(
    url: str,
    method: str,
    workdir: Path,
    *,
    rate_limit: int = ARJUN_RATE_LIMIT,
    stable: bool = ARJUN_STABLE_MODE,
    wordlist: Optional[Path] = None,
    headers: Optional[list[str]] = None,
    cookie: Optional[str] = None,
) -> EndpointResult:
    """
    Run Arjun against one endpoint. Returns an EndpointResult with parsed parameters.
    """
    result = EndpointResult(url=url, method=method)

    if not shutil.which("arjun"):
        result.error = "arjun not installed"
        return result

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", url.replace("://", "_"))[:60]
    output_file = workdir / f"arjun_{method}_{tag}.json"

    cmd = _build_arjun_cmd(
        url, method, output_file,
        rate_limit=rate_limit,
        stable=stable,
        wordlist=wordlist,
        headers=headers,
        cookie=cookie,
    )
    log.info(f"      arjun  [{method}] {url}")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        result.error = "arjun timeout"
        return result
    except FileNotFoundError:
        result.error = "arjun binary vanished"
        return result

    # Arjun JSON output can be either a single object or line-delimited
    if not output_file.exists():
        result.error = f"arjun produced no output (stderr: {proc.stderr[:160]})"
        return result

    raw_text = output_file.read_text()
    arjun_data: dict = {}

    # Try single JSON object first
    try:
        arjun_data = json.loads(raw_text)
    except json.JSONDecodeError:
        # Try line-delimited
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    arjun_data.update(obj)
            except json.JSONDecodeError:
                continue

    result.arjun_raw = arjun_data

    # Arjun JSON shape: {"https://target.com/path": ["param1", "param2"]}
    for target_url, params in arjun_data.items():
        if not isinstance(params, list):
            continue
        for param in params:
            if not isinstance(param, str):
                continue
            finding = ParameterFinding(
                url=target_url,
                method=method,
                parameter=param,
                oracle="arjun",
                confidence=_score_arjun(param, target_url),
                vuln_classes=_classify_param(param),
                evidence=f"arjun detected '{param}' on {method} {target_url}",
            )
            result.parameters.append(finding)

    return result


def _score_arjun(param: str, url: str) -> int:
    """Score an Arjun finding based on parameter name and endpoint context."""
    score = 50
    p = param.lower()
    path = urllib.parse.urlparse(url).path.lower()

    # High-value parameter names
    high_value = ("url", "redirect", "next", "callback", "file", "path", "id", "admin", "debug")
    if any(h in p for h in high_value):
        score += 30

    # Sensitive endpoint context
    if any(w in path for w in ("admin", "internal", "api", "debug", "v1", "v2")):
        score += 15

    # Parameter length suggests something specific
    if len(p) > 10:
        score += 5

    return min(score, 100)


def _classify_param(param: str) -> list[str]:
    """Map a parameter name to likely vulnerability classes."""
    p = param.lower()
    classes: list[str] = []
    for key, vulns in VULN_CLASS_MAP.items():
        if key in p:
            classes.extend(vulns)
    return sorted(set(classes))


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — VALIDATION (x8)
# ═════════════════════════════════════════════════════════════════════════════

def _run_x8(
    url: str,
    method: str,
    workdir: Path,
    *,
    cookie: Optional[str] = None,
) -> str:
    """
    Run x8 against one endpoint. Returns raw stdout (x8 does not always
    produce a stable JSON file format; we parse stdout for parameters).
    """
    if not shutil.which("x8"):
        return ""

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", url.replace("://", "_"))[:60]
    log.info(f"      x8     [{method}] {url}")

    cmd = [
        "x8",
        "-u", url,
        "-X", method,
        "-w", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "--output-format", "json",
        "--timeout", "10",
    ]
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    # x8 wordlist fallback
    if not Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt").exists():
        cmd[cmd.index("-w") + 1] = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=X8_TIMEOUT,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning(f"      x8 timeout on {url}")
        return ""
    except FileNotFoundError:
        return ""


def _parse_x8_output(stdout: str, url: str, method: str) -> list[ParameterFinding]:
    """Parse x8 stdout for discovered parameters."""
    findings: list[ParameterFinding] = []

    # x8 stdout lines often look like: "[+] parameter_name"
    # or in JSON mode, structured objects
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON parse first
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                param = obj.get("parameter") or obj.get("name")
                if param:
                    findings.append(ParameterFinding(
                        url=url, method=method, parameter=str(param),
                        oracle="x8", confidence=80,
                        vuln_classes=_classify_param(str(param)),
                        evidence=f"x8 validated '{param}' on {method} {url}",
                    ))
                    continue
            except json.JSONDecodeError:
                pass

        # Fallback: extract from [+] lines
        match = re.match(r"\[\+\]\s+(\S+)", line)
        if match:
            param = match.group(1)
            findings.append(ParameterFinding(
                url=url, method=method, parameter=param,
                oracle="x8", confidence=80,
                vuln_classes=_classify_param(param),
                evidence=f"x8 validated '{param}' on {method} {url}",
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION & AGGREGATION
# ═════════════════════════════════════════════════════════════════════════════

def _dedupe_findings(findings: list[ParameterFinding]) -> list[ParameterFinding]:
    """Keep the highest-confidence finding per (url, method, parameter)."""
    best: dict[tuple, ParameterFinding] = {}
    for f in findings:
        key = (f.url.rstrip("/"), f.method, f.parameter.lower())
        existing = best.get(key)
        if not existing or f.confidence > existing.confidence:
            best[key] = f
    return list(best.values())


def _group_by_endpoint(findings: list[ParameterFinding]) -> dict[str, list[ParameterFinding]]:
    grouped: dict[str, list[ParameterFinding]] = {}
    for f in findings:
        key = f"{f.method} {f.url}"
        grouped.setdefault(key, []).append(f)
    return grouped


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_param_discovery(
    live_urls_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    rate_limit: int = ARJUN_RATE_LIMIT,
    stable: bool = ARJUN_STABLE_MODE,
    custom_wordlist: Optional[Path] = None,
    headers: Optional[list[str]] = None,
    cookie: Optional[str] = None,
    validate_with_x8: bool = True,
    max_endpoints: int = MAX_ENDPOINTS,
) -> Path:
    """
    Run parameter discovery against every endpoint in `live_urls_file`.

    Returns the path to `param_findings.json`.
    """
    start = time.monotonic()

    if not shutil.which("arjun"):
        raise RuntimeError(
            "arjun not installed. Run `python3 tools.py --only arjun` first."
        )

    # ── Inputs ──────────────────────────────────────────────────────────────
    live_urls = _load_urls(live_urls_file)
    roots = _load_roots(wildcard_file)

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "param_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(live_urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Roots  : {len(roots)} wildcard(s)")
    log.info(f"  Config : rate-limit={rate_limit}/s  stable={stable}  "
             f"x8-validation={validate_with_x8}")
    log.info("")

    # ── Phase 1: Passive mining ─────────────────────────────────────────────
    log.info("  Phase 1 — Passive parameter mining")
    passive_urls: list[str] = []
    for root in roots:
        passive_urls.extend(_run_paramspider(root, workdir))

    passive_urls = sorted(set(passive_urls))
    (outdir / "param_passive.txt").write_text(
        "\n".join(passive_urls) + ("\n" if passive_urls else "")
    )

    passive_endpoints = _extract_endpoints_from_passive(passive_urls, roots)
    log.info(f"  Passive endpoints: {len(passive_endpoints)}")

    # Build the active target list: live URLs + passive endpoints
    active_targets: list[tuple[str, str]] = []
    for url in live_urls:
        parsed = urllib.parse.urlparse(url)
        base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
        active_targets.append((base.rstrip("/"), "GET"))
        # Also test POST/JSON on API-looking endpoints
        if any(w in parsed.path.lower() for w in ("/api", "/v1", "/v2", "/graphql")):
            active_targets.append((base.rstrip("/"), "POST"))
            active_targets.append((base.rstrip("/"), "JSON"))
    active_targets.extend(passive_endpoints)

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    unique_targets: list[tuple[str, str]] = []
    for t in active_targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if len(unique_targets) > max_endpoints:
        log.warning(f"  Capping at {max_endpoints} endpoints (input had {len(unique_targets)})")
        unique_targets = unique_targets[:max_endpoints]

    log.info(f"  Active targets: {len(unique_targets)} (method, url) pair(s)")

    # ── Phase 2: Active brute-forcing (Arjun) ──────────────────────────────
    log.info("")
    log.info("  Phase 2 — Active parameter discovery (Arjun)")

    all_findings: list[ParameterFinding] = []
    endpoint_results: list[EndpointResult] = []

    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as pool:
        future_map = {}
        for url, method in unique_targets:
            fut = pool.submit(
                _run_arjun, url, method, workdir,
                rate_limit=rate_limit,
                stable=stable,
                wordlist=custom_wordlist,
                headers=headers,
                cookie=cookie,
            )
            future_map[fut] = (url, method)

        for fut in as_completed(future_map):
            url, method = future_map[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = EndpointResult(url=url, method=method, error=str(e))
            endpoint_results.append(result)
            all_findings.extend(result.parameters)
            if result.parameters:
                log.info(f"      → {len(result.parameters)} param(s) on [{method}] {url}")

    # ── Phase 3: x8 validation ─────────────────────────────────────────────
    if validate_with_x8 and shutil.which("x8"):
        log.info("")
        log.info("  Phase 3 — x8 validation on high-value endpoints")

        # Pick endpoints with the most findings or highest scores
        candidates = sorted(
            [r for r in endpoint_results if r.parameters],
            key=lambda r: -len(r.parameters),
        )[:X8_VALIDATE_TOP_N]

        for result in candidates:
            x8_stdout = _run_x8(result.url, result.method, workdir, cookie=cookie)
            if x8_stdout:
                result.x8_raw = x8_stdout
                x8_findings = _parse_x8_output(x8_stdout, result.url, result.method)
                all_findings.extend(x8_findings)
                if x8_findings:
                    log.info(f"      x8 confirmed {len(x8_findings)} param(s) on {result.url}")
    elif validate_with_x8:
        log.info("  Phase 3 — x8 not installed, skipping validation")

    # ── Deduplicate & group ────────────────────────────────────────────────
    deduped = _dedupe_findings(all_findings)
    grouped = _group_by_endpoint(deduped)

    # ── Write flat output for downstream modules ───────────────────────────
    flat_lines: list[str] = []
    for endpoint_key in sorted(grouped):
        method, url = endpoint_key.split(" ", 1)
        params = sorted({f.parameter for f in grouped[endpoint_key]})
        flat_lines.append(f"{method}\t{url}\t{','.join(params)}")

    (outdir / "params_by_endpoint.txt").write_text(
        "\n".join(flat_lines) + ("\n" if flat_lines else "")
    )

    # ── Build JSON report ──────────────────────────────────────────────────
    elapsed = time.monotonic() - start

    by_oracle: dict[str, int] = {"arjun": 0, "x8": 0, "passive": 0}
    by_vuln: dict[str, int] = {}
    by_method: dict[str, int] = {}

    for f in deduped:
        by_oracle[f.oracle] = by_oracle.get(f.oracle, 0) + 1
        by_method[f.method] = by_method.get(f.method, 0) + 1
        for v in f.vuln_classes:
            by_vuln[v] = by_vuln.get(v, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "rate_limit":       rate_limit,
            "stable":           stable,
            "x8_validation":    validate_with_x8,
            "max_endpoints":    max_endpoints,
            "authenticated":    cookie is not None or headers is not None,
        },
        "totals": {
            "endpoints_scanned":    len(unique_targets),
            "passive_urls":         len(passive_urls),
            "total_parameters":     len(deduped),
            "unique_endpoints":     len(grouped),
            "high_confidence":      sum(1 for f in deduped if f.confidence >= CONFIDENCE_HIGH),
            "medium_confidence":    sum(1 for f in deduped if CONFIDENCE_MEDIUM <= f.confidence < CONFIDENCE_HIGH),
        },
        "summary": {
            "by_oracle": by_oracle,
            "by_vuln_class": dict(sorted(by_vuln.items(), key=lambda kv: -kv[1])),
            "by_method": by_method,
        },
        "findings": [f.to_dict() for f in sorted(deduped, key=lambda f: (-f.confidence, f.url, f.parameter))],
    }

    json_path = outdir / "param_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup ─────────────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Console summary ────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<24} {len(deduped):>5} parameter(s)")
    log.info(f"    params_by_endpoint.txt   {len(grouped):>5} endpoint(s)")
    log.info(f"    param_passive.txt        {len(passive_urls):>5} passive URL(s)")

    log.info("")
    log.info(f"  Oracle : arjun={by_oracle['arjun']}  x8={by_oracle['x8']}  passive={by_oracle['passive']}")
    if by_vuln:
        top_vuln = list(by_vuln.items())[:6]
        log.info("  Likely vulns : " + " · ".join(f"{v}({n})" for v, n in top_vuln))

    high_conf = [f for f in deduped if f.confidence >= CONFIDENCE_HIGH]
    if high_conf:
        log.info("")
        log.info("  High-confidence findings:")
        for f in high_conf[:12]:
            classes = ",".join(f.vuln_classes) if f.vuln_classes else "-"
            log.info(f"    [{f.confidence:>3}] {f.method:<5} {f.url:<60} {f.parameter:<20} [{classes}]")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    urls: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split()[0]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        urls.add(url.rstrip("/"))
    return sorted(urls)


def _load_roots(wildcard_file: Optional[Path]) -> list[str]:
    if not wildcard_file or not wildcard_file.exists():
        return []
    return [
        line.strip().lower()
        for line in wildcard_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


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
        run_param_discovery(live, out, wildcards)
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
