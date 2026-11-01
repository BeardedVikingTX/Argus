#!/usr/bin/env python3
"""
recon_tools/param_discovery.py — Hidden Parameter Discovery
═══════════════════════════════════════════════════════════════════════════════

Parameter discovery stage for Argus. Finds parameters that the server accepts
but the UI never exposes — the hidden surface that every downstream injection
finder depends on.

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every arjun and x8 request.

Three phases:

  Phase 1 — Passive mining (zero target traffic)
      ParamSpider or direct Wayback CDX query.

  Phase 2 — Active brute-forcing (Arjun)
      ~26,000-name curated wordlist. Supports GET / POST / JSON / XML.

  Phase 3 — Validation (x8, optional)
      Line-by-line differential analysis on the highest-value endpoints.

Accuracy model:
  • Multi-oracle merging — one row per (url, method, param) with an `oracles`
    list. `id` found by arjun AND x8 outranks `id` found by arjun alone.
  • Already-in-URL detection — params already present in the URL query string
    are flagged and de-prioritized (they were never "hidden").
  • Expanded classification — ~80 parameter → vuln-class mappings
  • Context-aware scoring — param sensitivity × endpoint sensitivity ×
    oracle strength × multi-confirmation

Config integration (config.py):
  • MODULE_RATE_LIMITS["params"]   → arjun --ratelimit
  • ACTIVE_HEADERS + AUTH_HEADERS  → arjun -H, x8 -H
  • AUTH_COOKIES                   → Cookie header
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Outputs (into `outdir`):
  • param_findings.json        — full structured report
  • params_by_endpoint.txt     — METHOD url param1,param2,... (flat)
  • param_passive.txt          — Wayback URLs with FUZZ placeholder
  • param_candidates.txt       — merged candidate list (one param per line)

Remote DB (if scan_id is provided):
  • param_findings table       — one row per (scan_id, url, method, param)

Integration:
  main.py → run_one("params") → run_param_discovery(live_urls_file, outdir)
  main.py also syncs param_findings.json via _sync_stage_artifacts()
  Standalone: run_param_discovery(..., scan_id=42) → self-syncs
"""

from __future__ import annotations

import json
import logging
import re
import shutil
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


def _param_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("params", {})
    return {
        "rate_limit": entry.get("rate_limit", 3),
        "stable":     entry.get("stable", False),
        "threads":    entry.get("concurrency", 5),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _tool_header_args() -> list[str]:
    """Return ['Name: Value', ...] for arjun's -H and x8's -H."""
    return [f"{k}: {v}" for k, v in _target_headers().items()]


def _auth_cookie_header() -> Optional[str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return None
    cookies = getattr(CFG, "AUTH_COOKIES", {}) or {}
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS           = 5
DEFAULT_TIMEOUT           = 10
MAX_ENDPOINTS             = 500
ARJUN_RATE_LIMIT          = 3
ARJUN_STABLE_MODE         = False

PARAMSPIDER_TIMEOUT       = 300
PARAMSPIDER_PLACEHOLDER   = "FUZZ"

X8_TIMEOUT                = 180
X8_VALIDATE_TOP_N         = 20

CONFIDENCE_HIGH           = 75
CONFIDENCE_MEDIUM         = 50


# ═════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY CLASS MAPPING
# ═════════════════════════════════════════════════════════════════════════════

VULN_CLASS_MAP: dict[str, list[str]] = {
    # ── SSRF / open redirect ────────────────────────────────────────────────
    "url":           ["ssrf", "open_redirect", "xss"],
    "uri":           ["ssrf", "open_redirect"],
    "link":          ["open_redirect", "ssrf"],
    "href":          ["open_redirect", "ssrf"],
    "src":           ["ssrf", "open_redirect"],
    "dest":          ["ssrf", "open_redirect"],
    "destination":   ["ssrf", "open_redirect"],
    "target":        ["ssrf", "open_redirect"],
    "redirect":      ["open_redirect"],
    "redirect_uri":  ["open_redirect"],
    "redirect_url":  ["open_redirect"],
    "next":          ["open_redirect"],
    "return":        ["open_redirect"],
    "return_to":     ["open_redirect"],
    "return_url":    ["open_redirect"],
    "continue":      ["open_redirect"],
    "goto":          ["open_redirect"],
    "out":           ["open_redirect"],
    "callback":      ["ssrf", "xss", "open_redirect"],
    "callback_url":  ["ssrf", "xss"],
    "webhook":       ["ssrf"],
    "webhook_url":   ["ssrf"],
    "feed":          ["ssrf"],
    "host":          ["ssrf", "open_redirect"],
    "site":          ["ssrf", "open_redirect"],
    "domain":        ["ssrf"],
    "fetch":         ["ssrf"],
    "load":          ["ssrf", "lfi"],
    "proxy":         ["ssrf"],
    "request":       ["ssrf"],
    "req":           ["ssrf"],
    "open":          ["ssrf", "open_redirect"],

    # ── IDOR / SQLi ─────────────────────────────────────────────────────────
    "id":            ["idor", "sqli"],
    "user_id":       ["idor", "sqli"],
    "userid":        ["idor", "sqli"],
    "uid":           ["idor", "sqli"],
    "uuid":          ["idor", "sqli"],
    "guid":          ["idor"],
    "account":       ["idor"],
    "account_id":    ["idor"],
    "customer_id":   ["idor"],
    "order_id":      ["idor"],
    "invoice_id":    ["idor"],
    "doc_id":        ["idor"],
    "file_id":       ["idor"],
    "object_id":     ["idor"],
    "resource_id":   ["idor"],
    "group_id":      ["idor"],
    "tenant_id":     ["idor", "privilege_escalation"],
    "org_id":        ["idor", "privilege_escalation"],
    "role_id":       ["idor", "privilege_escalation"],
    "profile_id":    ["idor"],
    "number":        ["idor", "sqli"],
    "key":           ["idor"],
    "ref":           ["idor"],
    "ref_id":        ["idor"],

    # ── LFI / path traversal ────────────────────────────────────────────────
    "file":          ["lfi", "rfi", "path_traversal"],
    "filename":      ["lfi", "rfi"],
    "filepath":      ["lfi", "path_traversal"],
    "file_path":     ["lfi", "path_traversal"],
    "path":          ["lfi", "path_traversal"],
    "page":          ["lfi", "path_traversal", "open_redirect"],
    "template":      ["ssti", "lfi"],
    "view":          ["lfi", "path_traversal"],
    "include":       ["lfi"],
    "inc":           ["lfi"],
    "require":       ["lfi"],
    "load_file":     ["lfi"],
    "doc":           ["lfi"],
    "document":      ["lfi"],
    "folder":        ["lfi"],
    "dir":           ["lfi"],
    "download":      ["lfi"],

    # ── SQLi / XSS / search ─────────────────────────────────────────────────
    "q":             ["sqli", "xss"],
    "query":         ["sqli", "xss"],
    "search":        ["sqli", "xss"],
    "s":             ["sqli", "xss"],
    "keyword":       ["sqli", "xss"],
    "term":          ["sqli", "xss"],
    "filter":        ["sqli", "xss"],
    "sort":          ["sqli"],
    "order":         ["sqli"],
    "order_by":      ["sqli"],
    "sort_by":       ["sqli"],
    "column":        ["sqli"],
    "field":         ["sqli"],
    "table":         ["sqli"],
    "select":        ["sqli"],
    "where":         ["sqli"],
    "having":        ["sqli"],
    "limit":         ["sqli"],
    "offset":        ["sqli"],
    "rows":          ["sqli"],

    # ── Debug / info disclosure ─────────────────────────────────────────────
    "debug":         ["info_disclosure"],
    "test":          ["info_disclosure"],
    "dev":           ["info_disclosure"],
    "env":           ["info_disclosure"],
    "verbose":       ["info_disclosure"],
    "trace":         ["info_disclosure"],

    # ── Admin / privilege ───────────────────────────────────────────────────
    "admin":         ["privilege_escalation", "info_disclosure"],
    "is_admin":      ["privilege_escalation"],
    "superuser":     ["privilege_escalation"],
    "role":          ["mass_assignment", "privilege_escalation"],
    "permission":    ["privilege_escalation"],
    "access":        ["privilege_escalation"],
    "privilege":     ["privilege_escalation"],

    # ── SSTI ────────────────────────────────────────────────────────────────
    "tpl":           ["ssti"],
    "template_name": ["ssti"],
    "layout":        ["ssti"],
    "format":        ["ssti"],
    "subject":       ["ssti", "xss"],
    "body":          ["ssti", "xss"],
    "content":       ["ssti", "xss"],

    # ── Command injection ───────────────────────────────────────────────────
    "cmd":           ["command_injection"],
    "command":       ["command_injection"],
    "exec":          ["command_injection"],
    "execute":       ["command_injection"],
    "shell":         ["command_injection"],
    "run":           ["command_injection"],

    # ── Auth / token ────────────────────────────────────────────────────────
    "token":         ["auth_bypass"],
    "auth":          ["auth_bypass"],
    "api_key":       ["auth_bypass"],
    "apikey":        ["auth_bypass"],
    "password":      ["auth_bypass"],
    "passwd":        ["auth_bypass"],
    "pwd":           ["auth_bypass"],
    "secret":        ["auth_bypass"],
    "session":       ["auth_bypass"],
    "jwt":           ["auth_bypass"],
    "bearer":        ["auth_bypass"],
    "signature":     ["auth_bypass"],
    "otp":           ["auth_bypass"],
    "pin":           ["auth_bypass"],
    "code":          ["auth_bypass"],
}

HIGH_RISK_CLASSES = {
    "idor", "sqli", "ssrf", "command_injection", "lfi",
    "path_traversal", "rce",
}
MEDIUM_RISK_CLASSES = {
    "open_redirect", "xss", "ssti", "auth_bypass",
    "privilege_escalation", "rfi", "mass_assignment",
}


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ParameterFinding:
    url: str
    method: str
    parameter: str
    oracles: list[str] = field(default_factory=list)
    confidence: int = 0
    vuln_classes: list[str] = field(default_factory=list)
    already_in_url: bool = False
    evidence: list[str] = field(default_factory=list)
    auth_enabled: bool = False
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "method":         self.method,
            "parameter":      self.parameter,
            "oracles":        self.oracles,
            "confidence":     self.confidence,
            "vuln_classes":   self.vuln_classes,
            "already_in_url": self.already_in_url,
            "evidence":       self.evidence,
            "auth_enabled":   self.auth_enabled,
            "first_seen":     self.first_seen,
        }


@dataclass
class EndpointResult:
    url: str
    method: str
    findings: list[ParameterFinding] = field(default_factory=list)
    x8_raw: str = ""
    error: str = ""


# ═════════════════════════════════════════════════════════════════════════════
#  PARAMETER CLASSIFICATION & SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _classify_param(param: str) -> list[str]:
    """Map a parameter name to likely vulnerability classes."""
    p = param.lower()
    classes: set[str] = set()
    for key, vulns in VULN_CLASS_MAP.items():
        if key == p or key in p:
            classes.update(vulns)
    return sorted(classes)


def _score_confidence(
    param: str, url: str, method: str, oracles: list[str],
    already_in_url: bool,
) -> int:
    """
    Score confidence 0-100.

    Factors:
      • Vulnerability class (high-risk > medium-risk > unknown)
      • Oracle strength (x8 line-diff > arjun hash-diff > passive)
      • Multi-oracle confirmation (+15)
      • Endpoint sensitivity (admin/api/v1/v2)
      • Method (POST/JSON > GET for state-changing endpoints)
      • already_in_url penalty (-20) — not really "hidden"
    """
    score = 40
    classes = _classify_param(param)

    if any(c in HIGH_RISK_CLASSES for c in classes):
        score += 25
    elif any(c in MEDIUM_RISK_CLASSES for c in classes):
        score += 15

    # Oracle strength
    if "x8" in oracles:
        score += 20      # line-by-line diff — strongest oracle
    if "arjun" in oracles:
        score += 5       # hash-based diff
    if "passive" in oracles:
        score -= 10      # historical only — weakest

    # Multi-oracle confirmation
    if len(oracles) > 1:
        score += 15

    # Endpoint context
    path = urllib.parse.urlparse(url).path.lower()
    if any(w in path for w in ("admin", "internal", "api", "debug", "v1", "v2", "graphql")):
        score += 15

    # Method
    if method.upper() in ("POST", "PUT", "PATCH", "JSON", "XML"):
        score += 5

    # Not actually hidden
    if already_in_url:
        score -= 20

    return max(0, min(100, score))


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING
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


def _strip_query(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(parsed._replace(query="", fragment="")).rstrip("/")


def _extract_query_params(url: str) -> set[str]:
    return set(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE MINING
# ═════════════════════════════════════════════════════════════════════════════

def _run_paramspider(domain: str, workdir: Path) -> list[str]:
    urls: list[str] = []

    if shutil.which("paramspider"):
        log.info(f"    paramspider  {domain}")
        output_file = workdir / f"paramspider_{domain}.txt"
        cmd = [
            "paramspider", "-d", domain,
            "-p", PARAMSPIDER_PLACEHOLDER,
            "-o", str(output_file), "-q",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=PARAMSPIDER_TIMEOUT)
            if output_file.exists():
                urls = [
                    line.strip()
                    for line in output_file.read_text().splitlines()
                    if line.strip() and "=" in line
                ]
        except subprocess.TimeoutExpired:
            log.warning(f"    paramspider timeout on {domain}")

    if not urls:
        log.info(f"    wayback fallback  {domain}")
        try:
            cdx_url = (
                f"http://web.archive.org/cdx/search/cdx?"
                f"url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
                f"&filter=original:.*\\?.*=.*"
            )
            headers = _target_headers() or None
            resp = requests.get(cdx_url, timeout=60, headers=headers)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    url = line.strip()
                    if not url or "=" not in url:
                        continue
                    parsed = urllib.parse.urlparse(url)
                    params = urllib.parse.parse_qs(parsed.query)
                    if not params:
                        continue
                    fuzz_params = {k: [PARAMSPIDER_PLACEHOLDER] for k in params}
                    new_query = urllib.parse.urlencode(fuzz_params, doseq=True)
                    fuzz_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    urls.append(fuzz_url)
        except Exception as e:
            log.debug(f"    wayback fallback failed: {e}")

    log.info(f"    → {len(urls)} parameterized URL(s)")
    return urls


def _passive_params_from_urls(urls: list[str]) -> dict[tuple[str, str], set[str]]:
    """
    Return {(base_url, 'GET'): {param1, param2, ...}} from passive URLs.
    """
    result: dict[tuple[str, str], set[str]] = {}
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base = _strip_query(url)
        params = set(urllib.parse.parse_qs(parsed.query).keys())
        if not params:
            continue
        result.setdefault((base, "GET"), set()).update(params)
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ARJUN
# ═════════════════════════════════════════════════════════════════════════════

def _run_arjun(
    url: str,
    method: str,
    workdir: Path,
    *,
    rate_limit: int,
    stable: bool,
    wordlist: Optional[Path],
    header_args: list[str],
    cookie_header: Optional[str],
) -> EndpointResult:
    result = EndpointResult(url=url, method=method)

    if not shutil.which("arjun"):
        result.error = "arjun not installed"
        return result

    tag = re.sub(r"[^a-zA-Z0-9]+", "_", url.replace("://", "_"))[:60]
    output_file = workdir / f"arjun_{method}_{tag}.json"

    cmd = [
        "arjun",
        "-u", url,
        "-m", method,
        "-oJ", str(output_file),
        "--ratelimit", str(rate_limit),
        "--quiet",
    ]
    if stable:
        cmd.append("--stable")
    if wordlist and wordlist.exists():
        cmd.extend(["-w", str(wordlist)])
    for h in header_args:
        cmd.extend(["-H", h])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    log.info(f"      arjun  [{method}] {url}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        result.error = "arjun timeout"
        return result
    except FileNotFoundError:
        result.error = "arjun binary vanished"
        return result

    if not output_file.exists():
        result.error = f"arjun produced no output (stderr: {proc.stderr[:160]})"
        return result

    raw_text = output_file.read_text()
    arjun_data: dict = {}
    try:
        arjun_data = json.loads(raw_text)
    except json.JSONDecodeError:
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

    # Arjun JSON shape: {"https://target.com/path": ["param1", "param2"]}
    for target_url, params in arjun_data.items():
        if not isinstance(params, list):
            continue
        for param in params:
            if not isinstance(param, str):
                continue
            result.findings.append(ParameterFinding(
                url=target_url,
                method=method,
                parameter=param,
                oracles=["arjun"],
                evidence=[f"arjun detected '{param}' on {method} {target_url}"],
            ))

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — X8 VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

def _run_x8(
    url: str,
    method: str,
    workdir: Path,
    *,
    header_args: list[str],
    cookie_header: Optional[str],
) -> str:
    if not shutil.which("x8"):
        return ""

    log.info(f"      x8     [{method}] {url}")

    # Prefer the burp-parameter-names list, fall back to raft-medium-words
    wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if not Path(wordlist).exists():
        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    if not Path(wordlist).exists():
        log.debug(f"      x8     no wordlist found — skipping")
        return ""

    cmd = [
        "x8",
        "-u", url,
        "-X", method,
        "-w", wordlist,
        "--output-format", "json",
        "--timeout", "10",
    ]
    for h in header_args:
        cmd.extend(["-H", h])
    if cookie_header:
        cmd.extend(["-H", f"Cookie: {cookie_header}"])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=X8_TIMEOUT)
        return proc.stdout
    except subprocess.TimeoutExpired:
        log.warning(f"      x8 timeout on {url}")
        return ""
    except FileNotFoundError:
        return ""


def _parse_x8_output(stdout: str, url: str, method: str) -> list[ParameterFinding]:
    findings: list[ParameterFinding] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # JSON line
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                param = obj.get("parameter") or obj.get("name")
                if param and param not in seen:
                    seen.add(str(param))
                    findings.append(ParameterFinding(
                        url=url, method=method,
                        parameter=str(param),
                        oracles=["x8"],
                        evidence=[f"x8 confirmed '{param}' on {method} {url}"],
                    ))
                    continue
            except json.JSONDecodeError:
                pass

        # [+] param lines
        m = re.match(r"\[\+\]\s+(\S+)", line)
        if m:
            param = m.group(1)
            if param in seen:
                continue
            seen.add(param)
            findings.append(ParameterFinding(
                url=url, method=method,
                parameter=param,
                oracles=["x8"],
                evidence=[f"x8 confirmed '{param}' on {method} {url}"],
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  MERGE & DEDUPE
# ═════════════════════════════════════════════════════════════════════════════

def _merge_findings(all_findings: list[ParameterFinding]) -> list[ParameterFinding]:
    """
    Merge findings by (url, method, parameter). Combines oracles, evidence,
    and recomputes confidence from the merged set.
    """
    merged: dict[tuple[str, str, str], ParameterFinding] = {}
    for f in all_findings:
        key = (f.url.rstrip("/"), f.method.upper(), f.parameter.lower())
        existing = merged.get(key)
        if not existing:
            merged[key] = ParameterFinding(
                url=f.url,
                method=f.method,
                parameter=f.parameter,
                oracles=list(f.oracles),
                evidence=list(f.evidence),
            )
            continue
        for o in f.oracles:
            if o not in existing.oracles:
                existing.oracles.append(o)
        for e in f.evidence:
            if e not in existing.evidence:
                existing.evidence.append(e)

    return list(merged.values())


def _finalize_findings(
    findings: list[ParameterFinding],
    pre_existing_params: dict[tuple[str, str], set[str]],
    auth_on: bool,
) -> list[ParameterFinding]:
    """
    Post-merge: score confidence, classify, and flag already_in_url.
    """
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        key = (f.url.rstrip("/"), f.method.upper())
        pre = pre_existing_params.get(key, set())
        f.already_in_url = f.parameter.lower() in {p.lower() for p in pre}
        f.vuln_classes = _classify_param(f.parameter)
        f.confidence = _score_confidence(
            f.parameter, f.url, f.method, f.oracles, f.already_in_url,
        )
        f.auth_enabled = auth_on
        f.first_seen = now
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[ParameterFinding]) -> None:
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
        result = DB.upsert_param_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} parameter(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_param_discovery(
    live_urls_file: Path,
    outdir: Path,
    wildcard_file: Optional[Path] = None,
    *,
    rate_limit: Optional[int] = None,
    stable: Optional[bool] = None,
    custom_wordlist: Optional[Path] = None,
    headers: Optional[dict] = None,
    cookie: Optional[str] = None,
    validate_with_x8: bool = True,
    max_endpoints: int = MAX_ENDPOINTS,
    scan_id: Optional[int] = None,
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

    # ── Effective settings ──────────────────────────────────────────────────
    settings = _param_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_stable = stable if stable is not None else settings["stable"]
    eff_threads = settings["threads"]

    # ── Headers + auth ──────────────────────────────────────────────────────
    header_args = _tool_header_args()
    if headers:
        for k, v in headers.items():
            h = f"{k}: {v}"
            if h not in header_args:
                header_args.append(h)
    cookie_header = _auth_cookie_header() or cookie
    auth_on = bool(header_args or cookie_header)

    # ── Inputs ──────────────────────────────────────────────────────────────
    live_urls = _load_urls(live_urls_file)
    roots = _load_roots(wildcard_file)

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "param_work"
    workdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(live_urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Roots  : {len(roots)} wildcard(s)")
    log.info(f"  Config : rate_limit={eff_rate}/s  stable={eff_stable}  "
             f"threads={eff_threads}  x8-validation={validate_with_x8}")
    log.info(f"           source: MODULE_RATE_LIMITS['params']")
    if auth_on:
        log.info(f"  Auth   : ENABLED ({len(header_args)} header(s)"
                 f"{', cookie' if cookie_header else ''})")
    else:
        log.info(f"  Auth   : disabled")
    log.info("")

    # ── Track pre-existing params ───────────────────────────────────────────
    # For each endpoint+method, remember what params were already in the URL.
    # These are NOT hidden — they were already in the URL. Flag them so the
    # triager can skip them or treat them as "known" parameters.
    pre_existing: dict[tuple[str, str], set[str]] = {}
    for url in live_urls:
        base = _strip_query(url)
        existing = _extract_query_params(url)
        if existing:
            pre_existing.setdefault((base, "GET"), set()).update(existing)

    # ── Phase 1: Passive ────────────────────────────────────────────────────
    log.info("  Phase 1 — Passive parameter mining")
    passive_urls: list[str] = []
    for root in roots:
        passive_urls.extend(_run_paramspider(root, workdir))

    passive_urls = sorted(set(passive_urls))
    (outdir / "param_passive.txt").write_text(
        "\n".join(passive_urls) + ("\n" if passive_urls else "")
    )

    passive_map = _passive_params_from_urls(passive_urls)
    log.info(f"  Passive endpoints: {len(passive_map)}")

    # ── Build active targets ────────────────────────────────────────────────
    active_targets: list[tuple[str, str]] = []
    for url in live_urls:
        base = _strip_query(url)
        active_targets.append((base, "GET"))
        # Also test POST/JSON on API-looking endpoints
        parsed = urllib.parse.urlparse(base)
        if any(w in parsed.path.lower() for w in ("/api", "/v1", "/v2", "/graphql")):
            active_targets.append((base, "POST"))
            active_targets.append((base, "JSON"))
    for (base_url, method) in passive_map.keys():
        active_targets.append((base_url, method))

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

    # ── Phase 2: Arjun ──────────────────────────────────────────────────────
    log.info("")
    log.info("  Phase 2 — Active parameter discovery (Arjun)")
    if eff_stable:
        log.info("           (stable mode — expect slow scans)")

    all_findings: list[ParameterFinding] = []
    endpoint_results: list[EndpointResult] = []

    with ThreadPoolExecutor(max_workers=eff_threads) as pool:
        future_map = {}
        for url, method in unique_targets:
            fut = pool.submit(
                _run_arjun, url, method, workdir,
                rate_limit=eff_rate,
                stable=eff_stable,
                wordlist=custom_wordlist,
                header_args=header_args,
                cookie_header=cookie_header,
            )
            future_map[fut] = (url, method)

        for fut in as_completed(future_map):
            url, method = future_map[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = EndpointResult(url=url, method=method, error=str(e))
            endpoint_results.append(result)
            all_findings.extend(result.findings)
            if result.findings:
                log.info(f"      → {len(result.findings)} param(s) on [{method}] {url}")

    # ── Phase 3: x8 validation ──────────────────────────────────────────────
    if validate_with_x8 and shutil.which("x8"):
        log.info("")
        log.info("  Phase 3 — x8 validation on high-value endpoints")

        candidates = sorted(
            [r for r in endpoint_results if r.findings],
            key=lambda r: -len(r.findings),
        )[:X8_VALIDATE_TOP_N]

        for result in candidates:
            stdout = _run_x8(
                result.url, result.method, workdir,
                header_args=header_args,
                cookie_header=cookie_header,
            )
            if stdout:
                result.x8_raw = stdout
                x8_findings = _parse_x8_output(stdout, result.url, result.method)
                all_findings.extend(x8_findings)
                if x8_findings:
                    log.info(f"      x8 confirmed {len(x8_findings)} param(s) on {result.url}")
    elif validate_with_x8:
        log.info("  Phase 3 — x8 not installed, skipping validation")

    # ── Phase 1 passive findings (from the passive URL map) ─────────────────
    for (base_url, method), params in passive_map.items():
        for param in params:
            all_findings.append(ParameterFinding(
                url=base_url,
                method=method,
                parameter=param,
                oracles=["passive"],
                evidence=[f"passive (wayback) found '{param}' on {base_url}"],
            ))

    # ── Merge, score, finalize ──────────────────────────────────────────────
    merged = _merge_findings(all_findings)
    finalized = _finalize_findings(merged, pre_existing, auth_on)

    SEV_ORDER = {"id": 0}

    def _sort_key(f: ParameterFinding) -> tuple:
        return (-f.confidence, -len(f.oracles), f.url, f.parameter)

    finalized.sort(key=_sort_key)

    # ── Flat outputs ────────────────────────────────────────────────────────
    by_endpoint: dict[str, list[ParameterFinding]] = {}
    for f in finalized:
        key = f"{f.method} {f.url}"
        by_endpoint.setdefault(key, []).append(f)

    flat_lines: list[str] = []
    for endpoint_key in sorted(by_endpoint):
        method, url = endpoint_key.split(" ", 1)
        params = sorted({f.parameter for f in by_endpoint[endpoint_key]})
        flat_lines.append(f"{method}\t{url}\t{','.join(params)}")

    (outdir / "params_by_endpoint.txt").write_text(
        "\n".join(flat_lines) + ("\n" if flat_lines else "")
    )

    # Merged candidate list (one param per line, no dedupe by endpoint)
    all_params: set[str] = {f.parameter for f in finalized}
    (outdir / "param_candidates.txt").write_text(
        "\n".join(sorted(all_params)) + ("\n" if all_params else "")
    )

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_oracle: dict[str, int] = {"arjun": 0, "x8": 0, "passive": 0}
    by_vuln: dict[str, int] = {}
    by_method: dict[str, int] = {}
    hidden_count = 0
    multi_oracle_count = 0

    for f in finalized:
        for o in f.oracles:
            by_oracle[o] = by_oracle.get(o, 0) + 1
        by_method[f.method] = by_method.get(f.method, 0) + 1
        for v in f.vuln_classes:
            by_vuln[v] = by_vuln.get(v, 0) + 1
        if not f.already_in_url:
            hidden_count += 1
        if len(f.oracles) > 1:
            multi_oracle_count += 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":       eff_rate,
            "stable":           eff_stable,
            "threads":          eff_threads,
            "x8_validation":    validate_with_x8,
            "max_endpoints":    max_endpoints,
            "headers_count":    len(header_args),
            "cookie_set":       bool(cookie_header),
        },
        "totals": {
            "endpoints_scanned":    len(unique_targets),
            "passive_urls":         len(passive_urls),
            "total_parameters":     len(finalized),
            "unique_endpoints":     len(by_endpoint),
            "hidden_parameters":    hidden_count,
            "multi_oracle":         multi_oracle_count,
            "high_confidence":      sum(1 for f in finalized if f.confidence >= CONFIDENCE_HIGH),
            "medium_confidence":    sum(1 for f in finalized if CONFIDENCE_MEDIUM <= f.confidence < CONFIDENCE_HIGH),
        },
        "summary": {
            "by_oracle":     by_oracle,
            "by_vuln_class": dict(sorted(by_vuln.items(), key=lambda kv: -kv[1])),
            "by_method":     by_method,
        },
        "findings": [f.to_dict() for f in finalized],
    }

    json_path = outdir / "param_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Cleanup ─────────────────────────────────────────────────────────────
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, finalized)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(finalized):>5} parameter(s)")
    log.info(f"    params_by_endpoint.txt       {len(by_endpoint):>5} endpoint(s)")
    log.info(f"    param_passive.txt            {len(passive_urls):>5} passive URL(s)")
    log.info(f"    param_candidates.txt         {len(all_params):>5} unique name(s)")

    log.info("")
    log.info(f"  Oracle  : arjun={by_oracle['arjun']}  "
             f"x8={by_oracle['x8']}  passive={by_oracle['passive']}")
    log.info(f"  Hidden  : {hidden_count}/{len(finalized)} not in URL query")
    log.info(f"  Multi   : {multi_oracle_count} confirmed by 2+ oracles")

    if by_vuln:
        top_vuln = list(by_vuln.items())[:6]
        log.info("  Likely  : " + " · ".join(f"{v}({n})" for v, n in top_vuln))

    high_conf = [f for f in finalized if f.confidence >= CONFIDENCE_HIGH]
    if high_conf:
        log.info("")
        log.info("  High-confidence findings:")
        for f in high_conf[:15]:
            classes = ",".join(f.vuln_classes) if f.vuln_classes else "-"
            oracles = ",".join(f.oracles)
            tag = " (known)" if f.already_in_url else ""
            log.info(f"    [{f.confidence:>3}] {f.method:<5} {f.url:<50} "
                     f"{f.parameter:<20} [{classes}] ({oracles}){tag}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus parameter discovery (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--wildcard-file", type=Path, default=base / "wildcard.txt")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--stable", action="store_true")
    parser.add_argument("--no-x8", action="store_true")
    parser.add_argument("--max-endpoints", type=int, default=MAX_ENDPOINTS)
    args = parser.parse_args()

    try:
        run_param_discovery(
            args.input, args.output,
            wildcard_file=args.wildcard_file,
            rate_limit=args.rate_limit,
            stable=args.stable if args.stable else None,
            validate_with_x8=not args.no_x8,
            max_endpoints=args.max_endpoints,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
