#!/usr/bin/env python3
"""
auditing_tools/open_redirect_finder.py — Open Redirect Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive open redirect detection for Argus.

Open redirect alone is Low/Medium on most programs — it becomes Critical when
chained to OAuth token theft (redirect_uri bypass → ATO), SSRF escalation
(server-side fetch follows the redirect), or phishing under a trusted domain.

Four-phase strategy:

  Phase 1 — Surface discovery
      Extract redirect-bearing parameters from URLs. Covers the full parameter
      taxonomy: explicit redirect, return URLs, navigation, URL params,
      destination, callback, and OAuth/SSO-specific fields.

  Phase 2 — Server-side redirect testing
      Send the payload matrix through each redirect parameter. Confirm via
      3xx status + Location header pointing to the external test domain.
      Covers protocol-relative, backslash, @-confusion, subdomain, fragment,
      encoding, null-byte, and parser-differential bypasses.

  Phase 3 — Client-side redirect detection
      Detect meta-refresh (<meta http-equiv="refresh">) and DOM-based sinks
      (window.location, document.location, location.href) that reflect the
      redirect payload in the response body or JavaScript.

  Phase 4 — Context-aware escalation scoring
      Weight findings by their real-world impact:
        • OAuth redirect_uri / returnTo / RelayState → CRITICAL (ATO chain)
        • Login next / return_to → HIGH (phishing chain)
        • Generic url / redirect → MEDIUM
        • Low-context params → LOW

Uses a safe confirmation domain (example.com) by default — never a live
attacker-controlled host unless explicitly configured.

Outputs (into `outdir`):
  • open_redirect_findings.json     — full structured report
  • open_redirect_candidates.txt    — flat list for triage
  • open_redirect_confirmed.txt     — confirmed findings only
  • open_redirect_oauth.txt         — OAuth/SSO-specific findings

Integration:
  main.py → run_one("redirect") → run_open_redirect_audit(urls_file, outdir)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.open_redirect")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-Redirect-Auditor/1.0"

# Safe confirmation domain — example.com is a public placeholder.
# Replace with your own controlled domain or Burp Collaborator for
# production use, but NEVER use a live third-party site as a test target.
CONFIRMATION_DOMAIN  = "example.com"
CONFIRMATION_URL     = f"https://{CONFIRMATION_DOMAIN}"

# Maximum URLs to test (safety cap)
MAX_URLS             = 2000

# Severity weights for context-aware scoring
CONTEXT_WEIGHTS = {
    # OAuth / SSO — highest impact (code/token theft → ATO)
    "redirect_uri":      40,
    "returnTo":          35,
    "RelayState":        35,
    "return_to":         30,
    "return":            25,
    # Login / auth — phishing chain
    "next":              25,
    "return_url":        25,
    "continue":          20,
    "checkout_url":      20,
    # Generic redirect — standard phishing
    "redirect":          15,
    "redirect_url":      15,
    "redirect_to":       15,
    "url":               15,
    "redir":             15,
    # Lower-context
    "dest":              10,
    "destination":       10,
    "go":                10,
    "target":            10,
    "to":                10,
    "forward":           10,
    "out":               10,
    "view":              10,
    "link":              10,
}

# Redirect parameter names (comprehensive)
REDIRECT_PARAMS = set(CONTEXT_WEIGHTS.keys()) | {
    "back", "backto", "backurl", "callback", "callback_url",
    "cancel_url", "success_url", "logout_redirect", "logout",
    "goto", "jump", "jump_url", "rurl", "service",
    "image_url", "file_url", "pic", "origin", "originUrl",
    "forward_url", "sp_url", "action", "action_url",
    "login", "logout", "ext", "clickurl", "click",
}

# ── Payload matrix ──────────────────────────────────────────────────────────
# Each entry: (label, payload, confidence_boost)
# confidence_boost is added to the base confidence when this payload succeeds.
PAYLOAD_MATRIX: list[tuple[str, str, int]] = [
    # Direct external
    ("direct_https",       f"https://{CONFIRMATION_DOMAIN}", 30),
    ("direct_http",        f"http://{CONFIRMATION_DOMAIN}", 25),
    # Protocol-relative
    ("protocol_relative",  f"//{CONFIRMATION_DOMAIN}", 35),
    ("protocol_relative_backslash", f"\\\\{CONFIRMATION_DOMAIN}", 30),
    ("protocol_relative_slash_backslash", f"/\\{CONFIRMATION_DOMAIN}", 30),
    # @-confusion
    ("at_confusion",       f"https://target.com@{CONFIRMATION_DOMAIN}", 30),
    # Subdomain trick
    ("subdomain_suffix",   f"https://target.com.{CONFIRMATION_DOMAIN}", 25),
    # Fragment
    ("fragment",           f"https://{CONFIRMATION_DOMAIN}#.target.com", 20),
    # Path prefix
    ("target_in_path",     f"https://{CONFIRMATION_DOMAIN}/target.com", 20),
    # Encoding
    ("url_encoded",        f"https://%65%76%69%6C%2E%63%6F%6D", 25),
    ("double_encoded",     f"https://{CONFIRMATION_DOMAIN}%2f..%2f", 20),
    # Null byte
    ("null_byte",          f"{CONFIRMATION_DOMAIN}%00target.com", 25),
    # Whitespace
    ("whitespace_tab",     f"{CONFIRMATION_DOMAIN}%09", 20),
    ("whitespace_space",   f"%20{CONFIRMATION_DOMAIN}", 20),
    # JavaScript / data URI (XSS pivot)
    ("javascript_uri",     "javascript:alert(document.domain)", 25),
    ("data_uri",           "data:text/html,<script>alert(document.domain)</script>", 20),
    # CRLF injection
    ("crlf_bypass",        f"java%0d%0ascript%0d%0a:alert(1)", 20),
    # Parser differential
    ("parser_bracket",     f"https://trusted.example[@attacker.example", 20),
    ("parser_encoded_bracket", f"https://trusted.example%5B@attacker.example", 20),
]

# ── Client-side sink patterns ───────────────────────────────────────────────
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?[^>]*url\s*=\s*([^"\'>\s]+)',
    re.I,
)

DOM_SINK_PATTERNS = [
    re.compile(r'window\.location(?:\.href)?\s*=\s*["\']?([^"\';]+)', re.I),
    re.compile(r'document\.location(?:\.href)?\s*=\s*["\']?([^"\';]+)', re.I),
    re.compile(r'location\.replace\s*\(\s*["\']?([^"\';]+)', re.I),
    re.compile(r'location\.assign\s*\(\s*["\']?([^"\';]+)', re.I),
    re.compile(r'window\.open\s*\(\s*["\']?([^"\';]+)', re.I),
]

# ── OAuth/SSO endpoint patterns ─────────────────────────────────────────────
OAUTH_ENDPOINT_RE = re.compile(
    r"/(oauth|authorize|auth|sso|saml|openid|connect|login|signin)",
    re.I,
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RedirectSurface:
    url: str
    param_name: str
    param_value: str
    location: str = "query"      # "query" | "path" | "fragment"
    is_oauth: bool = False

    def to_dict(self) -> dict:
        return {
            "url":        self.url,
            "param_name": self.param_name,
            "param_value": self.param_value,
            "location":   self.location,
            "is_oauth":   self.is_oauth,
        }


@dataclass
class OpenRedirectFinding:
    target: str
    param_name: str
    vector: str                  # "server_side" | "meta_refresh" | "dom_sink"
    severity: str = "MEDIUM"
    confidence: int = 50
    payload: str = ""
    payload_label: str = ""
    evidence: str = ""
    redirect_location: str = ""
    http_status: int = 0
    is_oauth: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":            self.target,
            "param_name":        self.param_name,
            "vector":            self.vector,
            "severity":          self.severity,
            "confidence":        self.confidence,
            "payload":           self.payload,
            "payload_label":     self.payload_label,
            "evidence":          self.evidence[:500],
            "redirect_location": self.redirect_location[:300],
            "http_status":       self.http_status,
            "is_oauth":          self.is_oauth,
            "details":           self.details,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        return []
    urls: list[str] = []
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
            urls.append(token)
    return urls


def _safe_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=False,   # critical: we want the raw 3xx
            verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _build_test_url(original_url: str, param: str, payload: str) -> str:
    """Replace a parameter's value with the payload in the URL."""
    parsed = urllib.parse.urlparse(original_url)
    params = urllib.parse.parse_qsl(parsed.query)
    new_params = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))


def _is_external_redirect(location: str, target_host: str) -> bool:
    """
    Check whether a Location header points to an external host.

    Handles protocol-relative, backslash, and encoded variants that a
    naive startswith() check would miss.
    """
    if not location:
        return False
    loc = location.strip()
    # Normalize backslashes to forward slashes
    loc_norm = loc.replace("\\", "/")
    # Protocol-relative
    if loc_norm.startswith("//"):
        parsed = urllib.parse.urlparse("https:" + loc_norm)
        return (parsed.hostname or "") != target_host
    # Absolute
    if loc_norm.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(loc_norm)
        return (parsed.hostname or "") != target_host
    # Relative — not an external redirect
    return False


def _contains_payload(body: str, payload: str) -> bool:
    """Check whether a payload appears (raw or URL-decoded) in the body."""
    if not body or not payload:
        return False
    if payload in body:
        return True
    decoded = urllib.parse.unquote(payload)
    return decoded in body


def _body_snippet(resp: requests.Response, max_len: int = 500) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


def _context_score(param: str) -> int:
    """Return the context weight for a parameter name."""
    return CONTEXT_WEIGHTS.get(param, 5)


def _is_oauth_url(url: str) -> bool:
    return bool(OAUTH_ENDPOINT_RE.search(url))


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def discover_surfaces(urls: list[str]) -> list[RedirectSurface]:
    """
    Extract every redirect-bearing parameter from every URL.

    Covers:
      • Query parameters matching the redirect taxonomy
      • Path-based redirect patterns (/redirect?url=, /out?url=, etc.)
      • OAuth/SSO endpoints with redirect_uri, returnTo, RelayState
    """
    surfaces: list[RedirectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        is_oauth = _is_oauth_url(url)

        for pname, pvals in params.items():
            pname_lower = pname.lower()
            # Case-insensitive match against the redirect taxonomy
            matched_name = None
            for known in REDIRECT_PARAMS:
                if pname_lower == known.lower():
                    matched_name = known
                    break
            if not matched_name:
                continue

            pval = pvals[0] if pvals else ""
            key = (url, pname)
            if key in seen:
                continue
            seen.add(key)

            surfaces.append(RedirectSurface(
                url=url,
                param_name=pname,
                param_value=pval,
                location="query",
                is_oauth=is_oauth,
            ))

        # Path-based redirect patterns: /redirect?url=, /out?url=, /go?url=
        path = parsed.path.lower()
        if any(seg in path for seg in ("/redirect", "/out", "/go", "/redir", "/forward")):
            if not params:
                # Try a common parameter name
                for guess in ("url", "next", "to", "target"):
                    surfaces.append(RedirectSurface(
                        url=url,
                        param_name=guess,
                        param_value="",
                        location="path",
                        is_oauth=is_oauth,
                    ))

    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — SERVER-SIDE REDIRECT TESTING
# ═════════════════════════════════════════════════════════════════════════════

def test_server_side(
    session: requests.Session,
    surface: RedirectSurface,
    headers: Optional[dict] = None,
) -> list[OpenRedirectFinding]:
    """
    Send each payload through the redirect parameter and check for a 3xx
    with a Location header pointing to the external confirmation domain.
    """
    findings: list[OpenRedirectFinding] = []
    target_host = urllib.parse.urlparse(surface.url).hostname or ""

    for label, payload, boost in PAYLOAD_MATRIX:
        test_url = _build_test_url(surface.url, surface.param_name, payload)
        resp = _safe_request(session, "GET", test_url, headers)
        if not resp:
            continue

        # Only 3xx responses with a Location header can be server-side redirects
        if not (300 <= resp.status_code < 400):
            continue

        location = resp.headers.get("Location", "")
        if not location:
            continue

        if not _is_external_redirect(location, target_host):
            continue

        # ── Confirmed external redirect ──────────────────────────────────────
        context = _context_score(surface.param_name)
        base_conf = 60 + boost + context
        confidence = min(base_conf, 100)

        # OAuth redirect_uri gets a strong bump
        if surface.is_oauth and surface.param_name.lower() in (
            "redirect_uri", "returnto", "relaystate",
        ):
            confidence = min(confidence + 20, 100)

        severity = (
            "CRITICAL" if confidence >= 90 and surface.is_oauth
            else "HIGH" if confidence >= 75
            else "MEDIUM" if confidence >= 55
            else "LOW"
        )

        findings.append(OpenRedirectFinding(
            target=surface.url,
            param_name=surface.param_name,
            vector="server_side",
            severity=severity,
            confidence=confidence,
            payload=payload,
            payload_label=label,
            evidence=f"HTTP {resp.status_code} Location: {location}",
            redirect_location=location,
            http_status=resp.status_code,
            is_oauth=surface.is_oauth,
            details={
                "target_host": target_host,
                "context_weight": context,
                "is_oauth_endpoint": surface.is_oauth,
            },
        ))

        # One confirmed bypass per parameter is enough
        break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CLIENT-SIDE REDIRECT DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_client_side(
    session: requests.Session,
    surface: RedirectSurface,
    headers: Optional[dict] = None,
) -> list[OpenRedirectFinding]:
    """
    Test for meta-refresh and DOM-based redirects.

    Sends a subset of payloads and checks whether the response body contains:
      • <meta http-equiv="refresh" content="...url=<payload>">
      • window.location = "<payload>"
      • location.href = "<payload>"
    """
    findings: list[OpenRedirectFinding] = []

    # Use a focused subset for client-side — the payload must appear
    # literally in the body, so encoding-heavy payloads are less useful.
    client_payloads = [
        ("meta_direct", f"https://{CONFIRMATION_DOMAIN}", 30),
        ("meta_protocol_relative", f"//{CONFIRMATION_DOMAIN}", 25),
        ("dom_javascript", "javascript:alert(document.domain)", 20),
    ]

    for label, payload, boost in client_payloads:
        test_url = _build_test_url(surface.url, surface.param_name, payload)
        resp = _safe_request(session, "GET", test_url, headers)
        if not resp or resp.status_code >= 500:
            continue
        body = resp.text

        # ── Meta refresh ─────────────────────────────────────────────────────
        for m in META_REFRESH_RE.finditer(body):
            url_val = m.group(1)
            if _contains_payload(url_val, payload) or CONFIRMATION_DOMAIN in url_val:
                context = _context_score(surface.param_name)
                confidence = min(55 + boost + context, 100)
                findings.append(OpenRedirectFinding(
                    target=surface.url,
                    param_name=surface.param_name,
                    vector="meta_refresh",
                    severity="HIGH" if confidence >= 75 else "MEDIUM",
                    confidence=confidence,
                    payload=payload,
                    payload_label=label,
                    evidence=f"Meta refresh with external URL: {url_val[:120]}",
                    redirect_location=url_val,
                    http_status=resp.status_code,
                    is_oauth=surface.is_oauth,
                    details={"vector": "meta_refresh", "matched_tag": m.group(0)[:200]},
                ))
                break

        if findings:
            break

        # ── DOM sink ─────────────────────────────────────────────────────────
        for pattern in DOM_SINK_PATTERNS:
            for m in pattern.finditer(body):
                sink_val = m.group(1)
                if _contains_payload(sink_val, payload) or CONFIRMATION_DOMAIN in sink_val:
                    context = _context_score(surface.param_name)
                    confidence = min(50 + boost + context, 100)
                    findings.append(OpenRedirectFinding(
                        target=surface.url,
                        param_name=surface.param_name,
                        vector="dom_sink",
                        severity="HIGH" if confidence >= 75 else "MEDIUM",
                        confidence=confidence,
                        payload=payload,
                        payload_label=label,
                        evidence=f"DOM sink: {sink_val[:120]}",
                        redirect_location=sink_val,
                        http_status=resp.status_code,
                        is_oauth=surface.is_oauth,
                        details={"vector": "dom_sink", "sink": sink_val[:200]},
                    ))
                    break
            if findings:
                break

        if findings:
            break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CONTEXT-AWARE ESCALATION SCORING
# ═════════════════════════════════════════════════════════════════════════════

def _apply_escalation(findings: list[OpenRedirectFinding]) -> None:
    """
    Post-process findings to apply escalation logic:
      • OAuth redirect_uri confirmed → CRITICAL
      • Login next / return_to → HIGH
      • Plain url / redirect → MEDIUM
    """
    for f in findings:
        pname = f.param_name.lower()

        if f.is_oauth and pname in ("redirect_uri", "returnto", "relaystate"):
            f.severity = "CRITICAL"
            f.details["escalation"] = "OAuth token/code theft → ATO"
        elif pname in ("next", "return", "return_to", "return_url", "continue"):
            f.severity = "HIGH"
            f.details["escalation"] = "Login-flow phishing chain"
        elif f.severity == "LOW" and f.confidence >= 70:
            f.severity = "MEDIUM"


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_open_redirect_audit(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    max_urls: int = MAX_URLS,
    test_client_side: bool = True,
) -> Path:
    """
    Run the open redirect audit against every URL in `urls_file`.

    Returns the path to `open_redirect_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(urls_file)
    if len(urls) > max_urls:
        log.warning(f"  Capping at {max_urls} URLs (input had {len(urls)})")
        urls = urls[:max_urls]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Confirm: {CONFIRMATION_URL}")
    log.info("")

    if not urls:
        log.warning("  No URLs to test — writing empty report")
        return _write_empty_report(outdir, urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    # ── Phase 1: Surface discovery ──────────────────────────────────────────
    log.info("  Phase 1 — Redirect surface discovery")
    surfaces = discover_surfaces(urls)
    log.info(f"    {len(surfaces)} redirect-bearing surface(s)")

    if not surfaces:
        log.warning("  No redirect surfaces found — writing empty report")
        return _write_empty_report(outdir, urls_file, start, total_input=len(urls))

    # ── Phase 2 & 3: Testing ────────────────────────────────────────────────
    all_findings: list[OpenRedirectFinding] = []

    log.info("")
    log.info(f"  Phase 2 — Server-side redirect testing ({len(surfaces)} surface(s))")
    for s in surfaces:
        findings = test_server_side(session, s, headers)
        if findings:
            all_findings.extend(findings)
            log.info(f"    {s.param_name:<20} {s.url[:60]:<60} {findings[0].severity}")

    if test_client_side:
        log.info("")
        log.info("  Phase 3 — Client-side redirect detection")
        for s in surfaces:
            findings = test_client_side(session, s, headers)
            if findings:
                all_findings.extend(findings)
                log.info(f"    {s.param_name:<20} {s.url[:60]:<60} {findings[0].vector}")

    # ── Phase 4: Escalation scoring ─────────────────────────────────────────
    _apply_escalation(all_findings)

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[OpenRedirectFinding] = []
    for f in all_findings:
        key = (f.target, f.param_name, f.vector)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_vector: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_vector[f.vector] = by_vector.get(f.vector, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.param_name}\t{f.vector}\t{f.severity}\t{f.confidence}\t{f.evidence[:120]}"
        for f in deduped
    ]
    (outdir / "open_redirect_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed only (HIGH+)
    confirmed = [f for f in deduped if f.severity in ("CRITICAL", "HIGH")]
    (outdir / "open_redirect_confirmed.txt").write_text(
        "\n".join(f"{f.target}\t{f.param_name}\t{f.payload_label}\t{f.redirect_location[:100]}" for f in confirmed) + "\n"
    )

    # OAuth-specific
    oauth_findings = [f for f in deduped if f.is_oauth]
    (outdir / "open_redirect_oauth.txt").write_text(
        "\n".join(f"{f.target}\t{f.param_name}\t{f.severity}\t{f.evidence[:120]}" for f in oauth_findings) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "confirmation_domain": CONFIRMATION_DOMAIN,
            "test_client_side":    test_client_side,
            "authenticated":       headers is not None,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces":         len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "oauth_findings":   len(oauth_findings),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_vector":   dict(sorted(by_vector.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "open_redirect_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<32} {len(deduped):>5} finding(s)")
    log.info(f"    open_redirect_candidates.txt    {len(deduped):>5} candidate(s)")
    log.info(f"    open_redirect_confirmed.txt     {len(confirmed):>5} confirmed")
    log.info(f"    open_redirect_oauth.txt         {len(oauth_findings):>5} OAuth finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if confirmed:
        log.info("")
        log.info("  Confirmed findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.param_name:<20} {f.vector:<14} {f.redirect_location[:60]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces": 0, "total_findings": 0,
            "confirmed": 0, "oauth_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_vector": {}},
        "findings": [],
    }
    path = outdir / "open_redirect_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("open_redirect_candidates.txt", "open_redirect_confirmed.txt", "open_redirect_oauth.txt"):
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus Open Redirect Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--cookie", help="Session cookie for authenticated testing")
    parser.add_argument("--no-client-side", action="store_true", help="Skip meta/DOM detection")
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_open_redirect_audit(
            args.input, args.output,
            headers=headers,
            test_client_side=not args.no_client_side,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
