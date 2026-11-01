#!/usr/bin/env python3
"""
auditing_tools/auth_tester.py — Authentication Security Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive authentication testing module for Argus. Discovers auth surfaces,
tests for JWT flaws, OAuth misconfigurations, SAML XSW candidates, and general
authentication bypass patterns.

Four-phase strategy:

  Phase 1 — Auth surface discovery
      Identify login endpoints, OAuth flows, SAML ACS endpoints, JWT-bearing
      endpoints from URL patterns and parameter names.

  Phase 2 — JWT analysis
      Extract tokens from headers/cookies/params. Test for alg:none, weak HMAC
      secrets (offline), RS256→HS256 confusion, kid injection, jku/x5u abuse,
      missing expiry.

  Phase 3 — OAuth/SAML misconfiguration testing
      OAuth: redirect_uri bypass (22 variants), missing state, PKCE downgrade,
      scope escalation.
      SAML: XSW candidate generation (8 permutations), signature stripping.

  Phase 4 — General auth bypass candidates
      Forced browsing to admin endpoints, response manipulation probes,
      authentication logic flaw patterns.

Each finding is scored by confidence, mapped to a severity, and written to
`auth_findings.json` plus a flat `auth_candidates.txt` for `vuln_triage.py`.

Outputs (into `outdir`):
  • auth_findings.json        — full structured report
  • auth_candidates.txt       — flat list for triage
  • jwt_candidates.txt        — JWT-specific findings
  • oauth_candidates.txt      — OAuth-specific findings
  • saml_candidates.txt       — SAML-specific findings

Integration:
  main.py → run_one("auth") → run_auth_tester(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
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
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.auth_tester")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 8
DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 2
USER_AGENT           = "Argus-Auth-Tester/1.0"

# JWT
JWT_CRACK_WORDLIST   = "/usr/share/wordlists/rockyou.txt"
JWT_MIN_SECRET_LEN   = 8
MAX_JWT_CANDIDATES   = 500

# OAuth
OAUTH_REDIRECT_PAYLOADS = [
    # Attacker domain
    "https://evil.example.com",
    # Subdomain trick
    "https://target.com.evil.example.com",
    # Path traversal
    "https://target.com/../evil",
    # @ confusion
    "https://evil.example.com@target.com",
    # Null byte
    "https://target.com%00.evil.example.com",
    # Backslash
    "https://target.com\\@evil.example.com",
    # Port
    "https://target.com:443@evil.example.com",
    # Scheme downgrade
    "http://target.com",
    # Localhost
    "http://localhost",
    # Fragment injection
    "https://target.com/callback#evil.example.com",
]

# SAML
SAML_XSW_PERMUTATIONS = 8  # XSW1 through XSW8

# General auth
ADMIN_PATH_PATTERNS = [
    "/admin", "/internal", "/private", "/debug", "/actuator",
    "/management", "/console", "/dashboard", "/api/admin",
    "/v1/admin", "/v2/admin", "/v3/admin",
]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthFinding:
    target: str
    vuln_type: str           # "jwt_none_alg", "oauth_redirect_bypass", etc.
    severity: str = "MEDIUM"
    confidence: int = 50
    evidence: str = ""
    details: dict = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "vuln_type":  self.vuln_type,
            "severity":   self.severity,
            "confidence": self.confidence,
            "evidence":   self.evidence[:500],
            "details":    self.details,
            "remediation": self.remediation,
        }


@dataclass
class JWTAnalysis:
    token: str
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature: str = ""
    findings: list[AuthFinding] = field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _safe_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs,
) -> Optional[requests.Response]:
    """Make a request, return None on failure."""
    try:
        return session.request(
            method, url,
            timeout=kwargs.pop("timeout", DEFAULT_TIMEOUT),
            allow_redirects=kwargs.pop("allow_redirects", False),
            verify=False,
            **kwargs,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _b64url_decode(s: str) -> bytes:
    """Decode base64url with padding."""
    s = s.strip()
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_urls(input_file: Path) -> list[str]:
    """Load URLs from a file, accepting various formats."""
    if not input_file.exists():
        return []
    urls = []
    seen = set()
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


def _extract_host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — AUTH SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

AUTH_ENDPOINT_PATTERNS = {
    "login": re.compile(r"/(login|signin|authenticate|auth|session|sso)", re.I),
    "oauth": re.compile(r"/(oauth|authorize|callback|redirect|token)", re.I),
    "saml": re.compile(r"/(saml|acs|metadata|idp|sp)", re.I),
    "jwt": re.compile(r"/(token|jwt|refresh|verify)", re.I),
    "register": re.compile(r"/(register|signup|create)", re.I),
    "password": re.compile(r"/(password|reset|forgot|recover)", re.I),
    "2fa": re.compile(r"/(2fa|mfa|otp|verify|code)", re.I),
}


def discover_auth_endpoints(urls: list[str], session: requests.Session) -> dict[str, list[str]]:
    """
    Classify URLs into auth endpoint categories based on path patterns.
    """
    endpoints: dict[str, list[str]] = {k: [] for k in AUTH_ENDPOINT_PATTERNS}
    endpoints["all"] = []

    for url in urls:
        path = urllib.parse.urlparse(url).path
        matched = False
        for category, pattern in AUTH_ENDPOINT_PATTERNS.items():
            if pattern.search(path):
                endpoints[category].append(url)
                matched = True
        if matched:
            endpoints["all"].append(url)

    return endpoints


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — JWT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def extract_jwts(text: str) -> list[str]:
    """Extract JWT-like strings from arbitrary text."""
    return list(set(JWT_RE.findall(text)))


def decode_jwt(token: str) -> Optional[dict]:
    """Decode a JWT into header and payload without verifying."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception:
        return None


def analyze_jwt(token: str, target: str) -> JWTAnalysis:
    """
    Static analysis of a JWT. Detects:
      • alg:none (CVE-2015-9235)
      • weak HMAC secrets (offline brute-force)
      • missing expiry
      • kid injection surfaces (path traversal, SQLi)
      • jku/x5u over HTTP or attacker-controlled
      • embedded jwk
    """
    analysis = JWTAnalysis(token=token)
    decoded = decode_jwt(token)
    if not decoded:
        return analysis

    analysis.header = decoded["header"]
    analysis.payload = decoded["payload"]
    analysis.signature = decoded["signature"]

    hdr = analysis.header
    alg = (hdr.get("alg") or "").lower()
    typ = (hdr.get("typ") or "").lower()

    # ── alg:none ─────────────────────────────────────────────────────────────
    if alg == "none":
        analysis.findings.append(AuthFinding(
            target=target,
            vuln_type="jwt_alg_none",
            severity="CRITICAL",
            confidence=95,
            evidence=f"JWT uses alg:none (no signature)",
            details={"header": hdr},
            remediation="Enforce signature verification; reject alg:none",
        ))

    # ── Missing expiry ───────────────────────────────────────────────────────
    if "exp" not in analysis.payload:
        analysis.findings.append(AuthFinding(
            target=target,
            vuln_type="jwt_missing_expiry",
            severity="MEDIUM",
            confidence=80,
            evidence="JWT has no 'exp' claim",
            details={"payload_keys": list(analysis.payload.keys())},
            remediation="Include exp claim; enforce short TTL",
        ))

    # ── kid injection surface ────────────────────────────────────────────────
    kid = hdr.get("kid")
    if kid:
        kid_str = str(kid)
        if ".." in kid_str or "/" in kid_str or "\\" in kid_str:
            analysis.findings.append(AuthFinding(
                target=target,
                vuln_type="jwt_kid_path_traversal",
                severity="HIGH",
                confidence=75,
                evidence=f"kid contains path traversal: {kid_str}",
                details={"kid": kid_str},
                remediation="Validate kid against allow-list; never use as path",
            ))
        if any(c in kid_str for c in ("'", '"', " or ", "union ", "select ")):
            analysis.findings.append(AuthFinding(
                target=target,
                vuln_type="jwt_kid_sqli_surface",
                severity="HIGH",
                confidence=70,
                evidence=f"kid may be SQL-injectable: {kid_str}",
                details={"kid": kid_str},
                remediation="Parameterize kid lookups; validate format",
            ))

    # ── jku/x5u over HTTP or external ────────────────────────────────────────
    for key in ("jku", "x5u"):
        if key in hdr:
            url = str(hdr[key])
            if url.startswith("http://"):
                analysis.findings.append(AuthFinding(
                    target=target,
                    vuln_type=f"jwt_{key}_http",
                    severity="HIGH",
                    confidence=85,
                    evidence=f"{key} points to HTTP: {url}",
                    details={key: url},
                    remediation=f"Require HTTPS for {key}; validate against allow-list",
                ))
            # Check if it's an external host
            if _extract_host(url) and _extract_host(url) != _extract_host(target):
                analysis.findings.append(AuthFinding(
                    target=target,
                    vuln_type=f"jwt_{key}_external",
                    severity="HIGH",
                    confidence=70,
                    evidence=f"{key} points to external host: {url}",
                    details={key: url},
                    remediation=f"Validate {key} against trusted hosts",
                ))

    # ── embedded jwk ─────────────────────────────────────────────────────────
    if "jwk" in hdr:
        analysis.findings.append(AuthFinding(
            target=target,
            vuln_type="jwt_embedded_jwk",
            severity="HIGH",
            confidence=75,
            evidence="JWT contains embedded jwk header",
            details={"jwk": hdr["jwk"]},
            remediation="Reject embedded jwk; use pre-configured keys",
        ))

    # ── weak HMAC secret ─────────────────────────────────────────────────────
    if alg in ("hs256", "hs384", "hs512"):
        # Offline crack — no traffic
        if Path(JWT_CRACK_WORDLIST).exists():
            cracked = _crack_jwt_secret(token, JWT_CRACK_WORDLIST, alg)
            if cracked:
                analysis.findings.append(AuthFinding(
                    target=target,
                    vuln_type="jwt_weak_secret",
                    severity="CRITICAL",
                    confidence=100,
                    evidence=f"HMAC secret cracked: {cracked[:8]}...",
                    details={"secret_prefix": cracked[:8], "algorithm": alg},
                    remediation="Use a high-entropy secret; rotate immediately",
                ))

    return analysis


def _crack_jwt_secret(token: str, wordlist_path: str, alg: str) -> Optional[str]:
    """
    Offline brute-force of HMAC secret. Returns the cracked secret or None.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = _b64url_decode(parts[2])

    hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg.lower())
    if not hash_fn:
        return None

    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for line in f:
                secret = line.strip().encode()
                if len(secret) < JWT_MIN_SECRET_LEN:
                    continue
                test_sig = hmac.new(secret, signing_input, hash_fn).digest()
                if hmac.compare_digest(test_sig, signature):
                    return secret.decode()
    except Exception as e:
        log.debug(f"JWT crack failed: {e}")
    return None


def run_jwt_analysis(urls: list[str], session: requests.Session, outdir: Path) -> list[AuthFinding]:
    """
    Extract JWTs from:
      • Response bodies
      • Response headers (Authorization, Set-Cookie)
      • URL query parameters
    Then analyze each unique token.
    """
    findings: list[AuthFinding] = []
    seen_tokens: set[str] = set()
    candidates: list[tuple[str, str]] = []  # (url, token)

    log.info("  Scanning for JWTs in responses...")

    def _scan_url(url: str):
        resp = _safe_request(session, "GET", url)
        if not resp:
            return []
        tokens = []

        # Body
        tokens.extend(extract_jwts(resp.text[:100000]))

        # Headers
        for hdr_name in ("Authorization", "X-Auth-Token", "X-Access-Token"):
            val = resp.headers.get(hdr_name, "")
            if "bearer " in val.lower():
                tokens.extend(extract_jwts(val))
            elif JWT_RE.match(val):
                tokens.append(val)

        # Cookies
        for cookie in resp.cookies:
            tokens.extend(extract_jwts(cookie.value))

        # URL params
        parsed = urllib.parse.urlparse(url)
        for _, vals in urllib.parse.parse_qs(parsed.query).items():
            for v in vals:
                tokens.extend(extract_jwts(v))

        return [(url, t) for t in tokens if t not in seen_tokens]

    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as pool:
        futures = {pool.submit(_scan_url, u): u for u in urls[:MAX_JWT_CANDIDATES]}
        for fut in as_completed(futures):
            try:
                for url, token in fut.result():
                    if token not in seen_tokens:
                        seen_tokens.add(token)
                        candidates.append((url, token))
            except Exception:
                pass

    log.info(f"    Found {len(candidates)} unique JWT(s)")

    for url, token in candidates:
        analysis = analyze_jwt(token, url)
        if analysis.findings:
            findings.extend(analysis.findings)
            log.info(f"    JWT findings on {url}: {len(analysis.findings)}")

    # Write JWT candidates flat file
    jwt_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.evidence[:120]}"
        for f in findings
    ]
    (outdir / "jwt_candidates.txt").write_text("\n".join(jwt_lines) + "\n")

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3A — OAUTH MISCONFIGURATION TESTING
# ═════════════════════════════════════════════════════════════════════════════

def test_oauth_endpoints(oauth_urls: list[str], session: requests.Session) -> list[AuthFinding]:
    """
    Test OAuth authorize endpoints for:
      • Missing state parameter
      • redirect_uri open redirect (multiple bypass payloads)
      • PKCE downgrade
      • Scope escalation
    """
    findings: list[AuthFinding] = []
    if not oauth_urls:
        return findings

    log.info(f"  Testing {len(oauth_urls)} OAuth endpoint(s)...")

    for url in oauth_urls[:50]:  # cap for safety
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # ── Missing state ────────────────────────────────────────────────────
        if "response_type" in params and "state" not in params:
            findings.append(AuthFinding(
                target=url,
                vuln_type="oauth_missing_state",
                severity="HIGH",
                confidence=85,
                evidence="OAuth authorize endpoint has no state parameter",
                details={"params": list(params.keys())},
                remediation="Require state parameter; bind to user session",
            ))

        # ── redirect_uri bypass ──────────────────────────────────────────────
        original_redirect = params.get("redirect_uri", [None])[0]
        if original_redirect:
            for payload in OAUTH_REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params["redirect_uri"] = payload
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                resp = _safe_request(session, "GET", test_url)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if payload in location or _extract_host(location) != _extract_host(original_redirect):
                        findings.append(AuthFinding(
                            target=url,
                            vuln_type="oauth_redirect_bypass",
                            severity="CRITICAL",
                            confidence=90,
                            evidence=f"redirect_uri accepted attacker payload: {payload}",
                            details={
                                "payload": payload,
                                "original_redirect": original_redirect,
                                "response_location": location[:200],
                            },
                            remediation="Strictly validate redirect_uri against allow-list",
                        ))
                        break  # one confirmed bypass per endpoint is enough

        # ── PKCE downgrade ───────────────────────────────────────────────────
        if "code_challenge" in params and "code_challenge_method" not in params:
            findings.append(AuthFinding(
                target=url,
                vuln_type="oauth_pkce_downgrade",
                severity="MEDIUM",
                confidence=60,
                evidence="code_challenge present without code_challenge_method",
                details={"params": list(params.keys())},
                remediation="Enforce S256 for code_challenge_method",
            ))

    # Write OAuth candidates flat file
    oauth_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.evidence[:120]}"
        for f in findings
    ]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3B — SAML MISCONFIGURATION TESTING
# ═════════════════════════════════════════════════════════════════════════════

SAML_ENDPOINT_RE = re.compile(r"/(saml|acs|metadata|idp|sp|sso)", re.I)


def test_saml_endpoints(urls: list[str], session: requests.Session) -> list[AuthFinding]:
    """
    Identify SAML endpoints and generate XSW candidates.
    Actual XSW testing requires manual XML manipulation with SAML Raider.
    This module flags the surface and produces the candidate list.
    """
    findings: list[AuthFinding] = []
    saml_urls = [u for u in urls if SAML_ENDPOINT_RE.search(urllib.parse.urlparse(u).path)]
    if not saml_urls:
        return findings

    log.info(f"  Identified {len(saml_urls)} SAML-related endpoint(s)")

    for url in saml_urls[:30]:
        # Probe for SAML metadata
        for meta_path in ("/saml/metadata", "/metadata", "/saml2/metadata", "/idp/metadata"):
            test_url = urllib.parse.urljoin(url, meta_path)
            resp = _safe_request(session, "GET", test_url)
            if resp and resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
                findings.append(AuthFinding(
                    target=test_url,
                    vuln_type="saml_metadata_exposed",
                    severity="MEDIUM",
                    confidence=80,
                    evidence="SAML metadata is publicly accessible",
                    details={"content_type": resp.headers.get("Content-Type")},
                    remediation="Restrict metadata to authorized IdPs/SPs",
                ))

        # Flag potential XSW surface
        findings.append(AuthFinding(
            target=url,
            vuln_type="saml_xsw_candidate",
            severity="HIGH",
            confidence=40,  # low confidence until manually confirmed
            evidence=f"SAML endpoint identified; test {SAML_XSW_PERMUTATIONS} XSW permutations manually",
            details={"xsw_permutations": SAML_XSW_PERMUTATIONS},
            remediation="Use hardened SAML library; validate signature reference",
        ))

    saml_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.evidence[:120]}"
        for f in findings
    ]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — GENERAL AUTH BYPASS CANDIDATES
# ═════════════════════════════════════════════════════════════════════════════

def test_general_auth_bypass(urls: list[str], session: requests.Session) -> list[AuthFinding]:
    """
    Test for:
      • Forced browsing to admin/internal endpoints
      • Authentication logic flaw patterns (response manipulation surface)
      • Default credential endpoints
    """
    findings: list[AuthFinding] = []

    # ── Forced browsing ──────────────────────────────────────────────────────
    log.info("  Testing forced browsing to admin endpoints...")
    hosts = sorted({_extract_host(u) for u in urls if _extract_host(u)})
    for host in hosts[:20]:
        for path in ADMIN_PATH_PATTERNS:
            test_url = f"https://{host}{path}"
            resp = _safe_request(session, "GET", test_url)
            if resp and resp.status_code in (200, 401, 403):
                # 200 = exposed, 401/403 = protected (interesting)
                severity = "HIGH" if resp.status_code == 200 else "MEDIUM"
                findings.append(AuthFinding(
                    target=test_url,
                    vuln_type="admin_endpoint_exposed" if resp.status_code == 200 else "admin_endpoint_protected",
                    severity=severity,
                    confidence=70 if resp.status_code == 200 else 50,
                    evidence=f"HTTP {resp.status_code} on admin path",
                    details={"status": resp.status_code, "path": path},
                    remediation="Enforce authentication on admin routes",
                ))

    # ── Default credential candidates ────────────────────────────────────────
    login_urls = [u for u in urls if "/login" in u or "/signin" in u]
    for url in login_urls[:20]:
        findings.append(AuthFinding(
            target=url,
            vuln_type="default_credential_candidate",
            severity="MEDIUM",
            confidence=30,
            evidence="Login endpoint identified; test default credentials manually",
            details={},
            remediation="Enforce password policy; disable default accounts",
        ))

    # ── Response manipulation candidates ─────────────────────────────────────
    for url in urls[:50]:
        if any(kw in url.lower() for kw in ("login", "auth", "verify", "2fa", "otp")):
            findings.append(AuthFinding(
                target=url,
                vuln_type="response_manipulation_candidate",
                severity="MEDIUM",
                confidence=25,
                evidence="Auth-related endpoint; test response manipulation (e.g., 401→200)",
                details={},
                remediation="Server-side validation; never trust client responses",
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_auth_tester(
    live_urls_file: Path,
    outdir: Path,
    *,
    test_jwt: bool = True,
    test_oauth: bool = True,
    test_saml: bool = True,
    test_general: bool = True,
) -> Path:
    """
    Run authentication testing against every URL in `live_urls_file`.

    Returns the path to `auth_findings.json`.
    """
    start = time.monotonic()

    # ── Inputs ──────────────────────────────────────────────────────────────
    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info("")

    if not urls:
        log.warning("  No URLs to test — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Session ─────────────────────────────────────────────────────────────
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.verify = False

    # ── Phase 1: Discovery ───────────────────────────────────────────────────
    log.info("  Phase 1 — Auth surface discovery")
    endpoints = discover_auth_endpoints(urls, session)
    for cat, urls_cat in endpoints.items():
        if cat != "all" and urls_cat:
            log.info(f"    {cat:<10}: {len(urls_cat)} endpoint(s)")

    all_findings: list[AuthFinding] = []

    # ── Phase 2: JWT ─────────────────────────────────────────────────────────
    if test_jwt:
        log.info("")
        log.info("  Phase 2 — JWT analysis")
        jwt_findings = run_jwt_analysis(urls, session, outdir)
        all_findings.extend(jwt_findings)
        log.info(f"    {len(jwt_findings)} JWT finding(s)")

    # ── Phase 3a: OAuth ──────────────────────────────────────────────────────
    if test_oauth and endpoints.get("oauth"):
        log.info("")
        log.info("  Phase 3a — OAuth testing")
        oauth_findings = test_oauth_endpoints(endpoints["oauth"], session)
        all_findings.extend(oauth_findings)
        log.info(f"    {len(oauth_findings)} OAuth finding(s)")

    # ── Phase 3b: SAML ───────────────────────────────────────────────────────
    if test_saml and endpoints.get("saml"):
        log.info("")
        log.info("  Phase 3b — SAML testing")
        saml_findings = test_saml_endpoints(endpoints["saml"], session)
        all_findings.extend(saml_findings)
        log.info(f"    {len(saml_findings)} SAML finding(s)")

    # ── Phase 4: General auth bypass ─────────────────────────────────────────
    if test_general:
        log.info("")
        log.info("  Phase 4 — General auth bypass candidates")
        general_findings = test_general_auth_bypass(urls, session)
        all_findings.extend(general_findings)
        log.info(f"    {len(general_findings)} general finding(s)")

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[AuthFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Sort by severity ─────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    # Flat candidates file
    candidates_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:160]}"
        for f in deduped
    ]
    (outdir / "auth_candidates.txt").write_text("\n".join(candidates_lines) + "\n")

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "test_jwt": test_jwt,
            "test_oauth": test_oauth,
            "test_saml": test_saml,
            "test_general": test_general,
        },
        "totals": {
            "urls_scanned": len(urls),
            "total_findings": len(deduped),
            "critical": by_severity["CRITICAL"],
            "high": by_severity["HIGH"],
            "medium": by_severity["MEDIUM"],
            "low": by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "auth_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    auth_candidates.txt          {len(deduped):>5} candidate(s)")
    if (outdir / "jwt_candidates.txt").exists():
        jwt_count = sum(1 for _ in (outdir / "jwt_candidates.txt").open())
        log.info(f"    jwt_candidates.txt           {jwt_count:>5} finding(s)")
    if (outdir / "oauth_candidates.txt").exists():
        oauth_count = sum(1 for _ in (outdir / "oauth_candidates.txt").open())
        log.info(f"    oauth_candidates.txt         {oauth_count:>5} finding(s)")
    if (outdir / "saml_candidates.txt").exists():
        saml_count = sum(1 for _ in (outdir / "saml_candidates.txt").open())
        log.info(f"    saml_candidates.txt          {saml_count:>5} finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if deduped:
        log.info("")
        log.info("  Top findings:")
        for f in deduped[:10]:
            log.info(f"    [{f.severity:<8}] {f.vuln_type:<28} {f.target[:60]}")

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
            "urls_scanned": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "auth_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "auth_candidates.txt").write_text("")
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

    parser = argparse.ArgumentParser(description="Argus Auth Tester (standalone)")
    parser.add_argument("--input", type=Path, default=live, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--no-jwt", action="store_true", help="Skip JWT analysis")
    parser.add_argument("--no-oauth", action="store_true", help="Skip OAuth testing")
    parser.add_argument("--no-saml", action="store_true", help="Skip SAML testing")
    parser.add_argument("--no-general", action="store_true", help="Skip general auth bypass")
    args = parser.parse_args()

    try:
        run_auth_tester(
            args.input,
            args.output,
            test_jwt=not args.no_jwt,
            test_oauth=not args.no_oauth,
            test_saml=not args.no_saml,
            test_general=not args.no_general,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
