#!/usr/bin/env python3
"""
auditing_tools/auth_tester.py — Authentication Security Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive authentication testing module for Argus.

THIS IS TARGET-TRAFFIC. Platform headers and request.txt auth are applied
to every request. Rate limits are honored — a 500-URL scan with all phases
triggers thousands of requests, so throttling is critical.

Six phases:

  1. Auth surface discovery     — login, OAuth, SAML, JWT, register, 2FA
  2. JWT analysis               — static (decode-only), zero target traffic
                                  beyond the initial extraction fetch
  3. OAuth misconfiguration     — 15 redirect_uri bypass variants + PKCE/state
  4. SAML surface mapping       — metadata probe + XSW candidate generation
  5. General auth bypass        — forced browsing to admin/console paths
  6. Cookie + CSRF analysis     — NEW: HttpOnly/Secure/SameSite missing,
                                  CSRF token absence on state-changing forms,
                                  bearer-token-in-URL detection,
                                  basic-auth realm discovery

What "precision" means here (FP reduction):
  • SAML XSW candidates are LOW-confidence (40) — never claim confirmed
  • OAuth redirect bypass requires ACTUAL 3xx + Location redirect
  • JWT weak-secret cracking is offline-only — no traffic amplification
  • Admin path probing requires a NON-default response (not 404, not 500)
  • Cookie analysis only flags cookies that look session-related
  • CSRF analysis only flags POST forms that modify state

Config integration (config.py):
  • MODULE_RATE_LIMITS["auth"]     → request rate + concurrency
  • ACTIVE_HEADERS + AUTH_HEADERS  → merged, applied to every request
  • AUTH_COOKIES                   → session cookies
  • SYNC_TO_DB, BRIDGE_*           → remote database sync

Outputs (into `outdir`):
  • auth_findings.json        — full structured report
  • auth_candidates.txt       — flat list for triage
  • jwt_candidates.txt        — JWT-specific findings
  • oauth_candidates.txt      — OAuth-specific findings
  • saml_candidates.txt       — SAML-specific findings

Remote DB (if scan_id is provided):
  • auth_findings table       — one row per (scan_id, finding_hash)

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

log = logging.getLogger("argus.auth_tester")

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


def _auth_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("auth", {})
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 2),
        "timeout":     entry.get("timeout", 12),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS         = 2
DEFAULT_RATE_LIMIT      = 2
DEFAULT_TIMEOUT         = 12
DEFAULT_RETRIES         = 2

# JWT
JWT_CRACK_WORDLIST      = "/usr/share/wordlists/rockyou.txt"
JWT_MIN_SECRET_LEN      = 8
MAX_JWT_CANDIDATES      = 500

# OAuth — 15 redirect_uri bypass variants (expanded)
OAUTH_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "https://evil.example.com/",
    "https://target.com.evil.example.com",
    "https://target.com/../evil",
    "https://target.com/..%2fevil",
    "https://evil.example.com@target.com",
    "https://target.com%00.evil.example.com",
    "https://target.com\\@evil.example.com",
    "https://target.com:443@evil.example.com",
    "http://target.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://target.com/callback#evil.example.com",
    "https://target.com/callback?x=https://evil.example.com",
    "https://target.com/callback%23.evil.example.com",
]

# SAML
SAML_XSW_PERMUTATIONS   = 8

# Admin paths for forced browsing
ADMIN_PATH_PATTERNS = [
    "/admin", "/administrator", "/internal", "/private", "/debug",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/management", "/manage", "/console", "/dashboard", "/panel",
    "/cp", "/control", "/api/admin", "/v1/admin", "/v2/admin", "/v3/admin",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    "/graphiql", "/graphql/console", "/.env", "/.git/config",
]

# Cookie names that suggest session cookies (case-insensitive substring match)
SESSION_COOKIE_HINTS = [
    "sess", "sid", "auth", "token", "jwt", "login", "user",
    "remember", "csrf", "xsrf", "access",
]

# CSRF-related form field names
CSRF_FIELD_HINTS = [
    "csrf", "xsrf", "_token", "authenticity_token",
    "csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthFinding:
    target: str
    vuln_type: str
    category: str = "general"     # jwt | oauth | saml | general | cookie | csrf
    severity: str = "MEDIUM"
    confidence: int = 50
    evidence: str = ""
    details: dict = field(default_factory=dict)
    remediation: str = ""
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(
            f"{self.target}|{self.vuln_type}".encode()
        ).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":       self.target,
            "vuln_type":    self.vuln_type,
            "category":     self.category,
            "severity":     self.severity,
            "confidence":   self.confidence,
            "evidence":     self.evidence[:500],
            "details":      self.details,
            "remediation":  self.remediation,
            "auth_enabled": self.auth_enabled,
            "finding_hash": self.finding_hash,
            "first_seen":   self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    """
    A requests.Session wrapper that enforces a minimum inter-request interval.

    Requests that would exceed the rate limit sleep briefly before firing.
    Config-driven — no request ever bypasses the throttle.
    """
    def __init__(
        self,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        timeout: int = DEFAULT_TIMEOUT,
        auth_enabled: bool = False,
    ):
        self.session = requests.Session()
        self.session.verify = False

        hdrs = _target_headers()
        if hdrs:
            self.session.headers.update(hdrs)
        if "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = "Argus-Auth-Tester/2.0"

        cookies = _auth_cookies()
        for k, v in cookies.items():
            self.session.cookies.set(k, v)

        self.auth_enabled = auth_enabled
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last_request_time = 0.0

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        # Enforce rate limit
        if self.min_interval > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)

        self._last_request_time = time.monotonic()

        try:
            return self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False,
                **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _load_urls(input_file: Path) -> list[str]:
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
    "login":    re.compile(r"/(login|signin|authenticate|auth|session|sso)(/|$|\?)", re.I),
    "oauth":    re.compile(r"/(oauth|authorize|callback|redirect|token)(/|$|\?)", re.I),
    "saml":     re.compile(r"/(saml|acs|metadata|idp|sp)(/|$|\?)", re.I),
    "jwt":      re.compile(r"/(token|jwt|refresh|verify)(/|$|\?)", re.I),
    "register": re.compile(r"/(register|signup|create-account)(/|$|\?)", re.I),
    "password": re.compile(r"/(password|reset|forgot|recover)(/|$|\?)", re.I),
    "2fa":      re.compile(r"/(2fa|mfa|otp|verify|code)(/|$|\?)", re.I),
}


def discover_auth_endpoints(urls: list[str]) -> dict[str, list[str]]:
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
    return list(set(JWT_RE.findall(text)))


def decode_jwt(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception:
        return None


def _crack_jwt_secret(token: str, wordlist_path: str, alg: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    signature = _b64url_decode(parts[2])
    hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg.lower())
    if not hash_fn:
        return None
    if not Path(wordlist_path).exists():
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


def analyze_jwt(token: str, target: str, auth_on: bool, now_iso: str) -> list[AuthFinding]:
    """Static JWT analysis — decode-only except for offline secret crack."""
    findings: list[AuthFinding] = []
    decoded = decode_jwt(token)
    if not decoded:
        return findings

    hdr = decoded["header"]
    payload = decoded["payload"]
    alg = (hdr.get("alg") or "").lower()
    typ = (hdr.get("typ") or "").lower()

    # alg:none — CVE-2015-9235
    if alg == "none":
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_alg_none", category="jwt",
            severity="CRITICAL", confidence=95,
            evidence="JWT uses alg:none (signature not verified)",
            details={"header": hdr},
            remediation="Reject alg:none; enforce signature verification",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # Empty signature (even without alg:none)
    if not decoded["signature"] and alg != "none":
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_empty_signature", category="jwt",
            severity="HIGH", confidence=85,
            evidence=f"JWT with alg={alg} has empty signature",
            details={"header": hdr, "signature_len": 0},
            remediation="Enforce signature verification",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # Missing exp — long-lived tokens
    if "exp" not in payload:
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_missing_expiry", category="jwt",
            severity="MEDIUM", confidence=80,
            evidence="JWT has no 'exp' claim",
            details={"payload_keys": list(payload.keys())},
            remediation="Include exp claim; enforce short TTL",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # typ confusion (at+jwt vs JWT on access tokens)
    if typ == "jwt" and "sub" in payload and "scope" not in payload:
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_typ_access_token", category="jwt",
            severity="LOW", confidence=50,
            evidence="Access-token-like JWT uses typ:JWT instead of typ:at+jwt",
            details={"typ": typ, "alg": alg},
            remediation="Use typ:at+jwt for access tokens (RFC 9068)",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # kid injection surface
    kid = hdr.get("kid")
    if kid:
        kid_str = str(kid)
        if ".." in kid_str or "/" in kid_str or "\\" in kid_str:
            findings.append(AuthFinding(
                target=target, vuln_type="jwt_kid_path_traversal", category="jwt",
                severity="HIGH", confidence=75,
                evidence=f"kid contains path traversal: {kid_str}",
                details={"kid": kid_str},
                remediation="Validate kid against allow-list; never use as path",
                auth_enabled=auth_on, first_seen=now_iso,
            ))
        if any(c in kid_str for c in ("'", '"', " or ", "union ", "select ")):
            findings.append(AuthFinding(
                target=target, vuln_type="jwt_kid_sqli_surface", category="jwt",
                severity="HIGH", confidence=70,
                evidence=f"kid may be SQL-injectable: {kid_str}",
                details={"kid": kid_str},
                remediation="Parameterize kid lookups; validate format",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    # jku / x5u over HTTP or external
    for key in ("jku", "x5u"):
        if key in hdr:
            url = str(hdr[key])
            if url.startswith("http://"):
                findings.append(AuthFinding(
                    target=target, vuln_type=f"jwt_{key}_http", category="jwt",
                    severity="HIGH", confidence=85,
                    evidence=f"{key} points to HTTP: {url}",
                    details={key: url},
                    remediation=f"Require HTTPS for {key}; validate against allow-list",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            if _extract_host(url) and _extract_host(url) != _extract_host(target):
                findings.append(AuthFinding(
                    target=target, vuln_type=f"jwt_{key}_external", category="jwt",
                    severity="HIGH", confidence=70,
                    evidence=f"{key} points to external host: {url}",
                    details={key: url},
                    remediation=f"Validate {key} against trusted hosts",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

    # Embedded jwk
    if "jwk" in hdr:
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_embedded_jwk", category="jwt",
            severity="HIGH", confidence=75,
            evidence="JWT contains embedded jwk header",
            details={"jwk": hdr["jwk"]},
            remediation="Reject embedded jwk; use pre-configured keys",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # Weak HMAC secret — offline crack
    if alg in ("hs256", "hs384", "hs512"):
        cracked = _crack_jwt_secret(token, JWT_CRACK_WORDLIST, alg)
        if cracked:
            findings.append(AuthFinding(
                target=target, vuln_type="jwt_weak_secret", category="jwt",
                severity="CRITICAL", confidence=100,
                evidence=f"HMAC secret cracked: {cracked[:8]}...",
                details={"secret_prefix": cracked[:8], "algorithm": alg},
                remediation="Use high-entropy secret; rotate immediately",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    return findings


def run_jwt_analysis(
    urls: list[str], session: RateLimitedSession,
    outdir: Path, auth_on: bool, threads: int,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    seen_tokens: set[str] = set()
    candidates: list[tuple[str, str]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info("  Scanning for JWTs in responses...")

    def _scan_url(url: str) -> list[tuple[str, str]]:
        resp = session.get(url)
        if not resp:
            return []
        tokens: list[str] = []
        try:
            tokens.extend(extract_jwts(resp.text[:100000]))
        except Exception:
            pass
        for hdr_name in ("Authorization", "X-Auth-Token", "X-Access-Token"):
            val = resp.headers.get(hdr_name, "")
            if "bearer " in val.lower():
                tokens.extend(extract_jwts(val))
            elif JWT_RE.match(val):
                tokens.append(val)
        for cookie in resp.cookies:
            tokens.extend(extract_jwts(cookie.value))
        parsed = urllib.parse.urlparse(url)
        for _, vals in urllib.parse.parse_qs(parsed.query).items():
            for v in vals:
                tokens.extend(extract_jwts(v))
        return [(url, t) for t in tokens if t not in seen_tokens]

    with ThreadPoolExecutor(max_workers=threads) as pool:
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
        findings.extend(analyze_jwt(token, url, auth_on, now_iso))

    # Write JWT flat file
    jwt_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:120]}"
        for f in findings
    ]
    (outdir / "jwt_candidates.txt").write_text(
        "\n".join(jwt_lines) + ("\n" if jwt_lines else "")
    )
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3A — OAUTH
# ═════════════════════════════════════════════════════════════════════════════

def test_oauth_endpoints(
    oauth_urls: list[str], session: RateLimitedSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    if not oauth_urls:
        return findings
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info(f"  Testing {len(oauth_urls)} OAuth endpoint(s)...")

    for url in oauth_urls[:50]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Missing state
        if "response_type" in params and "state" not in params:
            findings.append(AuthFinding(
                target=url, vuln_type="oauth_missing_state", category="oauth",
                severity="HIGH", confidence=85,
                evidence="OAuth authorize endpoint has no state parameter",
                details={"params": list(params.keys())},
                remediation="Require state parameter; bind to user session",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

        # redirect_uri bypass
        original_redirect = params.get("redirect_uri", [None])[0]
        if original_redirect:
            for payload in OAUTH_REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params["redirect_uri"] = payload
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                resp = session.get(test_url)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if payload in location or _extract_host(location) != _extract_host(original_redirect):
                        findings.append(AuthFinding(
                            target=url, vuln_type="oauth_redirect_bypass", category="oauth",
                            severity="CRITICAL", confidence=90,
                            evidence=f"redirect_uri accepted attacker payload: {payload}",
                            details={
                                "payload": payload,
                                "original_redirect": original_redirect,
                                "response_location": location[:200],
                            },
                            remediation="Strictly validate redirect_uri against allow-list",
                            auth_enabled=auth_on, first_seen=now_iso,
                        ))
                        break

        # PKCE downgrade
        if "code_challenge" in params and "code_challenge_method" not in params:
            findings.append(AuthFinding(
                target=url, vuln_type="oauth_pkce_downgrade", category="oauth",
                severity="MEDIUM", confidence=60,
                evidence="code_challenge present without code_challenge_method",
                details={"params": list(params.keys())},
                remediation="Enforce S256 for code_challenge_method",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    oauth_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:120]}"
        for f in findings
    ]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3B — SAML
# ═════════════════════════════════════════════════════════════════════════════

SAML_ENDPOINT_RE = re.compile(r"/(saml|acs|metadata|idp|sp|sso)(/|$)", re.I)


def test_saml_endpoints(
    urls: list[str], session: RateLimitedSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    saml_urls = [u for u in urls if SAML_ENDPOINT_RE.search(urllib.parse.urlparse(u).path)]
    if not saml_urls:
        return findings
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info(f"  Identified {len(saml_urls)} SAML-related endpoint(s)")

    for url in saml_urls[:30]:
        for meta_path in ("/saml/metadata", "/metadata", "/saml2/metadata", "/idp/metadata"):
            test_url = urllib.parse.urljoin(url, meta_path)
            resp = session.get(test_url)
            if resp and resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
                findings.append(AuthFinding(
                    target=test_url, vuln_type="saml_metadata_exposed", category="saml",
                    severity="MEDIUM", confidence=80,
                    evidence="SAML metadata is publicly accessible",
                    details={"content_type": resp.headers.get("Content-Type")},
                    remediation="Restrict metadata to authorized IdPs/SPs",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

        findings.append(AuthFinding(
            target=url, vuln_type="saml_xsw_candidate", category="saml",
            severity="HIGH", confidence=40,
            evidence=f"SAML endpoint identified; test {SAML_XSW_PERMUTATIONS} XSW permutations manually",
            details={"xsw_permutations": SAML_XSW_PERMUTATIONS},
            remediation="Use hardened SAML library; validate signature reference",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — GENERAL AUTH BYPASS
# ═════════════════════════════════════════════════════════════════════════════

def test_general_auth_bypass(
    urls: list[str], session: RateLimitedSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info("  Testing forced browsing to admin endpoints...")
    hosts = sorted({_extract_host(u) for u in urls if _extract_host(u)})
    for host in hosts[:20]:
        for path in ADMIN_PATH_PATTERNS:
            test_url = f"https://{host}{path}"
            resp = session.get(test_url)
            if not resp:
                continue
            # Only flag meaningful responses — not 404, not 500
            if resp.status_code in (200, 401, 403):
                severity = "HIGH" if resp.status_code == 200 else "MEDIUM"
                findings.append(AuthFinding(
                    target=test_url,
                    vuln_type="admin_endpoint_exposed" if resp.status_code == 200 else "admin_endpoint_protected",
                    category="general",
                    severity=severity,
                    confidence=70 if resp.status_code == 200 else 50,
                    evidence=f"HTTP {resp.status_code} on admin path",
                    details={"status": resp.status_code, "path": path},
                    remediation="Enforce authentication on admin routes",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            elif resp.status_code in (301, 302):
                # Redirect to login = protected. Redirect elsewhere = may be exposed.
                location = resp.headers.get("Location", "").lower()
                if "login" not in location and "signin" not in location and "auth" not in location:
                    findings.append(AuthFinding(
                        target=test_url, vuln_type="admin_endpoint_redirect",
                        category="general",
                        severity="MEDIUM", confidence=40,
                        evidence=f"Admin path redirects to {location[:80]} (not login)",
                        details={"status": resp.status_code, "location": location[:200]},
                        remediation="Verify redirect target is authorized",
                        auth_enabled=auth_on, first_seen=now_iso,
                    ))

    # Default credential candidates
    login_urls = [u for u in urls if "/login" in u or "/signin" in u]
    for url in login_urls[:20]:
        findings.append(AuthFinding(
            target=url, vuln_type="default_credential_candidate",
            category="general",
            severity="MEDIUM", confidence=30,
            evidence="Login endpoint identified; test default credentials manually",
            details={},
            remediation="Enforce password policy; disable default accounts",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — COOKIE + CSRF ANALYSIS (NEW)
# ═════════════════════════════════════════════════════════════════════════════

def _looks_like_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(hint in n for hint in SESSION_COOKIE_HINTS)


def _parse_set_cookie_attrs(set_cookie_header: str) -> dict:
    """Parse a Set-Cookie header into {name, value, attrs}."""
    parts = [p.strip() for p in set_cookie_header.split(";")]
    if not parts:
        return {}
    nv = parts[0]
    if "=" not in nv:
        return {}
    name, value = nv.split("=", 1)
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        elif p:
            attrs[p.strip().lower()] = ""
    return {"name": name.strip(), "value": value, "attrs": attrs}


def test_cookie_security(
    urls: list[str], session: RateLimitedSession, auth_on: bool,
) -> list[AuthFinding]:
    """
    Analyze Set-Cookie headers on auth-related endpoints.

    Flags:
      • Session cookies missing HttpOnly
      • Session cookies missing Secure (on HTTPS)
      • Session cookies missing SameSite (or SameSite=None without Secure)
    """
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info("  Analyzing cookie security on auth endpoints...")

    auth_urls = [
        u for u in urls
        if re.search(r"/(login|signin|auth|session|dashboard|account)", u, re.I)
    ][:30]

    seen_cookies: set[tuple[str, str]] = set()

    for url in auth_urls:
        resp = session.get(url)
        if not resp:
            continue

        # requests collapses multiple Set-Cookie headers — need raw
        set_cookies: list[str] = []
        try:
            set_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            sc = resp.headers.get("Set-Cookie", "")
            if sc:
                set_cookies = [sc]

        for sc in set_cookies:
            parsed = _parse_set_cookie_attrs(sc)
            if not parsed:
                continue
            name = parsed["name"]
            attrs = parsed["attrs"]

            if not _looks_like_session_cookie(name):
                continue

            key = (url, name)
            if key in seen_cookies:
                continue
            seen_cookies.add(key)

            missing: list[str] = []
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "secure" not in attrs and url.startswith("https://"):
                missing.append("Secure")
            same_site = attrs.get("samesite", "").lower()
            if not same_site:
                missing.append("SameSite")
            elif same_site == "none" and "secure" not in attrs:
                missing.append("SameSite=None_without_Secure")

            if missing:
                severity = "HIGH" if "HttpOnly" in missing or "Secure" in missing else "MEDIUM"
                findings.append(AuthFinding(
                    target=url, vuln_type="cookie_missing_security_attrs",
                    category="cookie",
                    severity=severity, confidence=80,
                    evidence=f"Session cookie '{name}' missing: {', '.join(missing)}",
                    details={
                        "cookie_name": name,
                        "cookie_attrs": attrs,
                        "missing_attrs": missing,
                    },
                    remediation="Set HttpOnly, Secure, SameSite=Strict/Lax on session cookies",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — CSRF TOKEN + BEARER-IN-URL ANALYSIS (NEW)
# ═════════════════════════════════════════════════════════════════════════════

CSRF_TOKEN_HEADER_HINTS = [
    "x-csrf-token", "x-xsrf-token", "x-csrftoken", "x-requested-with",
]

FORM_RE = re.compile(
    r'<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>.*?</form>',
    re.I | re.DOTALL,
)
FORM_INPUT_RE = re.compile(r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)


def test_csrf_protection(
    urls: list[str], session: RateLimitedSession, auth_on: bool,
) -> list[AuthFinding]:
    """
    Check state-changing forms (POST) for CSRF token presence.

    Only flags forms that look state-changing (login, register, password,
    account, settings) to avoid false positives on search forms.
    """
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    log.info("  Analyzing CSRF protection on state-changing forms...")

    state_urls = [
        u for u in urls
        if re.search(r"/(login|register|signup|password|account|settings|profile|admin)", u, re.I)
    ][:30]

    for url in state_urls:
        resp = session.get(url)
        if not resp:
            continue

        try:
            body = resp.text[:200000]
        except Exception:
            continue

        # Form-level analysis
        for form_match in FORM_RE.finditer(body):
            form_html = form_match.group(0)
            field_names = [m.group(1).lower() for m in FORM_INPUT_RE.finditer(form_html)]
            has_csrf_field = any(
                any(hint in fname for hint in CSRF_FIELD_HINTS)
                for fname in field_names
            )
            if not has_csrf_field:
                findings.append(AuthFinding(
                    target=url, vuln_type="csrf_missing_token_form",
                    category="csrf",
                    severity="MEDIUM", confidence=60,
                    evidence=f"POST form without CSRF token field ({len(field_names)} field(s))",
                    details={"form_fields": field_names[:20]},
                    remediation="Include a per-session CSRF token in all POST forms",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
                break  # one per URL is enough

        # Header-level: some APIs return X-CSRF-Token; check for it
        # (informational — presence means the API is CSRF-aware)
        # Not flagged if absent — header-only CSRF is optional

    # Bearer-token-in-URL detection (bad practice, leaks in logs/referer)
    log.info("  Checking for tokens exposed in URLs...")
    for url in urls[:100]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for k, vals in params.items():
            if any(hint in k.lower() for hint in ("token", "access_token", "jwt", "api_key", "apikey")):
                # Only flag if value looks token-like (long enough, has entropy)
                for v in vals:
                    if len(v) >= 16:
                        findings.append(AuthFinding(
                            target=url, vuln_type="token_in_url", category="general",
                            severity="MEDIUM", confidence=70,
                            evidence=f"Token-like parameter in URL: {k}",
                            details={"param": k, "value_len": len(v)},
                            remediation="Move tokens to Authorization header or POST body",
                            auth_enabled=auth_on, first_seen=now_iso,
                        ))
                        break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[AuthFinding]) -> None:
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
        result = DB.upsert_auth_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} auth finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_auth_tester(
    live_urls_file: Path,
    outdir: Path,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    headers: Optional[dict] = None,
    test_jwt: bool = True,
    test_oauth: bool = True,
    test_saml: bool = True,
    test_general: bool = True,
    test_cookies: bool = True,
    test_csrf: bool = True,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Run authentication testing against every URL in `live_urls_file`.

    Returns the path to `auth_findings.json`.
    """
    start = time.monotonic()

    settings = _auth_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))

    # ── Briefing ────────────────────────────────────────────────────────────
    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  "
             f"timeout={eff_timeout}s")
    log.info(f"           source: MODULE_RATE_LIMITS['auth']")

    hdrs = _target_headers()
    if hdrs:
        log.info(f"  Headers: {len(hdrs)} configured")
        for k, v in list(hdrs.items())[:3]:
            v_short = v[:40] + "…" if len(v) > 40 else v
            log.info(f"           · {k}: {v_short}")
        if len(hdrs) > 3:
            log.info(f"           · ... and {len(hdrs) - 3} more")

    if auth_on:
        log.info(f"  Auth   : ENABLED (request.txt)")
    else:
        log.info(f"  Auth   : disabled")

    phases = []
    if test_jwt:     phases.append("jwt")
    if test_oauth:   phases.append("oauth")
    if test_saml:    phases.append("saml")
    if test_general: phases.append("general")
    if test_cookies: phases.append("cookies")
    if test_csrf:    phases.append("csrf")
    log.info(f"  Phases : {', '.join(phases)}")
    log.info("")

    if not urls:
        log.warning("  No URLs to test — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Session ─────────────────────────────────────────────────────────────
    session = RateLimitedSession(
        rate_limit=eff_rate,
        timeout=eff_timeout,
        auth_enabled=auth_on,
    )

    # ── Phase 1: Discovery ──────────────────────────────────────────────────
    log.info("  Phase 1 — Auth surface discovery")
    endpoints = discover_auth_endpoints(urls)
    for cat, urls_cat in endpoints.items():
        if cat != "all" and urls_cat:
            log.info(f"    {cat:<10}: {len(urls_cat)} endpoint(s)")

    all_findings: list[AuthFinding] = []

    # ── Phase 2: JWT ────────────────────────────────────────────────────────
    if test_jwt:
        log.info("")
        log.info("  Phase 2 — JWT analysis")
        jwt_findings = run_jwt_analysis(urls, session, outdir, auth_on, eff_conc)
        all_findings.extend(jwt_findings)
        log.info(f"    {len(jwt_findings)} JWT finding(s)")

    # ── Phase 3a: OAuth ─────────────────────────────────────────────────────
    if test_oauth and endpoints.get("oauth"):
        log.info("")
        log.info("  Phase 3a — OAuth testing")
        oauth_findings = test_oauth_endpoints(endpoints["oauth"], session, auth_on)
        all_findings.extend(oauth_findings)
        log.info(f"    {len(oauth_findings)} OAuth finding(s)")
        # Write OAuth flat file
        oauth_lines = [
            f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:120]}"
            for f in oauth_findings
        ]
        (outdir / "oauth_candidates.txt").write_text(
            "\n".join(oauth_lines) + ("\n" if oauth_lines else "")
        )

    # ── Phase 3b: SAML ──────────────────────────────────────────────────────
    if test_saml and endpoints.get("saml"):
        log.info("")
        log.info("  Phase 3b — SAML testing")
        saml_findings = test_saml_endpoints(endpoints["saml"], session, auth_on)
        all_findings.extend(saml_findings)
        log.info(f"    {len(saml_findings)} SAML finding(s)")
        saml_lines = [
            f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:120]}"
            for f in saml_findings
        ]
        (outdir / "saml_candidates.txt").write_text(
            "\n".join(saml_lines) + ("\n" if saml_lines else "")
        )

    # ── Phase 4: General ────────────────────────────────────────────────────
    if test_general:
        log.info("")
        log.info("  Phase 4 — General auth bypass candidates")
        general_findings = test_general_auth_bypass(urls, session, auth_on)
        all_findings.extend(general_findings)
        log.info(f"    {len(general_findings)} general finding(s)")

    # ── Phase 5: Cookie security ────────────────────────────────────────────
    if test_cookies:
        log.info("")
        log.info("  Phase 5 — Cookie security analysis")
        cookie_findings = test_cookie_security(urls, session, auth_on)
        all_findings.extend(cookie_findings)
        log.info(f"    {len(cookie_findings)} cookie finding(s)")

    # ── Phase 6: CSRF + tokens-in-URL ───────────────────────────────────────
    if test_csrf:
        log.info("")
        log.info("  Phase 6 — CSRF + token exposure analysis")
        csrf_findings = test_csrf_protection(urls, session, auth_on)
        all_findings.extend(csrf_findings)
        log.info(f"    {len(csrf_findings)} CSRF/token finding(s)")

    # ── Dedupe + sort ───────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[AuthFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    # Flat candidates
    candidates_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.category}\t{f.severity}\t{f.confidence}\t{f.evidence[:160]}"
        for f in deduped
    ]
    (outdir / "auth_candidates.txt").write_text(
        "\n".join(candidates_lines) + ("\n" if candidates_lines else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "headers_count": len(hdrs),
            "test_jwt":      test_jwt,
            "test_oauth":    test_oauth,
            "test_saml":     test_saml,
            "test_general":  test_general,
            "test_cookies":  test_cookies,
            "test_csrf":     test_csrf,
        },
        "totals": {
            "urls_scanned":    len(urls),
            "total_findings":  len(deduped),
            "critical":        by_severity["CRITICAL"],
            "high":            by_severity["HIGH"],
            "medium":          by_severity["MEDIUM"],
            "low":             by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_type":      dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_category":  dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "auth_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync ───────────────────────────────────────────────────────────
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    auth_candidates.txt          {len(deduped):>5} candidate(s)")
    for fname in ("jwt_candidates.txt", "oauth_candidates.txt", "saml_candidates.txt"):
        p = outdir / fname
        if p.exists():
            count = sum(1 for _ in p.open())
            log.info(f"    {fname:<28} {count:>5} finding(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )

    if by_category:
        log.info("  Category : " + " · ".join(
            f"{k}({v})" for k, v in list(by_category.items())[:8]
        ))

    if deduped:
        log.info("")
        log.info("  Top findings:")
        for f in deduped[:10]:
            log.info(f"    [{f.severity:<8}] {f.category:<8} {f.vuln_type:<32} {f.target[:55]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "totals": {
            "urls_scanned": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}, "by_category": {}},
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
    default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus Auth Tester (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--no-jwt", action="store_true")
    parser.add_argument("--no-oauth", action="store_true")
    parser.add_argument("--no-saml", action="store_true")
    parser.add_argument("--no-general", action="store_true")
    parser.add_argument("--no-cookies", action="store_true")
    parser.add_argument("--no-csrf", action="store_true")
    args = parser.parse_args()

    try:
        run_auth_tester(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            test_jwt=not args.no_jwt,
            test_oauth=not args.no_oauth,
            test_saml=not args.no_saml,
            test_general=not args.no_general,
            test_cookies=not args.no_cookies,
            test_csrf=not args.no_csrf,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
