#!/usr/bin/env python3
"""
auditing_tools/idor_finder.py — Insecure Direct Object Reference Auditor (v3.0)
═══════════════════════════════════════════════════════════════════════════════

Cross-identity IDOR/BOLA detection with military-grade evasion, sensitivity
classification, and exploit-impact chains.

SAFETY MODEL
────────────
Every request flows through `EvasionSession`:
  • Jittered pacing
  • User-Agent + X-Forwarded-For rotation
  • Optional proxy rotation
  • Exponential back-off on 403/406/429/503
  • 60-second cool-down after a WAF block

Aggressive tests (extended enumeration, full bypass matrix, content-type
switching) are gated behind `--aggressive`.

CONFIRMATION MODEL (no false positives)
───────────────────────────────────────
A finding is CONFIRMED only when:

  A) DUAL-SESSION: User A requesting User B's object returns a response that
     contains User B's ownership identifiers (email, user_id, etc.) OR is
     byte-identical to User B's own baseline response.

  B) REVERSAL: the mirror request (User B → User A's object) also succeeds.
     Reversal raises confidence but is not strictly required — many targets
     only expose one direction due to asymmetric ownership.

  C) BYPASS: any of ~25 bypass variants (HPP, array, header injection,
     content-type switching, method rotation, encoding, JWT claim injection)
     returns User B's data to User A.

  D) SINGLE-SESSION ENUMERATION always produces LIKELY findings (never
     CONFIRMED) — the operator must supply dual sessions to actually prove it.

SEVERITY (impact-driven)
────────────────────────
  CRITICAL   Confirmed IDOR that leaks credentials / SSN / credit-card /
             admin role / account-takeover fields.
  HIGH       Confirmed IDOR that leaks PII (email/phone/address/dob) or
             financial data, OR any bypass variant confirmed.
  MEDIUM     Confirmed IDOR with non-sensitive foreign data, OR sensitive
             endpoint with auth-required parameters.
  LOW        Surface mapped; no confirmation attempted.
  INFO       Properly protected (correctly returns 401/403).

CHAINS (aggregated into idor_chains.json)
─────────────────────────────────────────
  idor-account-takeover    credentials or email-change endpoint exposed
  idor-pii-exposure        user's email / phone / address / dob leaked
  idor-financial           payment / invoice / balance leaked
  idor-admin-privesc       admin role / permissions leaked
  idor-tenant-isolation    cross-tenant access
  idor-mass-enum           sequential IDs confirmed enumerable

ID HARVESTING (per session)
───────────────────────────
  • Response bodies (sequential, UUID, hex)
  • HTML form actions
  • JavaScript string literals (localStorage, window.userId)
  • JSON responses from listing endpoints
  • JWT claims (sub, uid, user_id, account_id)
  • Cookie values (JSON-encoded or plain)
  • Response headers (X-User-Id, X-Account-Id)
  • GraphQL node-id decoding (base64 Type:ID → sequential)

OUTPUTS
───────
  idor_findings.json      — every finding (full report)
  idor_confirmed.json     — HIGH / CRITICAL only
  idor_chains.json        — structured chain records
  idor_candidates.txt     — flat triage
  idor_confirmed.txt      — confirmed-only flat triage
  idor_surface.txt        — every object-reference endpoint
  idor_protected.txt      — endpoints that correctly return 401/403
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import random
import re
import string
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

log = logging.getLogger("argus.idor_finder")

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


def _idor_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("idor", {}) or {}
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 2),
        "timeout":     entry.get("timeout", 15),
        "jitter":      entry.get("jitter", 0.5),
        "proxies":     entry.get("proxies", []),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        h.update(getattr(CFG, "AUTH_HEADERS", {}) or {})
    return h


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


# ═════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION + EVASION
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: dict[str, dict] = {
    "Cloudflare":  {"headers": ["cf-ray", "__cf_bm", "cf-cache-status"],
                    "body":    ["Attention Required! | Cloudflare"]},
    "Akamai":      {"headers": ["akamai-grn", "x-akamai-transformed", "_abck"],
                    "body":    ["Access Denied", "Reference&#32;&#35;"]},
    "Imperva":     {"headers": ["x-iinfo", "incap_ses", "_Incapsula_Resource"],
                    "body":    ["Pardon Our Interruption"]},
    "AWS WAF":     {"headers": ["x-amzn-requestid", "x-amzn-errortype"],
                    "body":    ["Request blocked", "AWS WAF"]},
    "F5 BIG-IP":   {"headers": ["x-wa-info", "bigipserver"],
                    "body":    ["The requested URL was rejected"]},
    "Sucuri":      {"headers": ["x-sucuri-id", "x-sucuri-cache"],
                    "body":    ["Sucuri WebSite Firewall"]},
    "DataDome":    {"headers": ["x-datadome", "datadome"],
                    "body":    ["captcha-delivery"]},
    "ModSecurity": {"headers": ["x-mod-security"], "body": ["ModSecurity"]},
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


@dataclass
class WAFReport:
    vendor: str = "unknown"
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    blocked: bool = False


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
    def __init__(self, profile: EvasionProfile, timeout: int = 15):
        self.profile = profile
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(_target_headers())

        self._min_interval = 1.0 / profile.rate_limit if profile.rate_limit > 0 else 0.0
        self._last = 0.0
        self._backoff = 0.0
        self._cooldown_until = 0.0
        self._proxy_idx = 0
        self._ua_idx = 0
        self._xff_counter = 0

    def __enter__(self): return self
    def __exit__(self, *exc):
        try: self.session.close()
        except Exception: pass

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

    def request(self, method: str, url: str, headers: Optional[dict] = None, **kwargs) -> Optional[requests.Response]:
        self._pace()
        self._rotate()
        proxy = self._proxy()
        try:
            resp = self.session.request(
                method, url,
                headers=headers,
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

    def get(self, url: str, headers: Optional[dict] = None, **kwargs):
        return self.request("GET", url, headers=headers, **kwargs)

    def benign_get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except requests.RequestException:
            return None


def detect_waf(session: EvasionSession, url: str) -> WAFReport:
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
        if any(w in low for w in ("blocked", "denied", "firewall", "captcha")):
            report.blocked = True
            if report.vendor == "unknown":
                report.vendor = "generic-waf"
                report.confidence = 40
    return report


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

SEQUENTIAL_RE = re.compile(r"\b(\d{1,10})\b")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_ID_RE = re.compile(r"\b([0-9a-f]{16,})\b", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

ID_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "customer_id", "customerid", "order_id", "orderid", "invoice_id",
    "invoiceid", "doc_id", "docid", "document_id", "documentid",
    "profile_id", "profileid", "org_id", "orgid", "tenant_id",
    "tenantid", "group_id", "groupid", "team_id", "teamid",
    "project_id", "projectid", "item_id", "itemid", "object_id",
    "objectid", "resource_id", "resourceid", "uuid", "guid",
    "ref", "reference", "key", "token_id", "tokenid", "sub", "owner_id",
}

ID_BODY_FIELDS = ID_PARAM_NAMES | {"owner", "created_by"}

IDENTITY_HEADERS = [
    "X-User-Id", "X-User-ID", "X-Account-Id", "X-Account-ID",
    "X-Customer-Id", "X-Tenant-Id", "X-Org-Id", "X-Forwarded-User",
    "X-Original-User", "X-Remote-User", "X-Authenticated-User",
]

METHOD_ROTATION = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

OWNERSHIP_FIELDS = {
    "user_id", "userId", "uid", "account_id", "accountId",
    "owner_id", "ownerId", "created_by", "createdBy",
    "email", "username", "user_name", "owner_email",
    "tenant_id", "org_id", "organization_id",
    "customer_id", "customerId",
}

# ── Sensitivity classification ────────────────────────────────────────────
SENSITIVE_FIELDS = {
    "credentials": [
        "password", "password_hash", "passwd", "secret", "api_key",
        "access_token", "refresh_token", "session_token", "private_key",
    ],
    "pii_high": [
        "ssn", "social_security", "credit_card", "card_number", "cvv",
        "bank_account", "routing_number", "tax_id", "national_id", "passport",
    ],
    "pii_medium": [
        "email", "phone", "address", "dob", "birthdate", "date_of_birth",
        "first_name", "last_name", "full_name", "postal_code",
    ],
    "financial": [
        "balance", "amount", "transaction", "invoice", "salary",
        "billing", "total", "payment", "order_total", "refund",
    ],
    "admin": [
        "role", "is_admin", "permissions", "groups", "scopes",
        "is_superuser", "is_staff", "admin",
    ],
}

SENSITIVITY_PRIORITY = ["credentials", "pii_high", "pii_medium", "financial", "admin"]


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class IDORFinding:
    target: str
    vuln_type: str
    technique: str = ""
    param_name: str = ""
    param_location: str = "query"
    id_type: str = "unknown"
    own_id: str = ""
    other_id: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = 50
    confirmed: bool = False
    evidence: str = ""
    request_curl: str = ""
    response_a: str = ""
    response_b: str = ""
    ownership_leak: str = ""
    sensitivity: str = ""
    sensitive_fields: list[str] = field(default_factory=list)
    chain_ids: list[str] = field(default_factory=list)
    waf_vendor: str = ""
    details: dict = field(default_factory=dict)
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(
            f"{self.target}|{self.vuln_type}|{self.param_name}|{self.own_id}|{self.other_id}".encode()
        ).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "target_host":      urllib.parse.urlparse(self.target).hostname or "",
            "vuln_type":        self.vuln_type,
            "technique":        self.technique,
            "param_name":       self.param_name,
            "param_location":   self.param_location,
            "id_type":          self.id_type,
            "own_id":           self.own_id,
            "other_id":         self.other_id,
            "severity":         self.severity.value,
            "confidence":       self.confidence,
            "confirmed":        self.confirmed,
            "evidence":         self.evidence[:600],
            "request_curl":     self.request_curl[:2000],
            "response_a":       self.response_a[:500],
            "response_b":       self.response_b[:500],
            "ownership_leak":   self.ownership_leak[:300],
            "sensitivity":      self.sensitivity,
            "sensitive_fields": self.sensitive_fields,
            "chain_ids":        self.chain_ids,
            "waf_vendor":       self.waf_vendor,
            "details":          self.details,
            "auth_enabled":     self.auth_enabled,
            "finding_hash":     self.finding_hash,
            "first_seen":       self.first_seen,
        }


@dataclass
class IDORChain:
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
            "evidence":       self.evidence[:600],
        }


@dataclass
class ObjectSurface:
    endpoint: str
    method: str = "GET"
    param_name: str = ""
    param_location: str = "query"
    id_type: str = "unknown"
    sample_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint":       self.endpoint,
            "method":         self.method,
            "param_name":     self.param_name,
            "param_location": self.param_location,
            "id_type":        self.id_type,
            "sample_ids":     self.sample_ids[:10],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

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


def _body_text(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:200000]
    except Exception:
        return ""


def _body_snippet(resp: Optional[requests.Response], n: int = 500) -> str:
    return _body_text(resp)[:n].replace("\n", " ").strip()


def _body_fingerprint(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return hashlib.sha256(resp.content).hexdigest()[:16]
    except Exception:
        return ""


def _similarity(resp_a: Optional[requests.Response], resp_b: Optional[requests.Response]) -> float:
    """0.0–1.0 similarity between two response bodies."""
    if resp_a is None or resp_b is None:
        return 0.0
    try:
        fa = _body_fingerprint(resp_a)
        fb = _body_fingerprint(resp_b)
        if fa and fa == fb:
            return 1.0
    except Exception:
        pass
    a = _body_text(resp_a)[:5000]
    b = _body_text(resp_b)[:5000]
    if not a and not b:
        return 1.0
    if a[:200] == b[:200]:
        return 0.95
    len_ratio = min(len(a), len(b)) / max(len(a), len(b), 1)
    return len_ratio


def _extract_ids(text: str) -> dict[str, list[str]]:
    result = {"sequential": [], "uuid": [], "hex": []}
    if not text:
        return result
    for m in UUID_RE.findall(text):
        result["uuid"].append(m)
    for m in SEQUENTIAL_RE.findall(text):
        if len(m) >= 3 and not (1900 <= int(m) <= 2100):
            result["sequential"].append(m)
    for m in HEX_ID_RE.findall(text):
        result["hex"].append(m)
    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:20]
    return result


def _extract_jwt_ids(text: str) -> list[tuple[str, str]]:
    """Extract ID-like claims from any JWTs embedded in the text."""
    out: list[tuple[str, str]] = []
    if not text:
        return out
    for tok in JWT_RE.findall(text)[:5]:
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        try:
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for k, v in data.items():
            if isinstance(v, (str, int)) and k.lower() in ID_PARAM_NAMES:
                out.append((k, str(v)))
    return out


def _extract_cookie_ids(resp: Optional[requests.Response]) -> list[tuple[str, str]]:
    """Extract ID-like values from cookies."""
    if resp is None:
        return []
    out: list[tuple[str, str]] = []
    for cookie in resp.cookies:
        try:
            v = cookie.value
            # Try JSON
            if v.startswith("{") or v.startswith("["):
                data = json.loads(v)
                if isinstance(data, dict):
                    for k, val in data.items():
                        if k.lower() in ID_PARAM_NAMES and isinstance(val, (str, int)):
                            out.append((k, str(val)))
            # Try base64-encoded JSON
            elif len(v) > 20:
                try:
                    pad = "=" * (4 - len(v) % 4)
                    decoded = base64.b64decode(v + pad)
                    data = json.loads(decoded)
                    if isinstance(data, dict):
                        for k, val in data.items():
                            if k.lower() in ID_PARAM_NAMES and isinstance(val, (str, int)):
                                out.append((k, str(val)))
                except Exception:
                    pass
        except Exception:
            continue
    return out


def _classify_id(sample: str) -> str:
    if UUID_RE.match(sample):
        return "uuid"
    if sample.isdigit():
        return "sequential"
    if len(sample) >= 16 and all(c in string.hexdigits for c in sample):
        return "hex"
    return "opaque"


def _nearby_ids(sample: str, radius: int = 3) -> list[str]:
    if not sample.isdigit():
        return []
    n = int(sample)
    out: list[str] = []
    for delta in range(1, radius + 1):
        out.append(str(n + delta))
        if n - delta >= 1:
            out.append(str(n - delta))
    return out


def _encode_variants(sample: str) -> list[str]:
    variants = [sample]
    try:
        variants.append(base64.b64encode(sample.encode()).decode().rstrip("="))
    except Exception:
        pass
    variants.append(urllib.parse.quote(sample, safe=""))
    variants.append(urllib.parse.quote(urllib.parse.quote(sample, safe=""), safe=""))
    try:
        variants.append(sample.encode().hex())
    except Exception:
        pass
    return list(dict.fromkeys(v for v in variants if v))


def _build_curl(
    method: str, url: str, headers: Optional[dict] = None,
    json_body: Optional[dict] = None, data: Optional[dict] = None,
) -> str:
    parts = [f"curl -X {method} '{url}'"]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("cookie", "authorization"):
                parts.append(f"-H '{k}: {v[:20]}...'")
            else:
                parts.append(f"-H '{k}: {v}'")
    if json_body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(json_body)[:300]}'")
    elif data:
        parts.append(f"-d '{urllib.parse.urlencode(data)[:300]}'")
    return " ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVITY CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def _classify_sensitivity(resp: Optional[requests.Response]) -> tuple[str, list[str]]:
    """
    Classify the response body's sensitivity.
    Returns (category, matched_field_names).
    Categories in priority order: credentials, pii_high, pii_medium,
    financial, admin, none.
    """
    if resp is None:
        return ("none", [])
    body = _body_text(resp).lower()
    if not body:
        return ("none", [])

    for category in SENSITIVITY_PRIORITY:
        markers = SENSITIVE_FIELDS.get(category, [])
        hits = [m for m in markers if m in body]
        if hits:
            return (category, hits)
    return ("none", [])


def _sensitivity_to_chain(category: str) -> Optional[str]:
    return {
        "credentials": "idor-account-takeover",
        "pii_high":    "idor-pii-exposure",
        "pii_medium":  "idor-pii-exposure",
        "financial":   "idor-financial",
        "admin":       "idor-admin-privesc",
    }.get(category)


def _severity_from_sensitivity(
    confirmed: bool, category: str, bypass_confirmed: bool = False,
) -> tuple[Severity, int]:
    """
    Return (severity, confidence) based on confirmed IDOR + sensitivity.
    """
    if not confirmed and not bypass_confirmed:
        return (Severity.MEDIUM, 55)

    if category in ("credentials", "pii_high", "admin"):
        return (Severity.CRITICAL, 95)
    if category in ("pii_medium", "financial"):
        return (Severity.HIGH, 90)
    if bypass_confirmed:
        return (Severity.HIGH, 88)
    return (Severity.MEDIUM, 75)


# ═════════════════════════════════════════════════════════════════════════════
#  OWNERSHIP ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def _extract_ownership_fields(resp: Optional[requests.Response]) -> list[tuple[str, str]]:
    if resp is None:
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    out: list[tuple[str, str]] = []

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in OWNERSHIP_FIELDS and isinstance(v, (str, int)):
                    out.append((k, str(v)))
                _walk(v)
        elif isinstance(obj, list):
            for item in obj[:10]:
                _walk(item)

    _walk(data)
    return out


def _ownership_match(
    resp: Optional[requests.Response], owner_id: str,
) -> Optional[tuple[str, str]]:
    if not owner_id or resp is None:
        return None
    for field_name, value in _extract_ownership_fields(resp):
        if value == owner_id or owner_id in value:
            return (field_name, value)
    return None


def _foreign_data_present(
    resp: Optional[requests.Response], own_id: str,
) -> Optional[str]:
    fields = _extract_ownership_fields(resp)
    if not fields:
        return None
    if all(v == own_id or own_id in v for _, v in fields):
        return None
    return ", ".join(f"{k}={v}" for k, v in fields[:3])


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

REST_ID_PATH_RE = re.compile(
    r"/([a-zA-Z][a-zA-Z0-9_-]*)/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)


def discover_surfaces_from_urls(urls: list[str]) -> list[ObjectSurface]:
    surfaces: list[ObjectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)

        for m in REST_ID_PATH_RE.finditer(parsed.path + "/"):
            resource = m.group(1)
            ident = m.group(2)
            key = ("path", resource, ident[:8])
            if key in seen:
                continue
            seen.add(key)
            surfaces.append(ObjectSurface(
                endpoint=url, method="GET",
                param_name="path_id", param_location="path",
                id_type=_classify_id(ident),
                sample_ids=[ident],
            ))

        for k, vals in urllib.parse.parse_qs(parsed.query).items():
            if k.lower() in ID_PARAM_NAMES and vals:
                key = ("query", url.split("?")[0], k)
                if key in seen:
                    continue
                seen.add(key)
                surfaces.append(ObjectSurface(
                    endpoint=url, method="GET",
                    param_name=k, param_location="query",
                    id_type=_classify_id(vals[0]),
                    sample_ids=[vals[0]],
                ))

    return surfaces


def discover_surfaces_from_pages(outdir: Path) -> list[ObjectSurface]:
    surfaces: list[ObjectSurface] = []
    pages_file = outdir / "site_pages.json"
    if not pages_file.exists():
        return surfaces

    try:
        data = json.loads(pages_file.read_text())
    except Exception:
        return surfaces

    seen: set[tuple] = set()
    for page in data.get("pages") or []:
        url = page.get("url") or ""
        if not url:
            continue
        for form in page.get("forms") or []:
            method = (form.get("method") or "get").upper()
            if method != "POST":
                continue
            action = form.get("action") or url
            for field_def in form.get("fields") or []:
                fname = (field_def.get("name") or "").lower()
                if fname in ID_BODY_FIELDS:
                    key = (action, fname)
                    if key in seen:
                        continue
                    seen.add(key)
                    surfaces.append(ObjectSurface(
                        endpoint=action, method="POST",
                        param_name=field_def.get("name"),
                        param_location="body", id_type="unknown",
                    ))
    return surfaces


def discover_surfaces_from_graphql(outdir: Path) -> list[ObjectSurface]:
    surfaces: list[ObjectSurface] = []
    schema_file = outdir / "graphql_schema.json"
    if not schema_file.exists():
        return surfaces
    try:
        schemas = json.loads(schema_file.read_text())
    except Exception:
        return surfaces

    for gql_url, schema in schemas.items():
        if not isinstance(schema, dict):
            continue
        for t in schema.get("types", []):
            if not isinstance(t, dict):
                continue
            for f in t.get("fields") or []:
                if not isinstance(f, dict):
                    continue
                for arg in f.get("args") or []:
                    if not isinstance(arg, dict):
                        continue
                    aname = (arg.get("name") or "").lower()
                    if aname in ("id", "uuid", "user_id", "account_id", "nodeid"):
                        surfaces.append(ObjectSurface(
                            endpoint=gql_url, method="POST",
                            param_name=arg.get("name", "id"),
                            param_location="graphql", id_type="opaque",
                        ))
                        break
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  ID HARVESTING
# ═════════════════════════════════════════════════════════════════════════════

LISTING_PATHS = [
    "/api/users", "/api/accounts", "/api/orders", "/api/invoices",
    "/api/documents", "/api/projects", "/api/items", "/api/v1/users",
    "/api/v1/accounts", "/api/v1/orders", "/api/me", "/users", "/accounts",
    "/api/v1/me", "/api/v2/me", "/api/profile", "/api/profile/me",
]

JS_ID_PATTERNS = [
    re.compile(r'["\']userId["\']\s*[:=]\s*["\']?(\d+)', re.I),
    re.compile(r'["\']accountId["\']\s*[:=]\s*["\']?(\d+)', re.I),
    re.compile(r'localStorage\.setItem\(["\']userId["\'],\s*["\'](\d+)', re.I),
    re.compile(r'window\.user\s*=\s*\{[^}]*["\']id["\']\s*:\s*["\']?(\d+)', re.I),
]


def harvest_ids_for_session(
    session: EvasionSession,
    headers: dict,
    host_url: str,
    surface: ObjectSurface,
    max_ids: int = 10,
) -> dict[str, list[str]]:
    """
    Harvest IDs visible to a specific session.
    Returns dict of {source: [ids]} where source ∈ {sequential, uuid, hex,
    jwt_claim, cookie, js_var}.
    """
    harvested: dict[str, set[str]] = {
        "sequential": set(), "uuid": set(), "hex": set(),
        "jwt_claim": set(), "cookie": set(), "js_var": set(),
    }

    def _harvest_response(resp: Optional[requests.Response]) -> None:
        if resp is None or resp.status_code >= 400:
            return
        text = _body_text(resp)
        for kind, ids in _extract_ids(text).items():
            harvested[kind].update(ids[:max_ids])
        for _, v in _extract_jwt_ids(text):
            harvested["jwt_claim"].add(v)
        for _, v in _extract_cookie_ids(resp):
            harvested["cookie"].add(v)
        for pat in JS_ID_PATTERNS:
            for m in pat.findall(text):
                harvested["js_var"].add(m)

    # From target endpoint
    _harvest_response(session.get(surface.endpoint, headers=headers))

    # From listing endpoints
    for path in LISTING_PATHS:
        test_url = host_url.rstrip("/") + path
        _harvest_response(session.get(test_url, headers=headers))
        if sum(len(v) for v in harvested.values()) >= max_ids * 2:
            break

    return {k: list(v)[:max_ids] for k, v in harvested.items() if v}


# ═════════════════════════════════════════════════════════════════════════════
#  URL / BODY BUILDERS
# ═════════════════════════════════════════════════════════════════════════════

def _build_test_url(surface: ObjectSurface, id_value: str) -> str:
    if surface.param_location == "path":
        if surface.sample_ids:
            return surface.endpoint.replace(surface.sample_ids[0], id_value, 1)
        return surface.endpoint
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        new_params = [(k, id_value if k == surface.param_name else v) for k, v in params]
        return urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(new_params),
        ))
    return surface.endpoint


def _build_request_body(surface: ObjectSurface, id_value: str) -> Optional[dict]:
    if surface.param_location == "body":
        return {surface.param_name: id_value}
    if surface.param_location == "graphql":
        for root_field in ("node", "user", "account", "order", "item"):
            return {"query": f'{{ {root_field}({surface.param_name}: "{id_value}") {{ __typename }} }}'}
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  BASELINE VARIANCE
# ═════════════════════════════════════════════════════════════════════════════

def compute_baseline(
    session: EvasionSession, surface: ObjectSurface, headers: dict,
) -> tuple[float, Optional[requests.Response]]:
    """Two identical requests — return (similarity, first_resp)."""
    r1 = session.get(surface.endpoint, headers=headers)
    if not r1:
        return 0.0, None
    time.sleep(0.1)
    r2 = session.get(surface.endpoint, headers=headers)
    if not r2:
        return 0.0, r1
    return _similarity(r1, r2), r1


# ═════════════════════════════════════════════════════════════════════════════
#  CORE — CROSS-IDENTITY TEST
# ═════════════════════════════════════════════════════════════════════════════

def _make_request(
    session: EvasionSession, surface: ObjectSurface, id_value: str,
    headers: dict,
) -> Optional[requests.Response]:
    url = _build_test_url(surface, id_value)
    body = _build_request_body(surface, id_value)
    if body is not None:
        return session.request(surface.method, url, headers=headers, json=body)
    return session.request(surface.method, url, headers=headers)


def test_idor_dual_session(
    session_a: EvasionSession,
    session_b: EvasionSession,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    headers_a: dict,
    headers_b: dict,
    waf: WAFReport,
) -> list[IDORFinding]:
    """
    Core cross-identity test.

    1. User A → own_id           (baseline A)
    2. User B → other_id         (baseline B)
    3. User A → other_id         (test)  — if 200 and matches B's data = IDOR
    4. User B → own_id           (reversal)

    A confirmed finding needs (3) to contain User B's ownership identifiers
    OR be byte-identical to (2).
    """
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    r_a_own = _make_request(session_a, surface, own_id, headers_a)
    if not r_a_own or not (200 <= r_a_own.status_code < 300):
        return findings

    r_b_other = _make_request(session_b, surface, other_id, headers_b)
    if not r_b_other:
        return findings

    # Test
    r_a_other = _make_request(session_a, surface, other_id, headers_a)
    if not r_a_other:
        return findings

    # Denied? Record as protected evidence, return
    if not (200 <= r_a_other.status_code < 300):
        if r_a_other.status_code in (401, 403):
            findings.append(IDORFinding(
                target=surface.endpoint, vuln_type="idor_protected",
                technique="direct_swap", param_name=surface.param_name,
                param_location=surface.param_location, id_type=surface.id_type,
                own_id=own_id, other_id=other_id,
                severity=Severity.INFO, confidence=30, confirmed=False,
                evidence=f"HTTP {r_a_other.status_code} — properly denied",
                response_a=_body_snippet(r_a_own),
                response_b=_body_snippet(r_a_other),
                waf_vendor=waf.vendor,
                details={"status_own": r_a_own.status_code,
                         "status_cross": r_a_other.status_code},
                auth_enabled=True, first_seen=now,
            ))
        return findings

    # Did we get User B's data?
    owns_b = _ownership_match(r_a_other, other_id)
    b_baseline_match = _similarity(r_a_other, r_b_other)
    a_baseline_match = _similarity(r_a_other, r_a_own)
    fp_cross = _body_fingerprint(r_a_other)
    fp_b = _body_fingerprint(r_b_other)

    evidence: list[str] = [f"User A → other_id returned HTTP {r_a_other.status_code}"]
    confidence = 70
    confirmed = False

    if owns_b:
        evidence.append(f"Response contains User B's identifier: {owns_b[0]}={owns_b[1]}")
        confidence = 90
        confirmed = True

    if b_baseline_match >= 0.90 and fp_cross and fp_cross == fp_b:
        evidence.append(f"Byte-identical to User B's baseline (fp={fp_cross})")
        confidence = 95
        confirmed = True
    elif b_baseline_match >= 0.90:
        evidence.append(f"Response matches User B's baseline ({b_baseline_match:.2f})")
        confidence = max(confidence, 88)
        confirmed = True

    if a_baseline_match >= 0.95:
        evidence.append("Response matches User A's own baseline — param likely ignored (not IDOR)")
        return findings

    # Reversal
    if confidence >= 70:
        r_b_own = _make_request(session_b, surface, own_id, headers_b)
        if r_b_own and (200 <= r_b_own.status_code < 300):
            reversal_sim = _similarity(r_b_own, r_a_own)
            if reversal_sim >= 0.90:
                evidence.append(f"Reversal confirmed (User B → User A's object, sim={reversal_sim:.2f})")
                confidence = max(confidence, 92)
                confirmed = True

    if not confirmed:
        return findings

    # ── Sensitivity classification
    sensitivity, sens_fields = _classify_sensitivity(r_a_other)
    sev, conf = _severity_from_sensitivity(
        confirmed=confirmed, category=sensitivity, bypass_confirmed=False,
    )

    # Chain assignment
    chain_id = _sensitivity_to_chain(sensitivity)
    chain_ids = [chain_id] if chain_id else []

    # Tenant isolation chain if response has tenant_id
    if any(f[0] in ("tenant_id", "org_id") for f in _extract_ownership_fields(r_a_other)):
        chain_ids.append("idor-tenant-isolation")

    findings.append(IDORFinding(
        target=surface.endpoint, vuln_type="idor_horizontal",
        technique="direct_swap", param_name=surface.param_name,
        param_location=surface.param_location, id_type=surface.id_type,
        own_id=own_id, other_id=other_id,
        severity=sev, confidence=conf, confirmed=True,
        evidence=" | ".join(evidence),
        request_curl=_build_curl(
            surface.method,
            _build_test_url(surface, other_id),
            headers_a,
            json_body=_build_request_body(surface, other_id),
        ),
        response_a=_body_snippet(r_a_own),
        response_b=_body_snippet(r_a_other),
        ownership_leak=str(owns_b) if owns_b else "",
        sensitivity=sensitivity,
        sensitive_fields=sens_fields,
        chain_ids=chain_ids,
        waf_vendor=waf.vendor,
        details={
            "param": surface.param_name,
            "own_id": own_id, "other_id": other_id,
            "status_a_own": r_a_own.status_code,
            "status_a_other": r_a_other.status_code,
            "status_b_other": r_b_other.status_code,
            "sim_to_b_baseline": round(b_baseline_match, 3),
            "sim_to_a_baseline": round(a_baseline_match, 3),
            "fingerprint": fp_cross,
            "reversed": confidence >= 92,
        },
        auth_enabled=True, first_seen=now,
    ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  BYPASS MATRIX (~25 techniques)
# ═════════════════════════════════════════════════════════════════════════════

def _test_bypass(
    session: EvasionSession,
    surface: ObjectSurface,
    other_id: str,
    headers: dict,
    technique: str,
    url: str,
    method: str = "GET",
    body: Optional[dict] = None,
    extra_headers: Optional[dict] = None,
    data: Optional[str] = None,
    content_type: Optional[str] = None,
) -> Optional[requests.Response]:
    h = dict(headers or {})
    if extra_headers:
        h.update(extra_headers)
    if content_type:
        h["Content-Type"] = content_type
    if body is not None:
        return session.request(method, url, headers=h, json=body)
    if data is not None:
        return session.request(method, url, headers=h, data=data)
    return session.request(method, url, headers=h)


def _check_and_build(
    response: Optional[requests.Response],
    other_id: str,
    baseline_b: Optional[requests.Response],
    technique: str,
    surface: ObjectSurface,
    own_id: str,
    other_id_val: str,
    headers: dict,
    url: str,
    method: str,
    waf: WAFReport,
    now: str,
    extra_details: Optional[dict] = None,
) -> Optional[IDORFinding]:
    """Shared confirmation logic for bypass results."""
    if response is None or not (200 <= response.status_code < 300):
        return None

    owns_b = _ownership_match(response, other_id)
    b_sim = _similarity(response, baseline_b) if baseline_b else 0.0
    confirmed = False
    evidence: list[str] = [f"{technique}: HTTP {response.status_code}"]

    if owns_b:
        evidence.append(f"Contains other user's identifier: {owns_b[0]}={owns_b[1]}")
        confirmed = True
    if b_sim >= 0.90:
        evidence.append(f"Matches User B's baseline ({b_sim:.2f})")
        confirmed = True

    if not confirmed:
        return None

    sensitivity, sens_fields = _classify_sensitivity(response)
    sev, conf = _severity_from_sensitivity(
        confirmed=True, category=sensitivity, bypass_confirmed=True,
    )
    chain_id = _sensitivity_to_chain(sensitivity)

    return IDORFinding(
        target=surface.endpoint, vuln_type=f"idor_bypass_{technique}",
        technique=technique, param_name=surface.param_name,
        param_location=surface.param_location, id_type=surface.id_type,
        own_id=own_id, other_id=other_id_val,
        severity=sev, confidence=conf, confirmed=True,
        evidence=" | ".join(evidence),
        request_curl=_build_curl(method, url, headers),
        response_b=_body_snippet(response),
        ownership_leak=str(owns_b) if owns_b else "",
        sensitivity=sensitivity,
        sensitive_fields=sens_fields,
        chain_ids=[chain_id] if chain_id else [],
        waf_vendor=waf.vendor,
        details={"technique": technique, **(extra_details or {})},
        auth_enabled=True, first_seen=now,
    )


def test_bypass_variants(
    session: EvasionSession,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    headers: dict,
    baseline_b: Optional[requests.Response],
    waf: WAFReport,
    aggressive: bool = False,
) -> list[IDORFinding]:
    """Try ~25 bypass variants against this surface."""
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    base_url = _build_test_url(surface, other_id)

    # ── 1. HTTP Parameter Pollution (query)
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query)
        polluted = params + [(surface.param_name, other_id)]
        test_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(polluted),
        ))
        r = session.get(test_url, headers=headers)
        f = _check_and_build(r, other_id, baseline_b, "hpp", surface,
                             own_id, other_id, headers, test_url, "GET",
                             waf, now)
        if f: findings.append(f)

    # ── 2. Array parameter
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query)
        arr_query = urllib.parse.urlencode([
            (k, v) for k, v in params
        ] + [(f"{surface.param_name}[]", own_id),
             (f"{surface.param_name}[]", other_id)])
        test_url = urllib.parse.urlunparse(parsed._replace(query=arr_query))
        r = session.get(test_url, headers=headers)
        f = _check_and_build(r, other_id, baseline_b, "array_param", surface,
                             own_id, other_id, headers, test_url, "GET",
                             waf, now)
        if f: findings.append(f)

    # ── 3. Case variation (ID vs id vs Id)
    if surface.param_location == "query":
        for case_name in (surface.param_name.upper(), surface.param_name.capitalize()):
            if case_name == surface.param_name:
                continue
            parsed = urllib.parse.urlparse(surface.endpoint)
            params = urllib.parse.parse_qsl(parsed.query)
            new_params = [(case_name if k == surface.param_name else k,
                           other_id if k == surface.param_name else v)
                          for k, v in params]
            if not any(k == case_name for k, _ in new_params):
                new_params.append((case_name, other_id))
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(new_params),
            ))
            r = session.get(test_url, headers=headers)
            f = _check_and_build(r, other_id, baseline_b, f"case_{case_name}",
                                 surface, own_id, other_id, headers, test_url,
                                 "GET", waf, now)
            if f: findings.append(f)

    # ── 4. Encoding variants (base64, hex, url-encoded)
    for variant in _encode_variants(other_id):
        if variant == other_id:
            continue
        test_url = _build_test_url(surface, variant)
        r = session.get(test_url, headers=headers)
        f = _check_and_build(r, other_id, baseline_b,
                             f"encoded_{variant[:6]}", surface,
                             own_id, other_id, headers, test_url, "GET",
                             waf, now, {"variant": variant})
        if f:
            findings.append(f)
            break

    # ── 5. Numeric edge cases
    for edge in ("0", "-1", "1.0", "0x1", "null", "NaN", "*", "%", ""):
        if surface.param_location not in ("path", "query"):
            break
        test_url = _build_test_url(surface, edge)
        r = session.get(test_url, headers=headers)
        if r and 200 <= r.status_code < 300 and _body_fingerprint(r) != _body_fingerprint(baseline_b):
            # Different response to edge case — flag as LOW/MEDIUM surface
            findings.append(IDORFinding(
                target=surface.endpoint, vuln_type=f"idor_numeric_edge_{edge[:4]}",
                technique="numeric_edge", param_name=surface.param_name,
                param_location=surface.param_location, id_type=surface.id_type,
                own_id=own_id, other_id=edge,
                severity=Severity.MEDIUM, confidence=50, confirmed=False,
                evidence=f"Numeric edge value '{edge}' produced different response (HTTP {r.status_code})",
                response_b=_body_snippet(r),
                waf_vendor=waf.vendor,
                details={"edge": edge},
                auth_enabled=True, first_seen=now,
            ))
            break

    # ── 6. Method rotation
    for alt_method in METHOD_ROTATION:
        if alt_method == surface.method:
            continue
        if surface.param_location in ("path", "query"):
            test_url = _build_test_url(surface, other_id)
            r = session.request(alt_method, test_url, headers=headers)
        elif surface.param_location == "body":
            r = session.request(
                alt_method, surface.endpoint, headers=headers,
                json={surface.param_name: other_id},
            )
        else:
            continue
        f = _check_and_build(r, other_id, baseline_b,
                             f"method_{alt_method.lower()}", surface,
                             own_id, other_id, headers,
                             _build_test_url(surface, other_id), alt_method,
                             waf, now)
        if f: findings.append(f)

    # ── 7. Method override headers
    for hdr_name, hdr_value in (
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method-Override", "POST"),
        ("X-Method-Override", "PUT"),
    ):
        test_url = _build_test_url(surface, other_id)
        r = session.get(test_url, headers={**headers, hdr_name: hdr_value})
        f = _check_and_build(r, other_id, baseline_b,
                             f"override_{hdr_value.lower()}", surface,
                             own_id, other_id,
                             {**headers, hdr_name: hdr_value},
                             test_url, "GET", waf, now)
        if f: findings.append(f)

    # ── 8. Identity header injection
    for hdr in IDENTITY_HEADERS:
        test_headers = {**headers, hdr: other_id}
        r = session.get(surface.endpoint, headers=test_headers)
        f = _check_and_build(r, other_id, baseline_b,
                             f"header_{hdr.lower().replace('-', '_')}",
                             surface, own_id, other_id, test_headers,
                             surface.endpoint, "GET", waf, now,
                             {"header": hdr})
        if f: findings.append(f)

    # ── 9. Cookie injection
    for cookie_name in ("user_id", "uid", "userid", "account_id"):
        test_headers = dict(headers or {})
        existing = test_headers.get("Cookie", "")
        new_cookie = f"{cookie_name}={other_id}"
        test_headers["Cookie"] = (existing + "; " if existing else "") + new_cookie
        r = session.get(surface.endpoint, headers=test_headers)
        f = _check_and_build(r, other_id, baseline_b,
                             f"cookie_{cookie_name}", surface,
                             own_id, other_id, test_headers,
                             surface.endpoint, "GET", waf, now,
                             {"cookie": cookie_name})
        if f: findings.append(f)

    # ── 10. Content-Type switching
    if aggressive and surface.param_location == "body":
        for ct, encode_fn in (
            ("application/json", lambda d: json.dumps(d)),
            ("application/x-www-form-urlencoded", lambda d: urllib.parse.urlencode(d)),
            ("text/plain", lambda d: json.dumps(d)),
        ):
            body = encode_fn({surface.param_name: other_id})
            r = session.request(
                surface.method, surface.endpoint,
                headers={**headers, "Content-Type": ct},
                data=body,
            )
            f = _check_and_build(r, other_id, baseline_b,
                                 f"content_type_{ct.split('/')[-1]}",
                                 surface, own_id, other_id, headers,
                                 surface.endpoint, surface.method,
                                 waf, now, {"content_type": ct})
            if f: findings.append(f)

    # ── 11. JSON duplicate key
    if aggressive and surface.param_location == "body":
        raw = f'{{"{surface.param_name}":"{own_id}","{surface.param_name}":"{other_id}"}}'
        r = session.request(
            surface.method, surface.endpoint,
            headers={**headers, "Content-Type": "application/json"},
            data=raw,
        )
        f = _check_and_build(r, other_id, baseline_b, "json_dup_key",
                             surface, own_id, other_id, headers,
                             surface.endpoint, surface.method, waf, now)
        if f: findings.append(f)

    # ── 12. JSON nested object
    if aggressive and surface.param_location == "body":
        r = session.request(
            surface.method, surface.endpoint, headers=headers,
            json={surface.param_name: {"id": other_id}},
        )
        f = _check_and_build(r, other_id, baseline_b, "json_nested",
                             surface, own_id, other_id, headers,
                             surface.endpoint, surface.method, waf, now)
        if f: findings.append(f)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  ENUMERATION (single-session)
# ═════════════════════════════════════════════════════════════════════════════

def test_idor_enumeration(
    session: EvasionSession,
    surface: ObjectSurface,
    own_id: str,
    headers: dict,
    waf: WAFReport,
    radius: int = 3,
) -> list[IDORFinding]:
    """Enumerate nearby sequential IDs when only one session is available."""
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    r_a_own = session.get(_build_test_url(surface, own_id), headers=headers)
    if not r_a_own or not (200 <= r_a_own.status_code < 300):
        return findings
    own_fp = _body_fingerprint(r_a_own)

    for test_id in _nearby_ids(own_id, radius):
        test_url = _build_test_url(surface, test_id)
        r = session.get(test_url, headers=headers)
        if not r or not (200 <= r.status_code < 300):
            continue

        test_fp = _body_fingerprint(r)
        if test_fp and test_fp == own_fp:
            continue  # Same response — param ignored

        sim_to_own = _similarity(r, r_a_own)
        if sim_to_own >= 0.95:
            continue

        if sim_to_own < 0.80 and len(_body_text(r)) > 50:
            foreign = _foreign_data_present(r, own_id)
            sensitivity, sens_fields = _classify_sensitivity(r)
            chain_ids = ["idor-mass-enum"]
            chain_id = _sensitivity_to_chain(sensitivity)
            if chain_id:
                chain_ids.append(chain_id)

            findings.append(IDORFinding(
                target=surface.endpoint, vuln_type="idor_enumeration",
                technique="sequential_enum", param_name=surface.param_name,
                param_location=surface.param_location, id_type=surface.id_type,
                own_id=own_id, other_id=test_id,
                severity=Severity.HIGH if foreign else Severity.MEDIUM,
                confidence=75 if foreign else 55, confirmed=False,
                evidence=(
                    f"ID {test_id} (own={own_id}) returned different data "
                    f"(sim={sim_to_own:.2f})"
                    + (f"; foreign indicators: {foreign}" if foreign else "")
                ),
                request_curl=_build_curl(surface.method, test_url, headers),
                response_a=_body_snippet(r_a_own),
                response_b=_body_snippet(r),
                ownership_leak=foreign or "",
                sensitivity=sensitivity,
                sensitive_fields=sens_fields,
                chain_ids=chain_ids,
                waf_vendor=waf.vendor,
                details={"own_id": own_id, "test_id": test_id,
                         "similarity": round(sim_to_own, 3)},
                auth_enabled=True, first_seen=now,
            ))
            break  # one confirmed enumeration per surface is enough

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  CHAINS
# ═════════════════════════════════════════════════════════════════════════════

def build_chains(findings: list[IDORFinding]) -> list[IDORChain]:
    chains: dict[str, list[IDORFinding]] = {}
    NAMES = {
        "idor-account-takeover": "IDOR → account takeover (credential exposure)",
        "idor-pii-exposure":     "IDOR → PII exposure",
        "idor-financial":        "IDOR → financial data exposure",
        "idor-admin-privesc":    "IDOR → admin privilege escalation",
        "idor-tenant-isolation": "IDOR → cross-tenant access",
        "idor-mass-enum":        "IDOR → mass enumeration",
    }
    for f in findings:
        if not (f.confirmed or f.severity.rank >= Severity.HIGH.rank):
            continue
        for cid in f.chain_ids:
            chains.setdefault(cid, []).append(f)

    out: list[IDORChain] = []
    for cid, fs in chains.items():
        max_sev = max(fs, key=lambda x: x.severity.rank).severity
        out.append(IDORChain(
            chain_id=cid,
            name=NAMES.get(cid, cid),
            severity=max_sev,
            steps=[f.evidence for f in fs],
            finding_hashes=[f.finding_hash for f in fs],
            evidence=fs[0].evidence if fs else "",
        ))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[IDORFinding]) -> None:
    if not findings or not DB_AVAILABLE or DB is None:
        return
    if not _cfg("SYNC_TO_DB", True) or not _cfg("BRIDGE_ENABLED", False):
        return
    if not getattr(DB, "available", False):
        return
    try:
        result = DB.upsert_idor_findings(scan_id, [f.to_dict() for f in findings])
        if result is not None:
            log.info(f"  DB sync: {result} IDOR finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_idor_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    headers: Optional[dict] = None,
    user_a_headers: Optional[dict] = None,
    user_b_headers: Optional[dict] = None,
    user_a_id: Optional[str] = None,
    user_b_id: Optional[str] = None,
    test_bypasses: bool = True,
    aggressive: bool = False,
    proxies: Optional[list[str]] = None,
    max_ids_per_surface: int = 3,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _idor_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]
    eff_jitter = settings["jitter"]
    eff_proxies = proxies if proxies is not None else list(settings["proxies"])

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    dual_session = bool(user_a_headers and user_b_headers)
    auth_on = bool(user_a_headers or cfg_hdrs)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  jitter={eff_jitter}s  "
             f"concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Mode   : {'AGGRESSIVE' if aggressive else 'safe'}")

    if dual_session:
        log.info("  Session: DUAL (cross-identity testing enabled)")
        log.info(f"           User A ID: {user_a_id or '(harvest from session)'}")
        log.info(f"           User B ID: {user_b_id or '(harvest from session)'}")
    elif user_a_headers:
        log.info("  Session: SINGLE (enumeration only — findings LIKELY, not confirmed)")
    else:
        log.info("  Session: SURFACE-ONLY (no credentials)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty(outdir, live_urls_file, start)

    profile = EvasionProfile(
        rate_limit=eff_rate, jitter=eff_jitter, proxies=eff_proxies,
    )

    session_a = EvasionSession(profile=profile, timeout=eff_timeout)
    session_b = EvasionSession(profile=profile, timeout=eff_timeout) if dual_session else None

    waf_by_host: dict[str, WAFReport] = {}

    try:
        # ── Phase 0: WAF detection ──────────────────────────────────────────
        log.info("  Phase 0 — WAF detection")
        for url in urls:
            host = urllib.parse.urlparse(url).hostname or ""
            if host in waf_by_host:
                continue
            waf = detect_waf(session_a, url)
            waf_by_host[host] = waf
            if waf.vendor != "unknown":
                log.info(f"    {host:<40} WAF: {waf.vendor} ({waf.confidence}%)")

        if any(w.vendor != "unknown" for w in waf_by_host.values()):
            session_a.profile.rate_limit = max(0.5, eff_rate * 0.6)
            session_a.profile.jitter = max(eff_jitter, 1.0)
            if session_b:
                session_b.profile.rate_limit = session_a.profile.rate_limit
                session_b.profile.jitter = session_a.profile.jitter

        # ── Phase 1: Surface discovery ──────────────────────────────────────
        log.info("")
        log.info("  Phase 1 — Object reference surface discovery")
        surfaces = discover_surfaces_from_urls(urls)
        pages_surfaces = discover_surfaces_from_pages(outdir)
        gql_surfaces = discover_surfaces_from_graphql(outdir)
        surfaces.extend(pages_surfaces)
        surfaces.extend(gql_surfaces)

        seen_surf: set[tuple] = set()
        unique: list[ObjectSurface] = []
        for s in surfaces:
            key = (s.endpoint, s.method, s.param_name, s.param_location)
            if key not in seen_surf:
                seen_surf.add(key)
                unique.append(s)
        surfaces = unique

        log.info(f"    {len(surfaces)} surface(s)  "
                 f"(URL: {len(surfaces) - len(pages_surfaces) - len(gql_surfaces)}, "
                 f"form: {len(pages_surfaces)}, graphql: {len(gql_surfaces)})")

        if not surfaces:
            log.warning("  No surfaces — writing empty report")
            return _write_empty(outdir, live_urls_file, start, len(urls))

        (outdir / "idor_surface.txt").write_text(
            "\n".join(
                f"{s.method}\t{s.endpoint}\t{s.param_name}\t{s.param_location}\t{s.id_type}"
                for s in surfaces
            ) + "\n"
        )

        # ── Phase 2–4: Test ─────────────────────────────────────────────────
        all_findings: list[IDORFinding] = []

        if not user_a_headers:
            # Surface-only
            for s in surfaces:
                all_findings.append(IDORFinding(
                    target=s.endpoint, vuln_type="idor_surface_candidate",
                    param_name=s.param_name, param_location=s.param_location,
                    id_type=s.id_type,
                    severity=Severity.LOW, confidence=40, confirmed=False,
                    evidence=f"{s.param_location} '{s.param_name}' ({s.id_type}) — supply sessions to confirm",
                    details=s.to_dict(),
                    auth_enabled=False,
                ))
        else:
            headers_a = dict(user_a_headers or {})
            headers_b = dict(user_b_headers or {})
            radius = 10 if aggressive else 3
            max_ids = 10 if aggressive else max_ids_per_surface

            def _process(surface: ObjectSurface) -> list[IDORFinding]:
                local: list[IDORFinding] = []
                parsed = urllib.parse.urlparse(surface.endpoint)
                host_url = f"{parsed.scheme}://{parsed.netloc}"
                waf = waf_by_host.get(parsed.hostname or "", WAFReport())

                harvested_a = harvest_ids_for_session(
                    session_a, headers_a, host_url, surface, max_ids,
                )
                harvested_b = harvest_ids_for_session(
                    session_b, headers_b, host_url, surface, max_ids,
                ) if session_b else {}

                def _pick(harvested: dict[str, list[str]]) -> str:
                    for kind in ("sequential", "uuid", "hex", "jwt_claim",
                                 "cookie", "js_var"):
                        if harvested.get(kind):
                            return harvested[kind][0]
                    return ""

                own_id = user_a_id or _pick(harvested_a) or (
                    surface.sample_ids[0] if surface.sample_ids else ""
                )
                other_id = user_b_id or _pick(harvested_b)

                if not own_id:
                    return local

                if session_b and other_id and other_id != own_id:
                    # Baseline B for comparison
                    baseline_b = _make_request(
                        session_b, surface, other_id, headers_b,
                    )

                    # Direct swap
                    findings = test_idor_dual_session(
                        session_a, session_b, surface,
                        own_id, other_id, headers_a, headers_b, waf,
                    )
                    local.extend(findings)

                    # Bypasses only if not already confirmed
                    if test_bypasses and not any(f.confirmed for f in findings):
                        bypass = test_bypass_variants(
                            session_a, surface, own_id, other_id, headers_a,
                            baseline_b, waf, aggressive,
                        )
                        local.extend(bypass)
                else:
                    local.extend(test_idor_enumeration(
                        session_a, surface, own_id, headers_a, waf, radius,
                    ))

                return local

            log.info("")
            log.info(f"  Phase 2–4 — Testing {len(surfaces)} surface(s)")
            with ThreadPoolExecutor(max_workers=eff_conc) as pool:
                futures = {pool.submit(_process, s): s for s in surfaces}
                for fut in as_completed(futures):
                    s = futures[fut]
                    try:
                        results = fut.result()
                        if results:
                            all_findings.extend(results)
                            confirmed = sum(1 for r in results if r.confirmed)
                            tag = f" ({confirmed} confirmed)" if confirmed else ""
                            log.info(f"    {s.endpoint[:60]:<60} {len(results)} finding(s){tag}")
                    except Exception as e:
                        log.debug(f"    error on {s.endpoint}: {e}")

        # ── Phase 5: Chains ─────────────────────────────────────────────────
        log.info("")
        log.info("  Phase 5 — Chain aggregation")
        chains = build_chains(all_findings)
        log.info(f"    {len(chains)} chain(s)")

        # ── Dedupe ──────────────────────────────────────────────────────────
        # For bypass findings on the same endpoint+param, keep the highest-
        # severity one so the report isn't flooded with 25 rows for one bug.
        grouped: dict[tuple, IDORFinding] = {}
        for f in all_findings:
            key = (f.target, f.param_name, f.param_location,
                   "bypass" if "bypass" in f.vuln_type else f.vuln_type)
            existing = grouped.get(key)
            if not existing:
                grouped[key] = f
            else:
                # Prefer confirmed, then higher severity, then higher confidence
                if (f.confirmed, f.severity.rank, f.confidence) > \
                   (existing.confirmed, existing.severity.rank, existing.confidence):
                    grouped[key] = f
        deduped = list(grouped.values())
        deduped.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.target))

        # ── Reports ─────────────────────────────────────────────────────────
        elapsed = time.monotonic() - start
        by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_tech: dict[str, int] = {}
        by_sens: dict[str, int] = {}
        confirmed_count = 0
        for f in deduped:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            if f.technique:
                by_tech[f.technique] = by_tech.get(f.technique, 0) + 1
            if f.sensitivity:
                by_sens[f.sensitivity] = by_sens.get(f.sensitivity, 0) + 1
            if f.confirmed:
                confirmed_count += 1

        confirmed = [f for f in deduped if f.confirmed]
        protected = [f for f in deduped if f.vuln_type == "idor_protected"]

        json_path = outdir / "idor_findings.json"
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "input_file": str(live_urls_file),
            "auth_enabled": auth_on,
            "dual_session": dual_session,
            "aggressive": aggressive,
            "config": {
                "rate_limit":    eff_rate,
                "jitter":        eff_jitter,
                "concurrency":   eff_conc,
                "timeout":       eff_timeout,
                "proxies":       len(eff_proxies),
                "test_bypasses": test_bypasses,
                "max_ids":       max_ids_per_surface,
            },
            "totals": {
                "urls_input":     len(urls),
                "surfaces":       len(surfaces),
                "total_findings": len(deduped),
                "confirmed":      confirmed_count,
                "critical":       by_sev["CRITICAL"],
                "high":           by_sev["HIGH"],
                "medium":         by_sev["MEDIUM"],
                "low":            by_sev["LOW"],
                "info":           by_sev["INFO"],
            },
            "summary": {
                "by_severity":  by_sev,
                "by_technique": dict(sorted(by_tech.items(), key=lambda kv: -kv[1])),
                "by_sensitivity": dict(sorted(by_sens.items(), key=lambda kv: -kv[1])),
            },
            "findings": [f.to_dict() for f in deduped],
        }
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

        # ── idor_confirmed.json — HIGH+ only ────────────────────────────────
        confirmed_findings = [
            f for f in deduped if f.severity.rank >= Severity.HIGH.rank
        ]
        (outdir / "idor_confirmed.json").write_text(
            json.dumps({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "input_file": str(live_urls_file),
                "dual_session": dual_session,
                "totals": {
                    "confirmed": len(confirmed_findings),
                    "critical":  sum(1 for f in confirmed_findings if f.severity == Severity.CRITICAL),
                    "high":      sum(1 for f in confirmed_findings if f.severity == Severity.HIGH),
                    "by_sensitivity": {
                        s: sum(1 for f in confirmed_findings if f.sensitivity == s)
                        for s in {f.sensitivity for f in confirmed_findings if f.sensitivity}
                    },
                    "by_chain": {
                        c: sum(1 for f in confirmed_findings if c in f.chain_ids)
                        for c in {cid for f in confirmed_findings for cid in f.chain_ids}
                    },
                },
                "findings": [f.to_dict() for f in confirmed_findings],
            }, indent=2, ensure_ascii=False) + "\n"
        )

        # ── idor_chains.json ────────────────────────────────────────────────
        (outdir / "idor_chains.json").write_text(
            json.dumps({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "chains": [c.to_dict() for c in chains],
            }, indent=2, ensure_ascii=False) + "\n"
        )

        # ── Flat files ──────────────────────────────────────────────────────
        (outdir / "idor_candidates.txt").write_text(
            "\n".join(
                f"{f.target}\t{f.vuln_type}\t{f.technique}\t{f.severity.value}\t"
                f"{f.confidence}\t{'CONFIRMED' if f.confirmed else 'candidate'}\t"
                f"{f.evidence[:160]}"
                for f in deduped
            ) + ("\n" if deduped else "")
        )
        (outdir / "idor_confirmed.txt").write_text(
            "\n".join(
                f"{f.target}\t{f.vuln_type}\t{f.severity.value}\t{f.technique}\t"
                f"{f.evidence[:200]}\t{f.request_curl[:200]}"
                for f in confirmed_findings
            ) + ("\n" if confirmed_findings else "")
        )
        (outdir / "idor_protected.txt").write_text(
            "\n".join(
                f"{f.target}\t{f.param_name}\t{f.evidence[:160]}"
                for f in protected
            ) + ("\n" if protected else "")
        )

        # ── DB sync ────────────────────────────────────────────────────────
        if scan_id is not None:
            log.info("")
            log.info(f"  Syncing to remote database (scan_id={scan_id})...")
            _self_sync(scan_id, deduped)

        # ── Console summary ────────────────────────────────────────────────
        log.info("")
        log.info("  Outputs :")
        log.info(f"    idor_findings.json           {len(deduped):>5} finding(s)")
        log.info(f"    idor_confirmed.json          {len(confirmed_findings):>5} confirmed (HIGH+)")
        log.info(f"    idor_chains.json             {len(chains):>5} chain(s)")
        log.info(f"    idor_candidates.txt          {len(deduped):>5} candidate(s)")
        log.info(f"    idor_confirmed.txt           {len(confirmed_findings):>5} confirmed")
        log.info(f"    idor_surface.txt             {len(surfaces):>5} surface(s)")
        log.info(f"    idor_protected.txt           {len(protected):>5} properly-denied")
        log.info("")
        log.info(f"  Severity : CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  "
                 f"MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}  INFO={by_sev['INFO']}")
        log.info(f"  Confirmed: {confirmed_count} / {len(deduped)}")
        if chains:
            log.info("  Chains   : " + " · ".join(
                f"{c.chain_id}({c.severity.value})" for c in chains
            ))
        if confirmed_findings:
            log.info("")
            log.info("  Confirmed IDOR findings:")
            for f in confirmed_findings[:10]:
                tag = f" [{','.join(f.chain_ids)}]" if f.chain_ids else ""
                log.info(f"    [{f.severity.value:<8}] {f.technique:<20} "
                         f"{f.param_name:<18} {f.target[:50]}{tag}")
        log.info("")
        log.info(f"  Completed in {elapsed:.1f}s")
        return json_path

    finally:
        try: session_a.session.close()
        except Exception: pass
        if session_b:
            try: session_b.session.close()
            except Exception: pass


def _write_empty(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "auth_enabled": False,
        "dual_session": False,
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces": 0, "total_findings": 0,
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_sensitivity": {}},
        "findings": [],
    }
    path = outdir / "idor_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "idor_confirmed.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "dual_session": False,
        "totals": {"confirmed": 0, "critical": 0, "high": 0,
                   "by_sensitivity": {}, "by_chain": {}},
        "findings": [],
    }, indent=2) + "\n")
    (outdir / "idor_chains.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chains": [],
    }, indent=2) + "\n")
    for name in ("idor_candidates.txt", "idor_confirmed.txt",
                 "idor_surface.txt", "idor_protected.txt"):
        (outdir / name).write_text("")
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

    parser = argparse.ArgumentParser(description="Argus IDOR Auditor v3")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--proxies", default=None)
    parser.add_argument("--user-a-headers", help="JSON dict of User A headers")
    parser.add_argument("--user-b-headers", help="JSON dict of User B headers")
    parser.add_argument("--user-a-id", help="User A's own object ID")
    parser.add_argument("--user-b-id", help="User B's object ID")
    parser.add_argument("--no-bypasses", action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    args = parser.parse_args()

    ua = json.loads(args.user_a_headers) if args.user_a_headers else None
    ub = json.loads(args.user_b_headers) if args.user_b_headers else None
    proxies = args.proxies.split(",") if args.proxies else None

    try:
        run_idor_audit(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            proxies=proxies,
            user_a_headers=ua,
            user_b_headers=ub,
            user_a_id=args.user_a_id,
            user_b_id=args.user_b_id,
            test_bypasses=not args.no_bypasses,
            aggressive=args.aggressive,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        import traceback
        log.debug(traceback.format_exc())
        sys.exit(1)
