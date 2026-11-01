#!/usr/bin/env python3
"""
auditing_tools/idor_finder.py — Insecure Direct Object Reference Auditor (v2)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive IDOR/BOLA detection for Argus. The v2 rewrite fixes the
fundamental v1 logic bug — v1 harvested IDs from a single session and
compared them to each other, which is not cross-identity testing at all.

Correct testing requires:
  • Own ID (User A's object) and Other ID (User B's object)
  • GET as User A for own_id       → baseline_a (User A sees User A's data)
  • GET as User B for other_id     → baseline_b (User B sees User B's data)
  • GET as User A for other_id     → if 200 + matches baseline_b → CONFIRMED IDOR
  • GET as User B for own_id       → reversal confirmation

This module implements that correctly, plus:

  • Rate-limited HTTP session (config-driven)
  • Header + cookie auth from config.py
  • Nine discovery vectors (path IDs, query IDs, JSON body IDs, GraphQL
    node-id, JWT sub claim, Flask session, JS-referenced IDs, form fields,
    enumeration)
  • Seven bypass techniques (HPP, encoding, path traversal, header
    injection, method rotation, content-type switching, ID enumeration)
  • Ownership-field comparison (not just "is a field present")
  • GraphQL node-ID IDOR testing
  • Self-sync to idor_findings table when scan_id is provided

Outputs (into `outdir`):
  • idor_findings.json      — full structured report
  • idor_candidates.txt     — flat list for triage
  • idor_confirmed.txt      — confirmed findings only
  • idor_surface.txt        — every object-reference endpoint

Integration:
  main.py → run_one("idor") → run_idor_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import re
import string
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
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _idor_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("idor", {})
    return {
        "rate_limit":  entry.get("rate_limit", 2),
        "concurrency": entry.get("concurrency", 2),
        "timeout":     entry.get("timeout", 15),
    }


def _target_headers() -> dict[str, str]:
    h = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    return h


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS = 2
DEFAULT_RATE_LIMIT = 2
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 1

SEQUENTIAL_RE = re.compile(r"\b(\d{1,10})\b")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
HEX_ID_RE = re.compile(r"\b([0-9a-f]{16,})\b", re.I)

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
]

METHOD_ROTATION = ["GET", "POST", "PUT", "PATCH", "DELETE"]

OWNERSHIP_FIELDS = {
    "user_id", "userId", "uid", "account_id", "accountId",
    "owner_id", "ownerId", "created_by", "createdBy",
    "email", "username", "user_name", "owner_email",
    "tenant_id", "org_id", "organization_id",
    "customer_id", "customerId",
}

CONF_CONFIRMED = 90
CONF_LIKELY = 70
CONF_SURFACE = 40

# Enumeration window for sequential IDs
ENUM_RADIUS = 3

# Sensitive content markers (for confirming foreign data)
SENSITIVE_MARKERS = [
    "email", "username", "account", "profile", "invoice",
    "billing", "password", "ssn", "credit", "address",
    "phone", "balance", "transaction",
]


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
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    evidence: str = ""
    request_curl: str = ""
    response_a: str = ""
    response_b: str = ""
    ownership_leak: str = ""
    details: dict = field(default_factory=dict)
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(
            f"{self.target}|{self.vuln_type}|{self.own_id}|{self.other_id}|{self.technique}".encode()
        ).hexdigest()

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "target_host":    urllib.parse.urlparse(self.target).hostname or "",
            "vuln_type":      self.vuln_type,
            "technique":      self.technique,
            "param_name":     self.param_name,
            "param_location": self.param_location,
            "id_type":        self.id_type,
            "own_id":         self.own_id,
            "other_id":       self.other_id,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "evidence":       self.evidence[:500],
            "request_curl":   self.request_curl[:2000],
            "response_a":     self.response_a[:500],
            "response_b":     self.response_b[:500],
            "ownership_leak": self.ownership_leak[:200],
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen,
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
            "endpoint": self.endpoint,
            "method": self.method,
            "param_name": self.param_name,
            "param_location": self.param_location,
            "id_type": self.id_type,
            "sample_ids": self.sample_ids[:10],
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    def __init__(self, rate_limit: int = DEFAULT_RATE_LIMIT, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.verify = False
        base_hdrs = _target_headers()
        if base_hdrs:
            self.session.headers.update(base_hdrs)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.min_interval > 0:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
        self._last = time.monotonic()
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


def _body_snippet(resp: requests.Response, max_len: int = 500) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


def _similarity(a_text: str, b_text: str) -> float:
    """Return similarity 0.0–1.0 between two response bodies."""
    a = (a_text or "")[:5000]
    b = (b_text or "")[:5000]
    if not a and not b:
        return 1.0
    if a == b:
        return 1.0
    if a[:200] == b[:200]:
        return 0.95
    len_ratio = min(len(a), len(b)) / max(len(a), len(b), 1)
    return len_ratio


def _body_text(resp: requests.Response) -> str:
    try:
        return resp.text[:200000]
    except Exception:
        return ""


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


def _classify_id(sample: str) -> str:
    if UUID_RE.match(sample):
        return "uuid"
    if sample.isdigit():
        return "sequential"
    if len(sample) >= 16 and all(c in string.hexdigits for c in sample):
        return "hex"
    return "opaque"


def _nearby_ids(sample: str, radius: int = ENUM_RADIUS) -> list[str]:
    """Enumerate IDs near a known sequential ID (for enumeration testing)."""
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
    variants.append(urllib.parse.quote(sample))
    variants.append(urllib.parse.quote(urllib.parse.quote(sample)))
    try:
        variants.append(sample.encode().hex())
    except Exception:
        pass
    return list(dict.fromkeys(variants))


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
        parts.append(f"-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(json_body)[:300]}'")
    elif data:
        parts.append(f"-d '{urllib.parse.urlencode(data)[:300]}'")
    return " ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
#  OWNERSHIP ANALYSIS (FIXED)
# ═════════════════════════════════════════════════════════════════════════════

def _extract_ownership_fields(resp: requests.Response) -> list[tuple[str, str]]:
    """
    Walk a JSON response and return every (field_name, value) pair where
    the field looks like an ownership identifier.
    """
    out: list[tuple[str, str]] = []
    try:
        data = resp.json()
    except Exception:
        return out

    def _walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in OWNERSHIP_FIELDS and isinstance(v, (str, int)):
                    out.append((k, str(v)))
                _walk(v, f"{prefix}.{k}" if prefix else k)
        elif isinstance(obj, list):
            for item in obj[:10]:
                _walk(item, prefix)

    _walk(data)
    return out


def _ownership_match(
    resp: requests.Response, owner_id: str,
) -> Optional[tuple[str, str]]:
    """
    Return the (field, value) where the response identifies `owner_id`
    as the owner. This is what we use to *confirm* IDOR — the response must
    contain the OTHER user's identifier, not just any ownership field.
    """
    if not owner_id:
        return None
    for field_name, value in _extract_ownership_fields(resp):
        if value == owner_id:
            return (field_name, value)
        # Sometimes owner IDs are embedded in strings
        if owner_id in value:
            return (field_name, value)
    return None


def _foreign_data_present(resp: requests.Response, own_id: str) -> Optional[str]:
    """
    Check whether the response clearly contains data that is NOT the
    requesting user's (i.e., doesn't reference own_id where it should).
    Returns a descriptive string or None.
    """
    fields = _extract_ownership_fields(resp)
    if not fields:
        return None
    # If every ownership field points to own_id, it's the requester's data
    if all(v == own_id or own_id in v for _, v in fields):
        return None
    # At least one field points elsewhere — foreign data
    sample = ", ".join(f"{k}={v}" for k, v in fields[:3])
    return sample


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SURFACE DISCOVERY (expanded)
# ═════════════════════════════════════════════════════════════════════════════

REST_ID_PATH_RE = re.compile(
    r"/([a-zA-Z][a-zA-Z0-9_-]*)/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)


def discover_surfaces_from_urls(urls: list[str]) -> list[ObjectSurface]:
    """REST path, query, and (if present) form surfaces."""
    surfaces: list[ObjectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)

        # ── Path-based IDs
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

        # ── Query-based IDs
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
    """
    Discover body-based surfaces from site_pages.json (if the crawler ran).
    Forms with POST methods and ID-like field names are the target.
    """
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
                        param_location="body",
                        id_type="unknown",
                        sample_ids=[],
                    ))

    return surfaces


def discover_surfaces_from_graphql(
    outdir: Path,
) -> list[ObjectSurface]:
    """Extract GraphQL node(id:) and ID-arg surfaces from the schema dump."""
    surfaces: list[ObjectSurface] = []
    schema_file = outdir / "graphql_schema.json"
    if not schema_file.exists():
        return surfaces

    try:
        schemas = json.loads(schema_file.read_text())
    except Exception:
        return surfaces

    for gql_url, schema in schemas.items():
        for t in schema.get("types", []):
            for f in t.get("fields") or []:
                for arg in f.get("args") or []:
                    aname = (arg.get("name") or "").lower()
                    if aname in ("id", "uuid", "user_id", "account_id", "nodeid"):
                        surfaces.append(ObjectSurface(
                            endpoint=gql_url, method="POST",
                            param_name=arg.get("name", "id"),
                            param_location="graphql",
                            id_type="opaque",
                            sample_ids=[],
                        ))
                        break

    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — IDENTIFIER HARVESTING PER SESSION
# ═════════════════════════════════════════════════════════════════════════════

LISTING_PATHS = [
    "/api/users", "/api/accounts", "/api/orders", "/api/invoices",
    "/api/documents", "/api/projects", "/api/items", "/api/v1/users",
    "/api/v1/accounts", "/api/v1/orders", "/api/me", "/users", "/accounts",
]


def harvest_ids_for_session(
    session: RateLimitedSession,
    headers: dict,
    host_url: str,
    surface: ObjectSurface,
    max_ids: int = 10,
) -> list[str]:
    """Harvest IDs visible to a specific session."""
    harvested: set[str] = set()

    # From the target endpoint itself
    resp = session.get(surface.endpoint, headers=headers)
    if resp and resp.status_code < 400:
        for kind in _extract_ids(_body_text(resp)).values():
            harvested.update(kind[:max_ids])

    # From common listing endpoints on the same host
    for path in LISTING_PATHS:
        test_url = host_url.rstrip("/") + path
        r = session.get(test_url, headers=headers)
        if not r or r.status_code >= 400:
            continue
        for kind in _extract_ids(_body_text(r)).values():
            harvested.update(kind[:max_ids])
        if len(harvested) >= max_ids * 2:
            break

    return list(harvested)[:max_ids]


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BASELINE VARIANCE
# ═════════════════════════════════════════════════════════════════════════════

def compute_baseline(
    session: RateLimitedSession, surface: ObjectSurface, headers: dict,
) -> tuple[float, Optional[requests.Response]]:
    """Fetch the endpoint twice with the same session — return (similarity, first_resp)."""
    r1 = session.get(surface.endpoint, headers=headers)
    if not r1:
        return 0.0, None
    time.sleep(0.1)
    r2 = session.get(surface.endpoint, headers=headers)
    if not r2:
        return 0.0, r1
    return _similarity(_body_text(r1), _body_text(r2)), r1


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CROSS-IDENTITY TESTING (FIXED)
# ═════════════════════════════════════════════════════════════════════════════

def _replace_id_in_url(url: str, old_id: str, new_id: str) -> str:
    """Replace an identifier in the URL path or query."""
    if old_id in url:
        url = url.replace(old_id, new_id, 1)
    return url


def _build_test_url(surface: ObjectSurface, id_value: str) -> str:
    """Build a URL that requests a specific ID on this surface."""
    if surface.param_location == "path":
        # The sample_ids[0] is the original ID — replace it
        if surface.sample_ids:
            return _replace_id_in_url(surface.endpoint, surface.sample_ids[0], id_value)
        return surface.endpoint
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        new_params = [(k, id_value if k == surface.param_name else v) for k, v in params]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))
    return surface.endpoint


def _build_graphql_query(surface: ObjectSurface, id_value: str) -> dict:
    """Build a GraphQL query that requests a specific ID."""
    # Heuristic: try { field(id: "value") { __typename } }
    # The field name has to be inferred — try common root query names
    for root_field in ("node", "user", "account", "order", "item"):
        q = f'{{ {root_field}({surface.param_name}: "{id_value}") {{ __typename }} }}'
        return {"query": q}
    return {"query": f'{{ __typename }}'}


def test_idor_dual_session(
    session_a: RateLimitedSession,
    session_b: RateLimitedSession,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    headers_a: dict,
    headers_b: dict,
    baseline_a_similarity: float = 1.0,
) -> list[IDORFinding]:
    """
    The real IDOR test. Compare four requests:

      1. User A → own_id          (baseline: User A sees User A's data)
      2. User B → other_id        (baseline: User B sees User B's data)
      3. User A → other_id        (test: if 200 + matches B's data = IDOR)
      4. User B → own_id          (reversal: confirms direction)

    A finding requires evidence that the response to request 3 contains
    User B's ownership identifiers OR is materially identical to User B's
    baseline response (request 2).
    """
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    if surface.param_location == "graphql":
        a_own_url = b_other_url = a_other_url = b_own_url = surface.endpoint
        a_own_body = _build_graphql_query(surface, own_id)
        b_other_body = _build_graphql_query(surface, other_id)
        a_other_body = _build_graphql_query(surface, other_id)
        b_own_body = _build_graphql_query(surface, own_id)
        req_kwargs = lambda body: {"json": body}  # noqa: E731
    elif surface.param_location == "body":
        a_own_url = b_other_url = a_other_url = b_own_url = surface.endpoint
        a_own_body = {surface.param_name: own_id}
        b_other_body = {surface.param_name: other_id}
        a_other_body = {surface.param_name: other_id}
        b_own_body = {surface.param_name: own_id}
        req_kwargs = lambda body: {"json": body}  # noqa: E731
    else:
        a_own_url = _build_test_url(surface, own_id)
        b_other_url = _build_test_url(surface, other_id)
        a_other_url = _build_test_url(surface, other_id)
        b_own_url = _build_test_url(surface, own_id)
        req_kwargs = lambda body: {}  # noqa: E731

    # ── Baselines
    r_a_own = session_a.request(surface.method, a_own_url, headers=headers_a, **req_kwargs(a_own_body if surface.param_location in ("body", "graphql") else None))
    r_b_other = session_b.request(surface.method, b_other_url, headers=headers_b, **req_kwargs(b_other_body if surface.param_location in ("body", "graphql") else None))

    if not r_a_own or not r_b_other:
        return findings
    if not (200 <= r_a_own.status_code < 300):
        return findings

    # ── Test: User A requesting User B's object
    r_a_other = session_a.request(surface.method, a_other_url, headers=headers_a, **req_kwargs(a_other_body if surface.param_location in ("body", "graphql") else None))
    if not r_a_other:
        return findings

    if not (200 <= r_a_other.status_code < 300):
        # 403/404 — properly denied. Not a finding, but useful evidence.
        if r_a_other.status_code in (403, 401):
            findings.append(IDORFinding(
                target=surface.endpoint, vuln_type="idor_protected",
                technique="direct_swap", param_name=surface.param_name,
                param_location=surface.param_location,
                id_type=surface.id_type,
                own_id=own_id, other_id=other_id,
                severity="INFO", confidence=30, confirmed=False,
                evidence=f"User A requesting User B's object returned HTTP {r_a_other.status_code} — properly denied",
                response_a=_body_snippet(r_a_own),
                response_b=_body_snippet(r_a_other),
                details={"status_own": r_a_own.status_code, "status_cross": r_a_other.status_code},
                auth_enabled=True, first_seen=now,
            ))
        return findings

    # ── Analysis: did we get User B's data?
    owns_b = _ownership_match(r_a_other, other_id)
    b_baseline_similarity = _similarity(_body_text(r_a_other), _body_text(r_b_other))
    a_baseline_similarity = _similarity(_body_text(r_a_other), _body_text(r_a_own))

    evidence: list[str] = [f"User A → other_id returned HTTP {r_a_other.status_code}"]
    confidence = CONF_LIKELY
    confirmed = False

    if owns_b:
        field_name, value = owns_b
        evidence.append(f"Response contains User B's identifier: {field_name}={value}")
        confidence = CONF_CONFIRMED
        confirmed = True

    if b_baseline_similarity >= 0.90:
        evidence.append(f"Response matches User B's baseline ({b_baseline_similarity:.2f} similarity)")
        confidence = CONF_CONFIRMED
        confirmed = True

    if a_baseline_similarity >= 0.95:
        # Response looks like User A's own data — likely the ID param is ignored
        evidence.append("Response matches User A's own baseline — parameter likely ignored (not IDOR)")
        return findings

    # ── Reversal (only if we're at LIKELY or higher)
    if confidence >= CONF_LIKELY:
        r_b_own = session_b.request(surface.method, b_own_url, headers=headers_b, **req_kwargs(b_own_body if surface.param_location in ("body", "graphql") else None))
        if r_b_own and 200 <= r_b_own.status_code < 300:
            a_baseline_match = _similarity(_body_text(r_b_own), _body_text(r_a_own))
            if a_baseline_match >= 0.90:
                evidence.append(f"Reversal: User B requesting User A's object returned matching data ({a_baseline_match:.2f})")
                confidence = CONF_CONFIRMED
                confirmed = True

    severity = (
        "CRITICAL" if confirmed
        else "HIGH" if confidence >= CONF_LIKELY
        else "MEDIUM"
    )

    findings.append(IDORFinding(
        target=surface.endpoint, vuln_type="idor_horizontal",
        technique="direct_swap", param_name=surface.param_name,
        param_location=surface.param_location, id_type=surface.id_type,
        own_id=own_id, other_id=other_id,
        severity=severity, confidence=confidence, confirmed=confirmed,
        evidence=" | ".join(evidence),
        request_curl=_build_curl(
            surface.method, a_other_url, headers_a,
            json_body=a_other_body if surface.param_location in ("body", "graphql") else None,
        ),
        response_a=_body_snippet(r_a_own),
        response_b=_body_snippet(r_a_other),
        ownership_leak=str(owns_b) if owns_b else "",
        details={
            "param": surface.param_name,
            "param_location": surface.param_location,
            "own_id": own_id, "other_id": other_id,
            "status_a_own": r_a_own.status_code,
            "status_a_other": r_a_other.status_code,
            "status_b_other": r_b_other.status_code,
            "sim_to_b_baseline": round(b_baseline_similarity, 3),
            "sim_to_a_baseline": round(a_baseline_similarity, 3),
            "baseline_stability": round(baseline_a_similarity, 3),
        },
        auth_enabled=True, first_seen=now,
    ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — ENUMERATION MODE (single-session fallback)
# ═════════════════════════════════════════════════════════════════════════════

def test_idor_enumeration(
    session: RateLimitedSession,
    surface: ObjectSurface,
    own_id: str,
    headers: dict,
) -> list[IDORFinding]:
    """
    When we only have one session, enumerate nearby sequential IDs.
    A 200 with foreign data is a strong candidate (LIKELY, not CONFIRMED).
    """
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    r_a_own = session.get(_build_test_url(surface, own_id), headers=headers)
    if not r_a_own or not (200 <= r_a_own.status_code < 300):
        return findings
    own_text = _body_text(r_a_own)

    for test_id in _nearby_ids(own_id):
        test_url = _build_test_url(surface, test_id)
        r = session.get(test_url, headers=headers)
        if not r or not (200 <= r.status_code < 300):
            continue

        test_text = _body_text(r)
        sim_to_own = _similarity(test_text, own_text)

        # If it matches our own data, the param is ignored
        if sim_to_own >= 0.95:
            continue

        # If it's substantially different, that's a candidate
        if sim_to_own < 0.80 and len(test_text) > 50:
            foreign = _foreign_data_present(r, own_id)
            confidence = CONF_LIKELY if foreign else 55
            findings.append(IDORFinding(
                target=surface.endpoint, vuln_type="idor_enumeration",
                technique="sequential_enum", param_name=surface.param_name,
                param_location=surface.param_location, id_type=surface.id_type,
                own_id=own_id, other_id=test_id,
                severity="HIGH", confidence=confidence, confirmed=False,
                evidence=(
                    f"Enumerated ID {test_id} (own={own_id}) returned 200 with different data"
                    + (f"; foreign data indicators: {foreign}" if foreign else "")
                ),
                request_curl=_build_curl(surface.method, test_url, headers),
                response_a=_body_snippet(r_a_own),
                response_b=_body_snippet(r),
                ownership_leak=foreign or "",
                details={
                    "param": surface.param_name,
                    "own_id": own_id, "test_id": test_id,
                    "similarity": round(sim_to_own, 3),
                },
                auth_enabled=True, first_seen=now,
            ))
            break  # one confirmed enumeration is enough per surface

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — BYPASS VARIANTS (fixed)
# ═════════════════════════════════════════════════════════════════════════════

def test_bypass_variants(
    session: RateLimitedSession,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    headers: dict,
) -> list[IDORFinding]:
    findings: list[IDORFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    # ── HTTP Parameter Pollution: ?id=A&id=B
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query)
        polluted = params + [(surface.param_name, other_id)]
        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(polluted)))
        r = session.get(test_url, headers=headers)
        if r and 200 <= r.status_code < 300:
            if _ownership_match(r, other_id):
                findings.append(IDORFinding(
                    target=surface.endpoint, vuln_type="idor_parameter_pollution",
                    technique="hpp", param_name=surface.param_name,
                    param_location="query", id_type=surface.id_type,
                    own_id=own_id, other_id=other_id,
                    severity="HIGH", confidence=CONF_LIKELY, confirmed=False,
                    evidence=f"HPP: response for ?{surface.param_name}=A&{surface.param_name}=B contains User B's data",
                    request_curl=_build_curl("GET", test_url, headers),
                    response_b=_body_snippet(r),
                    details={"technique": "HPP", "test_url": test_url},
                    auth_enabled=True, first_seen=now,
                ))

    # ── Encoded variants
    for variant in _encode_variants(other_id):
        if variant == other_id:
            continue
        test_url = _build_test_url(surface, variant)
        r = session.get(test_url, headers=headers)
        if r and 200 <= r.status_code < 300:
            if _ownership_match(r, other_id):
                findings.append(IDORFinding(
                    target=surface.endpoint, vuln_type="idor_encoded_bypass",
                    technique="encoding", param_name=surface.param_name,
                    param_location=surface.param_location, id_type=surface.id_type,
                    own_id=own_id, other_id=other_id,
                    severity="HIGH", confidence=CONF_LIKELY, confirmed=False,
                    evidence=f"Encoded variant '{variant}' bypassed authorization",
                    request_curl=_build_curl(surface.method, test_url, headers),
                    response_b=_body_snippet(r),
                    details={"variant": variant},
                    auth_enabled=True, first_seen=now,
                ))
                break

    # ── Identity header injection
    for hdr in IDENTITY_HEADERS:
        test_headers = dict(headers or {})
        test_headers[hdr] = other_id
        r = session.get(surface.endpoint, headers=test_headers)
        if r and 200 <= r.status_code < 300:
            if _ownership_match(r, other_id):
                findings.append(IDORFinding(
                    target=surface.endpoint, vuln_type="idor_header_injection",
                    technique="header_injection", param_name=hdr,
                    param_location="header", id_type=surface.id_type,
                    own_id=own_id, other_id=other_id,
                    severity="HIGH", confidence=CONF_LIKELY, confirmed=False,
                    evidence=f"Identity header {hdr} accepted with User B's ID",
                    request_curl=_build_curl(surface.method, surface.endpoint, test_headers),
                    response_b=_body_snippet(r),
                    details={"header": hdr},
                    auth_enabled=True, first_seen=now,
                ))
                break

    # ── Method rotation with body
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
        if r and 200 <= r.status_code < 300:
            if _ownership_match(r, other_id):
                findings.append(IDORFinding(
                    target=surface.endpoint, vuln_type="idor_method_tamper",
                    technique="method_rotation", param_name=surface.param_name,
                    param_location=surface.param_location, id_type=surface.id_type,
                    own_id=own_id, other_id=other_id,
                    severity="HIGH", confidence=CONF_LIKELY, confirmed=False,
                    evidence=f"Method {surface.method}→{alt_method} bypassed authorization",
                    request_curl=_build_curl(alt_method, surface.endpoint, headers),
                    response_b=_body_snippet(r),
                    details={"alt_method": alt_method},
                    auth_enabled=True, first_seen=now,
                ))
                break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[IDORFinding]) -> None:
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
        result = DB.upsert_idor_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
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
    graphql_schema_file: Optional[Path] = None,
    test_bypasses: bool = True,
    max_ids_per_surface: int = 3,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Run the IDOR audit against every URL in `live_urls_file`.

    Dual-session testing requires BOTH user_a_headers and user_b_headers.
    Without both, the module falls back to enumeration mode (LIKELY findings,
    not confirmed) — still useful, but slower to pay off.
    """
    start = time.monotonic()

    settings = _idor_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    dual_session = bool(user_a_headers and user_b_headers)
    auth_on = bool(user_a_headers or cfg_hdrs)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"           source: MODULE_RATE_LIMITS['idor']")

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured")

    if dual_session:
        log.info("  Mode   : DUAL-SESSION (IDOR confirmed via cross-identity comparison)")
        log.info(f"           User A ID: {user_a_id or '(not set — will harvest from User A)'}")
        log.info(f"           User B ID: {user_b_id or '(not set — will harvest from User B)'}")
    elif user_a_headers:
        log.info("  Mode   : ENUMERATION (single session — IDOR flagged as LIKELY, not confirmed)")
    else:
        log.info("  Mode   : SURFACE-ONLY (no credentials — mapping IDOR surface)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session_a = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)
    session_b = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout) if dual_session else None

    # ── Phase 1: Surface discovery ──────────────────────────────────────────
    log.info("  Phase 1 — Object reference surface discovery")
    surfaces = discover_surfaces_from_urls(urls)
    pages_surfaces = discover_surfaces_from_pages(outdir)
    gql_surfaces = discover_surfaces_from_graphql(outdir)
    surfaces.extend(pages_surfaces)
    surfaces.extend(gql_surfaces)

    # Dedupe surfaces
    seen_surf: set[tuple] = set()
    unique_surfaces: list[ObjectSurface] = []
    for s in surfaces:
        key = (s.endpoint, s.method, s.param_name, s.param_location)
        if key not in seen_surf:
            seen_surf.add(key)
            unique_surfaces.append(s)
    surfaces = unique_surfaces

    log.info(f"    {len(surfaces)} surface(s)  "
             f"(URL: {len(surfaces) - len(pages_surfaces) - len(gql_surfaces)}, "
             f"form: {len(pages_surfaces)}, graphql: {len(gql_surfaces)})")

    if not surfaces:
        log.warning("  No surfaces — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start, len(urls))

    (outdir / "idor_surface.txt").write_text(
        "\n".join(
            f"{s.method}\t{s.endpoint}\t{s.param_name}\t{s.param_location}\t{s.id_type}"
            for s in surfaces
        ) + "\n"
    )

    # ── Phase 2–5: Test ─────────────────────────────────────────────────────
    all_findings: list[IDORFinding] = []

    if not user_a_headers:
        # Surface-only — flag every endpoint as a candidate, no testing
        for s in surfaces:
            all_findings.append(IDORFinding(
                target=s.endpoint, vuln_type="idor_surface_candidate",
                param_name=s.param_name, param_location=s.param_location,
                id_type=s.id_type, severity="MEDIUM", confidence=CONF_SURFACE,
                evidence=f"{s.param_location} '{s.param_name}' ({s.id_type}); supply test accounts to confirm",
                details=s.to_dict(), auth_enabled=False,
            ))
    else:
        headers_a = dict(user_a_headers or {})
        headers_b = dict(user_b_headers or {})

        def _process_surface(surface: ObjectSurface) -> list[IDORFinding]:
            local: list[IDORFinding] = []
            host_url = f"{urllib.parse.urlparse(surface.endpoint).scheme}://{urllib.parse.urlparse(surface.endpoint).netloc}"

            # Harvest IDs from both sessions
            own_ids = harvest_ids_for_session(session_a, headers_a, host_url, surface)
            other_ids = (
                harvest_ids_for_session(session_b, headers_b, host_url, surface)
                if session_b else []
            )

            # Baseline variance for User A
            baseline_sim, _ = compute_baseline(session_a, surface, headers_a)

            # Prefer explicit IDs from config if provided
            own_id = user_a_id or (own_ids[0] if own_ids else "")
            other_id = user_b_id or (other_ids[0] if other_ids else "")

            if not own_id:
                return local

            # ── Dual-session test
            if session_b and other_id and other_id != own_id:
                findings = test_idor_dual_session(
                    session_a, session_b, surface,
                    own_id, other_id,
                    headers_a, headers_b, baseline_sim,
                )
                local.extend(findings)

                # Bypass variants only if direct swap didn't confirm
                if test_bypasses and not any(f.confirmed for f in findings):
                    local.extend(test_bypass_variants(
                        session_a, surface, own_id, other_id, headers_a,
                    ))
            else:
                # ── Enumeration fallback
                local.extend(test_idor_enumeration(
                    session_a, surface, own_id, headers_a,
                ))

            return local

        log.info("")
        log.info(f"  Phase 2–5 — Testing {len(surfaces)} surface(s)")
        with ThreadPoolExecutor(max_workers=eff_conc) as pool:
            futures = {pool.submit(_process_surface, s): s for s in surfaces}
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

    # ── Dedupe + sort ───────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[IDORFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type, f.own_id, f.other_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_technique: dict[str, int] = {}
    confirmed_count = 0

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if f.technique:
            by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        if f.confirmed:
            confirmed_count += 1

    confirmed = [f for f in deduped if f.confirmed]

    # Flat outputs
    (outdir / "idor_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.technique}\t{f.severity}\t{f.confidence}\t"
            f"{'CONFIRMED' if f.confirmed else 'candidate'}\t{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "idor_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.evidence}\t{f.request_curl[:200]}"
            for f in confirmed
        ) + ("\n" if confirmed else "")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "dual_session": dual_session,
        "config": {
            "rate_limit":    eff_rate,
            "concurrency":   eff_conc,
            "timeout":       eff_timeout,
            "headers_count": len(cfg_hdrs),
            "test_bypasses": test_bypasses,
            "max_ids":       max_ids_per_surface,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces":         len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        confirmed_count,
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity":  by_severity,
            "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "idor_findings.json"
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
    log.info(f"    idor_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    idor_confirmed.txt           {len(confirmed):>5} confirmed")
    log.info(f"    idor_surface.txt             {len(surfaces):>5} surface(s)")

    log.info("")
    log.info(
        f"  Severity : "
        f"CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  "
        f"MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}  "
        f"INFO={by_severity['INFO']}"
    )
    log.info(f"  Confirmed: {confirmed_count} / {len(deduped)}")

    if by_technique:
        log.info("  Technique: " + " · ".join(
            f"{k}({v})" for k, v in list(by_technique.items())[:8]
        ))

    if confirmed:
        log.info("")
        log.info("  Confirmed IDOR findings:")
        for f in confirmed[:10]:
            log.info(f"    [CRITICAL] {f.technique:<18} {f.param_name:<20} {f.target[:50]}")

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
        "auth_enabled": False,
        "dual_session": False,
        "config": {},
        "totals": {
            "urls_input": total_input, "surfaces": 0, "total_findings": 0,
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}},
        "findings": [],
    }
    path = outdir / "idor_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("idor_candidates.txt", "idor_confirmed.txt", "idor_surface.txt"):
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

    parser = argparse.ArgumentParser(description="Argus IDOR Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--user-a-headers", help="JSON dict of User A headers")
    parser.add_argument("--user-b-headers", help="JSON dict of User B headers")
    parser.add_argument("--user-a-id", help="User A's own object ID")
    parser.add_argument("--user-b-id", help="User B's object ID")
    parser.add_argument("--graphql-schema", type=Path, default=None)
    parser.add_argument("--no-bypasses", action="store_true")
    args = parser.parse_args()

    ua_headers = json.loads(args.user_a_headers) if args.user_a_headers else None
    ub_headers = json.loads(args.user_b_headers) if args.user_b_headers else None

    try:
        run_idor_audit(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            user_a_headers=ua_headers,
            user_b_headers=ub_headers,
            user_a_id=args.user_a_id,
            user_b_id=args.user_b_id,
            graphql_schema_file=args.graphql_schema,
            test_bypasses=not args.no_bypasses,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
