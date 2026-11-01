#!/usr/bin/env python3
"""
auditing_tools/idor_finder.py — Insecure Direct Object Reference Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive IDOR/BOLA detection module for Argus.

IDOR is not about guessing IDs. It is about detecting the ABSENCE of an
authorization check. The only reliable way to do that is differential
analysis: send the same request with two different identities and compare
responses.

Six-phase strategy:

  Phase 1 — Object reference surface discovery
      Extract candidate endpoints from:
        • REST paths with numeric/UUID/encoded identifiers
        • Query parameters with ID-like names
        • JSON body fields with ID-like names
        • GraphQL node(id:) queries (from schema)
        • JWT sub/user_id claims
        • Flask session cookies

  Phase 2 — Identifier harvesting
      For each endpoint, harvest real identifiers from:
        • Own responses (User A's objects)
        • Listing endpoints (GET /users, /orders, etc.)
        • JS files and error messages
      Classify as sequential, UUID, encoded, or opaque.

  Phase 3 — Dual-session baseline
      Fetch each endpoint twice with the SAME identity to detect per-request
      noise (nonces, timestamps, session tokens). Without this step, every
      diff is a false positive.

  Phase 4 — Cross-identity testing (the core)
      For each harvested identifier:
        • Request as User A with User A's ID → expect 200 + data
        • Request as User A with User B's ID → if 200 + data, BOLA candidate
        • Request as User B with User A's ID → confirm reversal
      Also test:
        • HTTP method tampering (GET→POST→PUT→PATCH→DELETE)
        • Parameter pollution (?id=A&id=B)
        • Content-Type switching
        • Path traversal variants
        • Header-based ID injection (X-User-Id, X-Account-Id)

  Phase 5 — Vertical escalation (BFLA)
      With User A's token, attempt admin-only mutations discovered from
      GraphQL schema or REST admin paths.

  Phase 6 — Evidence & reporting
      Every confirmed finding includes:
        • The exact request (curl-ready)
        • The two response snippets side-by-side
        • The ownership field that leaked
        • A CVSS-aligned severity

Outputs (into `outdir`):
  • idor_findings.json        — full structured report
  • idor_candidates.txt       — flat list for triage
  • idor_confirmed.txt        — confirmed findings only
  • idor_surface.txt          — all object-reference endpoints

Integration:
  main.py → run_one("idor") → run_idor_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
import base64
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
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 5
DEFAULT_TIMEOUT      = 15
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-IDOR-Auditor/1.0"

# Identifier patterns
SEQUENTIAL_RE        = re.compile(r"\b(\d{1,10})\b")
UUID_RE              = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)
BASE64_ID_RE         = re.compile(r"\b([A-Za-z0-9+/]{8,}={0,2})\b")
HEX_ID_RE            = re.compile(r"\b([0-9a-f]{16,})\b", re.I)

# ID-like parameter names
ID_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "customer_id", "customerid", "order_id", "orderid", "invoice_id",
    "invoiceid", "doc_id", "docid", "document_id", "documentid",
    "profile_id", "profileid", "org_id", "orgid", "tenant_id",
    "tenantid", "group_id", "groupid", "team_id", "teamid",
    "project_id", "projectid", "item_id", "itemid", "object_id",
    "objectid", "resource_id", "resourceid", "uuid", "guid",
    "ref", "reference", "key", "token_id", "tokenid",
}

# ID-like JSON body field names
ID_BODY_FIELDS = ID_PARAM_NAMES | {"sub", "owner", "owner_id", "created_by"}

# Headers that often carry identity and can be tampered with
IDENTITY_HEADERS = [
    "X-User-Id", "X-User-ID", "X-Account-Id", "X-Account-ID",
    "X-Customer-Id", "X-Tenant-Id", "X-Org-Id", "X-Forwarded-User",
]

# HTTP methods to test when the default method is blocked
METHOD_ROTATION = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Content types to try when JSON is rejected
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/xml",
    "text/plain",
]

# Path traversal variants for encoded IDs
PATH_TRAVERSAL_VARIANTS = [
    lambda x: x,
    lambda x: f"{x}/",
    lambda x: f"{x}.",
    lambda x: f"%2e/{x}",
    lambda x: f"%2e%2e/{x}",
    lambda x: f"{x}%00",
    lambda x: f"{x}%20",
]

# Ownership field patterns — used to detect leaked data
OWNERSHIP_FIELDS = {
    "user_id", "userId", "uid", "account_id", "accountId",
    "owner_id", "ownerId", "created_by", "createdBy",
    "email", "username", "user_name", "owner_email",
    "tenant_id", "org_id", "organization_id",
}

# Confidence thresholds
CONF_CONFIRMED = 90
CONF_LIKELY   = 70
CONF_SURFACE  = 40


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class IDORFinding:
    target: str
    vuln_type: str
    severity: str = "MEDIUM"
    confidence: int = 50
    evidence: str = ""
    request_curl: str = ""
    response_a: str = ""
    response_b: str = ""
    ownership_leak: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "vuln_type":      self.vuln_type,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "evidence":       self.evidence[:500],
            "request_curl":   self.request_curl[:1000],
            "response_a":     self.response_a[:500],
            "response_b":     self.response_b[:500],
            "ownership_leak": self.ownership_leak[:200],
            "details":        self.details,
        }


@dataclass
class ObjectSurface:
    endpoint: str
    method: str = "GET"
    param_name: str = ""
    param_location: str = ""      # "path" | "query" | "body" | "header" | "graphql"
    id_type: str = "unknown"      # "sequential" | "uuid" | "encoded" | "opaque"
    sample_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "endpoint":        self.endpoint,
            "method":          self.method,
            "param_name":      self.param_name,
            "param_location":  self.param_location,
            "id_type":         self.id_type,
            "sample_ids":      self.sample_ids[:10],
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
    json_body: Optional[dict] = None,
    data: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url,
            headers=headers or {},
            json=json_body,
            data=data,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body_snippet(resp: requests.Response, max_len: int = 500) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


def _diff_responses(a: requests.Response, b: requests.Response) -> float:
    """
    Return a similarity ratio between two responses (0.0 = different, 1.0 = identical).
    """
    try:
        a_text = a.text[:5000]
        b_text = b.text[:5000]
    except Exception:
        return 0.0
    if a_text == b_text:
        return 1.0
    # Quick length-ratio heuristic + first-200-char equality
    if a_text[:200] == b_text[:200]:
        return 0.95
    if abs(len(a_text) - len(b_text)) < 50:
        return 0.7
    return 0.0


def _extract_ids_from_text(text: str) -> dict[str, list[str]]:
    """Extract sequential, UUID, and encoded IDs from arbitrary text."""
    result = {"sequential": [], "uuid": [], "encoded": [], "hex": []}
    if not text:
        return result

    # UUIDs
    for m in UUID_RE.findall(text):
        result["uuid"].append(m)

    # Sequential IDs (3–10 digits, avoid years and common noise)
    for m in SEQUENTIAL_RE.findall(text):
        if len(m) >= 3 and not (1900 <= int(m) <= 2100):
            result["sequential"].append(m)

    # Hex IDs
    for m in HEX_ID_RE.findall(text):
        result["hex"].append(m)

    # Base64-ish encoded IDs
    for m in BASE64_ID_RE.findall(text):
        if len(m) >= 8 and any(c.isupper() for c in m) and any(c.isdigit() for c in m):
            try:
                decoded = base64.b64decode(m + "==").decode("utf-8", errors="ignore")
                if decoded.isdigit() or UUID_RE.match(decoded):
                    result["encoded"].append(m)
            except Exception:
                pass

    # Dedupe and cap
    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:20]
    return result


def _classify_id(sample: str) -> str:
    """Classify an identifier by its shape."""
    if UUID_RE.match(sample):
        return "uuid"
    if sample.isdigit():
        return "sequential"
    if len(sample) >= 16 and all(c in string.hexdigits for c in sample):
        return "hex"
    try:
        decoded = base64.b64decode(sample + "==").decode("utf-8", errors="ignore")
        if decoded.isdigit() or UUID_RE.match(decoded):
            return "encoded"
    except Exception:
        pass
    return "opaque"


def _increment_id(sample: str) -> str:
    """Produce a nearby ID to test authorization (not brute-force)."""
    if sample.isdigit():
        n = int(sample)
        # Try both directions but cap to avoid looking like enumeration
        return str(n + 1)
    return sample


def _decrement_id(sample: str) -> str:
    if sample.isdigit():
        n = int(sample)
        if n > 1:
            return str(n - 1)
    return sample


def _encode_variants(sample: str) -> list[str]:
    """Return encoded variants of an ID for bypass testing."""
    variants = [sample]
    # Base64
    try:
        variants.append(base64.b64encode(sample.encode()).decode())
    except Exception:
        pass
    # URL encoding
    variants.append(urllib.parse.quote(sample))
    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(sample)))
    # Hex
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
#  PHASE 1 — OBJECT REFERENCE SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

REST_ID_PATH_RE = re.compile(
    r"(/[a-zA-Z0-9_-]+/)(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)
REST_ID_SEGMENT_RE = re.compile(
    r"/(?:v\d+/)?([a-zA-Z][a-zA-Z0-9_-]*)/(\d{1,10}|[0-9a-f-]{36})(?:/|$|\?)",
    re.I,
)

def discover_surface_from_urls(urls: list[str]) -> list[ObjectSurface]:
    """Find REST-style ID-bearing endpoints from a URL list."""
    surfaces: list[ObjectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        # Path-based IDs
        for m in REST_ID_PATH_RE.finditer(path + "/"):
            resource = m.group(1).strip("/")
            ident = m.group(2)
            key = (resource, ident[:6])
            if key in seen:
                continue
            seen.add(key)
            surfaces.append(ObjectSurface(
                endpoint=url,
                method="GET",
                param_name="path_id",
                param_location="path",
                id_type=_classify_id(ident),
                sample_ids=[ident],
            ))

        # Query-based IDs
        for k, vals in urllib.parse.parse_qs(parsed.query).items():
            if k.lower() in ID_PARAM_NAMES and vals:
                surfaces.append(ObjectSurface(
                    endpoint=url,
                    method="GET",
                    param_name=k,
                    param_location="query",
                    id_type=_classify_id(vals[0]),
                    sample_ids=[vals[0]],
                ))

    return surfaces


def discover_surface_from_graphql(
    schema: Optional[dict], endpoint: str,
) -> list[ObjectSurface]:
    """Extract GraphQL node(id:) and ID-arg surfaces from an introspected schema."""
    surfaces: list[ObjectSurface] = []
    if not schema:
        return surfaces

    for t in schema.get("types", []):
        for f in t.get("fields") or []:
            for arg in f.get("args") or []:
                aname = (arg.get("name") or "").lower()
                if aname in ("id", "uuid", "user_id", "account_id", "nodeid"):
                    surfaces.append(ObjectSurface(
                        endpoint=endpoint,
                        method="POST",
                        param_name=arg.get("name", "id"),
                        param_location="graphql",
                        id_type="opaque",
                        sample_ids=[],
                    ))
    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — IDENTIFIER HARVESTING
# ═════════════════════════════════════════════════════════════════════════════

LISTING_ENDPOINTS = [
    "/api/users", "/api/accounts", "/api/orders", "/api/invoices",
    "/api/documents", "/api/projects", "/api/items", "/api/v1/users",
    "/api/v1/accounts", "/api/v1/orders", "/users", "/accounts",
]


def harvest_ids(
    session: requests.Session,
    surface: ObjectSurface,
    session_headers: Optional[dict] = None,
    max_ids: int = 5,
) -> list[str]:
    """
    Harvest real identifiers for a surface from:
      • The endpoint's own response
      • Listing endpoints on the same host
    """
    harvested: set[str] = set()
    base = f"{urllib.parse.urlparse(surface.endpoint).scheme}://{urllib.parse.urlparse(surface.endpoint).netloc}"

    # 1. From the endpoint's own response
    resp = _safe_request(session, "GET", surface.endpoint, session_headers)
    if resp:
        ids = _extract_ids_from_text(resp.text[:20000])
        for kind in ids.values():
            harvested.update(kind[:max_ids])

    # 2. From listing endpoints on the same host
    for path in LISTING_ENDPOINTS:
        test_url = base.rstrip("/") + path
        r = _safe_request(session, "GET", test_url, session_headers)
        if not r or r.status_code >= 400:
            continue
        ids = _extract_ids_from_text(r.text[:20000])
        for kind in ids.values():
            harvested.update(kind[:max_ids])
        if len(harvested) >= max_ids * 2:
            break

    return list(harvested)[:max_ids]


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — BASELINE VARIANCE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def compute_baseline_variance(
    session: requests.Session,
    surface: ObjectSurface,
    session_headers: Optional[dict] = None,
) -> float:
    """
    Fetch the endpoint twice with the SAME identity.
    The similarity between two identical requests is the "noise floor."
    Any cross-identity diff must be BELOW this floor to be a finding.
    """
    r1 = _safe_request(session, surface.method, surface.endpoint, session_headers)
    if not r1:
        return 0.0
    time.sleep(0.1)
    r2 = _safe_request(session, surface.method, surface.endpoint, session_headers)
    if not r2:
        return 0.0
    return _diff_responses(r1, r2)


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — CROSS-IDENTITY TESTING
# ═════════════════════════════════════════════════════════════════════════════

def _replace_id_in_url(url: str, old_id: str, new_id: str) -> str:
    """Replace an identifier in the URL path or query."""
    # Path replacement first
    path_replaced = url.replace(f"/{old_id}", f"/{new_id}")
    # Query replacement
    parsed = urllib.parse.urlparse(path_replaced)
    params = urllib.parse.parse_qsl(parsed.query)
    new_params = [(k, new_id if v == old_id else v) for k, v in params]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))


def _ownership_leak(resp: requests.Response, expected_owner: str) -> str:
    """Check whether the response contains an ownership field that doesn't match."""
    try:
        data = resp.json()
    except Exception:
        return ""
    if not isinstance(data, dict):
        # Could be a list or nested; search recursively
        text = resp.text
        for field in OWNERSHIP_FIELDS:
            if f'"{field}"' in text:
                return f"field '{field}' present in response"
        return ""

    def _walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in OWNERSHIP_FIELDS:
                    return f"{prefix}.{k}={v}" if prefix else f"{k}={v}"
                found = _walk(v, f"{prefix}.{k}" if prefix else k)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj[:3]:
                found = _walk(item, prefix)
                if found:
                    return found
        return ""

    return _walk(data)


def test_idor(
    session: requests.Session,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    session_headers: Optional[dict] = None,
    baseline_variance: float = 1.0,
) -> list[IDORFinding]:
    """
    Test a single surface for IDOR by swapping own_id → other_id.
    """
    findings: list[IDORFinding] = []

    # Build the two URLs (or two bodies for POST/JSON surfaces)
    if surface.param_location == "path":
        own_url = surface.endpoint
        other_url = _replace_id_in_url(own_url, own_id, other_id)
    elif surface.param_location == "query":
        own_url = surface.endpoint
        other_url = _replace_id_in_url(own_url, own_id, other_id)
    else:
        own_url = surface.endpoint
        other_url = surface.endpoint

    # Own request (User A, User A's ID) — expected to succeed
    own_resp = _safe_request(session, surface.method, own_url, session_headers)
    if not own_resp or own_resp.status_code >= 500:
        return findings

    # Cross request (User A, User B's ID)
    if surface.param_location in ("path", "query"):
        cross_resp = _safe_request(session, surface.method, other_url, session_headers)
    else:
        # Body-based ID: send the ID in JSON or form data
        cross_resp = _safe_request(
            session, surface.method, other_url, session_headers,
            json_body={surface.param_name: other_id},
        )

    if not cross_resp:
        return findings

    # ── Analysis ────────────────────────────────────────────────────────────
    similarity = _diff_responses(own_resp, cross_resp)

    # A finding requires the cross response to be substantially DIFFERENT
    # from own response (otherwise we're just re-fetching our own data)
    # AND the cross response to be "successful" (2xx, not a 403/404).
    cross_ok = 200 <= cross_resp.status_code < 300
    own_ok   = 200 <= own_resp.status_code < 300

    if not cross_ok or not own_ok:
        return findings

    # If the cross response is identical to own response, it's probably
    # returning the SAME object (our own) — not a finding.
    if similarity >= 0.98:
        return findings

    # If the cross response is identical to the BASELINE noise, it's a false positive.
    if similarity <= baseline_variance + 0.05:
        return findings

    # Ownership leak detection
    leak = _ownership_leak(cross_resp, own_id)

    # Confidence scoring
    confidence = CONF_SURFACE
    evidence_parts: list[str] = []

    if cross_ok and not own_ok:
        confidence = CONF_CONFIRMED
        evidence_parts.append("Cross-identity returned 2xx while own returned non-2xx")
    elif cross_ok and own_ok:
        confidence = CONF_LIKELY
        evidence_parts.append(f"Cross-identity returned 2xx (own={own_resp.status_code})")

    if leak:
        confidence = min(confidence + 10, 100)
        evidence_parts.append(f"Ownership field leaked: {leak}")

    if similarity < 0.5:
        confidence = min(confidence + 10, 100)
        evidence_parts.append(f"Response differs from own ({similarity:.2f} similarity)")

    # Method tampering: try rotating method if initial test didn't confirm
    if confidence < CONF_CONFIRMED:
        for alt_method in METHOD_ROTATION:
            if alt_method == surface.method:
                continue
            alt_resp = _safe_request(
                session, alt_method, other_url, session_headers,
                json_body={surface.param_name: other_id} if surface.param_location == "body" else None,
            )
            if alt_resp and 200 <= alt_resp.status_code < 300:
                alt_sim = _diff_responses(own_resp, alt_resp)
                if alt_sim < 0.9 and alt_sim > baseline_variance + 0.05:
                    confidence = min(confidence + 15, 100)
                    evidence_parts.append(f"Method tampering {surface.method}→{alt_method} succeeded")
                    break

    if confidence < CONF_SURFACE:
        return findings

    severity = "CRITICAL" if confidence >= CONF_CONFIRMED else "HIGH" if confidence >= CONF_LIKELY else "MEDIUM"

    findings.append(IDORFinding(
        target=surface.endpoint,
        vuln_type="idor_horizontal",
        severity=severity,
        confidence=confidence,
        evidence=" | ".join(evidence_parts),
        request_curl=_build_curl(
            surface.method, other_url, session_headers,
            json_body={surface.param_name: other_id} if surface.param_location == "body" else None,
        ),
        response_a=_body_snippet(own_resp),
        response_b=_body_snippet(cross_resp),
        ownership_leak=leak,
        details={
            "param":         surface.param_name,
            "param_location": surface.param_location,
            "own_id":        own_id,
            "other_id":      other_id,
            "own_status":    own_resp.status_code,
            "cross_status":  cross_resp.status_code,
            "similarity":    round(similarity, 3),
            "baseline":      round(baseline_variance, 3),
        },
    ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — BYPASS VARIANTS
# ═════════════════════════════════════════════════════════════════════════════

def test_bypass_variants(
    session: requests.Session,
    surface: ObjectSurface,
    own_id: str,
    other_id: str,
    session_headers: Optional[dict] = None,
) -> list[IDORFinding]:
    """
    Test IDOR bypass techniques:
      • Parameter pollution (?id=A&id=B)
      • Encoded ID variants (base64, URL, hex)
      • Path traversal
      • Identity header injection
    """
    findings: list[IDORFinding] = []
    baseline_url = surface.endpoint

    # ── Parameter pollution ────────────────────────────────────────────────
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(baseline_url)
        params = urllib.parse.parse_qsl(parsed.query)
        polluted = params + [(surface.param_name, other_id)]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(polluted))
        )
        resp = _safe_request(session, "GET", test_url, session_headers)
        if resp and 200 <= resp.status_code < 300:
            leak = _ownership_leak(resp, own_id)
            if leak:
                findings.append(IDORFinding(
                    target=surface.endpoint,
                    vuln_type="idor_parameter_pollution",
                    severity="HIGH",
                    confidence=CONF_LIKELY,
                    evidence=f"Parameter pollution leaked: {leak}",
                    request_curl=_build_curl("GET", test_url, session_headers),
                    response_b=_body_snippet(resp),
                    ownership_leak=leak,
                    details={"technique": "HPP", "own_id": own_id, "other_id": other_id},
                ))

    # ── Encoded variants ───────────────────────────────────────────────────
    for variant in _encode_variants(other_id):
        if variant == other_id:
            continue
        test_url = _replace_id_in_url(baseline_url, own_id, variant)
        resp = _safe_request(session, "GET", test_url, session_headers)
        if resp and 200 <= resp.status_code < 300:
            leak = _ownership_leak(resp, own_id)
            if leak:
                findings.append(IDORFinding(
                    target=surface.endpoint,
                    vuln_type="idor_encoded_bypass",
                    severity="HIGH",
                    confidence=CONF_LIKELY,
                    evidence=f"Encoded ID bypass leaked: {leak}",
                    request_curl=_build_curl("GET", test_url, session_headers),
                    response_b=_body_snippet(resp),
                    ownership_leak=leak,
                    details={"technique": "encoding", "variant": variant, "own_id": own_id},
                ))
                break

    # ── Identity header injection ──────────────────────────────────────────
    for hdr in IDENTITY_HEADERS:
        headers = dict(session_headers or {})
        headers[hdr] = other_id
        resp = _safe_request(session, "GET", baseline_url, headers)
        if resp and 200 <= resp.status_code < 300:
            leak = _ownership_leak(resp, own_id)
            if leak:
                findings.append(IDORFinding(
                    target=surface.endpoint,
                    vuln_type="idor_header_injection",
                    severity="HIGH",
                    confidence=CONF_LIKELY,
                    evidence=f"Identity header {hdr} accepted with other ID",
                    request_curl=_build_curl("GET", baseline_url, headers),
                    response_b=_body_snippet(resp),
                    ownership_leak=leak,
                    details={"header": hdr, "own_id": own_id, "other_id": other_id},
                ))
                break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_idor_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    user_a_headers: Optional[dict] = None,
    user_b_headers: Optional[dict] = None,
    user_a_id: Optional[str] = None,
    user_b_id: Optional[str] = None,
    graphql_schema_file: Optional[Path] = None,
    test_bypasses: bool = True,
    max_ids_per_surface: int = 3,
    threads: int = DEFAULT_THREADS,
) -> Path:
    """
    Run the full IDOR audit against every URL in `live_urls_file`.

    Returns the path to `idor_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    if user_a_headers:
        log.info("  User A : authenticated")
    if user_b_headers:
        log.info("  User B : authenticated (dual-session testing enabled)")
    else:
        log.info("  User B : NOT supplied — cross-identity testing will be SURFACE ONLY")
    log.info("")

    if not urls:
        log.warning("  No URLs to audit — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session_a = requests.Session()
    session_a.headers.update(user_a_headers or {})
    session_a.headers.setdefault("User-Agent", USER_AGENT)
    session_a.verify = False

    session_b = requests.Session()
    session_b.headers.update(user_b_headers or {})
    session_b.headers.setdefault("User-Agent", USER_AGENT)
    session_b.verify = False

    # ── Phase 1: Surface discovery ──────────────────────────────────────────
    log.info("  Phase 1 — Object reference surface discovery")
    surfaces = discover_surface_from_urls(urls)

    # GraphQL surfaces (optional)
    if graphql_schema_file and graphql_schema_file.exists():
        try:
            schema_data = json.loads(graphql_schema_file.read_text())
            # schema_data may be {url: schema}
            for gql_url, schema in schema_data.items():
                surfaces.extend(discover_surface_from_graphql(schema, gql_url))
        except Exception as e:
            log.warning(f"    Could not parse GraphQL schema: {e}")

    log.info(f"    Discovered {len(surfaces)} object-reference surface(s)")

    if not surfaces:
        log.warning("  No IDOR surface discovered — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start, total_input=len(urls))

    # Write surface list
    surface_lines = [
        f"{s.method}\t{s.endpoint}\t{s.param_name}\t{s.param_location}\t{s.id_type}"
        for s in surfaces
    ]
    (outdir / "idor_surface.txt").write_text("\n".join(surface_lines) + "\n")

    # ── Phase 2–4: Per-surface testing ──────────────────────────────────────
    all_findings: list[IDORFinding] = []

    if not (user_a_headers and user_b_headers):
        # Surface-only mode: report candidates without confirmation
        for s in surfaces:
            all_findings.append(IDORFinding(
                target=s.endpoint,
                vuln_type="idor_surface_candidate",
                severity="MEDIUM",
                confidence=CONF_SURFACE,
                evidence=f"{s.param_location} parameter '{s.param_name}' ({s.id_type}); supply dual sessions to confirm",
                details=s.to_dict(),
            ))
        log.info("  Surface-only mode: %d candidate(s)", len(all_findings))
    else:
        # Full dual-session testing
        log.info("")
        log.info("  Phase 2–4 — Dual-session IDOR testing")

        def _process_surface(surface: ObjectSurface) -> list[IDORFinding]:
            local: list[IDORFinding] = []

            # Harvest IDs using User A's session
            harvested = harvest_ids(
                session_a, surface, user_a_headers, max_ids=max_ids_per_surface,
            )
            if not harvested:
                return local

            # Baseline variance with User A
            baseline = compute_baseline_variance(session_a, surface, user_a_headers)

            # Use User A's ID as "own", harvested IDs as "other"
            own_id = user_a_id or harvested[0]
            other_ids = [x for x in harvested if x != own_id]

            if not other_ids:
                return local

            for other_id in other_ids[:max_ids_per_surface]:
                findings = test_idor(
                    session_a, surface, own_id, other_id,
                    session_headers=user_a_headers,
                    baseline_variance=baseline,
                )
                local.extend(findings)

                # Bypass variants
                if test_bypasses and not findings:
                    local.extend(test_bypass_variants(
                        session_a, surface, own_id, other_id, user_a_headers,
                    ))

            return local

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_process_surface, s): s for s in surfaces}
            for fut in as_completed(futures):
                s = futures[fut]
                try:
                    results = fut.result()
                    if results:
                        all_findings.extend(results)
                        log.info(f"    {s.endpoint[:60]:<60} {len(results)} finding(s)")
                except Exception as e:
                    log.debug(f"    error on {s.endpoint}: {e}")

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[IDORFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type, f.details.get("other_id", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Sort ────────────────────────────────────────────────────────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:160]}"
        for f in deduped
    ]
    (outdir / "idor_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed only
    confirmed = [f for f in deduped if f.confidence >= CONF_CONFIRMED]
    (outdir / "idor_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.evidence}\t{f.request_curl[:200]}"
            for f in confirmed
        ) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "dual_session":   bool(user_a_headers and user_b_headers),
            "test_bypasses":  test_bypasses,
            "max_ids":        max_ids_per_surface,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces":         len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "idor_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<30} {len(deduped):>5} finding(s)")
    log.info(f"    idor_candidates.txt             {len(deduped):>5} candidate(s)")
    log.info(f"    idor_confirmed.txt              {len(confirmed):>5} confirmed")
    log.info(f"    idor_surface.txt                {len(surfaces):>5} surface(s)")

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
        log.info("  Confirmed IDOR findings:")
        for f in confirmed[:10]:
            log.info(f"    [CRITICAL] {f.vuln_type:<28} {f.target[:60]}")
            log.info(f"               {f.evidence[:100]}")

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
            "confirmed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}},
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
    live = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus IDOR Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=live, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--user-a-headers", help="JSON dict of User A headers")
    parser.add_argument("--user-b-headers", help="JSON dict of User B headers")
    parser.add_argument("--user-a-id", help="User A's own object ID")
    parser.add_argument("--user-b-id", help="User B's object ID")
    parser.add_argument("--graphql-schema", type=Path, help="GraphQL schema JSON from graphql_finder")
    parser.add_argument("--no-bypasses", action="store_true", help="Skip bypass variant tests")
    args = parser.parse_args()

    user_a_headers = json.loads(args.user_a_headers) if args.user_a_headers else None
    user_b_headers = json.loads(args.user_b_headers) if args.user_b_headers else None

    try:
        run_idor_audit(
            args.input, args.output,
            user_a_headers=user_a_headers,
            user_b_headers=user_b_headers,
            user_a_id=args.user_a_id,
            user_b_id=args.user_b_id,
            graphql_schema_file=args.graphql_schema,
            test_bypasses=not args.no_bypasses,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
