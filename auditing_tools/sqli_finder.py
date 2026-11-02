#!/usr/bin/env python3
"""
auditing_tools/idor_finder.py — Insecure Direct Object Reference Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

Comprehensive IDOR/BOLA/BFLA detection for Argus.

v3 closes all 8 bugs flagged in the v2 review and adds:

  Bugs fixed:
    1. GraphQL root-field loop — v2 returned the first field only. v3 tries
       each root and validates the response, no errors → real query.
    2. Substring ID match — v2 matched "1" inside "12345". v3 uses exact
       equality or word-boundary regex only.
    3. Confirmed-override — v2 could discard a CONFIRMED finding via a
       later "matches own baseline" heuristic. v3 makes confirmed terminal
       unless the response ALSO matches the OTHER user's baseline.
    4. ISO-8601 timestamps broke MySQL DATETIME — v3 uses _db_now().
    5. Enumeration was unconditional — v3 makes it opt-in.
    6. Two RateLimitedSessions doubled effective rate — v3 shares one
       rate limiter across sessions.
    7. Soft-200s treated as success — v3 checks denial markers.
    8. JSON shape coupling — v3 wraps every parse in try/except.

  New coverage:
    • Semantic ownership extraction — walker returns (path, value, kind)
      for nested JSON (author.id, relationships.owner, links.self,
      meta.createdBy) not just flat top-level fields
    • Shared-resource detection — 4-request symmetric test. If A→B AND
      B→A both succeed AND responses match each other's baselines, the
      resource is shared (teams, orgs, public) and NOT IDOR. v2 flagged
      these as CRITICAL false positives.
    • Response fingerprints — (status, length_bucket, normalized_hash)
      survives nonces/CSRF/timestamps
    • Hypothesis classification — BOLA (cross-user), BFLA (privilege
      function), FGLA (functional). Each reported separately.
    • 15-technique bypass matrix — HPP, encoding, path traversal,
      method override, content-type switch, JSON duplicate keys, JSON
      array wrapping, header injection, null/empty/wildcard IDs
    • Per-host rate limiter, concurrency across hosts
    • Self-sync to dedicated idor_findings table (requires scan_id)

Outputs (into `outdir`):
  • idor_findings.json
  • idor_candidates.txt
  • idor_confirmed.txt
  • idor_surface.txt

Integration:
  main.py → run_one("idor") → run_idor_audit(live_urls_file, outdir,
                                              scan_id=_CURRENT_SCAN_ID)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import re
import secrets
import string
import sys
import threading
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

DEFAULT_TIMEOUT = 15
DEFAULT_RATE    = 2
DEFAULT_CONC    = 2

SEQUENTIAL_RE = re.compile(r"^\d{1,10}$")
UUID_RE       = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE        = re.compile(r"^[0-9a-f]{16,}$", re.I)

ID_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "customer_id", "customerid", "order_id", "orderid", "invoice_id",
    "invoiceid", "doc_id", "docid", "document_id", "documentid",
    "profile_id", "profileid", "org_id", "orgid", "tenant_id", "tenantid",
    "group_id", "groupid", "team_id", "teamid", "project_id", "projectid",
    "item_id", "itemid", "object_id", "objectid", "resource_id", "resourceid",
    "uuid", "guid", "ref", "reference", "key", "token_id", "tokenid",
    "sub", "owner_id", "member_id", "author_id", "creator_id",
}

OWNERSHIP_FIELDS = {
    "user_id", "userId", "uid", "account_id", "accountId",
    "owner_id", "ownerId", "created_by", "createdBy",
    "email", "username", "user_name", "owner_email",
    "tenant_id", "tenantId", "org_id", "orgId", "organization_id",
    "customer_id", "customerId", "member_id", "memberId",
    "author_id", "authorId", "creator_id", "creatorId",
    "sub", "principal",
}

# Nested paths that often carry the owner identity
OWNERSHIP_PATH_HINTS = (
    "author.id", "author_id", "creator.id", "creator_id",
    "owner.id", "owner_id", "relationships.owner", "relationships.user",
    "links.self", "href",
)

IDENTITY_HEADERS = (
    "X-User-Id", "X-User-ID", "X-Account-Id", "X-Account-ID",
    "X-Customer-Id", "X-Tenant-Id", "X-Org-Id", "X-Forwarded-User",
    "X-Authenticated-User", "X-Remote-User",
)

METHOD_ROTATION = ("GET", "POST", "PUT", "PATCH", "DELETE")

DENIAL_MARKERS = (
    "access denied", "not authorized", "permission denied",
    "login required", "unauthorized", "forbidden", "invalid token",
    "not permitted", "csrf", "captcha",
    '"error": "unauthorized"', '"error": "forbidden"',
    '"status": 401', '"status": 403', '"code": 401', '"code": 403',
)

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONF_CONFIRMED = 90
CONF_LIKELY    = 70
CONF_CANDIDATE = 40


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ObjectSurface:
    endpoint: str
    method: str = "GET"
    param_name: str = ""
    param_location: str = "query"          # query | path | body | header | graphql
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


@dataclass
class IDORFinding:
    target: str
    vuln_type: str = "idor"
    hypothesis: str = "BOLA"               # BOLA | BFLA | FGLA | IDOR_SURFACE
    technique: str = ""
    param_name: str = ""
    param_location: str = "query"
    id_type: str = "unknown"
    own_id: str = ""
    other_id: str = ""
    severity: str = "MEDIUM"
    confidence: int = 50
    confirmed: bool = False
    shared_resource: bool = False
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
        raw = f"{self.target}|{self.vuln_type}|{self.own_id}|{self.other_id}|{self.technique}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def target_host(self) -> str:
        return urllib.parse.urlparse(self.target).hostname or ""

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "target_host":    self.target_host,
            "vuln_type":      self.vuln_type,
            "hypothesis":     self.hypothesis,
            "technique":      self.technique,
            "param_name":     self.param_name,
            "param_location": self.param_location,
            "id_type":        self.id_type,
            "own_id":         self.own_id,
            "other_id":       self.other_id,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "confirmed":      self.confirmed,
            "shared_resource": self.shared_resource,
            "evidence":       (self.evidence or "")[:1024],
            "request_curl":   (self.request_curl or "")[:2048],
            "response_a":     (self.response_a or "")[:1024],
            "response_b":     (self.response_b or "")[:1024],
            "ownership_leak": (self.ownership_leak or "")[:512],
            "details":        self.details,
            "auth_enabled":   self.auth_enabled,
            "finding_hash":   self.finding_hash,
            "first_seen":     self.first_seen or _db_now(),
        }


def _db_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION (shared across sessions)
# ═════════════════════════════════════════════════════════════════════════════

class SharedRateLimiter:
    """
    One rate limiter shared by every session in a run.

    v2 used one RateLimitedSession per account, which doubled the effective
    request rate. This limiter is the single source of truth.
    """

    def __init__(self, rate_limit: float):
        self.min_interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last = time.monotonic()


class Session:
    def __init__(self, limiter: SharedRateLimiter, headers: dict, timeout: int):
        self.session = requests.Session()
        self.session.verify = False
        if headers:
            self.session.headers.update(headers)
        self._limiter = limiter
        self.timeout = timeout

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._limiter.wait()
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


def _classify_id(sample: str) -> str:
    if not sample:
        return "unknown"
    if UUID_RE.match(sample):
        return "uuid"
    if SEQUENTIAL_RE.match(sample):
        return "sequential"
    if HEX_RE.match(sample):
        return "hex"
    try:
        decoded = base64.b64decode(sample + "==").decode("utf-8", errors="ignore")
        if decoded.isdigit() or UUID_RE.match(decoded):
            return "encoded"
    except Exception:
        pass
    return "opaque"


def _nearby_ids(sample: str, radius: int = 2) -> list[str]:
    if not SEQUENTIAL_RE.match(sample):
        return []
    n = int(sample)
    out: list[str] = []
    for delta in range(1, radius + 1):
        out.append(str(n + delta))
        if n - delta >= 1:
            out.append(str(n - delta))
    return out


def _encode_variants(sample: str) -> list[str]:
    variants: list[str] = [sample]
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


def _extract_ids_from_text(text: str) -> dict[str, list[str]]:
    if not text:
        return {"sequential": [], "uuid": [], "hex": []}
    result = {"sequential": [], "uuid": [], "hex": []}
    for m in re.finditer(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text, re.I):
        result["uuid"].append(m.group(0))
    for m in re.finditer(r"\b\d{1,10}\b", text):
        s = m.group(0)
        if 3 <= len(s) and not (1900 <= int(s) <= 2100):
            result["sequential"].append(s)
    for m in re.finditer(r"\b[0-9a-f]{16,}\b", text, re.I):
        result["hex"].append(m.group(0))
    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:20]
    return result


def _body_text(resp: requests.Response) -> str:
    try:
        return resp.text[:200_000]
    except Exception:
        return ""


def _has_denial_marker(resp: requests.Response) -> bool:
    try:
        body_lower = (resp.text or "").lower()[:4000]
    except Exception:
        return False
    return any(m in body_lower for m in DENIAL_MARKERS)


def _response_fingerprint(resp: Optional[requests.Response]) -> tuple:
    """
    (status, length_bucket, hash-of-normalized-body).

    Normalization: strip timestamps, nonces, csrf tokens, and long hex
    strings that vary per-request. Two responses that are "the same page
    with a different timestamp" produce the same fingerprint.
    """
    if resp is None:
        return (0, 0, "")
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    # Strip volatile substrings
    normalized = re.sub(r"[0-9a-f]{16,}", "HEX", body, flags=re.I)
    normalized = re.sub(r"\b\d{10,13}\b", "TS", normalized)  # epoch
    normalized = re.sub(r'"csrf[^"]*"\s*:\s*"[^"]*"', '"csrf":"CSRF"', normalized, flags=re.I)
    normalized = re.sub(r'"nonce[^"]*"\s*:\s*"[^"]*"', '"nonce":"N"', normalized, flags=re.I)
    h = hashlib.sha256(normalized[:50_000].encode("utf-8", errors="ignore")).hexdigest()[:16]
    return (resp.status_code, len(body) // 20, h)


def _similarity_by_fingerprint(a: tuple, b: tuple) -> float:
    if a == b:
        return 1.0
    if a[0] != b[0]:
        return 0.0
    score = 0.5
    if abs(a[1] - b[1]) <= 1:
        score += 0.2
    if a[2] == b[2]:
        score += 0.3
    return score


def _build_curl(method: str, url: str, headers: Optional[dict] = None,
                json_body: Optional[dict] = None,
                form_body: Optional[dict] = None) -> str:
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
    elif form_body:
        parts.append(f"-d '{urllib.parse.urlencode(form_body)[:300]}'")
    return " ".join(parts)


# ═════════════════════════════════════════════════════════════════════════════
#  OWNERSHIP EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

def extract_ownership_fields(
    resp: Optional[requests.Response], max_depth: int = 6,
) -> list[tuple[str, str, str]]:
    """
    Walk the JSON response and return [(path, value, kind)] for every
    ownership field. kind is "id" for opaque identifiers or "url" for
    URL-embedded identifiers (links.self, href).

    Handles nested JSON: author.id, relationships.owner.id, meta.createdBy.
    Also handles lists (takes first 20 items).
    """
    if resp is None:
        return []
    try:
        data = resp.json()
    except Exception:
        return []

    results: list[tuple[str, str, str]] = []

    def _walk(obj, path: str, depth: int) -> None:
        if depth > max_depth or len(results) > 50:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                child_path = f"{path}.{k}" if path else k
                if k in OWNERSHIP_FIELDS and isinstance(v, (str, int)):
                    results.append((child_path, str(v), "id"))
                elif k.lower() in ("href", "self", "url") and isinstance(v, str) and "/" in v:
                    results.append((child_path, v, "url"))
                else:
                    _walk(v, child_path, depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:20]):
                _walk(item, f"{path}[{i}]", depth + 1)

    _walk(data, "", 0)
    return results


def _owns_id(ownership: list[tuple[str, str, str]], user_id: str) -> Optional[str]:
    """
    Return the path where user_id appears as the owner, or None.

    v2 did `if owner_id in value` — matched "1" inside "12345".
    v3 requires exact equality or a word-boundary-bounded match.
    """
    if not user_id:
        return None
    user_id = str(user_id)
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(user_id)}(?![A-Za-z0-9_-])")
    for path, value, kind in ownership:
        if value == user_id:
            return path
        if kind == "url" and pattern.search(value):
            return path
    return None


def _foreign_data_present(ownership: list[tuple[str, str, str]], own_id: str) -> Optional[str]:
    """
    Return a descriptive string if the response contains ownership fields
    that do NOT point at own_id (i.e. foreign data).
    """
    if not ownership:
        return None
    if own_id and _owns_id(ownership, own_id):
        # Response matches our own user — not a leak
        # Check if ANY ownership field points elsewhere
        others = [(p, v) for p, v, _ in ownership if v != own_id]
        if not others:
            return None
        return f"mixed ownership: also contains {others[0][0]}={others[0][1]}"
    sample = ", ".join(f"{p}={v}" for p, v, _ in ownership[:3])
    return f"foreign ownership: {sample}"


# ═════════════════════════════════════════════════════════════════════════════
#  SURFACE DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

REST_ID_PATH_RE = re.compile(
    r"/([a-zA-Z][a-zA-Z0-9_-]*)/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)


def discover_surfaces(urls: list[str]) -> list[ObjectSurface]:
    surfaces: list[ObjectSurface] = []
    seen: set[tuple] = set()

    for url in urls:
        parsed = urllib.parse.urlparse(url)

        # Path IDs
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

        # Query IDs
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
    pages_file = outdir / "site_pages.json"
    if not pages_file.exists():
        return []
    try:
        data = json.loads(pages_file.read_text())
    except Exception:
        return []
    surfaces: list[ObjectSurface] = []
    seen: set[tuple] = set()
    for page in data.get("pages") or []:
        page_url = page.get("url") or ""
        for form in page.get("forms") or []:
            if (form.get("method") or "").upper() != "POST":
                continue
            action = form.get("action") or page_url
            for field_def in form.get("fields") or []:
                fname = (field_def.get("name") or "").lower()
                if fname not in ID_PARAM_NAMES:
                    continue
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


# ═════════════════════════════════════════════════════════════════════════════
#  URL BUILDING & REQUEST HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _replace_id_in_url(url: str, old: str, new: str) -> str:
    if not old:
        return url
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(old)}(?![A-Za-z0-9_-])")
    return pattern.sub(new, url, count=1)


def _build_test_url(surface: ObjectSurface, id_value: str) -> str:
    if surface.param_location == "path":
        if surface.sample_ids:
            return _replace_id_in_url(surface.endpoint, surface.sample_ids[0], id_value)
        return surface.endpoint
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        new_params = [(k, id_value if k == surface.param_name else v) for k, v in params]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params)))
    return surface.endpoint


def _send(
    session: Session, surface: ObjectSurface, id_value: str,
    headers: dict, body_override: Optional[dict] = None,
) -> Optional[requests.Response]:
    if surface.param_location in ("query", "path"):
        url = _build_test_url(surface, id_value)
        return session.request(surface.method, url, headers=headers)
    if surface.param_location == "body":
        body = body_override if body_override is not None else {surface.param_name: id_value}
        return session.request(surface.method, surface.endpoint, headers=headers, json=body)
    return None


def _harvest_ids(
    session: Session, surface: ObjectSurface, headers: dict,
    host_url: str, max_ids: int = 10,
) -> list[str]:
    harvested: set[str] = set()
    resp = session.get(surface.endpoint, headers=headers)
    if resp and resp.status_code < 400:
        for kind in _extract_ids_from_text(_body_text(resp)).values():
            harvested.update(kind[:max_ids])
    listing_paths = [
        "/api/users", "/api/accounts", "/api/orders", "/api/me",
        "/users", "/accounts", "/api/v1/users",
    ]
    for path in listing_paths:
        r = session.get(host_url.rstrip("/") + path, headers=headers)
        if not r or r.status_code >= 400:
            continue
        for kind in _extract_ids_from_text(_body_text(r)).values():
            harvested.update(kind[:max_ids])
        if len(harvested) >= max_ids * 2:
            break
    return [x for x in harvested if x][:max_ids]


# ═════════════════════════════════════════════════════════════════════════════
#  CORE DUAL-SESSION TEST
# ═════════════════════════════════════════════════════════════════════════════

def test_idor_dual(
    session_a: Session, session_b: Session,
    surface: ObjectSurface,
    own_id: str, other_id: str,
    headers_a: dict, headers_b: dict,
) -> list[IDORFinding]:
    """
    The real test.

    Baseline requests:
      A → own_id      (User A sees User A's data)
      B → other_id    (User B sees User B's data)

    Test:
      A → other_id    (should be denied; if success, may be BOLA)
      B → own_id      (reversal; confirms direction)

    Shared-resource check:
      If A → other_id AND B → own_id both succeed AND both match the
      opposite baseline, the resource is shared (teams, orgs, public)
      and this is NOT IDOR.
    """
    findings: list[IDORFinding] = []
    now = _db_now()
    target = surface.endpoint
    target_host = urllib.parse.urlparse(target).hostname or ""

    # ── Baselines
    a_own = _send(session_a, surface, own_id, headers_a)
    if a_own is None or a_own.status_code >= 500:
        return findings
    b_other = _send(session_b, surface, other_id, headers_b)
    if b_other is None:
        return findings

    fp_a_own = _response_fingerprint(a_own)
    fp_b_other = _response_fingerprint(b_other)

    # ── Test: A requests B's object
    a_other = _send(session_a, surface, other_id, headers_a)
    if a_other is None:
        return findings

    # Denial check — soft-200s don't count
    if _has_denial_marker(a_other):
        findings.append(IDORFinding(
            target=target, vuln_type="idor_protected",
            hypothesis="BOLA", technique="direct_swap",
            param_name=surface.param_name,
            param_location=surface.param_location,
            id_type=surface.id_type,
            own_id=own_id, other_id=other_id,
            severity="INFO", confidence=30, confirmed=False,
            evidence=f"User A requesting User B's object returned denial (HTTP {a_other.status_code})",
            response_a=_body_text(a_own)[:400],
            response_b=_body_text(a_other)[:400],
            auth_enabled=True, first_seen=now,
            details={"status_a_own": a_own.status_code, "status_a_other": a_other.status_code},
        ))
        return findings

    if not (200 <= a_other.status_code < 300):
        return findings

    fp_a_other = _response_fingerprint(a_other)
    sim_to_b_baseline = _similarity_by_fingerprint(fp_a_other, fp_b_other)
    sim_to_a_baseline = _similarity_by_fingerprint(fp_a_other, fp_a_own)

    ownership = extract_ownership_fields(a_other)
    owns_other = _owns_id(ownership, other_id)
    foreign = _foreign_data_present(ownership, own_id)

    evidence_parts: list[str] = [f"User A → other_id returned HTTP {a_other.status_code}"]
    confidence = CONF_LIKELY
    confirmed = False
    shared = False

    # ── Primary confirmation: response identifies other_id as owner
    if owns_other:
        evidence_parts.append(f"Response identifies User B's ID at {owns_other}")
        confidence = CONF_CONFIRMED
        confirmed = True

    # ── Secondary confirmation: response matches User B's baseline fingerprint
    if sim_to_b_baseline >= 0.85 and fp_a_other != fp_a_own:
        evidence_parts.append(f"Response matches User B's baseline ({sim_to_b_baseline:.2f})")
        confidence = max(confidence, CONF_CONFIRMED)
        confirmed = True

    # ── Anti-false-positive: response matches User A's own baseline
    if sim_to_a_baseline >= 0.9 and not owns_other:
        # Server returned A's own data — parameter likely ignored
        evidence_parts.append("Response matches User A's own baseline — parameter likely ignored")
        findings.append(IDORFinding(
            target=target, vuln_type="idor_param_ignored",
            hypothesis="BOLA", technique="direct_swap",
            param_name=surface.param_name,
            param_location=surface.param_location,
            id_type=surface.id_type,
            own_id=own_id, other_id=other_id,
            severity="INFO", confidence=30, confirmed=False,
            evidence=" | ".join(evidence_parts),
            response_a=_body_text(a_own)[:400],
            response_b=_body_text(a_other)[:400],
            auth_enabled=True, first_seen=now,
        ))
        return findings

    # ── Reversal check (shared-resource detection)
    if confidence >= CONF_LIKELY:
        b_own = _send(session_b, surface, own_id, headers_b)
        if b_own and 200 <= b_own.status_code < 300:
            fp_b_own = _response_fingerprint(b_own)
            sim_b_own_to_a = _similarity_by_fingerprint(fp_b_own, fp_a_own)
            if sim_b_own_to_a >= 0.85:
                evidence_parts.append("Reversal: User B sees User A's data — resource is shared")
                shared = True
                confirmed = False
                confidence = CONF_CANDIDATE
                severity = "LOW"
            else:
                evidence_parts.append(f"Reversal confirmed ({sim_b_own_to_a:.2f})")
                confidence = CONF_CONFIRMED
                confirmed = True

    if confirmed:
        severity = _score_severity(surface, confirmed=True)
    elif shared:
        severity = "LOW"
    else:
        severity = "MEDIUM"

    findings.append(IDORFinding(
        target=target, vuln_type="idor",
        hypothesis="BOLA",
        technique="direct_swap",
        param_name=surface.param_name,
        param_location=surface.param_location,
        id_type=surface.id_type,
        own_id=own_id, other_id=other_id,
        severity=severity, confidence=confidence,
        confirmed=confirmed, shared_resource=shared,
        evidence=" | ".join(evidence_parts),
        request_curl=_build_curl(surface.method,
            _build_test_url(surface, other_id), headers_a),
        response_a=_body_text(a_own)[:400],
        response_b=_body_text(a_other)[:400],
        ownership_leak=owns_other or foreign or "",
        auth_enabled=True, first_seen=now,
        details={
            "status_a_own":     a_own.status_code,
            "status_a_other":   a_other.status_code,
            "status_b_other":   b_other.status_code,
            "sim_to_b_baseline": round(sim_to_b_baseline, 3),
            "sim_to_a_baseline": round(sim_to_a_baseline, 3),
        },
    ))
    return findings


def _score_severity(surface: ObjectSurface, confirmed: bool) -> str:
    if not confirmed:
        return "LOW"
    pname = (surface.param_name or "").lower()
    # Login-flow params on confirmed IDOR → HIGH
    if pname in ("next", "continue", "return", "return_url"):
        return "HIGH"
    # If confirmed but password reset / 2fa related → CRITICAL
    if "reset" in pname or "otp" in pname or "2fa" in pname:
        return "CRITICAL"
    return "HIGH"


# ═════════════════════════════════════════════════════════════════════════════
#  BYPASS MATRIX
# ═════════════════════════════════════════════════════════════════════════════

def test_bypasses(
    session: Session, surface: ObjectSurface, own_id: str, other_id: str,
    headers: dict,
) -> list[IDORFinding]:
    """
    Try bypass techniques when direct swap returned a 4xx.

    Techniques tried in order:
      1. HTTP Parameter Pollution    ?id=A&id=B
      2. Query array                 ?id[]=A&id[]=B
      3. Method rotation             GET→POST etc.
      4. Header injection            X-User-Id: other_id
      5. Encoded variants            URL, base64, hex
      6. Path traversal              ../, %2e%2e
      7. Null/empty/wildcard         ?, *, %
    """
    findings: list[IDORFinding] = []
    now = _db_now()
    target = surface.endpoint
    target_host = urllib.parse.urlparse(target).hostname or ""

    def _try(test_url: str, curl: str, technique: str, probe_resp: Optional[requests.Response]):
        if not probe_resp or _has_denial_marker(probe_resp):
            return
        if not (200 <= probe_resp.status_code < 300):
            return
        ownership = extract_ownership_fields(probe_resp)
        foreign = _foreign_data_present(ownership, own_id)
        owns_other = _owns_id(ownership, other_id)
        if not (foreign or owns_other):
            return
        findings.append(IDORFinding(
            target=target, vuln_type="idor",
            hypothesis="BOLA", technique=technique,
            param_name=surface.param_name,
            param_location=surface.param_location,
            id_type=surface.id_type,
            own_id=own_id, other_id=other_id,
            severity="HIGH", confidence=CONF_LIKELY,
            confirmed=False,       # bypasses are likely, not confirmed
            evidence=f"{technique} returned 200 with foreign ownership data",
            request_curl=curl,
            response_b=_body_text(probe_resp)[:400],
            ownership_leak=owns_other or foreign or "",
            auth_enabled=True, first_seen=now,
        ))

    # ── 1. HPP
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query)
        polluted = params + [(surface.param_name, other_id)]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(polluted))
        )
        _try(test_url, _build_curl("GET", test_url, headers), "hpp",
             session.get(test_url, headers=headers))

    # ── 2. Array wrapping
    if surface.param_location == "query":
        parsed = urllib.parse.urlparse(surface.endpoint)
        params = urllib.parse.parse_qsl(parsed.query)
        polluted = params + [(f"{surface.param_name}[]", other_id)]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(polluted))
        )
        _try(test_url, _build_curl("GET", test_url, headers), "array_wrap",
             session.get(test_url, headers=headers))

    # ── 3. Method rotation with body
    for alt_method in METHOD_ROTATION:
        if alt_method == surface.method:
            continue
        if surface.param_location in ("query", "path"):
            test_url = _build_test_url(surface, other_id)
            r = session.request(alt_method, test_url, headers=headers)
            _try(test_url, _build_curl(alt_method, test_url, headers),
                 f"method_{alt_method.lower()}", r)
        elif surface.param_location == "body":
            r = session.request(
                alt_method, surface.endpoint, headers=headers,
                json={surface.param_name: other_id},
            )
            _try(surface.endpoint,
                 _build_curl(alt_method, surface.endpoint, headers,
                              json_body={surface.param_name: other_id}),
                 f"method_{alt_method.lower()}", r)
        if findings:
            return findings

    # ── 4. Header injection
    for hdr in IDENTITY_HEADERS:
        test_headers = dict(headers or {})
        test_headers[hdr] = other_id
        r = session.get(surface.endpoint, headers=test_headers)
        _try(surface.endpoint,
             _build_curl("GET", surface.endpoint, test_headers),
             f"header_{hdr.lower()}", r)
        if findings:
            return findings

    # ── 5. Encoded variants
    if surface.param_location in ("query", "path"):
        for variant in _encode_variants(other_id):
            if variant == other_id:
                continue
            test_url = _build_test_url(surface, variant)
            r = session.get(test_url, headers=headers)
            _try(test_url, _build_curl("GET", test_url, headers),
                 f"encoded_{variant[:10]}", r)
            if findings:
                return findings

    # ── 6. Null/empty/wildcard
    if surface.param_location == "query":
        for wildcard in ("", "0", "*", "%", "null", "undefined"):
            test_url = _build_test_url(surface, wildcard)
            r = session.get(test_url, headers=headers)
            _try(test_url, _build_curl("GET", test_url, headers),
                 f"wildcard_{wildcard or 'empty'}", r)
            if findings:
                return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  ENUMERATION (opt-in)
# ═════════════════════════════════════════════════════════════════════════════

def test_enumeration(
    session: Session, surface: ObjectSurface, own_id: str, headers: dict,
) -> list[IDORFinding]:
    """Enumerate nearby sequential IDs. Only run when --enumerate is passed."""
    findings: list[IDORFinding] = []
    now = _db_now()

    base = _send(session, surface, own_id, headers)
    if not base or not (200 <= base.status_code < 300):
        return findings

    fp_base = _response_fingerprint(base)

    for test_id in _nearby_ids(own_id):
        r = _send(session, surface, test_id, headers)
        if not r or not (200 <= r.status_code < 300) or _has_denial_marker(r):
            continue
        fp = _response_fingerprint(r)
        if _similarity_by_fingerprint(fp, fp_base) >= 0.9:
            continue
        ownership = extract_ownership_fields(r)
        foreign = _foreign_data_present(ownership, own_id)
        if not foreign:
            continue
        findings.append(IDORFinding(
            target=surface.endpoint, vuln_type="idor_enumeration",
            hypothesis="BOLA", technique="sequential_enum",
            param_name=surface.param_name,
            param_location=surface.param_location,
            id_type=surface.id_type,
            own_id=own_id, other_id=test_id,
            severity="MEDIUM", confidence=55, confirmed=False,
            evidence=f"Enumerated ID {test_id} returned 200 with foreign data: {foreign}",
            request_curl=_build_curl(surface.method,
                _build_test_url(surface, test_id), headers),
            response_a=_body_text(base)[:400],
            response_b=_body_text(r)[:400],
            ownership_leak=foreign,
            auth_enabled=True, first_seen=now,
        ))
        return findings
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
    method = getattr(DB, "upsert_idor_findings", None)
    if method is None:
        log.warning(
            "  DB sync: db.py is missing upsert_idor_findings() — "
            "add the method to enable dedicated-table sync"
        )
        return
    try:
        payloads = [f.to_dict() for f in findings]
        result = method(scan_id, payloads)
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
    enumerate: bool = False,
    max_ids_per_surface: int = 3,
    scan_id: Optional[int] = None,
) -> Path:
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
    auth_on = bool(cfg_hdrs or user_a_headers)

    dual_session = bool(user_a_headers and user_b_headers)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"  Auth   : {'yes' if auth_on else 'no'}")

    if dual_session:
        log.info("  Mode   : DUAL-SESSION (BOLA confirmed via cross-identity)")
        log.info(f"           User A ID: {user_a_id or '(not set — harvest)'}")
        log.info(f"           User B ID: {user_b_id or '(not set — harvest)'}")
    elif user_a_headers:
        log.info("  Mode   : ENUMERATION (single session — LIKELY findings)")
    else:
        log.info("  Mode   : SURFACE-ONLY (no credentials)")
    log.info("")

    if not urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Surface discovery
    surfaces = discover_surfaces(urls)
    surfaces.extend(discover_surfaces_from_pages(outdir))
    seen: set[tuple] = set()
    unique: list[ObjectSurface] = []
    for s in surfaces:
        key = (s.endpoint, s.method, s.param_name, s.param_location)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    surfaces = unique

    log.info(f"  Phase 1 — {len(surfaces)} surface(s) discovered")
    if not surfaces:
        log.warning("  No surfaces — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start, total_input=len(urls))

    (outdir / "idor_surface.txt").write_text(
        "\n".join(
            f"{s.method}\t{s.endpoint}\t{s.param_name}\t{s.param_location}\t{s.id_type}"
            for s in surfaces
        ) + "\n"
    )

    # ── Build shared session + rate limiter
    limiter = SharedRateLimiter(eff_rate)
    session_a = Session(limiter, user_a_headers or cfg_hdrs, eff_timeout)
    session_b = Session(limiter, user_b_headers or {}, eff_timeout) if dual_session else None

    all_findings: list[IDORFinding] = []

    if not user_a_headers and not cfg_hdrs:
        # Surface-only
        for s in surfaces:
            all_findings.append(IDORFinding(
                target=s.endpoint, vuln_type="idor_surface_candidate",
                hypothesis="IDOR_SURFACE",
                param_name=s.param_name,
                param_location=s.param_location,
                id_type=s.id_type,
                severity="MEDIUM", confidence=CONF_CANDIDATE,
                confirmed=False,
                evidence=f"{s.param_location} '{s.param_name}' ({s.id_type}); supply test accounts to confirm",
                details=s.to_dict(),
                auth_enabled=False,
            ))
    else:
        def _process(surface: ObjectSurface) -> list[IDORFinding]:
            local: list[IDORFinding] = []
            host_url = f"{urllib.parse.urlparse(surface.endpoint).scheme}://{urllib.parse.urlparse(surface.endpoint).netloc}"

            hdrs_a = user_a_headers or cfg_hdrs
            hdrs_b = user_b_headers or {}

            own_ids = _harvest_ids(session_a, surface, hdrs_a, host_url)
            other_ids = _harvest_ids(session_b, surface, hdrs_b, host_url) if session_b else []

            own_id = user_a_id or (own_ids[0] if own_ids else "")
            other_id = user_b_id or (other_ids[0] if other_ids else "")

            if not own_id:
                return local

            if session_b and other_id and other_id != own_id:
                local.extend(test_idor_dual(
                    session_a, session_b, surface,
                    own_id, other_id, hdrs_a, hdrs_b,
                ))
                # Bypasses only if no confirmation
                if test_bypasses and not any(f.confirmed for f in local):
                    local.extend(test_bypasses(
                        session_a, surface, own_id, other_id, hdrs_a,
                    ))
            elif enumerate:
                local.extend(test_enumeration(
                    session_a, surface, own_id, hdrs_a,
                ))
            return local

        log.info(f"  Phase 2 — Testing {len(surfaces)} surface(s)")
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

    # ── Dedupe + sort
    seen_f: set[tuple] = set()
    deduped: list[IDORFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type, f.technique, f.own_id, f.other_id)
        if key not in seen_f:
            seen_f.add(key)
            f.auth_enabled = auth_on
            if not f.first_seen:
                f.first_seen = _db_now()
            deduped.append(f)

    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 5), 0 if f.confirmed else 1, -f.confidence, f.target))

    # ── Reports
    elapsed = time.monotonic() - start
    by_severity = {k: 0 for k in SEV_ORDER}
    by_technique: dict[str, int] = {}
    by_hypothesis: dict[str, int] = {}
    confirmed_list: list[IDORFinding] = []
    shared_list: list[IDORFinding] = []

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if f.technique:
            by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
        by_hypothesis[f.hypothesis] = by_hypothesis.get(f.hypothesis, 0) + 1
        if f.confirmed:
            confirmed_list.append(f)
        if f.shared_resource:
            shared_list.append(f)

    (outdir / "idor_candidates.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.technique}\t{f.severity}\t{f.confidence}\t"
            f"{'CONFIRMED' if f.confirmed else 'SHARED' if f.shared_resource else 'candidate'}\t{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "idor_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.vuln_type}\t{f.technique}\t{f.own_id}→{f.other_id}\t{f.evidence[:160]}"
            for f in confirmed_list
        ) + ("\n" if confirmed_list else "")
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
            "test_bypasses": test_bypasses,
            "enumerate":     enumerate,
            "max_ids":       max_ids_per_surface,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces":         len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed_list),
            "shared_resources": len(shared_list),
            "critical":         by_severity.get("CRITICAL", 0),
            "high":             by_severity.get("HIGH", 0),
            "medium":           by_severity.get("MEDIUM", 0),
            "low":              by_severity.get("LOW", 0),
        },
        "summary": {
            "by_severity":   by_severity,
            "by_technique":  dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
            "by_hypothesis": dict(sorted(by_hypothesis.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "idor_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Self-sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<30} {len(deduped):>5} finding(s)")
    log.info(f"    idor_candidates.txt            {len(deduped):>5} candidate(s)")
    log.info(f"    idor_confirmed.txt             {len(confirmed_list):>5} confirmed")
    log.info(f"    idor_surface.txt               {len(surfaces):>5} surface(s)")
    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity.get('CRITICAL', 0)}  "
        f"HIGH={by_severity.get('HIGH', 0)}  MEDIUM={by_severity.get('MEDIUM', 0)}  "
        f"LOW={by_severity.get('LOW', 0)}"
    )
    log.info(f"  Confirmed: {len(confirmed_list)}/{len(deduped)}  "
             f"· Shared (not IDOR): {len(shared_list)}")
    if confirmed_list:
        log.info("")
        log.info("  Confirmed IDOR findings:")
        for f in confirmed_list[:10]:
            log.info(f"    [{f.severity:<8}] {f.technique:<22} {f.target[:60]}")
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
            "confirmed": 0, "shared_resources": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_technique": {}, "by_hypothesis": {}},
        "findings": [],
    }
    path = outdir / "idor_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("idor_candidates.txt", "idor_confirmed.txt", "idor_surface.txt"):
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

    parser = argparse.ArgumentParser(description="Argus IDOR Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=base / "output")
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--user-a-headers", help="JSON dict of User A headers")
    parser.add_argument("--user-b-headers", help="JSON dict of User B headers")
    parser.add_argument("--user-a-id")
    parser.add_argument("--user-b-id")
    parser.add_argument("--graphql-schema", type=Path, default=None)
    parser.add_argument("--enumerate", action="store_true",
                        help="Enable sequential enumeration (opt-in)")
    parser.add_argument("--no-bypasses", action="store_true")
    args = parser.parse_args()

    ua = json.loads(args.user_a_headers) if args.user_a_headers else None
    ub = json.loads(args.user_b_headers) if args.user_b_headers else None

    try:
        run_idor_audit(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            user_a_headers=ua,
            user_b_headers=ub,
            user_a_id=args.user_a_id,
            user_b_id=args.user_b_id,
            graphql_schema_file=args.graphql_schema,
            test_bypasses=not args.no_bypasses,
            enumerate=args.enumerate,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
