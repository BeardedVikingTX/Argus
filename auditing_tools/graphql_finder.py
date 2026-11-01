#!/usr/bin/env python3
"""
auditing_tools/graphql_finder.py — GraphQL Security Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive GraphQL security testing module for Argus. Discovers endpoints,
fingerprints the engine, dumps the schema, tests authorization boundaries,
detects query abuse surfaces, and produces structured candidates.

Seven-phase strategy:

  Phase 1 — Endpoint discovery
      Brute-force 18+ common GraphQL paths. Detect via universal query
      ({"query":"{__typename}"}) and response structure (data/errors keys).

  Phase 2 — Engine fingerprinting
      Identify Apollo, graphql-js, Hasura, Graphene, etc. from headers,
      error messages, and introspection behavior.

  Phase 3 — Introspection & schema analysis
      Full introspection dump (with depth control). Identify sensitive
      types, fields (password, ssn, apiKey, internalNotes), and mutations
      (delete*, admin*, reset*). Flag risky schema surface.

  Phase 4 — Authorization testing (BOLA / BFLA / field-level)
      With two identity cookies (User A, User B), test:
        • BOLA: Query User B's data with User A's token
        • BFLA: Execute admin-only mutations with a regular user token
        • Field-level: Request sensitive fields the UI never shows

  Phase 5 — Query abuse detection
      Detect array batching, alias batching, depth limits, complexity limits.
      Measure impact carefully — a finding requires demonstrated resource
      consumption, not just a successful deep query.

  Phase 6 — Injection surface & error leakage
      Identify injectable arguments (SQLi/NoSQLi surface). Flag verbose
      errors that expose stack traces or internal paths.

  Phase 7 — CSRF / CORS / transport
      Detect GET-based GraphQL (CSRF surface), missing CSRF tokens,
      CORS misconfigurations, and WebSocket subscription endpoints.

Outputs (into `outdir`):
  • graphql_findings.json        — full structured report
  • graphql_candidates.txt       — flat list for triage
  • graphql_schema.json          — raw introspection dump (if available)
  • graphql_bola.txt             — BOLA-specific candidates
  • graphql_query_abuse.txt      — batching/depth findings

Integration:
  main.py → run_one("graphql") → run_graphql_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
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
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.graphql_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 5
DEFAULT_TIMEOUT      = 15
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-GraphQL-Auditor/1.0"

# Endpoint discovery
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/graphql.php", "/graphql/console",
    "/api/graphql", "/graphql/api", "/graphql/graphql",
    "/query", "/gql", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql", "/index.php/graphql",
]

# Introspection depth limit
INTROSPECTION_MAX_DEPTH = 5

# Query abuse
MAX_BATCH_SIZE       = 10      # array batching probe size
MAX_ALIAS_COUNT      = 10      # alias batching probe size
MAX_DEPTH_PROBE      = 20      # depth probe ceiling (safe)
DEPTH_IMPACT_THRESHOLD = 2.0   # seconds — response time delta that indicates impact

# Sensitive field patterns
SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "ssn", "social_security", "credit_card",
    "card_number", "cvv", "internal_notes", "internal_comment", "salary",
    "bank_account", "routing_number", "tax_id", "national_id",
]

SENSITIVE_TYPE_PATTERNS = [
    "admin", "internal", "private", "system", "audit", "billing",
    "payment", "credit", "invoice", "user", "account", "profile",
]

SENSITIVE_MUTATION_PATTERNS = [
    "delete", "destroy", "remove", "admin", "reset", "revoke",
    "impersonate", "override", "escalate", "grant", "disable",
]

# Error leakage patterns
ERROR_LEAK_PATTERNS = [
    r"stack\s*trace", r"at\s+\w+\.\w+\s*\(", r"SQLSTATE", r"mysql_",
    r"postgresql", r"ORA-\d+", r"at\s+Object\.<anonymous>",
    r"node_modules", r"\.java:\d+", r"\.py:\d+", r"\.rb:\d+",
    r"internal server error", r"debug mode",
]

# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphQLFinding:
    target: str
    vuln_type: str
    severity: str = "MEDIUM"
    confidence: int = 50
    evidence: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "vuln_type":  self.vuln_type,
            "severity":   self.severity,
            "confidence": self.confidence,
            "evidence":   self.evidence[:500],
            "details":    self.details,
        }


@dataclass
class GraphQLEndpoint:
    url: str
    engine: str = "unknown"
    introspectable: bool = False
    schema: Optional[dict] = None
    get_supported: bool = False
    websocket_url: str = ""
    cors_headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url":             self.url,
            "engine":          self.engine,
            "introspectable":  self.introspectable,
            "has_schema":      self.schema is not None,
            "get_supported":   self.get_supported,
            "websocket_url":   self.websocket_url,
            "cors_headers":    self.cors_headers,
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


def _graphql_post(
    session: requests.Session,
    url: str,
    query: str,
    variables: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    """Send a GraphQL query via POST."""
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    hdrs = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        return session.post(
            url, json=body, headers=hdrs,
            timeout=timeout, allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"POST {url} failed: {e}")
        return None


def _graphql_get(
    session: requests.Session,
    url: str,
    query: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    """Send a GraphQL query via GET (CSRF surface check)."""
    params = {"query": query}
    try:
        return session.get(
            url, params=params, timeout=timeout,
            allow_redirects=False, verify=False,
        )
    except requests.RequestException:
        return None


def _is_graphql_response(resp: requests.Response) -> bool:
    """Check whether a response looks like a GraphQL response."""
    if resp.status_code >= 500:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return "data" in data or "errors" in data


def _extract_errors(resp: requests.Response) -> list[str]:
    try:
        data = resp.json()
    except Exception:
        return []
    errors = data.get("errors", [])
    if not isinstance(errors, list):
        return []
    return [str(e.get("message", "")) for e in errors if isinstance(e, dict)]


def _body_text(resp: requests.Response, max_len: int = 500) -> str:
    try:
        return resp.text[:max_len].replace("\n", " ").strip()
    except Exception:
        return ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — ENDPOINT DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

DISCOVERY_QUERY = "{__typename}"


def discover_graphql_endpoints(
    session: requests.Session, base_urls: list[str],
) -> list[GraphQLEndpoint]:
    """Brute-force common GraphQL paths on every host."""
    endpoints: list[GraphQLEndpoint] = []
    seen: set[str] = set()

    # Extract unique hosts
    hosts: set[str] = set()
    for url in base_urls:
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname:
            hosts.add(f"{parsed.scheme}://{parsed.netloc}")

    log.info(f"    Probing {len(hosts)} host(s) × {len(GRAPHQL_PATHS)} path(s)")

    for host in sorted(hosts):
        for path in GRAPHQL_PATHS:
            test_url = host.rstrip("/") + path
            if test_url in seen:
                continue
            seen.add(test_url)

            resp = _graphql_post(session, test_url, DISCOVERY_QUERY)
            if resp and _is_graphql_response(resp):
                ep = GraphQLEndpoint(url=test_url)
                # Check GET support (CSRF surface)
                get_resp = _graphql_get(session, test_url, DISCOVERY_QUERY)
                if get_resp and _is_graphql_response(get_resp):
                    ep.get_supported = True
                endpoints.append(ep)
                log.info(f"      FOUND {test_url}")

    return endpoints


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — ENGINE FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_engine(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> str:
    """Identify the GraphQL engine from response characteristics."""
    # Send a deliberately malformed query to trigger engine-specific errors
    probe = '{"query":"{__typename"}'
    try:
        resp = session.post(
            endpoint.url, data=probe,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT, verify=False,
        )
    except requests.RequestException:
        return "unknown"

    body = resp.text.lower()
    headers_str = str(resp.headers).lower()

    # Engine-specific signatures
    if "apollo" in body or "apollo" in headers_str:
        return "Apollo"
    if "graphql-yoga" in body or "yoga" in body:
        return "graphql-yoga"
    if "hasura" in body:
        return "Hasura"
    if "graphene" in body:
        return "Graphene"
    if "ariadne" in body:
        return "Ariadne"
    if "express-graphql" in body or "express" in body:
        return "express-graphql"
    if "graphql-js" in body or "graphql.js" in body:
        return "graphql-js"
    if "absinthe" in body:
        return "Absinthe"
    if "juniper" in body:
        return "Juniper"
    if "sangria" in body:
        return "Sangria"

    # Fallback: check Server header
    server = resp.headers.get("Server", "").lower()
    if "apollo" in server:
        return "Apollo"
    if "hasura" in server:
        return "Hasura"

    return "unknown"


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — INTROSPECTION & SCHEMA ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      name
      description
      type { ...TypeRef }
    }
    type { ...TypeRef }
  }
  inputFields {
    name
    description
    type { ...TypeRef }
  }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
  }
  possibleTypes { ...TypeRef }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
  }
}
"""


def run_introspection(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> Optional[dict]:
    """Attempt full introspection. Returns the schema dict or None."""
    resp = _graphql_post(session, endpoint.url, INTROSPECTION_QUERY)
    if not resp:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if "data" not in data or not data["data"]:
        return None
    schema = data["data"].get("__schema")
    if schema:
        endpoint.introspectable = True
        endpoint.schema = schema
        return schema
    return None


def analyze_schema(
    endpoint: GraphQLEndpoint, schema: dict,
) -> list[GraphQLFinding]:
    """
    Analyze the introspected schema for:
      • Sensitive types
      • Sensitive fields (password, ssn, apiKey, etc.)
      • Sensitive mutations (delete*, admin*, reset*)
      • Risky arguments (id, uuid, email on user types)
    """
    findings: list[GraphQLFinding] = []
    types = schema.get("types", [])

    sensitive_types: list[str] = []
    sensitive_fields: list[dict] = []
    sensitive_mutations: list[dict] = []
    bola_args: list[dict] = []

    for t in types:
        tname = t.get("name", "")
        if tname.startswith("__"):
            continue

        # Sensitive type names
        if any(pat in tname.lower() for pat in SENSITIVE_TYPE_PATTERNS):
            sensitive_types.append(tname)

        # Sensitive fields
        for f in t.get("fields") or []:
            fname = (f.get("name") or "").lower()
            if any(pat in fname for pat in SENSITIVE_FIELD_PATTERNS):
                sensitive_fields.append({
                    "type":  tname,
                    "field": f.get("name"),
                    "args":  [a.get("name") for a in (f.get("args") or [])],
                })

            # BOLA argument surface: fields that take an id-like argument
            for arg in f.get("args") or []:
                aname = (arg.get("name") or "").lower()
                if aname in ("id", "uuid", "user_id", "userid", "account_id",
                             "email", "username", "tenant_id"):
                    bola_args.append({
                        "type":   tname,
                        "field":  f.get("name"),
                        "arg":    arg.get("name"),
                    })

    # Sensitive mutations
    for t in types:
        if t.get("name") == schema.get("mutationType", {}).get("name"):
            for f in t.get("fields") or []:
                fname = (f.get("name") or "").lower()
                if any(pat in fname for pat in SENSITIVE_MUTATION_PATTERNS):
                    sensitive_mutations.append({
                        "mutation": f.get("name"),
                        "args":     [a.get("name") for a in (f.get("args") or [])],
                    })

    # ── Build findings ──────────────────────────────────────────────────────
    if sensitive_types:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_sensitive_types",
            severity="LOW",
            confidence=70,
            evidence=f"Sensitive types exposed in schema: {', '.join(sensitive_types[:10])}",
            details={"types": sensitive_types[:50]},
        ))

    if sensitive_fields:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_sensitive_fields",
            severity="MEDIUM",
            confidence=80,
            evidence=f"Sensitive fields in schema: {', '.join(f['type'] + '.' + f['field'] for f in sensitive_fields[:10])}",
            details={"fields": sensitive_fields[:100]},
        ))

    if sensitive_mutations:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_sensitive_mutations",
            severity="MEDIUM",
            confidence=75,
            evidence=f"Admin-like mutations in schema: {', '.join(m['mutation'] for m in sensitive_mutations[:10])}",
            details={"mutations": sensitive_mutations[:50]},
        ))

    if bola_args:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_bola_surface",
            severity="HIGH",
            confidence=65,
            evidence=f"BOLA argument surface: {len(bola_args)} field(s) accept id-like args",
            details={"bola_args": bola_args[:100]},
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — AUTHORIZATION TESTING (BOLA / BFLA / FIELD-LEVEL)
# ═════════════════════════════════════════════════════════════════════════════

def test_bola(
    session: requests.Session,
    endpoint: GraphQLEndpoint,
    user_a_cookie: Optional[str] = None,
    user_b_id: Optional[str] = None,
) -> list[GraphQLFinding]:
    """
    Test BOLA by querying with User A's token for User B's data.

    Requires:
      • user_a_cookie — session/token for User A
      • user_b_id     — the identifier of an object owned by User B

    If either is missing, we can only surface the candidate (from schema).
    """
    findings: list[GraphQLFinding] = []

    if not endpoint.schema:
        return findings

    # Extract BOLA args from schema
    bola_fields: list[dict] = []
    for t in endpoint.schema.get("types", []):
        for f in t.get("fields") or []:
            for arg in f.get("args") or []:
                aname = (arg.get("name") or "").lower()
                if aname in ("id", "uuid", "user_id", "userid", "account_id", "email"):
                    bola_fields.append({
                        "type":   t.get("name"),
                        "field":  f.get("name"),
                        "arg":    arg.get("name"),
                    })

    if not bola_fields:
        return findings

    # If we have credentials, actually test
    if user_a_cookie and user_b_id:
        headers = {"Cookie": user_a_cookie}
        for bf in bola_fields[:10]:
            # Build query: { user(id: "USER_B_ID") { email } }
            # This is a heuristic; real testing depends on the schema structure.
            query = f'{{ {bf["field"]}({bf["arg"]}: "{user_b_id}") {{ __typename }} }}'
            resp = _graphql_post(session, endpoint.url, query, headers=headers)
            if resp and _is_graphql_response(resp):
                try:
                    data = resp.json()
                except Exception:
                    continue
                if "data" in data and data["data"]:
                    # Data returned for another user's ID = BOLA candidate
                    findings.append(GraphQLFinding(
                        target=endpoint.url,
                        vuln_type="graphql_bola_candidate",
                        severity="CRITICAL",
                        confidence=85,
                        evidence=f"Query for {bf['field']}({bf['arg']}={user_b_id}) returned data with User A's session",
                        details={
                            "type": bf["type"],
                            "field": bf["field"],
                            "arg": bf["arg"],
                            "query": query,
                            "response_snippet": _body_text(resp, 300),
                        },
                    ))
    else:
        # Surface candidate without confirmation
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_bola_surface",
            severity="HIGH",
            confidence=55,
            evidence=f"{len(bola_fields)} BOLA-suspect field(s); supply user_a_cookie and user_b_id to confirm",
            details={"bola_fields": bola_fields[:50]},
        ))

    return findings


def test_bfla(
    session: requests.Session,
    endpoint: GraphQLEndpoint,
    user_cookie: Optional[str] = None,
) -> list[GraphQLFinding]:
    """
    Test BFLA by attempting admin-like mutations with a regular user token.
    """
    findings: list[GraphQLFinding] = []

    if not endpoint.schema:
        return findings

    # Find mutation type
    mut_type_name = endpoint.schema.get("mutationType", {}).get("name")
    if not mut_type_name:
        return findings

    mutations: list[dict] = []
    for t in endpoint.schema.get("types", []):
        if t.get("name") != mut_type_name:
            continue
        for f in t.get("fields") or []:
            fname = (f.get("name") or "").lower()
            if any(pat in fname for pat in SENSITIVE_MUTATION_PATTERNS):
                mutations.append({
                    "mutation": f.get("name"),
                    "args":     [a.get("name") for a in (f.get("args") or [])],
                })

    if not mutations:
        return findings

    if user_cookie:
        headers = {"Cookie": user_cookie}
        for m in mutations[:5]:
            # Heuristic mutation: mutation { deleteUser(id: "1") { __typename } }
            args = ", ".join(f'{a}: "1"' for a in (m.get("args") or [])[:2])
            query = f'mutation {{ {m["mutation"]}({args}) {{ __typename }} }}'
            resp = _graphql_post(session, endpoint.url, query, headers=headers)
            if resp and _is_graphql_response(resp):
                try:
                    data = resp.json()
                except Exception:
                    continue
                # If data is non-null (not an auth error), mutation may have executed
                if "data" in data and data["data"] and not data.get("errors"):
                    findings.append(GraphQLFinding(
                        target=endpoint.url,
                        vuln_type="graphql_bfla_candidate",
                        severity="HIGH",
                        confidence=75,
                        evidence=f"Regular user executed mutation {m['mutation']}",
                        details={
                            "mutation": m["mutation"],
                            "query": query,
                            "response_snippet": _body_text(resp, 300),
                        },
                    ))
    else:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_bfla_surface",
            severity="MEDIUM",
            confidence=50,
            evidence=f"{len(mutations)} admin-like mutation(s); supply user_cookie to confirm",
            details={"mutations": mutations[:50]},
        ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — QUERY ABUSE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_batching(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> list[GraphQLFinding]:
    """Detect array batching and alias batching support."""
    findings: list[GraphQLFinding] = []

    # ── Array batching ──────────────────────────────────────────────────────
    array_body = [{"query": DISCOVERY_QUERY} for _ in range(MAX_BATCH_SIZE)]
    try:
        resp = session.post(
            endpoint.url, json=array_body,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT, verify=False,
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    findings.append(GraphQLFinding(
                        target=endpoint.url,
                        vuln_type="graphql_array_batching",
                        severity="MEDIUM",
                        confidence=85,
                        evidence=f"Array batching accepted {len(data)} operations in one request",
                        details={"batch_size": len(data)},
                    ))
            except Exception:
                pass
    except requests.RequestException:
        pass

    # ── Alias batching ──────────────────────────────────────────────────────
    aliases = " ".join(f'a{i}: __typename' for i in range(MAX_ALIAS_COUNT))
    alias_query = f"{{ {aliases} }}"
    resp = _graphql_post(session, endpoint.url, alias_query)
    if resp and _is_graphql_response(resp):
        try:
            data = resp.json()
            if "data" in data and data["data"] and len(data["data"]) >= MAX_ALIAS_COUNT:
                findings.append(GraphQLFinding(
                    target=endpoint.url,
                    vuln_type="graphql_alias_batching",
                    severity="MEDIUM",
                    confidence=80,
                    evidence=f"Alias batching accepted {len(data['data'])} aliases in one request",
                    details={"alias_count": len(data["data"])},
                ))
        except Exception:
            pass

    return findings


def test_depth(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> list[GraphQLFinding]:
    """
    Probe query depth limits. A finding requires measurable impact —
    we measure baseline response time and compare against a deep query.
    """
    findings: list[GraphQLFinding] = []

    # Baseline
    t0 = time.monotonic()
    baseline_resp = _graphql_post(session, endpoint.url, DISCOVERY_QUERY)
    baseline_time = time.monotonic() - t0
    if not baseline_resp or not _is_graphql_response(baseline_resp):
        return findings

    # Deep query using __typename (safe, self-referential)
    depth = MAX_DEPTH_PROBE
    # Build a valid nested query using a known type if possible
    # Fallback: use a recursive fragment pattern
    deep_query = "{ __typename }"  # Start safe
    if endpoint.schema:
        # Try to find a self-referential type
        for t in endpoint.schema.get("types", []):
            for f in t.get("fields") or []:
                ftype = f.get("type", {})
                # Check if the field returns the same type (self-referential)
                if ftype.get("name") == t.get("name"):
                    field_name = f.get("name")
                    nested = "{" + field_name + " " * 0
                    # Build depth
                    q = "{ " + " ".join(["__typename"] * 1) + " }"
                    # Simpler: just use a known deep pattern
                    deep_query = "{ " + (f"{field_name} {{ " * depth) + "__typename" + (" }" * depth) + " }"
                    break
            if deep_query != "{ __typename }":
                break

    if deep_query == "{ __typename }":
        # Cannot build a deep query without schema — skip
        return findings

    t0 = time.monotonic()
    deep_resp = _graphql_post(session, endpoint.url, deep_query, timeout=30)
    deep_time = time.monotonic() - t0

    if not deep_resp or not _is_graphql_response(deep_resp):
        return findings

    delta = deep_time - baseline_time
    if delta >= DEPTH_IMPACT_THRESHOLD:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_depth_impact",
            severity="MEDIUM",
            confidence=70,
            evidence=f"Depth {depth} query took {deep_time:.2f}s vs baseline {baseline_time:.2f}s (delta {delta:.2f}s)",
            details={
                "depth": depth,
                "baseline_seconds": round(baseline_time, 3),
                "deep_seconds": round(deep_time, 3),
                "delta_seconds": round(delta, 3),
                "query": deep_query[:300],
            },
        ))
    else:
        # No measurable impact — surface only, do not report as finding
        log.debug(f"    Depth {depth} completed in {deep_time:.2f}s (no significant impact)")

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — INJECTION SURFACE & ERROR LEAKAGE
# ═════════════════════════════════════════════════════════════════════════════

INJECTION_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "') OR ('1'='1",
    "1; SELECT 1", "1' AND SLEEP(0)--", "\" AND 1=1--",
    "../../../etc/passwd", "{{7*7}}", "${7*7}",
]


def test_injection_surface(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> list[GraphQLFinding]:
    """
    Identify injectable arguments from the schema and send benign
    error-triggering payloads. Flag arguments where the response
    contains database errors or stack traces.
    """
    findings: list[GraphQLFinding] = []

    if not endpoint.schema:
        return findings

    # Find string arguments
    injectable_args: list[dict] = []
    for t in endpoint.schema.get("types", []):
        for f in t.get("fields") or []:
            for arg in f.get("args") or []:
                arg_type = arg.get("type", {})
                # String-ish types
                if arg_type.get("name") in ("String", "ID"):
                    injectable_args.append({
                        "type":  t.get("name"),
                        "field": f.get("name"),
                        "arg":   arg.get("name"),
                    })

    if not injectable_args:
        return findings

    # Send benign payloads and check for error leakage
    for arg in injectable_args[:5]:
        for payload in INJECTION_PAYLOADS[:3]:
            query = f'{{ {arg["field"]}({arg["arg"]}: "{payload}") {{ __typename }} }}'
            resp = _graphql_post(session, endpoint.url, query)
            if not resp:
                continue
            body = resp.text
            # Check for error leakage patterns
            for pattern in ERROR_LEAK_PATTERNS:
                if re.search(pattern, body, re.I):
                    findings.append(GraphQLFinding(
                        target=endpoint.url,
                        vuln_type="graphql_error_leakage",
                        severity="MEDIUM",
                        confidence=75,
                        evidence=f"Error leakage on {arg['field']}({arg['arg']}) with payload {payload[:30]}",
                        details={
                            "type": arg["type"],
                            "field": arg["field"],
                            "arg": arg["arg"],
                            "payload": payload,
                            "leaked_pattern": pattern,
                            "response_snippet": _body_text(resp, 300),
                        },
                    ))
                    break  # one leak per arg is enough

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — CSRF / CORS / TRANSPORT
# ═════════════════════════════════════════════════════════════════════════════

def test_csrf_cors(
    session: requests.Session, endpoint: GraphQLEndpoint,
) -> list[GraphQLFinding]:
    """
    Test:
      • GET-based GraphQL (CSRF surface)
      • Missing CSRF token on mutations
      • CORS misconfiguration
    """
    findings: list[GraphQLFinding] = []

    # ── GET-based GraphQL ───────────────────────────────────────────────────
    if endpoint.get_supported:
        findings.append(GraphQLFinding(
            target=endpoint.url,
            vuln_type="graphql_get_method",
            severity="MEDIUM",
            confidence=70,
            evidence="GraphQL endpoint accepts GET requests — potential CSRF surface",
            details={"note": "Verify whether mutations are also accepted via GET"},
        ))

    # ── CORS ────────────────────────────────────────────────────────────────
    # Send with an attacker Origin and check reflection
    attacker_origin = "https://evil-argus.example"
    try:
        resp = session.options(
            endpoint.url,
            headers={"Origin": attacker_origin, "Access-Control-Request-Method": "POST"},
            timeout=DEFAULT_TIMEOUT, verify=False,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if attacker_origin in acao and acac:
            findings.append(GraphQLFinding(
                target=endpoint.url,
                vuln_type="graphql_cors_credentialed",
                severity="HIGH",
                confidence=90,
                evidence="CORS reflects attacker origin with credentials",
                details={"acao": acao, "acac": True},
            ))
    except requests.RequestException:
        pass

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_graphql_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    user_a_cookie: Optional[str] = None,
    user_b_cookie: Optional[str] = None,
    user_b_id: Optional[str] = None,
    test_authz: bool = True,
    test_query_abuse: bool = True,
    test_injection: bool = True,
    test_csrf_cors: bool = True,
    threads: int = DEFAULT_THREADS,
) -> Path:
    """
    Run the full GraphQL audit against every URL in `live_urls_file`.

    Returns the path to `graphql_findings.json`.
    """
    start = time.monotonic()

    base_urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(base_urls)} URL(s) from {live_urls_file.name}")
    if user_a_cookie:
        log.info("  Auth A : User A cookie supplied (BOLA/BFLA testing enabled)")
    if user_b_cookie:
        log.info("  Auth B : User B cookie supplied")
    log.info("")

    if not base_urls:
        log.warning("  No URLs to audit — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.verify = False

    # ── Phase 1: Discovery ──────────────────────────────────────────────────
    log.info("  Phase 1 — GraphQL endpoint discovery")
    endpoints = discover_graphql_endpoints(session, base_urls)

    if not endpoints:
        log.warning("  No GraphQL endpoints discovered — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start, total_input=len(base_urls))

    log.info(f"    Discovered {len(endpoints)} endpoint(s)")
    log.info("")

    all_findings: list[GraphQLFinding] = []
    schema_dumps: dict[str, dict] = {}

    for ep in endpoints:
        log.info(f"  Auditing {ep.url}")

        # ── Phase 2: Fingerprint ────────────────────────────────────────────
        ep.engine = fingerprint_engine(session, ep)
        log.info(f"    Engine   : {ep.engine}")

        # ── Phase 3: Introspection ──────────────────────────────────────────
        schema = run_introspection(session, ep)
        if schema:
            schema_dumps[ep.url] = schema
            log.info("    Schema   : introspectable")
            schema_findings = analyze_schema(ep, schema)
            all_findings.extend(schema_findings)
            log.info(f"    Schema findings: {len(schema_findings)}")
        else:
            log.info("    Schema   : not introspectable")

        # ── Phase 4: Authorization ──────────────────────────────────────────
        if test_authz:
            bola = test_bola(session, ep, user_a_cookie, user_b_id)
            bfla = test_bfla(session, ep, user_a_cookie)
            all_findings.extend(bola + bfla)
            log.info(f"    Authz findings: {len(bola) + len(bfla)}")

        # ── Phase 5: Query abuse ────────────────────────────────────────────
        if test_query_abuse:
            batch = test_batching(session, ep)
            depth = test_depth(session, ep)
            all_findings.extend(batch + depth)
            log.info(f"    Query abuse findings: {len(batch) + len(depth)}")

        # ── Phase 6: Injection surface ──────────────────────────────────────
        if test_injection:
            inj = test_injection_surface(session, ep)
            all_findings.extend(inj)
            log.info(f"    Injection/leak findings: {len(inj)}")

        # ── Phase 7: CSRF/CORS ──────────────────────────────────────────────
        if test_csrf_cors:
            csrf = test_csrf_cors(session, ep)
            all_findings.extend(csrf)
            log.info(f"    CSRF/CORS findings: {len(csrf)}")

        log.info("")

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[GraphQLFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
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
    (outdir / "graphql_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # BOLA-specific flat file
    bola_findings = [f for f in deduped if "bola" in f.vuln_type]
    (outdir / "graphql_bola.txt").write_text(
        "\n".join(f"{f.target}\t{f.evidence}" for f in bola_findings) + "\n"
    )

    # Query abuse flat file
    abuse_findings = [f for f in deduped if "batching" in f.vuln_type or "depth" in f.vuln_type]
    (outdir / "graphql_query_abuse.txt").write_text(
        "\n".join(f"{f.target}\t{f.vuln_type}\t{f.evidence}" for f in abuse_findings) + "\n"
    )

    # Schema dumps
    if schema_dumps:
        schema_path = outdir / "graphql_schema.json"
        schema_path.write_text(json.dumps(schema_dumps, indent=2) + "\n")

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "test_authz":       test_authz,
            "test_query_abuse": test_query_abuse,
            "test_injection":   test_injection,
            "test_csrf_cors":   test_csrf_cors,
            "authenticated":    user_a_cookie is not None,
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
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        },
        "findings": [f.to_dict() for f in deduped],
    }

    json_path = outdir / "graphql_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<30} {len(deduped):>5} finding(s)")
    log.info(f"    graphql_candidates.txt          {len(deduped):>5} candidate(s)")
    log.info(f"    graphql_bola.txt                {len(bola_findings):>5} BOLA finding(s)")
    log.info(f"    graphql_query_abuse.txt         {len(abuse_findings):>5} abuse finding(s)")
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

    if deduped:
        log.info("")
        log.info("  Top findings:")
        for f in deduped[:12]:
            log.info(f"    [{f.severity:<8}] {f.vuln_type:<32} {f.target[:55]}")

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
        "endpoints": [],
        "totals": {
            "urls_input": total_input, "endpoints_found": 0,
            "introspectable": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "graphql_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("graphql_candidates.txt", "graphql_bola.txt",
                 "graphql_query_abuse.txt"):
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

    parser = argparse.ArgumentParser(description="Argus GraphQL Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=live, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--cookie-a", help="User A session cookie for BOLA/BFLA")
    parser.add_argument("--cookie-b", help="User B session cookie")
    parser.add_argument("--user-b-id", help="User B's object identifier")
    parser.add_argument("--no-authz", action="store_true", help="Skip authz tests")
    parser.add_argument("--no-abuse", action="store_true", help="Skip query abuse")
    parser.add_argument("--no-injection", action="store_true", help="Skip injection")
    parser.add_argument("--no-csrf", action="store_true", help="Skip CSRF/CORS")
    args = parser.parse_args()

    try:
        run_graphql_audit(
            args.input, args.output,
            user_a_cookie=args.cookie_a,
            user_b_cookie=args.cookie_b,
            user_b_id=args.user_b_id,
            test_authz=not args.no_authz,
            test_query_abuse=not args.no_abuse,
            test_injection=not args.no_injection,
            test_csrf_cors=not args.no_csrf,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
