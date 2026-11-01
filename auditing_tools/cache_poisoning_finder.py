#!/usr/bin/env python3
"""
auditing_tools/cache_poisoning_finder.py — Web Cache Poisoning & Deception Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive cache attack detection module for Argus.

Two bug classes, one engine:

  Web Cache Poisoning
      An unkeyed input (header or parameter) is reflected into the response.
      The cache stores the poisoned response. Every subsequent visitor gets it.

  Web Cache Deception
      A dynamic, authenticated response is cached under a static-looking URL.
      An unauthenticated attacker retrieves the victim's private data.

Five-phase strategy:

  Phase 1 — Cache detection
      Identify whether a cache exists and what headers expose its behavior
      (X-Cache, CF-Cache-Status, Age, X-Cache-Status, X-Varnish).

  Phase 2 — Unkeyed header discovery & poisoning
      Probe 10+ headers known to be unkeyed by major CDNs. Confirm reflection,
      then confirm poisoning via cache-buster + headerless re-request.

  Phase 3 — Cache deception via path confusion
      Append static extensions (.css, .js, .png, etc.) to dynamic URLs.
      Test with a victim session cookie, then retrieve without auth.

  Phase 4 — Parameter cloaking & fat GET
      Duplicate parameters, body-in-GET, unkeyed params (utm_*, fbclid,
      callback). Cache normalizes what the origin does not.

  Phase 5 — Cache-key normalization gaps
      Case variations, trailing slashes, duplicate parameters, path
      parameters (;jsessionid). Cache and origin disagree on the key.

Every finding is scored, confirmed where possible, and written to
`cache_findings.json` plus a flat `cache_candidates.txt` for `vuln_triage.py`.

Outputs (into `outdir`):
  • cache_findings.json        — full structured report
  • cache_candidates.txt       — flat list for triage
  • cache_poisoning.txt        — poisoning-specific findings
  • cache_deception.txt        — deception-specific findings

Integration:
  main.py → run_one("cache") → run_cache_audit(live_urls_file, outdir)
"""

from __future__ import annotations

import argparse
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
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.cache_poisoning")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_THREADS      = 5
DEFAULT_TIMEOUT      = 12
DEFAULT_RETRIES      = 1
USER_AGENT           = "Argus-Cache-Auditor/1.0"

# Cache buster length — unique per request, never touches a shared key
CACHE_BUSTER_LEN     = 16

# Confirmation
CONFIRM_DELAY        = 0.3      # seconds between poison and re-request
MAX_URLS_PER_HOST    = 50       # cap per host to avoid runaway scans

# Deception
DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".json",
]
DECEPTION_DELIMITERS = [
    "",           # plain append: /account.css
    ";",          # path parameter: /account;.css
    "%2f",        # encoded slash:  /account%2f.css
    "%23",        # fragment:       /account%23.css
    "%00",        # null byte:      /account%00.css
    "/..%2f",     # traversal:      /account/..%2f.css
]

# Headers that are commonly unkeyed by CDNs
UNKEYED_HEADERS = [
    ("X-Forwarded-Host",   "evil-cache.example"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Port",   "1"),
    ("X-Forwarded-For",    "evil-cache.example"),
    ("X-Host",             "evil-cache.example"),
    ("X-Original-URL",     "/admin"),
    ("X-Rewrite-URL",      "/admin"),
    ("X-Forwarded-Server", "evil-cache.example"),
    ("Forwarded",          "host=evil-cache.example"),
    ("X-HTTP-Method-Override", "POST"),
]

# Headers that prove caching behavior
CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Status", "CF-Cache-Status",
    "X-Varnish", "Age", "Cache-Control", "Via",
]

# Parameters known to be frequently unkeyed
UNKEYED_PARAMS = ["utm_content", "utm_source", "fbclid", "gclid", "callback"]

# Scoring
CONFIDENCE_POISON_CONFIRMED   = 95
CONFIDENCE_POISON_REFLECTED  = 70
CONFIDENCE_DECEPTION_CONFIRMED = 90
CONFIDENCE_NORMALIZATION      = 60


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CacheFinding:
    target: str
    vuln_type: str           # "cache_poisoning", "cache_deception", "param_cloaking", etc.
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
class CacheProfile:
    url: str
    has_cache: bool = False
    cache_headers: dict = field(default_factory=dict)
    ttl: Optional[int] = None
    vary: str = ""

    def to_dict(self) -> dict:
        return {
            "url":          self.url,
            "has_cache":    self.has_cache,
            "cache_headers": self.cache_headers,
            "ttl":          self.ttl,
            "vary":         self.vary,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _cache_buster() -> str:
    """Random query value so we never touch a shared cache key."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=CACHE_BUSTER_LEN))


def _with_buster(url: str, extra: Optional[dict] = None) -> str:
    """Append a cache-buster query parameter to a URL."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params["cb"] = _cache_buster()
    if extra:
        params.update(extra)
    new_query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


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
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url, headers=headers or {},
            timeout=timeout, allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body_snippet(resp: requests.Response, max_len: int = 300) -> str:
    try:
        text = resp.text[:max_len].replace("\n", " ").strip()
        return text
    except Exception:
        return ""


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — CACHE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def detect_cache(session: requests.Session, url: str) -> CacheProfile:
    """
    Probe a URL and inspect response headers to determine whether a cache
    is in front of it and which headers expose its state.
    """
    profile = CacheProfile(url=url)
    test_url = _with_buster(url)

    resp = _safe_request(session, "GET", test_url)
    if not resp:
        return profile

    for hdr in CACHE_STATUS_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            profile.cache_headers[hdr] = val

    # Heuristic: if any cache-status header exists, a cache is present
    indicators = ("x-cache", "cf-cache-status", "x-cache-status", "x-varnish", "age")
    if any(any(ind in k.lower() for ind in indicators) for k in profile.cache_headers):
        profile.has_cache = True

    # Age header indicates TTL already elapsed on a cached object
    age = resp.headers.get("Age")
    if age:
        try:
            profile.ttl = int(age)
            profile.has_cache = True
        except ValueError:
            pass

    profile.vary = resp.headers.get("Vary", "")
    return profile


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — UNKEYED HEADER DISCOVERY & POISONING
# ═════════════════════════════════════════════════════════════════════════════

def _reflects(resp: requests.Response, needle: str) -> bool:
    """Check whether needle appears in body or Location header."""
    try:
        if needle in resp.text[:50000]:
            return True
    except Exception:
        pass
    loc = resp.headers.get("Location", "")
    return needle in loc


def test_header_poisoning(
    session: requests.Session, url: str,
) -> list[CacheFinding]:
    """
    For each unkeyed header, check:
      1. Does the response reflect the header value?
      2. If yes, does the cache store the poisoned response?
    """
    findings: list[CacheFinding] = []

    for header_name, header_value in UNKEYED_HEADERS:
        test_url = _with_buster(url)

        # First request: send the header
        resp_with = _safe_request(session, "GET", test_url, {header_name: header_value})
        if not resp_with:
            continue
        if not _reflects(resp_with, header_value):
            continue

        # Reflected — now confirm poisoning
        # Re-request the SAME cache-buster URL WITHOUT the header
        time.sleep(CONFIRM_DELAY)
        resp_without = _safe_request(session, "GET", test_url)
        if not resp_without:
            continue

        poisoned = _reflects(resp_without, header_value)

        confidence = CONFIDENCE_POISON_CONFIRMED if poisoned else CONFIDENCE_POISON_REFLECTED
        severity = "HIGH" if poisoned else "MEDIUM"

        findings.append(CacheFinding(
            target=url,
            vuln_type="cache_poisoning",
            severity=severity,
            confidence=confidence,
            evidence=(
                f"{header_name} reflected"
                + (" and CACHED (confirmed poisoning)" if poisoned else " (not yet confirmed as cached)")
            ),
            details={
                "header": header_name,
                "payload": header_value,
                "confirmed": poisoned,
                "body_snippet": _body_snippet(resp_with),
            },
        ))

        # If confirmed, no need to test further headers on this URL
        if poisoned:
            break

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — CACHE DECEPTION VIA PATH CONFUSION
# ═════════════════════════════════════════════════════════════════════════════

def test_cache_deception(
    session: requests.Session,
    url: str,
    victim_cookie: Optional[str] = None,
) -> list[CacheFinding]:
    """
    Append static extensions (with delimiter variants) to dynamic URLs.
    If a victim session is supplied, request with the cookie first, then
    without it, and check whether the authenticated response is served.

    Without a victim cookie, we still flag the surface as a candidate.
    """
    findings: list[CacheFinding] = []

    for ext in DECEPTION_EXTENSIONS:
        for delim in DECEPTION_DELIMITERS:
            test_path = f"{url.rstrip('/')}{delim}{_cache_buster()[:8]}{ext}"
            test_url = _with_buster(test_path)

            headers_victim = {"Cookie": victim_cookie} if victim_cookie else {}

            # Step 1: request as victim (or anonymous if no cookie)
            resp_victim = _safe_request(session, "GET", test_url, headers_victim)
            if not resp_victim:
                continue

            # If no victim cookie, we can only check cache behavior
            if not victim_cookie:
                # Check whether the response was cached
                time.sleep(CONFIRM_DELAY)
                resp_recheck = _safe_request(session, "GET", test_url)
                if resp_recheck:
                    cached = any(
                        "hit" in resp_recheck.headers.get(h, "").lower()
                        for h in ("X-Cache", "CF-Cache-Status", "X-Cache-Status")
                    ) or resp_recheck.headers.get("Age") not in (None, "0")
                    if cached:
                        findings.append(CacheFinding(
                            target=test_url,
                            vuln_type="cache_deception_surface",
                            severity="MEDIUM",
                            confidence=55,
                            evidence="Static extension variant was cached (deception surface confirmed)",
                            details={
                                "extension": ext,
                                "delimiter": delim,
                                "has_victim_cookie": False,
                            },
                        ))
                continue

            # With victim cookie: check whether the response differs from anonymous
            # Step 2: request same URL without cookie
            time.sleep(CONFIRM_DELAY)
            resp_anon = _safe_request(session, "GET", test_url)
            if not resp_anon:
                continue

            # If the anonymous response matches the victim response (and contains
            # more than a generic login page), deception is likely.
            victim_snippet = _body_snippet(resp_victim, 500)
            anon_snippet = _body_snippet(resp_anon, 500)

            # Heuristic: if both contain similar non-trivial content, flag it
            if victim_snippet and victim_snippet == anon_snippet and len(victim_snippet) > 100:
                findings.append(CacheFinding(
                    target=test_url,
                    vuln_type="cache_deception_confirmed",
                    severity="CRITICAL",
                    confidence=CONFIDENCE_DECEPTION_CONFIRMED,
                    evidence="Authenticated response served to unauthenticated request via static extension",
                    details={
                        "extension": ext,
                        "delimiter": delim,
                        "victim_snippet": victim_snippet[:200],
                        "anon_snippet": anon_snippet[:200],
                    },
                ))
                return findings  # one confirmed deception per URL is enough

        # Surface candidate even without confirmation
        if not findings:
            findings.append(CacheFinding(
                target=url,
                vuln_type="cache_deception_candidate",
                severity="LOW",
                confidence=30,
                evidence="Dynamic URL accepts static extension; test with victim session manually",
                details={"extensions_tested": DECEPTION_EXTENSIONS},
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — PARAMETER CLOAKING & FAT GET
# ═════════════════════════════════════════════════════════════════════════════

def test_parameter_cloaking(
    session: requests.Session, url: str,
) -> list[CacheFinding]:
    """
    Test:
      • Duplicate parameters (?a=1&a=2) — cache normalizes, origin doesn't
      • Unkeyed parameters (utm_*, fbclid, callback) — reflected but not keyed
      • Fat GET (body in GET) — origin parses body, cache doesn't key it
    """
    findings: list[CacheFinding] = []

    # ── Duplicate parameter cloaking ────────────────────────────────────────
    parsed = urllib.parse.urlparse(url)
    existing_params = urllib.parse.parse_qsl(parsed.query)
    if existing_params:
        key, _ = existing_params[0]
        payload = "argus-cloak-test"
        # Build: ?key=original&key=payload
        dup_query = f"{key}=original&{key}={payload}"
        test_url = urllib.parse.urlunparse(parsed._replace(query=dup_query)) + f"&cb={_cache_buster()}"

        resp = _safe_request(session, "GET", test_url)
        if resp and _reflects(resp, payload):
            findings.append(CacheFinding(
                target=url,
                vuln_type="parameter_cloaking_duplicate",
                severity="HIGH",
                confidence=70,
                evidence=f"Duplicate parameter '{key}' reflected — cache may parse differently",
                details={"param": key, "payload": payload},
            ))

    # ── Unkeyed parameter reflection ────────────────────────────────────────
    for param in UNKEYED_PARAMS:
        test_url = _with_buster(url, {param: "argus-cache-test"})
        resp = _safe_request(session, "GET", test_url)
        if resp and "argus-cache-test" in resp.text:
            findings.append(CacheFinding(
                target=url,
                vuln_type="unkeyed_parameter",
                severity="MEDIUM",
                confidence=60,
                evidence=f"Unkeyed parameter '{param}' reflected into response",
                details={"param": param},
            ))

    # ── Fat GET (body in GET request) ───────────────────────────────────────
    # Send a GET with a body — some origins parse it, caches typically ignore it.
    try:
        resp = session.request(
            "GET", _with_buster(url),
            data="argus_fat_get=payload",
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        if "argus_fat_get" in resp.text or "payload" in resp.text:
            findings.append(CacheFinding(
                target=url,
                vuln_type="fat_get",
                severity="MEDIUM",
                confidence=55,
                evidence="GET request body reflected — origin parses body, cache may not key it",
                details={"body_param": "argus_fat_get"},
            ))
    except Exception:
        pass

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — CACHE-KEY NORMALIZATION GAPS
# ═════════════════════════════════════════════════════════════════════════════

def test_normalization_gaps(
    session: requests.Session, url: str,
) -> list[CacheFinding]:
    """
    Test case, trailing-slash, and path-parameter variations.
    Cache and origin may disagree on what constitutes the "same" resource.
    """
    findings: list[CacheFinding] = []

    # Case variation
    parsed = urllib.parse.urlparse(url)
    if parsed.path and parsed.path != "/":
        case_variants = {
            "uppercase": parsed.path.upper(),
            "lowercase": parsed.path.lower(),
        }
        for label, path in case_variants.items():
            test_url = urllib.parse.urlunparse(
                parsed._replace(path=path, query=f"cb={_cache_buster()}")
            )
            resp = _safe_request(session, "GET", test_url)
            if resp and resp.status_code == 200:
                # We can't confirm a gap without comparing cache keys, but
                # a differential response is a candidate.
                pass

    # Trailing slash
    if parsed.path and not parsed.path.endswith("/"):
        test_path = parsed.path + "/"
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=test_path, query=f"cb={_cache_buster()}")
        )
        resp = _safe_request(session, "GET", test_url)
        if resp and resp.status_code in (200, 301, 302):
            findings.append(CacheFinding(
                target=url,
                vuln_type="normalization_trailing_slash",
                severity="LOW",
                confidence=40,
                evidence="Trailing-slash variant resolves differently — cache/origin may disagree",
                details={"variant": test_path},
            ))

    # Path parameter (;jsessionid, ;style.css)
    if parsed.path and not parsed.path.endswith("/"):
        param_path = f"{parsed.path};argus={_cache_buster()[:6]}"
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=param_path, query=f"cb={_cache_buster()}")
        )
        resp = _safe_request(session, "GET", test_url)
        if resp and resp.status_code == 200:
            findings.append(CacheFinding(
                target=url,
                vuln_type="normalization_path_param",
                severity="MEDIUM",
                confidence=50,
                evidence="Path parameter accepted — cache may strip it, origin may not",
                details={"variant": param_path},
            ))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_cache_audit(
    live_urls_file: Path,
    outdir: Path,
    *,
    victim_cookie: Optional[str] = None,
    test_poisoning: bool = True,
    test_deception: bool = True,
    test_cloaking: bool = True,
    test_normalization: bool = True,
    threads: int = DEFAULT_THREADS,
) -> Path:
    """
    Run the full cache audit against every URL in `live_urls_file`.

    Returns the path to `cache_findings.json`.
    """
    start = time.monotonic()

    urls = _load_urls(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {live_urls_file.name}")
    if victim_cookie:
        log.info("  Auth   : victim cookie supplied (deception confirmation enabled)")
    log.info("")

    if not urls:
        log.warning("  No URLs to audit — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.verify = False

    # ── Phase 1: Cache detection ────────────────────────────────────────────
    log.info("  Phase 1 — Cache detection")
    profiles: list[CacheProfile] = []

    # Deduplicate by host to avoid scanning every path on the same cache layer
    seen_hosts: set[str] = set()
    for url in urls:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        profile = detect_cache(session, url)
        profiles.append(profile)
        status = "CACHED" if profile.has_cache else "no cache"
        log.info(f"    {host:<40} {status}")

    cached_hosts = {p.url for p in profiles if p.has_cache}
    if not cached_hosts:
        log.warning("  No cache detected on any host — proceeding with surface mapping only")

    # ── Phase 2–5: Per-URL testing ──────────────────────────────────────────
    all_findings: list[CacheFinding] = []

    def _process(url: str) -> list[CacheFinding]:
        local: list[CacheFinding] = []

        if test_poisoning:
            local.extend(test_header_poisoning(session, url))

        if test_deception:
            local.extend(test_cache_deception(session, url, victim_cookie))

        if test_cloaking:
            local.extend(test_parameter_cloaking(session, url))

        if test_normalization:
            local.extend(test_normalization_gaps(session, url))

        return local

    log.info("")
    log.info(f"  Phase 2–5 — Testing {len(urls)} URL(s) for cache attacks...")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_process, u): u for u in urls}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                results = fut.result()
                if results:
                    all_findings.extend(results)
                    log.info(f"    {url[:60]:<60} {len(results)} finding(s)")
            except Exception as e:
                log.debug(f"    error on {url}: {e}")

    # ── Deduplicate ──────────────────────────────────────────────────────────
    seen_keys: set[tuple] = set()
    deduped: list[CacheFinding] = []
    for f in all_findings:
        key = (f.target, f.vuln_type)
        if key not in seen_keys:
            seen_keys.add(key)
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

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.vuln_type}\t{f.severity}\t{f.confidence}\t{f.evidence[:160]}"
        for f in deduped
    ]
    (outdir / "cache_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Poisoning-only flat file
    poisoning = [f for f in deduped if f.vuln_type == "cache_poisoning"]
    (outdir / "cache_poisoning.txt").write_text(
        "\n".join(f"{f.target}\t{f.evidence}" for f in poisoning) + "\n"
    )

    # Deception-only flat file
    deception = [f for f in deduped if "deception" in f.vuln_type]
    (outdir / "cache_deception.txt").write_text(
        "\n".join(f"{f.target}\t{f.evidence}" for f in deception) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(live_urls_file),
        "config": {
            "victim_cookie_supplied": victim_cookie is not None,
            "test_poisoning": test_poisoning,
            "test_deception": test_deception,
            "test_cloaking": test_cloaking,
            "test_normalization": test_normalization,
        },
        "cache_profiles": [p.to_dict() for p in profiles],
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

    json_path = outdir / "cache_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    cache_candidates.txt         {len(deduped):>5} candidate(s)")
    log.info(f"    cache_poisoning.txt          {len(poisoning):>5} poisoning finding(s)")
    log.info(f"    cache_deception.txt          {len(deception):>5} deception finding(s)")

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
            confirmed = f.details.get("confirmed", False)
            tag = "✓" if confirmed else " "
            log.info(f"    {tag} [{f.severity:<8}] {f.vuln_type:<28} {f.target[:60]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "cache_profiles": [],
        "totals": {
            "urls_scanned": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}},
        "findings": [],
    }
    path = outdir / "cache_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("cache_candidates.txt", "cache_poisoning.txt", "cache_deception.txt"):
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

    parser = argparse.ArgumentParser(description="Argus Cache Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=live, help="Input URL file")
    parser.add_argument("--output", type=Path, default=out, help="Output directory")
    parser.add_argument("--cookie", help="Victim session cookie for deception confirmation")
    parser.add_argument("--no-poisoning", action="store_true", help="Skip header poisoning")
    parser.add_argument("--no-deception", action="store_true", help="Skip cache deception")
    parser.add_argument("--no-cloaking", action="store_true", help="Skip parameter cloaking")
    parser.add_argument("--no-normalization", action="store_true", help="Skip normalization tests")
    args = parser.parse_args()

    try:
        run_cache_audit(
            args.input,
            args.output,
            victim_cookie=args.cookie,
            test_poisoning=not args.no_poisoning,
            test_deception=not args.no_deception,
            test_cloaking=not args.no_cloaking,
            test_normalization=not args.no_normalization,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
