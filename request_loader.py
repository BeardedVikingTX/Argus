#!/usr/bin/env python3
"""
request_loader.py — Parse an HTTP request captured from Burp into usable
                    auth headers and cookies.
─────────────────────────────────────────────────────────────────────────────

The user registers/logs in MANUALLY in a browser, captures an authenticated
request from Burp Suite, and saves the raw HTTP request to `request.txt`.

This loader parses that file into:
  • method    — GET / POST / PUT / ...
  • url       — reconstructed from Host + path
  • host      — from the Host header
  • headers   — dict of every header
  • cookies   — dict of individual cookies (parsed from Cookie header)
  • body      — raw body string (usually unused)

If request.txt is missing or malformed, returns None and every downstream
module falls back to unauthenticated mode. Nothing crashes.

NO form submission. NO registration automation. NO email reading.
Argus never touches authentication flows — the user does all of that
in their own browser. See ACCEPTABLE_USE.md.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.request_loader")


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedRequest:
    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""

    # Headers we never forward to clients (managed by the HTTP layer)
    HOP_BY_HOP = {
        "host", "content-length", "connection", "transfer-encoding",
        "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "upgrade",
    }

    def forwardable_headers(self) -> dict[str, str]:
        """Return only headers that are safe/meaningful to replay."""
        return {
            k: v for k, v in self.headers.items()
            if k.lower() not in self.HOP_BY_HOP
        }

    def to_curl_headers(self) -> list[str]:
        """Return ['Name: Value', ...] for CLI tools that take -H."""
        return [f"{k}: {v}" for k, v in self.forwardable_headers().items()]

    def to_requests_headers(self) -> dict[str, str]:
        """Return a dict suitable for requests.Session.headers.update()."""
        return self.forwardable_headers()

    def to_playwright_cookies(self, url: Optional[str] = None) -> list[dict]:
        """Return a list suitable for playwright context.add_cookies()."""
        target_url = url or f"https://{self.host}"
        return [
            {"name": name, "value": value, "url": target_url}
            for name, value in self.cookies.items()
        ]


# ═════════════════════════════════════════════════════════════════════════════
#  PARSER
# ═════════════════════════════════════════════════════════════════════════════

def parse_http_request(text: str) -> Optional[ParsedRequest]:
    """
    Parse a raw HTTP request (as captured by Burp, mitmproxy, curl --verbose).

    Tolerates:
      • CRLF or LF line endings
      • Multiple trailing newlines
      • HTTP/1.1, HTTP/2, HTTP/3 in the request line
      • Long bodies (we keep them but downstream modules rarely use them)

    Returns None on unparseable input.
    """
    if not text or not text.strip():
        log.debug("empty request file")
        return None

    # Normalize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Split headers from body (first blank line)
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""

    lines = head.split("\n")
    if not lines:
        return None

    # ── Request line ───────────────────────────────────────────────────────
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        log.debug(f"bad request line: {request_line!r}")
        return None

    method = parts[0].upper()
    path = parts[1]

    # If the file has an absolute URL in the request line (curl -v output),
    # handle that too.
    if path.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        p = urlparse(path)
        host_header_override = p.hostname or ""
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
    else:
        host_header_override = ""

    # ── Headers ────────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    for line in lines[1:]:
        line = line.rstrip()
        if not line:
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            continue

        # Fold duplicate headers with ", " (HTTP semantics)
        if name in headers:
            headers[name] = headers[name] + ", " + value
        else:
            headers[name] = value

        # Parse cookies
        if name.lower() == "cookie":
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()

    # ── Host ───────────────────────────────────────────────────────────────
    host = (
        host_header_override
        or headers.get("Host")
        or headers.get("host")
        or ""
    ).strip()

    if not host:
        log.debug("no Host header in request")
        return None

    # Reject hosts that look like loopback / internal — those are never
    # valid targets for the pipeline.
    if host.lower() in ("localhost", "127.0.0.1", "::1") or \
       host.lower().startswith(("10.", "192.168.", "172.")):
        log.warning(f"request.txt Host is internal ({host}) — refusing")
        return None

    # ── Scheme — assume HTTPS unless the request line said otherwise ───────
    scheme = "https"
    if request_line.endswith("HTTP/1.0") or ":80" in host:
        # Heuristic; most bug bounty targets are HTTPS anyway
        pass

    url = f"{scheme}://{host}{path}"

    return ParsedRequest(
        method=method,
        url=url,
        host=host,
        path=path,
        headers=headers,
        cookies=cookies,
        body=body,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  LOADER
# ═════════════════════════════════════════════════════════════════════════════

def load_auth_request(path: Path) -> Optional[ParsedRequest]:
    """
    Load and parse `request.txt` (or whatever path is passed).

    Returns None if:
      • The file does not exist
      • The file is empty
      • Parsing fails
      • The file's Host header is an internal address

    Never raises. The caller (config.py) treats None as "no auth configured"
    and falls back to unauthenticated mode.
    """
    if not path.exists():
        return None
    if path.stat().st_size == 0:
        log.debug(f"{path.name} exists but is empty — treating as no auth")
        return None

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        log.warning(f"could not read {path}: {e}")
        return None

    parsed = parse_http_request(text)
    if parsed is None:
        log.warning(f"{path.name} could not be parsed — treating as no auth")
        return None

    log.info(f"  Auth    : loaded from {path.name}")
    log.info(f"            host={parsed.host}  "
             f"method={parsed.method}  "
             f"cookies={len(parsed.cookies)}  "
             f"headers={len(parsed.headers)}")
    return parsed


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE TEST
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    p = Path(__file__).parent / "request.txt"
    req = load_auth_request(p)
    if req is None:
        print("no auth request loaded")
        sys.exit(0)
    print()
    print(f"  method      : {req.method}")
    print(f"  url         : {req.url}")
    print(f"  host        : {req.host}")
    print(f"  path        : {req.path}")
    print(f"  headers     : {len(req.headers)}")
    for k, v in req.forwardable_headers().items():
        print(f"    {k}: {v[:60]}")
    print(f"  cookies     : {len(req.cookies)}")
    for k, v in req.cookies.items():
        v_short = v[:20] + "…" if len(v) > 20 else v
        print(f"    {k} = {v_short}")
